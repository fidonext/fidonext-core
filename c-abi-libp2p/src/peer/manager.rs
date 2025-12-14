//! Command-driven event loop for managing the [`libp2p::Swarm`].
//!
//! The module mirrors the structure from the libp2p tutorials but breaks it
//! down into explicit steps: when a manager is created we obtain the transport,
//! persist the generated or supplied identity key, and start an asynchronous
//! loop that listens for user commands alongside network events.

use anyhow::{anyhow, Result};
use futures::StreamExt;
use libp2p::{
    core::Multiaddr,
    gossipsub,
    identity,
    swarm::{DialError, Swarm, SwarmEvent},
    PeerId,
    autonat,
    kad::{self, QueryResult},
    relay,
    multiaddr::Protocol,
};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

const DISCOVERY_DIAL_BACKOFF: Duration = Duration::from_secs(30);

use crate::{
    messaging::MessageQueueSender,
    transport::{BehaviourEvent, NetworkBehaviour, TransportConfig},
    peer::discovery::{DiscoveryEvent, DiscoveryEventSender, DiscoveryStatus},
    //config::DEFAULT_BOOTSTRAP_PEERS, // Dunno. Its empty should be here
};

/// Commands supported by the [`PeerManager`] event loop.
#[derive(Debug)]
pub enum PeerCommand {
    /// Start listening on the provided multi-address.
    StartListening(Multiaddr),
    /// Initiate a Kademlia find peer query for the provided target.
    FindPeer { peer_id: PeerId, request_id: u64 },
    /// Initiate a Kademlia get_closest_peers query for the provided target.
    GetClosestPeers { peer_id: PeerId, request_id: u64 },
    /// Dial the given remote multi-address.
    Dial(Multiaddr),
    /// Dial a public relay and request a reservation.
    ReserveRelay(Multiaddr),
    /// Publish a payload to the gossipsub topic.
    Publish(Vec<u8>),
    /// Shut the manager down gracefully.
    Shutdown,
}

/// Handle that allows callers to enqueue [`PeerCommand`]s.
#[derive(Clone, Debug)]
pub struct PeerManagerHandle {
    command_sender: mpsc::Sender<PeerCommand>,
    autonat_status: watch::Receiver<autonat::NatStatus>,
}

impl PeerManagerHandle {
    /// Enqueues a command to start listening on the given address.
    pub async fn start_listening(&self, address: Multiaddr) -> Result<()> {
        self.command_sender
            .send(PeerCommand::StartListening(address))
            .await
            .map_err(|err| anyhow!("peer manager command channel closed: {err}"))
    }

    /// Returns a watch channel receiver that yields AutoNAT status updates.
    pub fn autonat_status(&self) -> watch::Receiver<autonat::NatStatus> {
        self.autonat_status.clone()
    }

    /// Initiates a find_peer query against the DHT.
    pub async fn find_peer(&self, peer_id: PeerId, request_id: u64) -> Result<()> {
        self.command_sender
            .send(PeerCommand::FindPeer {
                peer_id,
                request_id,
            })
            .await
            .map_err(|err| anyhow!("peer manager command channel closed: {err}"))
    }

    /// Initiates a get_closest_peers query against the DHT.
    pub async fn get_closest_peers(&self, peer_id: PeerId, request_id: u64) -> Result<()> {
        self.command_sender
            .send(PeerCommand::GetClosestPeers {
                peer_id,
                request_id,
            })
            .await
            .map_err(|err| anyhow!("peer manager command channel closed: {err}"))
    }

    /// Enqueues a command to dial the provided address.
    pub async fn dial(&self, address: Multiaddr) -> Result<()> {
        self.command_sender
            .send(PeerCommand::Dial(address))
            .await
            .map_err(|err| anyhow!("peer manager command channel closed: {err}"))
    }

    /// Requests a reservation on a relay reachable at the given address.
    pub async fn reserve_relay(&self, address: Multiaddr) -> Result<()> {
        self.command_sender
            .send(PeerCommand::ReserveRelay(address))
            .await
            .map_err(|err| anyhow!("peer manager command channel closed: {err}"))
    }

    /// Publishes a message to connected peers via gossipsub.
    pub async fn publish(&self, payload: Vec<u8>) -> Result<()> {
        self.command_sender
            .send(PeerCommand::Publish(payload))
            .await
            .map_err(|err| anyhow!("peer manager command channel closed: {err}"))
    }

    /// Enqueues the shutdown command.
    pub async fn shutdown(&self) -> Result<()> {
        self.command_sender
            .send(PeerCommand::Shutdown)
            .await
            .map_err(|err| anyhow!("peer manager command channel closed: {err}"))
    }
}

#[derive(Debug, Clone)]
struct DiscoveryRequest {
    request_id: u64,
    target_peer_id: PeerId,
    kind: DiscoveryKind,
}

#[derive(Debug, Clone, Copy)]
enum DiscoveryKind {
    FindPeer,
    GetClosestPeers,
}

/// Manages the libp2p swarm (peer orchestrator) and exposes a command-driven control loop.
pub struct PeerManager {
    swarm: Swarm<NetworkBehaviour>,
    command_receiver: mpsc::Receiver<PeerCommand>,
    local_peer_id: PeerId,
    keypair: identity::Keypair,
    inbound_sender: MessageQueueSender,
    gossipsub_topic: gossipsub::IdentTopic,
    autonat_status: watch::Sender<autonat::NatStatus>,
    discovery_sender: DiscoveryEventSender,
    discovery_queries: HashMap<kad::QueryId, DiscoveryRequest>,
    discovery_dial_backoff: HashMap<PeerId, HashMap<Multiaddr, Instant>>,
    relay_base_address: Option<Multiaddr>,
    relay_peer_id: Option<PeerId>,
}

impl PeerManager {
    /// Creates a new [`PeerManager`] instance alongside a [`PeerManagerHandle`].
    pub fn new(
        config: TransportConfig,
        inbound_sender: MessageQueueSender,
        discovery_sender: DiscoveryEventSender,
        bootstrap_peers: Vec<Multiaddr>,
    ) -> Result<(Self, PeerManagerHandle)> {
        let (keypair, swarm) = config.build()?;
        let local_peer_id = PeerId::from(keypair.public());
        let (command_sender, command_receiver) = mpsc::channel(32);
        let (autonat_status, autonat_status_receiver) = watch::channel(autonat::NatStatus::Unknown);

        let mut swarm = swarm;
        let gossipsub_topic = gossipsub::IdentTopic::new("echo");
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub_topic)
            .map_err(|err| anyhow!("failed to subscribe to gossipsub topic: {err}"))?;

        /* These are not needed as DEFAULT_BOOTSTRAP_PEERS should be empty
        bootstrap_peers.extend(
            DEFAULT_BOOTSTRAP_PEERS
                .iter()
                .filter_map(|value| match value.parse::<Multiaddr>() {
                    Ok(addr) => Some(addr),
                    Err(err) => {
                        tracing::warn!(target: "peer", %err, value, "invalid default bootstrap peer; skipping");
                        None
                    }
                }),
        );
        */

        let mut manager = Self {
            swarm,
            command_receiver,
            local_peer_id,
            keypair,
            inbound_sender,
            gossipsub_topic,
            autonat_status,
            discovery_sender,
            discovery_queries: HashMap::new(),
            discovery_dial_backoff: HashMap::new(),
            relay_base_address: None,
            relay_peer_id: None,
        };

        manager.add_bootstrap_peers(bootstrap_peers);

        let handle = PeerManagerHandle {
            command_sender,
            autonat_status: autonat_status_receiver,
        };
        Ok((manager, handle))
    }

    /// Returns the local peer identifier.
    pub fn peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Provides access to the node's identity keypair.
    pub fn keypair(&self) -> &identity::Keypair {
        &self.keypair
    }

    /// Runs the peer manager control loop until shutdown is requested.
    pub async fn run(mut self) -> Result<()> {
        loop {
            tokio::select! {
                Some(command) = self.command_receiver.recv() => {
                    if self.handle_command(command)? {
                        break;
                    }
                }
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event);
                }
            }
        }
        Ok(())
    }

    /// Processes a command and returns whether shutdown was requested
    fn handle_command(&mut self, command: PeerCommand) -> Result<bool> {
        match command {
            PeerCommand::StartListening(address) => {
                match self.swarm.listen_on(address.clone()) {
                    Ok(_) => tracing::info!(target: "peer", %address, "started listening"),
                    Err(err) => tracing::error!(target: "peer", %address, %err, "failed to listen"),
                }
                Ok(false)
            }
            PeerCommand::Dial(address) => {
                match self.swarm.dial(address.clone()) {
                    Ok(_) => tracing::info!(target: "peer", %address, "dialing remote"),
                    Err(err) => tracing::error!(target: "peer", %address, %err, "failed to dial"),
                }
                Ok(false)
            }
            PeerCommand::ReserveRelay(address) => {
                if let Some(peer_id) = extract_peer_id(&address) {
                    self.relay_peer_id = Some(peer_id);
                }

                match self.swarm.listen_on(address.clone()) {
                    Ok(_) => tracing::info!(target: "peer", %address, "listening via relay"),
                    Err(err) => tracing::error!(
                        target: "peer",
                        %address,
                        %err,
                        "failed to start relay reservation"
                    ),
                }

                Ok(false)
            }
            PeerCommand::FindPeer {
                peer_id,
                request_id,
            } => {
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .get_closest_peers(peer_id.clone());

                self.discovery_queries.insert(
                    query_id,
                    DiscoveryRequest {
                        request_id,
                        target_peer_id: peer_id.clone(),
                        kind: DiscoveryKind::FindPeer,
                    },
                );

                tracing::info!(
                    target: "peer",
                    %peer_id,
                    ?query_id,
                    request_id,
                    "started find_peer query"
                );

                Ok(false)
            }
            PeerCommand::GetClosestPeers {
                peer_id,
                request_id,
            } => {
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .get_closest_peers(peer_id.clone());

                self.discovery_queries.insert(
                    query_id,
                    DiscoveryRequest {
                        request_id,
                        target_peer_id: peer_id.clone(),
                        kind: DiscoveryKind::GetClosestPeers,
                    },
                );

                tracing::info!(
                    target: "peer",
                    %peer_id,
                    ?query_id,
                    request_id,
                    "started get_closest_peers query"
                );

                Ok(false)
            }
            PeerCommand::Publish(payload) => {
                match self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(self.gossipsub_topic.clone(), payload)
                {
                    Ok(_) => tracing::info!(target: "peer", "published message"),
                    Err(err) => tracing::warn!(target: "peer", %err, "failed to publish message"),
                }
                Ok(false)
            }
            PeerCommand::Shutdown => {
                tracing::info!(target: "peer", "shutdown requested");
                Ok(true)
            }
        }
    }

    /// Logging and reacting to events coming from the swarm (peer orchestrator)
    fn handle_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(event) => self.handle_behaviour_event(event),

            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!(target: "peer", %address, "listening on new address");
            }

            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                tracing::info!(target: "peer", %peer_id, "connection established");
            }

            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                if let Some(error) = cause {
                    tracing::warn!(target: "peer", %peer_id, %error, "connection closed with error");
                } else {
                    tracing::info!(target: "peer", %peer_id, "connection closed");
                }
            }

            SwarmEvent::IncomingConnection { send_back_addr, .. } => {
                tracing::debug!(target: "peer", %send_back_addr, "incoming connection");
            }

            SwarmEvent::IncomingConnectionError {
                send_back_addr,
                error,
                ..
            } => {
                tracing::warn!(target: "peer", %send_back_addr, %error, "incoming connection error");
            }

            SwarmEvent::NewExternalAddrCandidate { address } => {
                tracing::info!(target: "peer", %address, "new external address candidate");
            }

            SwarmEvent::ExternalAddrConfirmed { address } => {
                tracing::info!(target: "peer", %address, "external address confirmed");
                self.update_relay_address(address);
            }

            SwarmEvent::ExternalAddrExpired { address } => {
                tracing::warn!(target: "peer", %address, "external address expired");
                self.clear_relay_address(&address);
            }

            SwarmEvent::ListenerClosed {
                addresses, reason, ..
            } => {
                tracing::warn!(target: "peer", ?addresses, ?reason, "listener closed");
            }

            SwarmEvent::ListenerError { error, .. } => {
                tracing::error!(target: "peer", %error, "listener error");
            }

            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::warn!(target: "peer", ?peer_id, %error, "outgoing connection error");

                if let Some(peer_id) = peer_id {
                    self.try_dial_via_relay(&peer_id, &error);
                }
            }
            
            _ => {}
        }
    }

    /// Handles events from additional network's features
    fn handle_behaviour_event(&mut self, event: BehaviourEvent) {
        match event {
            BehaviourEvent::Kademlia(event) => {
                self.handle_kademlia_event(event);
            }

            BehaviourEvent::Ping(event) => match event.result {
                Ok(rtt) => {
                    tracing::debug!(target: "peer", ?rtt, "ping success");
                }
                Err(error) => {
                    tracing::warn!(target: "peer", %error, "ping failure");
                }
            },

            BehaviourEvent::Identify(event) => {
                tracing::debug!(target: "peer", ?event, "identify event");
            }

            BehaviourEvent::Gossipsub(event) => {
                if let gossipsub::Event::Message {
                    message, propagation_source, ..
                } = event {
                    tracing::info!(target: "peer", %propagation_source, len = message.data.len(), "received gossipsub message");
                    if let Err(err) = self.inbound_sender.try_enqueue(message.data.clone()) {
                        tracing::warn!(target: "peer", %err, "failed to enqueue inbound message");
                    }
                }
            }

            BehaviourEvent::Autonat(event) => {
                tracing::debug!(target:"peer", ?event, "autonat event");
                
                if let autonat::Event::StatusChanged { new, .. } = event {
                    if self.autonat_status.send(new.clone()).is_err() {
                        tracing::trace!(
                            target: "peer",
                            "autonat status receiver dropped; skipping update"
                        );
                    }
                }
            }

            BehaviourEvent::RelayClient(event) => match event {
                relay::client::Event::ReservationReqAccepted {
                    relay_peer_id,
                    renewal,
                    limit,
                } => {
                    self.relay_peer_id = Some(relay_peer_id);
                    tracing::info!(
                        target: "peer",
                        relay_id = %relay_peer_id,
                        renewal,
                        ?limit,
                        "relay reservation accepted",
                    );
                }

                relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. } => {
                    tracing::info!(
                        target: "peer",
                        relay_id = %relay_peer_id,
                        "outbound circuit established",
                    );
                }

                other => {
                    tracing::debug!(target: "peer", ?other, "relay client event");
                }
            },

            BehaviourEvent::RelayServer(event) => {
                tracing::debug!(target: "peer", ?event, "relay server event");
            }
        }
    }

    fn handle_kademlia_event(&mut self, event: kad::Event) {
        match event {
            kad::Event::OutboundQueryProgressed {
                id, result, step, ..
            } => match result {
                QueryResult::GetClosestPeers(res) => {
                    self.handle_get_closest_peers_result(id, res, step.last)
                }
                other => {
                    tracing::debug!(target: "peer", ?id, ?other, "unhandled kademlia query result");
                    if step.last {
                        self.discovery_queries.remove(&id);
                    }
                }
            },
            other => tracing::debug!(target: "peer", ?other, "kademlia event"),
        }
    }

    fn handle_get_closest_peers_result(
        &mut self,
        query_id: kad::QueryId,
        result: kad::GetClosestPeersResult,
        is_last: bool,
    ) {
        let Some(request) = self.discovery_queries.get(&query_id).cloned() else {
            tracing::debug!(target: "peer", ?query_id, "ignoring untracked kademlia query");
            return;
        };

        match &result {
            Ok(ok) => match request.kind {
                DiscoveryKind::FindPeer => {
                    self.handle_find_peer_response(query_id, &request, ok, is_last);
                }
                DiscoveryKind::GetClosestPeers => {
                    self.handle_closest_peers_response(query_id, &request, ok, is_last);
                }
            },
            Err(kad::GetClosestPeersError::Timeout { peers, .. }) => {
                tracing::warn!(
                    target: "peer",
                    ?query_id,
                    request_id = request.request_id,
                    target = %request.target_peer_id,
                    "kademlia query timed out"
                );

                if !peers.is_empty() {
                    self.process_discovered_peers(&request, peers);
                }

                if is_last {
                    self.finish_discovery(query_id, request, DiscoveryStatus::Timeout);
                }
            }
        }
    }

    fn handle_find_peer_response(
        &mut self,
        query_id: kad::QueryId,
        request: &DiscoveryRequest,
        response: &kad::GetClosestPeersOk,
        is_last: bool,
    ) {
        let mut status = DiscoveryStatus::NotFound;

        if let Some(peer) = response
            .peers
            .iter()
            .find(|info| info.peer_id == request.target_peer_id)
        {
            if peer.addrs.is_empty() {
                tracing::warn!(
                    target: "peer",
                    target = %request.target_peer_id,
                    request_id = request.request_id,
                    "find_peer completed without any addresses"
                );
            } else {
                self.process_discovered_peers(request, &[peer.clone()]);
                status = DiscoveryStatus::Success;
            }
        } else {
            tracing::warn!(
                target: "peer",
                target = %request.target_peer_id,
                request_id = request.request_id,
                "find_peer did not return the target peer"
            );
        }

        if is_last {
            self.finish_discovery(query_id, request.clone(), status);
        }
    }

    fn handle_closest_peers_response(
        &mut self,
        query_id: kad::QueryId,
        request: &DiscoveryRequest,
        response: &kad::GetClosestPeersOk,
        is_last: bool,
    ) {
        if response.peers.is_empty() {
            tracing::warn!(
                target: "peer",
                target = %request.target_peer_id,
                request_id = request.request_id,
                "get_closest_peers returned no peers"
            );
        } else {
            self.process_discovered_peers(request, &response.peers);
        }

        if is_last {
            self.finish_discovery(query_id, request.clone(), DiscoveryStatus::Success);
        }
    }

    fn process_discovered_peers(&mut self, request: &DiscoveryRequest, peers: &[kad::PeerInfo]) {
        for peer in peers {
            if peer.peer_id == self.local_peer_id {
                tracing::debug!(target: "peer", "skipping self in discovery results");
                continue;
            }

            let now = Instant::now();
            let backoff = self
                .discovery_dial_backoff
                .entry(peer.peer_id.clone())
                .or_default();

            let mut unique_addresses = HashSet::new();

            for address in peer
                .addrs
                .iter()
                .cloned()
                .filter(|addr| unique_addresses.insert(addr.clone()))
            {
                if let Some(next_allowed) = backoff.get(&address) {
                    if *next_allowed > now {
                        tracing::debug!(
                            target: "peer",
                            peer_id = %peer.peer_id,
                            %address,
                            remaining_ms = next_allowed.saturating_duration_since(now).as_millis(),
                            "skipping discovery dial due to backoff",
                        );
                        continue;
                    }
                }

                let event = DiscoveryEvent::Address {
                    request_id: request.request_id,
                    target_peer_id: request.target_peer_id.clone(),
                    peer_id: peer.peer_id.clone(),
                    address: address.clone(),
                };

                if let Err(err) = self.discovery_sender.try_enqueue(event) {
                    tracing::warn!(target: "peer", %err, "failed to enqueue discovery address");
                }

                match self.swarm.dial(address.clone()) {
                    Ok(_) => tracing::info!(
                        target: "peer",
                        peer_id = %peer.peer_id,
                        %address,
                        "dialing discovered peer",
                    ),
                    Err(err) => tracing::warn!(
                        target: "peer",
                        peer_id = %peer.peer_id,
                        %address,
                        %err,
                        "failed to dial discovered peer",
                    ),
                }

                backoff.insert(address, now + DISCOVERY_DIAL_BACKOFF);
            }
        }
    }

    fn finish_discovery(
        &mut self,
        query_id: kad::QueryId,
        request: DiscoveryRequest,
        status: DiscoveryStatus,
    ) {
        self.discovery_queries.remove(&query_id);

        let event = DiscoveryEvent::Finished {
            request_id: request.request_id,
            target_peer_id: request.target_peer_id,
            status,
        };

        if let Err(err) = self.discovery_sender.try_enqueue(event) {
            tracing::warn!(target: "peer", %err, "failed to enqueue discovery completion");
        }
    }

    // Adding bootstraps into node's DHT initial network
    fn add_bootstrap_peers(&mut self, peers: Vec<Multiaddr>) {
        let mut added = 0usize;

        for mut addr in peers {
            let peer_component = addr.pop();
            match peer_component {
                Some(libp2p::multiaddr::Protocol::P2p(peer_id)) => {
                    tracing::info!(
                        target: "peer",
                        %peer_id,
                        address = %addr,
                        "adding bootstrap peer"
                    );
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                    added += 1;
                }
                other => {
                    tracing::warn!(
                        target: "peer",
                        ?other,
                        address = %addr,
                        "bootstrap peer missing p2p component"
                    );
                }
            }
        }

        match self.swarm.behaviour_mut().kademlia.bootstrap() {
            Ok(query_id) => {
                tracing::info!(target: "peer", ?query_id, added, "started kademlia bootstrap");
            }
            Err(err) => {
                tracing::warn!(target: "peer", %err, added, "failed to start kademlia bootstrap");
            }
        }
    }

    fn try_dial_via_relay(&mut self, target_peer_id: &PeerId, error: &DialError) {
        if self.relay_peer_id.as_ref() == Some(target_peer_id) {
            tracing::debug!(
                target: "peer",
                %target_peer_id,
                "skipping relay fallback when dialing relay peer itself",
            );
            return;
        }

        let Some(relay_base_address) = self.relay_base_address.clone() else {
            tracing::debug!(
                target: "peer",
                %target_peer_id,
                "no relay reservation available for fallback dialing",
            );
            return;
        };

        if dial_error_involves_circuit(error) {
            tracing::debug!(
                target: "peer",
                %target_peer_id,
                "dial attempt already used a relay circuit; skipping fallback",
            );
            return;
        }

        let mut relay_circuit_addr = relay_base_address.clone();
        relay_circuit_addr.push(Protocol::P2pCircuit);
        relay_circuit_addr.push(Protocol::P2p(target_peer_id.clone()));

        match self.swarm.dial(relay_circuit_addr.clone()) {
            Ok(_) => tracing::info!(
                target: "peer",
                %relay_circuit_addr,
                %target_peer_id,
                "retrying dial via relay circuit",
            ),
            Err(err) => tracing::error!(
                target: "peer",
                %relay_circuit_addr,
                %target_peer_id,
                %err,
                "failed to dial via relay circuit",
            ),
        }
    }

    fn update_relay_address(&mut self, address: Multiaddr) {
        if let Some((base_address, relay_peer_id)) =
            relay_base_from_external(&address, &self.local_peer_id)
        {
            tracing::info!(
                target: "peer",
                %base_address,
                relay_id = %relay_peer_id,
                "updated relay base address",
            );

            self.relay_base_address = Some(base_address);
            if self.relay_peer_id.is_none() {
                self.relay_peer_id = Some(relay_peer_id);
            }
        } else {
            tracing::debug!(
                target: "peer",
                %address,
                "external address is not a relay reservation for this peer",
            );
        }
    }

    fn clear_relay_address(&mut self, address: &Multiaddr) {
        if let Some((base_address, _)) = relay_base_from_external(address, &self.local_peer_id) {
            if self.relay_base_address.as_ref() == Some(&base_address) {
                tracing::info!(target: "peer", %base_address, "clearing relay base address");
                self.relay_base_address = None;
            }
        }
    }
}

fn extract_peer_id(address: &Multiaddr) -> Option<PeerId> {
    address
        .iter()
        .filter_map(|component| match component {
            Protocol::P2p(peer_id) => Some(peer_id),
            _ => None,
        })
        .last()
}

fn dial_error_involves_circuit(error: &DialError) -> bool {
    match error {
        DialError::Transport(address_errors) => address_errors.iter().any(|(addr, _)| {
            addr.iter()
                .any(|component| matches!(component, Protocol::P2pCircuit))
        }),
        _ => false,
    }
}

fn relay_base_from_external(
    address: &Multiaddr,
    local_peer_id: &PeerId,
) -> Option<(Multiaddr, PeerId)> {
    let mut addr = address.clone();

    match (addr.pop(), addr.pop()) {
        (Some(Protocol::P2p(local)), Some(Protocol::P2pCircuit)) if local == *local_peer_id => {
            match addr.iter().last() {
                Some(Protocol::P2p(relay_peer_id)) => Some((addr, relay_peer_id.clone())),
                _ => None,
            }
        }
        _ => None,
    }
}
