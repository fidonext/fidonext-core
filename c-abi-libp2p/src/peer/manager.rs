//! Command-driven event loop for managing the [`libp2p::Swarm`].
//!
//! The module mirrors the structure from the libp2p tutorials but breaks it
//! down into explicit steps: when a manager is created we obtain the transport,
//! persist the generated or supplied identity key, and start an asynchronous
//! loop that listens for user commands alongside network events.

use anyhow::{anyhow, Result};
use futures::StreamExt;
use libp2p::{
    autonat,
    core::Multiaddr,
    gossipsub, identify, identity,
    kad::{self, store::RecordStore, QueryResult},
    multiaddr::Protocol,
    relay, request_response,
    swarm::{DialError, Swarm, SwarmEvent},
    PeerId,
};
use rand::Rng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::MissedTickBehavior;

const DISCOVERY_DIAL_BACKOFF: Duration = Duration::from_secs(30);
const DELIVERY_TICK_INTERVAL: Duration = Duration::from_secs(1);
const DELIVERY_INITIAL_RETRY_DELAY: Duration = Duration::from_secs(2);
const DELIVERY_MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
const MAILBOX_FETCH_INTERVAL: Duration = Duration::from_secs(8);
const MAILBOX_FETCH_JITTER_SECONDS: u64 = 3;
const RELAY_PLACEMENT_N: usize = 5;
const RELAY_PLACEMENT_W: usize = 3;
const RELAY_READ_N: usize = 5;
const RELAY_READ_R: usize = 2;
const MAILBOX_MAX_PER_RECIPIENT: usize = 256;
const MAILBOX_MAX_BYTES_PER_RECIPIENT: usize = 512 * 1024;

fn mailbox_fetch_next_interval() -> Duration {
    let base = MAILBOX_FETCH_INTERVAL.as_secs();
    let jitter = MAILBOX_FETCH_JITTER_SECONDS;
    let min = base.saturating_sub(jitter).max(1);
    let max = base.saturating_add(jitter).max(min);
    let next = rand::thread_rng().gen_range(min..=max);
    Duration::from_secs(next)
}

use crate::{
    messaging::{
        build_ack, build_envelope_from_payload, build_mailbox_fetch, build_nack,
        chunk_size_or_default, encode_frame, is_addressed_payload, now_unix_seconds, parse_frame,
        DeliveryAck, DeliveryAckKind, DeliveryEnvelope, DeliveryFrame, DeliveryMailboxFetch,
        DeliveryNack, DeliveryNackReason, FileMetadata, FileTransferFrame, FileTransferQueueSender,
        InboundFileTransferFrame, MessageQueueSender,
    },
    peer::addr_events::{AddrEvent, AddrState},
    peer::discovery::{DiscoveryEvent, DiscoveryEventSender, DiscoveryStatus},
    peer::mailbox_store::{MailboxStoreInsertOutcome, MailboxStoreLimits, PersistentMailboxStore},
    transport::{
        BehaviourEvent, DeliveryDirectRequest, DeliveryDirectResponse, FileTransferRequest,
        FileTransferResponse, NetworkBehaviour, TransportConfig,
    },
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
    /// Store a binary record in Kademlia.
    PutDhtRecord {
        key: Vec<u8>,
        value: Vec<u8>,
        ttl_seconds: u64,
        response: oneshot::Sender<std::result::Result<(), DhtQueryError>>,
    },
    /// Retrieve a binary record from Kademlia.
    GetDhtRecord {
        key: Vec<u8>,
        response: oneshot::Sender<std::result::Result<Vec<u8>, DhtQueryError>>,
    },
    /// File sending pipeline.
    StartFileTransfer {
        recipient: PeerId,
        metadata: FileMetadata,
        data: Vec<u8>,
        chunk_size: usize,
    },
    /// Shut the manager down gracefully.
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum DhtQueryError {
    NotFound,
    Timeout,
    Internal(String),
}

/// Handle that allows callers to enqueue [`PeerCommand`]s.
#[derive(Clone, Debug)]
pub struct PeerManagerHandle {
    command_sender: mpsc::Sender<PeerCommand>,
    autonat_status: watch::Receiver<autonat::NatStatus>,
    local_peer_id: PeerId,
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

    /// Returns the local peer identifier.
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id.clone()
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

    /// Stores a key/value record in the DHT and waits for the query outcome.
    pub async fn dht_put_record(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> std::result::Result<(), DhtQueryError> {
        let (tx, rx) = oneshot::channel();
        self.command_sender
            .send(PeerCommand::PutDhtRecord {
                key,
                value,
                ttl_seconds,
                response: tx,
            })
            .await
            .map_err(|err| {
                DhtQueryError::Internal(format!("peer manager command channel closed: {err}"))
            })?;
        rx.await.map_err(|_| {
            DhtQueryError::Internal("dht put query response channel closed".to_string())
        })?
    }

    /// Resolves a key from the DHT and returns raw record bytes.
    pub async fn dht_get_record(
        &self,
        key: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, DhtQueryError> {
        let (tx, rx) = oneshot::channel();
        self.command_sender
            .send(PeerCommand::GetDhtRecord { key, response: tx })
            .await
            .map_err(|err| {
                DhtQueryError::Internal(format!("peer manager command channel closed: {err}"))
            })?;
        rx.await.map_err(|_| {
            DhtQueryError::Internal("dht get query response channel closed".to_string())
        })?
    }

    /// Enqueues the shutdown command.
    pub async fn shutdown(&self) -> Result<()> {
        self.command_sender
            .send(PeerCommand::Shutdown)
            .await
            .map_err(|err| anyhow!("peer manager command channel closed: {err}"))
    }

    // Requests starting an outbound file transfer to the target peer via the dedicated protocol.
    pub async fn start_file_transfer(
        &self,
        recipient: PeerId,
        metadata: FileMetadata,
        data: Vec<u8>,
        chunk_size: usize,
    ) -> Result<()> {
        self.command_sender
            .send(PeerCommand::StartFileTransfer {
                recipient,
                metadata,
                data,
                chunk_size,
            })
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

#[derive(Debug)]
struct PendingDhtPutQuery {
    response: oneshot::Sender<std::result::Result<(), DhtQueryError>>,
    fallback_record: kad::Record,
}

#[derive(Debug, Clone)]
struct PendingEnvelope {
    envelope: DeliveryEnvelope,
    next_retry_at: Instant,
    retry_delay: Duration,
    stored_ack_received: bool,
}

#[derive(Debug, Clone)]
struct StoredEnvelope {
    envelope: DeliveryEnvelope,
}

#[derive(Debug, Clone)]
struct PendingDirectRequest {
    frame: DeliveryFrame,
}

/// Manages the libp2p swarm (peer orchestrator) and exposes a command-driven control loop.
pub struct PeerManager {
    swarm: Swarm<NetworkBehaviour>,
    command_receiver: mpsc::Receiver<PeerCommand>,
    local_peer_id: PeerId,
    keypair: identity::Keypair,
    inbound_sender: MessageQueueSender,
    file_transfer_sender: FileTransferQueueSender,
    gossipsub_topic: gossipsub::IdentTopic,
    autonat_status: watch::Sender<autonat::NatStatus>,
    discovery_sender: DiscoveryEventSender,
    discovery_queries: HashMap<kad::QueryId, DiscoveryRequest>,
    dht_put_queries: HashMap<kad::QueryId, PendingDhtPutQuery>,
    dht_get_queries:
        HashMap<kad::QueryId, oneshot::Sender<std::result::Result<Vec<u8>, DhtQueryError>>>,
    discovery_dial_backoff: HashMap<PeerId, HashMap<Multiaddr, Instant>>,
    relay_base_address: Option<Multiaddr>,
    relay_peer_id: Option<PeerId>,
    addr_state: Arc<RwLock<AddrState>>,
    bootstrap_peer_ids: Vec<PeerId>,
    connected_peers: HashSet<PeerId>,
    mailbox_enabled: bool,
    mailbox_store: Option<PersistentMailboxStore>,
    pending_envelopes: HashMap<String, PendingEnvelope>,
    pending_direct_requests: HashMap<request_response::OutboundRequestId, PendingDirectRequest>,
    pending_file_transfer_requests: HashSet<request_response::OutboundRequestId>,
    delivered_envelopes: HashMap<String, u64>,
    mailbox_queues: HashMap<PeerId, VecDeque<StoredEnvelope>>,
    next_mailbox_fetch_at: Instant,
    delivery_sequence: u64,
}

impl PeerManager {
    /// Creates a new [`PeerManager`] instance alongside a [`PeerManagerHandle`].
    pub fn new(
        config: TransportConfig,
        inbound_sender: MessageQueueSender,
        file_transfer_sender: FileTransferQueueSender,
        discovery_sender: DiscoveryEventSender,
        addr_state: Arc<RwLock<AddrState>>,
        bootstrap_peers: Vec<Multiaddr>,
    ) -> Result<(Self, PeerManagerHandle)> {
        let mailbox_enabled = config.hop_relay;
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

        let mailbox_store = if mailbox_enabled {
            match PersistentMailboxStore::open(&local_peer_id) {
                Ok(store) => Some(store),
                Err(err) => {
                    tracing::warn!(
                        target: "peer",
                        %err,
                        "failed to initialize persistent mailbox store; falling back to in-memory queue",
                    );
                    None
                }
            }
        } else {
            None
        };

        let mut manager = Self {
            swarm,
            command_receiver,
            local_peer_id,
            keypair,
            inbound_sender,
            file_transfer_sender,
            gossipsub_topic,
            autonat_status,
            discovery_sender,
            discovery_queries: HashMap::new(),
            dht_put_queries: HashMap::new(),
            dht_get_queries: HashMap::new(),
            discovery_dial_backoff: HashMap::new(),
            relay_base_address: None,
            relay_peer_id: None,
            addr_state,
            bootstrap_peer_ids: Vec::new(),
            connected_peers: HashSet::new(),
            mailbox_enabled,
            mailbox_store,
            pending_envelopes: HashMap::new(),
            pending_direct_requests: HashMap::new(),
            pending_file_transfer_requests: HashSet::new(),
            delivered_envelopes: HashMap::new(),
            mailbox_queues: HashMap::new(),
            next_mailbox_fetch_at: Instant::now() + mailbox_fetch_next_interval(),
            delivery_sequence: 0,
        };

        manager.add_bootstrap_peers(bootstrap_peers);

        let handle = PeerManagerHandle {
            command_sender,
            autonat_status: autonat_status_receiver,
            local_peer_id: local_peer_id.clone(),
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
        let mut delivery_tick = tokio::time::interval(DELIVERY_TICK_INTERVAL);
        delivery_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                Some(command) = self.command_receiver.recv() => {
                    if self.handle_command(command)? {
                        break;
                    }
                }
                _ = delivery_tick.tick() => {
                    self.handle_delivery_tick();
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
            PeerCommand::ReserveRelay(mut address) => {
                // This one should contain relay peerId
                if let Some(peer_id) = extract_peer_id(&address) {
                    self.relay_peer_id = Some(peer_id);
                }

                // ensure /p2p-circuit is present
                let has_circuit = address.iter().any(|p| matches!(p, Protocol::P2pCircuit));
                if !has_circuit {
                    // Force it be a p2p-circuit (relay)
                    address.push(Protocol::P2pCircuit);
                }

                // This one is a reservation itself
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
                self.handle_publish_command(payload);
                Ok(false)
            }
            PeerCommand::PutDhtRecord {
                key,
                value,
                ttl_seconds,
                response,
            } => {
                if key.is_empty() || value.is_empty() {
                    let _ = response.send(Err(DhtQueryError::Internal(
                        "dht put requires non-empty key and value".to_string(),
                    )));
                    return Ok(false);
                }
                let expires = if ttl_seconds == 0 {
                    None
                } else {
                    Some(Instant::now() + Duration::from_secs(ttl_seconds))
                };
                let record = kad::Record {
                    key: kad::RecordKey::new(&key),
                    value,
                    publisher: Some(self.local_peer_id.clone()),
                    expires,
                };
                let local_fallback_record = record.clone();
                match self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .put_record(record, kad::Quorum::One)
                {
                    Ok(query_id) => {
                        self.dht_put_queries.insert(
                            query_id,
                            PendingDhtPutQuery {
                                response,
                                fallback_record: local_fallback_record,
                            },
                        );
                        tracing::info!(target: "peer", ?query_id, "started dht put_record query");
                    }
                    Err(err) => match self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .store_mut()
                        .put(local_fallback_record)
                    {
                        Ok(_) => {
                            tracing::warn!(
                                target: "peer",
                                %err,
                                "dht put_record quorum not met, stored record locally as fallback",
                            );
                            let _ = response.send(Ok(()));
                        }
                        Err(store_err) => {
                            let _ = response.send(Err(DhtQueryError::Internal(format!(
                                "failed to start dht put_record query: {err}; local fallback failed: {store_err}"
                            ))));
                        }
                    },
                }
                Ok(false)
            }
            PeerCommand::GetDhtRecord { key, response } => {
                if key.is_empty() {
                    let _ = response.send(Err(DhtQueryError::Internal(
                        "dht get requires non-empty key".to_string(),
                    )));
                    return Ok(false);
                }
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .get_record(kad::RecordKey::new(&key));
                self.dht_get_queries.insert(query_id, response);
                tracing::info!(target: "peer", ?query_id, "started dht get_record query");
                Ok(false)
            }
            PeerCommand::StartFileTransfer {
                recipient,
                metadata,
                data,
                chunk_size,
            } => {
                self.handle_start_file_transfer(recipient, metadata, data, chunk_size);
                Ok(false)
            }
            PeerCommand::Shutdown => {
                tracing::info!(target: "peer", "shutdown requested");
                Ok(true)
            }
        }
    }

    // Builds and sends the Init/Chunk/Complete sequence for a file transfer.
    fn handle_start_file_transfer(
        &mut self,
        recipient: PeerId,
        metadata: FileMetadata,
        data: Vec<u8>,
        chunk_size: usize,
    ) {
        use sha2::{Digest, Sha256};

        let chunk_size = chunk_size_or_default(chunk_size).clamp(
            crate::messaging::DEFAULT_FILE_TRANSFER_CHUNK_SIZE,
            crate::messaging::MAX_FILE_TRANSFER_CHUNK_SIZE,
        );
        let total_chunks = data.chunks(chunk_size).len() as u64;
        let init_request_id = self.swarm.behaviour_mut().file_transfer.send_request(
            &recipient,
            FileTransferRequest {
                frame: FileTransferFrame::Init {
                    metadata: metadata.clone(),
                    chunk_size: chunk_size as u32,
                    total_chunks,
                },
            },
        );
        self.pending_file_transfer_requests.insert(init_request_id);

        for (index, chunk) in data.chunks(chunk_size).enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(chunk);
            let chunk_hash = hex::encode(hasher.finalize());
            let request_id = self.swarm.behaviour_mut().file_transfer.send_request(
                &recipient,
                FileTransferRequest {
                    frame: FileTransferFrame::Chunk {
                        metadata: crate::messaging::ChunkMetadata {
                            file_id: metadata.file_id.clone(),
                            chunk_index: index as u64,
                            offset: (index * chunk_size) as u64,
                            chunk_size: chunk.len() as u32,
                            chunk_hash,
                        },
                        data: chunk.to_vec(),
                    },
                },
            );
            self.pending_file_transfer_requests.insert(request_id);
        }

        let complete_request_id = self.swarm.behaviour_mut().file_transfer.send_request(
            &recipient,
            FileTransferRequest {
                frame: FileTransferFrame::Complete {
                    file_id: metadata.file_id,
                    total_chunks,
                    file_hash: metadata.hash,
                },
            },
        );
        self.pending_file_transfer_requests
            .insert(complete_request_id);
    }

    fn handle_delivery_tick(&mut self) {
        let now_unix = now_unix_seconds();
        let now_instant = Instant::now();

        self.prune_delivery_state(now_unix);
        self.process_pending_retries(now_unix, now_instant);

        if now_instant >= self.next_mailbox_fetch_at && !self.mailbox_enabled {
            let fetch = build_mailbox_fetch(&self.local_peer_id, now_unix);
            let relay_targets: Vec<PeerId> = self
                .relay_targets()
                .into_iter()
                .take(RELAY_READ_N.max(1))
                .collect();
            let required_r = RELAY_READ_R.min(relay_targets.len()).max(1);
            let mut sent = 0usize;
            for relay_peer_id in relay_targets {
                if self.send_direct_frame(
                    &relay_peer_id,
                    DeliveryFrame::MailboxFetch(fetch.clone()),
                    "sent mailbox fetch request via direct unicast",
                ) {
                    sent = sent.saturating_add(1);
                }
            }
            if sent < required_r {
                tracing::debug!(
                    target: "peer",
                    sent,
                    required_r,
                    "mailbox read quorum not reached for this fetch round",
                );
            }
            self.next_mailbox_fetch_at = now_instant + mailbox_fetch_next_interval();
        }
    }

    fn handle_publish_command(&mut self, payload: Vec<u8>) {
        let now_unix = now_unix_seconds();
        let sequence = self.next_delivery_sequence();
        let addressed = is_addressed_payload(payload.as_slice());
        if let Some(envelope) =
            build_envelope_from_payload(&self.local_peer_id, payload.as_slice(), sequence, now_unix)
        {
            let frame = DeliveryFrame::Envelope(envelope.clone());
            if let Some(recipient_peer_id) = envelope.recipient() {
                self.send_addressed_frame(
                    &recipient_peer_id,
                    frame,
                    "sent reliable envelope via direct unicast",
                );
            }
            if envelope.ack_required {
                self.pending_envelopes.insert(
                    envelope.envelope_id.clone(),
                    PendingEnvelope {
                        envelope,
                        next_retry_at: Instant::now() + DELIVERY_INITIAL_RETRY_DELAY,
                        retry_delay: DELIVERY_INITIAL_RETRY_DELAY,
                        stored_ack_received: false,
                    },
                );
            }
            return;
        }

        if addressed {
            tracing::warn!(
                target: "peer",
                "dropping addressed payload because strict E2EE mode requires payload_type=libsignal",
            );
            return;
        }

        self.publish_legacy_payload(payload);
    }

    fn publish_legacy_payload(&mut self, payload: Vec<u8>) {
        match self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.gossipsub_topic.clone(), payload)
        {
            Ok(_) => tracing::info!(target: "peer", "published legacy message"),
            Err(err) => tracing::warn!(target: "peer", %err, "failed to publish legacy message"),
        }
    }

    fn send_addressed_frame(
        &mut self,
        target_peer_id: &PeerId,
        frame: DeliveryFrame,
        direct_action: &str,
    ) -> bool {
        if self.connected_peers.contains(target_peer_id)
            && self.send_direct_frame(target_peer_id, frame.clone(), direct_action)
        {
            return true;
        }

        let relay_targets: Vec<PeerId> = self
            .relay_targets()
            .into_iter()
            .filter(|relay_peer_id| relay_peer_id != target_peer_id)
            .collect();

        if !matches!(frame, DeliveryFrame::Envelope(_)) {
            for relay_peer_id in relay_targets {
                if self.send_direct_frame(
                    &relay_peer_id,
                    frame.clone(),
                    "sent addressed frame to relay mailbox hop",
                ) {
                    return true;
                }
            }
            tracing::warn!(
                target: "peer",
                %target_peer_id,
                kind = ?frame,
                "failed to route addressed frame: no direct or relay path",
            );
            return false;
        }

        if relay_targets.is_empty() {
            tracing::warn!(
                target: "peer",
                %target_peer_id,
                kind = ?frame,
                "failed to route addressed envelope: no relay candidates",
            );
            return false;
        }

        let placement_n = RELAY_PLACEMENT_N.max(1);
        let selected_relays: Vec<PeerId> = relay_targets.into_iter().take(placement_n).collect();
        let required_w = RELAY_PLACEMENT_W.min(selected_relays.len()).max(1);
        let mut successes = 0usize;
        for relay_peer_id in selected_relays.iter() {
            if self.send_direct_frame(
                relay_peer_id,
                frame.clone(),
                "sent addressed envelope to relay mailbox hop",
            ) {
                successes = successes.saturating_add(1);
            }
        }

        if successes >= required_w {
            tracing::debug!(
                target: "peer",
                %target_peer_id,
                successes,
                required_w,
                "relay placement accepted envelope"
            );
            return true;
        }

        tracing::warn!(
            target: "peer",
            %target_peer_id,
            kind = ?frame,
            successes,
            required_w,
            "relay placement failed to satisfy write quorum",
        );
        false
    }

    fn relay_targets(&self) -> Vec<PeerId> {
        let mut targets = Vec::new();
        if let Some(relay_peer_id) = &self.relay_peer_id {
            if self.connected_peers.contains(relay_peer_id) {
                targets.push(relay_peer_id.clone());
            }
        }
        for peer_id in &self.bootstrap_peer_ids {
            if !self.connected_peers.contains(peer_id) {
                continue;
            }
            if !targets.contains(peer_id) {
                targets.push(peer_id.clone());
            }
        }
        targets
    }

    fn send_direct_frame(
        &mut self,
        recipient_peer_id: &PeerId,
        frame: DeliveryFrame,
        action: &str,
    ) -> bool {
        if !self.connected_peers.contains(recipient_peer_id) {
            tracing::debug!(
                target: "peer",
                %recipient_peer_id,
                "direct frame skipped because peer is not connected",
            );
            return false;
        }
        let Some(payload) = encode_frame(&frame) else {
            tracing::warn!(target: "peer", kind = ?frame, "failed to serialize direct delivery frame");
            return false;
        };
        let request_id = self
            .swarm
            .behaviour_mut()
            .delivery_direct
            .send_request(recipient_peer_id, DeliveryDirectRequest { payload });
        self.pending_direct_requests
            .insert(request_id, PendingDirectRequest { frame });
        tracing::debug!(
            target: "peer",
            %recipient_peer_id,
            ?request_id,
            %action,
            "direct delivery frame queued",
        );
        true
    }

    fn process_pending_retries(&mut self, now_unix: u64, now_instant: Instant) {
        let due_envelopes: Vec<String> = self
            .pending_envelopes
            .iter()
            .filter(|(_, pending)| pending.next_retry_at <= now_instant)
            .map(|(envelope_id, _)| envelope_id.clone())
            .collect();

        for envelope_id in due_envelopes {
            let Some(mut pending) = self.pending_envelopes.remove(&envelope_id) else {
                continue;
            };
            if pending.envelope.expires_at_unix <= now_unix {
                continue;
            }

            pending.envelope.attempt = pending.envelope.attempt.saturating_add(1);
            let retry_frame = DeliveryFrame::Envelope(pending.envelope.clone());
            if let Some(recipient_peer_id) = pending.envelope.recipient() {
                self.send_addressed_frame(
                    &recipient_peer_id,
                    retry_frame,
                    "retrying pending envelope via direct unicast",
                );
            }

            let next_delay = if pending.stored_ack_received {
                DELIVERY_MAX_RETRY_DELAY
            } else {
                let doubled = pending
                    .retry_delay
                    .checked_mul(2)
                    .unwrap_or(DELIVERY_MAX_RETRY_DELAY);
                if doubled > DELIVERY_MAX_RETRY_DELAY {
                    DELIVERY_MAX_RETRY_DELAY
                } else {
                    doubled
                }
            };
            pending.retry_delay = next_delay;
            pending.next_retry_at = now_instant + pending.retry_delay;
            self.pending_envelopes.insert(envelope_id, pending);
        }
    }

    fn prune_delivery_state(&mut self, now_unix: u64) {
        self.pending_envelopes
            .retain(|_, pending| pending.envelope.expires_at_unix > now_unix);
        self.delivered_envelopes
            .retain(|_, expires_at_unix| *expires_at_unix > now_unix);
        if let Some(store) = &self.mailbox_store {
            if let Err(err) = store.prune_expired(now_unix) {
                tracing::warn!(target: "peer", %err, "failed to prune persistent mailbox store");
            }
        }
        self.mailbox_queues.retain(|_, queue| {
            queue.retain(|stored| stored.envelope.expires_at_unix > now_unix);
            !queue.is_empty()
        });
    }

    fn handle_delivery_frame(&mut self, payload: &[u8], source_peer_id: &PeerId) -> bool {
        let Some(frame) = parse_frame(payload) else {
            return false;
        };

        match frame {
            DeliveryFrame::Envelope(envelope) => {
                self.handle_delivery_envelope(envelope, source_peer_id);
            }
            DeliveryFrame::Ack(ack) => {
                self.handle_delivery_ack(ack, source_peer_id);
            }
            DeliveryFrame::Nack(nack) => {
                self.handle_delivery_nack(nack, source_peer_id);
            }
            DeliveryFrame::MailboxFetch(fetch) => {
                self.handle_mailbox_fetch(fetch, source_peer_id);
            }
        }

        true
    }

    fn handle_delivery_envelope(&mut self, envelope: DeliveryEnvelope, source_peer_id: &PeerId) {
        let now_unix = now_unix_seconds();
        if envelope.expires_at_unix <= now_unix {
            self.send_nack_for_envelope(
                &envelope,
                DeliveryNackReason::Expired,
                None,
                source_peer_id,
            );
            return;
        }

        let Some(recipient_peer_id) = envelope.recipient() else {
            tracing::warn!(
                target: "peer",
                envelope_id = %envelope.envelope_id,
                "ignoring envelope with invalid recipient peer id",
            );
            self.send_nack_for_envelope(
                &envelope,
                DeliveryNackReason::InvalidRecipient,
                None,
                source_peer_id,
            );
            return;
        };

        if recipient_peer_id == self.local_peer_id {
            let already_delivered = self
                .delivered_envelopes
                .get(&envelope.envelope_id)
                .map(|expires_at| *expires_at > now_unix)
                .unwrap_or(false);

            if !already_delivered {
                if let Some(message_payload) = envelope.payload_bytes() {
                    if let Err(err) = self.inbound_sender.try_enqueue(message_payload) {
                        tracing::warn!(target: "peer", %err, "failed to enqueue inbound message");
                    } else {
                        self.delivered_envelopes.insert(
                            envelope.envelope_id.clone(),
                            envelope.expires_at_unix.max(now_unix + 60),
                        );
                    }
                } else {
                    tracing::warn!(
                        target: "peer",
                        envelope_id = %envelope.envelope_id,
                        "failed to decode envelope payload",
                    );
                    self.send_nack_for_envelope(
                        &envelope,
                        DeliveryNackReason::InvalidRecipient,
                        None,
                        source_peer_id,
                    );
                }
            }

            if envelope.ack_required {
                self.send_ack_for_envelope(&envelope, DeliveryAckKind::Delivered, now_unix);
            }
            return;
        }

        if !self.mailbox_enabled {
            return;
        }

        if envelope.sender_peer_id != source_peer_id.to_string() {
            // Store only sender-originated copies to avoid mailbox loops across relays.
            return;
        }

        match self.store_mailbox_envelope(recipient_peer_id, envelope.clone()) {
            MailboxStoreInsertOutcome::Stored | MailboxStoreInsertOutcome::Duplicate => {
                if envelope.ack_required {
                    self.send_ack_for_envelope(&envelope, DeliveryAckKind::Stored, now_unix);
                }
            }
            MailboxStoreInsertOutcome::QuotaExceeded => {
                self.send_nack_for_envelope(
                    &envelope,
                    DeliveryNackReason::QuotaExceeded,
                    Some(30),
                    source_peer_id,
                );
            }
        }
    }

    fn handle_delivery_ack(&mut self, ack: DeliveryAck, source_peer_id: &PeerId) {
        if ack.recipient_peer_id == self.local_peer_id.to_string() {
            match ack.ack_kind {
                DeliveryAckKind::Delivered => {
                    if let Some(pending) = self.pending_envelopes.remove(&ack.envelope_id) {
                        self.emit_delivery_status(
                            pending.envelope.recipient_peer_id.as_str(),
                            ack.envelope_id.as_str(),
                            "delivered",
                            None,
                        );
                        tracing::debug!(
                            target: "peer",
                            envelope_id = %ack.envelope_id,
                            "delivery ack received; removed pending envelope",
                        );
                    }
                }
                DeliveryAckKind::Stored => {
                    if let Some(pending) = self.pending_envelopes.get_mut(&ack.envelope_id) {
                        let recipient_peer_id = pending.envelope.recipient_peer_id.clone();
                        pending.stored_ack_received = true;
                        pending.retry_delay = DELIVERY_MAX_RETRY_DELAY;
                        pending.next_retry_at = Instant::now() + DELIVERY_MAX_RETRY_DELAY;
                        let _ = pending;
                        self.emit_delivery_status(
                            &recipient_peer_id,
                            ack.envelope_id.as_str(),
                            "stored",
                            None,
                        );
                        self.emit_delivery_status(
                            &recipient_peer_id,
                            ack.envelope_id.as_str(),
                            "stored",
                            None,
                        );
                        self.emit_delivery_status(&recipient_peer_id, ack.envelope_id.as_str(), "stored", None);
                        tracing::debug!(
                            target: "peer",
                            envelope_id = %ack.envelope_id,
                            "stored ack received; keeping envelope pending until delivered ack",
                        );
                    }
                }
            }
        }

        if ack.ack_kind == DeliveryAckKind::Delivered {
            if let Ok(mailbox_recipient) = ack.sender_peer_id.parse::<PeerId>() {
                self.remove_mailbox_envelope(&mailbox_recipient, &ack.envelope_id);
            }
        }

        if self.mailbox_enabled && ack.recipient_peer_id != self.local_peer_id.to_string() {
            if ack.sender_peer_id != source_peer_id.to_string() {
                tracing::debug!(
                    target: "peer",
                    envelope_id = %ack.envelope_id,
                    "ignoring ack relay-forward because source is not ack sender",
                );
                return;
            }
            if let Ok(target_peer_id) = ack.recipient_peer_id.parse::<PeerId>() {
                let _ = self.send_addressed_frame(
                    &target_peer_id,
                    DeliveryFrame::Ack(ack),
                    "forwarding delivery ack via relay direct",
                );
            }
        }
    }

    fn handle_delivery_nack(&mut self, nack: DeliveryNack, source_peer_id: &PeerId) {
        if nack.recipient_peer_id != self.local_peer_id.to_string() {
            if self.mailbox_enabled {
                if nack.sender_peer_id != source_peer_id.to_string() {
                    tracing::debug!(
                        target: "peer",
                        envelope_id = %nack.envelope_id,
                        "ignoring nack relay-forward because source is not nack sender",
                    );
                    return;
                }
                if let Ok(target_peer_id) = nack.recipient_peer_id.parse::<PeerId>() {
                    let _ = self.send_addressed_frame(
                        &target_peer_id,
                        DeliveryFrame::Nack(nack),
                        "forwarding delivery nack via relay direct",
                    );
                }
            }
            return;
        }
        let Some(mut pending) = self.pending_envelopes.remove(&nack.envelope_id) else {
            return;
        };

        match nack.reason {
            DeliveryNackReason::Expired | DeliveryNackReason::InvalidRecipient => {
                let reason = match nack.reason {
                    DeliveryNackReason::Expired => "expired",
                    DeliveryNackReason::InvalidRecipient => "invalid_recipient",
                    DeliveryNackReason::QuotaExceeded => "quota_exceeded",
                };
                self.emit_delivery_status(
                    pending.envelope.recipient_peer_id.as_str(),
                    nack.envelope_id.as_str(),
                    "failed",
                    Some(reason),
                );
                tracing::warn!(
                    target: "peer",
                    envelope_id = %nack.envelope_id,
                    reason = ?nack.reason,
                    "received terminal nack; dropping pending envelope",
                );
            }
            DeliveryNackReason::QuotaExceeded => {
                let retry_after = nack.retry_after_seconds.unwrap_or(15).clamp(3, 300);
                pending.next_retry_at = Instant::now() + Duration::from_secs(retry_after);
                pending.retry_delay = Duration::from_secs(retry_after);
                self.emit_delivery_status(
                    pending.envelope.recipient_peer_id.as_str(),
                    nack.envelope_id.as_str(),
                    "retrying",
                    Some("quota_exceeded"),
                );
                self.pending_envelopes
                    .insert(nack.envelope_id.clone(), pending);
                tracing::warn!(
                    target: "peer",
                    envelope_id = %nack.envelope_id,
                    retry_after,
                    "received quota_exceeded nack; scheduled retry",
                );
            }
        }
    }

    fn send_ack_for_envelope(
        &mut self,
        envelope: &DeliveryEnvelope,
        ack_kind: DeliveryAckKind,
        now_unix: u64,
    ) {
        let ack = build_ack(envelope, &self.local_peer_id, ack_kind, now_unix);
        let frame = DeliveryFrame::Ack(ack);
        if let Some(sender_peer_id) = envelope.sender() {
            let _ = self.send_addressed_frame(
                &sender_peer_id,
                frame,
                "sent delivery ack via direct unicast",
            );
        }
    }

    fn send_nack_for_envelope(
        &mut self,
        envelope: &DeliveryEnvelope,
        reason: DeliveryNackReason,
        retry_after_seconds: Option<u64>,
        source_peer_id: &PeerId,
    ) {
        let nack = build_nack(
            envelope,
            &self.local_peer_id,
            reason,
            retry_after_seconds,
            now_unix_seconds(),
        );
        let frame = DeliveryFrame::Nack(nack);
        if let Some(sender_peer_id) = envelope.sender() {
            let _ = self.send_addressed_frame(
                &sender_peer_id,
                frame,
                "sent delivery nack via direct unicast",
            );
        } else {
            let _ = self.send_addressed_frame(
                source_peer_id,
                frame,
                "sent delivery nack to source peer via direct unicast",
            );
        }
    }

    fn emit_delivery_status(
        &self,
        peer_id: &str,
        envelope_id: &str,
        status: &str,
        reason: Option<&str>,
    ) {
        let mut payload = serde_json::json!({
            "schema": "fidonext-delivery-status-v1",
            "peer_id": peer_id,
            "message_id": envelope_id,
            "status": status,
            "updated_at_unix": now_unix_seconds(),
        });
        if let Some(reason_value) = reason {
            payload["reason"] = serde_json::Value::String(reason_value.to_string());
        }
        match serde_json::to_vec(&payload) {
            Ok(bytes) => {
                if let Err(err) = self.inbound_sender.try_enqueue(bytes) {
                    tracing::debug!(target: "peer", %err, "failed to enqueue delivery status event");
                }
            }
            Err(err) => {
                tracing::debug!(target: "peer", %err, "failed to encode delivery status event");
            }
        }
    }

    fn handle_mailbox_fetch(&mut self, fetch: DeliveryMailboxFetch, source_peer_id: &PeerId) {
        if !self.mailbox_enabled {
            return;
        }
        if fetch.requester_peer_id != fetch.recipient_peer_id {
            return;
        }
        let Ok(requester_peer_id) = fetch.requester_peer_id.parse::<PeerId>() else {
            return;
        };
        if requester_peer_id != *source_peer_id {
            tracing::debug!(
                target: "peer",
                requester = fetch.requester_peer_id,
                source = %source_peer_id,
                "ignoring mailbox fetch with mismatched source peer",
            );
            return;
        }

        let limit = fetch.limit.clamp(1, MAILBOX_MAX_PER_RECIPIENT as u32) as usize;
        self.emit_mailbox_for_recipient(&requester_peer_id, limit);
    }

    fn store_mailbox_envelope(
        &mut self,
        recipient_peer_id: PeerId,
        envelope: DeliveryEnvelope,
    ) -> MailboxStoreInsertOutcome {
        if let Some(store) = &self.mailbox_store {
            let limits = MailboxStoreLimits {
                max_messages_per_recipient: MAILBOX_MAX_PER_RECIPIENT,
                max_bytes_per_recipient: MAILBOX_MAX_BYTES_PER_RECIPIENT,
            };
            return match store.store_envelope(&recipient_peer_id, &envelope, limits) {
                Ok(result) => result,
                Err(err) => {
                    tracing::warn!(
                        target: "peer",
                        %err,
                        recipient = %recipient_peer_id,
                        "failed to persist mailbox envelope",
                    );
                    MailboxStoreInsertOutcome::QuotaExceeded
                }
            };
        }

        let queue = self
            .mailbox_queues
            .entry(recipient_peer_id.clone())
            .or_default();
        if queue
            .iter()
            .any(|stored| stored.envelope.envelope_id == envelope.envelope_id)
        {
            return MailboxStoreInsertOutcome::Duplicate;
        }
        if queue.len() >= MAILBOX_MAX_PER_RECIPIENT {
            return MailboxStoreInsertOutcome::QuotaExceeded;
        }
        queue.push_back(StoredEnvelope { envelope });
        MailboxStoreInsertOutcome::Stored
    }

    fn remove_mailbox_envelope(&mut self, recipient_peer_id: &PeerId, envelope_id: &str) {
        if let Some(store) = &self.mailbox_store {
            if let Err(err) = store.remove_envelope(recipient_peer_id, envelope_id) {
                tracing::warn!(
                    target: "peer",
                    %err,
                    recipient = %recipient_peer_id,
                    envelope_id,
                    "failed to remove mailbox envelope from persistent store",
                );
            }
            return;
        }

        let mut should_remove_queue = false;
        if let Some(queue) = self.mailbox_queues.get_mut(recipient_peer_id) {
            queue.retain(|stored| stored.envelope.envelope_id != envelope_id);
            should_remove_queue = queue.is_empty();
        }
        if should_remove_queue {
            self.mailbox_queues.remove(recipient_peer_id);
        }
    }

    fn emit_mailbox_for_recipient(&mut self, recipient_peer_id: &PeerId, limit: usize) {
        let envelopes: Vec<DeliveryEnvelope> = if let Some(store) = &self.mailbox_store {
            match store.fetch_envelopes(recipient_peer_id, limit, now_unix_seconds()) {
                Ok(values) => values,
                Err(err) => {
                    tracing::warn!(
                        target: "peer",
                        %err,
                        recipient = %recipient_peer_id,
                        "failed to fetch mailbox envelopes from persistent store",
                    );
                    Vec::new()
                }
            }
        } else {
            self.mailbox_queues
                .get(recipient_peer_id)
                .map(|queue| {
                    queue
                        .iter()
                        .take(limit)
                        .map(|stored| stored.envelope.clone())
                        .collect()
                })
                .unwrap_or_default()
        };

        for envelope in envelopes {
            let _ = self.send_addressed_frame(
                recipient_peer_id,
                DeliveryFrame::Envelope(envelope),
                "sent mailbox envelope via direct unicast",
            );
        }
    }

    fn next_delivery_sequence(&mut self) -> u64 {
        self.delivery_sequence = self.delivery_sequence.saturating_add(1);
        self.delivery_sequence
    }

    /// Logging and reacting to events coming from the swarm (peer orchestrator)
    fn handle_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(event) => self.handle_behaviour_event(event),

            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!(target: "peer", %address, "listening on new address");

                self.emit_addr_event(AddrEvent::ListenerAdded {
                    address: address.clone(),
                });

                self.update_relay_address(address);
            }

            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.connected_peers.insert(peer_id.clone());
                tracing::info!(target: "peer", %peer_id, "connection established");
                if let Ok(query_id) = self.swarm.behaviour_mut().kademlia.bootstrap() {
                    tracing::debug!(
                        target: "peer",
                        ?query_id,
                        %peer_id,
                        "started kademlia bootstrap after connection established",
                    );
                }
            }

            SwarmEvent::ConnectionClosed {
                peer_id,
                cause,
                num_established,
                ..
            } => {
                if num_established == 0 {
                    self.connected_peers.remove(&peer_id);
                }
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

                self.emit_addr_event(AddrEvent::ExternalConfirmed {
                    address: address.clone(),
                });

                self.update_relay_address(address);
            }

            SwarmEvent::ExternalAddrExpired { address } => {
                tracing::warn!(target: "peer", %address, "external address expired");
                self.clear_relay_address(&address);

                self.emit_addr_event(AddrEvent::ExternalExpired {
                    address: address.clone(),
                });
            }

            SwarmEvent::ListenerClosed {
                addresses, reason, ..
            } => {
                tracing::warn!(target: "peer", ?addresses, ?reason, "listener closed");

                // ListenerClosed can contain multiple addresses. Emit removal for each.
                for address in addresses {
                    self.emit_addr_event(AddrEvent::ListenerRemoved { address });
                }
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

            BehaviourEvent::Identify(event) => match event {
                identify::Event::Received { peer_id, info, .. } => {
                    tracing::debug!(
                        target: "peer",
                        %peer_id,
                        listen_addrs = info.listen_addrs.len(),
                        protocols = info.protocols.len(),
                        "identify received",
                    );

                    let mut unique_addresses = HashSet::new();

                    for address in info.listen_addrs {
                        if let Some(normalized) =
                            self.valid_kademlia_address(&peer_id, &address, &mut unique_addresses)
                        {
                            self.add_kademlia_address(&peer_id, &normalized, "identify");
                        }
                    }
                }
                other => tracing::debug!(target: "peer", ?other, "identify event"),
            },

            BehaviourEvent::Gossipsub(event) => {
                if let gossipsub::Event::Message {
                    message,
                    propagation_source,
                    ..
                } = event
                {
                    tracing::info!(target: "peer", %propagation_source, len = message.data.len(), "received gossipsub message");
                    if parse_frame(message.data.as_slice()).is_some() {
                        tracing::debug!(
                            target: "peer",
                            %propagation_source,
                            "dropping delivery frame from gossipsub (strict addressed-direct mode)",
                        );
                        return;
                    }
                    if let Err(err) = self.inbound_sender.try_enqueue(message.data) {
                        tracing::warn!(target: "peer", %err, "failed to enqueue inbound message");
                    }
                }
            }

            BehaviourEvent::DeliveryDirect(event) => {
                self.handle_delivery_direct_event(event);
            }

            BehaviourEvent::FileTransfer(event) => {
                self.handle_file_transfer_event(event);
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

            BehaviourEvent::RendezvousClient(event) => {
                tracing::info!(target: "peer", ?event, "rendezvous client event");
            }

            BehaviourEvent::RendezvousServer(event) => {
                tracing::info!(target: "peer", ?event, "rendezvous server event");
            }
        }
    }

    fn handle_delivery_direct_event(
        &mut self,
        event: request_response::Event<DeliveryDirectRequest, DeliveryDirectResponse>,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request,
                    channel,
                    request_id,
                } => {
                    let accepted = self.handle_delivery_frame(request.payload.as_slice(), &peer);
                    if self
                        .swarm
                        .behaviour_mut()
                        .delivery_direct
                        .send_response(channel, DeliveryDirectResponse { accepted })
                        .is_err()
                    {
                        tracing::debug!(
                            target: "peer",
                            %peer,
                            ?request_id,
                            "failed to send direct delivery response",
                        );
                    }
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let _ = self.pending_direct_requests.remove(&request_id);
                    if !response.accepted {
                        tracing::warn!(
                            target: "peer",
                            %peer,
                            ?request_id,
                            "direct delivery request was not accepted by remote peer",
                        );
                    }
                }
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                tracing::warn!(
                    target: "peer",
                    %peer,
                    ?request_id,
                    %error,
                    "direct delivery outbound request failed",
                );
                if let Some(pending) = self.pending_direct_requests.remove(&request_id) {
                    tracing::debug!(
                        target: "peer",
                        kind = ?pending.frame,
                        "direct frame removed from pending after outbound failure",
                    );
                }
            }
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                tracing::warn!(
                    target: "peer",
                    %peer,
                    ?request_id,
                    %error,
                    "direct delivery inbound request failed",
                );
            }
            request_response::Event::ResponseSent {
                peer, request_id, ..
            } => {
                tracing::debug!(
                    target: "peer",
                    %peer,
                    ?request_id,
                    "direct delivery response sent",
                );
            }
        }
    }

    // Handles file-transfer protocol events and enqueues inbound frames into the dedicated queue.
    fn handle_file_transfer_event(
        &mut self,
        event: request_response::Event<FileTransferRequest, FileTransferResponse>,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request,
                    channel,
                    request_id,
                } => {
                    let frame = request.frame;
                    let enqueue_result =
                        self.file_transfer_sender
                            .try_enqueue(InboundFileTransferFrame {
                                from_peer: peer,
                                frame: frame.clone(),
                            });
                    let accepted = enqueue_result.is_ok();
                    if let Err(err) = enqueue_result {
                        tracing::warn!(target: "peer", %err, "failed to enqueue inbound file transfer frame");
                    }
                    if self
                        .swarm
                        .behaviour_mut()
                        .file_transfer
                        .send_response(channel, FileTransferResponse { accepted })
                        .is_err()
                    {
                        tracing::debug!(target: "peer", %peer, ?request_id, "failed to send file transfer response");
                    }

                    if let FileTransferFrame::Chunk { metadata, .. } = frame {
                        let ack_request_id = self.swarm.behaviour_mut().file_transfer.send_request(
                            &peer,
                            FileTransferRequest {
                                frame: FileTransferFrame::ChunkAck {
                                    file_id: metadata.file_id,
                                    chunk_index: metadata.chunk_index,
                                    next_expected_chunk: metadata.chunk_index.saturating_add(1),
                                },
                            },
                        );
                        self.pending_file_transfer_requests.insert(ack_request_id);
                    }
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    self.pending_file_transfer_requests.remove(&request_id);
                    if !response.accepted {
                        tracing::warn!(target: "peer", %peer, ?request_id, "file transfer request was rejected");
                    }
                }
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                self.pending_file_transfer_requests.remove(&request_id);
                tracing::warn!(target: "peer", %peer, ?request_id, %error, "file transfer outbound request failed");
            }
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                tracing::warn!(target: "peer", %peer, ?request_id, %error, "file transfer inbound request failed");
            }
            request_response::Event::ResponseSent {
                peer, request_id, ..
            } => {
                tracing::debug!(target: "peer", %peer, ?request_id, "file transfer response sent");
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
                QueryResult::PutRecord(res) => {
                    self.handle_put_record_result(id, res, step.last);
                }
                QueryResult::GetRecord(res) => {
                    self.handle_get_record_result(id, res, step.last);
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

    fn handle_put_record_result(
        &mut self,
        query_id: kad::QueryId,
        result: kad::PutRecordResult,
        is_last: bool,
    ) {
        let Some(pending) = self.dht_put_queries.remove(&query_id) else {
            return;
        };
        let PendingDhtPutQuery {
            response,
            fallback_record,
        } = pending;
        let outcome = match result {
            Ok(_) => Ok(()),
            Err(kad::PutRecordError::Timeout { .. }) => match self
                .swarm
                .behaviour_mut()
                .kademlia
                .store_mut()
                .put(fallback_record)
            {
                Ok(_) => {
                    tracing::warn!(
                        target: "peer",
                        ?query_id,
                        "dht put_record timed out, stored record locally as fallback",
                    );
                    Ok(())
                }
                Err(err) => Err(DhtQueryError::Internal(format!(
                    "dht put_record timed out and local fallback failed: {err}"
                ))),
            },
            Err(err) => Err(DhtQueryError::Internal(format!(
                "dht put_record failed: {err}"
            ))),
        };
        if response.send(outcome).is_err() {
            tracing::debug!(target: "peer", ?query_id, "dht put response receiver dropped");
        }
        if !is_last {
            tracing::debug!(target: "peer", ?query_id, "dht put query produced non-final step");
        }
    }

    fn handle_get_record_result(
        &mut self,
        query_id: kad::QueryId,
        result: kad::GetRecordResult,
        is_last: bool,
    ) {
        let Some(response) = self.dht_get_queries.remove(&query_id) else {
            return;
        };
        let outcome = match result {
            Ok(kad::GetRecordOk::FoundRecord(peer_record)) => Ok(peer_record.record.value),
            Ok(_) => Err(DhtQueryError::NotFound),
            Err(kad::GetRecordError::NotFound { .. }) => Err(DhtQueryError::NotFound),
            Err(kad::GetRecordError::QuorumFailed { .. }) => Err(DhtQueryError::NotFound),
            Err(kad::GetRecordError::Timeout { .. }) => Err(DhtQueryError::Timeout),
        };
        if response.send(outcome).is_err() {
            tracing::debug!(target: "peer", ?query_id, "dht get response receiver dropped");
        }
        if !is_last {
            tracing::debug!(target: "peer", ?query_id, "dht get query produced non-final step");
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
            let mut unique_addresses = HashSet::new();

            // Processing peer addresses
            for address in peer.addrs.iter().cloned() {
                let Some(address) =
                    self.valid_kademlia_address(&peer.peer_id, &address, &mut unique_addresses)
                else {
                    continue;
                };

                self.add_kademlia_address(&peer.peer_id, &address, "discovery");

                let next_allowed = self
                    .discovery_dial_backoff
                    .get(&peer.peer_id)
                    .and_then(|per_peer| per_peer.get(&address).copied());

                if let Some(next_allowed) = next_allowed {
                    if next_allowed > now {
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

                self.discovery_dial_backoff
                    .entry(peer.peer_id.clone())
                    .or_default()
                    .insert(address, now + DISCOVERY_DIAL_BACKOFF);
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

    /// Adds address to Kademlia networking
    fn add_kademlia_address(&mut self, peer_id: &PeerId, address: &Multiaddr, source: &str) {
        self.swarm
            .behaviour_mut()
            .kademlia
            .add_address(peer_id, address.clone());

        tracing::info!(
            target: "peer",
            %peer_id,
            %address,
            source,
            "added address to kademlia",
        );
    }

    // Processes address to find valid, and non dublicated
    fn valid_kademlia_address(
        &self,
        peer_id: &PeerId,
        address: &Multiaddr,
        unique_addresses: &mut HashSet<Multiaddr>,
    ) -> Option<Multiaddr> {
        if *peer_id == self.local_peer_id {
            tracing::debug!(
                target: "peer",
                %peer_id,
                %address,
                "skipping self address for kademlia",
            );
            return None;
        }

        let mut normalized = address.clone();
        match normalized.iter().last() {
            Some(Protocol::P2p(last_peer_id)) if last_peer_id == *peer_id => {
                normalized.pop();
            }
            Some(Protocol::P2p(last_peer_id)) => {
                tracing::debug!(
                    target: "peer",
                    %peer_id,
                    %address,
                    last_peer_id = %last_peer_id,
                    "skipping address with mismatched trailing peer id",
                );
                return None;
            }
            _ => {}
        }

        if normalized.is_empty() {
            tracing::debug!(
                target: "peer",
                %peer_id,
                %address,
                "skipping empty address for kademlia",
            );
            return None;
        }

        let relay_only = normalized
            .iter()
            .all(|protocol| matches!(protocol, Protocol::P2pCircuit));
        if relay_only {
            tracing::debug!(
                target: "peer",
                %peer_id,
                %address,
                "skipping relay-only address without base transport",
            );
            return None;
        }

        if !unique_addresses.insert(normalized.clone()) {
            tracing::debug!(
                target: "peer",
                %peer_id,
                %address,
                normalized = %normalized,
                "skipping duplicate address",
            );
            return None;
        }

        Some(normalized)
    }

    // Adding bootstraps into node's DHT initial network
    fn add_bootstrap_peers(&mut self, peers: Vec<Multiaddr>) {
        let mut added = 0usize;

        for mut addr in peers {
            let peer_component = addr.pop();
            match peer_component {
                Some(libp2p::multiaddr::Protocol::P2p(peer_id)) => {
                    if !self.bootstrap_peer_ids.contains(&peer_id) {
                        self.bootstrap_peer_ids.push(peer_id.clone());
                    }
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

            let changed = self.relay_base_address.as_ref() != Some(&base_address);
            if changed {
                // Creating rachable addr of the current peer 
                // <relay_base>/p2p-circuit/p2p/<yourPeerId>
                let mut reachable = base_address.clone();
                reachable.push(Protocol::P2pCircuit);
                reachable.push(Protocol::P2p(self.local_peer_id.clone()));

                self.emit_addr_event(AddrEvent::RelayReachableReady { address: reachable });
            }

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

                // relay reachable snapshot clear
                self.emit_addr_event(AddrEvent::RelayReachableLost);
            }
        }
    }

    fn emit_addr_event(&mut self, ev: AddrEvent) {
        if let Ok(mut st) = self.addr_state.write() {
            st.apply(&ev);
        } else {
            tracing::warn!(target:"peer", "addr_state lock poisoned");
        }

        tracing::debug!(target:"peer", ?ev, "addr event");
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
        // .../p2p-circuit/p2p/<local> Format of addr
        (Some(Protocol::P2p(local)), Some(Protocol::P2pCircuit)) if local == *local_peer_id => {
            match addr.iter().last() {
                Some(Protocol::P2p(relay_peer_id)) => Some((addr, relay_peer_id.clone())),
                _ => None,
            }
        }

        // .../p2p-circuit Format of addr
        (Some(Protocol::P2pCircuit), _) => {
            // addr is already popped, so need to take address from param 
            // and use it as a base
            let mut base = address.clone();
            base.pop(); // poping p2p-circuit

            match base.iter().last() {
                Some(Protocol::P2p(relay_peer_id)) => Some((base, relay_peer_id.clone())),
                _ => None,
            }
        }
        
        _ => None,
    }
}