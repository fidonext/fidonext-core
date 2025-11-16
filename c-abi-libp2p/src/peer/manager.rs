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
    identity,
    swarm::{Swarm, SwarmEvent},
    PeerId,
};
use tokio::sync::mpsc;

use crate::transport::{BehaviourEvent, NetworkBehaviour, TransportConfig};

/// Commands supported by the [`PeerManager`] event loop.
#[derive(Debug)]
pub enum PeerCommand {
    /// Start listening on the provided multi-address.
    StartListening(Multiaddr),
    /// Dial the given remote multi-address.
    Dial(Multiaddr),
    /// Shut the manager down gracefully.
    Shutdown,
}

/// Handle that allows callers to enqueue [`PeerCommand`]s.
#[derive(Clone, Debug)]
pub struct PeerManagerHandle {
    command_sender: mpsc::Sender<PeerCommand>,
}

impl PeerManagerHandle {
    /// Enqueues a command to start listening on the given address.
    pub async fn start_listening(&self, address: Multiaddr) -> Result<()> {
        self.command_sender
            .send(PeerCommand::StartListening(address))
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

    /// Enqueues the shutdown command.
    pub async fn shutdown(&self) -> Result<()> {
        self.command_sender
            .send(PeerCommand::Shutdown)
            .await
            .map_err(|err| anyhow!("peer manager command channel closed: {err}"))
    }
}

/// Manages the libp2p swarm and exposes a command-driven control loop.
pub struct PeerManager {
    swarm: Swarm<NetworkBehaviour>,
    command_receiver: mpsc::Receiver<PeerCommand>,
    local_peer_id: PeerId,
    keypair: identity::Keypair,
}

impl PeerManager {
    /// Creates a new [`PeerManager`] instance alongside a [`PeerManagerHandle`].
    pub fn new(config: TransportConfig) -> Result<(Self, PeerManagerHandle)> {
        let (keypair, swarm) = config.build()?;
        let local_peer_id = PeerId::from(keypair.public());
        let (command_sender, command_receiver) = mpsc::channel(32);

        let manager = Self {
            swarm,
            command_receiver,
            local_peer_id,
            keypair,
        };

        let handle = PeerManagerHandle { command_sender };
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
            PeerCommand::Shutdown => {
                tracing::info!(target: "peer", "shutdown requested");
                Ok(true)
            }
        }
    }

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
            }
            _ => {}
        }
    }

    fn handle_behaviour_event(&mut self, event: BehaviourEvent) {
        match event {
            BehaviourEvent::Kademlia(event) => {
                tracing::debug!(target: "peer", ?event, "kademlia event");
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
        }
    }
}