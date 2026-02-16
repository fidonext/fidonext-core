//! Libp2p transport and behaviour configuration.

use anyhow::{anyhow, Result};
use futures::future::Either;
use libp2p::{
    autonat,
    core::{
        muxing::StreamMuxerBox,
        transport::{Boxed, Transport},
        upgrade,
    },
    gossipsub, identify, identity,
    kad::{self, store::MemoryStore},
    noise, ping, quic, relay, rendezvous,
    request_response,
    swarm::behaviour::toggle::Toggle,
    swarm::{Config as SwarmConfig, Swarm},
    tcp, PeerId, StreamProtocol,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Combined libp2p behaviour used across the node.
#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(to_swarm = "BehaviourEvent")]
pub struct NetworkBehaviour {
    /// Kademlia DHT behaviour for peer discovery
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// Ping behaviour to keep connections alive and measure latency
    pub ping: ping::Behaviour,
    /// Identify protocol for exchanging supported protocols and addresses
    pub identify: identify::Behaviour,
    /// AutoNAT behaviour to probe for public reachability
    pub autonat: autonat::Behaviour,
    /// Gossipsub for simple message propagation
    pub gossipsub: gossipsub::Behaviour,
    /// Relay client for connecting through hop relays.
    pub relay_client: relay::client::Behaviour,
    /// Optional relay server (hop) behaviour for acting as a public relay.
    pub relay_server: Toggle<relay::Behaviour>,
    /// Optional Rendezvous client for asking for a catalog of peers 
    pub rendezvous_client: Toggle<rendezvous::client::Behaviour>,
    /// Optional Rendezvous server for storing and sharing catalog of peers
    pub rendezvous_server: Toggle<rendezvous::server::Behaviour>,
    /// Direct unicast request-response channel for addressed delivery frames.
    pub delivery_direct:
        request_response::cbor::Behaviour<DeliveryDirectRequest, DeliveryDirectResponse>,
}

/// Event type produced by the composed [`NetworkBehaviour`].
#[derive(Debug)]
pub enum BehaviourEvent {
    Kademlia(kad::Event),
    Ping(ping::Event),
    /// Appears on creating connection and handshake on identity
    Identify(identify::Event),
    Autonat(autonat::Event),
    Gossipsub(gossipsub::Event),
    RelayClient(relay::client::Event),
    RelayServer(relay::Event),
    RendezvousClient(rendezvous::client::Event),
    RendezvousServer(rendezvous::server::Event),
    DeliveryDirect(request_response::Event<DeliveryDirectRequest, DeliveryDirectResponse>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryDirectRequest {
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryDirectResponse {
    pub accepted: bool,
}

impl From<kad::Event> for BehaviourEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kademlia(event)
    }
}

impl From<ping::Event> for BehaviourEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<identify::Event> for BehaviourEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<autonat::Event> for BehaviourEvent {
    fn from(event: autonat::Event) -> Self {
        Self::Autonat(event)
    }
}

impl From<gossipsub::Event> for BehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        Self::Gossipsub(event)
    }
}

impl From<relay::client::Event> for BehaviourEvent {
    fn from(event: relay::client::Event) -> Self {
        Self::RelayClient(event)
    }
}

impl From<relay::Event> for BehaviourEvent {
    fn from(event: relay::Event) -> Self {
        Self::RelayServer(event)
    }
}

impl From<rendezvous::client::Event> for BehaviourEvent {
    fn from(event: rendezvous::client::Event) -> Self {
        Self::RendezvousClient(event)
    }
}

impl From<rendezvous::server::Event> for BehaviourEvent {
    fn from(event: rendezvous::server::Event) -> Self {
        Self::RendezvousServer(event)
    }
}

impl From<request_response::Event<DeliveryDirectRequest, DeliveryDirectResponse>> for BehaviourEvent {
    fn from(event: request_response::Event<DeliveryDirectRequest, DeliveryDirectResponse>) -> Self {
        Self::DeliveryDirect(event)
    }
}

/// Transport configuration builder.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// When set, enable QUIC support alongside TCP.
    pub use_quic: bool,
    /// Controls whether the node should also act as a hop relay.
    pub hop_relay: bool,
    /// Controls whether rendezvous behaviours are enabled.
    pub enable_rendezvous: bool,
    /// Optional seed for deriving an exact Ed25519 identity keypair.
    pub identity_seed: Option<[u8; 32]>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            use_quic: false,     // Turn on for quic
            hop_relay: false,    // Turn on for node act as relay (at least try)
            enable_rendezvous: false, // FEATURE NOT USED. Turn on for rendezvous client/server
            identity_seed: None, // Pass to use identity seed for generating keypair
        }
    }
}

impl TransportConfig {
    /// Creates a new configuration with the provided flags.
    pub fn new(use_quic: bool, hop_relay: bool) -> Self {
        Self {
            use_quic,
            hop_relay,
            ..Default::default()
        }
    }

    /// Sets a exact seed for the Ed25519 identity keypair.
    /// Using the same seed yields the same `PeerId` and
    /// predictable connection paths (e.g., for tests or reproducible setups).
    pub fn with_identity_seed(mut self, seed: [u8; 32]) -> Self {
        self.identity_seed = Some(seed);
        self
    }


    /// Enables or disables rendezvous client/server behaviours.
    pub fn with_rendezvous_enabled(mut self, enable: bool) -> Self {
        self.enable_rendezvous = enable;
        self
    }

    /// Builds the swarm using the provided configuration.
    pub fn build(&self) -> Result<(identity::Keypair, Swarm<NetworkBehaviour>)> {
        let keypair = if let Some(seed) = self.identity_seed {
            let secret = identity::ed25519::SecretKey::try_from_bytes(seed)
                .map_err(|err| anyhow!("invalid ed25519 seed provided: {err}"))?;
            let keypair = identity::ed25519::Keypair::from(secret);
            identity::Keypair::from(keypair)
        } else {
            identity::Keypair::generate_ed25519()
        };
        let local_peer_id = PeerId::from(keypair.public());
        let (transport, relay_client) = self.build_transport(&keypair, local_peer_id)?;
        let behaviour = Self::build_behaviour(
            &keypair,
            relay_client,
            self.hop_relay,
            self.enable_rendezvous,
        );

        let swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            SwarmConfig::with_tokio_executor(),
        );

        Ok((keypair, swarm))
    }

    /// Constructs the composite network behaviour using the supplied keypair
    fn build_behaviour(
        keypair: &identity::Keypair,
        relay_client: relay::client::Behaviour,
        hop_relay: bool,
        enable_rendezvous: bool,
    ) -> NetworkBehaviour {
        let peer_id = PeerId::from(keypair.public());
        let mut kad_config = kad::Config::default();
        kad_config.set_query_timeout(Duration::from_secs(5));
        let store = MemoryStore::new(peer_id);

        let ping_config = ping::Config::new();
        let identify_config = identify::Config::new("/cabi/1.0.0".into(), keypair.public())
            .with_interval(Duration::from_secs(30));
        let autonat_config = autonat::Config::default();

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .build()
            .expect("valid gossipsub config");

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .expect("gossipsub behaviour");

        let relay_server = if hop_relay {
            Toggle::from(Some(relay::Behaviour::new(
                peer_id,
                relay::Config::default(),
            )))
        } else {
            Toggle::from(None)
        };

        let mut kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);
        kademlia.set_mode(Some(kad::Mode::Server));

        let rendezvous_client = if enable_rendezvous {
            Toggle::from(Some(rendezvous::client::Behaviour::new(
                keypair.clone(),
            )))
        } else {
            Toggle::from(None)
        };

        let rendezvous_server = if hop_relay {
            Toggle::from(
                Some(rendezvous::server::Behaviour::new(rendezvous::server::Config::default()))
            )
        } else {
            Toggle::from(None)
        };

        let direct_cfg =
            request_response::Config::default().with_request_timeout(Duration::from_secs(8));
        let delivery_direct = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::new("/fidonext/delivery-direct/1.0.0"),
                request_response::ProtocolSupport::Full,
            )],
            direct_cfg,
        );

        NetworkBehaviour {
            kademlia,
            ping: ping::Behaviour::new(ping_config),
            identify: identify::Behaviour::new(identify_config),
            autonat: autonat::Behaviour::new(peer_id, autonat_config),
            gossipsub,
            relay_client,
            relay_server,
            rendezvous_client,
            rendezvous_server,
            delivery_direct,
        }
    }

    /// Builds the transport stack using TCP and optionally QUIC and Relay
    fn build_transport(
        &self,
        keypair: &identity::Keypair,
        local_peer_id: PeerId,
    ) -> Result<(Boxed<(PeerId, StreamMuxerBox)>, relay::client::Behaviour)> {
        let noise_config = noise::Config::new(keypair)
            .map_err(|err| anyhow!("failed to create noise config: {err}"))?;

        let tcp_transport = Self::build_tcp_transport(noise_config.clone())?;

        let base_transport = if self.use_quic {
            let quic_transport = Self::build_quic_transport(keypair);
            quic_transport
                .or_transport(tcp_transport)
                .map(|either, _| match either {
                    Either::Left(output) | Either::Right(output) => output,
                })
                .boxed()
        } else {
            tcp_transport
        };

        let (relay_transport, relay_client) =
            Self::build_relay_transport(noise_config.clone(), local_peer_id);

        Ok((
            relay_transport
                .or_transport(base_transport)
                .map(|either, _| match either {
                    Either::Left(output) | Either::Right(output) => output,
                })
                .boxed(),
            relay_client,
        ))
    }

    /// Configures TCP with Noise authentication and Yamux multiplexing
    fn build_tcp_transport(noise_config: noise::Config) -> Result<Boxed<(PeerId, StreamMuxerBox)>> {
        let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default());
        Ok(tcp_transport
            .upgrade(upgrade::Version::V1Lazy)
            .authenticate(noise_config)
            .multiplex(libp2p::yamux::Config::default())
            .boxed())
    }

    /// Configures QUIC transport for encrypted, multiplexed streams
    fn build_quic_transport(keypair: &identity::Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
        let quic_config = quic::Config::new(keypair);

        quic::tokio::Transport::new(quic_config)
            .map(|(peer_id, connection), _| (peer_id, StreamMuxerBox::new(connection)))
            .boxed()
    }

    /// Configures Relay transport
    fn build_relay_transport(
        noise_config: noise::Config,
        local_peer_id: PeerId,
    ) -> (Boxed<(PeerId, StreamMuxerBox)>, relay::client::Behaviour) {
        let (relay_transport, relay_client) = relay::client::new(local_peer_id);

        let relay_transport = relay_transport
            .upgrade(upgrade::Version::V1Lazy)
            .authenticate(noise_config)
            .multiplex(libp2p::yamux::Config::default())
            .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
            .boxed();

        (relay_transport, relay_client)
    }
}
