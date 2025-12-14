//! Libp2p transport and behaviour configuration.

use anyhow::{anyhow, Result};
use futures::future::Either;
use libp2p::{
    core::{
        muxing::StreamMuxerBox,
        transport::{Boxed, Transport},
        upgrade,
    },
    gossipsub,
    identify, identity,
    kad::{self, store::MemoryStore},
    noise, ping, quic,
    swarm::{Config as SwarmConfig, Swarm},
    tcp, PeerId, autonat, 
    relay, swarm::behaviour::toggle::Toggle,
};
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
}

/// Event type produced by the composed [`NetworkBehaviour`].
#[derive(Debug)]
pub enum BehaviourEvent {
    Kademlia(kad::Event),
    Ping(ping::Event),
    Identify(identify::Event),
    Autonat(autonat::Event),
    Gossipsub(gossipsub::Event),
    RelayClient(relay::client::Event),
    RelayServer(relay::Event),
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

/// Transport configuration builder.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// When set, enable QUIC support alongside TCP.
    pub use_quic: bool,
    /// Controls whether the node should also act as a hop relay.
    pub hop_relay: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            use_quic: false, // Turn on for quic
            hop_relay: false, // Turn on for node act as relay (at least try)
        }
    }
}

impl TransportConfig {
    /// Builds the swarm using the provided configuration.
    pub fn build(&self) -> Result<(identity::Keypair, Swarm<NetworkBehaviour>)> {
        let keypair = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(keypair.public());
        let (transport, relay_client) = self.build_transport(&keypair, local_peer_id)?;
        let behaviour = Self::build_behaviour(&keypair, relay_client, self.hop_relay);
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
            .validation_mode(gossipsub::ValidationMode::None)
            .heartbeat_interval(Duration::from_secs(5))
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

        NetworkBehaviour {
            kademlia: kad::Behaviour::with_config(peer_id, store, kad_config),
            ping: ping::Behaviour::new(ping_config),
            identify: identify::Behaviour::new(identify_config),
            autonat: autonat::Behaviour::new(peer_id, autonat_config),
            gossipsub,
            relay_client,
            relay_server,
        }
    }

    /// Builds the transport stack using TCP and optionally QUIC and Relay
    fn build_transport(
        &self,
        keypair: &identity::Keypair,
        local_peer_id: PeerId,
    ) -> Result<(
        Boxed<(PeerId, StreamMuxerBox)>,
        relay::client::Behaviour,
     )> {
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
    ) -> (
        Boxed<(PeerId, StreamMuxerBox)>,
        relay::client::Behaviour,
    ) {
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