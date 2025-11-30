//! Libp2p transport and behaviour configuration.

use anyhow::{anyhow, Result};
use futures::future::Either;
use libp2p::{
    core::{
        muxing::StreamMuxerBox,
        transport::{Boxed, Transport},
        upgrade,
    },
    identify, identity,
    kad::{self, store::MemoryStore},
    noise, ping, quic,
    swarm::{Config as SwarmConfig, Swarm},
    tcp, PeerId, autonat,
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
}

/// Event type produced by the composed [`NetworkBehaviour`].
#[derive(Debug)]
pub enum BehaviourEvent {
    Kademlia(kad::Event),
    Ping(ping::Event),
    Identify(identify::Event),
    Autonat(autonat::Event),
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

/// Transport configuration builder.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// When set, enable QUIC support alongside TCP.
    pub use_quic: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self { use_quic: false } // Turn on for quic
    }
}

impl TransportConfig {
    /// Builds the swarm using the provided configuration.
    pub fn build(&self) -> Result<(identity::Keypair, Swarm<NetworkBehaviour>)> {
        let keypair = identity::Keypair::generate_ed25519();
        let transport = self.build_transport(&keypair)?;
        let behaviour = Self::build_behaviour(&keypair);
        let local_peer_id = PeerId::from(keypair.public());
        let swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            SwarmConfig::with_tokio_executor(),
        );
        Ok((keypair, swarm))
    }

    /// Constructs the composite network behaviour using the supplied keypair
    fn build_behaviour(keypair: &identity::Keypair) -> NetworkBehaviour {
        let peer_id = PeerId::from(keypair.public());
        let mut kad_config = kad::Config::default();
        kad_config.set_query_timeout(Duration::from_secs(5));
        let store = MemoryStore::new(peer_id);

        let ping_config = ping::Config::new();
        let identify_config = identify::Config::new("/cabi/1.0.0".into(), keypair.public())
            .with_interval(Duration::from_secs(30));
        let autonat_config = autonat::Config::default();

        NetworkBehaviour {
            kademlia: kad::Behaviour::with_config(peer_id, store, kad_config),
            ping: ping::Behaviour::new(ping_config),
            identify: identify::Behaviour::new(identify_config),
            autonat: autonat::Behaviour::new(peer_id, autonat_config),
        }
    }

    /// Builds the transport stack using TCP and optionally QUIC
    fn build_transport(
        &self,
        keypair: &identity::Keypair,
    ) -> Result<Boxed<(PeerId, StreamMuxerBox)>> {
        let tcp_transport = Self::build_tcp_transport(keypair)?;

        if self.use_quic {
            let quic_transport = Self::build_quic_transport(keypair);
            Ok(quic_transport
                .or_transport(tcp_transport)
                .map(|either, _| match either {
                    Either::Left(output) | Either::Right(output) => output,
                })
                .boxed())
        } else {
            Ok(tcp_transport)
        }
    }

    /// Configures TCP with Noise authentication and Yamux multiplexing
    fn build_tcp_transport(keypair: &identity::Keypair) -> Result<Boxed<(PeerId, StreamMuxerBox)>> {
        let noise_config = noise::Config::new(keypair)
            .map_err(|err| anyhow!("failed to create noise config: {err}"))?;

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
}
