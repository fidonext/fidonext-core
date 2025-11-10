//! Libp2p transport and behaviour configuration.

use anyhow::{anyhow, Result};
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade},
    identify, identity,
    kad::{store::MemoryStore, Kademlia, KademliaConfig},
    noise, ping, quic,
    swarm::Swarm,
    tcp,
    transport::{Transport, TransportExt},
    PeerId,
};
use std::time::Duration;

/// Combined libp2p behaviour used across the node.
#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(to_swarm = "BehaviourEvent")]
pub struct NetworkBehaviour {
    pub kademlia: Kademlia<MemoryStore>,
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
}

/// Event type produced by the composed [`NetworkBehaviour`].
pub type BehaviourEvent = <NetworkBehaviour as libp2p::swarm::NetworkBehaviour>::ToSwarm;

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
        let swarm = Swarm::with_tokio_executor(transport, behaviour, local_peer_id);
        Ok((keypair, swarm))
    }

    fn build_behaviour(keypair: &identity::Keypair) -> NetworkBehaviour {
        let peer_id = PeerId::from(keypair.public());
        let mut kad_config = KademliaConfig::default();
        kad_config.set_query_timeout(Duration::from_secs(5));
        let store = MemoryStore::new(peer_id);

        let ping_config = ping::Config::new().with_keep_alive(true);
        let identify_config = identify::Config::new("/cabi/1.0.0".into(), keypair.public())
            .with_interval(Duration::from_secs(30));

        NetworkBehaviour {
            kademlia: Kademlia::with_config(peer_id, store, kad_config),
            ping: ping::Behaviour::new(ping_config),
            identify: identify::Behaviour::new(identify_config),
        }
    }

    fn build_transport(
        &self,
        keypair: &identity::Keypair,
    ) -> Result<Boxed<(PeerId, StreamMuxerBox)>> {
        let tcp_transport = Self::build_tcp_transport(keypair)?;
        
        if self.use_quic {
            let quic_transport = Self::build_quic_transport(keypair);
            Ok(quic_transport.or_transport(tcp_transport).boxed())
        } else {
            Ok(tcp_transport)
        }
    }

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

    fn build_quic_transport(keypair: &identity::Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
        let quic_config = quic::Config::new(keypair);

        quic::tokio::Transport::new(quic_config)
            .map(|(peer_id, connection), _| (peer_id, StreamMuxerBox::new(connection)))
            .boxed()
    }
}