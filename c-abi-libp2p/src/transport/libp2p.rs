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
    noise, ping, quic, relay, rendezvous, request_response,
    swarm::behaviour::toggle::Toggle,
    swarm::{Config as SwarmConfig, Swarm},
    tcp, websocket, PeerId, StreamProtocol,
};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::time::Duration;

use crate::messaging::FileTransferFrame;

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
    /// Dedicated stream-oriented protocol for file transfer bulk payloads.
    pub file_transfer: request_response::cbor::Behaviour<FileTransferRequest, FileTransferResponse>,
    /// Small request-response channel for fetching a content-addressed blob by
    /// its SHA-256 (TD-06 / §15). Runs on its own protocol
    /// `/fidonext/blob-fetch/1.0.0` so it never blocks a long file transfer
    /// and cannot be confused with the chunked file-transfer
    /// init/chunk/complete flow. The avatar fetch (TD-06) is the first
    /// handler-level policy on top of this generic primitive; M6.1
    /// channel-event-by-CID and future small-content-by-hash fetches reuse
    /// the same behaviour with a different server-side policy.
    pub blob_fetch: request_response::cbor::Behaviour<BlobFetchRequest, BlobFetchResponse>,
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
    FileTransfer(request_response::Event<FileTransferRequest, FileTransferResponse>),
    BlobFetch(request_response::Event<BlobFetchRequest, BlobFetchResponse>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryDirectRequest {
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryDirectResponse {
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransferRequest {
    pub frame: FileTransferFrame,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransferResponse {
    pub accepted: bool,
}

/// Generic content-addressed blob-fetch request (TD-06 / §15). Carries the
/// 32-byte SHA-256 of the blob the requester wants. The responder either
/// replies with `BlobFetchResponse::Ok` if it is willing to serve a blob whose
/// bytes hash to that digest under the handler-level policy for the remote
/// peer, or with `NotFound` otherwise. The avatar-fetch TD-06 policy ("I only
/// serve my own self-avatar") is one such handler; additional policies
/// (channel-event-by-CID, sticker packs, link previews) ride the same wire.
///
/// Field name is kept as `avatar_sha256` for wire compatibility with
/// `/fidonext/blob-fetch/1.0.0` as introduced in commit `dbfc7d6`; renaming it
/// would be a real wire break. Field semantics are "content-addressed hash of
/// the requested blob", independent of what content class the handler serves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobFetchRequest {
    pub avatar_sha256: Vec<u8>,
}

/// Generic blob-fetch response (TD-06 / §15). `Ok.data` carries the raw blob
/// bytes (size capped by the handler-level policy; for the avatar handler
/// this is 64 KiB, enforced by the caller before we even reach the wire).
/// `NotFound` signals the responder has no blob matching the requested hash
/// under its active policy. The requester re-verifies
/// `SHA-256(data) == requested_hash` before surfacing the bytes to the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlobFetchResponse {
    Ok { data: Vec<u8> },
    NotFound,
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

impl From<request_response::Event<DeliveryDirectRequest, DeliveryDirectResponse>>
    for BehaviourEvent
{
    fn from(event: request_response::Event<DeliveryDirectRequest, DeliveryDirectResponse>) -> Self {
        Self::DeliveryDirect(event)
    }
}

impl From<request_response::Event<FileTransferRequest, FileTransferResponse>> for BehaviourEvent {
    fn from(event: request_response::Event<FileTransferRequest, FileTransferResponse>) -> Self {
        Self::FileTransfer(event)
    }
}

impl From<request_response::Event<BlobFetchRequest, BlobFetchResponse>> for BehaviourEvent {
    fn from(event: request_response::Event<BlobFetchRequest, BlobFetchResponse>) -> Self {
        Self::BlobFetch(event)
    }
}

/// Transport configuration builder.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// When set, enable QUIC support alongside TCP.
    pub use_quic: bool,
    /// When set, enable WebSocket transport (/ws multiaddrs) alongside TCP.
    pub use_websocket: bool,
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
            use_quic: false,          // Turn on for quic
            use_websocket: false,     // Turn on for ws transport (wss via reverse-proxy)
            hop_relay: false,         // Turn on for node act as relay (at least try)
            enable_rendezvous: false, // FEATURE NOT USED. Turn on for rendezvous client/server
            identity_seed: None,      // Pass to use identity seed for generating keypair
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
        // TD-18: bumped from 5 s -> 15 s. On the two-relay test fleet the
        // DHT routing table routinely carries < 3 peers, and a 5 s
        // query_timeout was tight enough that profile-record `get_record`
        // rounds regularly hit `DhtQueryError::Timeout` before Kademlia
        // finished walking the sparse routing table (QA scenario 2,
        // 2026-04-20). 15 s is a simple, non-adaptive bump — tighten back
        // once the fleet grows or once we add peer-count-aware adaptive
        // timeouts.
        kad_config.set_query_timeout(Duration::from_secs(15));
        // TD-26: right-size Kademlia replication factor to the realistic fleet
        // size. Default K=20 combined with `Quorum::Majority` in
        // `start_dht_put` would demand 11 confirmations — impossible on our
        // current 2–3-super-peer test fleet (TD-25a observed 2 relays plus 1
        // off-inventory peer), which would force every publish into the
        // QuorumFailed branch and regress worse than the pre-TD-26
        // single-replica reality. K=3 matches the observed swarm size and
        // yields `Majority = 2` — i.e. two replicas must confirm the put. When
        // the fleet grows past 3 super-peers, bump this to match and/or move
        // to an adaptive value; libp2p's default K=20 assumes a large public
        // DHT that we are not (yet) running.
        kad_config.set_replication_factor(NonZeroUsize::new(3).expect("3 != 0"));
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
            Toggle::from(Some(rendezvous::client::Behaviour::new(keypair.clone())))
        } else {
            Toggle::from(None)
        };

        let rendezvous_server = if hop_relay {
            Toggle::from(Some(rendezvous::server::Behaviour::new(
                rendezvous::server::Config::default(),
            )))
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

        let file_transfer = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::new("/fidonext/file-transfer/1.0.0"),
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
        );

        // TD-06 / §15: small generic blob-fetch channel. 8 s timeout is enough
        // for a <=64 KiB blob over relay and short enough to unblock the UI
        // quickly on cold peers. Separate protocol so it does not share the
        // 30 s timeout with the (bulk) file-transfer protocol. The protocol
        // is content-class-agnostic on the wire; per-content policy
        // (avatar-only, channel-event-only, ...) is enforced in the handler.
        let blob_fetch = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::new("/fidonext/blob-fetch/1.0.0"),
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default().with_request_timeout(Duration::from_secs(8)),
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
            file_transfer,
            blob_fetch,
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

        let mut base_transport: Boxed<(PeerId, StreamMuxerBox)> = if self.use_quic {
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

        if self.use_websocket {
            let ws_transport = Self::build_ws_transport(noise_config.clone())?;
            base_transport = ws_transport
                .or_transport(base_transport)
                .map(|either, _| match either {
                    Either::Left(output) | Either::Right(output) => output,
                })
                .boxed();
        }

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

    /// Configures WebSocket transport (/ws multiaddrs) over TCP, then Noise + Yamux.
    fn build_ws_transport(noise_config: noise::Config) -> Result<Boxed<(PeerId, StreamMuxerBox)>> {
        let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default());
        let ws_transport = websocket::Config::new(tcp_transport);
        Ok(ws_transport
            .upgrade(upgrade::Version::V1Lazy)
            .authenticate(noise_config)
            .multiplex(libp2p::yamux::Config::default())
            .boxed())
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
