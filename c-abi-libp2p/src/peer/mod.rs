//! Peer-related primitives and utilities.

pub mod discovery;
pub mod manager;


pub use discovery::{
    DiscoveryEvent, DiscoveryEventSender, DiscoveryQueue, DiscoveryStatus,
    DEFAULT_DISCOVERY_QUEUE_CAPACITY,
};
pub use manager::{DhtQueryError, PeerCommand, PeerManager, PeerManagerHandle};


/// Represents the local peer identity and metadata.
#[derive(Debug, Default, Clone)]
pub struct PeerInfo {
    // TODO: implement peer identity management
    /// String representation of the libp2p [`PeerId`].
    pub peer_id: Option<String>,
}

impl PeerInfo {
    /// Creates a new placeholder [`PeerInfo`] instance.
    pub fn new() -> Self {
        Self::default()
    }
}
