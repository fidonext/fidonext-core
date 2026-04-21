//! Peer-related primitives and utilities.

pub mod addr_events;
pub mod discovery;
mod mailbox_store;
pub mod manager;
pub mod nickname_events;

pub use addr_events::{AddrEvent, AddrState};
pub use discovery::{
    DiscoveryEvent, DiscoveryEventSender, DiscoveryQueue, DiscoveryStatus,
    DEFAULT_DISCOVERY_QUEUE_CAPACITY,
};
pub use manager::{
    BlobFetchError, DhtQueryError, PeerCommand, PeerManager, PeerManagerHandle,
    MAX_AVATAR_SIZE_BYTES,
};
pub use nickname_events::{
    NicknameEvent, NicknameEventQueue, NicknameEventSender, DEFAULT_NICKNAME_EVENT_QUEUE_CAPACITY,
};

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
