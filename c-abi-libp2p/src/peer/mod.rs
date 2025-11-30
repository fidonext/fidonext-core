//! Peer-related primitives and utilities.

pub mod manager;

pub use manager::{PeerCommand, PeerManager, PeerManagerHandle};

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
