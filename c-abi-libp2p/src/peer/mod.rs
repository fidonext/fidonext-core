//! Peer-related primitives and utilities.

/// Represents the local peer identity and metadata.
#[derive(Debug, Default, Clone)]
pub struct PeerInfo {
    // TODO: implement peer identity management
    pub peer_id: Option<String>,
}

impl PeerInfo {
    /// Creates a new placeholder [`PeerInfo`] instance.
    pub fn new() -> Self {
        Self::default()
    }
}