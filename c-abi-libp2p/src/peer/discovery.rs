//! Discovery-related primitives for bridging Kademlia responses back to the FFI layer.

use anyhow::{anyhow, Result};
use libp2p::{core::Multiaddr, PeerId};
use tokio::sync::mpsc;

/// Default capacity for the discovery event queue.
pub const DEFAULT_DISCOVERY_QUEUE_CAPACITY: usize = 64;

/// High-level statuses returned to the caller when a discovery query finishes.
#[derive(Debug, Clone)]
pub enum DiscoveryStatus {
    /// The query completed successfully.
    Success,
    /// The requested peer was not found.
    NotFound,
    /// The query timed out.
    Timeout,
    /// An internal error occurred.
    InternalError,
}

/// Events emitted by discovery queries.
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// A peer with a reachable address
    Address {
        request_id: u64,
        target_peer_id: PeerId,
        peer_id: PeerId,
        address: Multiaddr,
    },
    /// The query finished (success or fail).
    Finished {
        request_id: u64,
        target_peer_id: PeerId,
        status: DiscoveryStatus,
    },
}

/// Queue used to pass discovery events from the peer manager to the C-ABI.
#[derive(Debug)]
pub struct DiscoveryQueue {
    sender: mpsc::Sender<DiscoveryEvent>,
    receiver: mpsc::Receiver<DiscoveryEvent>,
}

/// Cloneable sender handle for enqueuing discovery events.
#[derive(Clone, Debug)]
pub struct DiscoveryEventSender {
    sender: mpsc::Sender<DiscoveryEvent>,
}

impl DiscoveryQueue {
    /// Creates a new queue with the given capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity);
        Self { sender, receiver }
    }

    /// Returns a clone of the sender.
    pub fn sender(&self) -> DiscoveryEventSender {
        DiscoveryEventSender {
            sender: self.sender.clone(),
        }
    }

    /// Attempts to dequeue a discovery event without blocking.
    pub fn try_dequeue(&mut self) -> Option<DiscoveryEvent> {
        self.receiver.try_recv().ok()
    }
}

impl DiscoveryEventSender {
    /// Attempts to enqueue a discovery event without awaiting.
    pub fn try_enqueue(&self, event: DiscoveryEvent) -> Result<()> {
        self.sender
            .try_send(event)
            .map_err(|err| anyhow!("failed to enqueue discovery event: {err}"))
    }
}
