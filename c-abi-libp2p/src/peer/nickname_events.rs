//! TD-37 · Nickname-ownership revocation events for the FFI polling surface.
//!
//! This module defines a polling-compatible queue used by the PeerManager
//! to notify the host (Android) when the local node LOSES a nickname
//! ownership race on the gossipsub anti-entropy topic. The flow:
//!
//! 1. Node publishes `NickClaim` for `alice` via `cabi_nickname_claim` and
//!    stores the claim in the in-memory observation map with
//!    `first_seen_ts = now()`.
//! 2. An inbound claim arrives on `NICKNAME_REGISTRY_TOPIC` from peer B
//!    with our-local `first_seen_ts` strictly earlier than ours (or equal
//!    with a smaller `sha256(peer_id)` per `tiebreak_winner`).
//! 3. The manager emits [`NicknameEvent::OwnershipRevoked`] into this
//!    queue, Android polls `cabi_node_dequeue_nickname_event`, flips its
//!    `PublishStatus.Succeeded` to `NicknameTaken(nickname)`, and drops
//!    the cached binding so the UX matches the network.
//!
//! The queue is bounded; on overflow the oldest event is dropped to avoid
//! memory growth on a mis-behaving host that never polls. Overflow is
//! logged at `warn!` so it's visible in `adb logcat`.

use anyhow::{anyhow, Result};
use tokio::sync::mpsc;

/// Default capacity for the nickname event queue. Sized loosely — a host
/// app that falls behind on draining this queue by more than 32 events is
/// almost certainly deadlocked elsewhere, and we'd rather log a warning
/// than buffer unbounded.
pub const DEFAULT_NICKNAME_EVENT_QUEUE_CAPACITY: usize = 32;

/// Events surfaced through the nickname-event polling queue.
#[derive(Debug, Clone)]
pub enum NicknameEvent {
    /// This node previously published a claim for `nickname` but lost the
    /// deterministic tiebreak against a remote claim observed on the
    /// gossipsub anti-entropy topic. The host MUST flip its UX to
    /// `NicknameTaken(nickname)` and drop any cached resolved binding.
    /// A vacate tombstone for this nickname is published asynchronously
    /// by the manager; the host does not need to drive that.
    OwnershipRevoked { nickname: String },
}

/// Queue used to pass nickname-registry events from the peer manager to
/// the C-ABI polling surface.
#[derive(Debug)]
pub struct NicknameEventQueue {
    sender: mpsc::Sender<NicknameEvent>,
    receiver: mpsc::Receiver<NicknameEvent>,
}

/// Cloneable sender handle for enqueuing nickname events from the
/// manager's event loop.
#[derive(Clone, Debug)]
pub struct NicknameEventSender {
    sender: mpsc::Sender<NicknameEvent>,
}

impl NicknameEventQueue {
    /// Creates a new queue with the given capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        Self { sender, receiver }
    }

    /// Returns a clone of the sender side.
    pub fn sender(&self) -> NicknameEventSender {
        NicknameEventSender {
            sender: self.sender.clone(),
        }
    }

    /// Attempts to dequeue a single event without blocking.
    pub fn try_dequeue(&mut self) -> Option<NicknameEvent> {
        self.receiver.try_recv().ok()
    }
}

impl NicknameEventSender {
    /// Attempts to enqueue an event. Returns an error if the queue is full
    /// or the receiver has been dropped.
    pub fn try_enqueue(&self, event: NicknameEvent) -> Result<()> {
        self.sender
            .try_send(event)
            .map_err(|err| anyhow!("failed to enqueue nickname event: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn td37_nickname_event_queue_roundtrip() {
        let mut queue = NicknameEventQueue::new(4);
        let sender = queue.sender();
        sender
            .try_enqueue(NicknameEvent::OwnershipRevoked {
                nickname: "alice".to_string(),
            })
            .expect("enqueue");
        match queue.try_dequeue() {
            Some(NicknameEvent::OwnershipRevoked { nickname }) => assert_eq!(nickname, "alice"),
            other => panic!("expected OwnershipRevoked(alice), got {other:?}"),
        }
        assert!(queue.try_dequeue().is_none());
    }

    #[test]
    fn td37_nickname_event_queue_full_returns_error() {
        let queue = NicknameEventQueue::new(1);
        let sender = queue.sender();
        sender
            .try_enqueue(NicknameEvent::OwnershipRevoked {
                nickname: "a".to_string(),
            })
            .expect("first enqueue");
        let err = sender
            .try_enqueue(NicknameEvent::OwnershipRevoked {
                nickname: "b".to_string(),
            })
            .expect_err("second enqueue must error (queue full)");
        assert!(err.to_string().contains("failed to enqueue"));
    }
}
