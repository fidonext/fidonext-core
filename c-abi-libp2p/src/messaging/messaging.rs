use anyhow::{anyhow, Result};
use tokio::sync::mpsc;

/// Default capacity for the message queue.
pub const DEFAULT_MESSAGE_QUEUE_CAPACITY: usize = 64;

/// Thin wrapper around a bounded channel used for passing payloads into the core.
#[derive(Debug)]
pub struct MessageQueue {
    sender: mpsc::Sender<Vec<u8>>,
    receiver: mpsc::Receiver<Vec<u8>>,
}

#[derive(Clone, Debug)]

// Multiple producer, single consumer queue
pub struct MessageQueueSender {
    sender: mpsc::Sender<Vec<u8>>,
}

impl MessageQueue {
    /// Creates a new queue with the given capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity);
        Self { sender, receiver }
    }

    /// Returns a clone of the sender so producers can enqueue messages.
    pub fn sender(&self) -> MessageQueueSender {
        MessageQueueSender {
            sender: self.sender.clone(),
        }
    }

    /// Enqueues a payload, waiting if the bounded channel is full.
    pub async fn enqueue(&self, payload: Vec<u8>) -> Result<()> {
        self.sender
            .send(payload)
            .await
            .map_err(|err| anyhow!("failed to enqueue message: {err}"))
    }

    /// Attempts to dequeue a payload without blocking.
    pub fn try_dequeue(&mut self) -> Option<Vec<u8>> {
        self.receiver.try_recv().ok()
    }
}

impl MessageQueueSender {
    /// Enqueues a payload, waiting if the bounded channel is full.
    pub async fn enqueue(&self, payload: Vec<u8>) -> Result<()> {
        self.sender
            .send(payload)
            .await
            .map_err(|err| anyhow!("failed to enqueue message: {err}"))
    }

    /// Attempts to enqueue without awaiting; returns Err if the channel is full or closed.
    pub fn try_enqueue(&self, payload: Vec<u8>) -> Result<()> {
        self.sender
            .try_send(payload)
            .map_err(|err| anyhow!("failed to enqueue message: {err}"))
    }
}
