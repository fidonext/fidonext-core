use anyhow::{anyhow, Result};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

pub const DEFAULT_FILE_TRANSFER_QUEUE_CAPACITY: usize = 256;
pub const DEFAULT_FILE_TRANSFER_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub file_id: String,
    pub name: String,
    pub size: u64,
    pub hash: String,
    pub mime: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileTransferFrame {
    Init {
        metadata: FileMetadata,
    },
    Chunk {
        file_id: String,
        offset: u64,
        data: Vec<u8>,
    },
    Complete {
        file_id: String,
    },
    Status {
        file_id: String,
        status: String,
    },
}

#[derive(Debug, Clone)]
pub struct InboundFileTransferFrame {
    pub from_peer: PeerId,
    pub frame: FileTransferFrame,
}

#[derive(Debug)]
pub struct FileTransferQueue {
    sender: mpsc::Sender<InboundFileTransferFrame>,
    receiver: mpsc::Receiver<InboundFileTransferFrame>,
}

#[derive(Clone, Debug)]
pub struct FileTransferQueueSender {
    sender: mpsc::Sender<InboundFileTransferFrame>,
}

impl FileTransferQueue {
    // Creates a bounded queue for inbound file-transfer frames.
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity);
        Self { sender, receiver }
    }

    // Returns a sender used to push file-transfer frames into the queue.
    pub fn sender(&self) -> FileTransferQueueSender {
        FileTransferQueueSender {
            sender: self.sender.clone(),
        }
    }

    // Tries to dequeue the next inbound file-transfer frame without waiting.
    pub fn try_dequeue(&mut self) -> Option<InboundFileTransferFrame> {
        self.receiver.try_recv().ok()
    }
}

impl FileTransferQueueSender {
    // Tries to enqueue an inbound file-transfer frame without waiting.
    pub fn try_enqueue(&self, frame: InboundFileTransferFrame) -> Result<()> {
        self.sender
            .try_send(frame)
            .map_err(|err| anyhow!("failed to enqueue file transfer frame: {err}"))
    }
}

// Returns the configured chunk size or the default when input is zero.
pub fn chunk_size_or_default(chunk_size: usize) -> usize {
    if chunk_size == 0 {
        DEFAULT_FILE_TRANSFER_CHUNK_SIZE
    } else {
        chunk_size
    }
}