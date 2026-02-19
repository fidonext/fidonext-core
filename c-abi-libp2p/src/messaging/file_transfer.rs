use anyhow::{anyhow, Result};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

pub const DEFAULT_FILE_TRANSFER_QUEUE_CAPACITY: usize = 256;
pub const DEFAULT_FILE_TRANSFER_CHUNK_SIZE: usize = 256 * 1024;
pub const MAX_FILE_TRANSFER_CHUNK_SIZE: usize = 1024 * 1024;
pub const DEFAULT_FILE_TRANSFER_WINDOW_SIZE: usize = 8;
pub const DEFAULT_FILE_TRANSFER_MAX_RETRIES: u32 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub file_id: String,
    pub name: String,
    pub size: u64,
    pub hash: String,
    pub mime: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkMetadata {
    pub file_id: String,
    pub chunk_index: u64,
    pub offset: u64,
    pub chunk_size: u32,
    pub chunk_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileTransferFrame {
    Init {
        metadata: FileMetadata,
        chunk_size: u32,
        total_chunks: u64,
    },
    Chunk {
        metadata: ChunkMetadata,
        data: Vec<u8>,
    },
    ChunkAck {
        file_id: String,
        chunk_index: u64,
        next_expected_chunk: u64,
    },
    Complete {
        file_id: String,
        total_chunks: u64,
        file_hash: String,
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

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_retries: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_FILE_TRANSFER_MAX_RETRIES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutboundChunk {
    pub metadata: ChunkMetadata,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct OutboundSession {
    metadata: FileMetadata,
    chunks: Vec<OutboundChunk>,
    window_size: usize,
    next_chunk_to_send: u64,
    in_flight: HashSet<u64>,
    acked: HashSet<u64>,
    retries: HashMap<u64, u32>,
}

impl OutboundSession {
    // Splits input bytes into hashed chunks and initializes outbound transfer state.
    fn new(metadata: FileMetadata, data: Vec<u8>, chunk_size: usize, window_size: usize) -> Self {
        let mut chunks = Vec::new();
        for (index, chunk) in data.chunks(chunk_size).enumerate() {
            let chunk_hash = compute_sha256_hex(chunk);
            chunks.push(OutboundChunk {
                metadata: ChunkMetadata {
                    file_id: metadata.file_id.clone(),
                    chunk_index: index as u64,
                    offset: (index * chunk_size) as u64,
                    chunk_size: chunk.len() as u32,
                    chunk_hash,
                },
                data: chunk.to_vec(),
            });
        }

        Self {
            metadata,
            chunks,
            window_size,
            next_chunk_to_send: 0,
            in_flight: HashSet::new(),
            acked: HashSet::new(),
            retries: HashMap::new(),
        }
    }

    // Returns the total number of chunks in the current outbound session.
    fn total_chunks(&self) -> u64 {
        self.chunks.len() as u64
    }

    // Selects the next batch of chunks according to the configured sliding window.
    fn fill_window(&mut self) -> Vec<OutboundChunk> {
        let mut send_now = Vec::new();
        while self.in_flight.len() < self.window_size
            && self.next_chunk_to_send < self.total_chunks()
        {
            let index = self.next_chunk_to_send;
            self.next_chunk_to_send += 1;
            if self.acked.contains(&index) {
                continue;
            }
            self.in_flight.insert(index);
            send_now.push(self.chunks[index as usize].clone());
        }
        send_now
    }

    // Marks a chunk as acknowledged and removes it from the in-flight set.
    fn on_ack(&mut self, chunk_index: u64) {
        self.acked.insert(chunk_index);
        self.in_flight.remove(&chunk_index);
    }

    // Returns a chunk for retry if retry budget is still available.
    fn request_retry(&mut self, chunk_index: u64, retry: &RetryPolicy) -> Option<OutboundChunk> {
        if self.acked.contains(&chunk_index) {
            return None;
        }
        let attempts = self.retries.entry(chunk_index).or_insert(0);
        if *attempts >= retry.max_retries {
            return None;
        }
        *attempts += 1;
        self.in_flight.insert(chunk_index);
        self.chunks.get(chunk_index as usize).cloned()
    }

    // Reports whether all chunks in this session were acknowledged.
    fn is_complete(&self) -> bool {
        self.acked.len() == self.chunks.len()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TransferProgressStore {
    next_expected_chunk: HashMap<String, u64>,
}

impl TransferProgressStore {
    // Gets the next expected chunk index for the provided file id.
    pub fn next_expected_chunk(&self, file_id: &str) -> u64 {
        self.next_expected_chunk.get(file_id).copied().unwrap_or(0)
    }

    // Persists ack progress for resume by advancing the next expected index.
    pub fn record_ack(&mut self, file_id: &str, chunk_index: u64) {
        let next = chunk_index.saturating_add(1);
        let entry = self
            .next_expected_chunk
            .entry(file_id.to_string())
            .or_insert(0);
        if *entry < next {
            *entry = next;
        }
    }

    // Clears stored progress for a file after successful completion.
    pub fn clear(&mut self, file_id: &str) {
        self.next_expected_chunk.remove(file_id);
    }
}

#[derive(Debug)]
pub struct FileTransferSender {
    sessions: HashMap<String, OutboundSession>,
    retry_policy: RetryPolicy,
    pub progress: TransferProgressStore,
}

impl FileTransferSender {
    // Creates a sender state holder with retry policy and empty session map.
    pub fn new(retry_policy: RetryPolicy) -> Self {
        Self {
            sessions: HashMap::new(),
            retry_policy,
            progress: TransferProgressStore::default(),
        }
    }

    // Starts a transfer and returns Init plus the first window of Chunk frames.
    pub fn start_transfer(
        &mut self,
        metadata: FileMetadata,
        data: Vec<u8>,
        chunk_size: usize,
        window_size: usize,
    ) -> Result<(FileTransferFrame, Vec<FileTransferFrame>)> {
        let chunk_size = chunk_size_or_default(chunk_size);
        let chunk_size = chunk_size.min(MAX_FILE_TRANSFER_CHUNK_SIZE);
        let window_size = window_size.max(1);
        let mut session = OutboundSession::new(metadata.clone(), data, chunk_size, window_size);
        let progress_next = self.progress.next_expected_chunk(&metadata.file_id);
        session.next_chunk_to_send = progress_next.min(session.total_chunks());

        let init = FileTransferFrame::Init {
            metadata: metadata.clone(),
            chunk_size: chunk_size as u32,
            total_chunks: session.total_chunks(),
        };
        let initial_chunks = session
            .fill_window()
            .into_iter()
            .map(|chunk| FileTransferFrame::Chunk {
                metadata: chunk.metadata,
                data: chunk.data,
            })
            .collect();

        self.sessions.insert(metadata.file_id, session);
        Ok((init, initial_chunks))
    }

    // Consumes a chunk acknowledgement and emits newly unblocked chunks or Complete.
    pub fn on_chunk_ack(&mut self, file_id: &str, chunk_index: u64) -> Vec<FileTransferFrame> {
        let mut next_frames = Vec::new();
        if let Some(session) = self.sessions.get_mut(file_id) {
            session.on_ack(chunk_index);
            self.progress.record_ack(file_id, chunk_index);
            for chunk in session.fill_window() {
                next_frames.push(FileTransferFrame::Chunk {
                    metadata: chunk.metadata,
                    data: chunk.data,
                });
            }
            if session.is_complete() {
                next_frames.push(FileTransferFrame::Complete {
                    file_id: session.metadata.file_id.clone(),
                    total_chunks: session.total_chunks(),
                    file_hash: session.metadata.hash.clone(),
                });
            }
        }
        next_frames
    }

    // Requests a retransmission frame for a specific chunk.
    pub fn retry_chunk(&mut self, file_id: &str, chunk_index: u64) -> Option<FileTransferFrame> {
        self.sessions
            .get_mut(file_id)
            .and_then(|session| session.request_retry(chunk_index, &self.retry_policy))
            .map(|chunk| FileTransferFrame::Chunk {
                metadata: chunk.metadata,
                data: chunk.data,
            })
    }

    // Rebuilds the current send window from persisted in-memory session state.
    pub fn resume_frames(&mut self, file_id: &str) -> Vec<FileTransferFrame> {
        let mut frames = Vec::new();
        if let Some(session) = self.sessions.get_mut(file_id) {
            for chunk in session.fill_window() {
                frames.push(FileTransferFrame::Chunk {
                    metadata: chunk.metadata,
                    data: chunk.data,
                });
            }
        }
        frames
    }
}

#[derive(Debug)]
pub struct ReceiverSession {
    metadata: FileMetadata,
    part_path: PathBuf,
    received: BTreeMap<u64, ChunkMetadata>,
}

#[derive(Debug)]
pub struct FileTransferReceiver {
    root: PathBuf,
    sessions: HashMap<String, ReceiverSession>,
    progress: TransferProgressStore,
}

impl FileTransferReceiver {
    // Creates a receiver rooted at a directory for temporary and finalized files.
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            sessions: HashMap::new(),
            progress: TransferProgressStore::default(),
        })
    }

    // Initializes receiver state and allocates a .part file for incoming chunks.
    pub fn handle_init(&mut self, metadata: FileMetadata) -> Result<PathBuf> {
        let part_path = self.root.join(format!("{}.part", metadata.file_id));
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&part_path)?;
        file.set_len(metadata.size)?;

        self.sessions.insert(
            metadata.file_id.clone(),
            ReceiverSession {
                metadata,
                part_path: part_path.clone(),
                received: BTreeMap::new(),
            },
        );
        Ok(part_path)
    }

    // Validates and writes a chunk into the .part file, then returns ChunkAck.
    pub fn handle_chunk(
        &mut self,
        metadata: ChunkMetadata,
        data: &[u8],
    ) -> Result<FileTransferFrame> {
        let session = self
            .sessions
            .get_mut(&metadata.file_id)
            .ok_or_else(|| anyhow!("missing receiver session for file {}", metadata.file_id))?;
        if metadata.chunk_size as usize != data.len() {
            return Err(anyhow!(
                "chunk size mismatch for file {} index {}",
                metadata.file_id,
                metadata.chunk_index
            ));
        }
        let actual_hash = compute_sha256_hex(data);
        if actual_hash != metadata.chunk_hash {
            return Err(anyhow!(
                "chunk hash mismatch for file {} index {}",
                metadata.file_id,
                metadata.chunk_index
            ));
        }

        let mut file = OpenOptions::new().write(true).open(&session.part_path)?;
        file.seek(SeekFrom::Start(metadata.offset))?;
        file.write_all(data)?;
        file.flush()?;

        session
            .received
            .insert(metadata.chunk_index, metadata.clone());
        self.progress
            .record_ack(&metadata.file_id, metadata.chunk_index);
        let next_expected_chunk = self.progress.next_expected_chunk(&metadata.file_id);

        Ok(FileTransferFrame::ChunkAck {
            file_id: metadata.file_id,
            chunk_index: metadata.chunk_index,
            next_expected_chunk,
        })
    }

    // Verifies full file hash and renames .part file to final filename.
    pub fn finalize(&mut self, file_id: &str, full_hash: &str) -> Result<PathBuf> {
        let session = self
            .sessions
            .remove(file_id)
            .ok_or_else(|| anyhow!("missing receiver session for file {file_id}"))?;
        let mut part = File::open(&session.part_path)?;
        let mut buf = Vec::new();
        part.read_to_end(&mut buf)?;
        let actual_hash = compute_sha256_hex(&buf);
        if actual_hash != full_hash {
            return Err(anyhow!("file hash mismatch for file {file_id}"));
        }
        let final_path = self.root.join(&session.metadata.name);
        fs::rename(&session.part_path, &final_path)?;
        self.progress.clear(file_id);
        Ok(final_path)
    }
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

// Computes a SHA-256 hex digest for chunk or file integrity checks.
fn compute_sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_respects_window_and_ack() {
        let payload = vec![7u8; 900_000];
        let file_hash = compute_sha256_hex(&payload);
        let metadata = FileMetadata {
            file_id: "f1".to_string(),
            name: "f1.bin".to_string(),
            size: payload.len() as u64,
            hash: file_hash,
            mime: "application/octet-stream".to_string(),
        };

        let mut sender = FileTransferSender::new(RetryPolicy::default());
        let (_init, initial_frames) = sender
            .start_transfer(metadata, payload, 256 * 1024, 2)
            .expect("start transfer");
        assert_eq!(initial_frames.len(), 2);

        let next = sender.on_chunk_ack("f1", 0);
        assert_eq!(next.len(), 1);
    }

    #[test]
    fn receiver_writes_part_and_finalizes() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut receiver = FileTransferReceiver::new(root.path()).expect("receiver");

        let payload = b"hello-file".to_vec();
        let metadata = FileMetadata {
            file_id: "f2".to_string(),
            name: "final.bin".to_string(),
            size: payload.len() as u64,
            hash: compute_sha256_hex(&payload),
            mime: "application/octet-stream".to_string(),
        };
        receiver.handle_init(metadata.clone()).expect("init");

        let chunk_meta = ChunkMetadata {
            file_id: metadata.file_id.clone(),
            chunk_index: 0,
            offset: 0,
            chunk_size: payload.len() as u32,
            chunk_hash: compute_sha256_hex(&payload),
        };
        let ack = receiver
            .handle_chunk(chunk_meta, &payload)
            .expect("write chunk");
        assert!(matches!(ack, FileTransferFrame::ChunkAck { .. }));

        let path = receiver
            .finalize(&metadata.file_id, &metadata.hash)
            .expect("finalize");
        assert!(path.ends_with("final.bin"));
    }
}