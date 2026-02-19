use anyhow::{anyhow, Result};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub const DEFAULT_FILE_TRANSFER_QUEUE_CAPACITY: usize = 256;
pub const DEFAULT_FILE_TRANSFER_CHUNK_SIZE: usize = 256 * 1024;
pub const MAX_FILE_TRANSFER_CHUNK_SIZE: usize = 1024 * 1024;
pub const DEFAULT_FILE_TRANSFER_WINDOW_SIZE: usize = 8;
pub const DEFAULT_FILE_TRANSFER_MAX_RETRIES: u32 = 5;
pub const DEFAULT_MAX_INBOUND_FILE_SIZE: u64 = 256 * 1024 * 1024;
pub const DEFAULT_MAX_PARALLEL_TRANSFERS: usize = 4;
pub const DEFAULT_MAX_BANDWIDTH: u64 = 16 * 1024 * 1024;
pub const DEFAULT_MAX_DISK_QUOTA: u64 = 2 * 1024 * 1024 * 1024;
pub const DEFAULT_INBOUND_TRANSFER_TTL_SECS: u64 = 15 * 60;

#[derive(Debug, Clone)]
pub struct FileTransferLimits {
    pub max_file_size: u64,
    pub max_parallel_transfers: usize,
    pub max_bandwidth: u64,
    pub max_disk_quota: u64,
    pub transfer_ttl: Duration,
}

impl Default for FileTransferLimits {
    fn default() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_INBOUND_FILE_SIZE,
            max_parallel_transfers: DEFAULT_MAX_PARALLEL_TRANSFERS,
            max_bandwidth: DEFAULT_MAX_BANDWIDTH,
            max_disk_quota: DEFAULT_MAX_DISK_QUOTA,
            transfer_ttl: Duration::from_secs(DEFAULT_INBOUND_TRANSFER_TTL_SECS),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundTransferDecision {
    Pending,
    Rejected,
}

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
    bytes_received: u64,
    created_at: Instant,
    last_activity: Instant,
    bandwidth_window_started_at: Instant,
    bandwidth_window_bytes: u64,
}

#[derive(Debug)]
struct PendingSession {
    metadata: FileMetadata,
    created_at: Instant,
}

#[derive(Debug)]
pub struct FileTransferReceiver {
    root: PathBuf,
    limits: FileTransferLimits,
    sessions: HashMap<String, ReceiverSession>,
    pending: HashMap<String, PendingSession>,
    progress: TransferProgressStore,
}

impl FileTransferReceiver {
    // Creates a receiver rooted at a directory for temporary and finalized files.
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        Self::with_limits(root, FileTransferLimits::default())
    }

    // Creates a receiver rooted at a directory for temporary and finalized files.
    pub fn with_limits(root: impl AsRef<Path>, limits: FileTransferLimits) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            limits,
            sessions: HashMap::new(),
            pending: HashMap::new(),
            progress: TransferProgressStore::default(),
        })
    }

    fn active_and_pending_count(&self) -> usize {
        self.sessions.len().saturating_add(self.pending.len())
    }

    fn check_init_limits(&self, metadata: &FileMetadata) -> Result<InboundTransferDecision> {
        if metadata.size > self.limits.max_file_size {
            tracing::warn!(target: "security", file_id = %metadata.file_id, declared_size = metadata.size, max_file_size = self.limits.max_file_size, "reject oversized transfer");
            return Ok(InboundTransferDecision::Rejected);
        }

        if self.active_and_pending_count() >= self.limits.max_parallel_transfers {
            tracing::warn!(target: "security", active_and_pending = self.active_and_pending_count(), max_parallel = self.limits.max_parallel_transfers, "reject transfer due to max_parallel_transfers");
            return Ok(InboundTransferDecision::Rejected);
        }

        let projected = self.current_disk_usage()?.saturating_add(metadata.size);
        if projected > self.limits.max_disk_quota {
            tracing::warn!(target: "security", file_id = %metadata.file_id, projected_usage = projected, max_disk_quota = self.limits.max_disk_quota, "reject transfer due to disk quota exceeded");
            return Ok(InboundTransferDecision::Rejected);
        }

        Ok(InboundTransferDecision::Pending)
    }

    // Registers inbound transfer metadata and waits for explicit user decision.
    pub fn handle_init(&mut self, metadata: FileMetadata) -> Result<InboundTransferDecision> {
        self.gc_expired_transfers()?;
        if self.check_init_limits(&metadata)? == InboundTransferDecision::Rejected {
            return Ok(InboundTransferDecision::Rejected);
        }

        if self.sessions.contains_key(&metadata.file_id)
            || self.pending.contains_key(&metadata.file_id)
        {
            tracing::warn!(target: "security", file_id = %metadata.file_id, "reject transfer with duplicate file id");
            return Ok(InboundTransferDecision::Rejected);
        }

        self.pending.insert(
            metadata.file_id.clone(),
            PendingSession {
                metadata,
                created_at: Instant::now(),
            },
        );
        Ok(InboundTransferDecision::Pending)
    }

    // Explicitly accepts a pending transfer and allocates a .part file.
    pub fn accept_transfer(&mut self, file_id: &str) -> Result<PathBuf> {
        self.gc_expired_transfers()?;
        let pending = self
            .pending
            .remove(file_id)
            .ok_or_else(|| anyhow!("missing pending transfer for file {file_id}"))?;
        let metadata = pending.metadata;
        if self.check_init_limits(&metadata)? == InboundTransferDecision::Rejected {
            return Err(anyhow!(
                "transfer {} rejected by limits before accept",
                metadata.file_id
            ));
        }

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
                bytes_received: 0,
                created_at: Instant::now(),
                last_activity: Instant::now(),
                bandwidth_window_started_at: Instant::now(),
                bandwidth_window_bytes: 0,
            },
        );
        Ok(part_path)
    }

    // Explicitly rejects a pending inbound transfer request.
    pub fn reject_transfer(&mut self, file_id: &str, reason: &str) {
        if self.pending.remove(file_id).is_some() {
            tracing::warn!(target: "security", %file_id, %reason, "rejected inbound transfer by user decision");
        }
    }

    // Validates and writes a chunk into the .part file, then returns ChunkAck.
    pub fn handle_chunk(
        &mut self,
        metadata: ChunkMetadata,
        data: &[u8],
    ) -> Result<FileTransferFrame> {
        if metadata.chunk_size as usize != data.len() {
            if self.sessions.contains_key(&metadata.file_id) {
                let _ = self.cancel_transfer(&metadata.file_id);
            }
            return Err(anyhow!(
                "chunk size mismatch for file {} index {}",
                metadata.file_id,
                metadata.chunk_index
            ));
        }
        let actual_hash = compute_sha256_hex(data);
        if actual_hash != metadata.chunk_hash {
            tracing::warn!(target: "security", file_id = %metadata.file_id, chunk_index = metadata.chunk_index, "hash mismatch while receiving chunk");
            let _ = self.cancel_transfer(&metadata.file_id);
            return Err(anyhow!(
                "chunk hash mismatch for file {} index {}",
                metadata.file_id,
                metadata.chunk_index
            ));
        }

        let now = Instant::now();
        let mut should_cancel = None::<&str>;
        {
            let session = self
                .sessions
                .get_mut(&metadata.file_id)
                .ok_or_else(|| anyhow!("missing receiver session for file {}", metadata.file_id))?;

            if metadata.offset.saturating_add(metadata.chunk_size as u64) > session.metadata.size {
                tracing::warn!(target: "security", file_id = %metadata.file_id, declared_size = session.metadata.size, offset = metadata.offset, chunk_size = metadata.chunk_size, "chunk exceeds declared file size");
                should_cancel = Some("declared size exceeded");
            } else {
                if now.duration_since(session.bandwidth_window_started_at) >= Duration::from_secs(1)
                {
                    session.bandwidth_window_started_at = now;
                    session.bandwidth_window_bytes = 0;
                }
                let projected_window = session
                    .bandwidth_window_bytes
                    .saturating_add(data.len() as u64);
                if projected_window > self.limits.max_bandwidth {
                    tracing::warn!(target: "security", file_id = %metadata.file_id, projected_bandwidth = projected_window, max_bandwidth = self.limits.max_bandwidth, "cancelling transfer due to bandwidth limit exceeded");
                    should_cancel = Some("bandwidth limit exceeded");
                } else {
                    let mut file = OpenOptions::new().write(true).open(&session.part_path)?;
                    file.seek(SeekFrom::Start(metadata.offset))?;
                    file.write_all(data)?;
                    file.flush()?;

                    session
                        .received
                        .insert(metadata.chunk_index, metadata.clone());
                    session.bytes_received =
                        session.bytes_received.saturating_add(data.len() as u64);
                    session.last_activity = now;
                    session.bandwidth_window_bytes = projected_window;

                    if session.bytes_received > session.metadata.size {
                        tracing::warn!(target: "security", file_id = %metadata.file_id, bytes_received = session.bytes_received, declared_size = session.metadata.size, "cancelling transfer due to actual size exceeding declared size");
                        should_cancel = Some("actual size exceeded");
                    }
                }
            }
        }

        if let Some(reason) = should_cancel {
            self.cancel_transfer(&metadata.file_id)?;
            return Err(anyhow!("{} for file {}", reason, metadata.file_id));
        }

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
            tracing::warn!(target: "security", %file_id, "hash mismatch while finalizing transfer");
            if session.part_path.exists() {
                fs::remove_file(&session.part_path)?;
            }
            return Err(anyhow!("file hash mismatch for file {file_id}"));
        }
        let final_path = self.root.join(&session.metadata.name);
        fs::rename(&session.part_path, &final_path)?;
        self.progress.clear(file_id);
        Ok(final_path)
    }

    // Removes timed-out pending and active transfers and their `.part` files.
    pub fn gc_expired_transfers(&mut self) -> Result<()> {
        let now = Instant::now();

        self.pending
            .retain(|file_id, pending| {
                let expired = now.duration_since(pending.created_at) > self.limits.transfer_ttl;
                if expired {
                    tracing::warn!(target: "security", %file_id, "expired pending transfer was garbage collected");
                }
                !expired
            });

        let expired_file_ids: Vec<String> = self
            .sessions
            .iter()
            .filter_map(|(file_id, session)| {
                let expired = now.duration_since(session.last_activity) > self.limits.transfer_ttl
                    || now.duration_since(session.created_at) > self.limits.transfer_ttl;
                if expired {
                    Some(file_id.clone())
                } else {
                    None
                }
            })
            .collect();
        for file_id in expired_file_ids {
            tracing::warn!(target: "security", %file_id, "expired active transfer was garbage collected");
            self.cancel_transfer(&file_id)?;
        }

        Ok(())
    }

    fn cancel_transfer(&mut self, file_id: &str) -> Result<()> {
        if let Some(session) = self.sessions.remove(file_id) {
            if session.part_path.exists() {
                fs::remove_file(&session.part_path)?;
            }
        }
        self.progress.clear(file_id);
        Ok(())
    }

    fn current_disk_usage(&self) -> Result<u64> {
        let mut total = 0u64;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
        Ok(total)
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
        let decision = receiver.handle_init(metadata.clone()).expect("init");
        assert_eq!(decision, InboundTransferDecision::Pending);
        receiver.accept_transfer(&metadata.file_id).expect("accept");

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
    #[test]
    fn receiver_rejects_oversized_declared_size() {
        let root = tempfile::tempdir().expect("tempdir");
        let limits = FileTransferLimits {
            max_file_size: 4,
            ..FileTransferLimits::default()
        };
        let mut receiver =
            FileTransferReceiver::with_limits(root.path(), limits).expect("receiver");

        let metadata = FileMetadata {
            file_id: "too-big".to_string(),
            name: "oversized.bin".to_string(),
            size: 5,
            hash: "x".to_string(),
            mime: "application/octet-stream".to_string(),
        };

        let decision = receiver.handle_init(metadata).expect("init");
        assert_eq!(decision, InboundTransferDecision::Rejected);
    }

    #[test]
    fn receiver_gc_removes_expired_part_file() {
        let root = tempfile::tempdir().expect("tempdir");
        let limits = FileTransferLimits {
            transfer_ttl: Duration::from_millis(1),
            ..FileTransferLimits::default()
        };
        let mut receiver =
            FileTransferReceiver::with_limits(root.path(), limits).expect("receiver");

        let payload = b"hello-file".to_vec();
        let metadata = FileMetadata {
            file_id: "expired".to_string(),
            name: "expired.bin".to_string(),
            size: payload.len() as u64,
            hash: compute_sha256_hex(&payload),
            mime: "application/octet-stream".to_string(),
        };

        let decision = receiver.handle_init(metadata.clone()).expect("init");
        assert_eq!(decision, InboundTransferDecision::Pending);
        let part = receiver.accept_transfer(&metadata.file_id).expect("accept");
        assert!(part.exists());

        std::thread::sleep(Duration::from_millis(2));
        receiver.gc_expired_transfers().expect("gc");
        assert!(!part.exists());
    }

    #[test]
    fn receiver_cancels_transfer_on_chunk_hash_mismatch() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut receiver = FileTransferReceiver::new(root.path()).expect("receiver");

        let payload = b"hello-file".to_vec();
        let metadata = FileMetadata {
            file_id: "bad-hash".to_string(),
            name: "bad.bin".to_string(),
            size: payload.len() as u64,
            hash: compute_sha256_hex(&payload),
            mime: "application/octet-stream".to_string(),
        };

        let decision = receiver.handle_init(metadata.clone()).expect("init");
        assert_eq!(decision, InboundTransferDecision::Pending);
        let part = receiver.accept_transfer(&metadata.file_id).expect("accept");

        let chunk_meta = ChunkMetadata {
            file_id: metadata.file_id.clone(),
            chunk_index: 0,
            offset: 0,
            chunk_size: payload.len() as u32,
            chunk_hash: "definitely-not-correct".to_string(),
        };

        let result = receiver.handle_chunk(chunk_meta, &payload);
        assert!(result.is_err());
        assert!(!part.exists());
    }
}
