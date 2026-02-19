//! c-abi-libp2p exposes both a native Rust API and a minimal C-compatible
//! surface that can be consumed by other runtimes.

pub mod config;
pub mod e2ee;
pub mod messaging;
pub mod peer;
pub mod transport;

pub use messaging::*;
pub use peer::*;
pub use transport::*;

use std::{
    ffi::CStr,
    os::raw::{c_char, c_int},
    path::PathBuf,
    ptr, slice,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use ::libp2p::{autonat, identity, Multiaddr, PeerId};
use anyhow::{Context, Result};
use tokio::{runtime::Runtime, sync::watch, task::JoinHandle};

/// More suitable alias for results while using C-ABI libp2p rust lib
type FfiResult<T> = std::result::Result<T, c_int>;

/// Operation completed successfully.
pub const CABI_STATUS_SUCCESS: c_int = 0;
/// One of the provided pointers was null.
pub const CABI_STATUS_NULL_POINTER: c_int = 1;
/// Invalid argument supplied (e.g. malformed multiaddr).
pub const CABI_STATUS_INVALID_ARGUMENT: c_int = 2;
/// Internal runtime error – check logs for details.
pub const CABI_STATUS_INTERNAL_ERROR: c_int = 3;

/// No message available in the internal queue.
pub const CABI_STATUS_QUEUE_EMPTY: c_int = -1;
/// Provided buffer is too small to fit the dequeued message.
pub const CABI_STATUS_BUFFER_TOO_SMALL: c_int = -2;

/// No file-transfer frame available in the internal queue.
pub const CABI_STATUS_FILE_TRANSFER_EMPTY: c_int = -3;

pub const CABI_FILE_TRANSFER_FRAME_INIT: c_int = 0;
pub const CABI_FILE_TRANSFER_FRAME_CHUNK: c_int = 1;
pub const CABI_FILE_TRANSFER_FRAME_COMPLETE: c_int = 2;
pub const CABI_FILE_TRANSFER_FRAME_STATUS: c_int = 3;

/// The discovery query timed out.
pub const CABI_STATUS_TIMEOUT: c_int = 6;
/// The target peer could not be located in the DHT.
pub const CABI_STATUS_NOT_FOUND: c_int = 7;

/// Fixed seed length used by E2EE identity profile APIs.
pub const CABI_IDENTITY_SEED_LEN: c_int = e2ee::IDENTITY_SEED_LEN as c_int;
/// Unknown decrypted E2EE message kind.
pub const CABI_E2EE_MESSAGE_KIND_UNKNOWN: c_int = 0;
/// Decrypted E2EE message was a prekey message.
pub const CABI_E2EE_MESSAGE_KIND_PREKEY: c_int = 1;
/// Decrypted E2EE message was a session message.
pub const CABI_E2EE_MESSAGE_KIND_SESSION: c_int = 2;

/// AutoNAT status has not yet been determined.
pub const CABI_AUTONAT_UNKNOWN: c_int = 0;
/// AutoNAT reports the node as privately reachable only.
pub const CABI_AUTONAT_PRIVATE: c_int = 1;
/// AutoNAT reports the node as publicly reachable.
pub const CABI_AUTONAT_PUBLIC: c_int = 2;

/// Discovery event carries an address for a peer.
pub const CABI_DISCOVERY_EVENT_ADDRESS: c_int = 0;
/// Discovery query has finished.
pub const CABI_DISCOVERY_EVENT_FINISHED: c_int = 1;

/// Opaque handle that callers treat as an identifier for a running node.
#[repr(C)]
pub struct CabiNodeHandle {
    _private: [u8; 0],
}

/// Wrapper struct around peer manager and tokio runtime
struct ManagedNode {
    runtime: Runtime,
    handle: peer::PeerManagerHandle,
    worker: Option<JoinHandle<()>>,
    autonat_status: watch::Receiver<autonat::NatStatus>,
    message_queue: messaging::MessageQueue,
    file_transfer_queue: messaging::FileTransferQueue,
    discovery_queue: peer::DiscoveryQueue,
    discovery_sequence: AtomicU64,
    addr_state: Arc<RwLock<AddrState>>,
}

impl ManagedNode {
    /// Creates new peer manager for the single peer
    fn new(config: transport::TransportConfig, bootstrap_peers: Vec<Multiaddr>) -> Result<Self> {
        let runtime = Runtime::new().context("failed to create tokio runtime")?;
        let message_queue = messaging::MessageQueue::new(messaging::DEFAULT_MESSAGE_QUEUE_CAPACITY);
        let file_transfer_queue =
            messaging::FileTransferQueue::new(messaging::DEFAULT_FILE_TRANSFER_QUEUE_CAPACITY);
        let discovery_queue = peer::DiscoveryQueue::new(peer::DEFAULT_DISCOVERY_QUEUE_CAPACITY);
        let addr_state = Arc::new(RwLock::new(AddrState::default()));

        let (manager, handle) = peer::PeerManager::new(
            config,
            message_queue.sender(),
            file_transfer_queue.sender(),
            discovery_queue.sender(),
            addr_state.clone(),
            bootstrap_peers,
        )?;

        let autonat_status = handle.autonat_status();
        let worker = runtime.spawn(async move {
            if let Err(err) = manager.run().await {
                tracing::error!(target: "ffi", %err, "peer manager exited with error");
            }
        });

        Ok(Self {
            runtime,
            handle,
            autonat_status,
            worker: Some(worker),
            message_queue,
            file_transfer_queue,
            discovery_queue,
            discovery_sequence: AtomicU64::new(0),
            addr_state,
        })
    }

    fn reserve_relay(&self, address: Multiaddr) -> Result<()> {
        self.runtime
            .block_on(self.handle.reserve_relay(address))
            .context("failed to reserver relay")
    }

    /// Requests to start listening operation on provided address
    fn start_listening(&self, address: Multiaddr) -> Result<()> {
        self.runtime
            .block_on(self.handle.start_listening(address))
            .context("failed to start listening")
    }

    /// Requests to dial peer with provided address
    fn dial(&self, address: Multiaddr) -> Result<()> {
        self.runtime
            .block_on(self.handle.dial(address))
            .context("failed to dial remote")
    }

    /// Publishes a binary payload to connected peers via gossipsub.
    fn publish_message(&self, payload: Vec<u8>) -> Result<()> {
        self.runtime
            .block_on(self.handle.publish(payload))
            .context("failed to publish message")
    }

    /// Initiates a Kademlia find_peer query and returns the request identifier.
    fn find_peer(&self, peer_id: PeerId) -> Result<u64> {
        let request_id = self.next_discovery_request_id();
        self.runtime
            .block_on(self.handle.find_peer(peer_id, request_id))
            .context("failed to start find_peer query")
            .map(|_| request_id)
    }

    /// Initiates a Kademlia get_closest_peers query and returns the request identifier.
    fn get_closest_peers(&self, peer_id: PeerId) -> Result<u64> {
        let request_id = self.next_discovery_request_id();
        self.runtime
            .block_on(self.handle.get_closest_peers(peer_id, request_id))
            .context("failed to start get_closest_peers query")
            .map(|_| request_id)
    }

    /// Stores a key/value record in Kademlia.
    fn dht_put_record(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> std::result::Result<(), peer::DhtQueryError> {
        self.runtime
            .block_on(self.handle.dht_put_record(key, value, ttl_seconds))
    }

    /// Resolves a binary record from Kademlia.
    fn dht_get_record(&self, key: Vec<u8>) -> std::result::Result<Vec<u8>, peer::DhtQueryError> {
        self.runtime.block_on(self.handle.dht_get_record(key))
    }
    /// Attempts to dequeue the next discovery event without blocking.
    fn try_dequeue_discovery(&mut self) -> Option<peer::DiscoveryEvent> {
        self.discovery_queue.try_dequeue()
    }

    /// Attempts to pull a message from the internal queue without blocking.
    fn try_dequeue_message(&mut self) -> Option<Vec<u8>> {
        self.message_queue.try_dequeue()
    }

    // Starts an outbound file transfer to a specific peer via the dedicated transport protocol.
    fn start_file_transfer(
        &self,
        recipient: PeerId,
        metadata: messaging::FileMetadata,
        data: Vec<u8>,
        chunk_size: usize,
    ) -> Result<()> {
        self.runtime
            .block_on(
                self.handle
                    .start_file_transfer(recipient, metadata, data, chunk_size),
            )
            .context("failed to start file transfer")
    }

    // Tries to pull the next inbound file-transfer frame without blocking.
    fn try_dequeue_file_transfer(&mut self) -> Option<messaging::InboundFileTransferFrame> {
        self.file_transfer_queue.try_dequeue()
    }

    /// Returns the local peer identifier.
    fn local_peer_id(&self) -> PeerId {
        self.handle.local_peer_id()
    }

    /// Requsets to gracefully shutdown peer manager and joins the background tasks
    fn shutdown(&mut self) {
        if let Err(err) = self.runtime.block_on(self.handle.shutdown()) {
            tracing::warn!(target: "ffi", %err, "node shutdown request failed");
        }

        if let Some(worker) = self.worker.take() {
            let _ = self.runtime.block_on(async {
                if let Err(err) = worker.await {
                    tracing::warn!(target: "ffi", %err, "peer manager task join failed");
                }
            });
        }
    }

    fn autonat_status(&self) -> autonat::NatStatus {
        self.autonat_status.borrow().clone()
    }

    fn next_discovery_request_id(&self) -> u64 {
        self.discovery_sequence.fetch_add(1, Ordering::Relaxed) + 1
    }
}

impl Drop for ManagedNode {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[no_mangle]
/// C-ABI. Inits tracing for the library in order to give more proper info on networking
pub extern "C" fn cabi_init_tracing() -> c_int {
    match config::init_tracing() {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => {
            eprintln!("fidonext: failed to init tracing: {err:?}");
            CABI_STATUS_INTERNAL_ERROR
        }
    }
}

#[no_mangle]
/// C-ABI. Verifies detached signature using a libp2p protobuf-encoded public key.
///
/// Inputs:
/// - `public_key_ptr/public_key_len`: protobuf-encoded public key bytes.
/// - `message_ptr/message_len`: signed payload bytes.
/// - `signature_ptr/signature_len`: detached signature bytes.
///
/// Returns:
/// - `CABI_STATUS_SUCCESS` when signature is valid.
/// - `CABI_STATUS_INVALID_ARGUMENT` when verification fails or input is malformed.
pub extern "C" fn cabi_identity_verify_signature(
    public_key_ptr: *const u8,
    public_key_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    signature_ptr: *const u8,
    signature_len: usize,
) -> c_int {
    let public_key_bytes = match parse_payload(public_key_ptr, public_key_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let message = match parse_payload(message_ptr, message_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let signature = match parse_payload(signature_ptr, signature_len) {
        Ok(value) => value,
        Err(status) => return status,
    };

    let public_key = match identity::PublicKey::try_decode_protobuf(&public_key_bytes) {
        Ok(value) => value,
        Err(_) => return CABI_STATUS_INVALID_ARGUMENT,
    };

    if public_key.verify(&message, &signature) {
        CABI_STATUS_SUCCESS
    } else {
        CABI_STATUS_INVALID_ARGUMENT
    }
}

#[no_mangle]
/// C-ABI. Derives protobuf-encoded public key bytes from a 32-byte Ed25519 seed.
pub extern "C" fn cabi_identity_public_key_from_seed(
    seed_ptr: *const u8,
    seed_len: usize,
    out_buffer: *mut u8,
    out_buffer_len: usize,
    out_written_len: *mut usize,
) -> c_int {
    if seed_ptr.is_null() || out_buffer.is_null() || out_written_len.is_null() {
        return CABI_STATUS_NULL_POINTER;
    }
    if seed_len != 32 || out_buffer_len == 0 {
        return CABI_STATUS_INVALID_ARGUMENT;
    }
    let seed_bytes = unsafe { slice::from_raw_parts(seed_ptr, seed_len) };
    let seed: [u8; 32] = match seed_bytes.try_into() {
        Ok(value) => value,
        Err(_) => return CABI_STATUS_INVALID_ARGUMENT,
    };
    let secret = match identity::ed25519::SecretKey::try_from_bytes(seed) {
        Ok(value) => value,
        Err(_) => return CABI_STATUS_INVALID_ARGUMENT,
    };
    let keypair = identity::ed25519::Keypair::from(secret);
    let public_key = identity::Keypair::from(keypair).public();
    let encoded = public_key.encode_protobuf();
    write_bytes(&encoded, out_buffer, out_buffer_len, out_written_len)
}

#[no_mangle]
/// C-ABI. Signs payload with Ed25519 key derived from 32-byte seed.
pub extern "C" fn cabi_identity_sign_with_seed(
    seed_ptr: *const u8,
    seed_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    out_signature: *mut u8,
    out_signature_len: usize,
    out_written_len: *mut usize,
) -> c_int {
    if seed_ptr.is_null()
        || payload_ptr.is_null()
        || out_signature.is_null()
        || out_written_len.is_null()
    {
        return CABI_STATUS_NULL_POINTER;
    }

    if seed_len != 32 || payload_len == 0 || out_signature_len == 0 {
        return CABI_STATUS_INVALID_ARGUMENT;
    }
    let seed_bytes = unsafe { slice::from_raw_parts(seed_ptr, seed_len) };
    let seed: [u8; 32] = match seed_bytes.try_into() {
        Ok(value) => value,
        Err(_) => return CABI_STATUS_INVALID_ARGUMENT,
    };
    let secret = match identity::ed25519::SecretKey::try_from_bytes(seed) {
        Ok(value) => value,
        Err(_) => return CABI_STATUS_INVALID_ARGUMENT,
    };
    let keypair = identity::ed25519::Keypair::from(secret);
    let keypair = identity::Keypair::from(keypair);
    let payload = unsafe { slice::from_raw_parts(payload_ptr, payload_len) };
    let signature = match keypair.sign(payload) {
        Ok(value) => value,
        Err(_) => return CABI_STATUS_INTERNAL_ERROR,
    };

    write_bytes(
        &signature,
        out_signature,
        out_signature_len,
        out_written_len,
    )
}

#[no_mangle]
/// C-ABI. Derives PeerId string from protobuf-encoded public key bytes.
pub extern "C" fn cabi_identity_peer_id_from_public_key(
    public_key_ptr: *const u8,
    public_key_len: usize,
    out_buffer: *mut c_char,
    out_buffer_len: usize,
    out_written_len: *mut usize,
) -> c_int {
    if public_key_ptr.is_null() || out_buffer.is_null() || out_written_len.is_null() {
        return CABI_STATUS_NULL_POINTER;
    }
    if public_key_len == 0 || out_buffer_len == 0 {
        return CABI_STATUS_INVALID_ARGUMENT;
    }
    let public_key_bytes = unsafe { slice::from_raw_parts(public_key_ptr, public_key_len) };
    let public_key = match identity::PublicKey::try_decode_protobuf(public_key_bytes) {
        Ok(value) => value,
        Err(_) => return CABI_STATUS_INVALID_ARGUMENT,
    };
    let peer_id = PeerId::from(public_key).to_string();

    write_c_string(
        peer_id.as_str(),
        out_buffer,
        out_buffer_len,
        out_written_len,
    )
}

#[no_mangle]
/// C-ABI. Loads an identity profile from disk or creates one when missing.
///
/// Returns account and device identifiers along with fixed-size identity seeds
/// used for deterministic libp2p/device bootstrap and Signal identity setup.
pub extern "C" fn cabi_identity_load_or_create(
    profile_path: *const c_char,
    account_id_buffer: *mut c_char,
    account_id_buffer_len: usize,
    account_id_written_len: *mut usize,
    device_id_buffer: *mut c_char,
    device_id_buffer_len: usize,
    device_id_written_len: *mut usize,
    libp2p_seed_buffer: *mut u8,
    libp2p_seed_buffer_len: usize,
    signal_identity_seed_buffer: *mut u8,
    signal_identity_seed_buffer_len: usize,
) -> c_int {
    let profile_path = match parse_path(profile_path) {
        Ok(path) => path,
        Err(status) => return status,
    };

    let profile = match e2ee::load_or_create_profile(&profile_path) {
        Ok(profile) => profile,
        Err(err) => {
            tracing::error!(
                target: "ffi",
                path = %profile_path.display(),
                %err,
                "failed to load or create identity profile"
            );
            return CABI_STATUS_INTERNAL_ERROR;
        }
    };

    let account_status = write_c_string(
        &profile.account_id,
        account_id_buffer,
        account_id_buffer_len,
        account_id_written_len,
    );
    if account_status != CABI_STATUS_SUCCESS {
        return account_status;
    }

    let device_status = write_c_string(
        &profile.device_id,
        device_id_buffer,
        device_id_buffer_len,
        device_id_written_len,
    );
    if device_status != CABI_STATUS_SUCCESS {
        return device_status;
    }

    let libp2p_status = write_fixed_seed(
        &profile.libp2p_seed,
        libp2p_seed_buffer,
        libp2p_seed_buffer_len,
    );
    if libp2p_status != CABI_STATUS_SUCCESS {
        return libp2p_status;
    }

    write_fixed_seed(
        &profile.signal_identity_seed,
        signal_identity_seed_buffer,
        signal_identity_seed_buffer_len,
    )
}

#[no_mangle]
/// C-ABI. Builds a signed key update document for the local profile.
///
/// The output is a UTF-8 JSON document written to `out_buffer`.
pub extern "C" fn cabi_e2ee_build_key_update(
    profile_path: *const c_char,
    peer_id: *const c_char,
    revision: u64,
    ttl_seconds: u64,
    out_buffer: *mut u8,
    out_buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    let profile_path = match parse_path(profile_path) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let peer_id = match parse_peer_id(peer_id) {
        Ok(peer_id) => peer_id,
        Err(status) => return status,
    };

    let profile = match e2ee::load_or_create_profile(&profile_path) {
        Ok(profile) => profile,
        Err(err) => {
            tracing::error!(
                target: "ffi",
                path = %profile_path.display(),
                %err,
                "failed to load profile for key update"
            );
            return CABI_STATUS_INTERNAL_ERROR;
        }
    };

    let effective_ttl = if ttl_seconds == 0 {
        e2ee::DEFAULT_KEY_UPDATE_TTL_SECONDS
    } else {
        ttl_seconds
    };
    let payload = match e2ee::build_key_update(&profile, &peer_id, revision, effective_ttl) {
        Ok(payload) => payload,
        Err(err) => {
            tracing::error!(target: "ffi", %err, "failed to build key update payload");
            return CABI_STATUS_INTERNAL_ERROR;
        }
    };

    write_bytes(&payload, out_buffer, out_buffer_len, written_len)
}

#[no_mangle]
/// C-ABI. Validates a signed key update JSON document.
///
/// `now_unix = 0` uses current UNIX timestamp for expiry checks.
pub extern "C" fn cabi_e2ee_validate_key_update(
    payload_ptr: *const u8,
    payload_len: usize,
    now_unix: u64,
) -> c_int {
    let payload = match parse_payload(payload_ptr, payload_len) {
        Ok(payload) => payload,
        Err(status) => return status,
    };
    let now = if now_unix == 0 {
        unix_seconds_now()
    } else {
        now_unix
    };

    match e2ee::validate_key_update(&payload, now) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => {
            tracing::warn!(target: "ffi", %err, "key update validation failed");
            CABI_STATUS_INVALID_ARGUMENT
        }
    }
}

#[no_mangle]
/// C-ABI. Builds an encrypted envelope JSON document.
///
/// This function only wraps encrypted bytes + metadata. Actual encryption is
/// expected to happen in the caller/libsignal layer.
pub extern "C" fn cabi_e2ee_build_envelope(
    sender_account_id: *const c_char,
    sender_device_id: *const c_char,
    recipient_account_id: *const c_char,
    recipient_device_id: *const c_char,
    ciphertext_ptr: *const u8,
    ciphertext_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    out_buffer: *mut u8,
    out_buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    let sender_account_id = match parse_required_c_string(sender_account_id) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let sender_device_id = match parse_required_c_string(sender_device_id) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let recipient_account_id = match parse_required_c_string(recipient_account_id) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let recipient_device_id = match parse_required_c_string(recipient_device_id) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let ciphertext = match parse_payload(ciphertext_ptr, ciphertext_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let aad = if aad_len == 0 {
        Vec::new()
    } else {
        match parse_payload(aad_ptr, aad_len) {
            Ok(value) => value,
            Err(status) => return status,
        }
    };

    let payload = match e2ee::build_envelope(
        &sender_account_id,
        &sender_device_id,
        &recipient_account_id,
        &recipient_device_id,
        &ciphertext,
        &aad,
    ) {
        Ok(payload) => payload,
        Err(err) => {
            tracing::error!(target: "ffi", %err, "failed to build encrypted envelope");
            return CABI_STATUS_INVALID_ARGUMENT;
        }
    };

    write_bytes(&payload, out_buffer, out_buffer_len, written_len)
}

#[no_mangle]
/// C-ABI. Validates an encrypted envelope JSON document.
pub extern "C" fn cabi_e2ee_validate_envelope(payload_ptr: *const u8, payload_len: usize) -> c_int {
    let payload = match parse_payload(payload_ptr, payload_len) {
        Ok(payload) => payload,
        Err(status) => return status,
    };

    match e2ee::validate_envelope(&payload) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => {
            tracing::warn!(target: "ffi", %err, "encrypted envelope validation failed");
            CABI_STATUS_INVALID_ARGUMENT
        }
    }
}

#[no_mangle]
/// C-ABI. Builds a signed pre-key bundle JSON document from local signal state.
///
/// The profile file controls where both identity and signal state are stored.
pub extern "C" fn cabi_e2ee_build_prekey_bundle(
    profile_path: *const c_char,
    one_time_prekey_count: usize,
    ttl_seconds: u64,
    out_buffer: *mut u8,
    out_buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    let profile_path = match parse_path(profile_path) {
        Ok(path) => path,
        Err(status) => return status,
    };

    let prekey_count = if one_time_prekey_count == 0 {
        e2ee::DEFAULT_ONE_TIME_PREKEY_COUNT
    } else {
        one_time_prekey_count
    };
    let effective_ttl = if ttl_seconds == 0 {
        e2ee::DEFAULT_PREKEY_BUNDLE_TTL_SECONDS
    } else {
        ttl_seconds
    };

    let payload = match e2ee::build_prekey_bundle(&profile_path, prekey_count, effective_ttl) {
        Ok(payload) => payload,
        Err(err) => {
            tracing::error!(
                target: "ffi",
                path = %profile_path.display(),
                %err,
                "failed to build prekey bundle"
            );
            return CABI_STATUS_INTERNAL_ERROR;
        }
    };

    write_bytes(&payload, out_buffer, out_buffer_len, written_len)
}

#[no_mangle]
/// C-ABI. Validates a signed pre-key bundle JSON document.
///
/// `now_unix = 0` uses current UNIX timestamp for expiry checks.
pub extern "C" fn cabi_e2ee_validate_prekey_bundle(
    payload_ptr: *const u8,
    payload_len: usize,
    now_unix: u64,
) -> c_int {
    let payload = match parse_payload(payload_ptr, payload_len) {
        Ok(payload) => payload,
        Err(status) => return status,
    };
    let now = if now_unix == 0 {
        unix_seconds_now()
    } else {
        now_unix
    };

    match e2ee::validate_prekey_bundle(&payload, now) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => {
            tracing::warn!(target: "ffi", %err, "prekey bundle validation failed");
            CABI_STATUS_INVALID_ARGUMENT
        }
    }
}

#[no_mangle]
/// C-ABI legacy endpoint kept for ABI compatibility.
///
/// Explicit prekey-message APIs are disabled; use `cabi_e2ee_build_message_auto`.
pub extern "C" fn cabi_e2ee_build_prekey_message(
    profile_path: *const c_char,
    recipient_prekey_bundle_ptr: *const u8,
    recipient_prekey_bundle_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    out_buffer: *mut u8,
    out_buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    let _ = (
        profile_path,
        recipient_prekey_bundle_ptr,
        recipient_prekey_bundle_len,
        plaintext_ptr,
        plaintext_len,
        aad_ptr,
        aad_len,
        out_buffer,
        out_buffer_len,
        written_len,
    );
    tracing::warn!(
        target: "ffi",
        "legacy prekey message API is disabled; use cabi_e2ee_build_message_auto"
    );
    CABI_STATUS_INVALID_ARGUMENT
}

#[no_mangle]
/// C-ABI. Validates prekey message envelope and metadata.
pub extern "C" fn cabi_e2ee_validate_prekey_message(
    payload_ptr: *const u8,
    payload_len: usize,
) -> c_int {
    let payload = match parse_payload(payload_ptr, payload_len) {
        Ok(payload) => payload,
        Err(status) => return status,
    };

    match e2ee::validate_prekey_message(&payload) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => {
            tracing::warn!(target: "ffi", %err, "prekey message validation failed");
            CABI_STATUS_INVALID_ARGUMENT
        }
    }
}

#[no_mangle]
/// C-ABI legacy endpoint kept for ABI compatibility.
///
/// Explicit prekey-decrypt APIs are disabled; use `cabi_e2ee_decrypt_message_auto`.
pub extern "C" fn cabi_e2ee_decrypt_prekey_message(
    profile_path: *const c_char,
    payload_ptr: *const u8,
    payload_len: usize,
    out_plaintext_buffer: *mut u8,
    out_plaintext_buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    let _ = (
        profile_path,
        payload_ptr,
        payload_len,
        out_plaintext_buffer,
        out_plaintext_buffer_len,
        written_len,
    );
    tracing::warn!(
        target: "ffi",
        "legacy prekey decrypt API is disabled; use cabi_e2ee_decrypt_message_auto"
    );
    CABI_STATUS_INVALID_ARGUMENT
}

#[no_mangle]
/// C-ABI legacy endpoint kept for ABI compatibility.
///
/// Explicit session-message APIs are disabled; use `cabi_e2ee_build_message_auto`.
pub extern "C" fn cabi_e2ee_build_session_message(
    profile_path: *const c_char,
    session_id: *const c_char,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    out_buffer: *mut u8,
    out_buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    let _ = (
        profile_path,
        session_id,
        plaintext_ptr,
        plaintext_len,
        aad_ptr,
        aad_len,
        out_buffer,
        out_buffer_len,
        written_len,
    );
    tracing::warn!(
        target: "ffi",
        "legacy session message API is disabled; use cabi_e2ee_build_message_auto"
    );
    CABI_STATUS_INVALID_ARGUMENT
}

#[no_mangle]
/// C-ABI. Validates session message envelope and metadata.
pub extern "C" fn cabi_e2ee_validate_session_message(
    payload_ptr: *const u8,
    payload_len: usize,
) -> c_int {
    let payload = match parse_payload(payload_ptr, payload_len) {
        Ok(payload) => payload,
        Err(status) => return status,
    };

    match e2ee::validate_session_message(&payload) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => {
            tracing::warn!(target: "ffi", %err, "session message validation failed");
            CABI_STATUS_INVALID_ARGUMENT
        }
    }
}

#[no_mangle]
/// C-ABI legacy endpoint kept for ABI compatibility.
///
/// Explicit session-decrypt APIs are disabled; use `cabi_e2ee_decrypt_message_auto`.
pub extern "C" fn cabi_e2ee_decrypt_session_message(
    profile_path: *const c_char,
    payload_ptr: *const u8,
    payload_len: usize,
    out_plaintext_buffer: *mut u8,
    out_plaintext_buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    let _ = (
        profile_path,
        payload_ptr,
        payload_len,
        out_plaintext_buffer,
        out_plaintext_buffer_len,
        written_len,
    );
    tracing::warn!(
        target: "ffi",
        "legacy session decrypt API is disabled; use cabi_e2ee_decrypt_message_auto"
    );
    CABI_STATUS_INVALID_ARGUMENT
}

#[no_mangle]
/// C-ABI. Builds and publishes the latest prekey bundle to DHT for local account/device.
pub extern "C" fn cabi_e2ee_publish_prekey_bundle(
    handle: *mut CabiNodeHandle,
    profile_path: *const c_char,
    one_time_prekey_count: usize,
    bundle_ttl_seconds: u64,
    dht_ttl_seconds: u64,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };
    let profile_path = match parse_path(profile_path) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let profile = match e2ee::load_or_create_profile(&profile_path) {
        Ok(profile) => profile,
        Err(err) => {
            tracing::error!(target: "ffi", %err, "failed to load profile for prekey publish");
            return CABI_STATUS_INTERNAL_ERROR;
        }
    };
    let prekey_count = if one_time_prekey_count == 0 {
        e2ee::DEFAULT_ONE_TIME_PREKEY_COUNT
    } else {
        one_time_prekey_count
    };
    let effective_bundle_ttl = if bundle_ttl_seconds == 0 {
        e2ee::DEFAULT_PREKEY_BUNDLE_TTL_SECONDS
    } else {
        bundle_ttl_seconds
    };
    let payload = match e2ee::build_prekey_bundle(&profile_path, prekey_count, effective_bundle_ttl)
    {
        Ok(payload) => payload,
        Err(err) => {
            tracing::error!(target: "ffi", %err, "failed to build prekey bundle for dht publish");
            return CABI_STATUS_INTERNAL_ERROR;
        }
    };
    let key = match e2ee::prekey_bundle_dht_key(&profile.account_id, &profile.device_id) {
        Ok(key) => key,
        Err(err) => {
            tracing::warn!(target: "ffi", %err, "invalid prekey dht key inputs");
            return CABI_STATUS_INVALID_ARGUMENT;
        }
    };
    let effective_dht_ttl = if dht_ttl_seconds == 0 {
        effective_bundle_ttl
    } else {
        dht_ttl_seconds
    };

    match node.dht_put_record(key, payload, effective_dht_ttl) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => dht_error_to_status(err),
    }
}

#[no_mangle]
/// C-ABI. Fetches and validates a prekey bundle from DHT by account/device id.
pub extern "C" fn cabi_e2ee_fetch_prekey_bundle(
    handle: *mut CabiNodeHandle,
    account_id: *const c_char,
    device_id: *const c_char,
    out_buffer: *mut u8,
    out_buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };
    let account_id = match parse_required_c_string(account_id) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let device_id = match parse_required_c_string(device_id) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let key = match e2ee::prekey_bundle_dht_key(&account_id, &device_id) {
        Ok(key) => key,
        Err(err) => {
            tracing::warn!(target: "ffi", %err, "invalid prekey dht key inputs");
            return CABI_STATUS_INVALID_ARGUMENT;
        }
    };
    let payload = match node.dht_get_record(key) {
        Ok(value) => value,
        Err(err) => return dht_error_to_status(err),
    };
    if let Err(err) = e2ee::validate_prekey_bundle(&payload, unix_seconds_now()) {
        tracing::warn!(target: "ffi", %err, "fetched prekey bundle validation failed");
        return CABI_STATUS_INVALID_ARGUMENT;
    }
    write_bytes(&payload, out_buffer, out_buffer_len, written_len)
}

#[no_mangle]
/// C-ABI. Builds and publishes key-update document to DHT for local account/device.
pub extern "C" fn cabi_e2ee_publish_key_update(
    handle: *mut CabiNodeHandle,
    profile_path: *const c_char,
    revision: u64,
    key_update_ttl_seconds: u64,
    dht_ttl_seconds: u64,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };
    let profile_path = match parse_path(profile_path) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let profile = match e2ee::load_or_create_profile(&profile_path) {
        Ok(profile) => profile,
        Err(err) => {
            tracing::error!(target: "ffi", %err, "failed to load profile for key update publish");
            return CABI_STATUS_INTERNAL_ERROR;
        }
    };
    let effective_update_ttl = if key_update_ttl_seconds == 0 {
        e2ee::DEFAULT_KEY_UPDATE_TTL_SECONDS
    } else {
        key_update_ttl_seconds
    };
    let effective_revision = match e2ee::resolve_key_update_revision(&profile_path, revision) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(target: "ffi", %err, "invalid key update revision");
            return CABI_STATUS_INVALID_ARGUMENT;
        }
    };
    let payload = match e2ee::build_key_update(
        &profile,
        &node.local_peer_id(),
        effective_revision,
        effective_update_ttl,
    ) {
        Ok(payload) => payload,
        Err(err) => {
            tracing::error!(target: "ffi", %err, "failed to build key update for dht publish");
            return CABI_STATUS_INTERNAL_ERROR;
        }
    };
    let key = match e2ee::key_update_dht_key(&profile.account_id, &profile.device_id) {
        Ok(key) => key,
        Err(err) => {
            tracing::warn!(target: "ffi", %err, "invalid key update dht key inputs");
            return CABI_STATUS_INVALID_ARGUMENT;
        }
    };
    let effective_dht_ttl = if dht_ttl_seconds == 0 {
        effective_update_ttl
    } else {
        dht_ttl_seconds
    };

    match node.dht_put_record(key, payload, effective_dht_ttl) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => dht_error_to_status(err),
    }
}

#[no_mangle]
/// C-ABI. Fetches and validates latest key-update document from DHT by account/device id.
pub extern "C" fn cabi_e2ee_fetch_key_update(
    handle: *mut CabiNodeHandle,
    account_id: *const c_char,
    device_id: *const c_char,
    out_buffer: *mut u8,
    out_buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };
    let account_id = match parse_required_c_string(account_id) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let device_id = match parse_required_c_string(device_id) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let key = match e2ee::key_update_dht_key(&account_id, &device_id) {
        Ok(key) => key,
        Err(err) => {
            tracing::warn!(target: "ffi", %err, "invalid key update dht key inputs");
            return CABI_STATUS_INVALID_ARGUMENT;
        }
    };
    let payload = match node.dht_get_record(key) {
        Ok(value) => value,
        Err(err) => return dht_error_to_status(err),
    };
    if let Err(err) = e2ee::validate_key_update(&payload, unix_seconds_now()) {
        tracing::warn!(target: "ffi", %err, "fetched key update validation failed");
        return CABI_STATUS_INVALID_ARGUMENT;
    }
    write_bytes(&payload, out_buffer, out_buffer_len, written_len)
}

#[no_mangle]
/// C-ABI. Legacy device-directory validation API (disabled in single-device mode).
pub extern "C" fn cabi_e2ee_validate_device_directory(
    payload_ptr: *const u8,
    payload_len: usize,
    now_unix: u64,
) -> c_int {
    let _ = (payload_ptr, payload_len, now_unix);
    tracing::warn!(
        target: "ffi",
        "device directory API is disabled in single-device mode"
    );
    CABI_STATUS_INVALID_ARGUMENT
}

#[no_mangle]
/// C-ABI. Legacy device-directory fetch API (disabled in single-device mode).
pub extern "C" fn cabi_e2ee_fetch_device_directory(
    handle: *mut CabiNodeHandle,
    account_id: *const c_char,
    out_buffer: *mut u8,
    out_buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    let _ = (handle, account_id, out_buffer, out_buffer_len, written_len);
    tracing::warn!(
        target: "ffi",
        "device directory API is disabled in single-device mode"
    );
    CABI_STATUS_INVALID_ARGUMENT
}

#[no_mangle]
/// C-ABI. Probe that executes an in-memory official libsignal roundtrip.
pub extern "C" fn cabi_e2ee_libsignal_probe() -> c_int {
    match futures::executor::block_on(e2ee::official_libsignal_roundtrip_smoke()) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => {
            tracing::warn!(target: "ffi", %err, "official libsignal roundtrip probe failed");
            CABI_STATUS_INTERNAL_ERROR
        }
    }
}

#[no_mangle]
/// C-ABI. Builds an outbound E2EE payload automatically:
/// - prekey message when no session exists for recipient account/device,
/// - session message when local session already exists.
pub extern "C" fn cabi_e2ee_build_message_auto(
    profile_path: *const c_char,
    recipient_prekey_bundle_ptr: *const u8,
    recipient_prekey_bundle_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    aad_ptr: *const u8,
    aad_len: usize,
    out_buffer: *mut u8,
    out_buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    let profile_path = match parse_path(profile_path) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let recipient_prekey_bundle =
        match parse_payload(recipient_prekey_bundle_ptr, recipient_prekey_bundle_len) {
            Ok(value) => value,
            Err(status) => return status,
        };
    let plaintext = match parse_payload(plaintext_ptr, plaintext_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let aad = if aad_len == 0 {
        Vec::new()
    } else {
        match parse_payload(aad_ptr, aad_len) {
            Ok(value) => value,
            Err(status) => return status,
        }
    };

    let outbound =
        match e2ee::build_message_auto(&profile_path, &recipient_prekey_bundle, &plaintext, &aad) {
            Ok(outbound) => outbound,
            Err(err) => {
                tracing::warn!(target: "ffi", %err, "failed to build auto e2ee message");
                return CABI_STATUS_INVALID_ARGUMENT;
            }
        };

    write_bytes(&outbound.payload, out_buffer, out_buffer_len, written_len)
}

#[no_mangle]
/// C-ABI. Automatically decrypts incoming E2EE payload and returns plaintext.
///
/// `message_kind` is set to one of:
/// - [`CABI_E2EE_MESSAGE_KIND_PREKEY`]
/// - [`CABI_E2EE_MESSAGE_KIND_SESSION`]
pub extern "C" fn cabi_e2ee_decrypt_message_auto(
    profile_path: *const c_char,
    payload_ptr: *const u8,
    payload_len: usize,
    out_plaintext_buffer: *mut u8,
    out_plaintext_buffer_len: usize,
    written_len: *mut usize,
    message_kind: *mut c_int,
) -> c_int {
    if message_kind.is_null() {
        return CABI_STATUS_NULL_POINTER;
    }

    let profile_path = match parse_path(profile_path) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let payload = match parse_payload(payload_ptr, payload_len) {
        Ok(payload) => payload,
        Err(status) => return status,
    };

    let decrypted = match e2ee::decrypt_message_auto(&profile_path, &payload) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(target: "ffi", %err, "failed to decrypt auto e2ee payload");
            return CABI_STATUS_INVALID_ARGUMENT;
        }
    };

    let kind = match decrypted.kind {
        e2ee::DecryptedMessageKind::PreKey => CABI_E2EE_MESSAGE_KIND_PREKEY,
        e2ee::DecryptedMessageKind::Session => CABI_E2EE_MESSAGE_KIND_SESSION,
    };
    unsafe {
        *message_kind = kind;
    }

    write_bytes(
        &decrypted.plaintext,
        out_plaintext_buffer,
        out_plaintext_buffer_len,
        written_len,
    )
}

#[no_mangle]
/// C-ABI. Returns the latest AutoNAT status observed for the node.
/// Use it to detect the node is public or not, which can be a signal to recreate
/// node as relay also
pub extern "C" fn cabi_autonat_status(handle: *mut CabiNodeHandle) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };

    match node.autonat_status() {
        autonat::NatStatus::Unknown => CABI_AUTONAT_UNKNOWN,
        autonat::NatStatus::Private => CABI_AUTONAT_PRIVATE,
        autonat::NatStatus::Public(_) => CABI_AUTONAT_PUBLIC,
    }
}

#[no_mangle]
/// C-ABI. Creates a new node instance and returns its handle with optional relay hop mode, bootstrap peers,
/// and a fixed Ed25519 identity seed.
pub extern "C" fn cabi_node_new(
    use_quic: bool,
    enable_relay_hop: bool,
    bootstrap_peers: *const *const c_char,
    bootstrap_peers_len: usize,
    identity_seed_ptr: *const u8,
    identity_seed_len: usize,
) -> *mut CabiNodeHandle {
    let bootstrap_peers = match parse_bootstrap_peers(bootstrap_peers, bootstrap_peers_len) {
        Ok(peers) => peers,
        Err(status) => {
            tracing::error!(
                target: "ffi",
                status,
                "failed to parse bootstrap peers; node creation aborted"
            );
            return ptr::null_mut();
        }
    };

    let identity_seed = match parse_identity_seed(identity_seed_ptr, identity_seed_len) {
        Ok(seed) => seed,
        Err(status) => {
            tracing::error!(
                target: "ffi",
                status,
                "invalid identity seed provided; node creation aborted"
            );
            return ptr::null_mut();
        }
    };

    let config = transport::TransportConfig {
        use_quic,
        hop_relay: enable_relay_hop,
        identity_seed,
        ..Default::default()
    };

    match ManagedNode::new(config, bootstrap_peers) {
        Ok(node) => {
            let boxed = Box::new(node);
            Box::into_raw(boxed) as *mut CabiNodeHandle
        }
        Err(err) => {
            tracing::error!(target: "ffi", %err, "failed to create node");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
/// C-ABI. Creates a new node instance (v2) with optional WebSocket transport enabled.
///
/// - When `use_websocket=true`, the node can listen/dial `/.../tcp/.../ws` multiaddrs.
/// - WSS (`/wss`) is typically achieved by running a TLS reverse-proxy (Caddy/Nginx)
///   in front of the node and forwarding to its `/ws` listener.
pub extern "C" fn cabi_node_new_v2(
    use_quic: bool,
    use_websocket: bool,
    enable_relay_hop: bool,
    bootstrap_peers: *const *const c_char,
    bootstrap_peers_len: usize,
    identity_seed_ptr: *const u8,
    identity_seed_len: usize,
) -> *mut CabiNodeHandle {
    let bootstrap_peers = match parse_bootstrap_peers(bootstrap_peers, bootstrap_peers_len) {
        Ok(peers) => peers,
        Err(status) => {
            tracing::error!(
                target: "ffi",
                status,
                "failed to parse bootstrap peers; node creation aborted"
            );
            return ptr::null_mut();
        }
    };

    let identity_seed = match parse_identity_seed(identity_seed_ptr, identity_seed_len) {
        Ok(seed) => seed,
        Err(status) => {
            tracing::error!(
                target: "ffi",
                status,
                "invalid identity seed provided; node creation aborted"
            );
            return ptr::null_mut();
        }
    };

    let config = transport::TransportConfig {
        use_quic,
        use_websocket,
        hop_relay: enable_relay_hop,
        identity_seed,
        ..Default::default()
    };

    match ManagedNode::new(config, bootstrap_peers) {
        Ok(node) => {
            let boxed = Box::new(node);
            Box::into_raw(boxed) as *mut CabiNodeHandle
        }
        Err(err) => {
            tracing::error!(target: "ffi", %err, "failed to create node");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
/// C-ABI. Writes the local PeerId into the provided buffer as a UTF-8 string.
pub extern "C" fn cabi_node_local_peer_id(
    handle: *mut CabiNodeHandle,
    out_buffer: *mut c_char,
    buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };

    let peer_id = node.local_peer_id().to_string();
    write_c_string(&peer_id, out_buffer, buffer_len, written_len)
}

#[no_mangle]
/// C-ABI. Requests a circuit-relay reservation on the given relay address.
pub extern "C" fn cabi_node_reserve_relay(
    handle: *mut CabiNodeHandle,
    address: *const c_char,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };

    let multiaddr = match parse_multiaddr(address) {
        Ok(addr) => addr,
        Err(status) => return status,
    };

    match node.reserve_relay(multiaddr) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => {
            tracing::error!(target: "ffi", %err, "reserve_relay failed");
            CABI_STATUS_INTERNAL_ERROR
        }
    }
}

#[no_mangle]
/// C-ABI. Inits listening on the given address
pub extern "C" fn cabi_node_listen(handle: *mut CabiNodeHandle, address: *const c_char) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };

    let multiaddr = match parse_multiaddr(address) {
        Ok(addr) => addr,
        Err(status) => return status,
    };

    match node.start_listening(multiaddr) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => {
            tracing::error!(target: "ffi", %err, "start_listening failed");
            CABI_STATUS_INTERNAL_ERROR
        }
    }
}

#[no_mangle]
/// C-ABI. Inits a dial to the outbound peer with the specified address
pub extern "C" fn cabi_node_dial(handle: *mut CabiNodeHandle, address: *const c_char) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };

    let multiaddr = match parse_multiaddr(address) {
        Ok(addr) => addr,
        Err(status) => return status,
    };

    match node.dial(multiaddr) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => {
            tracing::error!(target: "ffi", %err, "dial failed");
            CABI_STATUS_INTERNAL_ERROR
        }
    }
}

#[no_mangle]
/// C-ABI. Starts a find_peer query for the given PeerId and returns a request identifier.
pub extern "C" fn cabi_node_find_peer(
    handle: *mut CabiNodeHandle,
    peer_id: *const c_char,
    request_id: *mut u64,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };

    if request_id.is_null() {
        return CABI_STATUS_NULL_POINTER;
    }

    let peer_id = match parse_peer_id(peer_id) {
        Ok(id) => id,
        Err(status) => return status,
    };

    match node.find_peer(peer_id) {
        Ok(id) => unsafe {
            *request_id = id;
            CABI_STATUS_SUCCESS
        },
        Err(err) => {
            tracing::error!(target: "ffi", %err, "find_peer request failed");
            CABI_STATUS_INTERNAL_ERROR
        }
    }
}

#[no_mangle]
/// C-ABI. Starts a get_closest_peers query for the given PeerId and returns a request identifier.
pub extern "C" fn cabi_node_get_closest_peers(
    handle: *mut CabiNodeHandle,
    peer_id: *const c_char,
    request_id: *mut u64,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };

    if request_id.is_null() {
        return CABI_STATUS_NULL_POINTER;
    }

    let peer_id = match parse_peer_id(peer_id) {
        Ok(id) => id,
        Err(status) => return status,
    };

    match node.get_closest_peers(peer_id) {
        Ok(id) => unsafe {
            *request_id = id;
            CABI_STATUS_SUCCESS
        },
        Err(err) => {
            tracing::error!(target: "ffi", %err, "get_closest_peers request failed");
            CABI_STATUS_INTERNAL_ERROR
        }
    }
}

#[no_mangle]
/// C-ABI. Stores a binary key/value record in Kademlia DHT.
///
/// `ttl_seconds = 0` means "node default / no explicit TTL override".
pub extern "C" fn cabi_node_dht_put_record(
    handle: *mut CabiNodeHandle,
    key_ptr: *const u8,
    key_len: usize,
    value_ptr: *const u8,
    value_len: usize,
    ttl_seconds: u64,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };
    let key = match parse_payload(key_ptr, key_len) {
        Ok(payload) => payload,
        Err(status) => return status,
    };
    let value = match parse_payload(value_ptr, value_len) {
        Ok(payload) => payload,
        Err(status) => return status,
    };

    match node.dht_put_record(key, value, ttl_seconds) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => dht_error_to_status(err),
    }
}

#[no_mangle]
/// C-ABI. Resolves a binary value by key from Kademlia DHT.
pub extern "C" fn cabi_node_dht_get_record(
    handle: *mut CabiNodeHandle,
    key_ptr: *const u8,
    key_len: usize,
    out_buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };
    let key = match parse_payload(key_ptr, key_len) {
        Ok(payload) => payload,
        Err(status) => return status,
    };

    let value = match node.dht_get_record(key) {
        Ok(value) => value,
        Err(err) => return dht_error_to_status(err),
    };

    write_bytes(&value, out_buffer, buffer_len, written_len)
}

#[no_mangle]
/// C-ABI. Enqueues a binary payload into the node's internal message queue.
pub extern "C" fn cabi_node_enqueue_message(
    handle: *mut CabiNodeHandle,
    data_ptr: *const u8,
    data_len: usize,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };

    if data_ptr.is_null() {
        return CABI_STATUS_NULL_POINTER;
    }
    if data_len == 0 {
        return CABI_STATUS_INVALID_ARGUMENT;
    }

    let payload = unsafe { slice::from_raw_parts(data_ptr, data_len) }.to_vec();
    match node.publish_message(payload) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => {
            tracing::error!(target: "ffi", %err, "failed to publish message");
            CABI_STATUS_INTERNAL_ERROR
        }
    }
}

#[no_mangle]
/// C-ABI. Attempts to dequeue the next message into the provided buffer.
///
/// Returns [`CABI_STATUS_QUEUE_EMPTY`] if no message is currently available,
/// and [`CABI_STATUS_BUFFER_TOO_SMALL`] when the provided buffer is not large
/// enough to hold the message (in that case `written_len` is set to the
/// required length).
pub extern "C" fn cabi_node_dequeue_message(
    handle: *mut CabiNodeHandle,
    out_buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };

    if out_buffer.is_null() || written_len.is_null() {
        return CABI_STATUS_NULL_POINTER;
    }

    if buffer_len == 0 {
        return CABI_STATUS_INVALID_ARGUMENT;
    }

    // Always clear the written_len output.
    unsafe {
        *written_len = 0;
    }

    match node.try_dequeue_message() {
        None => CABI_STATUS_QUEUE_EMPTY,
        Some(message) => {
            if message.len() > buffer_len {
                unsafe {
                    *written_len = message.len();
                }
                return CABI_STATUS_BUFFER_TOO_SMALL;
            }

            unsafe {
                ptr::copy_nonoverlapping(message.as_ptr(), out_buffer, message.len());
                *written_len = message.len();
            }

            CABI_STATUS_SUCCESS
        }
    }
}

#[no_mangle]
/// C-ABI: starts a stream-based file transfer to the selected peer.
pub extern "C" fn cabi_node_start_file_transfer(
    handle: *mut CabiNodeHandle,
    peer_id: *const c_char,
    file_id: *const c_char,
    file_name: *const c_char,
    file_size: u64,
    file_hash: *const c_char,
    file_mime: *const c_char,
    data_ptr: *const u8,
    data_len: usize,
    chunk_size: usize,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };
    let peer_id = match parse_peer_id(peer_id) {
        Ok(value) => value,
        Err(status) => return status,
    };
    if data_ptr.is_null()
        || file_id.is_null()
        || file_name.is_null()
        || file_hash.is_null()
        || file_mime.is_null()
    {
        return CABI_STATUS_NULL_POINTER;
    }
    if data_len == 0 {
        return CABI_STATUS_INVALID_ARGUMENT;
    }

    let file_id = match parse_required_c_string(file_id) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let file_name = match parse_required_c_string(file_name) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let file_hash = match parse_required_c_string(file_hash) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let file_mime = match parse_required_c_string(file_mime) {
        Ok(value) => value,
        Err(status) => return status,
    };

    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) }.to_vec();
    let metadata = messaging::FileMetadata {
        file_id,
        name: file_name,
        size: file_size,
        hash: file_hash,
        mime: file_mime,
    };

    match node.start_file_transfer(peer_id, metadata, data, chunk_size) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => {
            tracing::error!(target: "ffi", %err, "failed to start file transfer");
            CABI_STATUS_INTERNAL_ERROR
        }
    }
}

#[no_mangle]
/// C-ABI: reads the next inbound file-transfer frame from the dedicated queue.
pub extern "C" fn cabi_node_receive_file_transfer(
    handle: *mut CabiNodeHandle,
    frame_kind: *mut c_int,
    from_peer_buffer: *mut c_char,
    from_peer_buffer_len: usize,
    from_peer_written_len: *mut usize,
    file_id_buffer: *mut c_char,
    file_id_buffer_len: usize,
    file_id_written_len: *mut usize,
    payload_buffer: *mut u8,
    payload_buffer_len: usize,
    payload_written_len: *mut usize,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };

    if frame_kind.is_null()
        || from_peer_buffer.is_null()
        || from_peer_written_len.is_null()
        || file_id_buffer.is_null()
        || file_id_written_len.is_null()
        || payload_buffer.is_null()
        || payload_written_len.is_null()
    {
        return CABI_STATUS_NULL_POINTER;
    }
    if from_peer_buffer_len == 0 || file_id_buffer_len == 0 || payload_buffer_len == 0 {
        return CABI_STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *from_peer_written_len = 0;
        *file_id_written_len = 0;
        *payload_written_len = 0;
    }

    let event = match node.try_dequeue_file_transfer() {
        Some(event) => event,
        None => return CABI_STATUS_FILE_TRANSFER_EMPTY,
    };

    let from_peer = event.from_peer.to_string();
    let from_peer_status = write_c_string(
        &from_peer,
        from_peer_buffer,
        from_peer_buffer_len,
        from_peer_written_len,
    );
    if from_peer_status != CABI_STATUS_SUCCESS {
        return from_peer_status;
    }

    match event.frame {
        messaging::FileTransferFrame::Init { metadata } => {
            unsafe {
                *frame_kind = CABI_FILE_TRANSFER_FRAME_INIT;
            }
            let status = write_c_string(
                &metadata.file_id,
                file_id_buffer,
                file_id_buffer_len,
                file_id_written_len,
            );
            if status != CABI_STATUS_SUCCESS {
                return status;
            }
            let payload = format!(
                "name={}\\nsize={}\\nhash={}\\nmime={}",
                metadata.name, metadata.size, metadata.hash, metadata.mime
            );
            write_bytes(
                payload.as_bytes(),
                payload_buffer,
                payload_buffer_len,
                payload_written_len,
            )
        }
        messaging::FileTransferFrame::Chunk {
            file_id,
            offset: _,
            data,
        } => {
            unsafe {
                *frame_kind = CABI_FILE_TRANSFER_FRAME_CHUNK;
            }
            let status = write_c_string(
                &file_id,
                file_id_buffer,
                file_id_buffer_len,
                file_id_written_len,
            );
            if status != CABI_STATUS_SUCCESS {
                return status;
            }
            write_bytes(
                &data,
                payload_buffer,
                payload_buffer_len,
                payload_written_len,
            )
        }
        messaging::FileTransferFrame::Complete { file_id } => {
            unsafe {
                *frame_kind = CABI_FILE_TRANSFER_FRAME_COMPLETE;
            }
            let status = write_c_string(
                &file_id,
                file_id_buffer,
                file_id_buffer_len,
                file_id_written_len,
            );
            if status != CABI_STATUS_SUCCESS {
                return status;
            }
            CABI_STATUS_SUCCESS
        }
        messaging::FileTransferFrame::Status { file_id, status } => {
            unsafe {
                *frame_kind = CABI_FILE_TRANSFER_FRAME_STATUS;
            }
            let code = write_c_string(
                &file_id,
                file_id_buffer,
                file_id_buffer_len,
                file_id_written_len,
            );
            if code != CABI_STATUS_SUCCESS {
                return code;
            }
            write_bytes(
                status.as_bytes(),
                payload_buffer,
                payload_buffer_len,
                payload_written_len,
            )
        }
    }
}

#[no_mangle]
/// C-ABI. Attempts to dequeue a discovery result produced by a Kademlia query.
pub extern "C" fn cabi_node_dequeue_discovery_event(
    handle: *mut CabiNodeHandle,
    event_kind: *mut c_int,
    request_id: *mut u64,
    status_code: *mut c_int,
    peer_id_buffer: *mut c_char,
    peer_id_buffer_len: usize,
    peer_id_written_len: *mut usize,
    address_buffer: *mut c_char,
    address_buffer_len: usize,
    address_written_len: *mut usize,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };

    if event_kind.is_null()
        || request_id.is_null()
        || status_code.is_null()
        || peer_id_buffer.is_null()
        || peer_id_written_len.is_null()
        || address_buffer.is_null()
        || address_written_len.is_null()
    {
        return CABI_STATUS_NULL_POINTER;
    }

    if peer_id_buffer_len == 0 || address_buffer_len == 0 {
        return CABI_STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *peer_id_written_len = 0;
        *address_written_len = 0;
    }

    let event = match node.try_dequeue_discovery() {
        Some(event) => event,
        None => return CABI_STATUS_QUEUE_EMPTY,
    };

    let (kind, req_id, status, peer_id, address) = match event {
        peer::DiscoveryEvent::Address {
            request_id,
            peer_id,
            address,
            ..
        } => (
            CABI_DISCOVERY_EVENT_ADDRESS,
            request_id,
            CABI_STATUS_SUCCESS,
            peer_id.to_string(),
            address.to_string(),
        ),
        peer::DiscoveryEvent::Finished {
            request_id,
            target_peer_id,
            status,
        } => (
            CABI_DISCOVERY_EVENT_FINISHED,
            request_id,
            discovery_status_to_code(&status),
            target_peer_id.to_string(),
            String::new(),
        ),
    };

    unsafe {
        *event_kind = kind;
        *request_id = req_id;
        *status_code = status;
    }

    let peer_status = write_c_string(
        peer_id.as_str(),
        peer_id_buffer,
        peer_id_buffer_len,
        peer_id_written_len,
    );
    if peer_status != CABI_STATUS_SUCCESS {
        return peer_status;
    }

    write_c_string(
        address.as_str(),
        address_buffer,
        address_buffer_len,
        address_written_len,
    )
}

#[no_mangle]
pub extern "C" fn cabi_node_get_addrs_snapshot(
    handle: *mut CabiNodeHandle,
    out_version: *mut u64,
    out_buf: *mut std::os::raw::c_char,
    out_buf_len: usize,
    out_written: *mut usize,
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };

    if out_version.is_null() {
        return CABI_STATUS_NULL_POINTER;
    }

    let (version, snapshot) = match node.addr_state.read() {
        Ok(state) => (state.version(), state.snapshot_string()),
        Err(_) => {
            tracing::warn!(target:"ffi", "addr_state lock poisoned");
            return CABI_STATUS_INTERNAL_ERROR;
        }
    };

    unsafe {
        *out_version = version;
    }

    write_c_string(&snapshot, out_buf, out_buf_len, out_written)
}

#[no_mangle]
/// C-ABI. Frees node with specified handle
pub extern "C" fn cabi_node_free(handle: *mut CabiNodeHandle) {
    if handle.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(handle as *mut ManagedNode));
    }
}

/// Converts pointer into node reference
fn node_from_ptr(handle: *mut CabiNodeHandle) -> FfiResult<&'static mut ManagedNode> {
    if handle.is_null() {
        return Err(CABI_STATUS_NULL_POINTER);
    }

    Ok(unsafe { &mut *(handle as *mut ManagedNode) })
}

/// Parses a c string into a libp2p multiaddr. Returns additional status codes on error.
fn parse_multiaddr(address: *const c_char) -> FfiResult<Multiaddr> {
    if address.is_null() {
        return Err(CABI_STATUS_NULL_POINTER);
    }

    let c_str = unsafe { CStr::from_ptr(address) };
    let addr_str = match c_str.to_str() {
        Ok(value) => value,
        Err(_) => return Err(CABI_STATUS_INVALID_ARGUMENT),
    };

    Multiaddr::from_str(addr_str).map_err(|_| CABI_STATUS_INVALID_ARGUMENT)
}

fn parse_required_c_string(value: *const c_char) -> FfiResult<String> {
    if value.is_null() {
        return Err(CABI_STATUS_NULL_POINTER);
    }
    let c_str = unsafe { CStr::from_ptr(value) };
    let value = c_str
        .to_str()
        .map_err(|_| CABI_STATUS_INVALID_ARGUMENT)?
        .trim();
    if value.is_empty() {
        return Err(CABI_STATUS_INVALID_ARGUMENT);
    }
    Ok(value.to_string())
}

/// Parses a c string into a filesystem path.
fn parse_path(path: *const c_char) -> FfiResult<PathBuf> {
    if path.is_null() {
        return Err(CABI_STATUS_NULL_POINTER);
    }

    let c_str = unsafe { CStr::from_ptr(path) };
    let raw = match c_str.to_str() {
        Ok(value) => value.trim(),
        Err(_) => return Err(CABI_STATUS_INVALID_ARGUMENT),
    };

    if raw.is_empty() {
        return Err(CABI_STATUS_INVALID_ARGUMENT);
    }

    Ok(PathBuf::from(raw))
}

fn parse_payload(data_ptr: *const u8, data_len: usize) -> FfiResult<Vec<u8>> {
    if data_ptr.is_null() {
        return Err(CABI_STATUS_NULL_POINTER);
    }
    if data_len == 0 {
        return Err(CABI_STATUS_INVALID_ARGUMENT);
    }

    let payload = unsafe { slice::from_raw_parts(data_ptr, data_len) }.to_vec();
    Ok(payload)
}

// Parses a c string into vector with bootstraps.
fn parse_bootstrap_peers(
    peers: *const *const c_char,
    peers_len: usize,
) -> FfiResult<Vec<Multiaddr>> {
    if peers_len == 0 {
        return Ok(Vec::new());
    }

    if peers.is_null() {
        return Err(CABI_STATUS_NULL_POINTER);
    }

    let peer_slice = unsafe { slice::from_raw_parts(peers, peers_len) };
    let mut parsed = Vec::with_capacity(peer_slice.len());

    for &peer in peer_slice {
        parsed.push(parse_multiaddr(peer)?);
    }

    Ok(parsed)
}

fn parse_identity_seed(
    identity_seed_ptr: *const u8,
    identity_seed_len: usize,
) -> FfiResult<Option<[u8; 32]>> {
    if identity_seed_len == 0 {
        return Ok(None);
    }

    if identity_seed_ptr.is_null() {
        return Err(CABI_STATUS_NULL_POINTER);
    }

    if identity_seed_len != 32 {
        return Err(CABI_STATUS_INVALID_ARGUMENT);
    }

    let seed_bytes = unsafe { slice::from_raw_parts(identity_seed_ptr, identity_seed_len) };
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| CABI_STATUS_INVALID_ARGUMENT)?;

    Ok(Some(seed))
}

/// Parses a c string into a libp2p PeerId.
fn parse_peer_id(peer_id: *const c_char) -> FfiResult<PeerId> {
    if peer_id.is_null() {
        return Err(CABI_STATUS_NULL_POINTER);
    }

    let c_str = unsafe { CStr::from_ptr(peer_id) };
    let peer_str = match c_str.to_str() {
        Ok(value) => value,
        Err(_) => return Err(CABI_STATUS_INVALID_ARGUMENT),
    };

    PeerId::from_str(peer_str).map_err(|_| CABI_STATUS_INVALID_ARGUMENT)
}

fn write_c_string(
    value: &str,
    out_buffer: *mut c_char,
    buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    if out_buffer.is_null() || written_len.is_null() {
        return CABI_STATUS_NULL_POINTER;
    }

    if buffer_len == 0 {
        return CABI_STATUS_INVALID_ARGUMENT;
    }

    let bytes = value.as_bytes();
    let required = bytes.len() + 1;

    unsafe {
        *written_len = bytes.len();
    }

    if required > buffer_len {
        return CABI_STATUS_BUFFER_TOO_SMALL;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out_buffer as *mut u8, bytes.len());
        *out_buffer.add(bytes.len()) = 0;
    }

    CABI_STATUS_SUCCESS
}

fn write_fixed_seed(
    seed: &[u8; e2ee::IDENTITY_SEED_LEN],
    out_buffer: *mut u8,
    buffer_len: usize,
) -> c_int {
    if out_buffer.is_null() {
        return CABI_STATUS_NULL_POINTER;
    }

    if buffer_len < e2ee::IDENTITY_SEED_LEN {
        return CABI_STATUS_BUFFER_TOO_SMALL;
    }

    unsafe {
        ptr::copy_nonoverlapping(seed.as_ptr(), out_buffer, e2ee::IDENTITY_SEED_LEN);
    }

    CABI_STATUS_SUCCESS
}

fn write_bytes(
    value: &[u8],
    out_buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> c_int {
    if out_buffer.is_null() || written_len.is_null() {
        return CABI_STATUS_NULL_POINTER;
    }
    if buffer_len == 0 {
        return CABI_STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *written_len = value.len();
    }
    if value.len() > buffer_len {
        return CABI_STATUS_BUFFER_TOO_SMALL;
    }

    unsafe {
        ptr::copy_nonoverlapping(value.as_ptr(), out_buffer, value.len());
    }

    CABI_STATUS_SUCCESS
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn discovery_status_to_code(status: &peer::DiscoveryStatus) -> c_int {
    match status {
        peer::DiscoveryStatus::Success => CABI_STATUS_SUCCESS,
        peer::DiscoveryStatus::NotFound => CABI_STATUS_NOT_FOUND,
        peer::DiscoveryStatus::Timeout => CABI_STATUS_TIMEOUT,
        peer::DiscoveryStatus::InternalError => CABI_STATUS_INTERNAL_ERROR,
    }
}

fn dht_error_to_status(err: peer::DhtQueryError) -> c_int {
    match err {
        peer::DhtQueryError::NotFound => CABI_STATUS_NOT_FOUND,
        peer::DhtQueryError::Timeout => CABI_STATUS_TIMEOUT,
        peer::DhtQueryError::Internal(message) => {
            tracing::warn!(target: "ffi", %message, "dht query failed");
            CABI_STATUS_INTERNAL_ERROR
        }
    }
}
