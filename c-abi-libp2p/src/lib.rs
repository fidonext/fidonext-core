//! c-abi-libp2p exposes both a native Rust API and a minimal C-compatible
//! surface that can be consumed by other runtimes.

pub mod config;
pub mod messaging;
pub mod peer;
pub mod transport;

pub use messaging::*;
pub use peer::*;
pub use transport::*;

use std::{
    ffi::CStr,
    os::raw::{c_char, c_int},
    ptr,
    slice,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result};
use ::libp2p::{autonat, Multiaddr, PeerId};
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

/// The discovery query timed out.
pub const CABI_STATUS_TIMEOUT: c_int = 6;
/// The target peer could not be located in the DHT.
pub const CABI_STATUS_NOT_FOUND: c_int = 7;


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

pub const CABI_ADDR_EVENT_LISTEN_ADDED: c_int = 0;
pub const CABI_ADDR_EVENT_LISTEN_REMOVED: c_int = 1;
pub const CABI_ADDR_EVENT_EXTERNAL_CONFIRMED: c_int = 2;
pub const CABI_ADDR_EVENT_EXTERNAL_EXPIRED: c_int = 3;
pub const CABI_ADDR_EVENT_RELAY_READY: c_int = 4;

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
    discovery_queue: peer::DiscoveryQueue,
    discovery_sequence: AtomicU64,
    addr_event_queue: peer::AddrEventQueue
}

impl ManagedNode {
    /// Creates new peer manager for the single peer
    fn new(config: transport::TransportConfig, bootstrap_peers: Vec<Multiaddr>) -> Result<Self> {
        let runtime = Runtime::new().context("failed to create tokio runtime")?;
        let message_queue = messaging::MessageQueue::new(messaging::DEFAULT_MESSAGE_QUEUE_CAPACITY);
        let discovery_queue = peer::DiscoveryQueue::new(peer::DEFAULT_DISCOVERY_QUEUE_CAPACITY);
        let addr_event_queue = peer::AddrEventQueue::new(peer::DEFAULT_ADDR_EVENTS_CAPACITY);

        let (manager, handle) = peer::PeerManager::new(
            config,
            message_queue.sender(),
            discovery_queue.sender(),
            addr_event_queue.sender(),
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
            discovery_queue,
            discovery_sequence: AtomicU64::new(0),
            addr_event_queue,
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

    /// Attempts to dequeue the next discovery event without blocking.
    fn try_dequeue_discovery(&mut self) -> Option<peer::DiscoveryEvent> {
        self.discovery_queue.try_dequeue()
    }

    /// Tries to dequeue the next Addr event without blocking.
    fn try_dequeue_addr_event(&mut self) -> Option<peer::AddrEvent> {
        self.addr_event_queue.try_dequeue()
    }

    /// Attempts to pull a message from the internal queue without blocking.
    fn try_dequeue_message(&mut self) -> Option<Vec<u8>> {
        self.message_queue.try_dequeue()
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
    address: *const c_char
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
/// C-ABI. Attempts to dequeue an addr event from the node
pub extern "C" fn cabi_node_dequeue_addr_event(
    handle: *mut CabiNodeHandle,
    out_kind: *mut c_int,
    addr_buf: *mut c_char,
    addr_buf_len: usize,
    out_written: *mut usize
) -> c_int {
    let node = match node_from_ptr(handle) {
        Ok(node) => node,
        Err(status) => return status,
    };

    if out_kind.is_null() || addr_buf.is_null() || out_written.is_null() {
        return CABI_STATUS_NULL_POINTER;
    }

    if addr_buf_len == 0 {
        return CABI_STATUS_INVALID_ARGUMENT;
    }

    unsafe {
        *out_written = 0;
    }

    let ev = match node.try_dequeue_addr_event() {
        Some(ev) => ev,
        None => return CABI_STATUS_QUEUE_EMPTY,
    };

    let (kind, addr_str) = match ev {
        peer::AddrEvent::ListenerAdded { address } => (
            CABI_ADDR_EVENT_LISTEN_ADDED,
            address.to_string(),
        ),

        peer::AddrEvent::ListenRemoved { address } => (
            CABI_ADDR_EVENT_LISTEN_REMOVED,
            address.to_string(),
        ),

        peer::AddrEvent::ExternalConfirmed { address } => (
            CABI_ADDR_EVENT_EXTERNAL_CONFIRMED,
            address.to_string(),
        ),

        peer::AddrEvent::ExternalExpired { address } => (
            CABI_ADDR_EVENT_EXTERNAL_EXPIRED,
            address.to_string(),
        ),

        peer::AddrEvent::RelayReachableReady { address } => (
            CABI_ADDR_EVENT_RELAY_READY,
            address.to_string(),
        ),
    };

    unsafe {
        *out_kind = kind;
    }

    write_c_string(addr_str.as_str(), addr_buf, addr_buf_len, out_written)
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

fn discovery_status_to_code(status: &peer::DiscoveryStatus) -> c_int {
    match status {
        peer::DiscoveryStatus::Success => CABI_STATUS_SUCCESS,
        peer::DiscoveryStatus::NotFound => CABI_STATUS_NOT_FOUND,
        peer::DiscoveryStatus::Timeout => CABI_STATUS_TIMEOUT,
        peer::DiscoveryStatus::InternalError => CABI_STATUS_INTERNAL_ERROR,
    }
}