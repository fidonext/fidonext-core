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
};

use anyhow::{Context, Result};
use ::libp2p::{autonat, Multiaddr};
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

/// AutoNAT status has not yet been determined.
pub const CABI_AUTONAT_UNKNOWN: c_int = 0;
/// AutoNAT reports the node as privately reachable only.
pub const CABI_AUTONAT_PRIVATE: c_int = 1;
/// AutoNAT reports the node as publicly reachable.
pub const CABI_AUTONAT_PUBLIC: c_int = 2;
/// No message available in the internal queue.
pub const CABI_STATUS_QUEUE_EMPTY: c_int = 4;
/// Provided buffer is too small to fit the dequeued message.
pub const CABI_STATUS_BUFFER_TOO_SMALL: c_int = 5;

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
}

impl ManagedNode {
    /// Creates new peer manager for the single peer
    fn new(config: transport::TransportConfig) -> Result<Self> {
        let runtime = Runtime::new().context("failed to create tokio runtime")?;
        let (manager, handle) = peer::PeerManager::new(config)?;
        let autonat_status = handle.autonat_status();
        let message_queue = messaging::MessageQueue::new(messaging::DEFAULT_MESSAGE_QUEUE_CAPACITY);
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
        })
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

    /// Enqueues a binary payload into the internal message queue.
    fn enqueue_message(&self, payload: Vec<u8>) -> Result<()> {
        self.runtime
            .block_on(self.message_queue.enqueue(payload))
            .context("failed to enqueue message")
    }

    /// Attempts to pull a message from the internal queue without blocking.
    fn try_dequeue_message(&mut self) -> Option<Vec<u8>> {
        self.message_queue.try_dequeue()
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
/// C-ABI. Creates a new node instance and returns its handle
pub extern "C" fn cabi_node_new(use_quic: bool) -> *mut CabiNodeHandle {
    cabi_node_new_with_relay(use_quic, false)
}

#[no_mangle]
/// C-ABI. Creates a new node instance and returns its handle with optional relay hop mode
pub extern "C" fn cabi_node_new_with_relay(
    use_quic: bool,
    enable_relay_hop: bool,
) -> *mut CabiNodeHandle {
    // Safe to call multiple times; only the first invocation sets up tracing.
    let _ = config::init_tracing();

    let config = transport::TransportConfig {
        use_quic,
        hop_relay: enable_relay_hop,
    };

    match ManagedNode::new(config) {
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
    match node.enqueue_message(payload) {
        Ok(_) => CABI_STATUS_SUCCESS,
        Err(err) => {
            tracing::error!(target: "ffi", %err, "failed to enqueue message");
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