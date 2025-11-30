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
    str::FromStr,
};

use anyhow::{Context, Result};
use ::libp2p::Multiaddr;
use tokio::{runtime::Runtime, task::JoinHandle};

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
}

impl ManagedNode {
    /// Creates new peer manager for the single peer
    fn new(config: transport::TransportConfig) -> Result<Self> {
        let runtime = Runtime::new().context("failed to create tokio runtime")?;
        let (manager, handle) = peer::PeerManager::new(config)?;
        let worker = runtime.spawn(async move {
            if let Err(err) = manager.run().await {
                tracing::error!(target: "ffi", %err, "peer manager exited with error");
            }
        });

        Ok(Self {
            runtime,
            handle,
            worker: Some(worker),
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
/// C-ABI. Creates a new node instance and returns its handle
pub extern "C" fn cabi_node_new(use_quic: bool) -> *mut CabiNodeHandle {
    // Safe to call multiple times; only the first invocation sets up tracing.
    let _ = config::init_tracing();

    let config = transport::TransportConfig { use_quic };
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