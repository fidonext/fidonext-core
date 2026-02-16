//! High-level messaging primitives built on top of libp2p protocols.
//!
//! For now we expose a simple in-memory queue that can be used by the FFI
//! surface to pass binary payloads between the host runtime and the Rust core.

pub mod delivery;
pub mod messaging;

pub use delivery::*;
pub use messaging::{MessageQueue, MessageQueueSender, DEFAULT_MESSAGE_QUEUE_CAPACITY};
