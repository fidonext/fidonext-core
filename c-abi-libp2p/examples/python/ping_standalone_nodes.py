#!/usr/bin/env python3
"""Standalone node example via the C ABI.

This script runs a single libp2p node that can either listen or dial.
Designed to be run in separate processes/containers.
"""

import argparse
import ctypes
import os
import signal
import sys
import time
from pathlib import Path

# Setup similar to ping_two_nodes.py
try:
    # Try to determine project root relative to this script
    # This works in the repo structure: .../pheonx-core/c-abi-libp2p/examples/python/script.py
    repo_root = Path(__file__).resolve().parents[3]
    DEFAULT_LIB = repo_root / "c-abi-libp2p" / "target" / "debug" / "libcabi_rust_libp2p.so"
except IndexError:
    # Fallback for shallow directory structures (e.g. inside Docker /app/script.py)
    # In this case, we rely on FIDONEXT_C_ABI being set.
    DEFAULT_LIB = Path("/nonexistent/lib.so")

# In Docker, we will set this env var to the installed location
LIB_PATH = Path(os.environ.get("FIDONEXT_C_ABI", DEFAULT_LIB))

os.environ.setdefault("RUST_LOG", "info,peer=info,ffi=info")

if not LIB_PATH.exists():
    print(f"Shared library not found at {LIB_PATH}.", file=sys.stderr)
    print("Run `cargo build` in c-abi-libp2p first or set FIDONEXT_C_ABI.", file=sys.stderr)
    sys.exit(1)

try:
    lib = ctypes.CDLL(str(LIB_PATH))
except OSError as e:
    print(f"Failed to load library {LIB_PATH}: {e}", file=sys.stderr)
    sys.exit(1)

# Status codes exported from the ABI.
CABI_STATUS_SUCCESS = 0
CABI_STATUS_NULL_POINTER = 1
CABI_STATUS_INVALID_ARGUMENT = 2
CABI_STATUS_QUEUE_EMPTY = 4
CABI_STATUS_BUFFER_TOO_SMALL = 5

# Define signatures
lib.cabi_init_tracing.restype = ctypes.c_int
lib.cabi_node_new.argtypes = [ctypes.c_bool]
lib.cabi_node_new.restype = ctypes.c_void_p
lib.cabi_node_listen.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.cabi_node_listen.restype = ctypes.c_int
lib.cabi_node_dial.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.cabi_node_dial.restype = ctypes.c_int
lib.cabi_node_enqueue_message.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
]
lib.cabi_node_enqueue_message.restype = ctypes.c_int
lib.cabi_node_dequeue_message.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cabi_node_dequeue_message.restype = ctypes.c_int
lib.cabi_node_free.argtypes = [ctypes.c_void_p]
lib.cabi_node_free.restype = None

def _check(status: int, context: str) -> None:
    if status == CABI_STATUS_SUCCESS:
        return
    if status == CABI_STATUS_NULL_POINTER:
        reason = "null pointer passed into ABI"
    elif status == CABI_STATUS_INVALID_ARGUMENT:
        reason = "invalid argument (multiaddr or UTF-8)"
    elif status == CABI_STATUS_BUFFER_TOO_SMALL:
        reason = "provided buffer too small"
    else:
        reason = "internal error – inspect Rust logs for details"
    raise RuntimeError(f"{context} failed: {reason} (status={status})")

class Node:
    def __init__(self, use_quic: bool = False) -> None:
        pointer = lib.cabi_node_new(ctypes.c_bool(use_quic))
        if not pointer:
            raise RuntimeError("cabi_node_new returned NULL, check Rust logs")
        self._ptr = ctypes.c_void_p(pointer)

    def listen(self, multiaddr: str) -> None:
        print(f"Attempting to listen on {multiaddr}...")
        _check(
            lib.cabi_node_listen(self._ptr, multiaddr.encode("utf-8")),
            f"listen({multiaddr})",
        )
        print(f"Listening on {multiaddr}")

    def dial(self, multiaddr: str) -> None:
        print(f"Attempting to dial {multiaddr}...")
        _check(
            lib.cabi_node_dial(self._ptr, multiaddr.encode("utf-8")),
            f"dial({multiaddr})",
        )
        print(f"Dialed {multiaddr}")

    def send_message(self, payload: bytes | bytearray | str) -> None:
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        buffer = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
        _check(
            lib.cabi_node_enqueue_message(
                self._ptr, buffer, ctypes.c_size_t(len(payload))
            ),
            "enqueue_message",
        )

    def try_receive_message(self, buffer_size: int = 1024) -> bytes | None:
        out_buffer = (ctypes.c_ubyte * buffer_size)()
        written = ctypes.c_size_t(0)
        status = lib.cabi_node_dequeue_message(
            self._ptr,
            out_buffer,
            ctypes.c_size_t(buffer_size),
            ctypes.byref(written),
        )

        if status == CABI_STATUS_QUEUE_EMPTY:
            return None
        if status == CABI_STATUS_BUFFER_TOO_SMALL:
            needed = written.value
            raise RuntimeError(
                f"dequeue_message failed: buffer too small (need {needed} bytes)"
            )

        _check(status, "dequeue_message")
        return bytes(out_buffer[: written.value])

    def close(self) -> None:
        if self._ptr:
            print("Closing node...")
            lib.cabi_node_free(self._ptr)
            self._ptr = None

    def __del__(self) -> None:
        self.close()

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a standalone libp2p node via the C ABI."
    )
    parser.add_argument(
        "--mode",
        choices=["listen", "dial"],
        required=True,
        help="Mode to run the node in.",
    )
    parser.add_argument(
        "--addr",
        required=True,
        help="Multiaddr to listen on (if mode=listen) or dial (if mode=dial).",
    )
    parser.add_argument(
        "--use-quic",
        action="store_true",
        help="Enable the QUIC transport.",
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    
    # Initialize tracing once
    _check(lib.cabi_init_tracing(), "init tracing")

    node = Node(use_quic=args.use_quic)

    # Demonstrate the internal Rust message queue via the FFI surface.
    test_payload = b"hello from python via rust queue"
    print(f"Sending test payload into Rust queue: {test_payload!r}")
    node.send_message(test_payload)
    echoed = node.try_receive_message()
    if echoed == test_payload:
        print(f"Dequeued payload matches: {echoed!r}")
    elif echoed is None:
        print("Queue reported empty when attempting to read the test payload.")
    else:
        print(f"Dequeued payload differed: {echoed!r}")
    
    # Handle graceful shutdown
    running = True
    def signal_handler(sig, frame):
        nonlocal running
        print("\nReceived signal, shutting down...")
        running = False
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        if args.mode == "listen":
            node.listen(args.addr)
            print("Node is ready. Press Ctrl+C to stop.")
            while running:
                time.sleep(1)
        elif args.mode == "dial":
            # For dialer, we might want to retry if the listener isn't ready yet
            max_retries = 10
            for i in range(max_retries):
                try:
                    node.dial(args.addr)
                    break
                except RuntimeError as e:
                    if i == max_retries - 1:
                        raise
                    print(f"Dial failed, retrying in 1s ({i+1}/{max_retries})...")
                    time.sleep(1)
            
            print("Connection established. Maintaining connection...")
            while running:
                time.sleep(1)
                
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        node.close()

if __name__ == "__main__":
    main()

