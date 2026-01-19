#!/usr/bin/env python3
"""Standalone node example via the C ABI.

This CLI mirrors the C++ ping example: it exposes the same switches so a single
process can become either a relay or a leaf peer, optionally wires in bootstrap
and target peers, enables relay hop mode when AutoNAT reports PUBLIC, and
forwards stdin payloads over the gossipsub bridge.
"""

import argparse
import ctypes
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Optional, Sequence, Union

# Setup similar to ping_two_nodes.py
try:
    repo_root = Path(__file__).resolve().parents[3]
    DEFAULT_LIB = (
        repo_root / "c-abi-libp2p" / "target" / "debug" / "libcabi_rust_libp2p.so"
    )
except IndexError:
    DEFAULT_LIB = Path("/nonexistent/lib.so")

LIB_PATH = Path(os.environ.get("FIDONEXT_C_ABI", DEFAULT_LIB))

os.environ.setdefault("RUST_LOG", "info,peer=info,ffi=info")

if not LIB_PATH.exists():
    print(f"Shared library not found at {LIB_PATH}.", file=sys.stderr)
    print("Run `cargo build` in c-abi-libp2p first or set FIDONEXT_C_ABI.", file=sys.stderr)
    sys.exit(1)

try:
    lib = ctypes.CDLL(str(LIB_PATH))
except OSError as exc:
    print(f"Failed to load library {LIB_PATH}: {exc}", file=sys.stderr)
    sys.exit(1)

# Status codes exported from the ABI.
CABI_STATUS_SUCCESS = 0
CABI_STATUS_NULL_POINTER = 1
CABI_STATUS_INVALID_ARGUMENT = 2
CABI_STATUS_INTERNAL_ERROR = 3
CABI_STATUS_QUEUE_EMPTY = 4
CABI_STATUS_BUFFER_TOO_SMALL = 5

# AutoNAT statuses
CABI_AUTONAT_UNKNOWN = 0
CABI_AUTONAT_PRIVATE = 1
CABI_AUTONAT_PUBLIC = 2

lib.cabi_init_tracing.restype = ctypes.c_int
lib.cabi_node_new.argtypes = [
    ctypes.c_bool,
    ctypes.c_bool,
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
]
lib.cabi_node_new.restype = ctypes.c_void_p
lib.cabi_node_listen.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.cabi_node_listen.restype = ctypes.c_int
lib.cabi_node_dial.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.cabi_node_dial.restype = ctypes.c_int
lib.cabi_autonat_status.argtypes = [ctypes.c_void_p]
lib.cabi_autonat_status.restype = ctypes.c_int
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
lib.cabi_node_local_peer_id.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cabi_node_local_peer_id.restype = ctypes.c_int
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


def default_listen(use_quic: bool) -> str:
    if use_quic:
        return "/ip4/127.0.0.1/udp/41000/quic-v1"
    return "/ip4/127.0.0.1/tcp/41000"


def parse_seed(seed_hex: str) -> bytes:
    seed_hex = seed_hex.strip()
    if len(seed_hex) != 64:
        raise ValueError("seed must contain exactly 64 hex characters (32 bytes)")
    try:
        return bytes.fromhex(seed_hex)
    except ValueError as exc:
        raise ValueError("seed contains non-hex characters") from exc


def derive_seed_from_phrase(seed_phrase: str) -> bytes:
    fnv_offset = 0xCBF29CE484222325
    fnv_prime = 0x100000001B3
    lanes = [
        fnv_offset ^ 0x736565646C616E65,  # "seedlane"
        fnv_offset ^ 0x706872617365313,   # "phrase1"
        fnv_offset ^ 0x706872617365323,   # "phrase2"
        fnv_offset ^ 0x706872617365333,   # "phrase3"
    ]
    phrase_bytes = seed_phrase.encode("utf-8")
    for byte in phrase_bytes:
        for idx in range(len(lanes)):
            lanes[idx] ^= byte + (0x9E3779B97F4A7C15 * idx)
            lanes[idx] = (lanes[idx] * (fnv_prime + (idx * 2))) & 0xFFFFFFFFFFFFFFFF
            lanes[idx] ^= lanes[(idx + 1) % len(lanes)] >> (8 * (idx + 1))
    seed = bytearray(32)
    for i, value in enumerate(lanes):
        for shift in range(8):
            seed[i * 8 + shift] = (value >> (8 * shift)) & 0xFF
    return bytes(seed)


class Node:
    def __init__(
        self,
        *,
        use_quic: bool = False,
        enable_relay_hop: bool = False,
        bootstrap_peers: Optional[Sequence[str]] = None,
        identity_seed: Optional[bytes] = None,
    ) -> None:
        bootstrap_peers = list(bootstrap_peers or [])
        if bootstrap_peers:
            encoded = [addr.encode("utf-8") for addr in bootstrap_peers]
            self._bootstrap_array = (ctypes.c_char_p * len(encoded))(*encoded)
            bootstrap_ptr = ctypes.cast(
                self._bootstrap_array, ctypes.POINTER(ctypes.c_char_p)
            )
        else:
            self._bootstrap_array = None
            bootstrap_ptr = None

        if identity_seed is not None:
            if len(identity_seed) != 32:
                raise ValueError("identity_seed must contain exactly 32 bytes")
            self._seed_buffer = (ctypes.c_ubyte * len(identity_seed))(*identity_seed)
            seed_ptr = ctypes.cast(self._seed_buffer, ctypes.POINTER(ctypes.c_ubyte))
            seed_len = len(identity_seed)
        else:
            self._seed_buffer = None
            seed_ptr = None
            seed_len = 0

        pointer = lib.cabi_node_new(
            ctypes.c_bool(use_quic),
            ctypes.c_bool(enable_relay_hop),
            bootstrap_ptr,
            ctypes.c_size_t(len(bootstrap_peers)),
            seed_ptr,
            ctypes.c_size_t(seed_len),
        )
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

    def local_peer_id(self) -> str:
        buffer_len = 128
        while True:
            buffer = (ctypes.c_char * buffer_len)()
            written = ctypes.c_size_t(0)
            status = lib.cabi_node_local_peer_id(
                self._ptr,
                ctypes.cast(buffer, ctypes.c_void_p),
                ctypes.c_size_t(buffer_len),
                ctypes.byref(written),
            )
            if status == CABI_STATUS_BUFFER_TOO_SMALL:
                buffer_len = max(buffer_len * 2, written.value + 1)
                continue
            _check(status, "local_peer_id")
            return bytes(buffer[: written.value]).decode("utf-8")

    def autonat_status(self) -> int:
        status = lib.cabi_autonat_status(self._ptr)
        if status > CABI_AUTONAT_PUBLIC:
            _check(status, "autonat_status")
        return status

    def send_message(self, payload: Union[bytes, bytearray, str]) -> None:
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        buffer = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
        _check(
            lib.cabi_node_enqueue_message(
                self._ptr, buffer, ctypes.c_size_t(len(payload))
            ),
            "enqueue_message",
        )

    def try_receive_message(self, buffer_size: int = 1024) -> Optional[bytes]:
        current_size = buffer_size
        while True:
            out_buffer = (ctypes.c_ubyte * current_size)()
            written = ctypes.c_size_t(0)
            status = lib.cabi_node_dequeue_message(
                self._ptr,
                out_buffer,
                ctypes.c_size_t(current_size),
                ctypes.byref(written),
            )
            if status == CABI_STATUS_QUEUE_EMPTY:
                return None
            if status == CABI_STATUS_BUFFER_TOO_SMALL:
                needed = max(written.value, current_size * 2)
                current_size = max(needed, 1)
                continue
            _check(status, "dequeue_message")
            return bytes(out_buffer[: written.value])

    def close(self) -> None:
        if getattr(self, "_ptr", None):
            print("Closing node...")
            lib.cabi_node_free(self._ptr)
            self._ptr = None

    def __del__(self) -> None:
        self.close()


def wait_for_public_autonat(
    node: Node, timeout: float = 10.0, poll_interval: float = 1.0
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = node.autonat_status()
        if status == CABI_AUTONAT_PUBLIC:
            print("AutoNAT: PUBLIC")
            return True
        if status == CABI_AUTONAT_PRIVATE:
            print("AutoNAT: PRIVATE")
        elif status == CABI_AUTONAT_UNKNOWN:
            print("AutoNAT: UNKNOWN")
        time.sleep(poll_interval)
    return False


def dial_peers(node: Node, peers: Sequence[str], label: str) -> None:
    for addr in peers:
        try:
            node.dial(addr)
            print(f"Dialed {label} peer: {addr}")
        except RuntimeError as exc:
            print(f"Failed to dial {label} peer {addr}: {exc}", file=sys.stderr)


def recv_loop(node: Node, running: threading.Event, poll_interval: float = 0.1) -> None:
    while running.is_set():
        try:
            payload = node.try_receive_message()
        except RuntimeError as exc:
            print(f"Receive loop error: {exc}", file=sys.stderr)
            running.clear()
            break
        if payload is None:
            time.sleep(poll_interval)
            continue
        text = payload.decode("utf-8", "replace")
        print(f"Received payload: '{text}'", flush=True)


def interactive_send_loop(node: Node, running: threading.Event) -> None:
    print("Enter payload (empty line or /quit to exit):")
    while running.is_set():
        try:
            line = input()
        except EOFError:
            print("STDIN closed; stopping send loop.")
            running.clear()
            break
        except KeyboardInterrupt:
            running.clear()
            break
        if not line or line.strip() == "/quit":
            running.clear()
            break
        try:
            node.send_message(line.rstrip("\n"))
        except RuntimeError as exc:
            print(f"Failed to send message: {exc}", file=sys.stderr)
            running.clear()
            break
        print("Enter payload (empty line or /quit to exit):")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a standalone libp2p node via the C ABI."
    )
    parser.add_argument(
        "--role",
        choices=["relay", "leaf"],
        default="leaf",
        help="Select relay or leaf mode.",
    )
    parser.add_argument(
        "--use-quic",
        action="store_true",
        help="Enable the QUIC transport (otherwise TCP).",
    )
    parser.add_argument(
        "--force-hop",
        action="store_true",
        help="Relay only: enable hop without waiting for AutoNAT PUBLIC.",
    )
    parser.add_argument(
        "--listen",
        help="Multiaddr to listen on (defaults to loopback 41000).",
    )
    parser.add_argument(
        "--bootstrap",
        action="append",
        default=[],
        help="Bootstrap peer multiaddr (repeatable).",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="Peers to dial immediately (repeatable).",
    )
    seed_group = parser.add_mutually_exclusive_group()
    seed_group.add_argument(
        "--seed",
        help="Hex-encoded 32-byte identity seed (64 hex characters).",
    )
    seed_group.add_argument(
        "--seed-phrase",
        help="Seed phrase expanded deterministically to 32 bytes.",
    )
    parser.add_argument(
        "--message",
        help="Publish a scripted payload once after startup.",
    )
    parser.add_argument(
        "--message-delay",
        type=float,
        default=2.0,
        help="Delay in seconds before publishing --message (only when provided).",
    )
    parser.add_argument(
        "--post-message-wait",
        type=float,
        default=5.0,
        help="Seconds to keep the node alive after publishing --message.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    _check(lib.cabi_init_tracing(), "init tracing")

    listen_addr = args.listen or default_listen(args.use_quic)
    identity_seed: Optional[bytes] = None
    if args.seed:
        identity_seed = parse_seed(args.seed)
    elif args.seed_phrase:
        identity_seed = derive_seed_from_phrase(args.seed_phrase)

    def build_node(enable_hop: bool) -> Node:
        return Node(
            use_quic=args.use_quic,
            enable_relay_hop=enable_hop,
            bootstrap_peers=args.bootstrap,
            identity_seed=identity_seed,
        )

    running = threading.Event()
    running.set()

    def handle_signal(sig, frame):
        print("\nReceived signal, shutting down...", flush=True)
        running.clear()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    node: Optional[Node] = None
    recv_thread: Optional[threading.Thread] = None
    autonat_wait = 10.0

    try:
        enable_initial_hop = args.role == "relay" and args.force_hop
        node = build_node(enable_initial_hop)
        print(f"Local PeerId: {node.local_peer_id()}")

        node.listen(listen_addr)

        if args.role == "relay":
            if args.force_hop:
                print("Force hop enabled; relay started with hop support.")
            else:
                print(
                    f"Waiting up to {autonat_wait:.0f}s for PUBLIC AutoNAT before enabling relay hop..."
                )
                if wait_for_public_autonat(node, timeout=autonat_wait):
                    print("AutoNAT PUBLIC detected. Restarting relay with hop enabled.")
                    node.close()
                    node = build_node(True)
                    print(f"Local PeerId: {node.local_peer_id()}")
                    node.listen(listen_addr)
                else:
                    print("AutoNAT did not report PUBLIC; continuing without hop.")

        dial_peers(node, args.bootstrap, "bootstrap")
        dial_peers(node, args.target, "target")

        recv_thread = threading.Thread(
            target=recv_loop, args=(node, running), daemon=True
        )
        recv_thread.start()

        force_stdin = os.environ.get("FIDONEXT_FORCE_STDIN") == "1"
        scripted_message = args.message is not None

        if scripted_message:
            delay = max(args.message_delay, 0.0)
            if delay:
                print(f"Waiting {delay:.1f}s before scripted publish...", flush=True)
                waited = 0.0
                while running.is_set() and waited < delay:
                    time.sleep(0.5)
                    waited += 0.5
            if running.is_set():
                node.send_message(args.message)
                print(f"Scripted payload published: {args.message!r}", flush=True)
            wait_after = max(args.post_message_wait, 0.0)
            waited = 0.0
            while running.is_set() and waited < wait_after:
                time.sleep(0.5)
                waited += 0.5
            running.clear()
        elif sys.stdin.isatty() or force_stdin:
            if force_stdin and not sys.stdin.isatty():
                print("STDIN override enabled; reading scripted input.", flush=True)
            interactive_send_loop(node, running)
        else:
            print("STDIN is non-interactive; running receive-only mode. Press Ctrl+C to exit.")
            while running.is_set():
                time.sleep(1)
    except Exception as exc:
        running.clear()
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        running.clear()
        if recv_thread:
            recv_thread.join(timeout=1.0)
        if node:
            node.close()


if __name__ == "__main__":
    main()

