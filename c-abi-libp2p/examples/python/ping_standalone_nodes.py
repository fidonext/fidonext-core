#!/usr/bin/env python3
"""Standalone node example via the C ABI.

This CLI mirrors the C++ ping example: it exposes the same switches so a single
process can become either a relay or a leaf peer, optionally wires in bootstrap
and target peers, enables relay hop mode when AutoNAT reports PUBLIC, and
forwards stdin payloads over the gossipsub bridge.
"""

import argparse
import ctypes
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Optional, Sequence, Tuple, Union

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
CABI_STATUS_TIMEOUT = 6
CABI_STATUS_NOT_FOUND = 7
CABI_IDENTITY_SEED_LEN = 32
CABI_E2EE_MESSAGE_KIND_UNKNOWN = 0
CABI_E2EE_MESSAGE_KIND_PREKEY = 1
CABI_E2EE_MESSAGE_KIND_SESSION = 2
CABI_DISCOVERY_EVENT_ADDRESS = 0
CABI_DISCOVERY_EVENT_FINISHED = 1

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
lib.cabi_node_find_peer.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_uint64),
]
lib.cabi_node_find_peer.restype = ctypes.c_int
lib.cabi_node_dht_put_record.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_uint64,
]
lib.cabi_node_dht_put_record.restype = ctypes.c_int
lib.cabi_node_dht_get_record.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cabi_node_dht_get_record.restype = ctypes.c_int
lib.cabi_node_dequeue_discovery_event.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_char),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_char),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cabi_node_dequeue_discovery_event.restype = ctypes.c_int
lib.cabi_node_free.argtypes = [ctypes.c_void_p]
lib.cabi_node_free.restype = None
lib.cabi_identity_load_or_create.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_char),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_char),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
]
lib.cabi_identity_load_or_create.restype = ctypes.c_int
lib.cabi_e2ee_build_prekey_bundle.argtypes = [
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cabi_e2ee_build_prekey_bundle.restype = ctypes.c_int
lib.cabi_e2ee_build_message_auto.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cabi_e2ee_build_message_auto.restype = ctypes.c_int
lib.cabi_e2ee_decrypt_message_auto.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_int),
]
lib.cabi_e2ee_decrypt_message_auto.restype = ctypes.c_int
lib.cabi_e2ee_libsignal_probe.argtypes = []
lib.cabi_e2ee_libsignal_probe.restype = ctypes.c_int


def _check(status: int, context: str) -> None:
    if status == CABI_STATUS_SUCCESS:
        return
    if status == CABI_STATUS_NULL_POINTER:
        reason = "null pointer passed into ABI"
    elif status == CABI_STATUS_INVALID_ARGUMENT:
        reason = "invalid argument (multiaddr or UTF-8)"
    elif status == CABI_STATUS_BUFFER_TOO_SMALL:
        reason = "provided buffer too small"
    elif status == CABI_STATUS_TIMEOUT:
        reason = "operation timed out"
    elif status == CABI_STATUS_NOT_FOUND:
        reason = "record not found"
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


def load_or_create_identity_profile(profile_path: Union[str, Path]) -> Tuple[str, str, bytes, bytes]:
    profile_path = Path(profile_path).expanduser().resolve()
    account_buffer_len = 256
    device_buffer_len = 256
    account_buffer = (ctypes.c_char * account_buffer_len)()
    account_written = ctypes.c_size_t(0)
    device_buffer = (ctypes.c_char * device_buffer_len)()
    device_written = ctypes.c_size_t(0)
    libp2p_seed_buffer = (ctypes.c_ubyte * CABI_IDENTITY_SEED_LEN)()
    signal_seed_buffer = (ctypes.c_ubyte * CABI_IDENTITY_SEED_LEN)()

    status = lib.cabi_identity_load_or_create(
        str(profile_path).encode("utf-8"),
        account_buffer,
        ctypes.c_size_t(account_buffer_len),
        ctypes.byref(account_written),
        device_buffer,
        ctypes.c_size_t(device_buffer_len),
        ctypes.byref(device_written),
        libp2p_seed_buffer,
        ctypes.c_size_t(CABI_IDENTITY_SEED_LEN),
        signal_seed_buffer,
        ctypes.c_size_t(CABI_IDENTITY_SEED_LEN),
    )
    _check(status, f"identity_load_or_create({profile_path})")

    account_id = bytes(account_buffer[: account_written.value]).decode("utf-8")
    device_id = bytes(device_buffer[: device_written.value]).decode("utf-8")
    libp2p_seed = bytes(libp2p_seed_buffer)
    signal_seed = bytes(signal_seed_buffer)
    return account_id, device_id, libp2p_seed, signal_seed


def build_prekey_bundle(
    profile_path: Union[str, Path],
    one_time_prekey_count: int = 32,
    ttl_seconds: int = 7 * 24 * 60 * 60,
) -> bytes:
    profile_path = Path(profile_path).expanduser().resolve()
    output_len = 64 * 1024
    output = (ctypes.c_ubyte * output_len)()
    written = ctypes.c_size_t(0)
    status = lib.cabi_e2ee_build_prekey_bundle(
        str(profile_path).encode("utf-8"),
        ctypes.c_size_t(max(one_time_prekey_count, 1)),
        ctypes.c_uint64(max(ttl_seconds, 1)),
        output,
        ctypes.c_size_t(output_len),
        ctypes.byref(written),
    )
    _check(status, f"e2ee_build_prekey_bundle({profile_path})")
    return bytes(output[: written.value])


def build_message_auto(
    profile_path: Union[str, Path],
    recipient_prekey_bundle: bytes,
    plaintext: Union[bytes, bytearray, str],
    aad: Union[bytes, bytearray, str] = b"",
) -> bytes:
    profile_path = Path(profile_path).expanduser().resolve()
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    if isinstance(aad, str):
        aad = aad.encode("utf-8")

    bundle_buf = (ctypes.c_ubyte * len(recipient_prekey_bundle)).from_buffer_copy(
        recipient_prekey_bundle
    )
    plain_buf = (ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
    if aad:
        aad_buf = (ctypes.c_ubyte * len(aad)).from_buffer_copy(aad)
    else:
        aad_buf = None

    output_len = 64 * 1024
    output = (ctypes.c_ubyte * output_len)()
    written = ctypes.c_size_t(0)
    status = lib.cabi_e2ee_build_message_auto(
        str(profile_path).encode("utf-8"),
        bundle_buf,
        ctypes.c_size_t(len(recipient_prekey_bundle)),
        plain_buf,
        ctypes.c_size_t(len(plaintext)),
        aad_buf,
        ctypes.c_size_t(len(aad)),
        output,
        ctypes.c_size_t(output_len),
        ctypes.byref(written),
    )
    _check(status, f"e2ee_build_message_auto({profile_path})")
    return bytes(output[: written.value])


def decrypt_message_auto(profile_path: Union[str, Path], payload: bytes) -> Tuple[int, bytes]:
    profile_path = Path(profile_path).expanduser().resolve()
    payload_buf = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
    output_len = 64 * 1024
    output = (ctypes.c_ubyte * output_len)()
    written = ctypes.c_size_t(0)
    kind = ctypes.c_int(CABI_E2EE_MESSAGE_KIND_UNKNOWN)
    status = lib.cabi_e2ee_decrypt_message_auto(
        str(profile_path).encode("utf-8"),
        payload_buf,
        ctypes.c_size_t(len(payload)),
        output,
        ctypes.c_size_t(output_len),
        ctypes.byref(written),
        ctypes.byref(kind),
    )
    _check(status, f"e2ee_decrypt_message_auto({profile_path})")
    return int(kind.value), bytes(output[: written.value])


def message_kind_name(kind: int) -> str:
    if kind == CABI_E2EE_MESSAGE_KIND_PREKEY:
        return "prekey"
    if kind == CABI_E2EE_MESSAGE_KIND_SESSION:
        return "session"
    return "unknown"


def run_libsignal_probe() -> None:
    status = lib.cabi_e2ee_libsignal_probe()
    _check(status, "e2ee_libsignal_probe")


def extract_session_id(message_payload: bytes) -> Optional[str]:
    try:
        decoded = json.loads(message_payload.decode("utf-8"))
    except Exception:
        return None
    session_id = decoded.get("session_id")
    if isinstance(session_id, str) and session_id.strip():
        return session_id
    return None


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

    def find_peer(self, peer_id: str) -> int:
        request_id = ctypes.c_uint64(0)
        status = lib.cabi_node_find_peer(
            self._ptr,
            peer_id.encode("utf-8"),
            ctypes.byref(request_id),
        )
        _check(status, f"find_peer({peer_id})")
        return int(request_id.value)

    def try_dequeue_discovery_event(
        self, peer_buffer_size: int = 256, address_buffer_size: int = 1024
    ) -> Optional[dict]:
        peer_size = peer_buffer_size
        addr_size = address_buffer_size
        while True:
            kind = ctypes.c_int(0)
            request_id = ctypes.c_uint64(0)
            status_code = ctypes.c_int(0)
            peer_buffer = (ctypes.c_char * peer_size)()
            peer_written = ctypes.c_size_t(0)
            address_buffer = (ctypes.c_char * addr_size)()
            address_written = ctypes.c_size_t(0)
            status = lib.cabi_node_dequeue_discovery_event(
                self._ptr,
                ctypes.byref(kind),
                ctypes.byref(request_id),
                ctypes.byref(status_code),
                peer_buffer,
                ctypes.c_size_t(peer_size),
                ctypes.byref(peer_written),
                address_buffer,
                ctypes.c_size_t(addr_size),
                ctypes.byref(address_written),
            )
            if status == CABI_STATUS_QUEUE_EMPTY:
                return None
            if status == CABI_STATUS_BUFFER_TOO_SMALL:
                peer_size = max(peer_size * 2, peer_written.value + 1)
                addr_size = max(addr_size * 2, address_written.value + 1)
                continue
            _check(status, "dequeue_discovery_event")
            peer_id = bytes(peer_buffer[: peer_written.value]).decode("utf-8", "replace")
            address = bytes(address_buffer[: address_written.value]).decode(
                "utf-8", "replace"
            )
            return {
                "event_kind": int(kind.value),
                "request_id": int(request_id.value),
                "status_code": int(status_code.value),
                "peer_id": peer_id,
                "address": address,
            }

    def dht_put_record(self, key: bytes, value: bytes, ttl_seconds: int = 0) -> None:
        if not key or not value:
            raise ValueError("dht_put_record requires non-empty key and value")
        key_buf = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
        value_buf = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
        status = lib.cabi_node_dht_put_record(
            self._ptr,
            key_buf,
            ctypes.c_size_t(len(key)),
            value_buf,
            ctypes.c_size_t(len(value)),
            ctypes.c_uint64(max(ttl_seconds, 0)),
        )
        _check(status, "dht_put_record")

    def dht_get_record(self, key: bytes, buffer_size: int = 64 * 1024) -> bytes:
        if not key:
            raise ValueError("dht_get_record requires non-empty key")
        key_buf = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
        current_size = buffer_size
        while True:
            out_buffer = (ctypes.c_ubyte * current_size)()
            written = ctypes.c_size_t(0)
            status = lib.cabi_node_dht_get_record(
                self._ptr,
                key_buf,
                ctypes.c_size_t(len(key)),
                out_buffer,
                ctypes.c_size_t(current_size),
                ctypes.byref(written),
            )
            if status == CABI_STATUS_BUFFER_TOO_SMALL:
                current_size = max(current_size * 2, written.value + 1)
                continue
            _check(status, "dht_get_record")
            return bytes(out_buffer[: written.value])

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

    def try_receive_message(self, buffer_size: int = 64 * 1024) -> Optional[bytes]:
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


def recv_loop(
    node: Node,
    running: threading.Event,
    profile_path: Optional[Path] = None,
    decrypt_auto_enabled: bool = False,
    poll_interval: float = 0.1,
) -> None:
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
        if decrypt_auto_enabled and profile_path is not None:
            try:
                kind, plaintext = decrypt_message_auto(profile_path, payload)
                text = plaintext.decode("utf-8", "replace")
                print(
                    f"Received {message_kind_name(kind)} payload: '{text}'",
                    flush=True,
                )
                continue
            except RuntimeError:
                # Payload may be plain (non-E2EE) in mixed mode.
                pass
        text = payload.decode("utf-8", "replace")
        print(f"Received payload: '{text}'", flush=True)


def interactive_send_loop(
    node: Node,
    running: threading.Event,
    profile_path: Optional[Path] = None,
    recipient_prekey_bundle: Optional[bytes] = None,
    prekey_aad: str = "",
) -> None:
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
            payload_text = line.rstrip("\n")
            if recipient_prekey_bundle is not None and profile_path is not None:
                payload = build_message_auto(
                    profile_path,
                    recipient_prekey_bundle,
                    payload_text,
                    prekey_aad,
                )
                node.send_message(payload)
            else:
                node.send_message(payload_text)

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
        "--profile",
        help="Path to local identity profile (creates on first run). "
        "Provides stable account/device IDs and libp2p identity seed.",
    )
    parser.add_argument(
        "--dump-prekey-bundle",
        action="store_true",
        help="Build and print a signed pre-key bundle JSON (requires --profile), then exit.",
    )
    parser.add_argument(
        "--prekey-count",
        type=int,
        default=32,
        help="Number of one-time pre-keys to include when building pre-key bundle.",
    )
    parser.add_argument(
        "--prekey-ttl",
        type=int,
        default=7 * 24 * 60 * 60,
        help="Pre-key bundle lifetime in seconds.",
    )
    parser.add_argument(
        "--encrypt-to-prekey-bundle-file",
        help="Path to recipient pre-key bundle JSON file. Outgoing payloads use libsignal auto E2EE.",
    )
    parser.add_argument(
        "--prekey-aad",
        default="",
        help="Optional AAD string for libsignal message encryption.",
    )
    parser.add_argument(
        "--libsignal-probe",
        action="store_true",
        help="Run official libsignal in-memory probe through C-ABI and exit.",
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

    if args.libsignal_probe:
        run_libsignal_probe()
        print("libsignal probe OK")
        return

    if args.dump_prekey_bundle:
        if not args.profile:
            raise ValueError("--dump-prekey-bundle requires --profile")
        bundle = build_prekey_bundle(
            args.profile,
            one_time_prekey_count=max(args.prekey_count, 1),
            ttl_seconds=max(args.prekey_ttl, 1),
        )
        print(bundle.decode("utf-8"))
        return

    if args.encrypt_to_prekey_bundle_file and not args.profile:
        raise ValueError("--encrypt-to-prekey-bundle-file requires --profile")

    recipient_prekey_bundle: Optional[bytes] = None
    profile_path_obj: Optional[Path] = None
    if args.profile:
        profile_path_obj = Path(args.profile).expanduser().resolve()
    if args.encrypt_to_prekey_bundle_file:
        bundle_path = Path(args.encrypt_to_prekey_bundle_file).expanduser().resolve()
        recipient_prekey_bundle = bundle_path.read_bytes()
    encrypt_auto_enabled = (
        profile_path_obj is not None
        and recipient_prekey_bundle is not None
    )
    decrypt_auto_enabled = (
        profile_path_obj is not None
    )

    listen_addr = args.listen or default_listen(args.use_quic)
    identity_seed: Optional[bytes] = None
    if args.profile and (args.seed or args.seed_phrase):
        raise ValueError("--profile cannot be combined with --seed or --seed-phrase")

    if args.profile:
        account_id, device_id, profile_seed, _signal_seed = load_or_create_identity_profile(
            args.profile
        )
        print(f"Local AccountId: {account_id}")
        print(f"Local DeviceId: {device_id}")
        identity_seed = profile_seed
    elif args.seed:
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
            target=recv_loop,
            kwargs={
                "node": node,
                "running": running,
                "profile_path": profile_path_obj,
                "decrypt_auto_enabled": decrypt_auto_enabled,
            },
            daemon=True,
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
                payloads: list[Union[bytes, str]] = []
                if encrypt_auto_enabled and recipient_prekey_bundle is not None and profile_path_obj is not None:
                    payload = build_message_auto(
                        profile_path_obj,
                        recipient_prekey_bundle,
                        args.message,
                        args.prekey_aad,
                    )
                    payloads.append(payload)
                    session_id = extract_session_id(payload)
                    print(
                        "Scripted payload published as libsignal auto E2EE message"
                        + (
                            f" (session_id={session_id})."
                            if session_id is not None
                            else "."
                        ),
                        flush=True,
                    )
                else:
                    print(f"Scripted payload published: {args.message!r}", flush=True)
                    payloads.append(args.message)
                for payload in payloads:
                    node.send_message(payload)
            wait_after = max(args.post_message_wait, 0.0)
            waited = 0.0
            while running.is_set() and waited < wait_after:
                time.sleep(0.5)
                waited += 0.5
            running.clear()
        elif sys.stdin.isatty() or force_stdin:
            if force_stdin and not sys.stdin.isatty():
                print("STDIN override enabled; reading scripted input.", flush=True)
            interactive_send_loop(
                node,
                running,
                profile_path=profile_path_obj,
                recipient_prekey_bundle=recipient_prekey_bundle,
                prekey_aad=args.prekey_aad,
            )
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

