#!/usr/bin/env python3
"""Standalone node example via the C ABI.

This CLI mirrors the C++ ping example: it exposes the same switches so a single
process can become either a relay or a leaf peer, optionally wires in bootstrap
and target peers, enables relay hop mode when AutoNAT reports PUBLIC, and
forwards stdin payloads over the gossipsub bridge.
"""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import ctypes
import hashlib
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

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
CABI_STATUS_QUEUE_EMPTY = -1
CABI_STATUS_BUFFER_TOO_SMALL = -2
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

BOOTSTRAP_MANIFEST_SCHEMA = "fidonext-bootstrap-manifest-v1"
BOOTSTRAP_MANIFEST_STATE_SCHEMA = "fidonext-bootstrap-manifest-state-v1"
KNOWN_PEERS_SCHEMA = "fidonext-known-peers-v1"
RELAY_DESCRIPTOR_SCHEMA = "fidonext-relay-descriptor-v1"
RELAY_DESCRIPTOR_DHT_PREFIX = "fidonext-relay-v1/descriptor"
MAX_MANIFEST_CLOCK_SKEW_SECONDS = 5 * 60
MAX_MANIFEST_ADDR_COUNT = 2048
DEFAULT_KNOWN_PEERS_MAX = 1500
DEFAULT_STARTUP_DIAL_K = 8
DEFAULT_STARTUP_DIAL_WORKERS = 8
MAX_STARTUP_DIAL_WORKERS = 32
DEFAULT_RELAY_DESCRIPTOR_TTL_SECONDS = 30 * 60
DEFAULT_RELAY_DESCRIPTOR_QUERY_MAX = 24

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
lib.cabi_node_new_v2.argtypes = [
    ctypes.c_bool,
    ctypes.c_bool,
    ctypes.c_bool,
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
]
lib.cabi_node_new_v2.restype = ctypes.c_void_p
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
lib.cabi_e2ee_validate_prekey_bundle.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_uint64,
]
lib.cabi_e2ee_validate_prekey_bundle.restype = ctypes.c_int
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
lib.cabi_e2ee_encrypt_file_chunk.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cabi_e2ee_encrypt_file_chunk.restype = ctypes.c_int
lib.cabi_e2ee_decrypt_file_chunk.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cabi_e2ee_decrypt_file_chunk.restype = ctypes.c_int
lib.cabi_e2ee_file_sha256.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
]
lib.cabi_e2ee_file_sha256.restype = ctypes.c_int
lib.cabi_e2ee_build_file_manifest.argtypes = [
    ctypes.c_char_p,
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cabi_e2ee_build_file_manifest.restype = ctypes.c_int
lib.cabi_e2ee_verify_file_manifest.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
]
lib.cabi_e2ee_verify_file_manifest.restype = ctypes.c_int
lib.cabi_e2ee_libsignal_probe.argtypes = []
lib.cabi_e2ee_libsignal_probe.restype = ctypes.c_int
lib.cabi_identity_verify_signature.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
]
lib.cabi_identity_verify_signature.restype = ctypes.c_int
lib.cabi_identity_public_key_from_seed.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cabi_identity_public_key_from_seed.restype = ctypes.c_int
lib.cabi_identity_sign_with_seed.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cabi_identity_sign_with_seed.restype = ctypes.c_int
lib.cabi_identity_peer_id_from_public_key.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cabi_identity_peer_id_from_public_key.restype = ctypes.c_int


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


def load_text_list_file(path: Path) -> List[str]:
    values: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        values.append(line)
    return values


def _normalize_multiaddrs(values: Sequence[str], limit: int = MAX_MANIFEST_ADDR_COUNT) -> List[str]:
    result: List[str] = []
    seen = set()
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        if text in seen:
            continue
        seen.add(text)
        result.append(text)
        if len(result) >= limit:
            break
    return result


def _canonical_manifest_unsigned_payload(manifest: Dict[str, Any]) -> bytes:
    payload = {
        "schema": BOOTSTRAP_MANIFEST_SCHEMA,
        "manifest_version": int(manifest["manifest_version"]),
        "issued_at_unix": int(manifest["issued_at_unix"]),
        "expires_at_unix": int(manifest["expires_at_unix"]),
        "signing_public_key_b64": str(manifest["signing_public_key_b64"]),
        "bootstrap_multiaddrs": _normalize_multiaddrs(manifest["bootstrap_multiaddrs"]),
        "bridge_multiaddrs": _normalize_multiaddrs(manifest.get("bridge_multiaddrs") or []),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _verify_manifest_signature(
    signing_public_key_b64: str, unsigned_payload: bytes, signature_b64: str
) -> None:
    try:
        public_key = base64.b64decode(signing_public_key_b64, validate=True)
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise ValueError("manifest contains invalid base64 in signing key or signature") from exc
    if not public_key or not signature:
        raise ValueError("manifest signing key/signature must be non-empty")

    public_key_buf = (ctypes.c_ubyte * len(public_key))(*public_key)
    payload_buf = (ctypes.c_ubyte * len(unsigned_payload))(*unsigned_payload)
    signature_buf = (ctypes.c_ubyte * len(signature))(*signature)
    status = lib.cabi_identity_verify_signature(
        ctypes.cast(public_key_buf, ctypes.POINTER(ctypes.c_ubyte)),
        ctypes.c_size_t(len(public_key)),
        ctypes.cast(payload_buf, ctypes.POINTER(ctypes.c_ubyte)),
        ctypes.c_size_t(len(unsigned_payload)),
        ctypes.cast(signature_buf, ctypes.POINTER(ctypes.c_ubyte)),
        ctypes.c_size_t(len(signature)),
    )
    if status != CABI_STATUS_SUCCESS:
        raise ValueError("manifest signature verification failed")


def _parse_manifest_file(path: Path) -> Dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("manifest root must be a JSON object")
    if raw.get("schema") != BOOTSTRAP_MANIFEST_SCHEMA:
        raise ValueError(f"manifest schema must be {BOOTSTRAP_MANIFEST_SCHEMA!r}")

    required = (
        "manifest_version",
        "issued_at_unix",
        "expires_at_unix",
        "signing_public_key_b64",
        "bootstrap_multiaddrs",
        "signature_b64",
    )
    for key in required:
        if key not in raw:
            raise ValueError(f"manifest is missing required field: {key}")

    manifest_version = int(raw["manifest_version"])
    issued_at_unix = int(raw["issued_at_unix"])
    expires_at_unix = int(raw["expires_at_unix"])
    if manifest_version < 1:
        raise ValueError("manifest_version must be >= 1")
    if expires_at_unix <= issued_at_unix:
        raise ValueError("manifest expires_at_unix must be greater than issued_at_unix")

    bootstrap_multiaddrs = raw["bootstrap_multiaddrs"]
    bridge_multiaddrs = raw.get("bridge_multiaddrs") or []
    if not isinstance(bootstrap_multiaddrs, list):
        raise ValueError("bootstrap_multiaddrs must be a JSON array")
    if not isinstance(bridge_multiaddrs, list):
        raise ValueError("bridge_multiaddrs must be a JSON array when present")

    normalized_bootstrap = _normalize_multiaddrs(bootstrap_multiaddrs)
    normalized_bridges = _normalize_multiaddrs(bridge_multiaddrs)
    if not normalized_bootstrap:
        raise ValueError("manifest bootstrap_multiaddrs is empty after normalization")

    return {
        "schema": BOOTSTRAP_MANIFEST_SCHEMA,
        "manifest_version": manifest_version,
        "issued_at_unix": issued_at_unix,
        "expires_at_unix": expires_at_unix,
        "signing_public_key_b64": str(raw["signing_public_key_b64"]).strip(),
        "bootstrap_multiaddrs": normalized_bootstrap,
        "bridge_multiaddrs": normalized_bridges,
        "signature_b64": str(raw["signature_b64"]).strip(),
    }


def _default_manifest_state_path(manifest_paths: Sequence[Path]) -> Path:
    first = manifest_paths[0]
    return first.with_suffix(first.suffix + ".state.json")


def _load_manifest_state(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"schema": BOOTSTRAP_MANIFEST_STATE_SCHEMA, "last_applied_version": 0}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"invalid manifest state file: {path}") from exc
    if not isinstance(raw, dict) or raw.get("schema") != BOOTSTRAP_MANIFEST_STATE_SCHEMA:
        raise ValueError(f"unexpected manifest state schema in {path}")
    version = int(raw.get("last_applied_version", 0))
    return {"schema": BOOTSTRAP_MANIFEST_STATE_SCHEMA, "last_applied_version": max(version, 0)}


def _write_manifest_state(path: Path, *, manifest_version: int, manifest_hash_hex: str) -> None:
    payload = {
        "schema": BOOTSTRAP_MANIFEST_STATE_SCHEMA,
        "last_applied_version": int(manifest_version),
        "last_manifest_hash_hex": manifest_hash_hex,
        "updated_at_unix": int(time.time()),
    }
    if path.parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    tmp.replace(path)


def load_bootstrap_from_manifests(
    manifest_paths: Sequence[Path],
    *,
    allowed_signing_keys_b64: Sequence[str],
    state_path: Optional[Path] = None,
    allow_rollback: bool = False,
) -> List[str]:
    if not manifest_paths:
        return []

    allowed_signers = {item.strip() for item in allowed_signing_keys_b64 if str(item).strip()}
    if not allowed_signers:
        raise ValueError(
            "bootstrap-manifest requires at least one trusted signing key "
            "(--manifest-allowed-signing-key or --manifest-allowed-signing-key-file)"
        )

    state_file = state_path or _default_manifest_state_path(manifest_paths)
    state = _load_manifest_state(state_file)
    last_applied_version = int(state.get("last_applied_version", 0))
    now = int(time.time())
    candidates: List[Dict[str, Any]] = []
    errors: List[str] = []

    for path in manifest_paths:
        try:
            manifest = _parse_manifest_file(path)
            signer = manifest["signing_public_key_b64"]
            if signer not in allowed_signers:
                raise ValueError("manifest signing key is not in trusted signer set")

            unsigned_payload = _canonical_manifest_unsigned_payload(manifest)
            _verify_manifest_signature(
                manifest["signing_public_key_b64"],
                unsigned_payload,
                manifest["signature_b64"],
            )

            if manifest["issued_at_unix"] > now + MAX_MANIFEST_CLOCK_SKEW_SECONDS:
                raise ValueError("manifest issued_at_unix is too far in the future")
            if manifest["expires_at_unix"] <= now - MAX_MANIFEST_CLOCK_SKEW_SECONDS:
                raise ValueError("manifest is expired")

            if not allow_rollback and manifest["manifest_version"] <= last_applied_version:
                continue

            manifest_hash_hex = hashlib.sha256(unsigned_payload).hexdigest()
            manifest["_hash_hex"] = manifest_hash_hex
            manifest["_source_path"] = str(path)
            candidates.append(manifest)
        except Exception as exc:
            errors.append(f"{path}: {exc}")

    if not candidates:
        if errors and last_applied_version == 0:
            joined = "\n  - ".join(errors)
            raise ValueError(f"no valid bootstrap manifests found:\n  - {joined}")
        if errors:
            print(
                "[manifest] no newer valid manifest found; continuing with existing state. "
                "errors:\n  - "
                + "\n  - ".join(errors),
                file=sys.stderr,
            )
        return []

    best = sorted(
        candidates,
        key=lambda item: (int(item["manifest_version"]), int(item["issued_at_unix"])),
        reverse=True,
    )[0]
    _write_manifest_state(
        state_file,
        manifest_version=int(best["manifest_version"]),
        manifest_hash_hex=str(best["_hash_hex"]),
    )
    print(
        "[manifest] applied"
        f" version={best['manifest_version']}"
        f" source={best['_source_path']}"
        f" addrs={len(best['bootstrap_multiaddrs']) + len(best['bridge_multiaddrs'])}",
        flush=True,
    )
    return _normalize_multiaddrs(
        list(best["bootstrap_multiaddrs"]) + list(best["bridge_multiaddrs"])
    )


def extract_peer_id_from_multiaddr(addr: str) -> Optional[str]:
    marker = "/p2p/"
    if marker not in addr:
        return None
    value = addr.rsplit(marker, 1)[-1].strip()
    return value if value else None


def ensure_multiaddr_has_peer_id(addr: str, peer_id: str) -> str:
    value = str(addr).strip()
    if not value:
        return value
    current = extract_peer_id_from_multiaddr(value)
    if current:
        return value
    if value.endswith("/"):
        value = value[:-1]
    return f"{value}/p2p/{peer_id}"


def identity_public_key_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("identity seed must be exactly 32 bytes")
    seed_buf = (ctypes.c_ubyte * len(seed)).from_buffer_copy(seed)
    out_size = 256
    while True:
        out_buf = (ctypes.c_ubyte * out_size)()
        written = ctypes.c_size_t(0)
        status = lib.cabi_identity_public_key_from_seed(
            seed_buf,
            ctypes.c_size_t(len(seed)),
            out_buf,
            ctypes.c_size_t(out_size),
            ctypes.byref(written),
        )
        if status == CABI_STATUS_BUFFER_TOO_SMALL:
            out_size = max(out_size * 2, written.value + 1)
            continue
        _check(status, "identity_public_key_from_seed")
        return bytes(out_buf[: written.value])


def identity_sign_with_seed(seed: bytes, payload: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("identity seed must be exactly 32 bytes")
    if not payload:
        raise ValueError("identity_sign_with_seed requires non-empty payload")
    seed_buf = (ctypes.c_ubyte * len(seed)).from_buffer_copy(seed)
    payload_buf = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
    out_size = 256
    while True:
        out_buf = (ctypes.c_ubyte * out_size)()
        written = ctypes.c_size_t(0)
        status = lib.cabi_identity_sign_with_seed(
            seed_buf,
            ctypes.c_size_t(len(seed)),
            payload_buf,
            ctypes.c_size_t(len(payload)),
            out_buf,
            ctypes.c_size_t(out_size),
            ctypes.byref(written),
        )
        if status == CABI_STATUS_BUFFER_TOO_SMALL:
            out_size = max(out_size * 2, written.value + 1)
            continue
        _check(status, "identity_sign_with_seed")
        return bytes(out_buf[: written.value])


def identity_peer_id_from_public_key(public_key: bytes) -> str:
    if not public_key:
        raise ValueError("public key cannot be empty")
    key_buf = (ctypes.c_ubyte * len(public_key)).from_buffer_copy(public_key)
    out_size = 128
    while True:
        out_buf = (ctypes.c_char * out_size)()
        written = ctypes.c_size_t(0)
        status = lib.cabi_identity_peer_id_from_public_key(
            key_buf,
            ctypes.c_size_t(len(public_key)),
            ctypes.cast(out_buf, ctypes.c_void_p),
            ctypes.c_size_t(out_size),
            ctypes.byref(written),
        )
        if status == CABI_STATUS_BUFFER_TOO_SMALL:
            out_size = max(out_size * 2, written.value + 1)
            continue
        _check(status, "identity_peer_id_from_public_key")
        return bytes(out_buf[: written.value]).decode("utf-8")


def relay_descriptor_dht_key(peer_id: str) -> bytes:
    return f"{RELAY_DESCRIPTOR_DHT_PREFIX}/{peer_id}".encode("utf-8")


def _canonical_relay_descriptor_unsigned_payload(descriptor: Dict[str, Any]) -> bytes:
    payload = {
        "schema": RELAY_DESCRIPTOR_SCHEMA,
        "peer_id": str(descriptor["peer_id"]),
        "issued_at_unix": int(descriptor["issued_at_unix"]),
        "expires_at_unix": int(descriptor["expires_at_unix"]),
        "signing_public_key_b64": str(descriptor["signing_public_key_b64"]),
        "listen_addrs": _normalize_multiaddrs(descriptor["listen_addrs"], limit=256),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def build_relay_descriptor(
    *,
    local_peer_id: str,
    listen_addrs: Sequence[str],
    identity_seed: bytes,
    ttl_seconds: int,
) -> Dict[str, Any]:
    if len(identity_seed) != 32:
        raise ValueError("relay descriptor requires 32-byte identity seed")
    normalized_addrs = _normalize_multiaddrs(
        [ensure_multiaddr_has_peer_id(addr, local_peer_id) for addr in listen_addrs],
        limit=256,
    )
    if not normalized_addrs:
        raise ValueError("relay descriptor requires at least one listen address")

    public_key = identity_public_key_from_seed(identity_seed)
    derived_peer_id = identity_peer_id_from_public_key(public_key)
    if derived_peer_id != local_peer_id:
        raise ValueError(
            "relay descriptor signer mismatch: seed-derived peer_id does not match local peer_id"
        )

    now_unix = int(time.time())
    ttl = max(60, min(int(ttl_seconds), 24 * 60 * 60))
    descriptor = {
        "schema": RELAY_DESCRIPTOR_SCHEMA,
        "peer_id": local_peer_id,
        "issued_at_unix": now_unix,
        "expires_at_unix": now_unix + ttl,
        "signing_public_key_b64": base64.b64encode(public_key).decode("ascii"),
        "listen_addrs": normalized_addrs,
    }
    unsigned_payload = _canonical_relay_descriptor_unsigned_payload(descriptor)
    signature = identity_sign_with_seed(identity_seed, unsigned_payload)
    descriptor["signature_b64"] = base64.b64encode(signature).decode("ascii")
    return descriptor


def publish_relay_descriptor(
    node: "Node",
    *,
    local_peer_id: str,
    listen_addrs: Sequence[str],
    identity_seed: Optional[bytes],
    ttl_seconds: int = DEFAULT_RELAY_DESCRIPTOR_TTL_SECONDS,
) -> Optional[Dict[str, Any]]:
    if identity_seed is None:
        return None
    descriptor = build_relay_descriptor(
        local_peer_id=local_peer_id,
        listen_addrs=listen_addrs,
        identity_seed=identity_seed,
        ttl_seconds=ttl_seconds,
    )
    key = relay_descriptor_dht_key(local_peer_id)
    payload = json.dumps(descriptor, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    node.dht_put_record(key, payload, ttl_seconds=max(60, min(int(ttl_seconds), 24 * 60 * 60)))
    return descriptor


def validate_relay_descriptor(
    payload: bytes,
    *,
    now_unix: Optional[int] = None,
) -> Dict[str, Any]:
    try:
        raw = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise ValueError("relay descriptor payload is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError("relay descriptor root must be JSON object")
    if raw.get("schema") != RELAY_DESCRIPTOR_SCHEMA:
        raise ValueError(f"relay descriptor schema must be {RELAY_DESCRIPTOR_SCHEMA!r}")
    required = (
        "peer_id",
        "issued_at_unix",
        "expires_at_unix",
        "signing_public_key_b64",
        "listen_addrs",
        "signature_b64",
    )
    for key in required:
        if key not in raw:
            raise ValueError(f"relay descriptor missing field: {key}")
    peer_id = str(raw["peer_id"]).strip()
    if not peer_id:
        raise ValueError("relay descriptor peer_id is empty")
    issued = int(raw["issued_at_unix"])
    expires = int(raw["expires_at_unix"])
    if expires <= issued:
        raise ValueError("relay descriptor expires_at_unix must be greater than issued_at_unix")
    current = now_unix if now_unix is not None else int(time.time())
    if issued > current + MAX_MANIFEST_CLOCK_SKEW_SECONDS:
        raise ValueError("relay descriptor issued_at_unix is too far in future")
    if expires <= current - MAX_MANIFEST_CLOCK_SKEW_SECONDS:
        raise ValueError("relay descriptor is expired")

    listen_addrs = _normalize_multiaddrs(raw["listen_addrs"], limit=256)
    if not listen_addrs:
        raise ValueError("relay descriptor listen_addrs is empty")
    listen_addrs = [ensure_multiaddr_has_peer_id(item, peer_id) for item in listen_addrs]

    unsigned_payload = _canonical_relay_descriptor_unsigned_payload(
        {
            "peer_id": peer_id,
            "issued_at_unix": issued,
            "expires_at_unix": expires,
            "signing_public_key_b64": str(raw["signing_public_key_b64"]).strip(),
            "listen_addrs": listen_addrs,
        }
    )
    _verify_manifest_signature(
        str(raw["signing_public_key_b64"]).strip(),
        unsigned_payload,
        str(raw["signature_b64"]).strip(),
    )
    public_key = base64.b64decode(str(raw["signing_public_key_b64"]).strip(), validate=True)
    derived_peer_id = identity_peer_id_from_public_key(public_key)
    if derived_peer_id != peer_id:
        raise ValueError("relay descriptor signer does not match peer_id")

    return {
        "schema": RELAY_DESCRIPTOR_SCHEMA,
        "peer_id": peer_id,
        "issued_at_unix": issued,
        "expires_at_unix": expires,
        "signing_public_key_b64": str(raw["signing_public_key_b64"]).strip(),
        "listen_addrs": listen_addrs,
        "signature_b64": str(raw["signature_b64"]).strip(),
    }


def discover_relay_descriptors(
    node: "Node",
    peer_ids: Sequence[str],
    *,
    max_queries: int = DEFAULT_RELAY_DESCRIPTOR_QUERY_MAX,
) -> List[Dict[str, Any]]:
    unique_peer_ids: List[str] = []
    seen = set()
    for value in peer_ids:
        peer_id = str(value).strip()
        if not peer_id or peer_id in seen:
            continue
        seen.add(peer_id)
        unique_peer_ids.append(peer_id)
        if len(unique_peer_ids) >= max(1, int(max_queries)):
            break

    descriptors: List[Dict[str, Any]] = []
    for peer_id in unique_peer_ids:
        try:
            payload = node.dht_get_record(relay_descriptor_dht_key(peer_id))
        except RuntimeError:
            continue
        try:
            descriptor = validate_relay_descriptor(payload)
        except Exception:
            continue
        descriptors.append(descriptor)
    return descriptors


def merge_peer_source(existing: str, new: str) -> str:
    priority = {
        "manifest": 5,
        "static_file": 4,
        "cli": 3,
        "descriptor": 3,
        "cache": 2,
        "discovery": 1,
    }
    left = str(existing or "").strip() or "cache"
    right = str(new or "").strip() or "cache"
    return right if priority.get(right, 0) >= priority.get(left, 0) else left


def resolve_known_peers_path(
    explicit_path: Optional[Path], profile_path: Optional[Path]
) -> Path:
    if explicit_path is not None:
        return explicit_path
    if profile_path is not None:
        return profile_path.with_suffix(profile_path.suffix + ".known_peers.json")
    return (Path.cwd() / ".fidonext_known_peers.json").resolve()


def _empty_known_peer_entry(address: str, source: str = "cache") -> Dict[str, Any]:
    return {
        "address": str(address).strip(),
        "source": str(source).strip() or "cache",
        "last_success_unix": 0,
        "last_failure_unix": 0,
        "last_attempt_unix": 0,
        "success_count": 0,
        "fail_count": 0,
        "backoff_until_unix": 0,
    }


def load_known_peers_file(path: Path, *, max_entries: int = DEFAULT_KNOWN_PEERS_MAX) -> Dict[str, Dict[str, Any]]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(raw, dict) or raw.get("schema") != KNOWN_PEERS_SCHEMA:
        return {}
    entries = raw.get("entries")
    if not isinstance(entries, list):
        return {}

    result: Dict[str, Dict[str, Any]] = {}
    max_allowed = max(1, int(max_entries))
    for item in entries:
        if not isinstance(item, dict):
            continue
        address = str(item.get("address") or "").strip()
        if not address or address in result:
            continue
        entry = _empty_known_peer_entry(address, str(item.get("source") or "cache"))
        entry["last_success_unix"] = max(0, int(item.get("last_success_unix", 0)))
        entry["last_failure_unix"] = max(0, int(item.get("last_failure_unix", 0)))
        entry["last_attempt_unix"] = max(0, int(item.get("last_attempt_unix", 0)))
        entry["success_count"] = max(0, int(item.get("success_count", 0)))
        entry["fail_count"] = max(0, int(item.get("fail_count", 0)))
        entry["backoff_until_unix"] = max(0, int(item.get("backoff_until_unix", 0)))
        result[address] = entry
        if len(result) >= max_allowed:
            break
    return result


def _known_peer_score(entry: Dict[str, Any], now_unix: int) -> float:
    source_weight = {
        "manifest": 100.0,
        "static_file": 80.0,
        "cli": 70.0,
        "descriptor": 75.0,
        "cache": 55.0,
        "discovery": 60.0,
    }.get(str(entry.get("source") or "cache"), 50.0)
    success_count = float(max(0, int(entry.get("success_count", 0))))
    fail_count = float(max(0, int(entry.get("fail_count", 0))))
    last_success = int(entry.get("last_success_unix", 0))
    last_failure = int(entry.get("last_failure_unix", 0))
    backoff_until = int(entry.get("backoff_until_unix", 0))

    score = source_weight + min(success_count, 100.0) * 2.0 - min(fail_count, 100.0) * 5.0
    if last_success > 0:
        age_hours = max(0.0, float(now_unix - last_success) / 3600.0)
        score += max(0.0, 48.0 - age_hours)
    if last_failure > 0 and now_unix - last_failure < 600:
        score -= 20.0
    if backoff_until > now_unix:
        score -= 1000.0
    return score


def save_known_peers_file(
    path: Path,
    entries: Dict[str, Dict[str, Any]],
    *,
    max_entries: int = DEFAULT_KNOWN_PEERS_MAX,
) -> None:
    now_unix = int(time.time())
    ranked = sorted(
        entries.values(),
        key=lambda item: _known_peer_score(item, now_unix),
        reverse=True,
    )
    limit = max(1, int(max_entries))
    payload = {
        "schema": KNOWN_PEERS_SCHEMA,
        "updated_at_unix": now_unix,
        "entries": ranked[:limit],
    }
    if path.parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    tmp.replace(path)


def build_bootstrap_candidates(
    seed_sources: Dict[str, str],
    known_peers: Dict[str, Dict[str, Any]],
    *,
    max_candidates: int = DEFAULT_KNOWN_PEERS_MAX,
) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for address, entry in known_peers.items():
        merged[address] = dict(entry)
    for address, source in seed_sources.items():
        existing = merged.get(address)
        if existing is None:
            merged[address] = _empty_known_peer_entry(address, source)
            continue
        existing["source"] = merge_peer_source(str(existing.get("source") or "cache"), source)
        merged[address] = existing

    now_unix = int(time.time())
    ranked = sorted(
        merged.values(),
        key=lambda item: _known_peer_score(item, now_unix),
        reverse=True,
    )
    return ranked[: max(1, int(max_candidates))]


def dial_bootstrap_top_k(
    node: "Node",
    candidates: Sequence[Dict[str, Any]],
    *,
    startup_dial_k: int = DEFAULT_STARTUP_DIAL_K,
    startup_dial_workers: int = DEFAULT_STARTUP_DIAL_WORKERS,
) -> List[Dict[str, Any]]:
    if not candidates:
        return []
    top_k = max(1, int(startup_dial_k))
    selected = list(candidates[:top_k])
    workers = max(1, min(int(startup_dial_workers), MAX_STARTUP_DIAL_WORKERS, len(selected)))
    results: List[Dict[str, Any]] = []

    def _dial(candidate: Dict[str, Any]) -> Dict[str, Any]:
        address = str(candidate.get("address") or "").strip()
        source = str(candidate.get("source") or "cache")
        if not address:
            return {"address": address, "source": source, "success": False, "error": "empty address"}
        try:
            node.dial(address)
            return {"address": address, "source": source, "success": True, "error": None}
        except RuntimeError as exc:
            return {"address": address, "source": source, "success": False, "error": str(exc)}

    if workers == 1:
        for candidate in selected:
            results.append(_dial(candidate))
        return results

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_dial, candidate) for candidate in selected]
        for future in as_completed(futures):
            results.append(future.result())
    return results


def update_known_peers_after_dial(
    known_peers: Dict[str, Dict[str, Any]],
    dial_results: Sequence[Dict[str, Any]],
) -> None:
    now_unix = int(time.time())
    for item in dial_results:
        address = str(item.get("address") or "").strip()
        if not address:
            continue
        source = str(item.get("source") or "cache")
        success = bool(item.get("success"))
        entry = dict(known_peers.get(address) or _empty_known_peer_entry(address, source))
        entry["source"] = merge_peer_source(str(entry.get("source") or "cache"), source)
        entry["last_attempt_unix"] = now_unix
        if success:
            entry["last_success_unix"] = now_unix
            entry["success_count"] = max(0, int(entry.get("success_count", 0))) + 1
            entry["fail_count"] = 0
            entry["backoff_until_unix"] = 0
        else:
            fail_count = max(0, int(entry.get("fail_count", 0))) + 1
            backoff = min(1800, 2 ** min(fail_count, 10))
            entry["last_failure_unix"] = now_unix
            entry["fail_count"] = fail_count
            entry["backoff_until_unix"] = now_unix + backoff
        known_peers[address] = entry


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


def validate_prekey_bundle(payload: bytes, now_unix: int = 0) -> None:
    if not payload:
        raise ValueError("prekey bundle payload cannot be empty")
    payload_buf = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
    status = lib.cabi_e2ee_validate_prekey_bundle(
        payload_buf,
        ctypes.c_size_t(len(payload)),
        ctypes.c_uint64(max(int(now_unix), 0)),
    )
    _check(status, "e2ee_validate_prekey_bundle")


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

# Encrypts a single file chunk via C ABI with chunk-bound AAD context.
def encrypt_file_chunk(
    file_key: bytes,
    file_id: str,
    chunk_index: int,
    sequence: int,
    plaintext: Union[bytes, bytearray, str],
) -> bytes:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    key_buf = (ctypes.c_ubyte * len(file_key)).from_buffer_copy(file_key)
    plain_buf = (ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
    output_len = max(4096, len(plaintext) * 2)
    output = (ctypes.c_ubyte * output_len)()
    written = ctypes.c_size_t(0)
    status = lib.cabi_e2ee_encrypt_file_chunk(
        key_buf,
        ctypes.c_size_t(len(file_key)),
        file_id.encode("utf-8"),
        ctypes.c_uint64(chunk_index),
        ctypes.c_uint64(sequence),
        plain_buf,
        ctypes.c_size_t(len(plaintext)),
        output,
        ctypes.c_size_t(output_len),
        ctypes.byref(written),
    )
    _check(status, "e2ee_encrypt_file_chunk")
    return bytes(output[: written.value])


# Decrypts and authenticates a single file chunk via C ABI.
def decrypt_file_chunk(
    file_key: bytes,
    file_id: str,
    chunk_index: int,
    sequence: int,
    encoded_chunk: bytes,
) -> bytes:
    key_buf = (ctypes.c_ubyte * len(file_key)).from_buffer_copy(file_key)
    chunk_buf = (ctypes.c_ubyte * len(encoded_chunk)).from_buffer_copy(encoded_chunk)
    output_len = max(4096, len(encoded_chunk))
    output = (ctypes.c_ubyte * output_len)()
    written = ctypes.c_size_t(0)
    status = lib.cabi_e2ee_decrypt_file_chunk(
        key_buf,
        ctypes.c_size_t(len(file_key)),
        file_id.encode("utf-8"),
        ctypes.c_uint64(chunk_index),
        ctypes.c_uint64(sequence),
        chunk_buf,
        ctypes.c_size_t(len(encoded_chunk)),
        output,
        ctypes.c_size_t(output_len),
        ctypes.byref(written),
    )
    _check(status, "e2ee_decrypt_file_chunk")
    return bytes(output[: written.value])


# Computes SHA-256 digest of a file via streaming C ABI helper.
def file_sha256(file_path: Union[str, Path]) -> bytes:
    path = Path(file_path).expanduser().resolve()
    out = (ctypes.c_ubyte * 32)()
    status = lib.cabi_e2ee_file_sha256(str(path).encode("utf-8"), out, ctypes.c_size_t(32))
    _check(status, f"e2ee_file_sha256({path})")
    return bytes(out)


# Builds a file integrity manifest payload with optional signature bytes.
def build_file_manifest(
    file_id: str,
    total_chunks: int,
    file_sha256_digest: bytes,
    signature: bytes = b"",
) -> bytes:
    sha_buf = (ctypes.c_ubyte * len(file_sha256_digest)).from_buffer_copy(file_sha256_digest)
    sig_buf = (
        (ctypes.c_ubyte * len(signature)).from_buffer_copy(signature)
        if signature
        else None
    )
    output_len = 4096
    output = (ctypes.c_ubyte * output_len)()
    written = ctypes.c_size_t(0)
    status = lib.cabi_e2ee_build_file_manifest(
        file_id.encode("utf-8"),
        ctypes.c_uint64(total_chunks),
        sha_buf,
        ctypes.c_size_t(len(file_sha256_digest)),
        sig_buf,
        ctypes.c_size_t(len(signature)),
        output,
        ctypes.c_size_t(output_len),
        ctypes.byref(written),
    )
    _check(status, "e2ee_build_file_manifest")
    return bytes(output[: written.value])


# Verifies manifest fields and optional signer public key via C ABI.
def verify_file_manifest(
    manifest: bytes,
    file_id: str,
    total_chunks: int,
    file_sha256_digest: bytes,
    signer_public_key: bytes = b"",
) -> None:
    manifest_buf = (ctypes.c_ubyte * len(manifest)).from_buffer_copy(manifest)
    sha_buf = (ctypes.c_ubyte * len(file_sha256_digest)).from_buffer_copy(file_sha256_digest)
    key_buf = (
        (ctypes.c_ubyte * len(signer_public_key)).from_buffer_copy(signer_public_key)
        if signer_public_key
        else None
    )
    status = lib.cabi_e2ee_verify_file_manifest(
        manifest_buf,
        ctypes.c_size_t(len(manifest)),
        file_id.encode("utf-8"),
        ctypes.c_uint64(total_chunks),
        sha_buf,
        ctypes.c_size_t(len(file_sha256_digest)),
        key_buf,
        ctypes.c_size_t(len(signer_public_key)),
    )
    _check(status, "e2ee_verify_file_manifest")

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
        use_websocket: bool = False,
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

        if use_websocket:
            pointer = lib.cabi_node_new_v2(
                ctypes.c_bool(use_quic),
                ctypes.c_bool(use_websocket),
                ctypes.c_bool(enable_relay_hop),
                bootstrap_ptr,
                ctypes.c_size_t(len(bootstrap_peers)),
                seed_ptr,
                ctypes.c_size_t(seed_len),
            )
        else:
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
        "--use-ws",
        action="store_true",
        help="Enable the WebSocket transport (allows /ws multiaddrs).",
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
        "--bootstrap-file",
        action="append",
        default=[],
        help="Path to text file with bootstrap multiaddrs (one per line, repeatable).",
    )
    parser.add_argument(
        "--bootstrap-manifest",
        action="append",
        default=[],
        help="Signed bootstrap-manifest JSON path (repeatable; newest valid version wins).",
    )
    parser.add_argument(
        "--manifest-allowed-signing-key",
        action="append",
        default=[],
        help="Trusted manifest signer key (base64 protobuf-encoded libp2p public key).",
    )
    parser.add_argument(
        "--manifest-allowed-signing-key-file",
        action="append",
        default=[],
        help="File with trusted manifest signer keys, one base64 key per line (repeatable).",
    )
    parser.add_argument(
        "--manifest-state-file",
        help="Path to anti-rollback state for bootstrap manifests.",
    )
    parser.add_argument(
        "--allow-manifest-rollback",
        action="store_true",
        help="Allow applying manifest versions <= stored anti-rollback version (debug only).",
    )
    parser.add_argument(
        "--known-peers-file",
        help="Path to known_peers.json cache (defaults near profile or cwd).",
    )
    parser.add_argument(
        "--known-peers-max",
        type=int,
        default=DEFAULT_KNOWN_PEERS_MAX,
        help="Maximum number of known peers kept in cache.",
    )
    parser.add_argument(
        "--startup-dial-k",
        type=int,
        default=DEFAULT_STARTUP_DIAL_K,
        help="How many top-ranked bootstrap candidates to dial on startup.",
    )
    parser.add_argument(
        "--startup-dial-workers",
        type=int,
        default=DEFAULT_STARTUP_DIAL_WORKERS,
        help="Parallel workers used to dial startup bootstrap candidates.",
    )
    parser.add_argument(
        "--relay-descriptor-ttl-seconds",
        type=int,
        default=DEFAULT_RELAY_DESCRIPTOR_TTL_SECONDS,
        help="TTL for published relay descriptor record in DHT.",
    )
    parser.add_argument(
        "--relay-descriptor-query-max",
        type=int,
        default=DEFAULT_RELAY_DESCRIPTOR_QUERY_MAX,
        help="Maximum relay descriptor DHT lookups during startup.",
    )
    parser.add_argument(
        "--disable-relay-descriptor-discovery",
        action="store_true",
        help="Skip fetching relay descriptors from DHT during startup.",
    )
    parser.add_argument(
        "--disable-relay-descriptor-publish",
        action="store_true",
        help="Relay mode: do not publish signed relay descriptor to DHT.",
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

    if args.listen:
        listen_addr = args.listen
    elif args.use_ws:
        listen_addr = "/ip4/127.0.0.1/tcp/41000/ws"
    else:
        listen_addr = default_listen(args.use_quic)
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

    bootstrap_seed_sources: Dict[str, str] = {}
    for addr in args.bootstrap:
        normalized = _normalize_multiaddrs([addr])
        if not normalized:
            continue
        current = bootstrap_seed_sources.get(normalized[0], "cli")
        bootstrap_seed_sources[normalized[0]] = merge_peer_source(current, "cli")
    for file_path in args.bootstrap_file:
        path = Path(file_path).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"bootstrap file not found: {path}")
        for addr in load_text_list_file(path):
            normalized = _normalize_multiaddrs([addr])
            if not normalized:
                continue
            current = bootstrap_seed_sources.get(normalized[0], "static_file")
            bootstrap_seed_sources[normalized[0]] = merge_peer_source(current, "static_file")

    manifest_paths: List[Path] = [
        Path(item).expanduser().resolve() for item in args.bootstrap_manifest
    ]
    trusted_manifest_signers: List[str] = list(args.manifest_allowed_signing_key)
    for file_path in args.manifest_allowed_signing_key_file:
        path = Path(file_path).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"manifest signer key file not found: {path}")
        trusted_manifest_signers.extend(load_text_list_file(path))

    manifest_state_path: Optional[Path] = (
        Path(args.manifest_state_file).expanduser().resolve()
        if args.manifest_state_file
        else None
    )
    manifest_bootstrap_addresses = load_bootstrap_from_manifests(
        manifest_paths,
        allowed_signing_keys_b64=trusted_manifest_signers,
        state_path=manifest_state_path,
        allow_rollback=args.allow_manifest_rollback,
    )
    for addr in manifest_bootstrap_addresses:
        normalized = _normalize_multiaddrs([addr])
        if not normalized:
            continue
        current = bootstrap_seed_sources.get(normalized[0], "manifest")
        bootstrap_seed_sources[normalized[0]] = merge_peer_source(current, "manifest")

    bootstrap_seed_addresses = list(bootstrap_seed_sources.keys())
    known_peers_path = resolve_known_peers_path(
        Path(args.known_peers_file).expanduser().resolve() if args.known_peers_file else None,
        profile_path_obj,
    )
    known_peers = load_known_peers_file(
        known_peers_path,
        max_entries=max(1, int(args.known_peers_max)),
    )

    def build_node(enable_hop: bool) -> Node:
        return Node(
            use_quic=args.use_quic,
            use_websocket=args.use_ws,
            enable_relay_hop=enable_hop,
            bootstrap_peers=bootstrap_seed_addresses,
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
        local_peer_id = node.local_peer_id()
        print(f"Local PeerId: {local_peer_id}")

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
                    local_peer_id = node.local_peer_id()
                    print(f"Local PeerId: {local_peer_id}")
                    node.listen(listen_addr)
                else:
                    print("AutoNAT did not report PUBLIC; continuing without hop.")

        if args.role == "relay" and not args.disable_relay_descriptor_publish:
            descriptor = publish_relay_descriptor(
                node,
                local_peer_id=local_peer_id,
                listen_addrs=[listen_addr],
                identity_seed=identity_seed,
                ttl_seconds=max(60, int(args.relay_descriptor_ttl_seconds)),
            )
            if descriptor is None:
                print(
                    "[relay-descriptor] skipped: identity seed is required for signing",
                    file=sys.stderr,
                )
            else:
                print(
                    "[relay-descriptor] published"
                    f" key={relay_descriptor_dht_key(local_peer_id).decode('utf-8')}"
                    f" addrs={len(descriptor.get('listen_addrs') or [])}"
                    f" ttl={int(args.relay_descriptor_ttl_seconds)}",
                    flush=True,
                )

        if not args.disable_relay_descriptor_discovery:
            candidate_peer_ids: List[str] = []
            for addr in bootstrap_seed_addresses:
                peer_id = extract_peer_id_from_multiaddr(addr)
                if peer_id:
                    candidate_peer_ids.append(peer_id)
            for addr in known_peers.keys():
                peer_id = extract_peer_id_from_multiaddr(addr)
                if peer_id:
                    candidate_peer_ids.append(peer_id)
            descriptors = discover_relay_descriptors(
                node,
                candidate_peer_ids,
                max_queries=max(1, int(args.relay_descriptor_query_max)),
            )
            for descriptor in descriptors:
                for addr in descriptor.get("listen_addrs") or []:
                    normalized = _normalize_multiaddrs([str(addr)], limit=1)
                    if not normalized:
                        continue
                    current = bootstrap_seed_sources.get(normalized[0], "descriptor")
                    bootstrap_seed_sources[normalized[0]] = merge_peer_source(
                        current, "descriptor"
                    )
            if descriptors:
                print(
                    "[relay-descriptor] discovered"
                    f" descriptors={len(descriptors)}"
                    f" new_addrs={len(bootstrap_seed_sources) - len(bootstrap_seed_addresses)}",
                    flush=True,
                )

        bootstrap_candidates = build_bootstrap_candidates(
            bootstrap_seed_sources,
            known_peers,
            max_candidates=max(1, int(args.known_peers_max)),
        )

        dial_results = dial_bootstrap_top_k(
            node,
            bootstrap_candidates,
            startup_dial_k=max(1, int(args.startup_dial_k)),
            startup_dial_workers=max(1, int(args.startup_dial_workers)),
        )
        for item in dial_results:
            addr = item["address"]
            if item["success"]:
                print(f"Dialed bootstrap peer: {addr}")
            else:
                print(
                    f"Failed to dial bootstrap peer {addr}: {item.get('error')}",
                    file=sys.stderr,
                )
        update_known_peers_after_dial(known_peers, dial_results)
        save_known_peers_file(
            known_peers_path,
            known_peers,
            max_entries=max(1, int(args.known_peers_max)),
        )
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

