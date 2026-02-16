#!/usr/bin/env python3
"""
FidoNext terminal chat client (MVP).

Features:
- local identity/profile registration via --profile
- persistent contacts/chats state in JSON file
- shareable own node address
- connect to peers by multiaddr
- chat switch/list/history commands
- send/receive libsignal E2EE messages
- auto prekey-bundle publish/discovery via DHT
- per-contact libsignal encryption via prekey bundle file (manual fallback)
"""

from __future__ import annotations

import argparse
import base64
import json
import signal
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import readline
except Exception:  # pragma: no cover - platform-dependent
    readline = None


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ping_standalone_nodes import (  # noqa: E402
    CABI_DISCOVERY_EVENT_ADDRESS,
    CABI_DISCOVERY_EVENT_FINISHED,
    CABI_STATUS_SUCCESS,
    CABI_STATUS_TIMEOUT,
    Node,
    build_prekey_bundle,
    build_message_auto,
    decrypt_message_auto,
    default_listen,
    load_or_create_identity_profile,
    validate_prekey_bundle,
)


CHAT_SCHEMA = "fidonext-chat-v1"
CHAT_STATE_SCHEMA_VERSION = 1
DEFAULT_HISTORY_LIMIT = 100
DIRECTORY_SCHEMA = "fidonext-directory-v1"
DIRECTORY_KEY_PREFIX = "fidonext/directory/v1"
DEFAULT_DIRECTORY_TTL_SECONDS = 30 * 60
DEFAULT_DIRECTORY_REANNOUNCE_SECONDS = 10 * 60
PREKEY_SCHEMA = "fidonext-prekey-bundle-v1"
PREKEY_KEY_PREFIX = "fidonext/prekey/v1"
DEFAULT_PREKEY_TTL_SECONDS = 24 * 60 * 60
DEFAULT_PREKEY_ONE_TIME_COUNT = 32
DELIVERY_STATUS_SCHEMA = "fidonext-delivery-status-v1"
REPL_HISTORY_LIMIT = 1000


def now_unix() -> int:
    return int(time.time())


def extract_peer_id_from_multiaddr(addr: str) -> Optional[str]:
    marker = "/p2p/"
    if marker not in addr:
        return None
    value = addr.rsplit(marker, 1)[-1].strip()
    return value if value else None


def stable_state_path(profile_path: Path) -> Path:
    return profile_path.with_suffix(profile_path.suffix + ".chat_state.json")


def directory_key_for_peer(peer_id: str) -> bytes:
    return f"{DIRECTORY_KEY_PREFIX}/peer/{peer_id}".encode("utf-8")


def directory_key_for_account(account_id: str) -> bytes:
    return f"{DIRECTORY_KEY_PREFIX}/account/{account_id}".encode("utf-8")


def prekey_key_for_peer(peer_id: str) -> bytes:
    return f"{PREKEY_KEY_PREFIX}/peer/{peer_id}".encode("utf-8")


def prekey_key_for_account(account_id: str) -> bytes:
    return f"{PREKEY_KEY_PREFIX}/account/{account_id}".encode("utf-8")


def ensure_parent(path: Path) -> None:
    if path.parent:
        path.parent.mkdir(parents=True, exist_ok=True)


def load_bootstrap_file(path: Path) -> List[str]:
    entries: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line)
    return entries


class ChatState:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.contacts: Dict[str, Dict[str, Any]] = {}
        self.chats: Dict[str, List[Dict[str, Any]]] = {}
        self.unread: Dict[str, int] = {}
        self.active_chat_peer_id: Optional[str] = None
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if raw.get("schema_version") != CHAT_STATE_SCHEMA_VERSION:
            return
        self.contacts = dict(raw.get("contacts") or {})
        self.chats = dict(raw.get("chats") or {})
        self.unread = {k: int(v) for k, v in (raw.get("unread") or {}).items()}
        self.active_chat_peer_id = raw.get("active_chat_peer_id")

    def save(self) -> None:
        payload = {
            "schema_version": CHAT_STATE_SCHEMA_VERSION,
            "contacts": self.contacts,
            "chats": self.chats,
            "unread": self.unread,
            "active_chat_peer_id": self.active_chat_peer_id,
            "updated_at_unix": now_unix(),
        }
        ensure_parent(self.path)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def upsert_contact(self, peer_id: str, **updates: Any) -> None:
        item = dict(self.contacts.get(peer_id) or {})
        for key, value in updates.items():
            if value is not None:
                item[key] = value
        self.contacts[peer_id] = item
        self.save()

    def resolve_peer(self, token: str) -> Optional[str]:
        token = token.strip()
        if token in self.contacts:
            return token
        for peer_id, contact in self.contacts.items():
            if contact.get("alias") == token:
                return peer_id
        return None

    def contact_label(self, peer_id: str) -> str:
        contact = self.contacts.get(peer_id) or {}
        alias = contact.get("alias")
        return f"{alias} ({peer_id})" if alias else peer_id

    def append_chat_message(self, peer_id: str, message: Dict[str, Any], incoming: bool) -> None:
        entries = list(self.chats.get(peer_id) or [])
        entries.append(message)
        if len(entries) > 500:
            entries = entries[-500:]
        self.chats[peer_id] = entries
        if incoming and self.active_chat_peer_id != peer_id:
            self.unread[peer_id] = int(self.unread.get(peer_id, 0)) + 1
        self.save()

    def mark_read(self, peer_id: str) -> None:
        if peer_id in self.unread:
            self.unread[peer_id] = 0
            self.save()

    def update_outbound_status(
        self,
        message_id: str,
        status: str,
        peer_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Optional[str]:
        message_id = str(message_id or "").strip()
        if not message_id:
            return None

        peers: List[str]
        if peer_id and peer_id in self.chats:
            peers = [peer_id]
        else:
            peers = list(self.chats.keys())

        for candidate_peer in peers:
            entries = list(self.chats.get(candidate_peer) or [])
            for idx in range(len(entries) - 1, -1, -1):
                item = entries[idx]
                if (
                    str(item.get("direction") or "") == "out"
                    and str(item.get("message_id") or "") == message_id
                ):
                    entries[idx]["delivery_status"] = status
                    if reason:
                        entries[idx]["delivery_reason"] = reason
                    self.chats[candidate_peer] = entries
                    self.save()
                    return candidate_peer
        return None


class TerminalChatClient:
    def __init__(
        self,
        *,
        node: Node,
        state: ChatState,
        account_id: str,
        device_id: str,
        local_peer_id: str,
        listen_addr: str,
        profile_path: Path,
        directory_ttl_seconds: int,
        directory_reannounce_seconds: int,
        prekey_ttl_seconds: int,
        prekey_one_time_count: int,
    ) -> None:
        self.node = node
        self.state = state
        self.account_id = account_id
        self.device_id = device_id
        self.local_peer_id = local_peer_id
        self.listen_addr = listen_addr
        self.profile_path = profile_path
        self.directory_ttl_seconds = max(60, directory_ttl_seconds)
        self.directory_reannounce_seconds = max(30, directory_reannounce_seconds)
        self.prekey_ttl_seconds = max(300, prekey_ttl_seconds)
        self.prekey_one_time_count = max(1, prekey_one_time_count)
        self.running = threading.Event()
        self.running.set()
        self.print_lock = threading.Lock()
        self.announce_lock = threading.Lock()
        self.receiver_thread: Optional[threading.Thread] = None
        self.announce_thread: Optional[threading.Thread] = None
        self.repl_history_path = self.state.path.with_suffix(self.state.path.suffix + ".repl_history")
        self._current_prompt: str = ""
        self._waiting_for_input = False

    def _println(self, text: str) -> None:
        with self.print_lock:
            print(text, flush=True)

    def _redraw_prompt_if_needed(self) -> None:
        if not self._waiting_for_input or not self._current_prompt:
            return
        with self.print_lock:
            line_buffer = ""
            if readline is not None:
                try:
                    line_buffer = readline.get_line_buffer()
                except Exception:
                    line_buffer = ""
            # Repaint prompt immediately after async prints from receiver thread.
            sys.stdout.write("\r")
            sys.stdout.write(self._current_prompt + line_buffer)
            sys.stdout.flush()

    def start_receiver(self) -> None:
        self.receiver_thread = threading.Thread(target=self._receiver_loop, daemon=True)
        self.receiver_thread.start()
        self.announce_thread = threading.Thread(target=self._announce_loop, daemon=True)
        self.announce_thread.start()

    def stop(self) -> None:
        self.running.clear()
        if self.receiver_thread is not None:
            self.receiver_thread.join(timeout=1.0)
        if self.announce_thread is not None:
            self.announce_thread.join(timeout=1.0)
        self._save_repl_history()
        self.node.close()

    def _init_repl_history(self) -> None:
        if readline is None:
            return
        try:
            readline.set_history_length(REPL_HISTORY_LIMIT)
            if self.repl_history_path.exists():
                readline.read_history_file(str(self.repl_history_path))
        except Exception:
            pass

    def _save_repl_history(self) -> None:
        if readline is None:
            return
        try:
            ensure_parent(self.repl_history_path)
            readline.write_history_file(str(self.repl_history_path))
        except Exception:
            pass

    def _announce_loop(self) -> None:
        # Re-announce periodically to keep DHT contact card fresh.
        while self.running.is_set():
            try:
                self.announce_self(verbose=False)
            except Exception as exc:
                self._println(f"[announce] background announce failed: {exc}")
            self.running.wait(self.directory_reannounce_seconds)

    def _receiver_loop(self) -> None:
        while self.running.is_set():
            try:
                payload = self.node.try_receive_message()
            except RuntimeError as exc:
                self._println(f"[recv] error: {exc}")
                self.running.clear()
                break

            if payload is None:
                time.sleep(0.1)
                continue
            self._handle_inbound(payload)

    def _handle_inbound(self, payload: bytes) -> None:
        try:
            packet = json.loads(payload.decode("utf-8"))
        except Exception:
            # Best-effort fallback: raw libsignal payload from older tools.
            try:
                _kind, plaintext = decrypt_message_auto(self.profile_path, payload)
                text = plaintext.decode("utf-8", "replace")
                self._println(f"[recv:e2ee] {text}")
            except Exception:
                self._println("[recv] unknown payload ignored")
            return

        if not isinstance(packet, dict):
            self._println("[recv] non-chat packet ignored")
            return

        if packet.get("schema") == DELIVERY_STATUS_SCHEMA:
            self._handle_delivery_status_packet(packet)
            return

        if packet.get("schema") != CHAT_SCHEMA:
            self._println("[recv] non-chat packet ignored")
            return

        from_peer_id = str(packet.get("from_peer_id") or "").strip()
        to_peer_id = str(packet.get("to_peer_id") or "").strip()
        payload_type = str(packet.get("payload_type") or "").strip()
        body_b64 = str(packet.get("payload_b64") or "")

        if to_peer_id != self.local_peer_id:
            return
        if not from_peer_id:
            return

        text = ""
        e2ee = False
        if payload_type == "libsignal":
            try:
                encrypted = base64.b64decode(body_b64)
                _kind, plaintext = decrypt_message_auto(self.profile_path, encrypted)
                text = plaintext.decode("utf-8", "replace")
                e2ee = True
            except Exception as exc:
                self._println(f"[recv] libsignal decrypt failed: {exc}")
                return
        else:
            self._println("[recv] unsupported payload type (strict E2EE mode expects payload_type=libsignal)")
            return

        self.state.append_chat_message(
            from_peer_id,
            {
                "ts_unix": now_unix(),
                "direction": "in",
                "text": text,
                "e2ee": e2ee,
                "message_id": packet.get("message_id"),
            },
            incoming=True,
        )
        if self.state.active_chat_peer_id == from_peer_id:
            tag = " e2ee" if e2ee else ""
            self._println(f"in{tag} {self.state.contact_label(from_peer_id)}: {text}")
        else:
            prefix = "[recv:e2ee]" if e2ee else "[recv]"
            self._println(f"{prefix} {self.state.contact_label(from_peer_id)}: {text}")
        self._redraw_prompt_if_needed()

    def _handle_delivery_status_packet(self, packet: Dict[str, Any]) -> None:
        message_id = str(packet.get("message_id") or "").strip()
        status = str(packet.get("status") or "").strip()
        peer_id = str(packet.get("peer_id") or "").strip() or None
        reason = str(packet.get("reason") or "").strip() or None
        if not message_id or not status:
            return
        updated_peer_id = self.state.update_outbound_status(
            message_id=message_id,
            status=status,
            peer_id=peer_id,
            reason=reason,
        )
        if not updated_peer_id:
            return
        reason_suffix = f" ({reason})" if reason else ""
        self._println(
            f"[delivery] {status} for {self.state.contact_label(updated_peer_id)} id={message_id[:8]}{reason_suffix}"
        )
        self._redraw_prompt_if_needed()

    def _is_libsignal_prekey_bundle(self, bundle: bytes) -> bool:
        try:
            payload = json.loads(bundle.decode("utf-8"))
        except Exception:
            return False
        if not isinstance(payload, dict):
            return False
        required = [
            "libsignal_identity_key_b64",
            "libsignal_signed_pre_key_id",
            "libsignal_signed_pre_key_public_b64",
            "libsignal_signed_pre_key_signature_b64",
            "libsignal_kyber_pre_key_id",
            "libsignal_kyber_pre_key_public_b64",
            "libsignal_kyber_pre_key_signature_b64",
        ]
        return all(payload.get(key) not in (None, "") for key in required)

    def _validate_recipient_bundle(self, bundle: bytes, source: str) -> bool:
        try:
            validate_prekey_bundle(bundle, now_unix=0)
        except Exception as exc:
            self._println(f"[prekey] invalid bundle from {source}: {exc}")
            return False
        if not self._is_libsignal_prekey_bundle(bundle):
            self._println(
                f"[prekey] bundle from {source} is legacy/non-libsignal; skipping for strict E2EE"
            )
            return False
        return True

    def _load_contact_prekey_bundle(self, peer_id: str) -> Optional[bytes]:
        contact = self.state.contacts.get(peer_id) or {}
        bundle_path = str(contact.get("prekey_bundle_path") or "").strip()
        if bundle_path:
            path = Path(bundle_path).expanduser().resolve()
            try:
                bundle = path.read_bytes()
                if self._validate_recipient_bundle(bundle, f"file:{path}"):
                    return bundle
            except Exception:
                self._println(f"[prekey] failed to read bundle file: {path}")
        inline_b64 = str(contact.get("prekey_bundle_b64") or "").strip()
        if inline_b64:
            try:
                bundle = base64.b64decode(inline_b64)
                if self._validate_recipient_bundle(bundle, "contact cache"):
                    return bundle
            except Exception:
                self._println("[prekey] failed to decode cached bundle from contact state")
        return None

    def send_to_active_chat(self, text: str) -> None:
        peer_id = self.state.active_chat_peer_id
        if not peer_id:
            self._println("[send] no active chat. Use /chats then /open <index>")
            return

        bundle = self._load_contact_prekey_bundle(peer_id)
        if bundle is None:
            self._println(
                "[send] strict E2EE mode: no prekey bundle set for contact. "
                "Use /contact bundle <peer_or_alias> <bundle.json>"
            )
            return

        payload_type = "libsignal"
        payload_bytes: bytes
        try:
            encrypted = build_message_auto(self.profile_path, bundle, text)
            payload_bytes = encrypted
        except Exception as exc:
            self._println(f"[send] failed to encrypt with bundle: {exc}")
            return

        packet = {
            "schema": CHAT_SCHEMA,
            "message_id": uuid.uuid4().hex,
            "created_at_unix": now_unix(),
            "from_peer_id": self.local_peer_id,
            "to_peer_id": peer_id,
            "payload_type": payload_type,
            "payload_b64": base64.b64encode(payload_bytes).decode("ascii"),
        }
        encoded = json.dumps(packet, ensure_ascii=True, separators=(",", ":")).encode("utf-8")

        try:
            self.node.send_message(encoded)
        except RuntimeError as exc:
            self._println(f"[send] publish failed: {exc}")
            return

        e2ee = payload_type == "libsignal"
        self.state.append_chat_message(
            peer_id,
            {
                "ts_unix": now_unix(),
                "direction": "out",
                "text": text,
                "e2ee": e2ee,
                "message_id": packet["message_id"],
                "delivery_status": "sent",
            },
            incoming=False,
        )
        tag = "[sent:e2ee]" if e2ee else "[sent]"
        self._println(f"{tag} to {self.state.contact_label(peer_id)}: {text}")

    def _directory_card(self) -> Dict[str, Any]:
        return {
            "schema": DIRECTORY_SCHEMA,
            "updated_at_unix": now_unix(),
            "peer_id": self.local_peer_id,
            "account_id": self.account_id,
            "device_id": self.device_id,
            "addresses": [f"{self.listen_addr}/p2p/{self.local_peer_id}"],
        }

    def _prekey_card_payload(self) -> bytes:
        bundle = build_prekey_bundle(
            self.profile_path,
            one_time_prekey_count=self.prekey_one_time_count,
            ttl_seconds=self.prekey_ttl_seconds,
        )
        card = {
            "schema": PREKEY_SCHEMA,
            "updated_at_unix": now_unix(),
            "peer_id": self.local_peer_id,
            "account_id": self.account_id,
            "device_id": self.device_id,
            "bundle_b64": base64.b64encode(bundle).decode("ascii"),
        }
        return json.dumps(card, ensure_ascii=True, separators=(",", ":")).encode("utf-8")

    def announce_self(self, verbose: bool = True) -> None:
        with self.announce_lock:
            card = self._directory_card()
            payload = json.dumps(card, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            prekey_payload = self._prekey_card_payload()
            self.node.dht_put_record(
                directory_key_for_peer(self.local_peer_id),
                payload,
                ttl_seconds=self.directory_ttl_seconds,
            )
            self.node.dht_put_record(
                directory_key_for_account(self.account_id),
                payload,
                ttl_seconds=self.directory_ttl_seconds,
            )
            self.node.dht_put_record(
                prekey_key_for_peer(self.local_peer_id),
                prekey_payload,
                ttl_seconds=self.prekey_ttl_seconds,
            )
            self.node.dht_put_record(
                prekey_key_for_account(self.account_id),
                prekey_payload,
                ttl_seconds=self.prekey_ttl_seconds,
            )
            if verbose:
                self._println(
                    f"[announce] published directory+prekey cards for peer={self.local_peer_id} account={self.account_id}"
                )

    def lookup_directory(self, identifier: str) -> Optional[Dict[str, Any]]:
        key_candidates = [
            directory_key_for_peer(identifier),
            directory_key_for_account(identifier),
        ]
        for key in key_candidates:
            try:
                raw = self.node.dht_get_record(key)
            except RuntimeError:
                continue
            try:
                card = json.loads(raw.decode("utf-8"))
            except Exception:
                continue
            if isinstance(card, dict) and card.get("schema") == DIRECTORY_SCHEMA:
                return card
        return None

    def _parse_prekey_payload(self, raw: bytes) -> Optional[Tuple[bytes, Dict[str, Any]]]:
        try:
            card = json.loads(raw.decode("utf-8"))
        except Exception:
            return None
        if not isinstance(card, dict) or card.get("schema") != PREKEY_SCHEMA:
            return None
        bundle_b64 = str(card.get("bundle_b64") or "")
        if not bundle_b64:
            return None
        try:
            bundle = base64.b64decode(bundle_b64)
        except Exception:
            return None
        if not self._validate_recipient_bundle(bundle, "DHT prekey record"):
            return None
        return bundle, card

    def lookup_prekey_bundle(self, identifier: str) -> Optional[Tuple[bytes, Dict[str, Any]]]:
        key_candidates = [
            prekey_key_for_peer(identifier),
            prekey_key_for_account(identifier),
        ]
        for key in key_candidates:
            try:
                raw = self.node.dht_get_record(key)
            except RuntimeError:
                continue
            parsed = self._parse_prekey_payload(raw)
            if parsed is not None:
                return parsed
        return None

    def resolve_peer_addresses(
        self, peer_id: str, timeout_seconds: int = 12
    ) -> Tuple[List[str], int]:
        request_id = self.node.find_peer(peer_id)
        deadline = time.time() + max(1, timeout_seconds)
        addresses: List[str] = []
        final_status = CABI_STATUS_TIMEOUT
        while time.time() < deadline and self.running.is_set():
            event = self.node.try_dequeue_discovery_event()
            if event is None:
                time.sleep(0.1)
                continue
            if int(event.get("request_id", 0)) != request_id:
                continue
            event_kind = int(event.get("event_kind", -1))
            if event_kind == CABI_DISCOVERY_EVENT_ADDRESS:
                address = str(event.get("address") or "").strip()
                if address and address not in addresses:
                    addresses.append(address)
            elif event_kind == CABI_DISCOVERY_EVENT_FINISHED:
                final_status = int(event.get("status_code", CABI_STATUS_TIMEOUT))
                break
        return addresses, final_status

    def lookup_and_dial(self, identifier: str, alias: Optional[str] = None) -> bool:
        card = self.lookup_directory(identifier)
        if card is None:
            self._println(
                f"[lookup] not found in directory for '{identifier}', trying direct find_peer if it is PeerId..."
            )
            peer_id = identifier
            addresses, status = self.resolve_peer_addresses(peer_id)
        else:
            peer_id = str(card.get("peer_id") or "").strip()
            account_id = str(card.get("account_id") or "").strip()
            if not peer_id:
                self._println("[lookup] directory card is invalid: peer_id missing")
                return False
            if account_id:
                self._println(f"[lookup] account_id={account_id} -> peer_id={peer_id}")
            addresses = [
                str(item).strip() for item in (card.get("addresses") or []) if str(item).strip()
            ]
            status = CABI_STATUS_SUCCESS
            if not addresses:
                discovered, status = self.resolve_peer_addresses(peer_id)
                addresses.extend(discovered)

        if not addresses:
            self._println(f"[lookup] no addresses resolved for {peer_id}")
            return False

        for addr in addresses:
            try:
                self.node.dial(addr)
                self.state.upsert_contact(
                    peer_id,
                    alias=alias,
                    last_address=addr,
                    account_id=(card or {}).get("account_id"),
                    device_id=(card or {}).get("device_id"),
                )
                self._println(f"[connect] connected: {self.state.contact_label(peer_id)} via {addr}")
                return True
            except RuntimeError:
                continue

        self._println(
            f"[connect] failed to dial resolved addresses for {peer_id} (find_peer_status={status})"
        )
        return False

    def _ensure_contact_prekey_bundle(self, peer_id: str) -> bool:
        if self._load_contact_prekey_bundle(peer_id) is not None:
            return True

        contact = self.state.contacts.get(peer_id) or {}
        account_id = str(contact.get("account_id") or "").strip()
        identifiers: List[str] = [peer_id]
        if account_id:
            identifiers.append(account_id)

        # Refresh account metadata from directory if unknown.
        if not account_id:
            card = self.lookup_directory(peer_id)
            if card and str(card.get("account_id") or "").strip():
                account_id = str(card.get("account_id")).strip()
                self.state.upsert_contact(
                    peer_id,
                    account_id=account_id,
                    device_id=str(card.get("device_id") or "").strip() or None,
                )
                identifiers.append(account_id)

        for identifier in list(dict.fromkeys([item for item in identifiers if item])):
            found = self.lookup_prekey_bundle(identifier)
            if found is None:
                continue
            bundle, card = found
            updates: Dict[str, Any] = {
                "prekey_bundle_b64": base64.b64encode(bundle).decode("ascii"),
            }
            card_account_id = str(card.get("account_id") or "").strip()
            card_device_id = str(card.get("device_id") or "").strip()
            if card_account_id:
                updates["account_id"] = card_account_id
            if card_device_id:
                updates["device_id"] = card_device_id
            self.state.upsert_contact(peer_id, **updates)
            self._println(f"[prekey] fetched bundle from DHT for {self.state.contact_label(peer_id)}")
            return True
        return False

    def show_help(self) -> None:
        self._println(
            "\n".join(
                [
                    "Commands:",
                    "  /help",
                    "  /id                                  Show local identifiers and share address",
                    "  /announce                            Publish own contact card to DHT directory",
                    "  /contacts                             List contacts",
                    "  /contact add <peer_id> [alias]       Add/update contact",
                    "  /contact bundle <peer> <bundle.json> Set recipient libsignal prekey bundle",
                    "  /chats                                List chats with indexes",
                    "  /open <index|peer|alias>             Open chat, connect, and show history",
                    "  /chat history [limit]                 Show active chat history",
                    "  /history [peer_or_alias] [limit]      Show chat history",
                    "  /send <text>                          Send to active chat",
                    "  /quit                                 Exit client",
                    "Tip: plain text (without /command) sends to active chat (always E2EE).",
                    "Tip: /open auto-fetches recipient bundle from DHT when available.",
                    "Tip: /contact bundle stays available as manual fallback.",
                    "Tip: Ctrl+C does not exit; use /quit to close client.",
                ]
            )
        )

    def show_id(self) -> None:
        self._println(f"Local AccountId: {self.account_id}")
        self._println(f"Local DeviceId: {self.device_id}")
        self._println(f"Local PeerId: {self.local_peer_id}")
        self._println(f"Share address: {self.listen_addr}/p2p/{self.local_peer_id}")

    def _chat_peers_sorted(self) -> List[str]:
        peers = set(self.state.chats.keys()) | set(self.state.contacts.keys())
        return sorted(peers)

    def _resolve_chat_selector(self, token: str) -> Optional[str]:
        token = token.strip()
        if not token:
            return None
        resolved = self.state.resolve_peer(token)
        if resolved:
            return resolved
        if token in self.state.contacts or token in self.state.chats:
            return token
        if token.isdigit():
            index = int(token)
            peers = self._chat_peers_sorted()
            if 1 <= index <= len(peers):
                return peers[index - 1]
            self._println(f"[chat] index out of range: {index}")
            return None
        return token

    def _print_chats(self) -> None:
        peers = self._chat_peers_sorted()
        if not peers:
            self._println("No chats.")
            return
        self._println("Chats:")
        for idx, peer_id in enumerate(peers, start=1):
            unread = int(self.state.unread.get(peer_id, 0))
            marker = "*" if self.state.active_chat_peer_id == peer_id else " "
            history = list(self.state.chats.get(peer_id) or [])
            if history:
                item = history[-1]
                direction = str(item.get("direction") or "?")
                text = str(item.get("text") or "")
                preview = (text[:42] + "...") if len(text) > 45 else text
                tail = f"{direction}: {preview}"
            else:
                tail = "no messages"
            self._println(
                f"{marker} [{idx}] {self.state.contact_label(peer_id)} | unread={unread} | {tail}"
            )

    def _print_history(self, peer_id: str, limit: int) -> None:
        history = list(self.state.chats.get(peer_id) or [])[-limit:]
        if not history:
            self._println(f"No history with {self.state.contact_label(peer_id)}")
            return
        self._println(f"--- history with {self.state.contact_label(peer_id)} ---")
        for item in history:
            direction = item.get("direction", "?")
            ts = item.get("ts_unix", 0)
            text = item.get("text", "")
            e2ee = " e2ee" if item.get("e2ee") else ""
            status_suffix = ""
            if direction == "out":
                delivery_status = str(item.get("delivery_status") or "").strip()
                delivery_reason = str(item.get("delivery_reason") or "").strip()
                if delivery_status:
                    status_suffix = f" [{delivery_status}]"
                if delivery_reason:
                    status_suffix += f"({delivery_reason})"
            self._println(f"[{ts}] {direction}{e2ee}{status_suffix}: {text}")
        self._println("--- end ---")

    def _ensure_chat_connection(self, peer_id: str) -> bool:
        contact = self.state.contacts.get(peer_id) or {}
        last_address = str(contact.get("last_address") or "").strip()
        if last_address:
            try:
                self.node.dial(last_address)
                self._println(f"[open] connected via saved address: {last_address}")
                return True
            except RuntimeError:
                pass
        # Fallback to DHT directory lookup and find_peer discovery.
        return self.lookup_and_dial(peer_id, alias=contact.get("alias"))

    def _open_chat(self, token: str) -> None:
        peer_id = self._resolve_chat_selector(token)
        if not peer_id:
            return
        # Ensure entry exists so empty chats can be opened immediately.
        self.state.upsert_contact(peer_id)
        connected = self._ensure_chat_connection(peer_id)
        self._ensure_contact_prekey_bundle(peer_id)
        self.state.active_chat_peer_id = peer_id
        self.state.mark_read(peer_id)
        status = "connected" if connected else "offline"
        self._println(f"[open] active chat -> {self.state.contact_label(peer_id)} ({status})")
        self._print_history(peer_id, 50)

    def repl(self) -> None:
        self._init_repl_history()
        self.show_help()
        while self.running.is_set():
            active = self.state.active_chat_peer_id
            prompt = (
                f"chat[{self.state.contact_label(active)}]> " if active else "chat[none]> "
            )
            self._current_prompt = prompt
            self._waiting_for_input = True
            try:
                line = input(prompt)
            except EOFError:
                self.running.clear()
                break
            except KeyboardInterrupt:
                # Keep REPL alive on Ctrl+C to avoid accidental exits.
                self._println("\n[repl] input cancelled. Use /quit to exit.")
                continue
            finally:
                self._waiting_for_input = False

            line = line.strip()
            if not line:
                continue
            line = self._normalize_repl_line(line)
            if line.startswith("/"):
                self._handle_command(line)
            else:
                self.send_to_active_chat(line)

    def _normalize_repl_line(self, line: str) -> str:
        if line.startswith("/"):
            return line
        first = line.split(maxsplit=1)[0].lower()
        known = {
            "help",
            "quit",
            "id",
            "announce",
            "open",
            "contacts",
            "contact",
            "chats",
            "chat",
            "history",
            "send",
        }
        if first in known:
            return "/" + line
        return line

    def _handle_command(self, line: str) -> None:
        parts = line.split()
        cmd = parts[0].lower()
        if cmd == "/help":
            self.show_help()
            return
        if cmd in {"/quit", "/exit", "/q"}:
            self.running.clear()
            return
        if cmd == "/id":
            self.show_id()
            return
        if cmd == "/open":
            if len(parts) < 2:
                self._println("usage: /open <index|peer|alias>")
                return
            self._open_chat(parts[1])
            return
        if cmd == "/announce":
            try:
                self.announce_self(verbose=True)
            except RuntimeError as exc:
                self._println(f"[announce] failed: {exc}")
            return
        if cmd == "/lookup":
            if len(parts) < 2:
                self._println("usage: /lookup <peer_id_or_account_id>")
                return
            identifier = parts[1].strip()
            card = self.lookup_directory(identifier)
            if not card:
                self._println(f"[lookup] directory card not found for '{identifier}'")
                return
            peer_id = card.get("peer_id") or "-"
            account_id = card.get("account_id") or "-"
            device_id = card.get("device_id") or "-"
            addresses = card.get("addresses") or []
            self._println(f"[lookup] peer_id={peer_id} account_id={account_id} device_id={device_id}")
            for addr in addresses:
                self._println(f"  - {addr}")
            return
        if cmd == "/connectid":
            if len(parts) < 2:
                self._println("usage: /connectid <peer_id_or_account_id> [alias]")
                return
            identifier = parts[1].strip()
            alias = parts[2].strip() if len(parts) > 2 else None
            self.lookup_and_dial(identifier, alias=alias)
            return
        if cmd == "/connect":
            if len(parts) < 2:
                self._println("usage: /connect <multiaddr> [alias]")
                return
            addr = parts[1]
            if not addr.startswith("/"):
                self._println("[connect] expects a multiaddr. Use /open <index|peer|alias> for chat connect.")
                return
            alias = parts[2] if len(parts) > 2 else None
            try:
                self.node.dial(addr)
            except RuntimeError as exc:
                self._println(f"[connect] dial failed: {exc}")
                return
            peer_id = extract_peer_id_from_multiaddr(addr)
            if peer_id:
                self.state.upsert_contact(peer_id, alias=alias)
                self._println(f"[connect] connected and saved contact: {self.state.contact_label(peer_id)}")
            else:
                self._println("[connect] dialed, but peer_id not found in address")
            return
        if cmd == "/contacts":
            if not self.state.contacts:
                self._println("No contacts.")
                return
            for peer_id, contact in self.state.contacts.items():
                alias = contact.get("alias") or "-"
                bundle_path = str(contact.get("prekey_bundle_path") or "").strip()
                bundle_inline = bool(str(contact.get("prekey_bundle_b64") or "").strip())
                if bundle_path:
                    bundle = f"file:{bundle_path}"
                elif bundle_inline:
                    bundle = "cached:dht"
                else:
                    bundle = "-"
                account_id = contact.get("account_id") or "-"
                last_address = contact.get("last_address") or "-"
                self._println(
                    f"- {peer_id} | alias={alias} | account={account_id} | addr={last_address} | bundle={bundle}"
                )
            return
        if cmd == "/contact":
            if len(parts) < 3:
                self._println("usage: /contact add <peer_id> [alias] OR /contact bundle <peer> <bundle.json>")
                return
            sub = parts[1].lower()
            if sub == "add":
                peer_id = parts[2]
                alias = parts[3] if len(parts) > 3 else None
                self.state.upsert_contact(peer_id, alias=alias)
                self._println(f"[contact] saved {self.state.contact_label(peer_id)}")
                return
            if sub == "bundle":
                if len(parts) < 4:
                    self._println("usage: /contact bundle <peer_or_alias> <bundle.json>")
                    return
                token = parts[2]
                peer_id = self.state.resolve_peer(token) or token
                bundle_path = str(Path(parts[3]).expanduser().resolve())
                if not Path(bundle_path).exists():
                    self._println(f"[contact] bundle file not found: {bundle_path}")
                    return
                self.state.upsert_contact(
                    peer_id,
                    prekey_bundle_path=bundle_path,
                    prekey_bundle_b64="",
                )
                self._println(f"[contact] set bundle for {self.state.contact_label(peer_id)}")
                return
            self._println("unknown /contact subcommand")
            return
        if cmd == "/chats":
            self._print_chats()
            return
        if cmd == "/chat":
            if len(parts) < 2:
                self._println("usage: /chat list | /chat open <index|peer|alias> | /chat history [limit]")
                return
            sub = parts[1].lower()
            if sub == "list":
                self._print_chats()
                return
            if sub in {"open", "use"}:
                if len(parts) < 3:
                    self._println("usage: /chat open <index|peer|alias>")
                    return
                self._open_chat(parts[2])
                return
            if sub == "history":
                peer_id = self.state.active_chat_peer_id
                if not peer_id:
                    self._println("[chat] no active chat. Use /chats then /chat open <index>")
                    return
                limit = DEFAULT_HISTORY_LIMIT
                if len(parts) >= 3:
                    try:
                        limit = max(1, int(parts[2]))
                    except ValueError:
                        self._println("history limit must be integer")
                        return
                self._print_history(peer_id, limit)
                return
            self._println("usage: /chat list | /chat open <index|peer|alias> | /chat history [limit]")
            return
        if cmd == "/history":
            token = parts[1] if len(parts) >= 2 else (self.state.active_chat_peer_id or "")
            if not token:
                self._println("usage: /history [peer_or_alias] [limit]")
                return
            peer_id = self._resolve_chat_selector(token)
            if not peer_id:
                return
            limit = DEFAULT_HISTORY_LIMIT
            if len(parts) >= 3:
                try:
                    limit = max(1, int(parts[2]))
                except ValueError:
                    self._println("history limit must be integer")
                    return
            self._print_history(peer_id, limit)
            return
        if cmd == "/send":
            text = line[len("/send") :].strip()
            if not text:
                self._println("usage: /send <text>")
                return
            self.send_to_active_chat(text)
            return

        self._println("Unknown command. Use /help")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FidoNext terminal chat client (MVP).")
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
        "--target",
        action="append",
        default=[],
        help="Peers to dial immediately (repeatable).",
    )
    parser.add_argument(
        "--use-quic",
        action="store_true",
        help="Enable QUIC transport (otherwise TCP).",
    )
    parser.add_argument(
        "--profile",
        required=True,
        help="Path to local identity profile (created on first run).",
    )
    parser.add_argument(
        "--state-file",
        help="Optional path for chat state JSON (defaults to <profile>.chat_state.json).",
    )
    parser.add_argument(
        "--directory-ttl-seconds",
        type=int,
        default=DEFAULT_DIRECTORY_TTL_SECONDS,
        help="DHT TTL for own discovery card.",
    )
    parser.add_argument(
        "--directory-reannounce-seconds",
        type=int,
        default=DEFAULT_DIRECTORY_REANNOUNCE_SECONDS,
        help="How often to re-publish own discovery card in DHT.",
    )
    parser.add_argument(
        "--prekey-ttl-seconds",
        type=int,
        default=DEFAULT_PREKEY_TTL_SECONDS,
        help="TTL for published prekey bundle records in DHT.",
    )
    parser.add_argument(
        "--prekey-one-time-count",
        type=int,
        default=DEFAULT_PREKEY_ONE_TIME_COUNT,
        help="Number of one-time prekeys when (re)building bundle for DHT publish.",
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
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    listen_addr = args.listen or default_listen(args.use_quic)
    profile_path = Path(args.profile).expanduser().resolve()
    state_path = (
        Path(args.state_file).expanduser().resolve()
        if args.state_file
        else stable_state_path(profile_path)
    )

    if args.seed or args.seed_phrase:
        raise ValueError("seed options are not supported with --profile in this client")

    account_id, device_id, libp2p_seed, _signal_seed = load_or_create_identity_profile(profile_path)
    bootstrap_addresses: List[str] = list(args.bootstrap)
    for file_path in args.bootstrap_file:
        path = Path(file_path).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"bootstrap file not found: {path}")
        bootstrap_addresses.extend(load_bootstrap_file(path))
    # Preserve order while removing duplicates.
    bootstrap_addresses = list(dict.fromkeys(bootstrap_addresses))

    node = Node(
        use_quic=args.use_quic,
        enable_relay_hop=False,
        bootstrap_peers=bootstrap_addresses,
        identity_seed=libp2p_seed,
    )
    local_peer_id = node.local_peer_id()
    node.listen(listen_addr)

    bootstrap_connected = False
    for addr in bootstrap_addresses:
        try:
            node.dial(addr)
            bootstrap_connected = True
        except RuntimeError:
            pass
    for addr in args.target:
        try:
            node.dial(addr)
        except RuntimeError:
            pass

    state = ChatState(state_path)
    client = TerminalChatClient(
        node=node,
        state=state,
        account_id=account_id,
        device_id=device_id,
        local_peer_id=local_peer_id,
        listen_addr=listen_addr,
        profile_path=profile_path,
        directory_ttl_seconds=args.directory_ttl_seconds,
        directory_reannounce_seconds=args.directory_reannounce_seconds,
        prekey_ttl_seconds=args.prekey_ttl_seconds,
        prekey_one_time_count=args.prekey_one_time_count,
    )

    def _handle_signal(_sig: int, _frame: Any) -> None:
        client.running.clear()

    signal.signal(signal.SIGTERM, _handle_signal)

    print(f"Profile: {profile_path}")
    print(f"Chat state: {state_path}")
    print(f"Local AccountId: {account_id}")
    print(f"Local DeviceId: {device_id}")
    print(f"Local PeerId: {local_peer_id}")
    print(f"Share address: {listen_addr}/p2p/{local_peer_id}")
    if bootstrap_addresses:
        print("Bootstrap peers:")
        for item in bootstrap_addresses:
            print(f"  - {item}")
        if bootstrap_connected:
            print("[status] online: connected to relay/bootstrap")
        else:
            print("[status] offline: failed to connect to relay/bootstrap")
    else:
        print("[status] offline: no bootstrap relay configured")

    client.start_receiver()
    print("[announce] running in background")
    client.repl()
    client.stop()


if __name__ == "__main__":
    main()

