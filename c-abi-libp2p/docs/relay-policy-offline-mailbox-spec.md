# Relay Policy, Governance, and Offline Mailbox Spec (Draft v1)

This document defines a protocol-level design for:

- relay role selection (`off`, `limited`, `full`) in the network core,
- relay capability advertisement and scoring,
- authorization model for `super-relay` nodes,
- offline message delivery and per-device mailbox retention.

The goal is to move these decisions from ad-hoc client behavior into explicit, verifiable protocol rules.

## 1. Scope and status

Status in the current codebase (`c-abi-libp2p`):

- implemented:
  - libp2p relay transport client,
  - optional hop relay server switch (`hop_relay`),
  - AutoNAT status signal (`public/private/unknown`),
  - E2EE key documents in DHT (prekey/key-update).
- not implemented yet:
  - policy engine for automatic relay mode selection,
  - relay descriptor registry and ranking,
  - super-relay authorization certificates,
  - offline mailbox persistence protocol.
- explicitly deferred (not part of this stage):
  - sync protocol between user's own devices,
  - long-term large-file storage integrations (including Filecoin/IPFS).

This spec is a design target for implementation phases.

## 2. Node relay modes

Each node has two relay-related values:

- `policy_intent` (local preference, configured by user/client),
- `effective_mode` (computed mode actually applied by core).

### 2.1 `policy_intent`

Allowed values:

- `disabled`
- `auto`
- `force_limited`
- `force_full`

### 2.2 `effective_mode`

Allowed values:

- `off`: node does not serve relay mailbox traffic.
- `limited`: node can serve relay mailbox traffic with strict resource limits.
- `full`: node serves relay mailbox traffic using full configured limits.

### 2.3 Inputs used to compute mode

The core policy engine consumes:

- `nat_status`: `public/private/unknown` (AutoNAT).
- `device_class`: `mobile/desktop/server` (provided by client, not self-declared on network).
- `power_state`: `battery/charging/ac` (client-supplied).
- `network_class`: `metered/unmetered` (client-supplied).
- user limits:
  - max relay storage bytes,
  - max mailbox ttl,
  - max upload bandwidth budget.

### 2.4 Baseline decision rules

- if `policy_intent = disabled` -> `off`
- if `nat_status != public` and no explicit override -> `off`
- mobile defaults:
  - `auto` -> `limited` only when `charging` and `unmetered`
  - otherwise `off`
- desktop/server defaults:
  - `auto` + `public` -> `full` when user enabled relay service
  - otherwise `off`
- `force_full` may be downgraded to `limited/off` if hard safety limits are violated.

## 3. Relay descriptor and discovery

Relay metadata is published as a signed descriptor.

### 3.1 DHT key

`fidonext-relay-v1/descriptor/{peer_id}`

### 3.2 Descriptor shape (canonical JSON)

```json
{
  "schema_version": 1,
  "peer_id": "12D3Koo...",
  "issued_at_unix": 1771149000,
  "expires_at_unix": 1771150800,
  "relay_mode": "limited",
  "relay_class": "mobile",
  "capabilities": {
    "mailbox": true,
    "max_mailbox_ttl_seconds": 86400,
    "max_mailbox_bytes_total": 1073741824,
    "max_mailbox_bytes_per_device": 33554432,
    "max_attachment_pointer_bytes": 16384
  },
  "listen_addrs": [
    "/ip4/203.0.113.10/tcp/41000/p2p/12D3Koo..."
  ],
  "super_relay": false,
  "super_relay_cert_b64": null,
  "signature_b64": "<peer-key-signature>"
}
```

Validation:

- `peer_id` must match descriptor signing key.
- descriptor must be fresh (`now <= expires_at_unix`).
- ttl window must be bounded (for example max 30 minutes).
- declared limits must pass local hard caps.

## 4. Super-relay authorization

`super-relay` status is never self-assigned.

### 4.1 Trust root

- clients pin one or more `developer_root_pubkeys`.
- root keys are updated only by signed release/governance update.

### 4.2 Delegation certificate

Certificate binds a `peer_id` to elevated relay privileges.

DHT key:

`fidonext-relay-v1/super-cert/{peer_id}`

Certificate fields:

- `schema_version`
- `subject_peer_id`
- `capabilities_scope` (for example max storage, max ttl, region flags)
- `not_before_unix`
- `not_after_unix`
- `issuer_key_id`
- `signature_b64` (issuer over canonical bytes)

Validation:

- cert signature chain must terminate at pinned root.
- current time must be inside cert validity window.
- descriptor claiming `super_relay=true` must include matching valid cert.

### 4.3 Revocation

Revocation list key:

`fidonext-relay-v1/revocations/{issuer_key_id}`

Clients refuse super-relay certs appearing on revocation list or signed by revoked issuer.

## 5. Relay scoring and placement

Messages are placed on multiple relays; placement is client-side deterministic with weighted ranking.

### 5.1 Candidate filtering

Exclude relays that fail any of:

- invalid/expired descriptor,
- no mailbox capability,
- `effective` limits below message requirements,
- invalid super-relay claim.

### 5.2 Score function (example)

`score = 0.35*uptime + 0.25*delivery_success + 0.20*latency + 0.10*freshness + 0.10*capacity_headroom`

All terms are normalized [0..1], based on observed measurements (not self-reported values).

### 5.3 Placement policy

- choose `N` relays (default `N=5`)
- write quorum `W` (default `W=3`)
- read quorum `R` (default `R=2`)
- enforce diversity constraints (different ASN/region/operator when possible).

If fewer than `W` writes succeed, sender keeps local retry queue and retries with backoff.

## 6. Offline mailbox protocol (per-device)

Mailbox is keyed by recipient account/device. Relay stores only ciphertext envelopes.

### 6.1 Data model

Envelope fields:

- `message_id` (globally unique)
- `recipient_account_id`
- `recipient_device_id`
- `created_at_unix`
- `expires_at_unix`
- `ciphertext_kind` (prekey/session)
- `ciphertext_b64`
- `aad_b64`
- `size_bytes`

Relay never needs plaintext or private keys.

### 6.2 Operations

- `PUT_ENVELOPE` (store)
- `LIST_ENVELOPES` (paged fetch of headers)
- `GET_ENVELOPE` (fetch body)
- `ACK_ENVELOPE` (delete/tombstone after client persisted/decrypted)
- `EXTEND_TTL` (optional, policy-limited)

Transport can be implemented as libp2p request/response protocol:

- `/fidonext/mailbox/1.0.0`

### 6.3 Retention and quotas

Recommended defaults:

- max ttl: 7 days
- hard max ttl: 30 days
- per-device quota: 32 MiB
- per-account quota (sum of devices): 256 MiB

Mandatory behavior:

- reject writes exceeding quota,
- evict expired envelopes first,
- remove acknowledged envelopes immediately (or tombstone short-term for idempotency),
- enforce sender rate limits.

## 7. Deferred topics (TBD)

The following topics are intentionally out of scope for this draft and remain undecided:

- sync model between a user's own devices,
- large file storage and delivery architecture,
- any Filecoin/IPFS integration details.

## 8. Security requirements

- all protocol docs and envelopes must have canonical serialization before signature checks.
- reject clocks far in the future/past beyond drift allowance.
- never trust self-reported uptime/reputation; use local observations and challenge probes.
- enforce message size caps and strict parsing to prevent memory abuse.
- require replay protection using `message_id` + sender tuple and bounded retention window.

## 9. Rollout plan

Phase 1:

- implement relay descriptor publication/validation.
- add policy engine APIs (`set/get policy`) in C-ABI.

Phase 2:

- implement mailbox request/response protocol and local disk store.
- add N/W relay placement and retry queue.

Phase 3:

- add super-relay certificate chain validation and revocation handling.
- add scoring and diversity-aware placement.

Future phases (TBD, out of this stage):

- device sync protocol design and wire format,
- large-file storage architecture and optional external integrations.

