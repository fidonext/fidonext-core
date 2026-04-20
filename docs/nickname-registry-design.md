# TD-15 · Globally-unique nickname registry — design note

Status: design draft v2 (system-architect, 2026-04-19; crypto review folded in 2026-04-20).
Crypto review by `security-crypto-engineer` complete 2026-04-20 — see §12 for the original CHANGES_REQUESTED trail kept as an audit breadcrumb; all of it is now folded into §§3–7 below so implementers read a single coherent spec.
Implementation owner: `rust-p2p-engineer`, then `android-engineer`.
Supersedes / folds in: **TD-05** (device-directory fetch), partly **TD-06** (avatar hash carrier).
Cross-references: **TD-16** (domain-separator fix for legacy `KeyUpdateRecord` / `PreKeyBundleRecord`) tracked separately in `ROADMAP.md` — not required to ship TD-15 but should land in the same audit-readiness window. **TD-17** (BIP39 recovery mnemonic) deferred from TD-15 scope; tracked separately.

## 0. Scope

User decision (prompt #38): FidoNext nicknames must be globally unique across
the mesh, no central server. Avatars auto-fetch (incl. cellular); profile
changes are silent. This doc picks the mechanism, pins the record schema,
and lists the attack surface so `rust-p2p-engineer` can implement cleanly.

Non-goals: MLS group profiles (M5), channel handles (M6.1 — will reuse
this primitive with a different namespace), moderation (M6.2).

## 1. Chosen approach — Hybrid A+B: DHT as authoritative claim, Gossipsub as freshness/invalidation channel

**Short form:** primary claim record lives in Kademlia under
`key = H("fidonext/nick/v1/" || utf8_nfc(nickname))`. A dedicated pubsub topic
`/fidonext/nickname-registry/v1` broadcasts claims/vacates/conflicts for
anti-entropy. On conflict, first-writer-wins via deterministic tiebreak
`(first_seen_ts_at_observer ASC, sha256(peer_id) ASC)` — see §5 for why the
observer timestamp, not the self-asserted `claim_ts`.

### Why not pure (A) DHT
`libp2p::kad` stores one value per key. Under partition two honest peers can
both `PutRecord` the same nick; on heal, replicas disagree and a read-repair
flips the binding. Unacceptable for identity — we need an explicit conflict rule.

### Why not pure (B) CRDT on gossipsub
Forces every peer to ingest the full claim history to answer "is `alice` free?"
at add-peer time. Write amplification O(N). Kademlia already gives us
content-addressed lookup for free.

### Why not (C) registrar quorum
Super-relays are assist-only per trust model in repo `AGENTS.md`. Cosigning
turns them into a gate — violates "no central trust".

### The hybrid, concretely
1. **Claim**: sign `NickClaim` with `account_seed` (see §3), call
   `cabi_node_dht_put_record(key, cbor, ttl=30d)`. Publish the same bytes on
   the gossipsub topic (short fanout) via the registry topic handle directly —
   **not** through `cabi_node_publish` / `PeerCommand::Publish`. This keeps the
   record off the main message topic and avoids `handle_publish_command`
   entirely (see §7 for why this matters).
2. **Read**: `cabi_node_dht_get_record(key)` at `Quorum::Majority` (see §6).
   On miss, fall back to a 2 s gossipsub listen (handles "just published, not
   replicated yet"). Validation (signature + PoW + domain separator + field
   lengths) runs inside the Rust module **before** raw bytes cross the FFI —
   Android sees only a validated struct or a typed failure code.
3. **Refresh**: owner re-publishes every 7 days (inside 30-day TTL).
   Missed refresh > 30 d frees the name (see §4).
4. **Conflict**: if two claims for same key surface with overlapping validity,
   `winner = min_by((first_seen_ts_at_observer, sha256(peer_id)))` (see §5).
   If local cache disagrees, re-`PutRecord` the winner to heal the DHT. Loser
   gets a "nickname taken" error on next publish.

### libp2p APIs relied on
- `libp2p::kad::Behaviour::put_record` with `Quorum::Majority` (via the
  existing `dht_put_record(key, value, ttl_seconds)` wrapper — no new FFI).
- `libp2p::kad::Behaviour::get_record` at **`Quorum::Majority`** (see §6 for
  the MITM rationale — `Quorum::One` is NOT acceptable here). Optional
  latency optimisation: return the first record to the caller only if its
  canonical-CBOR bytes match the majority after the quorum completes;
  otherwise surface a "verifying..." state and re-fetch.
- `libp2p::gossipsub::Behaviour::publish` on a new topic hash, called on the
  gossipsub handle directly (not via the `Publish` command path).
- We do **not** override `libp2p::kad::store::RecordStore`. Conflict is
  decided at the application layer on top of `MemoryStore`.

## 2. Record schema (CBOR, canonical / deterministic encoding)

Moving off ad-hoc JSON. Prekey exchange uses JSON today (TD-03) but
that's a wire message, not a signed identity record. CBOR with canonical
map-key ordering + shortest-form integer encoding + no indefinite-length
items → reproducible signatures.

```
NickClaim = {
    0:  uint              ; schema_version, = 1
    1:  tstr              ; nickname, NFC-lowercase, ^[a-z0-9][a-z0-9_.-]{2,31}$
    2:  bstr              ; peer_id (libp2p PeerId::to_bytes(), derived from libp2p_seed)
    3:  tstr              ; display_name, 1..40 chars, no control chars
    4:  bstr(32) / null   ; avatar_sha256 — matches TD-06 file-transfer handle
    5:  uint              ; claim_timestamp_unix_seconds (self-asserted, used only for stale-replay reject — see §5)
    6:  uint              ; valid_until_unix_seconds (claim_ts + 30d)
    7:  uint              ; revision — monotonic per-owner, +1 on every re-publish, capped at u32::MAX
    8:  bstr(64)          ; Ed25519 signature over keys {0..7, 9, 10?, 11} (key 8 itself excluded)
    9:  uint (optional)   ; pow_nonce — see §4
    10: bstr(32) (future) ; recovery_pubkey — RESERVED, NOT USED in TD-15; see TD-17
    11: bstr              ; account_public_key — protobuf-encoded Ed25519 pubkey derived from account_seed; used to verify key 8
}
```

**Signing key**: `account_seed` (Ed25519, the app-level identity that also signs
`KeyUpdateRecord` / `PreKeyBundleRecord`). **NOT** `libp2p_seed`. Rationale:
(i) rotating the transport key for privacy must not invalidate every nickname
claim; (ii) `libp2p_seed` is presented in every Noise handshake, pulling it
into a second role as claim-signer concentrates blast radius. The `peer_id`
field (map key 2) binds the claim to the transport identity; the
`peer_id ↔ account_id` binding is separately attested by the existing
`KeyUpdateRecord` on the DHT (`e2ee/mod.rs:455`) — a high-stakes verifier may
cross-check this (not in TD-15 MVP; file as hardening follow-up).

> **Prerequisite for `rust-p2p-engineer`**: `account_seed` / `account_public_key`
> must be exposed to the nickname module. If not already in `PeerState` /
> profile state, wire it up before implementing `build_claim` — this is a
> blocking prereq, not an in-flight discovery.

**Signing payload** (exact bytes hashed and signed):
```
b"fidonext-nick-claim-v1\x00" || canonical_cbor_map({0,1,2,3,4,5,6,7,9?,10?,11})
```
Domain separator is written as a raw byte literal (`b"...\x00"`), not via
`format!` / `String` concatenation, so rustc freezes the bytes at compile
time. Signature (key 8) is excluded from the signed payload by construction.
Every other present key — including `pow_nonce` (key 9) and
`account_public_key` (key 11) — is covered by the signature.

**Canonical CBOR encoder**: use `ciborium` (already pulled in via the libp2p
`cbor` feature in `Cargo.toml`) with a hand-written canonicalizer, OR
`minicbor` with explicit canonical encoding. **`serde_cbor::ser::to_vec_packed`
is NOT sufficient** — it produces packed encoding but does not guarantee
RFC 8949 §4.2 map-key sorting on arbitrary input. Reject any incoming record
that does not round-trip byte-identically through canonical re-encoding.

**Curve**: Ed25519 over Curve25519 (libp2p's `identity::ed25519::SecretKey`
via `keypair_from_seed` at `e2ee/mod.rs:1223`). Plain Ed25519, not Ed25519ph,
not Ristretto — matches `KeyUpdateRecord` / `PreKeyBundleRecord` conventions.
Verification uses `libp2p::identity::PublicKey::verify` which wraps
`ed25519-dalek` `verify_strict` since libp2p 0.56 (rejects small-order A
points and non-canonical encodings — no malleability action required).

### Notes to implementers
- **Do NOT name any field `to_peer_id`** (TD-03 trap in
  `peer/manager.rs::handle_publish_command`). This record broadcasts, it is
  not addressed; it travels on its own gossipsub topic, not the main message
  topic, so it never hits `is_addressed_payload()`. Discipline anyway: the
  field is `peer_id` (not `to_peer_id`, not `target_peer_id`).
- **Unknown CBOR map keys must be rejected**, not ignored. Signed records
  tolerating unknowns let an attacker smuggle metadata some clients render.
  Also kills sig determinism across versions. This must be covered in the
  `validate_claim` unit tests (§9).
- **Check `schema_version` before signature verification** so we can evolve
  without fake-broken sigs on old clients.
- **Verification-before-parse**: the cheap PoW check (§4) runs before full
  CBOR parsing; malformed records never reach the parser.

### Why CBOR, not protobuf
`ciborium` is already in the tree (libp2p `cbor` feature). Protobuf adds
codegen. Canonical CBOR (RFC 8949 §4.2) gives us deterministic bytes for
signature coverage.

## 3. Domain separators — registry

All registry domain separators are pinned as raw byte literals in a single
`consts.rs` module inside the nickname submodule and reviewed so that no
separator is a prefix of another:

- `b"fidonext-nick-claim-v1\x00"` — `NickClaim` signature payload prefix.
- `b"fidonext-nick-pow-v1\x00"` — PoW hash input prefix (§4).
- `b"fidonext-nick-vacate-v1\x00"` — `NickVacate` signature payload prefix.

Verified non-colliding with existing separators in `c-abi-libp2p/src/`:
- `e2ee/mod.rs:57` — `b"fidonext-file-chunk-nonce-v1"` (AEAD nonce derivation).
- `e2ee/mod.rs:40` — `"fidonext-e2ee-v1"` (DHT key namespace string, not signing).
- `messaging/delivery.rs:8` — `"fidonext-delivery-v1"` (JSON schema tag, not signing).
- `"fidonext-prekey-exchange-v1"` (JSON schema tag, not signing).
- `"fidonext-delivery-status-v1"` (JSON schema tag).

The `\x00` terminator is load-bearing: it prevents length-extension style
ambiguity against a hypothetical future separator like
`"fidonext-nick-claim-v1-extended"`.

## 4. Squatting prevention (PoW + rate limit)

Bare Ed25519 costs ~30 µs. An attacker can grab every dictionary word in a day.
We need cost asymmetry.

**PoW on the claim, not the identity.** Each `NickClaim` carries `pow_nonce`
such that the first **22 bits** of the hash below are zero:

```
fn verify_pow(peer_id: &[u8], nickname: &str, pow_nonce: u64) -> bool {
    let mut h = Sha256::new();
    h.update(b"fidonext-nick-pow-v1\x00");              // domain sep, explicit \x00
    h.update(&(peer_id.len() as u32).to_be_bytes());    // length-prefix each variable field
    h.update(peer_id);
    h.update(&(nickname.len() as u32).to_be_bytes());
    h.update(nickname.as_bytes());
    h.update(&pow_nonce.to_be_bytes());
    let d = h.finalize();
    leading_zero_bits(&d) >= 22
}
```

**Hash**: SHA-256 via `sha2 = "0.10"` (already a Cargo dep in
`c-abi-libp2p/Cargo.toml`). **Not Blake3** — `blake3` is not in the tree;
attack asymmetry is identical for this use case; adding a new hash primitive
for one feature is not justified.

**Bit count**: 22 bits. 20 bits is roughly 200 ms of grind on a single modern
CPU core (~5 M SHA-256/s per core, so 2²⁰ ≈ 200 ms), which lets a one-laptop
squat-farm mint a claim every quarter-second and drown the topic. 22 bits
lands at ~8–15 s median on a 2020-era Android, ~1 s on a laptop, with
verification still in the low microseconds. Paid once per claim.

**Length-prefixing is not optional.** Without it, an attacker grinds
`peer_id=X, nickname=Y1|Y2` into a different `peer_id=X|Y1, nickname=Y2`
claim with the same pre-image hash. Every variable-length field in the PoW
input and the signing input MUST be length-prefixed with a fixed-width big-
endian u32.

**Verification-before-parse**: on inbound registry gossip, the verifier
(i) recomputes the PoW over the claimed `peer_id` and `nickname` bytes and
rejects on mismatch before allocating / parsing the CBOR body, (ii) drops
malformed frames at the gossipsub layer, (iii) applies a `PeerScoreParams`
penalty on repeated bad PoW from the same peer. This blocks CPU-DoS via
flood of malformed records.

**Rate limit** (complements PoW — PoW alone cannot stop a farm, the rate
limit makes squatting expensive per-identity):
- 1 new distinct nickname per peer_id per 7 days (re-publish / vacate-and-
  reclaim of your own name does not count).
- Enforced by: super-relay observed gossip rate-limit (drops republishes from
  same peer_id faster than 1/hour); honest-client restraint; "too recent"
  rejection in peer validation; gossipsub `PeerScoreParams` penalty on
  offenders.

Rejected alternatives:
- "Prior-message-exchange edge" gate — creates a first-user onboarding deadlock.
- PoW on peer_id itself — breaks TD-14 (profiles exist today without PoW) and
  penalises users who never claim a nickname. Claim-time PoW keeps TD-14
  intact and is opt-in with the nickname feature.

## 4b. Reclaim after identity loss — (TD-15 scope: accept the loss)

User loses phone / loses `alice.profile.json`. New profile = new `peer_id` =
no signature chained to the old claim.

**For TD-15 we ship option (4a) "accept the loss":** the claim sits in DHT
until TTL expires (30 d), then the name is up for grabs again. This is
consistent with `AGENTS.md` ("Rotating identity = new profile") and honest
about the current threat model (profile = secret at rest on Android
app-private storage; device loss = identity loss).

**Recovery mnemonic (BIP39) deferred to TD-17**; for TD-15 ship, lost identity
= lost nickname after 30-day TTL. The user can re-claim the same nickname
after expiry if nobody else grabbed it. Rationale for deferral is in the TD-17
ROADMAP row — in short, introducing a forever-user-secret rewrites our
at-rest threat contract and the ceremony for "prove I am the old owner
without the old key" needs its own threat model.

Map key `10: recovery_pubkey` is **RESERVED** in the schema so a future TD-17
`NickRecovery` flow can slot in without a schema_version bump — but it is
NOT USED, NOT SIGNED, and NOT PRODUCED by TD-15 clients. Verifiers in TD-15
reject any claim where key 10 is present (unknown-field policy, §2).

**Stolen account_seed**: without recovery, an attacker with the account key
can re-publish in the victim's name. The legitimate owner cannot produce a
higher-revision vacate faster than the attacker. Name is effectively lost
for 30 d until TTL expiry. Accepted cost of (4a).

## 5. Lookup, tiebreak, and clock skew

UX flow: "Add peer" → types `alice` → confirms.

**Worst case** (cold client, no cache):
1. `cabi_node_dht_get_record(H("fidonext/nick/v1/alice"))` at
   `Quorum::Majority` — Kademlia iterative, 2-4 RTT, 200-800 ms typical, up
   to a few seconds over CGNAT.
2. On miss: 2 s gossipsub listen on the registry topic.
3. Validation (signature + PoW + timestamp skew + field lengths) runs inside
   the Rust module, < 1 ms local. Android receives a validated struct or a
   typed failure code — never raw bytes.
4. Kick off avatar fetch via TD-06 file-transfer by `avatar_sha256` (async,
   does not block add-peer).
5. Return resolved `peer_id` to Android → existing `lookupAndDial` + prekey fetch.

**Clock skew tolerance: ±120 s on first-sight**, matching what Android's
Signal client uses and what our NTP-sync-on-first-boot (§10 risk row) can
achieve reliably. Reject any claim where `|claim_ts - observer_now| > 120 s`.
Widen to ±300 s only if QA reports >5% false-reject on a real device fleet;
do not default to wide. 600 s (the initial design sketch) is too generous
under first-writer-wins — an attacker with NTP wins every race against
honest users whose phones are anywhere from −10 min to +10 min off, which
is most phones.

**Stale-replay reject**: if `claim_ts` is more than **24 h** before
`observer_now`, reject outright. Stops an offline-grinder from submitting a
5-year-old `claim_ts` to win tiebreaks.

**Tiebreak**: on two claims for the same key with overlapping validity, use

```
winner = min_by((first_seen_ts_at_observer, sha256(peer_id)))
```

The first component is "when did **this observer** first hear about the
claim on the registry topic", NOT the self-asserted `claim_ts`. Rationale:
self-asserted timestamps are adversary-controllable; "who did the network
hear first" is adversary-resistant. `claim_ts` is kept in the record only
for the stale-replay window above. This replaces the earlier
`(claim_ts, sha256(peer_id))` rule sketched in the pre-crypto-review draft.

**Revision**: monotonic per-owner, +1 on every re-publish. Capped at
`u32::MAX`; reject any claim that sets `revision >= 2^31` without an
`attestation` from the current binding. At 7-day refresh cadence the cap is
effectively unreachable; low cap makes replay-with-grinding harder.

**UX recommendation:**
- Async, 5 s spinner timeout. After 5 s show "still searching..." and keep
  running in background. Never block UI.
- Local `NicknameCache(nickname → NickClaim)`, evict on `valid_until`. Cache
  hit < 24 h → resolve immediately, refresh in background.
- On lookup failure: offer "add by peer_id" fallback (existing TD-07 flow).
- On `Quorum::Majority` disagreement between replicas: surface a
  "verifying..." badge in the UI; re-fetch; resolve only after agreement.

## 6. Replay / revocation / DHT MITM

- **Replay**: each `NickClaim` carries monotonic `revision`. Reject any claim
  with `revision <= cached_revision` from the same `peer_id`. If `peer_id`
  differs, tiebreak (§5) decides.
- **Timestamp grinding**: addressed by the 24 h stale-replay rule plus the
  observer-timestamp tiebreak (§5).
- **Rate limit**: see §4.
- **Vacate**: `NickVacate { schema_version, nickname, peer_id,
  account_public_key, vacate_ts, revision, signature }` on the registry
  topic, signed under `b"fidonext-nick-vacate-v1\x00"`. Valid vacate with
  `revision > last_seen_revision` clears local binding. DHT record is
  overwritten with a **tombstone whose TTL = original claim's remaining
  validity, minimum 30 days**. Carries the last-seen `revision` and a fresh
  signature. The initial "7-day tombstone TTL" sketch was too short against
  `libp2p::kad` record re-propagation from lagging replicas — a short
  tombstone gets overwritten by a stale replica and the name flips back.
- **DHT MITM hardening**: Kademlia by itself is unauthenticated at the
  resolver — any node holding a replica can answer a `get_record`, and
  `Quorum::One` means a single malicious relay can return a crafted record
  for any nickname. The signature on the record is the defense, but only if
  enforced correctly:
  - `get_record` runs at **`Quorum::Majority`** (not `Quorum::One`). The
    latency-optimistic "return first, repair in background" pattern is
    allowed only if the first result's canonical-CBOR bytes match the
    majority once the quorum completes; otherwise re-fetch and show
    "verifying...".
  - **Validation runs before the FFI boundary.** Raw record bytes never
    cross into Android. The JNI wrapper receives a validated struct or a
    typed failure code (`NickLookupErr::BadSignature`,
    `NickLookupErr::BadPoW`, `NickLookupErr::StaleClaim`,
    `NickLookupErr::SchemaReject`, `NickLookupErr::NotFound`,
    `NickLookupErr::NetworkTimeout`). This is pinned as a contract on
    `validate_claim` in §9.
  - Gossipsub-on-miss fallback (§1.4 step 2) applies the same validation
    rigor — do not trust the fact that we asked for it.
- **Stolen account key**: see §4b.

## 7. Interaction with TD-05, TD-06, and `handle_publish_command`

**This design subsumes TD-05.** The stubbed
`cabi_e2ee_{validate,fetch}_device_directory` in `lib.rs` become the
nickname-registry entry points — either renamed, or removed in favour
of the generic DHT FFI (see below).

### strict-E2EE / `handle_publish_command` interaction — confirmed safe
Crypto review traced `c-abi-libp2p/src/peer/manager.rs:764-819` and
`c-abi-libp2p/src/messaging/delivery.rs:192-212` and confirmed:
- The registry topic `/fidonext/nickname-registry/v1` is separate from the
  main gossipsub topic (`"echo"` in `peer/manager.rs:354`).
- The registry publish path calls the gossipsub handle **directly** on the
  registry topic, NOT `cabi_node_publish` / `PeerCommand::Publish`. This is a
  load-bearing constraint — pin it in the hand-off to `rust-p2p-engineer`
  (§9). It keeps registry traffic out of `handle_publish_command` entirely.
- Even if it did flow through `handle_publish_command`, the CBOR payload has
  no top-level `to_peer_id` JSON field (by construction — §2 bans the name
  and we're not using JSON), so `is_addressed_payload()` returns false (JSON
  parse fails first: CBOR starts with major-type 5 map marker `0xA*`, not
  `{`), and the payload would fall through to `publish_legacy_payload`. The
  TD-03 trap is avoided both by topic isolation and by serialization format.

### C-ABI delta — minimal, reuses existing primitives

**Option 1 (recommended): no new FFI.** Registry is built on top of
existing `cabi_node_dht_put_record` / `cabi_node_dht_get_record` and the
existing gossipsub publish/dequeue. Record schema, signing, validation
live in a new pure-Rust module `e2ee::nickname` — no FFI boundary. Android
identifies nickname-registry frames on the gossipsub dequeue by CBOR schema
version + topic. Polling contract intact. No new queues.

**Option 2 (only if Android CBOR is awkward in Kotlin):** add four strictly
polling-compatible C-ABI functions:
- `cabi_nickname_claim(handle, nick, display_name, avatar_sha256)`
- `cabi_nickname_lookup(handle, nick, request_id)` → async result
- `cabi_nickname_vacate(handle, nick)`
- `cabi_node_dequeue_nickname_event(handle, out_buf, out_len, written)`
  — new queue capacity 128, carries `{kind, nickname, peer_id,
  display_name, avatar_sha256, status}`.

Architect recommends **Option 1**. Revisit Option 2 if the Kotlin side
hits CBOR friction — the wire protocol is identical either way, and the
migration back to Option 1 is free if we change our mind.

### TD-06 avatar hash
`avatar_sha256` in `NickClaim` is the exact file-transfer handle TD-06 will
define. Fetch after resolve via existing `/fidonext/file-transfer/1.0.0`
request-response. Cache to `filesDir/avatars/<sha256>.jpg`, render in `ChatItem`.

### Data model split vs existing profile
One signed record, stored at two DHT keys:
- `H("fidonext/nick/v1/" + nickname)` — for nickname → peer_id.
- `H("fidonext/profile/v1/" + peer_id.to_bytes())` — for peer_id → profile
  (used when we have a peer_id but no nickname cache entry, e.g. TD-07 peers).

Both keys store the *same* CBOR bytes. One extra `PutRecord` per 7-day
refresh. Closes TD-05 story (profile fetch by peer_id) with zero extra schema.

## 8. Open questions for PO / user

1. **Nickname-change linkage**: display_name/avatar updates are silent per
   decision #38. A *nickname* change is vacate + new-claim — a peer watching
   the registry topic sees "alice vacated, peer X now claims bob". OK, or
   must we hide linkage (rotating peer_id on nickname change is expensive
   and breaks open sessions)? Architect: OK, nickname changes are rare.
2. **Channel names (M6.1)**: reuse this primitive under namespace
   `fidonext/channel/v1/...`, or a separate protocol? Not blocking TD-15,
   but affects module naming (`e2ee::nickname` vs `e2ee::directory`).
   Architect prefers reuse.
3. **Metadata leak copy in Settings UI**: users claiming a nickname publish
   `<nick> → <peer_id>` to everyone on the mesh (§10 risk row). Surface a
   one-liner in Settings next to the nickname field, e.g. *"Claiming a
   nickname publishes `<nick> → <peer_id>` to everyone on the mesh. Leave
   blank for anonymous peer-id-only mode."* Architect: YES, hand to
   `android-engineer` as part of the wiring task. Flagging for PO to approve
   copy.

## 9. Hand-off

### For `rust-p2p-engineer` (after TD-05/TD-06 unblock)

Prerequisites:
- **`account_seed` / `account_public_key` must be exposed** to the nickname
  module. If not already in `PeerState` / profile state, wire it up first.
  This is a blocking prereq.

Work items:
- New module `c-abi-libp2p/src/e2ee/nickname.rs` with a `consts.rs` sibling:
  - Domain-separator byte literals (§3) pinned in `consts.rs`.
  - `NickClaim` / `NickVacate` CBOR types (key `10: recovery_pubkey`
    reserved but unused — TD-17).
  - `build_claim(profile, nickname, display_name, avatar) -> Vec<u8>`
    using `ciborium` canonical encoding, signed with `account_seed`.
  - `validate_claim(bytes, now_unix) -> Result<NickClaim, NickLookupErr>`
    covering: verification-before-parse PoW (22-bit SHA-256,
    length-prefixed), canonical-CBOR round-trip check, schema_version check
    before signature, signature verification against key 11
    (`account_public_key`) under `b"fidonext-nick-claim-v1\x00"`,
    ±120 s clock-skew check, 24 h stale-replay reject, unknown-map-key
    rejection, reserved-key-10-present rejection. **Runs before the FFI
    boundary** — caller receives a validated struct or a typed error, never
    raw bytes.
  - `claim_dht_key(nickname) -> Vec<u8>`, `profile_dht_key(peer_id) -> Vec<u8>`.
  - Constant `NICKNAME_REGISTRY_TOPIC = "/fidonext/nickname-registry/v1"`.
- Subscribe `PeerManager` to the new gossipsub topic at boot.
- **Registry publish uses the gossipsub topic handle directly, not the
  `Publish` command path / `cabi_node_publish`** (§7). Pin this in code
  review.
- Conflict-resolution handler on received claims: observer-timestamp tiebreak
  (§5), DHT heal on mismatch.
- `get_record` calls run at **`Quorum::Majority`** (§6). Latency-optimistic
  early return only on canonical-byte agreement with the majority.
- Re-enable `cabi_e2ee_{validate,fetch}_device_directory` — either route to
  the new module (closes TD-05) or remove them (Option 1: Android uses
  generic DHT FFI).
- Background task: every 7 d, republish own `NickClaim` on both DHT keys.
- Vacate tombstone TTL = remaining claim validity (min 30 d).
- Gossipsub `PeerScoreParams` penalty on repeated bad PoW / malformed frames.
- 10+ unit tests: PoW grinding at 22 bits, PoW length-prefix manipulation
  detection, signature forgery against wrong key, account_seed vs
  libp2p_seed confusion, timestamp skew (±120 s boundaries), 24 h stale
  reject, replay-by-revision, observer-timestamp tiebreak determinism,
  vacate, tombstone TTL, canonical CBOR roundtrip, unknown-field rejection,
  reserved-key-10 rejection.

### For `android-engineer` (after core lands)
- `SelfProfileRepository` (TD-14) gains `publishToMesh()` calling
  `cabi_node_dht_put_record` with bytes built by a Rust helper taking
  plain fields (cleaner than a Kotlin CBOR encoder).
- `PeerRepository.lookupByNickname(String)` wraps `dht_get_record` + 2 s
  gossipsub listen fallback, returns async `Result<PeerId, NickLookupErr>`.
  Typed failure codes from core — no raw bytes on this side of the FFI.
- Avatar fetch on resolve via file-transfer by `avatar_sha256`, cache to
  `filesDir/avatars/`.
- Settings: "nickname taken" inline error, Save disabled. Plus the
  metadata-leak disclaimer copy (§8 q3), pending PO approval.
- UX: 5 s spinner on add-by-nickname, fallback to add-by-peer_id.
- "Verifying..." badge UI state for `Quorum::Majority` disagreement case.

### For `e2e-qa-engineer` (playbook additions)
- (f) two phones race-claim same nick — only one wins, loser sees error;
  winner is the one the observer heard first, not the one with the earlier
  self-asserted `claim_ts`.
- (g) A claims `alice`, offline 35 d, B claims `alice` — B wins post-TTL.
- (h) A changes display_name; B sees it within one refresh, no chat disruption.
- (i) Avatar auto-fetch on cellular succeeds, renders in ChatItem.
- (j) Malformed claim (bad sig / bad PoW / skewed ts / unknown CBOR field /
  reserved-key-10 present / non-canonical CBOR) rejected by all observers;
  no cache poisoning.
- (k) Phone with clock skew +90 s → accepts. +180 s → rejects. -90 s →
  accepts. -180 s → rejects. (±120 s boundary.)
- (l) Stale-replay: a claim with `claim_ts = now - 48 h` is rejected
  outright even if otherwise well-formed.
- (m) DHT MITM sim: one relay returns a forged record for `alice`;
  `Quorum::Majority` disagrees with the forgery; client shows "verifying..."
  and converges to the real record.

## 10. Risks

- **Partition + replay**: gossipsub partitions let two regions both believe
  they own `alice`. Merge flips one. Mitigated by §5 observer-timestamp
  tiebreak; UX shows cached name with "verifying..." badge while DHT
  reconciles.
- **Metadata leak**: registry topic leaks `(nickname → peer_id)` to all
  subscribers including super-relays. That is the point — discoverability
  requires it. Users wanting unlinkable presence don't register a nickname
  and use peer_id-only add (TD-07). Must be explicit in the Settings copy
  (§8 q3) and in the privacy FAQ.
- **M8 fractal sharding**: registry keys are flat today. When sharded,
  nickname keys live in a *global* shard (names are global); profiles can
  live in the owner's cell. Plan namespace split
  `fidonext/global/nick/v1/...` vs `fidonext/cell/<cid>/profile/v1/...`
  when M8 lands. Not blocking M1-M3.
- **Unicode homograph attacks**: `аlice` (Cyrillic а) vs `alice`. Mitigated
  by ASCII-only regex (§2). If relaxed for non-English, add `unicode-security`
  confusables check before accept. Flag for PO if relaxation requested.
- **PoW on entry-level Android**: 2²² hashes ≈ 8-15 s median on a 2020-era
  Android. One-time at claim. Lower bits halves squat cost — crypto has
  pinned 22 bits; do not tune down without re-review.
- **Clock skew**: strict ±120 s on `claim_ts` rejects legitimate users with
  wildly-wrong device clocks. On first-boot we sync via NTP from a known
  relay or fall back to Android `SystemClock.wallTime`. QA scenario (k)
  covers the boundary.
- **DHT MITM**: addressed in §6 (`Quorum::Majority`, validation-before-FFI).

## 11. Milestone alignment

TD-15 fits the M2.x polish window (between M2.1 mailbox and M2.2 push).
It unblocks the "real user names" half of the UX milestone gated to
"first real-user release" in the tech-debt table. No M3/M4 code is
blocked. Foundation for M6.1 channel names.

Crypto sign-off (approvals): domain-separator scheme, 30 d TTL + 7 d
refresh cadence, unknown-CBOR-field rejection. See §12 for the full trail.

---

## 12. Crypto Review trail (security-crypto-engineer, 2026-04-20)

Original review preserved as an audit breadcrumb. All CHANGES_REQUESTED and
the VETO below have been folded into §§2–7 above; this section is historical.

Verdict summary:
- **APPROVE**: 3 items — domain-separator scheme (with byte-literal fix),
  30 d TTL + 7 d refresh cadence, unknown-CBOR-field rejection.
- **CHANGES_REQUESTED**: 4 items — PoW bit count + algorithm + length-prefix;
  Ed25519 signing key choice + canonical CBOR encoder; replay / clock skew /
  tiebreak rules; DHT MITM hardening via `Quorum::Majority` and
  validation-before-FFI.
- **VETO**: 1 item — shipping BIP39 recovery mnemonic (§4b option 4b) in
  TD-15. Filed as TD-17. Design direction approved for a future separate TD.

Crypto-flagged TD-16 (pre-existing domain-separator gap in
`KeyUpdateRecord` / `PreKeyBundleRecord`) is tracked separately in
`ROADMAP.md` and is not required to ship TD-15, but should land in the same
audit-readiness window.

Overall: **Conditional GO** for `rust-p2p-engineer` once TD-05 / TD-06
unblock and the CHANGES_REQUESTED items above are folded in. This fold-in
(2026-04-20) fulfills that second condition. Awaiting crypto verify-pass on
the folded-in document — see §13.

## 13. Crypto Sign-Off (pending)

Space reserved for `security-crypto-engineer` verify-pass on the
folded-in document. Expected format:

> `## Crypto Sign-Off (2026-04-20): <verdict> — <one-paragraph summary>`

`system-architect` to request the verify-pass via a new Agent call
immediately after this fold-in lands.

---

## §13 — Crypto Sign-Off (security-crypto-engineer, 2026-04-20, verify-pass)

**Verdict:** APPROVE — design is locked.

**Items 1–4 folded faithfully:**
1. **YES.** §4 specifies 22 bits (line 196, `>= 22`), SHA-256 via `sha2 = "0.10"` (line 200, "Not Blake3" called out line 201), length-prefix with fixed-width big-endian u32 on every variable field (lines 190-194 code; line 215 "Every variable-length field ... MUST be length-prefixed"), and verification-before-parse (lines 149-150, 219-222) with explicit ordering "recomputes the PoW ... before allocating / parsing the CBOR body".
2. **YES.** §2 line 98 pins `account_seed` with "NOT `libp2p_seed`" and rationale; no stray `libp2p_seed` references remain as signing key (the three remaining hits are the explicit negation at line 99, the rationale prose at line 101, and a unit-test name "account_seed vs libp2p_seed confusion" at line 482 — all correct uses). Key `11: account_public_key` present at line 94 and covered by signature (line 91, line 121). `serde_cbor::ser::to_vec_packed` is explicitly called "NOT sufficient" (line 125), `ciborium` / `minicbor` named as the replacement. Domain separators are byte literals `b"...\x00"` (§3 lines 163-165). Prereq on `rust-p2p-engineer` called out as "blocking prereq" at lines 108-111 and 443-446.
3. **YES.** §5: ±120 s (line 285), tiebreak on `first_seen_ts_at_observer` (line 299, with explicit "NOT the self-asserted `claim_ts`" at line 303), stale-replay reject at 24 h (line 293). §6: vacate tombstone TTL = remaining claim validity, min 30 d (lines 336-337).
4. **YES.** §1.2 and §6: `Quorum::Majority` on `get_record` (lines 49, 64, 345); `Quorum::One` explicitly called "NOT acceptable" (line 65). Validation-before-FFI pinned at lines 51-53, 277-278, 350-352. Typed `NickLookupErr` enum with {BadSignature, BadPoW, StaleClaim, SchemaReject, NotFound, NetworkTimeout} at lines 353-355.

**Judgment calls A–D:**
- **(A) Reserved key 10** — **APPROVE.** Reserving `recovery_pubkey` with explicit "verifiers reject claims where key 10 is present" (lines 259-261) preserves the unknown-field-rejection invariant while giving TD-17 a clean slot. Cleaner than a schema_version bump because TD-17 will need to extend the signed payload anyway; reserving now means no version skew between TD-15 and TD-17 verifiers on well-formed TD-15 records. Unit test for "reserved-key-10 rejection" is in the test list (line 485).
- **(B) Option 1 vs Option 2 FFI choice left open** — **APPROVE.** Not a crypto concern; wire protocol is identical in both options (line 402-404). No objection.
- **(C) `NickLookupErr` typed-error enum** — **APPROVE as proposed.** Six variants cover the crypto-relevant failure modes without leaking internal state. One minor note for impl: `SchemaReject` should cover both unknown-map-key and reserved-key-10-present cases (single error variant is fine — the log / metric side can distinguish, the caller does not need to).
- **(D) QA scenarios (k)(l)(m)** — **APPROVE, one addition.** Coverage is good. Add **(n) PoW length-prefix manipulation**: craft two records `(peer_id=X, nick=Y1||Y2)` and `(peer_id=X||Y1, nick=Y2)` that would collide without length-prefixing; verifier must reject the one whose computed PoW doesn't match its declared fields. This validates the §4 length-prefix invariant end-to-end, not just in the unit test.

**Additional observations:**
- **TD-16 cross-reference** (line 7, §7 implicit via the `handle_publish_command` analysis): faithful. The pointer correctly states TD-16 does not block TD-15 ship but targets the same audit-readiness window. No change requested.
- **`handle_publish_command` safety analysis** (lines 368-382): intact and correct. The two-layer defense (topic isolation + serialization-format check via `is_addressed_payload()` JSON-parse failure on CBOR major-type 5) is accurately described. The explicit pin "registry publish uses the gossipsub topic handle directly, NOT `cabi_node_publish`" at lines 374-376 and 467-469 is load-bearing and correctly elevated.
- **`PeerScoreParams` penalty hook** (§4 line 221, §9 line 479): this was **not** in my original review. It is, however, a reasonable crypto-adjacent hardening — it blunts the CPU-DoS-via-malformed-flood vector that verification-before-parse only partially mitigates (per-frame work is low but not zero). **Approve as added.** Implementation note for `rust-p2p-engineer`: the penalty weight should be tuned so that a peer hitting the malformed/bad-PoW threshold is score-graylisted before they can exhaust the verifier, not after. Not blocking; flag for post-impl review.
- **Canonical-CBOR round-trip check** (line 128): this was implied in my review but the architect made it concrete ("Reject any incoming record that does not round-trip byte-identically"). Good — approve.
- **`verify_strict` note** (lines 133-135): architect added the `ed25519-dalek verify_strict` small-order-A rejection assurance. Not in my original review, correctly crypto-adjacent, **approve** — matches what the existing `KeyUpdateRecord` path relies on via `libp2p::identity::PublicKey::verify`.

**Go / no-go for `rust-p2p-engineer` to start TD-15 impl (once TD-05 + TD-06 land):** **GO**, conditional on:
1. The `account_seed` / `account_public_key` exposure prereq (§2 lines 108-111, §9 lines 443-446) is satisfied before `build_claim` is written — not discovered mid-impl.
2. QA playbook picks up scenario **(n)** above alongside (k)(l)(m).
3. Unit-test list in §9 (lines 480-485) is implemented in full — specifically the "account_seed vs libp2p_seed confusion" test and the "PoW length-prefix manipulation detection" test are non-negotiable; they are the regression backstops for items 1 and 2 of this review.

Design is **LOCKED**. No further crypto review required unless the record schema, domain separators, signing-key choice, PoW parameters, tiebreak rule, or FFI-validation contract change. Out-of-band changes to any of those → re-review.

## §14 — TD-05 Quorum Deferral (security-crypto-engineer, 2026-04-20)

**Verdict: APPROVE DEFERRAL.**

TD-05 may ship with default (`Quorum::One`) `get_record` behavior and take `Quorum::Majority` with TD-15. Rationale: the profile record is low-stakes mutable metadata (display_name, nickname-as-hint, avatar_sha256), not a commitment or ownership claim. The signature + embedded `account_public_key` + FFI-side `record.peer_id == requested_peer_id` check (`lib.rs:1396`) already block identity substitution. The only residual attack under `Quorum::One` is stale-but-validly-signed replay; in steady state the `previous_updated_at` anti-downgrade guard (`profile_record.rs:261-268`) handles it. First-contact replay lets a malicious replica pin an out-of-date display name until the next write propagates — unpleasant, not a crypto failure. Upgrade call site is confirmed single-point (`peer/manager.rs:770`), so TD-15 covers both paths atomically. **No patch required on the TD-05 commit.** TD-15 MUST NOT ship without `Quorum::Majority` — that verdict from §9 stands and is now load-bearing for the profile path too.

## §15 — TD-06 Protocol Deviation (system-architect, 2026-04-20)

**Verdict: APPROVE, with a forward-looking rename required before M6.1.**

Commit `dbfc7d6` adds a dedicated `/fidonext/avatar-fetch/1.0.0` request-response behaviour instead of extending `FileTransferFrame`. The deviation is justified on operational grounds, but the engineer's wire-break argument is overstated and the protocol name sets a bad precedent.

**Rationale to approve:**
- The real separation-of-concerns win is timeout and head-of-line isolation. `/fidonext/file-transfer/1.0.0` runs a 30 s timeout tuned for multi-MB chunked uploads with an in-flight window; avatar fetch is a single-RTT ≤64 KiB pull that wants an 8 s UI-friendly deadline. Colocating them on one behaviour couples unrelated backpressure.
- M3 will extend `FileTransferFrame` with FEC + CID manifest variants. Keeping the avatar path off that enum lets M3 evolve the chunked-file wire without dragging avatars through the same migration.
- Additive-only wire change: peers without the new protocol return `UnsupportedProtocols` cleanly; nothing queued on `/fidonext/file-transfer/1.0.0` is disturbed.

**Where the engineer's framing is wrong (note, not blocking):**
- Adding a `FileTransferFrame::AvatarFetch` variant would NOT break in-flight file transfers that use existing variants. CBOR enum deserialization fails only on the unknown variant frames themselves. The accurate cost is "older peers can't participate in avatar fetch" — identical to the cost of a new protocol. The protocol-separation case rests on timeout/queueing, not on serde safety. Please correct the commit message narrative in any downstream report.

**CHANGES_REQUESTED (non-blocking for this commit; required before M6.1 SDK design freeze):**
- **Rename the protocol** from `/fidonext/avatar-fetch/1.0.0` to `/fidonext/blob-fetch/1.0.0` (or `/fidonext/content-fetch/1.0.0`) with the same wire shape. Avatars are a degenerate case of "small content-addressed blob by sha256"; M6.1 channel cache reads (latest event by CID) and any future small-object fetch (sticker packs, link previews) should ride the same protocol with policy layered above (who-serves-what is a handler concern, not a protocol concern). One small-blob protocol forever is fine; N asset-type protocols is not.
- The size cap and 8 s timeout stay. The server-side policy "I only serve my own self-avatar" becomes a handler-level filter; other handlers can serve other content classes on the same behaviour. Request/response payload shape is unchanged.
- If rename lands in a follow-up commit before Android wiring (TD-06 app side), no Android churn. If app wiring lands first on `avatar-fetch/1.0.0`, bumping to `blob-fetch/1.0.0` becomes an Android release-coupled change. **Prefer the follow-up commit now.**

**Not requested:**
- No C-ABI rename. `cabi_node_set_self_avatar` / `cabi_node_fetch_avatar` are the right FFI granularity for the Android UX layer; they can sit on top of a generic blob-fetch protocol without leaking that generality to the JNI boundary. Keep `CABI_MAX_AVATAR_SIZE_BYTES` and the 64 KiB cap as the avatar-specific policy; a future `cabi_node_fetch_blob` (M6.1) can pick its own cap.

**Milestone alignment:** fits TD-06 (M2-era polish). Rename unlocks clean M6.1 reuse.

**Risks:**
- Protocol-surface growth: mitigated by the rename above.
- Metadata leak: `/fidonext/avatar-fetch/1.0.0` in Identify `protocols` field is a FidoNext-client fingerprint distinct from `/fidonext/file-transfer/1.0.0`. Post-rename, `blob-fetch` is the single "small content fetch" signal. Acceptable for M2/M3; flag for M7 DPI-camouflage work to collapse these into a smaller protocol set.
- No FFI polling-contract drift: both new FFIs are synchronous call-return (set/fetch with response buffer). No new queue, no new dequeue function. Conforms to the polling-only rule.

**Hand-off:**
1. `rust-p2p-engineer`: follow-up commit renaming the libp2p protocol string and the Rust type names (`AvatarFetchRequest` → `BlobFetchRequest`, etc.), keeping the C-ABI surface identical. Single-file change on the wire side; handler-level "is this my self-avatar?" check stays in `peer/manager.rs`. Target: before TD-06 Android wiring lands.
2. `android-engineer`: proceed with `cabi_node_set_self_avatar` / `cabi_node_fetch_avatar` wiring as planned. No Android-side change from the rename.
3. `product-owner`: update ROADMAP TD-06 row to reflect "approved with rename follow-up" and record the M6.1 linkage (blob-fetch reuse).
