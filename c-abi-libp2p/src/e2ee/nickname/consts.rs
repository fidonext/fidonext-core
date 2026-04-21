//! TD-15 · Nickname registry — pinned constants.
//!
//! All domain-separator byte literals, size caps, and schema keys for the
//! nickname registry live here. Every separator is a byte literal (not
//! `format!` / `concat!`) so rustc freezes it at compile time. A trailing
//! `\x00` closes each separator to block length-extension collisions with
//! a hypothetical future `-extended` variant (mirrors the TD-05
//! `fidonext-profile-record-v1\x00` pattern).
//!
//! Verified non-colliding with existing separators in the crate:
//! - `e2ee::profile_record::PROFILE_SIGNATURE_DOMAIN`
//!   (`b"fidonext-profile-record-v1\x00"`)
//! - `e2ee::mod::FILE_CHUNK_NONCE_CONTEXT`
//!   (`b"fidonext-file-chunk-nonce-v1"`)
//! - JSON schema tags (`"fidonext-prekey-exchange-v1"`, etc.) — not signing
//!   separators, live in JSON `schema` fields.

/// Domain separator for `NickClaim` Ed25519 signatures. The signed payload
/// is `DOMAIN || canonical_cbor_map_without_signature_key`.
pub const CLAIM_SIGNATURE_DOMAIN: &[u8] = b"fidonext-nick-claim-v1\x00";

/// Domain separator for the PoW hash input. Separate from the signature
/// domain so that a signature pre-image and a PoW pre-image can never
/// collide, regardless of how clever the grinding gets.
pub const CLAIM_POW_DOMAIN: &[u8] = b"fidonext-nick-pow-v1\x00";

/// Domain separator for `NickVacate` Ed25519 signatures.
pub const VACATE_SIGNATURE_DOMAIN: &[u8] = b"fidonext-nick-vacate-v1\x00";

/// DHT key prefix for nickname -> claim. Full DHT key is
/// `SHA-256(CLAIM_DHT_KEY_PREFIX || utf8_nfc(nickname))` per design §1.
/// The `utf8_nfc` is a no-op for the v0.0.7 `^[a-z0-9_-]{3,32}$` charset
/// (all ASCII, all NFC-stable) but we document the shape here so future
/// charset expansion keeps the property.
pub const CLAIM_DHT_KEY_PREFIX: &[u8] = b"fidonext/nick/v1/";

/// Gossipsub topic for nickname registry anti-entropy / freshness.
/// **Reserved for future use.** TD-15 MVP ships DHT-only; registry-topic
/// pub/sub is not yet wired through the PeerManager event loop. When that
/// lands, the publish path MUST call the gossipsub handle directly on this
/// topic — NOT through `cabi_node_publish` / `PeerCommand::Publish` — so
/// registry traffic bypasses `handle_publish_command` entirely (design §7).
pub const NICKNAME_REGISTRY_TOPIC: &str = "/fidonext/nickname-registry/v1";

/// Nickname charset bounds for v0.0.7. Latin-only: `^[a-z0-9_-]{3,32}$`.
/// Cyrillic / i18n arrives later behind a charset-policy version bump.
pub const MIN_NICKNAME_LEN: usize = 3;
pub const MAX_NICKNAME_LEN: usize = 32;

/// Hard caps on claim / vacate record sizes. Tight caps make the
/// verification-before-parse guard cheap (if the CBOR expands past the
/// cap, reject without allocating field-level structures).
pub const MAX_CLAIM_RECORD_BYTES: usize = 2048;
pub const MAX_VACATE_RECORD_BYTES: usize = 1024;

/// Ed25519 signature length.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// PoW difficulty — first N bits of SHA-256 must be zero. Pinned at 22 by
/// the security-crypto-engineer sign-off (design §4). Lowering this
/// requires a crypto re-review.
pub const POW_LEADING_ZERO_BITS: u32 = 22;

/// Default claim validity, in seconds (30 days). Owner re-publishes every
/// 7 days; missed refresh past this TTL frees the name.
pub const DEFAULT_CLAIM_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Minimum vacate tombstone TTL, in seconds (30 days). Design §6 —
/// shorter tombstones get overwritten by a stale replica before the name
/// is safely released.
pub const MIN_VACATE_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Accepted ±window on self-asserted `claim_ts` vs observer clock, in
/// seconds (±120 s). Design §5. Widen to ±300 only on QA-measured
/// false-reject rate >5%; do not default to wide.
pub const MAX_CLAIM_TS_SKEW_SECONDS: u64 = 120;

/// Stale-replay reject: if `claim_ts` is more than this many seconds
/// before `observer_now`, the record is dropped outright (24 h; design §5).
pub const STALE_REPLAY_REJECT_SECONDS: u64 = 24 * 60 * 60;

/// Revision cap. Crypto review §5 asks for `u32::MAX` with a policy check
/// around `2^31`; we enforce both: anything with revision >= 2^31 is
/// rejected without an attestation. TD-15 never produces revision >= 2^31.
pub const REVISION_HARD_CAP: u32 = u32::MAX;
pub const REVISION_SOFT_CAP: u32 = 1 << 31;

/// CBOR integer-keyed map keys. Kept contiguous so canonical ordering is
/// trivial. Key `10` is RESERVED for the TD-17 recovery_pubkey flow —
/// TD-15 clients MUST reject any claim where key 10 is present.
pub const KEY_SCHEMA_VERSION: i128 = 0;
pub const KEY_NICKNAME: i128 = 1;
pub const KEY_PEER_ID: i128 = 2;
pub const KEY_DISPLAY_NAME: i128 = 3;
pub const KEY_AVATAR_SHA256: i128 = 4;
pub const KEY_CLAIM_TS: i128 = 5;
pub const KEY_VALID_UNTIL: i128 = 6;
pub const KEY_REVISION: i128 = 7;
pub const KEY_SIGNATURE: i128 = 8;
pub const KEY_POW_NONCE: i128 = 9;
/// RESERVED (TD-17). Verifiers in TD-15 reject records where this key is
/// present. Not produced by TD-15 clients.
pub const KEY_RECOVERY_PUBKEY_RESERVED: i128 = 10;
pub const KEY_ACCOUNT_PUBLIC_KEY: i128 = 11;

/// Vacate-record CBOR keys (subset of the claim keys; vacate is smaller).
pub const VKEY_SCHEMA_VERSION: i128 = 0;
pub const VKEY_NICKNAME: i128 = 1;
pub const VKEY_PEER_ID: i128 = 2;
pub const VKEY_VACATE_TS: i128 = 5;
pub const VKEY_REVISION: i128 = 7;
pub const VKEY_SIGNATURE: i128 = 8;
pub const VKEY_ACCOUNT_PUBLIC_KEY: i128 = 11;

/// Current schema version. Bumping this is a hard wire break — all
/// verifiers must be updated in lockstep. TD-17 (recovery mnemonic)
/// slots in under the same schema_version by populating the already-
/// reserved key 10.
pub const NICKNAME_SCHEMA_VERSION: u64 = 1;
