//! TD-15 · Globally-unique nickname registry — core record / validation
//! primitives.
//!
//! The registry binds a globally-unique nickname to a `peer_id` via a
//! signed CBOR claim record stored in the DHT at
//! `SHA-256("fidonext/nick/v1/" || nickname)`. See
//! `fidonext-core/docs/nickname-registry-design.md` for the locked spec.
//!
//! **Scope of this module**
//!
//! - `NickClaim` / `NickVacate` CBOR types and canonical encoding.
//! - `build_claim` / `build_vacate` (signing + PoW).
//! - `validate_claim` / `validate_vacate` (verification-before-parse,
//!   signature, PoW, domain separator, ±120 s skew, 24 h stale-replay,
//!   unknown-key reject, reserved-key-10 reject).
//! - `claim_dht_key(nickname)` and `validate_nickname_charset`.
//!
//! **Out of scope for TD-15 MVP** (tracked as follow-ups):
//! - Gossipsub registry topic subscription + anti-entropy (`NICKNAME_REGISTRY_TOPIC`
//!   is defined in `consts.rs` but the PeerManager does not yet subscribe;
//!   DHT alone carries the MVP).
//! - Observer-timestamp tiebreak bookkeeping in PeerManager state. Design
//!   §5's deterministic winner is implemented as a pure `tiebreak_winner`
//!   helper here so the state-carrying wiring can land on top without a
//!   protocol change.
//! - TD-17 recovery_pubkey (key 10) — RESERVED and REJECTED on inbound.
//!
//! All validation runs **before** the FFI boundary. Callers receive a
//! typed `NickLookupErr` or a validated struct, never raw record bytes.

use anyhow::{anyhow, Context, Result};
use ciborium::value::{Integer, Value};
use libp2p::{identity, PeerId};
use sha2::{Digest, Sha256};

use super::{keypair_from_seed, IdentityProfile};

pub mod consts;

pub use consts::{
    CLAIM_DHT_KEY_PREFIX, CLAIM_POW_DOMAIN, CLAIM_SIGNATURE_DOMAIN, DEFAULT_CLAIM_TTL_SECONDS,
    ED25519_SIGNATURE_LEN, MAX_CLAIM_RECORD_BYTES, MAX_CLAIM_TS_SKEW_SECONDS, MAX_NICKNAME_LEN,
    MAX_VACATE_RECORD_BYTES, MIN_NICKNAME_LEN, MIN_VACATE_TTL_SECONDS, NICKNAME_REGISTRY_TOPIC,
    NICKNAME_SCHEMA_VERSION, POW_LEADING_ZERO_BITS, REVISION_HARD_CAP, REVISION_SOFT_CAP,
    STALE_REPLAY_REJECT_SECONDS, VACATE_SIGNATURE_DOMAIN,
};

use consts::{
    KEY_ACCOUNT_PUBLIC_KEY, KEY_AVATAR_SHA256, KEY_CLAIM_TS, KEY_DISPLAY_NAME, KEY_NICKNAME,
    KEY_PEER_ID, KEY_POW_NONCE, KEY_RECOVERY_PUBKEY_RESERVED, KEY_REVISION, KEY_SCHEMA_VERSION,
    KEY_SIGNATURE, KEY_VALID_UNTIL, VKEY_ACCOUNT_PUBLIC_KEY, VKEY_NICKNAME, VKEY_PEER_ID,
    VKEY_REVISION, VKEY_SCHEMA_VERSION, VKEY_SIGNATURE, VKEY_VACATE_TS,
};

/// Typed outcome of nickname lookup / validation. The FFI layer translates
/// these to `CABI_NICK_*` codes. `security-crypto-engineer` approved this
/// shape in design §13.C with the clarification that both unknown-map-key
/// and reserved-key-10 cases surface as [`NickLookupErr::SchemaReject`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NickLookupErr {
    /// No record under this key (or query completed without a record).
    NotFound,
    /// Ed25519 signature check failed, or domain separator mismatch.
    BadSignature,
    /// PoW check failed (leading-zero bits < 22), or length-prefix did
    /// not match the declared field lengths.
    BadPoW,
    /// Claim is outside the accepted window: `claim_ts` is either more
    /// than ±120 s from observer clock, or more than 24 h in the past
    /// (stale-replay reject).
    StaleClaim,
    /// Schema reject: unknown / missing CBOR map key, wrong schema
    /// version, reserved-key-10 present, non-canonical encoding,
    /// charset violation on the record-carried nickname, or oversize.
    SchemaReject,
    /// DHT query timed out before finding a record.
    NetworkTimeout,
    /// Invalid caller input (nickname fails charset / size before it even
    /// gets near the network).
    InvalidInput,
    /// Nickname already taken by a different peer — emitted on the claim
    /// path when a pre-existing claim is found for the requested name.
    Taken,
}

/// A validated, signed nickname claim. Fields are public so Rust callers
/// can introspect; across the FFI boundary only the `peer_id` bytes and a
/// typed error code cross the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NickClaim {
    pub schema_version: u64,
    pub nickname: String,
    pub peer_id: PeerId,
    pub display_name: String,
    pub avatar_sha256: Option<[u8; 32]>,
    pub claim_ts: u64,
    pub valid_until: u64,
    pub revision: u32,
    pub pow_nonce: Option<u64>,
    pub signature: Vec<u8>,
    pub account_public_key_protobuf: Vec<u8>,
}

/// Signed vacate tombstone. Publishing this with a `revision` strictly
/// greater than the last-seen claim revision clears the local binding and
/// releases the name after `MIN_VACATE_TTL_SECONDS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NickVacate {
    pub schema_version: u64,
    pub nickname: String,
    pub peer_id: PeerId,
    pub vacate_ts: u64,
    pub revision: u32,
    pub signature: Vec<u8>,
    pub account_public_key_protobuf: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Charset
// ---------------------------------------------------------------------------

/// Latin-only charset for v0.0.7: `^[a-z0-9_-]{3,32}$`. Rejects uppercase,
/// non-ASCII (including Cyrillic homographs), and any byte outside the
/// explicit allow-list. Cyrillic / i18n arrives later behind a charset-
/// policy version bump; see design §10 (Unicode homograph attacks).
pub fn validate_nickname_charset(value: &str) -> std::result::Result<(), NickLookupErr> {
    let len = value.len();
    if !(MIN_NICKNAME_LEN..=MAX_NICKNAME_LEN).contains(&len) {
        return Err(NickLookupErr::InvalidInput);
    }
    for &byte in value.as_bytes() {
        let ok = matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-');
        if !ok {
            return Err(NickLookupErr::InvalidInput);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DHT key derivation
// ---------------------------------------------------------------------------

/// `SHA-256(CLAIM_DHT_KEY_PREFIX || utf8(nickname))`. Callers should have
/// already passed the nickname through [`validate_nickname_charset`] —
/// this function does not re-validate and would happily hash an invalid
/// string if asked, which is the correct low-level contract.
pub fn claim_dht_key(nickname: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(CLAIM_DHT_KEY_PREFIX);
    hasher.update(nickname.as_bytes());
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// PoW (22-bit leading-zero SHA-256 with length-prefixed inputs)
// ---------------------------------------------------------------------------

/// Count leading zero bits in a byte slice, MSB-first.
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for &b in bytes {
        if b == 0 {
            count += 8;
            continue;
        }
        count += b.leading_zeros();
        break;
    }
    count
}

/// Recompute the PoW hash over the three length-prefixed inputs. Length
/// prefixes are **load-bearing** — without them an attacker can rearrange
/// byte boundaries between `peer_id` and `nickname` and win the grind
/// once for arbitrarily many `(peer_id_prefix, nickname_suffix)` pairs
/// (design §4, crypto review non-negotiable item from §13 §(D)(n)).
fn pow_hash(peer_id_bytes: &[u8], nickname: &str, pow_nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CLAIM_POW_DOMAIN);
    hasher.update((peer_id_bytes.len() as u32).to_be_bytes());
    hasher.update(peer_id_bytes);
    hasher.update((nickname.len() as u32).to_be_bytes());
    hasher.update(nickname.as_bytes());
    hasher.update(pow_nonce.to_be_bytes());
    hasher.finalize().into()
}

/// Verify that `pow_nonce` meets the configured difficulty for the
/// `(peer_id, nickname)` pair. Called by `validate_claim` **before** any
/// CBOR-field parsing (verification-before-parse discipline).
pub fn verify_pow(peer_id_bytes: &[u8], nickname: &str, pow_nonce: u64) -> bool {
    let digest = pow_hash(peer_id_bytes, nickname, pow_nonce);
    leading_zero_bits(&digest) >= POW_LEADING_ZERO_BITS
}

/// Grind a PoW nonce meeting the configured difficulty. Median ~1 s on a
/// modern laptop, ~8-15 s on a 2020-era Android. Paid once per claim.
///
/// This is a blocking computation; callers that run it from async code
/// should wrap it in `tokio::task::spawn_blocking`. The FFI layer already
/// runs on a worker thread via `block_on`, so direct use there is fine.
pub fn grind_pow_nonce(peer_id_bytes: &[u8], nickname: &str) -> u64 {
    let mut nonce: u64 = 0;
    loop {
        if verify_pow(peer_id_bytes, nickname, nonce) {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

// ---------------------------------------------------------------------------
// Canonical CBOR (integer-keyed map, sorted ascending)
// ---------------------------------------------------------------------------

fn int_key(key: i128) -> Value {
    Value::Integer(Integer::try_from(key).expect("small positive keys fit in ciborium Integer"))
}

fn encode_canonical(entries: &[(Value, Value)]) -> Result<Vec<u8>> {
    let mut sorted: Vec<(Value, Value)> = entries.to_vec();
    sorted.sort_by(|a, b| {
        let ak = match &a.0 {
            Value::Integer(i) => i128::from(*i),
            _ => i128::MAX,
        };
        let bk = match &b.0 {
            Value::Integer(i) => i128::from(*i),
            _ => i128::MAX,
        };
        ak.cmp(&bk)
    });
    let value = Value::Map(sorted);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out)
        .map_err(|err| anyhow!("failed to encode canonical CBOR: {err}"))?;
    Ok(out)
}

fn expect_bytes(value: Value, field: &str) -> std::result::Result<Vec<u8>, NickLookupErr> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => {
            tracing::warn!(target: "nickname", field, "expected bytes");
            Err(NickLookupErr::SchemaReject)
        }
    }
}

fn expect_text(value: Value, field: &str) -> std::result::Result<String, NickLookupErr> {
    match value {
        Value::Text(s) => Ok(s),
        _ => {
            tracing::warn!(target: "nickname", field, "expected text");
            Err(NickLookupErr::SchemaReject)
        }
    }
}

fn expect_u64(value: Value, field: &str) -> std::result::Result<u64, NickLookupErr> {
    match value {
        Value::Integer(i) => {
            let as_i128 = i128::from(i);
            if as_i128 < 0 {
                tracing::warn!(target: "nickname", field, "negative integer");
                return Err(NickLookupErr::SchemaReject);
            }
            u64::try_from(as_i128).map_err(|_| {
                tracing::warn!(target: "nickname", field, "u64 overflow");
                NickLookupErr::SchemaReject
            })
        }
        _ => {
            tracing::warn!(target: "nickname", field, "expected integer");
            Err(NickLookupErr::SchemaReject)
        }
    }
}

// ---------------------------------------------------------------------------
// Claim — build + validate
// ---------------------------------------------------------------------------

/// Build a signed + PoW'd `NickClaim` as canonical CBOR bytes.
///
/// `claim_ts` is the self-asserted claim timestamp in unix seconds (used
/// for stale-replay reject; NOT for tiebreak). `valid_until` defaults to
/// `claim_ts + DEFAULT_CLAIM_TTL_SECONDS` when the supplied value is 0.
/// `revision` is monotonic per-owner — the caller is responsible for
/// incrementing it on re-publish.
#[allow(clippy::too_many_arguments)]
pub fn build_claim(
    profile: &IdentityProfile,
    peer_id: &PeerId,
    nickname: &str,
    display_name: &str,
    avatar_sha256: Option<&[u8; 32]>,
    claim_ts_unix: u64,
    valid_until_unix: u64,
    revision: u32,
) -> Result<Vec<u8>> {
    validate_nickname_charset(nickname).map_err(|_| anyhow!("nickname charset violation"))?;
    if display_name.trim().is_empty() {
        return Err(anyhow!("display_name is empty"));
    }
    if display_name.chars().count() > 40 {
        return Err(anyhow!("display_name exceeds 40 chars"));
    }
    if display_name.chars().any(|c| c.is_control()) {
        return Err(anyhow!("display_name contains control characters"));
    }
    if revision >= REVISION_SOFT_CAP {
        return Err(anyhow!(
            "revision {} exceeds soft cap {} — attestation path not implemented in TD-15",
            revision,
            REVISION_SOFT_CAP
        ));
    }

    let effective_valid_until = if valid_until_unix == 0 {
        claim_ts_unix.saturating_add(DEFAULT_CLAIM_TTL_SECONDS)
    } else {
        valid_until_unix
    };
    if effective_valid_until <= claim_ts_unix {
        return Err(anyhow!(
            "valid_until must be strictly greater than claim_ts"
        ));
    }

    let account_keypair = keypair_from_seed(&profile.account_seed)?;
    let account_public_key_pb = account_keypair.public().encode_protobuf();
    let peer_id_bytes = peer_id.to_bytes();

    // Grind PoW first. Order matters only for readability — PoW covers the
    // raw (peer_id, nickname) pair; it is independent of the full CBOR body
    // and the signature.
    let pow_nonce = grind_pow_nonce(&peer_id_bytes, nickname);

    let unsigned_map = build_claim_map(
        NICKNAME_SCHEMA_VERSION,
        nickname,
        &peer_id_bytes,
        display_name,
        avatar_sha256,
        claim_ts_unix,
        effective_valid_until,
        revision,
        Some(pow_nonce),
        &account_public_key_pb,
        None,
    );
    let unsigned_bytes = encode_canonical(&unsigned_map)?;

    let mut to_sign = Vec::with_capacity(CLAIM_SIGNATURE_DOMAIN.len() + unsigned_bytes.len());
    to_sign.extend_from_slice(CLAIM_SIGNATURE_DOMAIN);
    to_sign.extend_from_slice(&unsigned_bytes);

    let signature = account_keypair
        .sign(&to_sign)
        .context("failed to sign nickname claim")?;
    if signature.len() != ED25519_SIGNATURE_LEN {
        return Err(anyhow!(
            "unexpected signature length {} (want {})",
            signature.len(),
            ED25519_SIGNATURE_LEN
        ));
    }

    let signed_map = build_claim_map(
        NICKNAME_SCHEMA_VERSION,
        nickname,
        &peer_id_bytes,
        display_name,
        avatar_sha256,
        claim_ts_unix,
        effective_valid_until,
        revision,
        Some(pow_nonce),
        &account_public_key_pb,
        Some(&signature),
    );
    encode_canonical(&signed_map)
}

#[allow(clippy::too_many_arguments)]
fn build_claim_map(
    schema_version: u64,
    nickname: &str,
    peer_id_bytes: &[u8],
    display_name: &str,
    avatar_sha256: Option<&[u8; 32]>,
    claim_ts: u64,
    valid_until: u64,
    revision: u32,
    pow_nonce: Option<u64>,
    account_public_key_pb: &[u8],
    signature: Option<&[u8]>,
) -> Vec<(Value, Value)> {
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(11);
    entries.push((
        int_key(KEY_SCHEMA_VERSION),
        Value::Integer(Integer::from(schema_version)),
    ));
    entries.push((int_key(KEY_NICKNAME), Value::Text(nickname.to_string())));
    entries.push((int_key(KEY_PEER_ID), Value::Bytes(peer_id_bytes.to_vec())));
    entries.push((
        int_key(KEY_DISPLAY_NAME),
        Value::Text(display_name.to_string()),
    ));
    if let Some(hash) = avatar_sha256 {
        entries.push((int_key(KEY_AVATAR_SHA256), Value::Bytes(hash.to_vec())));
    }
    entries.push((
        int_key(KEY_CLAIM_TS),
        Value::Integer(Integer::from(claim_ts)),
    ));
    entries.push((
        int_key(KEY_VALID_UNTIL),
        Value::Integer(Integer::from(valid_until)),
    ));
    entries.push((
        int_key(KEY_REVISION),
        Value::Integer(Integer::from(revision)),
    ));
    if let Some(sig) = signature {
        entries.push((int_key(KEY_SIGNATURE), Value::Bytes(sig.to_vec())));
    }
    if let Some(nonce) = pow_nonce {
        entries.push((int_key(KEY_POW_NONCE), Value::Integer(Integer::from(nonce))));
    }
    entries.push((
        int_key(KEY_ACCOUNT_PUBLIC_KEY),
        Value::Bytes(account_public_key_pb.to_vec()),
    ));
    entries
}

/// Validate + parse a signed + PoW'd claim. This is the
/// **verification-before-parse** gate: size cap, CBOR decode, charset,
/// reserved-key-10 reject, unknown-key reject, PoW check, timestamp
/// skew + stale-replay, then signature.
///
/// `observer_now_unix` is the validator's current wall-clock second. Pass
/// `u64::MAX` to disable skew checks (test/debug only).
pub fn validate_claim(
    encoded: &[u8],
    observer_now_unix: u64,
) -> std::result::Result<NickClaim, NickLookupErr> {
    if encoded.len() > MAX_CLAIM_RECORD_BYTES {
        tracing::warn!(
            target: "nickname",
            len = encoded.len(),
            cap = MAX_CLAIM_RECORD_BYTES,
            "claim exceeds max size"
        );
        return Err(NickLookupErr::SchemaReject);
    }

    let value: Value = ciborium::de::from_reader(encoded).map_err(|err| {
        tracing::warn!(target: "nickname", %err, "claim CBOR decode failed");
        NickLookupErr::SchemaReject
    })?;
    let map = match value {
        Value::Map(entries) => entries,
        _ => return Err(NickLookupErr::SchemaReject),
    };

    let mut schema_version: Option<u64> = None;
    let mut nickname: Option<String> = None;
    let mut peer_id_bytes: Option<Vec<u8>> = None;
    let mut display_name: Option<String> = None;
    let mut avatar_sha256: Option<[u8; 32]> = None;
    let mut claim_ts: Option<u64> = None;
    let mut valid_until: Option<u64> = None;
    let mut revision: Option<u32> = None;
    let mut signature: Option<Vec<u8>> = None;
    let mut pow_nonce: Option<u64> = None;
    let mut account_public_key_pb: Option<Vec<u8>> = None;

    for (key_v, value_v) in map.into_iter() {
        let key = match key_v {
            Value::Integer(i) => i128::from(i),
            _ => {
                tracing::warn!(target: "nickname", "non-integer map key");
                return Err(NickLookupErr::SchemaReject);
            }
        };
        match key {
            KEY_SCHEMA_VERSION => schema_version = Some(expect_u64(value_v, "schema_version")?),
            KEY_NICKNAME => nickname = Some(expect_text(value_v, "nickname")?),
            KEY_PEER_ID => peer_id_bytes = Some(expect_bytes(value_v, "peer_id")?),
            KEY_DISPLAY_NAME => display_name = Some(expect_text(value_v, "display_name")?),
            KEY_AVATAR_SHA256 => {
                let bytes = expect_bytes(value_v, "avatar_sha256")?;
                if bytes.len() != 32 {
                    tracing::warn!(target: "nickname", "avatar_sha256 wrong length");
                    return Err(NickLookupErr::SchemaReject);
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                avatar_sha256 = Some(arr);
            }
            KEY_CLAIM_TS => claim_ts = Some(expect_u64(value_v, "claim_ts")?),
            KEY_VALID_UNTIL => valid_until = Some(expect_u64(value_v, "valid_until")?),
            KEY_REVISION => {
                let r = expect_u64(value_v, "revision")?;
                if r > REVISION_HARD_CAP as u64 {
                    return Err(NickLookupErr::SchemaReject);
                }
                revision = Some(r as u32);
            }
            KEY_SIGNATURE => {
                let bytes = expect_bytes(value_v, "signature")?;
                if bytes.len() != ED25519_SIGNATURE_LEN {
                    return Err(NickLookupErr::SchemaReject);
                }
                signature = Some(bytes);
            }
            KEY_POW_NONCE => pow_nonce = Some(expect_u64(value_v, "pow_nonce")?),
            KEY_RECOVERY_PUBKEY_RESERVED => {
                tracing::warn!(
                    target: "nickname",
                    "reserved key 10 (recovery_pubkey) present — TD-15 rejects (TD-17 forward compat)"
                );
                return Err(NickLookupErr::SchemaReject);
            }
            KEY_ACCOUNT_PUBLIC_KEY => {
                account_public_key_pb = Some(expect_bytes(value_v, "account_public_key")?);
            }
            other => {
                tracing::warn!(target: "nickname", other, "unknown CBOR map key");
                return Err(NickLookupErr::SchemaReject);
            }
        }
    }

    let schema_version = schema_version.ok_or(NickLookupErr::SchemaReject)?;
    if schema_version != NICKNAME_SCHEMA_VERSION {
        tracing::warn!(target: "nickname", schema_version, "unsupported schema");
        return Err(NickLookupErr::SchemaReject);
    }
    let nickname = nickname.ok_or(NickLookupErr::SchemaReject)?;
    let peer_id_bytes = peer_id_bytes.ok_or(NickLookupErr::SchemaReject)?;
    let display_name = display_name.ok_or(NickLookupErr::SchemaReject)?;
    let claim_ts = claim_ts.ok_or(NickLookupErr::SchemaReject)?;
    let valid_until = valid_until.ok_or(NickLookupErr::SchemaReject)?;
    let revision = revision.ok_or(NickLookupErr::SchemaReject)?;
    let signature = signature.ok_or(NickLookupErr::SchemaReject)?;
    let pow_nonce = pow_nonce.ok_or(NickLookupErr::SchemaReject)?;
    let account_public_key_pb = account_public_key_pb.ok_or(NickLookupErr::SchemaReject)?;

    // Charset re-check: the wire-carried nickname must pass the same
    // rules as a caller-provided one. Stops an attacker from smuggling
    // uppercase / non-ASCII past the resolver.
    validate_nickname_charset(&nickname).map_err(|_| NickLookupErr::SchemaReject)?;

    if valid_until <= claim_ts {
        return Err(NickLookupErr::SchemaReject);
    }
    if revision >= REVISION_SOFT_CAP {
        return Err(NickLookupErr::SchemaReject);
    }

    // Display-name constraints.
    if display_name.trim().is_empty()
        || display_name.chars().count() > 40
        || display_name.chars().any(|c| c.is_control())
    {
        return Err(NickLookupErr::SchemaReject);
    }

    // Verification-before-parse PoW. We already have the declared
    // nickname + peer_id bytes; PoW covers exactly those two fields plus
    // the nonce. Running this before the expensive signature check keeps
    // CPU-DoS-via-bad-PoW cheap to drop.
    if !verify_pow(&peer_id_bytes, &nickname, pow_nonce) {
        return Err(NickLookupErr::BadPoW);
    }

    // Clock skew / stale-replay checks. `observer_now_unix == u64::MAX`
    // is the "disable" sentinel used by tests that want to bypass the
    // wall-clock gate.
    if observer_now_unix != u64::MAX {
        if claim_ts > observer_now_unix.saturating_add(MAX_CLAIM_TS_SKEW_SECONDS) {
            return Err(NickLookupErr::StaleClaim);
        }
        if observer_now_unix > claim_ts.saturating_add(STALE_REPLAY_REJECT_SECONDS) {
            return Err(NickLookupErr::StaleClaim);
        }
    }

    // Reconstruct the unsigned canonical bytes and verify the signature.
    let unsigned_map = build_claim_map(
        schema_version,
        &nickname,
        &peer_id_bytes,
        &display_name,
        avatar_sha256.as_ref(),
        claim_ts,
        valid_until,
        revision,
        Some(pow_nonce),
        &account_public_key_pb,
        None,
    );
    let unsigned_bytes = encode_canonical(&unsigned_map).map_err(|err| {
        tracing::warn!(target: "nickname", %err, "failed to re-encode unsigned claim");
        NickLookupErr::SchemaReject
    })?;

    // Canonical round-trip: re-encode the fully signed map and require
    // byte equality with the input. Catches any deviation from canonical
    // CBOR (packed, indefinite-length, unsorted keys).
    let signed_map = build_claim_map(
        schema_version,
        &nickname,
        &peer_id_bytes,
        &display_name,
        avatar_sha256.as_ref(),
        claim_ts,
        valid_until,
        revision,
        Some(pow_nonce),
        &account_public_key_pb,
        Some(&signature),
    );
    let canonical_signed =
        encode_canonical(&signed_map).map_err(|_| NickLookupErr::SchemaReject)?;
    if canonical_signed.as_slice() != encoded {
        tracing::warn!(target: "nickname", "claim failed canonical CBOR round-trip check");
        return Err(NickLookupErr::SchemaReject);
    }

    let mut to_verify = Vec::with_capacity(CLAIM_SIGNATURE_DOMAIN.len() + unsigned_bytes.len());
    to_verify.extend_from_slice(CLAIM_SIGNATURE_DOMAIN);
    to_verify.extend_from_slice(&unsigned_bytes);

    let account_public_key = identity::PublicKey::try_decode_protobuf(&account_public_key_pb)
        .map_err(|_| NickLookupErr::SchemaReject)?;
    if !account_public_key.verify(&to_verify, &signature) {
        return Err(NickLookupErr::BadSignature);
    }

    let peer_id = PeerId::from_bytes(&peer_id_bytes).map_err(|_| NickLookupErr::SchemaReject)?;

    Ok(NickClaim {
        schema_version,
        nickname,
        peer_id,
        display_name,
        avatar_sha256,
        claim_ts,
        valid_until,
        revision,
        pow_nonce: Some(pow_nonce),
        signature,
        account_public_key_protobuf: account_public_key_pb,
    })
}

// ---------------------------------------------------------------------------
// Vacate — build + validate
// ---------------------------------------------------------------------------

fn build_vacate_map(
    schema_version: u64,
    nickname: &str,
    peer_id_bytes: &[u8],
    vacate_ts: u64,
    revision: u32,
    account_public_key_pb: &[u8],
    signature: Option<&[u8]>,
) -> Vec<(Value, Value)> {
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(7);
    entries.push((
        int_key(VKEY_SCHEMA_VERSION),
        Value::Integer(Integer::from(schema_version)),
    ));
    entries.push((int_key(VKEY_NICKNAME), Value::Text(nickname.to_string())));
    entries.push((int_key(VKEY_PEER_ID), Value::Bytes(peer_id_bytes.to_vec())));
    entries.push((
        int_key(VKEY_VACATE_TS),
        Value::Integer(Integer::from(vacate_ts)),
    ));
    entries.push((
        int_key(VKEY_REVISION),
        Value::Integer(Integer::from(revision)),
    ));
    if let Some(sig) = signature {
        entries.push((int_key(VKEY_SIGNATURE), Value::Bytes(sig.to_vec())));
    }
    entries.push((
        int_key(VKEY_ACCOUNT_PUBLIC_KEY),
        Value::Bytes(account_public_key_pb.to_vec()),
    ));
    entries
}

/// Build a signed vacate tombstone. Caller passes the revision strictly
/// greater than the last-seen claim revision (the core does not track
/// per-nickname revision state in the TD-15 MVP — the caller is
/// responsible).
pub fn build_vacate(
    profile: &IdentityProfile,
    peer_id: &PeerId,
    nickname: &str,
    vacate_ts_unix: u64,
    revision: u32,
) -> Result<Vec<u8>> {
    validate_nickname_charset(nickname).map_err(|_| anyhow!("nickname charset violation"))?;
    if revision >= REVISION_SOFT_CAP {
        return Err(anyhow!("revision exceeds soft cap"));
    }
    let account_keypair = keypair_from_seed(&profile.account_seed)?;
    let account_public_key_pb = account_keypair.public().encode_protobuf();
    let peer_id_bytes = peer_id.to_bytes();

    let unsigned_map = build_vacate_map(
        NICKNAME_SCHEMA_VERSION,
        nickname,
        &peer_id_bytes,
        vacate_ts_unix,
        revision,
        &account_public_key_pb,
        None,
    );
    let unsigned_bytes = encode_canonical(&unsigned_map)?;

    let mut to_sign = Vec::with_capacity(VACATE_SIGNATURE_DOMAIN.len() + unsigned_bytes.len());
    to_sign.extend_from_slice(VACATE_SIGNATURE_DOMAIN);
    to_sign.extend_from_slice(&unsigned_bytes);
    let signature = account_keypair
        .sign(&to_sign)
        .context("failed to sign nickname vacate")?;
    if signature.len() != ED25519_SIGNATURE_LEN {
        return Err(anyhow!("unexpected vacate signature length"));
    }
    let signed_map = build_vacate_map(
        NICKNAME_SCHEMA_VERSION,
        nickname,
        &peer_id_bytes,
        vacate_ts_unix,
        revision,
        &account_public_key_pb,
        Some(&signature),
    );
    encode_canonical(&signed_map)
}

/// Validate a vacate tombstone. Same verification-before-parse discipline
/// as [`validate_claim`], minus the PoW (vacate is not rate-limited by
/// PoW — the owner already paid PoW on the matching claim) and minus the
/// skew windows (a future-dated vacate is harmless; a stale vacate is
/// rejected by the revision-monotonic rule at the caller).
pub fn validate_vacate(encoded: &[u8]) -> std::result::Result<NickVacate, NickLookupErr> {
    if encoded.len() > MAX_VACATE_RECORD_BYTES {
        return Err(NickLookupErr::SchemaReject);
    }

    let value: Value =
        ciborium::de::from_reader(encoded).map_err(|_| NickLookupErr::SchemaReject)?;
    let map = match value {
        Value::Map(entries) => entries,
        _ => return Err(NickLookupErr::SchemaReject),
    };

    let mut schema_version: Option<u64> = None;
    let mut nickname: Option<String> = None;
    let mut peer_id_bytes: Option<Vec<u8>> = None;
    let mut vacate_ts: Option<u64> = None;
    let mut revision: Option<u32> = None;
    let mut signature: Option<Vec<u8>> = None;
    let mut account_public_key_pb: Option<Vec<u8>> = None;

    for (key_v, value_v) in map.into_iter() {
        let key = match key_v {
            Value::Integer(i) => i128::from(i),
            _ => return Err(NickLookupErr::SchemaReject),
        };
        match key {
            VKEY_SCHEMA_VERSION => schema_version = Some(expect_u64(value_v, "schema_version")?),
            VKEY_NICKNAME => nickname = Some(expect_text(value_v, "nickname")?),
            VKEY_PEER_ID => peer_id_bytes = Some(expect_bytes(value_v, "peer_id")?),
            VKEY_VACATE_TS => vacate_ts = Some(expect_u64(value_v, "vacate_ts")?),
            VKEY_REVISION => {
                let r = expect_u64(value_v, "revision")?;
                if r > REVISION_HARD_CAP as u64 {
                    return Err(NickLookupErr::SchemaReject);
                }
                revision = Some(r as u32);
            }
            VKEY_SIGNATURE => {
                let bytes = expect_bytes(value_v, "signature")?;
                if bytes.len() != ED25519_SIGNATURE_LEN {
                    return Err(NickLookupErr::SchemaReject);
                }
                signature = Some(bytes);
            }
            VKEY_ACCOUNT_PUBLIC_KEY => {
                account_public_key_pb = Some(expect_bytes(value_v, "account_public_key")?);
            }
            KEY_RECOVERY_PUBKEY_RESERVED => {
                // TD-17 forward-compat reject also applies to vacate
                // records so an attacker cannot use the reserved slot to
                // smuggle state into a tombstone some future verifier
                // might render.
                return Err(NickLookupErr::SchemaReject);
            }
            _ => return Err(NickLookupErr::SchemaReject),
        }
    }

    let schema_version = schema_version.ok_or(NickLookupErr::SchemaReject)?;
    if schema_version != NICKNAME_SCHEMA_VERSION {
        return Err(NickLookupErr::SchemaReject);
    }
    let nickname = nickname.ok_or(NickLookupErr::SchemaReject)?;
    let peer_id_bytes = peer_id_bytes.ok_or(NickLookupErr::SchemaReject)?;
    let vacate_ts = vacate_ts.ok_or(NickLookupErr::SchemaReject)?;
    let revision = revision.ok_or(NickLookupErr::SchemaReject)?;
    let signature = signature.ok_or(NickLookupErr::SchemaReject)?;
    let account_public_key_pb = account_public_key_pb.ok_or(NickLookupErr::SchemaReject)?;

    validate_nickname_charset(&nickname).map_err(|_| NickLookupErr::SchemaReject)?;
    if revision >= REVISION_SOFT_CAP {
        return Err(NickLookupErr::SchemaReject);
    }

    let unsigned_map = build_vacate_map(
        schema_version,
        &nickname,
        &peer_id_bytes,
        vacate_ts,
        revision,
        &account_public_key_pb,
        None,
    );
    let unsigned_bytes =
        encode_canonical(&unsigned_map).map_err(|_| NickLookupErr::SchemaReject)?;

    let signed_map = build_vacate_map(
        schema_version,
        &nickname,
        &peer_id_bytes,
        vacate_ts,
        revision,
        &account_public_key_pb,
        Some(&signature),
    );
    let canonical_signed =
        encode_canonical(&signed_map).map_err(|_| NickLookupErr::SchemaReject)?;
    if canonical_signed.as_slice() != encoded {
        return Err(NickLookupErr::SchemaReject);
    }

    let mut to_verify = Vec::with_capacity(VACATE_SIGNATURE_DOMAIN.len() + unsigned_bytes.len());
    to_verify.extend_from_slice(VACATE_SIGNATURE_DOMAIN);
    to_verify.extend_from_slice(&unsigned_bytes);

    let account_public_key = identity::PublicKey::try_decode_protobuf(&account_public_key_pb)
        .map_err(|_| NickLookupErr::SchemaReject)?;
    if !account_public_key.verify(&to_verify, &signature) {
        return Err(NickLookupErr::BadSignature);
    }

    let peer_id = PeerId::from_bytes(&peer_id_bytes).map_err(|_| NickLookupErr::SchemaReject)?;
    Ok(NickVacate {
        schema_version,
        nickname,
        peer_id,
        vacate_ts,
        revision,
        signature,
        account_public_key_protobuf: account_public_key_pb,
    })
}

// ---------------------------------------------------------------------------
// Tiebreak (design §5)
// ---------------------------------------------------------------------------

/// Deterministic winner between two competing claims for the same
/// nickname. The observer's own first-seen timestamp is the primary key
/// (adversary-resistant vs self-asserted `claim_ts`); `sha256(peer_id)`
/// is the secondary key.
///
/// Returns `true` if `a` wins, `false` if `b` wins.
pub fn tiebreak_winner(
    a_first_seen_ts: u64,
    a_peer_id: &PeerId,
    b_first_seen_ts: u64,
    b_peer_id: &PeerId,
) -> bool {
    match a_first_seen_ts.cmp(&b_first_seen_ts) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => {
            let a_hash = Sha256::digest(a_peer_id.to_bytes());
            let b_hash = Sha256::digest(b_peer_id.to_bytes());
            a_hash.as_slice() < b_hash.as_slice()
        }
    }
}

/// TD-37 Layer-A verdict: given an already-validated pre-existing holder
/// of a nickname (from DHT or local gossip observation) and our own
/// account public key, return `true` if we should short-circuit with
/// `CABI_NICK_TAKEN`. Returns `false` when the pre-existing holder is
/// ourselves (renewal proceeds).
///
/// Pure function, extracted so the pre-check logic can be unit-tested
/// without spinning up a full `PeerManager` + DHT.
pub fn layer_a_should_short_circuit(existing: &NickClaim, my_account_public_key_pb: &[u8]) -> bool {
    existing.account_public_key_protobuf != my_account_public_key_pb
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2ee::load_or_create_profile;
    use tempfile::TempDir;

    fn fresh_profile() -> (IdentityProfile, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("profile.json");
        let profile = load_or_create_profile(&path).expect("profile");
        (profile, dir)
    }

    fn derive_peer_id(profile: &IdentityProfile) -> PeerId {
        let kp = keypair_from_seed(&profile.libp2p_seed).expect("libp2p keypair");
        PeerId::from(kp.public())
    }

    // -----------------------------------------------------------------
    // Charset
    // -----------------------------------------------------------------

    #[test]
    fn td15_charset_accepts_valid_nicknames() {
        assert!(validate_nickname_charset("alice").is_ok());
        assert!(validate_nickname_charset("bob_99").is_ok());
        assert!(validate_nickname_charset("a-b").is_ok());
        assert!(validate_nickname_charset("abc").is_ok()); // exactly 3
        assert!(validate_nickname_charset(&"a".repeat(32)).is_ok()); // exactly 32
    }

    #[test]
    fn td15_charset_rejects_uppercase() {
        assert_eq!(
            validate_nickname_charset("Alice").unwrap_err(),
            NickLookupErr::InvalidInput
        );
    }

    #[test]
    fn td15_charset_rejects_cyrillic() {
        // Cyrillic lowercase а (U+0430), not Latin a — homograph attack.
        assert_eq!(
            validate_nickname_charset("аlice").unwrap_err(),
            NickLookupErr::InvalidInput
        );
    }

    #[test]
    fn td15_charset_rejects_too_short_and_too_long() {
        assert_eq!(
            validate_nickname_charset("ab").unwrap_err(),
            NickLookupErr::InvalidInput
        );
        let long = "a".repeat(33);
        assert_eq!(
            validate_nickname_charset(&long).unwrap_err(),
            NickLookupErr::InvalidInput
        );
    }

    #[test]
    fn td15_charset_rejects_illegal_chars() {
        for bad in ["alice!", "al ice", "al.ice", "al/ice", "al@ice"] {
            assert_eq!(
                validate_nickname_charset(bad).unwrap_err(),
                NickLookupErr::InvalidInput,
                "expected reject for {bad}"
            );
        }
    }

    // -----------------------------------------------------------------
    // Domain separators + keys
    // -----------------------------------------------------------------

    #[test]
    fn td15_domain_separators_are_byte_literals_and_distinct() {
        // Freeze the exact bytes so a regression rewriting via format!
        // would wedge here. Also verify the trailing \x00 and
        // pairwise-non-prefix property: no separator is a prefix of
        // another.
        assert_eq!(CLAIM_SIGNATURE_DOMAIN, b"fidonext-nick-claim-v1\x00");
        assert_eq!(CLAIM_POW_DOMAIN, b"fidonext-nick-pow-v1\x00");
        assert_eq!(VACATE_SIGNATURE_DOMAIN, b"fidonext-nick-vacate-v1\x00");
        let all: &[&[u8]] = &[
            CLAIM_SIGNATURE_DOMAIN,
            CLAIM_POW_DOMAIN,
            VACATE_SIGNATURE_DOMAIN,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert!(
                    !a.starts_with(b) && !b.starts_with(a),
                    "domain separators must not be prefix-related: {a:?} vs {b:?}"
                );
            }
        }
    }

    #[test]
    fn td15_claim_dht_key_is_stable_and_32_bytes() {
        let a = claim_dht_key("alice");
        let b = claim_dht_key("alice");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        assert_ne!(a, claim_dht_key("bob"));
    }

    // -----------------------------------------------------------------
    // PoW
    // -----------------------------------------------------------------

    #[test]
    fn td15_pow_grind_meets_difficulty() {
        // Small peer_id / nickname for fast grind in test.
        let peer_id = vec![0u8; 8];
        let nickname = "alice";
        let nonce = grind_pow_nonce(&peer_id, nickname);
        assert!(verify_pow(&peer_id, nickname, nonce));
        // Arbitrary bogus nonce is (overwhelmingly likely to be) wrong.
        assert!(!verify_pow(&peer_id, nickname, nonce.wrapping_add(1)));
    }

    #[test]
    fn td15_pow_length_prefix_rejects_boundary_manipulation() {
        // CRYPTO NON-NEGOTIABLE (design §13.D.n + §9 unit-test list):
        // crafting two records (peer_id=X, nickname=Y1||Y2) and
        // (peer_id=X||Y1, nickname=Y2) where the raw concatenation of
        // (X || Y1 || Y2) is identical must NOT collide. The length
        // prefixes are what block it — remove them and both hash the
        // same bytes.
        //
        // We verify by computing the hash directly (with length prefix)
        // and confirming the two tuples land on DIFFERENT digests.
        let x = vec![0xAAu8; 4]; // "peer_id" bytes base
        let y1 = b"one";
        let y2 = b"two";
        let nonce = 0u64;

        // Tuple A: peer_id = X, nickname = Y1||Y2
        let mut peer_a = x.clone();
        let nick_a = format!(
            "{}{}",
            std::str::from_utf8(y1).unwrap(),
            std::str::from_utf8(y2).unwrap()
        );
        let _ = &mut peer_a;

        // Tuple B: peer_id = X||Y1, nickname = Y2
        let mut peer_b = x.clone();
        peer_b.extend_from_slice(y1);
        let nick_b = std::str::from_utf8(y2).unwrap();

        let h_a = pow_hash(&peer_a, &nick_a, nonce);
        let h_b = pow_hash(&peer_b, nick_b, nonce);
        assert_ne!(
            h_a, h_b,
            "length-prefix is load-bearing: boundary-shift tuples must hash differently"
        );
    }

    #[test]
    fn td15_pow_covers_domain_separator() {
        // Swapping the PoW domain separator must change the digest.
        let peer_id = vec![0u8; 4];
        let nickname = "x";
        let digest_canonical = pow_hash(&peer_id, nickname, 0);

        let mut h = Sha256::new();
        h.update(b"fidonext-different-pow-v1\x00");
        h.update((peer_id.len() as u32).to_be_bytes());
        h.update(&peer_id);
        h.update((nickname.len() as u32).to_be_bytes());
        h.update(nickname.as_bytes());
        h.update(0u64.to_be_bytes());
        let digest_foreign: [u8; 32] = h.finalize().into();
        assert_ne!(digest_canonical, digest_foreign);
    }

    // -----------------------------------------------------------------
    // Claim roundtrip + validation
    // -----------------------------------------------------------------

    #[test]
    fn td15_claim_roundtrip_validates() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let claim_ts = 1_700_000_000u64;
        let encoded = build_claim(
            &profile,
            &peer_id,
            "alice",
            "Alice Cooper",
            None,
            claim_ts,
            0, // default TTL
            1,
        )
        .expect("build claim");

        let parsed = validate_claim(&encoded, claim_ts + 5).expect("validate");
        assert_eq!(parsed.nickname, "alice");
        assert_eq!(parsed.display_name, "Alice Cooper");
        assert_eq!(parsed.peer_id, peer_id);
        assert_eq!(parsed.claim_ts, claim_ts);
        assert_eq!(parsed.valid_until, claim_ts + DEFAULT_CLAIM_TTL_SECONDS);
        assert_eq!(parsed.revision, 1);
        assert_eq!(parsed.schema_version, NICKNAME_SCHEMA_VERSION);
    }

    #[test]
    fn td15_claim_tampered_signature_bytes_rejected() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let claim_ts = 1_700_000_000u64;
        let encoded = build_claim(&profile, &peer_id, "alice", "Alice", None, claim_ts, 0, 1)
            .expect("build claim");

        // Flip the last byte (inside signature region because sig key 8
        // sorts before key 9 and 11 — but even if not at end, flipping
        // somewhere in the middle of CBOR usually corrupts canonical
        // encoding first → SchemaReject). Either BadSignature or
        // SchemaReject is acceptable; the test is "does NOT succeed".
        let mut corrupt = encoded.clone();
        let mid = corrupt.len() / 2;
        corrupt[mid] ^= 0x01;
        let err = validate_claim(&corrupt, claim_ts + 5).expect_err("must reject");
        assert!(matches!(
            err,
            NickLookupErr::BadSignature | NickLookupErr::SchemaReject | NickLookupErr::BadPoW
        ));
    }

    #[test]
    fn td15_claim_wrong_signing_seed_rejected_account_vs_libp2p() {
        // CRYPTO NON-NEGOTIABLE (design §13 item 1 + §9 unit-test list):
        // a claim built with `libp2p_seed` as the signing key must NOT
        // validate. The validator derives the verification key from the
        // embedded `account_public_key` (key 11), so any mismatch
        // between "who signed" and "what key 11 says" must reject.
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let claim_ts = 1_700_000_000u64;

        // Build a claim "by hand" that puts account_public_key (key 11)
        // correctly but signs with libp2p_seed. Mirrors the profile_record
        // test of the same name.
        let account_keypair = keypair_from_seed(&profile.account_seed).expect("acc kp");
        let libp2p_keypair = keypair_from_seed(&profile.libp2p_seed).expect("libp2p kp");
        let account_public_key_pb = account_keypair.public().encode_protobuf();
        let peer_id_bytes = peer_id.to_bytes();
        let pow_nonce = grind_pow_nonce(&peer_id_bytes, "alice");
        let unsigned_map = build_claim_map(
            NICKNAME_SCHEMA_VERSION,
            "alice",
            &peer_id_bytes,
            "Alice",
            None,
            claim_ts,
            claim_ts + DEFAULT_CLAIM_TTL_SECONDS,
            1,
            Some(pow_nonce),
            &account_public_key_pb,
            None,
        );
        let unsigned_bytes = encode_canonical(&unsigned_map).expect("encode");
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(CLAIM_SIGNATURE_DOMAIN);
        to_sign.extend_from_slice(&unsigned_bytes);
        // Wrong seed: libp2p_seed, not account_seed.
        let wrong_sig = libp2p_keypair.sign(&to_sign).expect("wrong sign");
        let signed_map = build_claim_map(
            NICKNAME_SCHEMA_VERSION,
            "alice",
            &peer_id_bytes,
            "Alice",
            None,
            claim_ts,
            claim_ts + DEFAULT_CLAIM_TTL_SECONDS,
            1,
            Some(pow_nonce),
            &account_public_key_pb,
            Some(&wrong_sig),
        );
        let encoded = encode_canonical(&signed_map).expect("encode signed");

        let err = validate_claim(&encoded, claim_ts + 5).expect_err("must reject");
        assert_eq!(err, NickLookupErr::BadSignature);
    }

    #[test]
    fn td15_claim_wrong_domain_separator_rejected() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let account_keypair = keypair_from_seed(&profile.account_seed).expect("kp");
        let account_public_key_pb = account_keypair.public().encode_protobuf();
        let peer_id_bytes = peer_id.to_bytes();
        let claim_ts = 1_700_000_000u64;
        let pow_nonce = grind_pow_nonce(&peer_id_bytes, "alice");
        let unsigned_map = build_claim_map(
            NICKNAME_SCHEMA_VERSION,
            "alice",
            &peer_id_bytes,
            "Alice",
            None,
            claim_ts,
            claim_ts + DEFAULT_CLAIM_TTL_SECONDS,
            1,
            Some(pow_nonce),
            &account_public_key_pb,
            None,
        );
        let unsigned_bytes = encode_canonical(&unsigned_map).expect("encode");
        let mut to_sign_bad = Vec::new();
        to_sign_bad.extend_from_slice(b"fidonext-nick-claim-v2\x00");
        to_sign_bad.extend_from_slice(&unsigned_bytes);
        let bad_sig = account_keypair.sign(&to_sign_bad).expect("sign");
        let signed_map = build_claim_map(
            NICKNAME_SCHEMA_VERSION,
            "alice",
            &peer_id_bytes,
            "Alice",
            None,
            claim_ts,
            claim_ts + DEFAULT_CLAIM_TTL_SECONDS,
            1,
            Some(pow_nonce),
            &account_public_key_pb,
            Some(&bad_sig),
        );
        let encoded = encode_canonical(&signed_map).expect("encode");
        let err = validate_claim(&encoded, claim_ts + 5).expect_err("must reject");
        assert_eq!(err, NickLookupErr::BadSignature);
    }

    // -----------------------------------------------------------------
    // Clock skew + stale-replay
    // -----------------------------------------------------------------

    #[test]
    fn td15_clock_skew_plus_119s_accepts_plus_121s_rejects() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let claim_ts = 1_700_000_000u64;
        let encoded =
            build_claim(&profile, &peer_id, "alice", "Alice", None, claim_ts, 0, 1).expect("build");

        // +119 s future claim vs observer_now = claim_ts - 119 → within
        // window → accept.
        let ok_observer = claim_ts - 119;
        let _ok = validate_claim(&encoded, ok_observer).expect("within skew");

        // +121 s future claim vs observer_now = claim_ts - 121 → outside
        // window → reject.
        let bad_observer = claim_ts - 121;
        let err = validate_claim(&encoded, bad_observer).expect_err("skew reject");
        assert_eq!(err, NickLookupErr::StaleClaim);
    }

    #[test]
    fn td15_stale_replay_reject_at_24h() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let claim_ts = 1_700_000_000u64;
        let encoded =
            build_claim(&profile, &peer_id, "alice", "Alice", None, claim_ts, 0, 1).expect("build");

        // Observer 24h + 1s past claim_ts → reject.
        let far_future = claim_ts + STALE_REPLAY_REJECT_SECONDS + 1;
        let err = validate_claim(&encoded, far_future).expect_err("stale replay reject");
        assert_eq!(err, NickLookupErr::StaleClaim);

        // Observer 24h - 1s past claim_ts → accept.
        let near_future = claim_ts + STALE_REPLAY_REJECT_SECONDS - 1;
        let _ok = validate_claim(&encoded, near_future).expect("within 24h");
    }

    // -----------------------------------------------------------------
    // Unknown / reserved keys
    // -----------------------------------------------------------------

    #[test]
    fn td15_reserved_key_10_recovery_pubkey_rejects() {
        // TD-17 forward-compat invariant. Crafting a claim that inserts
        // key 10 (recovery_pubkey) must be rejected by TD-15 verifiers
        // even if signed correctly.
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let account_keypair = keypair_from_seed(&profile.account_seed).expect("kp");
        let account_public_key_pb = account_keypair.public().encode_protobuf();
        let peer_id_bytes = peer_id.to_bytes();
        let claim_ts = 1_700_000_000u64;
        let pow_nonce = grind_pow_nonce(&peer_id_bytes, "alice");

        let mut entries = build_claim_map(
            NICKNAME_SCHEMA_VERSION,
            "alice",
            &peer_id_bytes,
            "Alice",
            None,
            claim_ts,
            claim_ts + DEFAULT_CLAIM_TTL_SECONDS,
            1,
            Some(pow_nonce),
            &account_public_key_pb,
            None,
        );
        // Smuggle a reserved recovery_pubkey into the unsigned map.
        entries.push((
            int_key(KEY_RECOVERY_PUBKEY_RESERVED),
            Value::Bytes(vec![0u8; 32]),
        ));
        let unsigned_bytes = encode_canonical(&entries).expect("encode");
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(CLAIM_SIGNATURE_DOMAIN);
        to_sign.extend_from_slice(&unsigned_bytes);
        let sig = account_keypair.sign(&to_sign).expect("sign");
        entries.push((int_key(KEY_SIGNATURE), Value::Bytes(sig)));
        let encoded = encode_canonical(&entries).expect("encode signed");

        let err = validate_claim(&encoded, claim_ts + 5).expect_err("must reject reserved 10");
        assert_eq!(err, NickLookupErr::SchemaReject);
    }

    #[test]
    fn td15_unknown_map_key_rejected() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let account_keypair = keypair_from_seed(&profile.account_seed).expect("kp");
        let account_public_key_pb = account_keypair.public().encode_protobuf();
        let peer_id_bytes = peer_id.to_bytes();
        let claim_ts = 1_700_000_000u64;
        let pow_nonce = grind_pow_nonce(&peer_id_bytes, "alice");

        let mut entries = build_claim_map(
            NICKNAME_SCHEMA_VERSION,
            "alice",
            &peer_id_bytes,
            "Alice",
            None,
            claim_ts,
            claim_ts + DEFAULT_CLAIM_TTL_SECONDS,
            1,
            Some(pow_nonce),
            &account_public_key_pb,
            None,
        );
        entries.push((int_key(42), Value::Text("smuggled".to_string())));
        let unsigned_bytes = encode_canonical(&entries).expect("encode");
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(CLAIM_SIGNATURE_DOMAIN);
        to_sign.extend_from_slice(&unsigned_bytes);
        let sig = account_keypair.sign(&to_sign).expect("sign");
        entries.push((int_key(KEY_SIGNATURE), Value::Bytes(sig)));
        let encoded = encode_canonical(&entries).expect("encode");

        let err = validate_claim(&encoded, claim_ts + 5).expect_err("must reject unknown");
        assert_eq!(err, NickLookupErr::SchemaReject);
    }

    // -----------------------------------------------------------------
    // Tiebreak
    // -----------------------------------------------------------------

    #[test]
    fn td15_tiebreak_first_seen_wins_and_is_deterministic() {
        let (profile_a, _tmp_a) = fresh_profile();
        let (profile_b, _tmp_b) = fresh_profile();
        let peer_a = derive_peer_id(&profile_a);
        let peer_b = derive_peer_id(&profile_b);

        // Earlier first-seen wins regardless of peer_id hash.
        let a_wins = tiebreak_winner(100, &peer_a, 200, &peer_b);
        assert!(a_wins, "earlier observer-first-seen must win");
        let b_wins = tiebreak_winner(500, &peer_a, 200, &peer_b);
        assert!(!b_wins, "later observer-first-seen must lose");

        // Same timestamp → deterministic, always same answer under repeat.
        let first = tiebreak_winner(300, &peer_a, 300, &peer_b);
        let second = tiebreak_winner(300, &peer_a, 300, &peer_b);
        assert_eq!(first, second);
        // Anti-symmetric: swapping the arguments flips the result (when
        // peer_ids differ).
        let swapped = tiebreak_winner(300, &peer_b, 300, &peer_a);
        assert_eq!(first, !swapped);
    }

    // -----------------------------------------------------------------
    // Vacate roundtrip
    // -----------------------------------------------------------------

    #[test]
    fn td15_vacate_roundtrip() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let vacate_ts = 1_700_000_500u64;
        let encoded =
            build_vacate(&profile, &peer_id, "alice", vacate_ts, 2).expect("build vacate");
        let parsed = validate_vacate(&encoded).expect("validate vacate");
        assert_eq!(parsed.nickname, "alice");
        assert_eq!(parsed.peer_id, peer_id);
        assert_eq!(parsed.vacate_ts, vacate_ts);
        assert_eq!(parsed.revision, 2);
    }

    #[test]
    fn td15_claim_resolve_release_resolve_cycle() {
        // Integration-style: the full build → validate → vacate →
        // attempt-to-use-vacate-as-claim cycle. The last step verifies
        // that a vacate is NOT accepted by the claim validator (wrong
        // domain separator + shape).
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let claim_ts = 1_700_000_000u64;

        let claim_bytes =
            build_claim(&profile, &peer_id, "alice", "Alice", None, claim_ts, 0, 1).expect("claim");
        let claim = validate_claim(&claim_bytes, claim_ts + 10).expect("validate claim");
        assert_eq!(claim.revision, 1);

        let vacate_bytes =
            build_vacate(&profile, &peer_id, "alice", claim_ts + 60, 2).expect("vacate");
        let vacate = validate_vacate(&vacate_bytes).expect("validate vacate");
        assert_eq!(vacate.revision, 2);

        // Passing vacate bytes through the claim validator must reject.
        let err = validate_claim(&vacate_bytes, claim_ts + 10).expect_err("vacate != claim");
        assert!(matches!(
            err,
            NickLookupErr::SchemaReject | NickLookupErr::BadSignature | NickLookupErr::BadPoW
        ));
    }

    // -----------------------------------------------------------------
    // Oversize + malformed
    // -----------------------------------------------------------------

    #[test]
    fn td15_claim_oversize_rejected_before_parse() {
        let bogus = vec![0xBFu8; MAX_CLAIM_RECORD_BYTES + 1];
        let err = validate_claim(&bogus, 1_700_000_000).expect_err("oversize");
        assert_eq!(err, NickLookupErr::SchemaReject);
    }

    #[test]
    fn td15_claim_canonical_cbor_is_deterministic() {
        // Rebuilding twice with identical inputs must produce identical
        // bytes — a rebuild with fresh PoW grind will re-find the same
        // (lowest) nonce, so output must be byte-identical across calls.
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let claim_ts = 1_700_000_000u64;
        let a = build_claim(&profile, &peer_id, "alice", "Alice", None, claim_ts, 0, 1)
            .expect("build a");
        let b = build_claim(&profile, &peer_id, "alice", "Alice", None, claim_ts, 0, 1)
            .expect("build b");
        assert_eq!(a, b, "canonical CBOR must produce byte-identical output");
    }

    #[test]
    fn td15_claim_with_avatar_roundtrips() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let avatar = [7u8; 32];
        let claim_ts = 1_700_000_000u64;
        let encoded = build_claim(
            &profile,
            &peer_id,
            "alice",
            "Alice",
            Some(&avatar),
            claim_ts,
            0,
            1,
        )
        .expect("build");
        let parsed = validate_claim(&encoded, claim_ts + 5).expect("validate");
        assert_eq!(parsed.avatar_sha256, Some(avatar));
    }

    // -----------------------------------------------------------------
    // TD-37 Layer-A verdict (pre-check decision logic)
    // -----------------------------------------------------------------

    #[test]
    fn td37_layer_a_takes_nickname_when_holder_is_different_peer() {
        // Holder's account key (some other user's protobuf pubkey) differs
        // from our own → short-circuit with TAKEN, no PoW grind.
        let (profile_a, _tmp_a) = fresh_profile();
        let (profile_b, _tmp_b) = fresh_profile();
        let peer_a = derive_peer_id(&profile_a);
        let claim_ts = 1_700_000_000u64;
        let encoded = build_claim(&profile_a, &peer_a, "alice", "Alice", None, claim_ts, 0, 1)
            .expect("build");
        let existing = validate_claim(&encoded, claim_ts + 5).expect("validate");

        let b_keypair = keypair_from_seed(&profile_b.account_seed).expect("kp");
        let b_pubkey_pb = b_keypair.public().encode_protobuf();
        assert!(layer_a_should_short_circuit(&existing, &b_pubkey_pb));
    }

    #[test]
    fn td37_layer_a_passes_through_when_holder_is_self() {
        // Holder's account key matches ours → treat as renewal, proceed.
        let (profile, _tmp) = fresh_profile();
        let peer = derive_peer_id(&profile);
        let claim_ts = 1_700_000_000u64;
        let encoded =
            build_claim(&profile, &peer, "alice", "Alice", None, claim_ts, 0, 1).expect("build");
        let existing = validate_claim(&encoded, claim_ts + 5).expect("validate");

        let keypair = keypair_from_seed(&profile.account_seed).expect("kp");
        let my_pubkey_pb = keypair.public().encode_protobuf();
        assert!(!layer_a_should_short_circuit(&existing, &my_pubkey_pb));
    }

    #[test]
    fn td37_layer_a_short_circuit_is_exact_byte_comparison() {
        // Flipping one byte of a held account_public_key_pb must cause a
        // mismatch → short-circuit. (Defense-in-depth against a
        // partial-equality bug sneaking in.)
        let (profile, _tmp) = fresh_profile();
        let peer = derive_peer_id(&profile);
        let claim_ts = 1_700_000_000u64;
        let encoded =
            build_claim(&profile, &peer, "alice", "Alice", None, claim_ts, 0, 1).expect("build");
        let existing = validate_claim(&encoded, claim_ts + 5).expect("validate");

        let keypair = keypair_from_seed(&profile.account_seed).expect("kp");
        let mut my_pubkey_pb = keypair.public().encode_protobuf();
        // Flip the last byte.
        let last = my_pubkey_pb.len() - 1;
        my_pubkey_pb[last] ^= 0x01;
        assert!(layer_a_should_short_circuit(&existing, &my_pubkey_pb));
    }

    #[test]
    fn td15_build_claim_rejects_charset_violation_before_grind() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        // Uppercase → build should fail before grinding PoW (which
        // would otherwise hang this test for seconds).
        let err = build_claim(
            &profile,
            &peer_id,
            "Alice",
            "Alice",
            None,
            1_700_000_000,
            0,
            1,
        )
        .unwrap_err();
        assert!(err.to_string().contains("charset"));
    }
}
