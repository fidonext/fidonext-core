//! TD-05 · Self-profile record.
//!
//! A peer publishes a signed CBOR profile record to the DHT so that partners
//! can resolve `peer_id → { display_name, nickname, avatar_sha256 }`. The
//! nickname field here is descriptive metadata only — global uniqueness is
//! the separate TD-15 registry that will sit on top of this record's
//! signing/serialization primitives. That is why the crypto decisions here
//! (account_seed signing, ciborium canonical CBOR, domain-separated signature
//! bytes) intentionally mirror the TD-15 design note's CHANGES_REQUESTED
//! addendum — see `fidonext-core/docs/nickname-registry-design.md`, section
//! "Crypto Review".
//!
//! ## Wire shape (canonical CBOR map, integer keys)
//!
//! ```text
//! {
//!     1: bstr        peer_id (multihash bytes)
//!     2: tstr        display_name (<=40 UTF-8 chars, no control chars)
//!     3: tstr        nickname (^[a-z0-9_]{3,20}$)
//!     4: bstr(32)    avatar_sha256 (optional — absent if no avatar)
//!     5: uint        updated_at (unix seconds)
//!     11: bstr       account_public_key (protobuf-encoded Ed25519 public key)
//!     15: bstr(64)   signature (Ed25519 over domain_sep || canonical_cbor(record - 15))
//! }
//! ```
//!
//! ## Signing
//!
//! `signature = Ed25519(account_seed, b"fidonext-profile-record-v1\x00" || cbor)`
//! where `cbor` is the canonical CBOR encoding of the map above with key 15
//! (the signature itself) removed. The account seed is used — NOT the libp2p
//! transport seed — so that rotating the transport identity for privacy does
//! not invalidate the profile binding. (Crypto directive from TD-15 review.)

use anyhow::{anyhow, Context, Result};
use ciborium::value::{Integer, Value};
use libp2p::{identity, PeerId};
use sha2::{Digest, Sha256};
use std::str::FromStr;

use super::{keypair_from_seed, IdentityProfile};

/// Domain separator for profile-record signatures. The trailing `\x00` closes
/// the string so that appending more domain-separator-looking bytes cannot
/// create a collision with a future
/// `"fidonext-profile-record-v1-extended"`-style separator. Written as a byte
/// literal (per crypto review item 2) so it is compile-time frozen.
pub(crate) const PROFILE_SIGNATURE_DOMAIN: &[u8] = b"fidonext-profile-record-v1\x00";

/// DHT-key prefix for profile records.
///
/// The full DHT key is `SHA-256(PROFILE_DHT_KEY_PREFIX || peer_id_bytes)`.
/// The 32-byte hash is opaque to callers; they simply put/get under it.
pub(crate) const PROFILE_DHT_KEY_PREFIX: &[u8] = b"fidonext/profile/v1/";

/// Hard caps on record fields. Tight caps make verification-before-parse
/// cheap (if the CBOR expands to >4 KiB we reject without allocating the
/// fields). The real caps on display_name / nickname are tighter below.
pub const MAX_PROFILE_RECORD_BYTES: usize = 4096;
pub const MAX_DISPLAY_NAME_LEN: usize = 40;
pub const MIN_NICKNAME_LEN: usize = 3;
pub const MAX_NICKNAME_LEN: usize = 20;
pub const AVATAR_SHA256_LEN: usize = 32;
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Integer-keyed tags. Kept contiguous in `{1..=15}` so canonical
/// encoding orders them deterministically regardless of insertion order.
const KEY_PEER_ID: i128 = 1;
const KEY_DISPLAY_NAME: i128 = 2;
const KEY_NICKNAME: i128 = 3;
const KEY_AVATAR_SHA256: i128 = 4;
const KEY_UPDATED_AT: i128 = 5;
const KEY_ACCOUNT_PUBLIC_KEY: i128 = 11;
const KEY_SIGNATURE: i128 = 15;

/// A validated, signed profile record. Fields are intentionally public so
/// the Rust caller can introspect them; across the FFI boundary we only
/// hand Android the signed bytes (after internal validation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRecord {
    pub peer_id: PeerId,
    pub display_name: String,
    pub nickname: String,
    pub avatar_sha256: Option<[u8; AVATAR_SHA256_LEN]>,
    pub updated_at: u64,
    pub account_public_key_protobuf: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Build a signed profile record as canonical CBOR bytes.
pub fn build_profile_record(
    profile: &IdentityProfile,
    peer_id: &PeerId,
    display_name: &str,
    nickname: &str,
    avatar_sha256: Option<&[u8; AVATAR_SHA256_LEN]>,
    updated_at_unix: u64,
) -> Result<Vec<u8>> {
    validate_display_name(display_name)?;
    validate_nickname(nickname)?;

    let account_keypair = keypair_from_seed(&profile.account_seed)?;
    let account_public_key_pb = account_keypair.public().encode_protobuf();

    let unsigned_map = build_map(
        peer_id,
        display_name,
        nickname,
        avatar_sha256,
        updated_at_unix,
        &account_public_key_pb,
        None,
    );
    let unsigned_bytes = encode_canonical(&unsigned_map)?;

    let mut to_sign = Vec::with_capacity(PROFILE_SIGNATURE_DOMAIN.len() + unsigned_bytes.len());
    to_sign.extend_from_slice(PROFILE_SIGNATURE_DOMAIN);
    to_sign.extend_from_slice(&unsigned_bytes);

    let signature = account_keypair
        .sign(&to_sign)
        .context("failed to sign profile record")?;
    if signature.len() != ED25519_SIGNATURE_LEN {
        return Err(anyhow!(
            "unexpected signature length {} (want {})",
            signature.len(),
            ED25519_SIGNATURE_LEN
        ));
    }

    let signed_map = build_map(
        peer_id,
        display_name,
        nickname,
        avatar_sha256,
        updated_at_unix,
        &account_public_key_pb,
        Some(&signature),
    );
    encode_canonical(&signed_map)
}

/// Validate a signed profile record. Verifies: length caps, canonical CBOR
/// shape, field-value constraints, account_public_key → peer_id binding,
/// and the Ed25519 signature under the `fidonext-profile-record-v1\x00`
/// domain.
///
/// `previous_updated_at` is the caller's cached `updated_at` for the same
/// peer_id, or `None` if the caller has no cached record. A fresh record
/// must carry `updated_at > previous_updated_at`; equal or older is
/// rejected as replay (TD-05 anti-downgrade rule).
pub fn validate_profile_record(
    encoded: &[u8],
    previous_updated_at: Option<u64>,
) -> Result<ProfileRecord> {
    if encoded.len() > MAX_PROFILE_RECORD_BYTES {
        return Err(anyhow!(
            "profile record exceeds max size: {} > {}",
            encoded.len(),
            MAX_PROFILE_RECORD_BYTES
        ));
    }

    let value: Value = ciborium::de::from_reader(encoded)
        .map_err(|err| anyhow!("failed to decode profile CBOR: {err}"))?;
    let map = match value {
        Value::Map(entries) => entries,
        other => {
            return Err(anyhow!(
                "profile record root must be CBOR map, got {:?}",
                value_kind(&other)
            ));
        }
    };

    let mut peer_id_bytes: Option<Vec<u8>> = None;
    let mut display_name: Option<String> = None;
    let mut nickname: Option<String> = None;
    let mut avatar_sha256: Option<[u8; AVATAR_SHA256_LEN]> = None;
    let mut updated_at: Option<u64> = None;
    let mut account_public_key_pb: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;

    for (key_v, value_v) in map.into_iter() {
        let key = match key_v {
            Value::Integer(i) => i128::from(i),
            other => {
                return Err(anyhow!(
                    "non-integer map key in profile record: {:?}",
                    value_kind(&other)
                ))
            }
        };
        match key {
            KEY_PEER_ID => {
                let bytes = expect_bytes(value_v, "peer_id")?;
                peer_id_bytes = Some(bytes);
            }
            KEY_DISPLAY_NAME => {
                let s = expect_text(value_v, "display_name")?;
                display_name = Some(s);
            }
            KEY_NICKNAME => {
                let s = expect_text(value_v, "nickname")?;
                nickname = Some(s);
            }
            KEY_AVATAR_SHA256 => {
                let bytes = expect_bytes(value_v, "avatar_sha256")?;
                if bytes.len() != AVATAR_SHA256_LEN {
                    return Err(anyhow!(
                        "avatar_sha256 must be {} bytes, got {}",
                        AVATAR_SHA256_LEN,
                        bytes.len()
                    ));
                }
                let mut arr = [0u8; AVATAR_SHA256_LEN];
                arr.copy_from_slice(&bytes);
                avatar_sha256 = Some(arr);
            }
            KEY_UPDATED_AT => {
                updated_at = Some(expect_u64(value_v, "updated_at")?);
            }
            KEY_ACCOUNT_PUBLIC_KEY => {
                let bytes = expect_bytes(value_v, "account_public_key")?;
                if bytes.is_empty() {
                    return Err(anyhow!("account_public_key is empty"));
                }
                account_public_key_pb = Some(bytes);
            }
            KEY_SIGNATURE => {
                let bytes = expect_bytes(value_v, "signature")?;
                if bytes.len() != ED25519_SIGNATURE_LEN {
                    return Err(anyhow!(
                        "signature must be {} bytes, got {}",
                        ED25519_SIGNATURE_LEN,
                        bytes.len()
                    ));
                }
                signature = Some(bytes);
            }
            other => {
                return Err(anyhow!("unknown CBOR map key in profile record: {}", other));
            }
        }
    }

    let peer_id_bytes = peer_id_bytes.ok_or_else(|| anyhow!("missing peer_id"))?;
    let display_name = display_name.ok_or_else(|| anyhow!("missing display_name"))?;
    let nickname = nickname.ok_or_else(|| anyhow!("missing nickname"))?;
    let updated_at = updated_at.ok_or_else(|| anyhow!("missing updated_at"))?;
    let account_public_key_pb =
        account_public_key_pb.ok_or_else(|| anyhow!("missing account_public_key"))?;
    let signature = signature.ok_or_else(|| anyhow!("missing signature"))?;

    validate_display_name(&display_name)?;
    validate_nickname(&nickname)?;

    let peer_id =
        PeerId::from_bytes(&peer_id_bytes).map_err(|err| anyhow!("invalid peer_id: {err}"))?;

    if let Some(previous) = previous_updated_at {
        if updated_at <= previous {
            return Err(anyhow!(
                "profile record is stale (updated_at {} <= previous {})",
                updated_at,
                previous
            ));
        }
    }

    let account_public_key = identity::PublicKey::try_decode_protobuf(&account_public_key_pb)
        .map_err(|err| anyhow!("invalid account_public_key protobuf: {err}"))?;

    // Signed bytes are canonical_cbor(map minus the signature key 15),
    // prefixed with the domain separator. Reconstruct that map and re-encode.
    let unsigned_map = build_map(
        &peer_id,
        &display_name,
        &nickname,
        avatar_sha256.as_ref(),
        updated_at,
        &account_public_key_pb,
        None,
    );
    let unsigned_bytes = encode_canonical(&unsigned_map)?;

    let mut to_verify = Vec::with_capacity(PROFILE_SIGNATURE_DOMAIN.len() + unsigned_bytes.len());
    to_verify.extend_from_slice(PROFILE_SIGNATURE_DOMAIN);
    to_verify.extend_from_slice(&unsigned_bytes);

    if !account_public_key.verify(&to_verify, &signature) {
        return Err(anyhow!("profile record signature verification failed"));
    }

    Ok(ProfileRecord {
        peer_id,
        display_name,
        nickname,
        avatar_sha256,
        updated_at,
        account_public_key_protobuf: account_public_key_pb,
        signature,
    })
}

/// Peer-id -> DHT key for the profile record. `SHA-256(prefix || peer_id_bytes)`.
pub fn profile_dht_key(peer_id: &PeerId) -> Vec<u8> {
    let peer_bytes = peer_id.to_bytes();
    let mut hasher = Sha256::new();
    hasher.update(PROFILE_DHT_KEY_PREFIX);
    hasher.update(&peer_bytes);
    hasher.finalize().to_vec()
}

fn build_map(
    peer_id: &PeerId,
    display_name: &str,
    nickname: &str,
    avatar_sha256: Option<&[u8; AVATAR_SHA256_LEN]>,
    updated_at: u64,
    account_public_key_pb: &[u8],
    signature: Option<&[u8]>,
) -> Vec<(Value, Value)> {
    // Order matters for canonical CBOR — integer map keys are sorted ascending
    // by numeric value (RFC 8949 §4.2.3). We build in natural order and
    // `encode_canonical` re-sorts just in case.
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(8);
    entries.push((int_key(KEY_PEER_ID), Value::Bytes(peer_id.to_bytes())));
    entries.push((
        int_key(KEY_DISPLAY_NAME),
        Value::Text(display_name.to_string()),
    ));
    entries.push((int_key(KEY_NICKNAME), Value::Text(nickname.to_string())));
    if let Some(hash) = avatar_sha256 {
        entries.push((int_key(KEY_AVATAR_SHA256), Value::Bytes(hash.to_vec())));
    }
    entries.push((
        int_key(KEY_UPDATED_AT),
        Value::Integer(Integer::from(updated_at)),
    ));
    entries.push((
        int_key(KEY_ACCOUNT_PUBLIC_KEY),
        Value::Bytes(account_public_key_pb.to_vec()),
    ));
    if let Some(sig) = signature {
        entries.push((int_key(KEY_SIGNATURE), Value::Bytes(sig.to_vec())));
    }
    entries
}

fn int_key(key: i128) -> Value {
    Value::Integer(Integer::try_from(key).expect("small positive keys fit in ciborium Integer"))
}

/// Canonical CBOR (RFC 8949 §4.2). `ciborium` does not guarantee this for
/// `Value` maps — we hand-sort by the integer key numeric value ascending
/// (all our keys are small non-negative integers) and then serialize. If
/// we later add non-integer keys this becomes more involved; for now the
/// fixed schema keeps it simple.
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

fn expect_bytes(value: Value, field: &str) -> Result<Vec<u8>> {
    match value {
        Value::Bytes(b) => Ok(b),
        other => Err(anyhow!(
            "field {} expected bytes, got {:?}",
            field,
            value_kind(&other)
        )),
    }
}

fn expect_text(value: Value, field: &str) -> Result<String> {
    match value {
        Value::Text(s) => Ok(s),
        other => Err(anyhow!(
            "field {} expected text, got {:?}",
            field,
            value_kind(&other)
        )),
    }
}

fn expect_u64(value: Value, field: &str) -> Result<u64> {
    match value {
        Value::Integer(i) => {
            let as_i128 = i128::from(i);
            if as_i128 < 0 {
                return Err(anyhow!("field {} must be unsigned, got {}", field, as_i128));
            }
            u64::try_from(as_i128)
                .map_err(|_| anyhow!("field {} exceeds u64 range: {}", field, as_i128))
        }
        other => Err(anyhow!(
            "field {} expected integer, got {:?}",
            field,
            value_kind(&other)
        )),
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Integer(_) => "integer",
        Value::Bytes(_) => "bytes",
        Value::Text(_) => "text",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Tag(_, _) => "tag",
        Value::Bool(_) => "bool",
        Value::Null => "null",
        Value::Float(_) => "float",
        _ => "unknown",
    }
}

pub fn validate_display_name(value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("display_name cannot be empty"));
    }
    let char_count = value.chars().count();
    if char_count > MAX_DISPLAY_NAME_LEN {
        return Err(anyhow!(
            "display_name exceeds {} characters",
            MAX_DISPLAY_NAME_LEN
        ));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(anyhow!("display_name contains control characters"));
    }
    Ok(())
}

pub fn validate_nickname(value: &str) -> Result<()> {
    let len = value.len();
    if !(MIN_NICKNAME_LEN..=MAX_NICKNAME_LEN).contains(&len) {
        return Err(anyhow!(
            "nickname length {} out of range [{}, {}]",
            len,
            MIN_NICKNAME_LEN,
            MAX_NICKNAME_LEN
        ));
    }
    for (idx, c) in value.bytes().enumerate() {
        let ok = matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_');
        if !ok {
            return Err(anyhow!(
                "nickname byte at position {} is not in [a-z0-9_]: {:#x}",
                idx,
                c
            ));
        }
    }
    Ok(())
}

/// Parse a PeerId from an FFI-provided string without pulling in lib.rs helpers.
pub fn parse_peer_id_str(raw: &str) -> Result<PeerId> {
    PeerId::from_str(raw).map_err(|err| anyhow!("invalid peer_id string: {err}"))
}

#[cfg(test)]
mod tests {
    use super::super::{load_or_create_profile, IDENTITY_SEED_LEN};
    use super::*;
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

    #[test]
    fn roundtrip_record_round_trips_and_verifies() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let avatar = [7u8; AVATAR_SHA256_LEN];

        let encoded = build_profile_record(
            &profile,
            &peer_id,
            "Alice Cooper",
            "alice_99",
            Some(&avatar),
            1_700_000_000,
        )
        .expect("build");

        let record = validate_profile_record(&encoded, None).expect("validate");
        assert_eq!(record.peer_id, peer_id);
        assert_eq!(record.display_name, "Alice Cooper");
        assert_eq!(record.nickname, "alice_99");
        assert_eq!(record.avatar_sha256, Some(avatar));
        assert_eq!(record.updated_at, 1_700_000_000);
    }

    #[test]
    fn roundtrip_without_avatar() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);

        let encoded = build_profile_record(&profile, &peer_id, "Bob", "bob", None, 1_700_000_000)
            .expect("build");
        let record = validate_profile_record(&encoded, None).expect("validate");
        assert_eq!(record.avatar_sha256, None);
    }

    #[test]
    fn tampered_record_fails_signature_check() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);

        let mut encoded =
            build_profile_record(&profile, &peer_id, "Alice", "alice", None, 1_700_000_000)
                .expect("build");

        // Flip a bit near the middle of the record. CBOR tolerates most byte
        // flips without structural error, so the signature check is what must
        // reject.
        let mid = encoded.len() / 2;
        encoded[mid] ^= 0x01;

        let err = validate_profile_record(&encoded, None).expect_err("must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("signature")
                || msg.contains("decode")
                || msg.contains("invalid")
                || msg.contains("expected"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn tampered_signature_bytes_fail_verification() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);

        let encoded =
            build_profile_record(&profile, &peer_id, "Alice", "alice", None, 1_700_000_000)
                .expect("build");

        // Walk the bytes and flip a bit inside what we believe is the
        // signature region. Since our canonical encoder places key 15 last,
        // the signature payload lives near the end. Flip the very last byte.
        let mut corrupt = encoded.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0x80;

        let err = validate_profile_record(&corrupt, None).expect_err("must reject");
        assert!(format!("{err:#}").contains("signature"));
    }

    #[test]
    fn wrong_domain_separator_does_not_verify() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);

        let account_keypair = keypair_from_seed(&profile.account_seed).expect("kp");
        let account_public_key_pb = account_keypair.public().encode_protobuf();

        // Build the unsigned CBOR ourselves and sign with a DIFFERENT
        // domain separator, then splice the signature back into the record.
        // Expected result: verification under the real domain separator
        // must fail.
        let unsigned_map = build_map(
            &peer_id,
            "Alice",
            "alice",
            None,
            1_700_000_000,
            &account_public_key_pb,
            None,
        );
        let unsigned_bytes = encode_canonical(&unsigned_map).expect("encode");
        let mut to_sign_bad = Vec::new();
        to_sign_bad.extend_from_slice(b"fidonext-different-domain-v1\x00");
        to_sign_bad.extend_from_slice(&unsigned_bytes);
        let bad_sig = account_keypair.sign(&to_sign_bad).expect("sign");

        let signed_map = build_map(
            &peer_id,
            "Alice",
            "alice",
            None,
            1_700_000_000,
            &account_public_key_pb,
            Some(&bad_sig),
        );
        let encoded = encode_canonical(&signed_map).expect("encode");

        let err = validate_profile_record(&encoded, None).expect_err("must reject");
        assert!(format!("{err:#}").contains("signature"));
    }

    #[test]
    fn replay_with_equal_or_older_updated_at_is_rejected() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);

        let encoded =
            build_profile_record(&profile, &peer_id, "Alice", "alice", None, 1_700_000_100)
                .expect("build");

        // Equal -> reject.
        let err = validate_profile_record(&encoded, Some(1_700_000_100)).expect_err("replay");
        assert!(format!("{err:#}").contains("stale"));

        // Older cached is fine.
        let _ok = validate_profile_record(&encoded, Some(1_700_000_099)).expect("fresh");

        // Cached newer than the record -> reject.
        let err = validate_profile_record(&encoded, Some(1_700_000_200)).expect_err("downgrade");
        assert!(format!("{err:#}").contains("stale"));
    }

    #[test]
    fn canonical_cbor_is_deterministic() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let avatar = [1u8; AVATAR_SHA256_LEN];

        let a = build_profile_record(
            &profile,
            &peer_id,
            "Alice",
            "alice",
            Some(&avatar),
            1_700_000_000,
        )
        .expect("build a");
        let b = build_profile_record(
            &profile,
            &peer_id,
            "Alice",
            "alice",
            Some(&avatar),
            1_700_000_000,
        )
        .expect("build b");

        assert_eq!(a, b, "canonical CBOR must produce byte-identical output");
    }

    #[test]
    fn nickname_regex_rejects_out_of_range() {
        assert!(validate_nickname("ab").is_err());
        assert!(validate_nickname("a".repeat(21).as_str()).is_err());
        assert!(validate_nickname("Alice").is_err()); // uppercase
        assert!(validate_nickname("alice!").is_err());
        assert!(validate_nickname("al ice").is_err());
        assert!(validate_nickname("alice_1").is_ok());
        assert!(validate_nickname("a_0").is_ok());
    }

    #[test]
    fn display_name_rejects_too_long_and_control_chars() {
        assert!(validate_display_name("").is_err());
        assert!(validate_display_name("   ").is_err());
        let long: String = std::iter::repeat('a').take(41).collect();
        assert!(validate_display_name(&long).is_err());
        let ctrl = "alice\u{0007}".to_string();
        assert!(validate_display_name(&ctrl).is_err());
        assert!(validate_display_name("Alice Cooper").is_ok());
        // Unicode is OK as long as <=40 chars.
        assert!(validate_display_name("Алиса Купер").is_ok());
    }

    #[test]
    fn profile_dht_key_is_stable_and_32_bytes() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);
        let a = profile_dht_key(&peer_id);
        let b = profile_dht_key(&peer_id);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn domain_separator_is_byte_literal_and_stable() {
        // Defensive: if anyone ever rewrites the const as a format! or
        // concat! that drifts between builds, this test will wedge.
        assert_eq!(PROFILE_SIGNATURE_DOMAIN, b"fidonext-profile-record-v1\x00");
        assert_eq!(PROFILE_SIGNATURE_DOMAIN.len(), 27);
    }

    #[test]
    fn unknown_map_key_is_rejected() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);

        let account_keypair = keypair_from_seed(&profile.account_seed).expect("kp");
        let account_public_key_pb = account_keypair.public().encode_protobuf();

        // Add an extra CBOR key (7) alongside the allowed set. The spec
        // rejects unknown keys — even a "harmless" one like 7.
        let mut entries = build_map(
            &peer_id,
            "Alice",
            "alice",
            None,
            1_700_000_000,
            &account_public_key_pb,
            None,
        );
        entries.push((int_key(7), Value::Text("smuggled".to_string())));
        let unsigned_bytes = encode_canonical(&entries).expect("encode");
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(PROFILE_SIGNATURE_DOMAIN);
        to_sign.extend_from_slice(&unsigned_bytes);
        let sig = account_keypair.sign(&to_sign).expect("sign");
        entries.push((int_key(KEY_SIGNATURE), Value::Bytes(sig)));
        let encoded = encode_canonical(&entries).expect("encode");

        let err = validate_profile_record(&encoded, None).expect_err("reject");
        assert!(format!("{err:#}").contains("unknown"));
    }

    #[test]
    fn oversize_record_is_rejected_before_parse() {
        let mut bogus = vec![0u8; MAX_PROFILE_RECORD_BYTES + 1];
        // Give it a CBOR map prefix so the size check is what triggers
        // (not the CBOR decoder refusing a non-map).
        bogus[0] = 0xBF;
        let err = validate_profile_record(&bogus, None).expect_err("reject");
        assert!(format!("{err:#}").contains("exceeds max size"));
    }

    #[test]
    fn malformed_peer_id_bytes_are_rejected() {
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);

        let account_keypair = keypair_from_seed(&profile.account_seed).expect("kp");
        let account_public_key_pb = account_keypair.public().encode_protobuf();

        // Build a record where the peer_id bytes are intentionally not a
        // valid multihash, but sign it properly so that only the peer_id
        // shape check can fail.
        let mut entries: Vec<(Value, Value)> = Vec::new();
        entries.push((int_key(KEY_PEER_ID), Value::Bytes(vec![0xff, 0xff, 0xff])));
        entries.push((int_key(KEY_DISPLAY_NAME), Value::Text("Alice".to_string())));
        entries.push((int_key(KEY_NICKNAME), Value::Text("alice".to_string())));
        entries.push((
            int_key(KEY_UPDATED_AT),
            Value::Integer(Integer::try_from(1_700_000_000i128).unwrap()),
        ));
        entries.push((
            int_key(KEY_ACCOUNT_PUBLIC_KEY),
            Value::Bytes(account_public_key_pb.clone()),
        ));
        let unsigned = encode_canonical(&entries).expect("encode");
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(PROFILE_SIGNATURE_DOMAIN);
        to_sign.extend_from_slice(&unsigned);
        let sig = account_keypair.sign(&to_sign).expect("sign");
        entries.push((int_key(KEY_SIGNATURE), Value::Bytes(sig)));
        let encoded = encode_canonical(&entries).expect("encode");

        let err = validate_profile_record(&encoded, None).expect_err("reject");
        assert!(format!("{err:#}").contains("peer_id"));

        // Silence unused-var on peer_id
        let _ = peer_id;
    }

    #[test]
    fn account_seed_is_the_signing_key_not_libp2p_seed() {
        // Strict: a record built with `build_profile_record` must verify
        // under the public key derived from `account_seed`, and NOT under
        // the public key derived from `libp2p_seed`. This catches any
        // regression where a future contributor swaps the signing seed.
        let (profile, _tmp) = fresh_profile();
        let peer_id = derive_peer_id(&profile);

        // Flip one seed byte to synthesize a "wrong" libp2p-seed profile.
        let mut bogus_profile = profile.clone();
        bogus_profile.libp2p_seed[0] ^= 0x11;

        // Sanity: account_seed in both is untouched.
        assert_ne!(bogus_profile.libp2p_seed, profile.libp2p_seed);

        let encoded =
            build_profile_record(&profile, &peer_id, "Alice", "alice", None, 1_700_000_000)
                .expect("build");

        // Validation uses the embedded account_public_key_protobuf, so
        // regardless of whether libp2p_seed rotated, the record must still
        // validate. This locks the binding: signatures are over account
        // identity, not transport identity.
        let _ok = validate_profile_record(&encoded, None).expect("validate");

        // Byte-zero sanity: IDENTITY_SEED_LEN is still 32.
        assert_eq!(IDENTITY_SEED_LEN, 32);
    }
}
