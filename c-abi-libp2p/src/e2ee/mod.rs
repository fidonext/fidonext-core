//! Local identity primitives used by the E2EE rollout.
//!
//! This module intentionally focuses on a minimal, durable profile format:
//! - one stable account identity seed (`account_seed`)
//! - one device identity (`device_id`)
//! - one stable libp2p identity seed for this device (`libp2p_seed`)
//! - one seed reserved for Signal identity material (`signal_identity_seed`)
//!
//! The profile is persisted to a JSON file on disk and reused across restarts.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use hkdf::Hkdf;
use libp2p::{identity, PeerId};
use rand::{Rng, RngCore};
use rand09::{Rng as Rand09Rng, TryRngCore as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub(crate) const IDENTITY_SEED_LEN: usize = 32;
const PROFILE_SCHEMA_VERSION: u32 = 1;
const E2EE_SCHEMA_VERSION: u32 = 1;
const PREKEY_MESSAGE_PROTOCOL: &str = "signal-prekey-message-v1";
const SESSION_MESSAGE_PROTOCOL: &str = "signal-session-message-v1";
const DHT_KEY_NAMESPACE: &str = "fidonext-e2ee-v1";
const DHT_KEY_PREKEY_BUNDLE_PREFIX: &str = "prekey-bundle";
const DHT_KEY_KEY_UPDATE_PREFIX: &str = "key-update";
pub(crate) const DEFAULT_KEY_UPDATE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
pub(crate) const DEFAULT_PREKEY_BUNDLE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
pub(crate) const DEFAULT_ONE_TIME_PREKEY_COUNT: usize = 32;
pub(crate) const DEFAULT_SIGNED_PREKEY_ROTATION_SECONDS: u64 = 7 * 24 * 60 * 60;
const ONE_TIME_PREKEY_START_ID: u32 = 1000;
const SIGNED_PREKEY_START_ID: u32 = 1;
const PREVIOUS_SIGNED_PREKEY_HISTORY_LIMIT: usize = 3;
const SIGNAL_STATE_SCHEMA_VERSION: u32 = 1;
const LIBSIGNAL_STATE_SCHEMA_VERSION: u32 = 1;
const LIBSIGNAL_MESSAGE_PROTOCOL: &str = "signal-libsignal-message-v1";
const LIBSIGNAL_MESSAGE_KIND_PREKEY: &str = "prekey";
const LIBSIGNAL_MESSAGE_KIND_SESSION: &str = "session";

pub async fn official_libsignal_roundtrip_smoke() -> Result<()> {
    use libsignal_protocol::{
        kem, message_decrypt, message_encrypt, process_prekey_bundle, DeviceId,
        GenericSignedPreKey, IdentityKeyPair, IdentityKeyStore, InMemSignalProtocolStore, KeyPair,
        KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyRecord, PreKeyStore,
        ProtocolAddress, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
    };
    use rand09::{rngs::OsRng, Rng, TryRngCore as _};

    let mut csprng = OsRng.unwrap_err();
    let alice_device_id = DeviceId::new(1)?;
    let bob_device_id = DeviceId::new(1)?;
    let alice_address = ProtocolAddress::new("alice".to_string(), alice_device_id);
    let bob_address = ProtocolAddress::new("bob".to_string(), bob_device_id);

    let alice_identity = IdentityKeyPair::generate(&mut csprng);
    let bob_identity = IdentityKeyPair::generate(&mut csprng);
    let alice_registration_id = (csprng.random::<u16>() as u32) & 0x3fff;
    let bob_registration_id = (csprng.random::<u16>() as u32) & 0x3fff;
    let mut alice_store = InMemSignalProtocolStore::new(alice_identity, alice_registration_id)?;
    let mut bob_store = InMemSignalProtocolStore::new(bob_identity, bob_registration_id)?;

    let pre_key_pair = KeyPair::generate(&mut csprng);
    let signed_pre_key_pair = KeyPair::generate(&mut csprng);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut csprng);
    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
    let signed_pre_key_signature = bob_store
        .get_identity_key_pair()
        .await?
        .private_key()
        .calculate_signature(&signed_pre_key_public, &mut csprng)?;
    let kyber_pre_key_public = kyber_pre_key_pair.public_key.serialize();
    let kyber_pre_key_signature = bob_store
        .get_identity_key_pair()
        .await?
        .private_key()
        .calculate_signature(&kyber_pre_key_public, &mut csprng)?;

    let pre_key_id = 1001u32;
    let signed_pre_key_id = 2001u32;
    let kyber_pre_key_id = 3001u32;
    let bundle = PreKeyBundle::new(
        bob_store.get_local_registration_id().await?,
        bob_device_id,
        Some((pre_key_id.into(), pre_key_pair.public_key)),
        signed_pre_key_id.into(),
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        kyber_pre_key_id.into(),
        kyber_pre_key_pair.public_key.clone(),
        kyber_pre_key_signature.to_vec(),
        *bob_store.get_identity_key_pair().await?.identity_key(),
    )?;

    bob_store
        .save_pre_key(
            pre_key_id.into(),
            &PreKeyRecord::new(pre_key_id.into(), &pre_key_pair),
        )
        .await?;
    bob_store
        .save_signed_pre_key(
            signed_pre_key_id.into(),
            &SignedPreKeyRecord::new(
                signed_pre_key_id.into(),
                Timestamp::from_epoch_millis(1),
                &signed_pre_key_pair,
                &signed_pre_key_signature,
            ),
        )
        .await?;
    bob_store
        .save_kyber_pre_key(
            kyber_pre_key_id.into(),
            &KyberPreKeyRecord::new(
                kyber_pre_key_id.into(),
                Timestamp::from_epoch_millis(1),
                &kyber_pre_key_pair,
                &kyber_pre_key_signature,
            ),
        )
        .await?;

    process_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bundle,
        SystemTime::now(),
        &mut csprng,
    )
    .await?;

    let outbound = message_encrypt(
        b"official-libsignal-smoke",
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::now(),
        &mut csprng,
    )
    .await?;
    let plaintext = message_decrypt(
        &outbound,
        &alice_address,
        &mut bob_store.session_store,
        &mut bob_store.identity_store,
        &mut bob_store.pre_key_store,
        &bob_store.signed_pre_key_store,
        &mut bob_store.kyber_pre_key_store,
        &mut csprng,
    )
    .await?;
    if plaintext.as_slice() != b"official-libsignal-smoke" {
        return Err(anyhow!("official libsignal roundtrip plaintext mismatch"));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct IdentityProfile {
    account_seed: [u8; IDENTITY_SEED_LEN],
    pub account_id: String,
    pub device_id: String,
    pub libp2p_seed: [u8; IDENTITY_SEED_LEN],
    pub signal_identity_seed: [u8; IDENTITY_SEED_LEN],
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredIdentityProfile {
    schema_version: u32,
    account_seed_b64: String,
    device_id: String,
    libp2p_seed_b64: String,
    signal_identity_seed_b64: String,
    created_at_unix: u64,
}

pub fn load_or_create_profile(path: &Path) -> Result<IdentityProfile> {
    if path.exists() {
        return load_profile(path);
    }

    create_profile(path)
}

fn load_profile(path: &Path) -> Result<IdentityProfile> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read identity profile: {}", path.display()))?;
    let stored: StoredIdentityProfile = serde_json::from_str(&raw)
        .with_context(|| format!("invalid identity profile json: {}", path.display()))?;

    if stored.schema_version != PROFILE_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported identity profile schema version: {}",
            stored.schema_version
        ));
    }

    let account_seed = decode_seed(&stored.account_seed_b64, "account_seed_b64")?;
    let libp2p_seed = decode_seed(&stored.libp2p_seed_b64, "libp2p_seed_b64")?;
    let signal_identity_seed =
        decode_seed(&stored.signal_identity_seed_b64, "signal_identity_seed_b64")?;
    if stored.device_id.trim().is_empty() {
        return Err(anyhow!("device_id is empty in identity profile"));
    }

    Ok(IdentityProfile {
        account_seed,
        account_id: derive_account_id(&account_seed)?,
        device_id: stored.device_id,
        libp2p_seed,
        signal_identity_seed,
    })
}

fn create_profile(path: &Path) -> Result<IdentityProfile> {
    let mut account_seed = [0u8; IDENTITY_SEED_LEN];
    let mut libp2p_seed = [0u8; IDENTITY_SEED_LEN];
    let mut signal_identity_seed = [0u8; IDENTITY_SEED_LEN];
    let mut device_id_raw = [0u8; 16];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut account_seed);
    rng.fill_bytes(&mut libp2p_seed);
    rng.fill_bytes(&mut signal_identity_seed);
    rng.fill_bytes(&mut device_id_raw);

    let device_id = format!("dev-{}", hex::encode(device_id_raw));
    let account_id = derive_account_id(&account_seed)?;

    let stored = StoredIdentityProfile {
        schema_version: PROFILE_SCHEMA_VERSION,
        account_seed_b64: encode_seed(account_seed),
        device_id: device_id.clone(),
        libp2p_seed_b64: encode_seed(libp2p_seed),
        signal_identity_seed_b64: encode_seed(signal_identity_seed),
        created_at_unix: current_unix_seconds(),
    };

    persist_profile(path, &stored)?;

    Ok(IdentityProfile {
        account_seed,
        account_id,
        device_id,
        libp2p_seed,
        signal_identity_seed,
    })
}

fn persist_profile(path: &Path, stored: &StoredIdentityProfile) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create identity profile directory: {}",
                parent.display()
            )
        })?;
    }

    let json =
        serde_json::to_string_pretty(stored).context("failed to serialize identity profile")?;
    let temp_path = temporary_path(path);

    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }

    let mut file = options.open(&temp_path).with_context(|| {
        format!(
            "failed to create temp identity profile: {}",
            temp_path.display()
        )
    })?;
    file.write_all(json.as_bytes())
        .context("failed to write identity profile data")?;
    file.sync_all()
        .context("failed to fsync identity profile data")?;

    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to move identity profile into place: {} -> {}",
            temp_path.display(),
            path.display()
        )
    })?;

    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms).with_context(|| {
            format!(
                "failed to set identity profile permissions to 0600: {}",
                path.display()
            )
        })?;
    }

    Ok(())
}

fn derive_account_id(account_seed: &[u8; IDENTITY_SEED_LEN]) -> Result<String> {
    let secret = identity::ed25519::SecretKey::try_from_bytes(*account_seed)
        .map_err(|err| anyhow!("invalid account seed: {err}"))?;
    let keypair = identity::ed25519::Keypair::from(secret);
    let peer_id = PeerId::from(identity::Keypair::from(keypair).public());
    Ok(peer_id.to_string())
}

fn decode_seed(encoded: &str, field_name: &str) -> Result<[u8; IDENTITY_SEED_LEN]> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .with_context(|| format!("failed to decode {field_name}"))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{field_name} must contain exactly {IDENTITY_SEED_LEN} bytes"))
}

fn encode_seed(seed: [u8; IDENTITY_SEED_LEN]) -> String {
    base64::engine::general_purpose::STANDARD.encode(seed)
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn temporary_path(path: &Path) -> PathBuf {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.tmp"))
        .unwrap_or_else(|| "tmp".to_string());
    path.with_extension(extension)
}

#[derive(Debug, Serialize, Deserialize)]
struct UnsignedKeyUpdateRecord {
    schema_version: u32,
    account_id: String,
    account_public_key_b64: String,
    device_id: String,
    peer_id: String,
    signal_identity_key_id: String,
    revision: u64,
    issued_at_unix: u64,
    expires_at_unix: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyUpdateRecord {
    schema_version: u32,
    account_id: String,
    account_public_key_b64: String,
    device_id: String,
    peer_id: String,
    signal_identity_key_id: String,
    revision: u64,
    issued_at_unix: u64,
    expires_at_unix: u64,
    signature_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    schema_version: u32,
    protocol: String,
    sender_account_id: String,
    sender_device_id: String,
    recipient_account_id: String,
    recipient_device_id: String,
    message_id: String,
    created_at_unix: u64,
    ciphertext_b64: String,
    aad_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LibsignalInnerPayload {
    plaintext_b64: String,
    aad_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LibsignalMessageRecord {
    schema_version: u32,
    protocol: String,
    sender_account_id: String,
    sender_device_id: String,
    recipient_account_id: String,
    recipient_device_id: String,
    session_id: String,
    message_id: String,
    created_at_unix: u64,
    ciphertext_kind: String,
    #[serde(default)]
    recipient_one_time_pre_key_id: Option<u32>,
    aad_b64: String,
    ciphertext_b64: String,
}

pub fn build_key_update(
    profile: &IdentityProfile,
    peer_id: &PeerId,
    revision: u64,
    ttl_seconds: u64,
) -> Result<Vec<u8>> {
    let issued_at_unix = current_unix_seconds();
    let expires_at_unix = issued_at_unix.saturating_add(ttl_seconds.max(1));
    let account_keypair = keypair_from_seed(&profile.account_seed)?;
    let account_public_key_b64 = base64::engine::general_purpose::STANDARD
        .encode(account_keypair.public().encode_protobuf());
    let signal_identity_key_id = derive_account_id(&profile.signal_identity_seed)?;

    let unsigned = UnsignedKeyUpdateRecord {
        schema_version: E2EE_SCHEMA_VERSION,
        account_id: profile.account_id.clone(),
        account_public_key_b64,
        device_id: profile.device_id.clone(),
        peer_id: peer_id.to_string(),
        signal_identity_key_id,
        revision,
        issued_at_unix,
        expires_at_unix,
    };

    let unsigned_bytes =
        serde_json::to_vec(&unsigned).context("failed to encode unsigned key update")?;
    let signature = account_keypair
        .sign(&unsigned_bytes)
        .context("failed to sign key update payload")?;
    let record = KeyUpdateRecord {
        schema_version: unsigned.schema_version,
        account_id: unsigned.account_id,
        account_public_key_b64: unsigned.account_public_key_b64,
        device_id: unsigned.device_id,
        peer_id: unsigned.peer_id,
        signal_identity_key_id: unsigned.signal_identity_key_id,
        revision: unsigned.revision,
        issued_at_unix: unsigned.issued_at_unix,
        expires_at_unix: unsigned.expires_at_unix,
        signature_b64: base64::engine::general_purpose::STANDARD.encode(signature),
    };

    serde_json::to_vec(&record).context("failed to encode signed key update")
}

pub fn validate_key_update(encoded: &[u8], now_unix: u64) -> Result<KeyUpdateRecord> {
    let record: KeyUpdateRecord =
        serde_json::from_slice(encoded).context("failed to decode key update json")?;
    if record.schema_version != E2EE_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported key update schema version: {}",
            record.schema_version
        ));
    }
    if record.account_id.trim().is_empty() || record.device_id.trim().is_empty() {
        return Err(anyhow!("account_id/device_id cannot be empty"));
    }
    if record.expires_at_unix <= record.issued_at_unix {
        return Err(anyhow!(
            "key update expires_at_unix must be greater than issued_at_unix"
        ));
    }
    if now_unix > record.expires_at_unix {
        return Err(anyhow!("key update has expired"));
    }
    PeerId::from_str(&record.account_id).context("invalid account_id PeerId")?;
    PeerId::from_str(&record.peer_id).context("invalid peer_id")?;
    PeerId::from_str(&record.signal_identity_key_id).context("invalid signal_identity_key_id")?;

    let public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&record.account_public_key_b64)
        .context("invalid account_public_key_b64")?;
    let public_key = identity::PublicKey::try_decode_protobuf(&public_key_bytes)
        .context("invalid account public key")?;
    let derived_account_id = PeerId::from(public_key.clone()).to_string();
    if derived_account_id != record.account_id {
        return Err(anyhow!("account_id does not match account_public_key"));
    }

    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&record.signature_b64)
        .context("invalid signature_b64")?;
    let unsigned = UnsignedKeyUpdateRecord {
        schema_version: record.schema_version,
        account_id: record.account_id.clone(),
        account_public_key_b64: record.account_public_key_b64.clone(),
        device_id: record.device_id.clone(),
        peer_id: record.peer_id.clone(),
        signal_identity_key_id: record.signal_identity_key_id.clone(),
        revision: record.revision,
        issued_at_unix: record.issued_at_unix,
        expires_at_unix: record.expires_at_unix,
    };
    let unsigned_bytes = serde_json::to_vec(&unsigned)
        .context("failed to encode unsigned key update for verification")?;
    if !public_key.verify(&unsigned_bytes, &signature_bytes) {
        return Err(anyhow!("key update signature verification failed"));
    }

    Ok(record)
}

pub fn resolve_key_update_revision(profile_path: &Path, requested_revision: u64) -> Result<u64> {
    let profile = load_or_create_profile(profile_path)?;
    let mut state =
        load_or_create_signal_state(profile_path, &profile, DEFAULT_ONE_TIME_PREKEY_COUNT, true)?;

    if requested_revision == 0 {
        return Ok(state.key_update_revision.max(1));
    }
    if requested_revision < state.key_update_revision {
        return Err(anyhow!(
            "requested key update revision {} is behind current revision {}",
            requested_revision,
            state.key_update_revision
        ));
    }
    if requested_revision > state.key_update_revision {
        state.key_update_revision = requested_revision;
        persist_signal_state(&signal_state_path(profile_path), &state)?;
    }
    Ok(state.key_update_revision)
}

pub fn prekey_bundle_dht_key(account_id: &str, device_id: &str) -> Result<Vec<u8>> {
    validate_account_and_device_ids(account_id, device_id)?;
    Ok(
        format!("{DHT_KEY_NAMESPACE}/{DHT_KEY_PREKEY_BUNDLE_PREFIX}/{account_id}/{device_id}")
            .into_bytes(),
    )
}

pub fn key_update_dht_key(account_id: &str, device_id: &str) -> Result<Vec<u8>> {
    validate_account_and_device_ids(account_id, device_id)?;
    Ok(
        format!("{DHT_KEY_NAMESPACE}/{DHT_KEY_KEY_UPDATE_PREFIX}/{account_id}/{device_id}")
            .into_bytes(),
    )
}

fn validate_account_and_device_ids(account_id: &str, device_id: &str) -> Result<()> {
    if account_id.trim().is_empty() || device_id.trim().is_empty() {
        return Err(anyhow!("account_id/device_id cannot be empty"));
    }
    PeerId::from_str(account_id).context("invalid account_id PeerId")?;
    Ok(())
}

pub fn build_envelope(
    sender_account_id: &str,
    sender_device_id: &str,
    recipient_account_id: &str,
    recipient_device_id: &str,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if sender_account_id.trim().is_empty()
        || sender_device_id.trim().is_empty()
        || recipient_account_id.trim().is_empty()
        || recipient_device_id.trim().is_empty()
    {
        return Err(anyhow!("envelope identity fields cannot be empty"));
    }
    if ciphertext.is_empty() {
        return Err(anyhow!("ciphertext cannot be empty"));
    }

    let mut message_id_raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut message_id_raw);

    let envelope = EncryptedEnvelope {
        schema_version: E2EE_SCHEMA_VERSION,
        protocol: "signal-envelope-v1".to_string(),
        sender_account_id: sender_account_id.to_string(),
        sender_device_id: sender_device_id.to_string(),
        recipient_account_id: recipient_account_id.to_string(),
        recipient_device_id: recipient_device_id.to_string(),
        message_id: hex::encode(message_id_raw),
        created_at_unix: current_unix_seconds(),
        ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(ciphertext),
        aad_b64: base64::engine::general_purpose::STANDARD.encode(aad),
    };

    serde_json::to_vec(&envelope).context("failed to encode encrypted envelope")
}

pub fn validate_envelope(encoded: &[u8]) -> Result<EncryptedEnvelope> {
    let envelope: EncryptedEnvelope =
        serde_json::from_slice(encoded).context("failed to decode encrypted envelope json")?;
    if envelope.schema_version != E2EE_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported encrypted envelope schema version: {}",
            envelope.schema_version
        ));
    }
    if envelope.protocol != "signal-envelope-v1" {
        return Err(anyhow!("unsupported encrypted envelope protocol"));
    }
    if envelope.sender_account_id.trim().is_empty()
        || envelope.sender_device_id.trim().is_empty()
        || envelope.recipient_account_id.trim().is_empty()
        || envelope.recipient_device_id.trim().is_empty()
    {
        return Err(anyhow!("envelope identity fields cannot be empty"));
    }
    if envelope.message_id.len() < 16 {
        return Err(anyhow!("invalid envelope message_id"));
    }

    PeerId::from_str(&envelope.sender_account_id).context("invalid sender_account_id")?;
    PeerId::from_str(&envelope.recipient_account_id).context("invalid recipient_account_id")?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&envelope.ciphertext_b64)
        .context("invalid envelope ciphertext_b64")?;
    if ciphertext.is_empty() {
        return Err(anyhow!("envelope ciphertext cannot be empty"));
    }
    base64::engine::general_purpose::STANDARD
        .decode(&envelope.aad_b64)
        .context("invalid envelope aad_b64")?;

    Ok(envelope)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreKeyMessageRecord {
    schema_version: u32,
    protocol: String,
    sender_account_id: String,
    sender_device_id: String,
    recipient_account_id: String,
    recipient_device_id: String,
    recipient_signed_pre_key_id: u32,
    recipient_one_time_pre_key_id: u32,
    session_id: String,
    sender_ephemeral_public_b64: String,
    message_id: String,
    created_at_unix: u64,
    nonce_b64: String,
    aad_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Serialize)]
struct PreKeyMessageMeta<'a> {
    protocol: &'a str,
    sender_account_id: &'a str,
    sender_device_id: &'a str,
    recipient_account_id: &'a str,
    recipient_device_id: &'a str,
    recipient_signed_pre_key_id: u32,
    recipient_one_time_pre_key_id: u32,
    message_id: &'a str,
}

pub fn build_prekey_message(
    profile_path: &Path,
    recipient_prekey_bundle_encoded: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.is_empty() {
        return Err(anyhow!("plaintext cannot be empty"));
    }

    let sender_profile = load_or_create_profile(profile_path)?;
    let recipient_bundle =
        validate_prekey_bundle(recipient_prekey_bundle_encoded, current_unix_seconds())?;
    if recipient_bundle.account_id.trim().is_empty() || recipient_bundle.device_id.trim().is_empty()
    {
        return Err(anyhow!(
            "recipient prekey bundle has empty account/device id"
        ));
    }

    let recipient_signed_pre_key_public = decode_base64_fixed_32(
        &recipient_bundle.signed_pre_key_public_b64,
        "recipient_bundle.signed_pre_key_public_b64",
    )?;
    let selected_one_time_pre_key = recipient_bundle
        .one_time_pre_keys
        .iter()
        .nth(rand::thread_rng().gen_range(0..recipient_bundle.one_time_pre_keys.len()))
        .ok_or_else(|| anyhow!("recipient prekey bundle has no selectable one-time pre-keys"))?;
    let recipient_one_time_pre_key_public = decode_base64_fixed_32(
        &selected_one_time_pre_key.public_key_b64,
        "recipient_bundle.one_time_pre_keys.public_key_b64",
    )?;
    let sender_ephemeral = generate_x25519_keypair(0);
    let shared_secret_signed =
        x25519_shared_secret(&sender_ephemeral.private, &recipient_signed_pre_key_public);
    let shared_secret_one_time = x25519_shared_secret(
        &sender_ephemeral.private,
        &recipient_one_time_pre_key_public,
    );
    let shared_secret =
        combine_prekey_shared_secrets(&shared_secret_signed, &shared_secret_one_time);
    let session_material = derive_session_material(
        &shared_secret,
        &sender_profile.account_id,
        &sender_profile.device_id,
        &recipient_bundle.account_id,
        &recipient_bundle.device_id,
        recipient_bundle.signed_pre_key_id,
        selected_one_time_pre_key.key_id,
    )?;

    let mut message_id_raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut message_id_raw);
    let message_id = hex::encode(message_id_raw);
    let mut nonce_raw = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_raw);
    let derived_key = derive_prekey_message_key(
        &shared_secret,
        &sender_profile.account_id,
        &recipient_bundle.account_id,
        selected_one_time_pre_key.key_id,
        &message_id,
    )?;
    let aad_compound = build_prekey_message_aad(
        PREKEY_MESSAGE_PROTOCOL,
        &sender_profile.account_id,
        &sender_profile.device_id,
        &recipient_bundle.account_id,
        &recipient_bundle.device_id,
        recipient_bundle.signed_pre_key_id,
        selected_one_time_pre_key.key_id,
        &message_id,
        aad,
    )?;
    let ciphertext = aead_encrypt(&derived_key, &nonce_raw, &aad_compound, plaintext)?;

    let record = PreKeyMessageRecord {
        schema_version: E2EE_SCHEMA_VERSION,
        protocol: PREKEY_MESSAGE_PROTOCOL.to_string(),
        sender_account_id: sender_profile.account_id,
        sender_device_id: sender_profile.device_id,
        recipient_account_id: recipient_bundle.account_id,
        recipient_device_id: recipient_bundle.device_id,
        recipient_signed_pre_key_id: recipient_bundle.signed_pre_key_id,
        recipient_one_time_pre_key_id: selected_one_time_pre_key.key_id,
        session_id: session_material.session_id.clone(),
        sender_ephemeral_public_b64: encode_bytes(sender_ephemeral.public.as_slice()),
        message_id,
        created_at_unix: current_unix_seconds(),
        nonce_b64: encode_bytes(&nonce_raw),
        aad_b64: encode_bytes(aad),
        ciphertext_b64: encode_bytes(&ciphertext),
    };

    upsert_session_from_prekey(
        profile_path,
        &record.sender_account_id,
        &record.sender_device_id,
        &record.recipient_account_id,
        &record.recipient_device_id,
        &session_material,
        true,
    )?;

    serde_json::to_vec(&record).context("failed to encode prekey message")
}

pub fn decrypt_prekey_message(profile_path: &Path, encoded_message: &[u8]) -> Result<Vec<u8>> {
    let profile = load_or_create_profile(profile_path)?;
    let mut state =
        load_or_create_signal_state(profile_path, &profile, DEFAULT_ONE_TIME_PREKEY_COUNT, false)?;
    let message = validate_prekey_message(encoded_message)?;

    if message.recipient_account_id != profile.account_id
        || message.recipient_device_id != profile.device_id
    {
        return Err(anyhow!(
            "prekey message is not addressed to this account/device"
        ));
    }
    let signed_pre_key_private_b64 =
        if message.recipient_signed_pre_key_id == state.signed_pre_key.key_id {
            state.signed_pre_key.private_b64.clone()
        } else {
            state
                .previous_signed_pre_keys
                .iter()
                .find(|value| value.key_id == message.recipient_signed_pre_key_id)
                .map(|value| value.private_b64.clone())
                .ok_or_else(|| {
                    anyhow!(
                        "prekey message targets unknown signed_pre_key_id: {}",
                        message.recipient_signed_pre_key_id
                    )
                })?
        };
    let recipient_one_time_pre_key = state
        .one_time_pre_keys
        .iter()
        .find(|value| value.key_id == message.recipient_one_time_pre_key_id)
        .ok_or_else(|| {
            anyhow!(
                "prekey message targets unknown or already consumed one-time pre-key id: {}",
                message.recipient_one_time_pre_key_id
            )
        })?;

    let sender_ephemeral_public = decode_base64_fixed_32(
        &message.sender_ephemeral_public_b64,
        "sender_ephemeral_public_b64",
    )?;
    let recipient_signed_pre_key_private =
        decode_base64_fixed_32(&signed_pre_key_private_b64, "signed_pre_key.private_b64")?;
    let recipient_one_time_pre_key_private = decode_base64_fixed_32(
        &recipient_one_time_pre_key.private_b64,
        "one_time_pre_key.private_b64",
    )?;
    let shared_secret_signed =
        x25519_shared_secret(&recipient_signed_pre_key_private, &sender_ephemeral_public);
    let shared_secret_one_time = x25519_shared_secret(
        &recipient_one_time_pre_key_private,
        &sender_ephemeral_public,
    );
    let shared_secret =
        combine_prekey_shared_secrets(&shared_secret_signed, &shared_secret_one_time);
    let session_material = derive_session_material(
        &shared_secret,
        &message.sender_account_id,
        &message.sender_device_id,
        &message.recipient_account_id,
        &message.recipient_device_id,
        message.recipient_signed_pre_key_id,
        message.recipient_one_time_pre_key_id,
    )?;
    if session_material.session_id != message.session_id {
        return Err(anyhow!("prekey message session_id verification failed"));
    }
    let derived_key = derive_prekey_message_key(
        &shared_secret,
        &message.sender_account_id,
        &message.recipient_account_id,
        message.recipient_one_time_pre_key_id,
        &message.message_id,
    )?;

    let nonce = decode_base64_fixed_12(&message.nonce_b64, "nonce_b64")?;
    let aad_user = decode_base64(&message.aad_b64, "aad_b64")?;
    let aad_compound = build_prekey_message_aad(
        PREKEY_MESSAGE_PROTOCOL,
        &message.sender_account_id,
        &message.sender_device_id,
        &message.recipient_account_id,
        &message.recipient_device_id,
        message.recipient_signed_pre_key_id,
        message.recipient_one_time_pre_key_id,
        &message.message_id,
        &aad_user,
    )?;
    let ciphertext = decode_base64(&message.ciphertext_b64, "ciphertext_b64")?;
    let plaintext = aead_decrypt(&derived_key, &nonce, &aad_compound, &ciphertext)?;

    upsert_session_from_prekey(
        profile_path,
        &message.recipient_account_id,
        &message.recipient_device_id,
        &message.sender_account_id,
        &message.sender_device_id,
        &session_material,
        false,
    )?;
    consume_one_time_pre_key(&mut state, message.recipient_one_time_pre_key_id)?;
    maybe_replenish_one_time_pre_keys(&mut state, DEFAULT_ONE_TIME_PREKEY_COUNT)?;
    persist_signal_state(&signal_state_path(profile_path), &state)?;

    Ok(plaintext)
}

pub fn validate_prekey_message(encoded_message: &[u8]) -> Result<PreKeyMessageRecord> {
    let message: PreKeyMessageRecord =
        serde_json::from_slice(encoded_message).context("failed to decode prekey message json")?;
    if message.schema_version != E2EE_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported prekey message schema version: {}",
            message.schema_version
        ));
    }
    if message.protocol != PREKEY_MESSAGE_PROTOCOL {
        return Err(anyhow!("unsupported prekey message protocol"));
    }
    if message.sender_account_id.trim().is_empty()
        || message.sender_device_id.trim().is_empty()
        || message.recipient_account_id.trim().is_empty()
        || message.recipient_device_id.trim().is_empty()
    {
        return Err(anyhow!(
            "prekey message account/device fields cannot be empty"
        ));
    }
    if message.recipient_signed_pre_key_id == 0 {
        return Err(anyhow!(
            "prekey message recipient_signed_pre_key_id cannot be zero"
        ));
    }
    if message.recipient_one_time_pre_key_id == 0 {
        return Err(anyhow!(
            "prekey message recipient_one_time_pre_key_id cannot be zero"
        ));
    }
    if message.session_id.len() < 16 {
        return Err(anyhow!("invalid prekey message session_id"));
    }
    if message.message_id.len() < 16 {
        return Err(anyhow!("invalid prekey message_id"));
    }

    PeerId::from_str(&message.sender_account_id).context("invalid sender_account_id")?;
    PeerId::from_str(&message.recipient_account_id).context("invalid recipient_account_id")?;
    decode_base64_fixed_32(
        &message.sender_ephemeral_public_b64,
        "sender_ephemeral_public_b64",
    )?;
    decode_base64_fixed_12(&message.nonce_b64, "nonce_b64")?;
    let ciphertext = decode_base64(&message.ciphertext_b64, "ciphertext_b64")?;
    if ciphertext.is_empty() {
        return Err(anyhow!("prekey message ciphertext cannot be empty"));
    }
    decode_base64(&message.aad_b64, "aad_b64")?;

    Ok(message)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionMessageRecord {
    schema_version: u32,
    protocol: String,
    session_id: String,
    sender_account_id: String,
    sender_device_id: String,
    recipient_account_id: String,
    recipient_device_id: String,
    counter: u64,
    message_id: String,
    created_at_unix: u64,
    nonce_b64: String,
    aad_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Serialize)]
struct SessionMessageMeta<'a> {
    protocol: &'a str,
    session_id: &'a str,
    sender_account_id: &'a str,
    sender_device_id: &'a str,
    recipient_account_id: &'a str,
    recipient_device_id: &'a str,
    counter: u64,
    message_id: &'a str,
}

pub fn build_session_message(
    profile_path: &Path,
    session_id: &str,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.is_empty() {
        return Err(anyhow!("plaintext cannot be empty"));
    }
    if session_id.trim().is_empty() {
        return Err(anyhow!("session_id cannot be empty"));
    }

    let mut store = load_or_create_session_store(profile_path)?;
    let (
        counter,
        session_id_value,
        sender_account_id,
        sender_device_id,
        recipient_account_id,
        recipient_device_id,
    ) = {
        let session = find_session_mut(&mut store, session_id)
            .ok_or_else(|| anyhow!("session not found for id: {session_id}"))?;
        (
            session.send_counter.saturating_add(1),
            session.session_id.clone(),
            session.local_account_id.clone(),
            session.local_device_id.clone(),
            session.peer_account_id.clone(),
            session.peer_device_id.clone(),
        )
    };
    let mut message_id_raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut message_id_raw);
    let message_id = hex::encode(message_id_raw);
    let mut nonce_raw = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_raw);
    let chain_key = {
        let session = find_session_mut(&mut store, session_id)
            .ok_or_else(|| anyhow!("session not found for id: {session_id}"))?;
        decode_base64_fixed_32(&session.send_chain_key_b64, "send_chain_key_b64")?
    };
    let derived_key = derive_session_message_key(&chain_key, &session_id_value, counter)?;
    let aad_compound = build_session_message_aad(
        &session_id_value,
        &sender_account_id,
        &sender_device_id,
        &recipient_account_id,
        &recipient_device_id,
        counter,
        &message_id,
        aad,
    )?;
    let ciphertext = aead_encrypt(&derived_key, &nonce_raw, &aad_compound, plaintext)?;

    {
        let session = find_session_mut(&mut store, session_id)
            .ok_or_else(|| anyhow!("session not found for id: {session_id}"))?;
        session.send_counter = counter;
    }
    persist_session_store(profile_path, &store)?;

    let record = SessionMessageRecord {
        schema_version: E2EE_SCHEMA_VERSION,
        protocol: SESSION_MESSAGE_PROTOCOL.to_string(),
        session_id: session_id_value,
        sender_account_id,
        sender_device_id,
        recipient_account_id,
        recipient_device_id,
        counter,
        message_id,
        created_at_unix: current_unix_seconds(),
        nonce_b64: encode_bytes(&nonce_raw),
        aad_b64: encode_bytes(aad),
        ciphertext_b64: encode_bytes(&ciphertext),
    };

    serde_json::to_vec(&record).context("failed to encode session message")
}

pub fn decrypt_session_message(profile_path: &Path, encoded_message: &[u8]) -> Result<Vec<u8>> {
    let message = validate_session_message(encoded_message)?;
    let mut store = load_or_create_session_store(profile_path)?;
    let session = find_session_mut(&mut store, &message.session_id)
        .ok_or_else(|| anyhow!("session not found for id: {}", message.session_id))?;

    if session.local_account_id != message.recipient_account_id
        || session.local_device_id != message.recipient_device_id
    {
        return Err(anyhow!(
            "session message is not addressed to this local session owner"
        ));
    }
    if session.peer_account_id != message.sender_account_id
        || session.peer_device_id != message.sender_device_id
    {
        return Err(anyhow!(
            "session message sender does not match stored peer identity"
        ));
    }
    if message.counter <= session.recv_counter {
        return Err(anyhow!(
            "session message replay or out-of-order detected: counter={} recv_counter={}",
            message.counter,
            session.recv_counter
        ));
    }

    let chain_key = decode_base64_fixed_32(&session.recv_chain_key_b64, "recv_chain_key_b64")?;
    let derived_key = derive_session_message_key(&chain_key, &session.session_id, message.counter)?;
    let nonce = decode_base64_fixed_12(&message.nonce_b64, "nonce_b64")?;
    let aad_user = decode_base64(&message.aad_b64, "aad_b64")?;
    let aad_compound = build_session_message_aad(
        &message.session_id,
        &message.sender_account_id,
        &message.sender_device_id,
        &message.recipient_account_id,
        &message.recipient_device_id,
        message.counter,
        &message.message_id,
        &aad_user,
    )?;
    let ciphertext = decode_base64(&message.ciphertext_b64, "ciphertext_b64")?;
    let plaintext = aead_decrypt(&derived_key, &nonce, &aad_compound, &ciphertext)?;

    session.recv_counter = message.counter;
    persist_session_store(profile_path, &store)?;
    Ok(plaintext)
}

pub fn validate_session_message(encoded_message: &[u8]) -> Result<SessionMessageRecord> {
    let message: SessionMessageRecord =
        serde_json::from_slice(encoded_message).context("failed to decode session message json")?;

    if message.schema_version != E2EE_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported session message schema version: {}",
            message.schema_version
        ));
    }
    if message.protocol != SESSION_MESSAGE_PROTOCOL {
        return Err(anyhow!("unsupported session message protocol"));
    }
    if message.session_id.trim().is_empty()
        || message.sender_account_id.trim().is_empty()
        || message.sender_device_id.trim().is_empty()
        || message.recipient_account_id.trim().is_empty()
        || message.recipient_device_id.trim().is_empty()
    {
        return Err(anyhow!("session message fields cannot be empty"));
    }
    if message.counter == 0 {
        return Err(anyhow!("session message counter must be positive"));
    }
    if message.message_id.len() < 16 {
        return Err(anyhow!("invalid session message_id"));
    }

    PeerId::from_str(&message.sender_account_id).context("invalid sender_account_id")?;
    PeerId::from_str(&message.recipient_account_id).context("invalid recipient_account_id")?;
    decode_base64_fixed_12(&message.nonce_b64, "nonce_b64")?;
    decode_base64(&message.aad_b64, "aad_b64")?;
    let ciphertext = decode_base64(&message.ciphertext_b64, "ciphertext_b64")?;
    if ciphertext.is_empty() {
        return Err(anyhow!("session message ciphertext cannot be empty"));
    }

    Ok(message)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptedMessageKind {
    PreKey,
    Session,
}

#[derive(Debug, Clone)]
pub struct DecryptedMessage {
    pub plaintext: Vec<u8>,
    pub kind: DecryptedMessageKind,
}

#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub payload: Vec<u8>,
    pub session_id: String,
    pub used_session: bool,
}

pub fn build_message_auto(
    profile_path: &Path,
    recipient_prekey_bundle_encoded: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<OutboundMessage> {
    let profile = load_or_create_profile(profile_path)?;
    let recipient_bundle =
        validate_prekey_bundle(recipient_prekey_bundle_encoded, current_unix_seconds())?;
    if !has_complete_libsignal_bundle_fields(&recipient_bundle) {
        return Err(anyhow!(
            "recipient prekey bundle is missing libsignal fields; auto mode requires official libsignal bundle"
        ));
    }
    build_libsignal_message_auto(profile_path, &profile, &recipient_bundle, plaintext, aad)
}

pub fn decrypt_message_auto(profile_path: &Path, payload: &[u8]) -> Result<DecryptedMessage> {
    if validate_libsignal_message(payload).is_err() {
        return Err(anyhow!(
            "payload is not a valid libsignal auto message; legacy auto decrypt path is disabled"
        ));
    }
    decrypt_libsignal_message_auto(profile_path, payload)
}

fn keypair_from_seed(seed: &[u8; IDENTITY_SEED_LEN]) -> Result<identity::Keypair> {
    let secret = identity::ed25519::SecretKey::try_from_bytes(*seed)
        .map_err(|err| anyhow!("invalid key seed: {err}"))?;
    let keypair = identity::ed25519::Keypair::from(secret);
    Ok(identity::Keypair::from(keypair))
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredSignalState {
    schema_version: u32,
    registration_id: u32,
    identity_private_b64: String,
    identity_public_b64: String,
    signed_pre_key: StoredSignalKeyPair,
    signed_pre_key_signature_b64: String,
    #[serde(default)]
    previous_signed_pre_keys: Vec<StoredSignalKeyPair>,
    #[serde(default = "default_signed_pre_key_generated_at_unix")]
    signed_pre_key_generated_at_unix: u64,
    #[serde(default = "default_next_signed_pre_key_id")]
    next_signed_pre_key_id: u32,
    one_time_pre_keys: Vec<StoredSignalKeyPair>,
    #[serde(default = "default_next_one_time_pre_key_id")]
    next_one_time_pre_key_id: u32,
    #[serde(default = "default_key_update_revision")]
    key_update_revision: u64,
    generated_at_unix: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredSignalKeyPair {
    key_id: u32,
    private_b64: String,
    public_b64: String,
}

fn default_next_one_time_pre_key_id() -> u32 {
    ONE_TIME_PREKEY_START_ID
}

fn default_signed_pre_key_generated_at_unix() -> u64 {
    0
}

fn default_next_signed_pre_key_id() -> u32 {
    SIGNED_PREKEY_START_ID + 1
}

fn default_key_update_revision() -> u64 {
    1
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoredLibsignalState {
    schema_version: u32,
    registration_id: u32,
    identity_key_pair_b64: String,
    next_pre_key_id: u32,
    next_signed_pre_key_id: u32,
    next_kyber_pre_key_id: u32,
    active_signed_pre_key_id: u32,
    active_kyber_pre_key_id: u32,
    pre_keys: Vec<StoredLibsignalKeyRecord>,
    signed_pre_keys: Vec<StoredLibsignalKeyRecord>,
    kyber_pre_keys: Vec<StoredLibsignalKeyRecord>,
    sessions: Vec<StoredLibsignalSessionRecord>,
    trusted_identities: Vec<StoredLibsignalIdentityRecord>,
    generated_at_unix: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredLibsignalKeyRecord {
    key_id: u32,
    record_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredLibsignalSessionRecord {
    peer_account_id: String,
    peer_device_id: String,
    record_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredLibsignalIdentityRecord {
    peer_account_id: String,
    peer_device_id: String,
    identity_key_b64: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct StoredSessionStore {
    schema_version: u32,
    sessions: Vec<StoredSessionRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredSessionRecord {
    session_id: String,
    local_account_id: String,
    local_device_id: String,
    peer_account_id: String,
    peer_device_id: String,
    send_chain_key_b64: String,
    recv_chain_key_b64: String,
    send_counter: u64,
    recv_counter: u64,
    established_at_unix: u64,
}

struct SessionMaterial {
    session_id: String,
    initiator_to_responder_chain_key: [u8; 32],
    responder_to_initiator_chain_key: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
struct UnsignedPreKeyBundleRecord {
    schema_version: u32,
    account_id: String,
    account_public_key_b64: String,
    device_id: String,
    registration_id: u32,
    identity_key_b64: String,
    signed_pre_key_id: u32,
    signed_pre_key_public_b64: String,
    signed_pre_key_signature_b64: String,
    one_time_pre_keys: Vec<PreKeyPublicRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_identity_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_pre_key_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_pre_key_public_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_signed_pre_key_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_signed_pre_key_public_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_signed_pre_key_signature_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_kyber_pre_key_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_kyber_pre_key_public_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_kyber_pre_key_signature_b64: Option<String>,
    generated_at_unix: u64,
    expires_at_unix: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreKeyBundleRecord {
    schema_version: u32,
    account_id: String,
    account_public_key_b64: String,
    device_id: String,
    registration_id: u32,
    identity_key_b64: String,
    signed_pre_key_id: u32,
    signed_pre_key_public_b64: String,
    signed_pre_key_signature_b64: String,
    one_time_pre_keys: Vec<PreKeyPublicRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_identity_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_pre_key_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_pre_key_public_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_signed_pre_key_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_signed_pre_key_public_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_signed_pre_key_signature_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_kyber_pre_key_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_kyber_pre_key_public_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    libsignal_kyber_pre_key_signature_b64: Option<String>,
    generated_at_unix: u64,
    expires_at_unix: u64,
    account_signature_b64: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PreKeyPublicRecord {
    key_id: u32,
    public_key_b64: String,
}

pub fn build_prekey_bundle(
    profile_path: &Path,
    one_time_prekey_count: usize,
    ttl_seconds: u64,
) -> Result<Vec<u8>> {
    let profile = load_or_create_profile(profile_path)?;
    let state =
        load_or_create_signal_state(profile_path, &profile, one_time_prekey_count.max(1), true)?;
    let account_keypair = keypair_from_seed(&profile.account_seed)?;
    let account_public_key_b64 = base64::engine::general_purpose::STANDARD
        .encode(account_keypair.public().encode_protobuf());

    let one_time_pre_keys = state
        .one_time_pre_keys
        .iter()
        .map(|value| PreKeyPublicRecord {
            key_id: value.key_id,
            public_key_b64: value.public_b64.clone(),
        })
        .collect::<Vec<_>>();
    if one_time_pre_keys.is_empty() {
        return Err(anyhow!("no one-time pre-keys available"));
    }

    let target_prekey = one_time_prekey_count.max(1);
    let (mut libsignal_state, mut libsignal_store) =
        load_or_create_libsignal_store(profile_path, target_prekey)?;

    let libsignal_fields = {
        replenish_libsignal_prekeys_if_needed(
            &mut libsignal_state,
            &mut libsignal_store,
            target_prekey,
        )?;
        let pre_key_id = libsignal_store
            .all_pre_key_ids()
            .next()
            .copied()
            .ok_or_else(|| anyhow!("libsignal store has no pre-keys"))?;
        let pre_key_record = libsignal_store
            .get_pre_key(pre_key_id)
            .await_blocking()
            .map_err(|e| anyhow!("get_pre_key: {}", e))?;
        let pre_key_public_b64 = encode_bytes(
            &pre_key_record
                .public_key()
                .map_err(|e| anyhow!("pre_key public: {}", e))?
                .serialize(),
        );
        let signed_pre_key_id = libsignal_state.active_signed_pre_key_id;
        let signed_pre_key_record = libsignal_store
            .get_signed_pre_key(signed_pre_key_id.into())
            .await_blocking()
            .map_err(|e| anyhow!("get_signed_pre_key: {}", e))?;
        let signed_pre_key_public_b64 = encode_bytes(
            &signed_pre_key_record
                .public_key()
                .map_err(|e| anyhow!("signed_pre_key public: {}", e))?
                .serialize(),
        );
        let signed_pre_key_signature_b64 = encode_bytes(
            &signed_pre_key_record
                .signature()
                .map_err(|e| anyhow!("signed_pre_key signature: {}", e))?,
        );
        let kyber_pre_key_id = libsignal_state.active_kyber_pre_key_id;
        let kyber_pre_key_record = libsignal_store
            .get_kyber_pre_key(kyber_pre_key_id.into())
            .await_blocking()
            .map_err(|e| anyhow!("get_kyber_pre_key: {}", e))?;
        let kyber_pre_key_public_b64 = encode_bytes(
            &kyber_pre_key_record
                .public_key()
                .map_err(|e| anyhow!("kyber_pre_key public: {}", e))?
                .serialize(),
        );
        let kyber_pre_key_signature_b64 = encode_bytes(
            &kyber_pre_key_record
                .signature()
                .map_err(|e| anyhow!("kyber_pre_key signature: {}", e))?,
        );
        let identity_key_pair = libsignal_store
            .get_identity_key_pair()
            .await_blocking()
            .map_err(|e| anyhow!("get_identity_key_pair: {}", e))?;
        let libsignal_identity_key_b64 =
            encode_bytes(identity_key_pair.identity_key().serialize().as_ref());
        (
            libsignal_identity_key_b64,
            pre_key_id.into(),
            pre_key_public_b64,
            signed_pre_key_id,
            signed_pre_key_public_b64,
            signed_pre_key_signature_b64,
            kyber_pre_key_id,
            kyber_pre_key_public_b64,
            kyber_pre_key_signature_b64,
        )
    };

    let generated_at_unix = current_unix_seconds();
    let expires_at_unix = generated_at_unix.saturating_add(ttl_seconds.max(1));
    let (
        libsignal_identity_key_b64,
        libsignal_pre_key_id,
        libsignal_pre_key_public_b64,
        libsignal_signed_pre_key_id,
        libsignal_signed_pre_key_public_b64,
        libsignal_signed_pre_key_signature_b64,
        libsignal_kyber_pre_key_id,
        libsignal_kyber_pre_key_public_b64,
        libsignal_kyber_pre_key_signature_b64,
    ) = libsignal_fields;

    let unsigned = UnsignedPreKeyBundleRecord {
        schema_version: E2EE_SCHEMA_VERSION,
        account_id: profile.account_id,
        account_public_key_b64,
        device_id: profile.device_id,
        registration_id: state.registration_id,
        identity_key_b64: state.identity_public_b64,
        signed_pre_key_id: state.signed_pre_key.key_id,
        signed_pre_key_public_b64: state.signed_pre_key.public_b64,
        signed_pre_key_signature_b64: state.signed_pre_key_signature_b64,
        one_time_pre_keys,
        libsignal_identity_key_b64: Some(libsignal_identity_key_b64),
        libsignal_pre_key_id: Some(libsignal_pre_key_id),
        libsignal_pre_key_public_b64: Some(libsignal_pre_key_public_b64),
        libsignal_signed_pre_key_id: Some(libsignal_signed_pre_key_id),
        libsignal_signed_pre_key_public_b64: Some(libsignal_signed_pre_key_public_b64),
        libsignal_signed_pre_key_signature_b64: Some(libsignal_signed_pre_key_signature_b64),
        libsignal_kyber_pre_key_id: Some(libsignal_kyber_pre_key_id),
        libsignal_kyber_pre_key_public_b64: Some(libsignal_kyber_pre_key_public_b64),
        libsignal_kyber_pre_key_signature_b64: Some(libsignal_kyber_pre_key_signature_b64),
        generated_at_unix,
        expires_at_unix,
    };

    let unsigned_bytes =
        serde_json::to_vec(&unsigned).context("failed to encode unsigned prekey bundle")?;
    let signature = account_keypair
        .sign(&unsigned_bytes)
        .context("failed to sign prekey bundle")?;
    let record = PreKeyBundleRecord {
        schema_version: unsigned.schema_version,
        account_id: unsigned.account_id,
        account_public_key_b64: unsigned.account_public_key_b64,
        device_id: unsigned.device_id,
        registration_id: unsigned.registration_id,
        identity_key_b64: unsigned.identity_key_b64,
        signed_pre_key_id: unsigned.signed_pre_key_id,
        signed_pre_key_public_b64: unsigned.signed_pre_key_public_b64,
        signed_pre_key_signature_b64: unsigned.signed_pre_key_signature_b64,
        one_time_pre_keys: unsigned.one_time_pre_keys,
        libsignal_identity_key_b64: unsigned.libsignal_identity_key_b64,
        libsignal_pre_key_id: unsigned.libsignal_pre_key_id,
        libsignal_pre_key_public_b64: unsigned.libsignal_pre_key_public_b64,
        libsignal_signed_pre_key_id: unsigned.libsignal_signed_pre_key_id,
        libsignal_signed_pre_key_public_b64: unsigned.libsignal_signed_pre_key_public_b64,
        libsignal_signed_pre_key_signature_b64: unsigned.libsignal_signed_pre_key_signature_b64,
        libsignal_kyber_pre_key_id: unsigned.libsignal_kyber_pre_key_id,
        libsignal_kyber_pre_key_public_b64: unsigned.libsignal_kyber_pre_key_public_b64,
        libsignal_kyber_pre_key_signature_b64: unsigned.libsignal_kyber_pre_key_signature_b64,
        generated_at_unix: unsigned.generated_at_unix,
        expires_at_unix: unsigned.expires_at_unix,
        account_signature_b64: base64::engine::general_purpose::STANDARD.encode(signature),
    };

    capture_libsignal_store_state(&mut libsignal_state, &mut libsignal_store, None)?;
    persist_libsignal_state(&libsignal_state_path(profile_path), &libsignal_state)?;

    serde_json::to_vec(&record).context("failed to encode signed prekey bundle")
}

pub fn validate_prekey_bundle(encoded: &[u8], now_unix: u64) -> Result<PreKeyBundleRecord> {
    let record: PreKeyBundleRecord =
        serde_json::from_slice(encoded).context("failed to decode prekey bundle json")?;

    if record.schema_version != E2EE_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported prekey bundle schema version: {}",
            record.schema_version
        ));
    }
    if record.account_id.trim().is_empty() || record.device_id.trim().is_empty() {
        return Err(anyhow!("account_id/device_id cannot be empty"));
    }
    if record.expires_at_unix <= record.generated_at_unix {
        return Err(anyhow!(
            "prekey bundle expires_at_unix must be greater than generated_at_unix"
        ));
    }
    if now_unix > record.expires_at_unix {
        return Err(anyhow!("prekey bundle has expired"));
    }
    if record.one_time_pre_keys.is_empty() {
        return Err(anyhow!("prekey bundle does not contain one-time pre-keys"));
    }

    PeerId::from_str(&record.account_id).context("invalid account_id PeerId")?;
    let account_public_key_bytes =
        decode_base64(&record.account_public_key_b64, "account_public_key_b64")?;
    let account_public_key = identity::PublicKey::try_decode_protobuf(&account_public_key_bytes)
        .context("invalid account_public_key")?;
    let derived_account_id = PeerId::from(account_public_key.clone()).to_string();
    if derived_account_id != record.account_id {
        return Err(anyhow!("account_id does not match account_public_key"));
    }

    let libsignal_fields = [
        record.libsignal_identity_key_b64.is_some(),
        record.libsignal_pre_key_id.is_some(),
        record.libsignal_pre_key_public_b64.is_some(),
        record.libsignal_signed_pre_key_id.is_some(),
        record.libsignal_signed_pre_key_public_b64.is_some(),
        record.libsignal_signed_pre_key_signature_b64.is_some(),
        record.libsignal_kyber_pre_key_id.is_some(),
        record.libsignal_kyber_pre_key_public_b64.is_some(),
        record.libsignal_kyber_pre_key_signature_b64.is_some(),
    ];
    let any_libsignal = libsignal_fields.iter().any(|&x| x);
    let all_libsignal = libsignal_fields.iter().all(|&x| x);
    if any_libsignal && !all_libsignal {
        return Err(anyhow!(
            "libsignal fields must be all-or-none: all 9 must be present or all absent"
        ));
    }

    decode_base64_fixed_32(&record.identity_key_b64, "identity_key_b64")?;
    let signed_pre_key_public = decode_base64_fixed_32(
        &record.signed_pre_key_public_b64,
        "signed_pre_key_public_b64",
    )?;
    let signed_pre_key_signature = decode_base64(
        &record.signed_pre_key_signature_b64,
        "signed_pre_key_signature_b64",
    )?;
    let signed_pre_key_signed_payload = signed_pre_key_payload(
        record.signed_pre_key_id,
        record.registration_id,
        &signed_pre_key_public,
    );
    if !account_public_key.verify(&signed_pre_key_signed_payload, &signed_pre_key_signature) {
        if all_libsignal {
            tracing::warn!(
                target: "e2ee",
                account_id = %record.account_id,
                "legacy signed pre-key signature verification failed; accepting due to complete libsignal fields"
            );
        } else {
            return Err(anyhow!("signed pre-key signature verification failed"));
        }
    }

    for pre_key in &record.one_time_pre_keys {
        if pre_key.key_id == 0 {
            return Err(anyhow!("one-time pre-key id cannot be zero"));
        }
        decode_base64_fixed_32(&pre_key.public_key_b64, "one_time_pre_key.public_key_b64")?;
    }

    if all_libsignal {
        if record.libsignal_pre_key_id.map_or(true, |id| id == 0) {
            return Err(anyhow!(
                "libsignal_pre_key_id must be > 0 when libsignal fields present"
            ));
        }
        if record
            .libsignal_signed_pre_key_id
            .map_or(true, |id| id == 0)
        {
            return Err(anyhow!(
                "libsignal_signed_pre_key_id must be > 0 when libsignal fields present"
            ));
        }
        if record.libsignal_kyber_pre_key_id.map_or(true, |id| id == 0) {
            return Err(anyhow!(
                "libsignal_kyber_pre_key_id must be > 0 when libsignal fields present"
            ));
        }
        decode_base64(
            record.libsignal_identity_key_b64.as_ref().unwrap(),
            "libsignal_identity_key_b64",
        )?;
        decode_base64(
            record.libsignal_pre_key_public_b64.as_ref().unwrap(),
            "libsignal_pre_key_public_b64",
        )?;
        decode_base64(
            record.libsignal_signed_pre_key_public_b64.as_ref().unwrap(),
            "libsignal_signed_pre_key_public_b64",
        )?;
        decode_base64(
            record
                .libsignal_signed_pre_key_signature_b64
                .as_ref()
                .unwrap(),
            "libsignal_signed_pre_key_signature_b64",
        )?;
        decode_base64(
            record.libsignal_kyber_pre_key_public_b64.as_ref().unwrap(),
            "libsignal_kyber_pre_key_public_b64",
        )?;
        decode_base64(
            record
                .libsignal_kyber_pre_key_signature_b64
                .as_ref()
                .unwrap(),
            "libsignal_kyber_pre_key_signature_b64",
        )?;
    }

    let account_signature = decode_base64(&record.account_signature_b64, "account_signature_b64")?;
    let unsigned = UnsignedPreKeyBundleRecord {
        schema_version: record.schema_version,
        account_id: record.account_id.clone(),
        account_public_key_b64: record.account_public_key_b64.clone(),
        device_id: record.device_id.clone(),
        registration_id: record.registration_id,
        identity_key_b64: record.identity_key_b64.clone(),
        signed_pre_key_id: record.signed_pre_key_id,
        signed_pre_key_public_b64: record.signed_pre_key_public_b64.clone(),
        signed_pre_key_signature_b64: record.signed_pre_key_signature_b64.clone(),
        one_time_pre_keys: record.one_time_pre_keys.clone(),
        libsignal_identity_key_b64: record.libsignal_identity_key_b64.clone(),
        libsignal_pre_key_id: record.libsignal_pre_key_id,
        libsignal_pre_key_public_b64: record.libsignal_pre_key_public_b64.clone(),
        libsignal_signed_pre_key_id: record.libsignal_signed_pre_key_id,
        libsignal_signed_pre_key_public_b64: record.libsignal_signed_pre_key_public_b64.clone(),
        libsignal_signed_pre_key_signature_b64: record
            .libsignal_signed_pre_key_signature_b64
            .clone(),
        libsignal_kyber_pre_key_id: record.libsignal_kyber_pre_key_id,
        libsignal_kyber_pre_key_public_b64: record.libsignal_kyber_pre_key_public_b64.clone(),
        libsignal_kyber_pre_key_signature_b64: record.libsignal_kyber_pre_key_signature_b64.clone(),
        generated_at_unix: record.generated_at_unix,
        expires_at_unix: record.expires_at_unix,
    };
    let unsigned_bytes = serde_json::to_vec(&unsigned)
        .context("failed to encode unsigned prekey bundle for verification")?;
    if !account_public_key.verify(&unsigned_bytes, &account_signature) {
        return Err(anyhow!(
            "prekey bundle account signature verification failed"
        ));
    }

    Ok(record)
}

fn load_or_create_signal_state(
    profile_path: &Path,
    profile: &IdentityProfile,
    one_time_prekey_count: usize,
    rotate_signed_pre_key: bool,
) -> Result<StoredSignalState> {
    let path = signal_state_path(profile_path);
    if path.exists() {
        let mut state = load_signal_state(&path)?;
        if !signal_state_matches_profile(&state, profile)? {
            tracing::warn!(
                target: "e2ee",
                "signal state does not match profile identity/account; regenerating state"
            );
            return create_signal_state(&path, profile, one_time_prekey_count);
        }
        let mut changed = false;
        if rotate_signed_pre_key
            && maybe_rotate_signed_pre_key(
                &mut state,
                profile,
                DEFAULT_SIGNED_PREKEY_ROTATION_SECONDS,
            )?
        {
            changed = true;
        }
        if maybe_replenish_one_time_pre_keys(&mut state, one_time_prekey_count.max(1))? {
            changed = true;
        }
        if changed {
            persist_signal_state(&path, &state)?;
        }
        return Ok(state);
    }

    create_signal_state(&path, profile, one_time_prekey_count)
}

fn signal_state_matches_profile(state: &StoredSignalState, profile: &IdentityProfile) -> Result<bool> {
    let identity_private = decode_base64_fixed_32(&state.identity_private_b64, "identity_private_b64")?;
    if identity_private != profile.signal_identity_seed {
        return Ok(false);
    }
    let expected_public = x25519_public_from_private(&profile.signal_identity_seed);
    let identity_public = decode_base64_fixed_32(&state.identity_public_b64, "identity_public_b64")?;
    if identity_public != expected_public {
        return Ok(false);
    }

    let account_keypair = keypair_from_seed(&profile.account_seed)?;
    let signed_public = decode_base64_fixed_32(&state.signed_pre_key.public_b64, "signed_pre_key.public_b64")?;
    let signed_signature = decode_base64(
        &state.signed_pre_key_signature_b64,
        "signed_pre_key_signature_b64",
    )?;
    let payload = signed_pre_key_payload(
        state.signed_pre_key.key_id,
        state.registration_id,
        &signed_public,
    );
    Ok(account_keypair.public().verify(&payload, &signed_signature))
}

fn load_signal_state(path: &Path) -> Result<StoredSignalState> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read signal state: {}", path.display()))?;
    let mut state: StoredSignalState = serde_json::from_str(&raw)
        .with_context(|| format!("invalid signal state json: {}", path.display()))?;
    let changed = ensure_signal_state_defaults(&mut state)?;
    validate_signal_state(&state)?;
    if changed {
        persist_signal_state(path, &state)?;
    }
    Ok(state)
}

fn create_signal_state(
    path: &Path,
    profile: &IdentityProfile,
    one_time_prekey_count: usize,
) -> Result<StoredSignalState> {
    let one_time_prekey_count = one_time_prekey_count.max(1);
    let registration_id: u32 = rand::thread_rng().r#gen::<u16>() as u32 & 0x3fff;
    let identity_private = profile.signal_identity_seed;
    let identity_public = x25519_public_from_private(&identity_private);

    let signed_pre_key_id = SIGNED_PREKEY_START_ID;
    let signed_pre_key_pair = generate_x25519_keypair(signed_pre_key_id);
    let account_keypair = keypair_from_seed(&profile.account_seed)?;
    let signed_pre_key_signature = account_keypair
        .sign(&signed_pre_key_payload(
            signed_pre_key_id,
            registration_id,
            &signed_pre_key_pair.public,
        ))
        .context("failed to sign signal signed pre-key")?;

    let mut one_time_pre_keys = Vec::with_capacity(one_time_prekey_count);
    for index in 0..one_time_prekey_count {
        let key_id = ONE_TIME_PREKEY_START_ID
            .checked_add(index as u32)
            .ok_or_else(|| anyhow!("one-time pre-key id overflow"))?;
        one_time_pre_keys.push(generate_x25519_keypair(key_id));
    }
    let next_one_time_pre_key_id = one_time_pre_keys
        .iter()
        .map(|value| value.key_id)
        .max()
        .unwrap_or(ONE_TIME_PREKEY_START_ID.saturating_sub(1))
        .checked_add(1)
        .ok_or_else(|| anyhow!("one-time pre-key id overflow"))?;

    let state = StoredSignalState {
        schema_version: SIGNAL_STATE_SCHEMA_VERSION,
        registration_id,
        identity_private_b64: encode_bytes(identity_private.as_slice()),
        identity_public_b64: encode_bytes(identity_public.as_slice()),
        signed_pre_key: StoredSignalKeyPair {
            key_id: signed_pre_key_pair.key_id,
            private_b64: encode_bytes(signed_pre_key_pair.private.as_slice()),
            public_b64: encode_bytes(signed_pre_key_pair.public.as_slice()),
        },
        signed_pre_key_signature_b64: encode_bytes(&signed_pre_key_signature),
        one_time_pre_keys: one_time_pre_keys
            .into_iter()
            .map(|pair| StoredSignalKeyPair {
                key_id: pair.key_id,
                private_b64: encode_bytes(pair.private.as_slice()),
                public_b64: encode_bytes(pair.public.as_slice()),
            })
            .collect(),
        previous_signed_pre_keys: Vec::new(),
        signed_pre_key_generated_at_unix: current_unix_seconds(),
        next_signed_pre_key_id: signed_pre_key_id.saturating_add(1),
        next_one_time_pre_key_id,
        key_update_revision: default_key_update_revision(),
        generated_at_unix: current_unix_seconds(),
    };

    validate_signal_state(&state)?;
    persist_signal_state(path, &state)?;
    Ok(state)
}

fn ensure_signal_state_defaults(state: &mut StoredSignalState) -> Result<bool> {
    let mut changed = false;

    let max_key_id = state
        .one_time_pre_keys
        .iter()
        .map(|value| value.key_id)
        .max()
        .unwrap_or(ONE_TIME_PREKEY_START_ID.saturating_sub(1));
    let minimum_next = max_key_id
        .checked_add(1)
        .ok_or_else(|| anyhow!("one-time pre-key id overflow"))?;
    if state.next_one_time_pre_key_id < minimum_next || state.next_one_time_pre_key_id == 0 {
        state.next_one_time_pre_key_id = minimum_next;
        changed = true;
    }

    if state.signed_pre_key_generated_at_unix == 0 {
        state.signed_pre_key_generated_at_unix = if state.generated_at_unix == 0 {
            current_unix_seconds()
        } else {
            state.generated_at_unix
        };
        changed = true;
    }
    let minimum_next_signed = state
        .signed_pre_key
        .key_id
        .checked_add(1)
        .ok_or_else(|| anyhow!("signed pre-key id overflow"))?;
    if state.next_signed_pre_key_id < minimum_next_signed || state.next_signed_pre_key_id == 0 {
        state.next_signed_pre_key_id = minimum_next_signed;
        changed = true;
    }
    if state.key_update_revision == 0 {
        state.key_update_revision = default_key_update_revision();
        changed = true;
    }

    Ok(changed)
}

fn validate_signal_state(state: &StoredSignalState) -> Result<()> {
    if state.schema_version != SIGNAL_STATE_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported signal state schema version: {}",
            state.schema_version
        ));
    }
    if state.registration_id == 0 {
        return Err(anyhow!("signal state registration_id cannot be zero"));
    }
    if state.next_signed_pre_key_id == 0 {
        return Err(anyhow!(
            "signal state next_signed_pre_key_id cannot be zero"
        ));
    }
    if state.next_one_time_pre_key_id == 0 {
        return Err(anyhow!(
            "signal state next_one_time_pre_key_id cannot be zero"
        ));
    }
    if state.key_update_revision == 0 {
        return Err(anyhow!("signal state key_update_revision cannot be zero"));
    }
    decode_base64_fixed_32(&state.identity_private_b64, "identity_private_b64")?;
    decode_base64_fixed_32(&state.identity_public_b64, "identity_public_b64")?;
    decode_base64_fixed_32(
        &state.signed_pre_key.private_b64,
        "signed_pre_key.private_b64",
    )?;
    decode_base64_fixed_32(
        &state.signed_pre_key.public_b64,
        "signed_pre_key.public_b64",
    )?;
    decode_base64(
        &state.signed_pre_key_signature_b64,
        "signed_pre_key_signature_b64",
    )?;
    if state.signed_pre_key.key_id == 0 {
        return Err(anyhow!("signed pre-key id cannot be zero"));
    }
    for key in &state.previous_signed_pre_keys {
        if key.key_id == 0 {
            return Err(anyhow!("previous signed pre-key id cannot be zero"));
        }
        decode_base64_fixed_32(&key.private_b64, "previous_signed_pre_key.private_b64")?;
        decode_base64_fixed_32(&key.public_b64, "previous_signed_pre_key.public_b64")?;
    }
    if state.one_time_pre_keys.is_empty() {
        return Err(anyhow!("signal state has no one-time pre-keys"));
    }
    for pre_key in &state.one_time_pre_keys {
        if pre_key.key_id == 0 {
            return Err(anyhow!("signal state one-time pre-key id cannot be zero"));
        }
        decode_base64_fixed_32(&pre_key.private_b64, "one_time_pre_key.private_b64")?;
        decode_base64_fixed_32(&pre_key.public_b64, "one_time_pre_key.public_b64")?;
    }
    for (index, pre_key) in state.one_time_pre_keys.iter().enumerate() {
        if state.one_time_pre_keys[index + 1..]
            .iter()
            .any(|candidate| candidate.key_id == pre_key.key_id)
        {
            return Err(anyhow!(
                "signal state contains duplicate one-time pre-key id: {}",
                pre_key.key_id
            ));
        }
    }
    for previous in &state.previous_signed_pre_keys {
        if previous.key_id == state.signed_pre_key.key_id {
            return Err(anyhow!(
                "previous signed pre-key duplicates current signed pre-key id"
            ));
        }
    }
    for (index, key) in state.previous_signed_pre_keys.iter().enumerate() {
        if state.previous_signed_pre_keys[index + 1..]
            .iter()
            .any(|candidate| candidate.key_id == key.key_id)
        {
            return Err(anyhow!(
                "signal state contains duplicate previous signed pre-key id: {}",
                key.key_id
            ));
        }
    }
    if state.previous_signed_pre_keys.len() > PREVIOUS_SIGNED_PREKEY_HISTORY_LIMIT {
        return Err(anyhow!("too many previous signed pre-keys in state"));
    }
    let max_key_id = state
        .one_time_pre_keys
        .iter()
        .map(|value| value.key_id)
        .max()
        .unwrap_or(ONE_TIME_PREKEY_START_ID.saturating_sub(1));
    if state.next_one_time_pre_key_id <= max_key_id {
        return Err(anyhow!(
            "signal state next_one_time_pre_key_id must be greater than existing key ids"
        ));
    }
    if state.next_signed_pre_key_id <= state.signed_pre_key.key_id {
        return Err(anyhow!(
            "signal state next_signed_pre_key_id must be greater than current signed pre-key id"
        ));
    }
    Ok(())
}

fn consume_one_time_pre_key(state: &mut StoredSignalState, key_id: u32) -> Result<()> {
    let index = state
        .one_time_pre_keys
        .iter()
        .position(|value| value.key_id == key_id)
        .ok_or_else(|| anyhow!("one-time pre-key not found for key_id={key_id}"))?;
    state.one_time_pre_keys.remove(index);
    state.generated_at_unix = current_unix_seconds();
    Ok(())
}

fn maybe_rotate_signed_pre_key(
    state: &mut StoredSignalState,
    profile: &IdentityProfile,
    max_age_seconds: u64,
) -> Result<bool> {
    let max_age_seconds = max_age_seconds.max(1);
    let now = current_unix_seconds();
    if now.saturating_sub(state.signed_pre_key_generated_at_unix) < max_age_seconds {
        return Ok(false);
    }

    ensure_signal_state_defaults(state)?;

    let new_key_id = state.next_signed_pre_key_id;
    let generated = generate_x25519_keypair(new_key_id);
    let account_keypair = keypair_from_seed(&profile.account_seed)?;
    let signature = account_keypair
        .sign(&signed_pre_key_payload(
            generated.key_id,
            state.registration_id,
            &generated.public,
        ))
        .context("failed to sign rotated signed pre-key")?;

    state.previous_signed_pre_keys.insert(
        0,
        StoredSignalKeyPair {
            key_id: state.signed_pre_key.key_id,
            private_b64: state.signed_pre_key.private_b64.clone(),
            public_b64: state.signed_pre_key.public_b64.clone(),
        },
    );
    if state.previous_signed_pre_keys.len() > PREVIOUS_SIGNED_PREKEY_HISTORY_LIMIT {
        state
            .previous_signed_pre_keys
            .truncate(PREVIOUS_SIGNED_PREKEY_HISTORY_LIMIT);
    }

    state.signed_pre_key = StoredSignalKeyPair {
        key_id: generated.key_id,
        private_b64: encode_bytes(generated.private.as_slice()),
        public_b64: encode_bytes(generated.public.as_slice()),
    };
    state.signed_pre_key_signature_b64 = encode_bytes(&signature);
    state.signed_pre_key_generated_at_unix = now;
    state.next_signed_pre_key_id = state
        .next_signed_pre_key_id
        .checked_add(1)
        .ok_or_else(|| anyhow!("signed pre-key id overflow during rotation"))?;
    state.key_update_revision = state.key_update_revision.saturating_add(1).max(1);
    state.generated_at_unix = now;
    Ok(true)
}

fn one_time_prekey_replenish_threshold(target_count: usize) -> usize {
    (target_count / 2).max(1)
}

fn maybe_replenish_one_time_pre_keys(
    state: &mut StoredSignalState,
    target_count: usize,
) -> Result<bool> {
    ensure_signal_state_defaults(state)?;
    let target_count = target_count.max(1);
    if state.one_time_pre_keys.len() >= one_time_prekey_replenish_threshold(target_count) {
        return Ok(false);
    }

    while state.one_time_pre_keys.len() < target_count {
        let next_key_id = state.next_one_time_pre_key_id;
        state.next_one_time_pre_key_id = state
            .next_one_time_pre_key_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("one-time pre-key id overflow during replenishment"))?;
        let generated = generate_x25519_keypair(next_key_id);
        state.one_time_pre_keys.push(StoredSignalKeyPair {
            key_id: generated.key_id,
            private_b64: encode_bytes(generated.private.as_slice()),
            public_b64: encode_bytes(generated.public.as_slice()),
        });
    }
    state.generated_at_unix = current_unix_seconds();
    Ok(true)
}

fn persist_signal_state(path: &Path, state: &StoredSignalState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create signal state directory: {}",
                parent.display()
            )
        })?;
    }

    let json = serde_json::to_string_pretty(state).context("failed to serialize signal state")?;
    let temp_path = temporary_path(path);

    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(&temp_path).with_context(|| {
        format!(
            "failed to create temp signal state: {}",
            temp_path.display()
        )
    })?;
    file.write_all(json.as_bytes())
        .context("failed to write signal state data")?;
    file.sync_all()
        .context("failed to fsync signal state data")?;

    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to move signal state into place: {} -> {}",
            temp_path.display(),
            path.display()
        )
    })?;

    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms).with_context(|| {
            format!(
                "failed to set signal state permissions to 0600: {}",
                path.display()
            )
        })?;
    }

    Ok(())
}

fn signal_state_path(profile_path: &Path) -> PathBuf {
    let stem = profile_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("identity");
    profile_path.with_file_name(format!("{stem}.signal_state.json"))
}

fn session_store_path(profile_path: &Path) -> PathBuf {
    let stem = profile_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("identity");
    profile_path.with_file_name(format!("{stem}.sessions.json"))
}

fn load_or_create_session_store(profile_path: &Path) -> Result<StoredSessionStore> {
    let path = session_store_path(profile_path);
    if path.exists() {
        return load_session_store(&path);
    }

    Ok(StoredSessionStore {
        schema_version: E2EE_SCHEMA_VERSION,
        sessions: Vec::new(),
    })
}

fn load_session_store(path: &Path) -> Result<StoredSessionStore> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read session store: {}", path.display()))?;
    let store: StoredSessionStore = serde_json::from_str(&raw)
        .with_context(|| format!("invalid session store json: {}", path.display()))?;
    validate_session_store(&store)?;
    Ok(store)
}

fn persist_session_store(profile_path: &Path, store: &StoredSessionStore) -> Result<()> {
    validate_session_store(store)?;
    let path = session_store_path(profile_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create session store directory: {}",
                parent.display()
            )
        })?;
    }

    let json = serde_json::to_string_pretty(store).context("failed to serialize session store")?;
    let temp_path = temporary_path(&path);

    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(&temp_path).with_context(|| {
        format!(
            "failed to create temp session store: {}",
            temp_path.display()
        )
    })?;
    file.write_all(json.as_bytes())
        .context("failed to write session store data")?;
    file.sync_all()
        .context("failed to fsync session store data")?;

    fs::rename(&temp_path, &path).with_context(|| {
        format!(
            "failed to move session store into place: {} -> {}",
            temp_path.display(),
            path.display()
        )
    })?;

    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&path, perms).with_context(|| {
            format!(
                "failed to set session store permissions to 0600: {}",
                path.display()
            )
        })?;
    }

    Ok(())
}

fn validate_session_store(store: &StoredSessionStore) -> Result<()> {
    if store.schema_version != E2EE_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported session store schema version: {}",
            store.schema_version
        ));
    }
    for session in &store.sessions {
        if session.session_id.trim().is_empty()
            || session.local_account_id.trim().is_empty()
            || session.local_device_id.trim().is_empty()
            || session.peer_account_id.trim().is_empty()
            || session.peer_device_id.trim().is_empty()
        {
            return Err(anyhow!("session store contains empty identity fields"));
        }
        PeerId::from_str(&session.local_account_id).context("invalid session local_account_id")?;
        PeerId::from_str(&session.peer_account_id).context("invalid session peer_account_id")?;
        decode_base64_fixed_32(&session.send_chain_key_b64, "session.send_chain_key_b64")?;
        decode_base64_fixed_32(&session.recv_chain_key_b64, "session.recv_chain_key_b64")?;
    }
    Ok(())
}

fn find_session_mut<'a>(
    store: &'a mut StoredSessionStore,
    session_id: &str,
) -> Option<&'a mut StoredSessionRecord> {
    store
        .sessions
        .iter_mut()
        .find(|value| value.session_id == session_id)
}

fn upsert_session_from_prekey(
    profile_path: &Path,
    local_account_id: &str,
    local_device_id: &str,
    peer_account_id: &str,
    peer_device_id: &str,
    session_material: &SessionMaterial,
    local_is_initiator: bool,
) -> Result<()> {
    let mut store = load_or_create_session_store(profile_path)?;
    let (send_chain_key, recv_chain_key) = if local_is_initiator {
        (
            session_material.initiator_to_responder_chain_key,
            session_material.responder_to_initiator_chain_key,
        )
    } else {
        (
            session_material.responder_to_initiator_chain_key,
            session_material.initiator_to_responder_chain_key,
        )
    };

    if let Some(existing) = find_session_mut(&mut store, &session_material.session_id) {
        existing.local_account_id = local_account_id.to_string();
        existing.local_device_id = local_device_id.to_string();
        existing.peer_account_id = peer_account_id.to_string();
        existing.peer_device_id = peer_device_id.to_string();
        existing.send_chain_key_b64 = encode_bytes(send_chain_key.as_slice());
        existing.recv_chain_key_b64 = encode_bytes(recv_chain_key.as_slice());
        existing.send_counter = 0;
        existing.recv_counter = 0;
        existing.established_at_unix = current_unix_seconds();
    } else {
        store.sessions.push(StoredSessionRecord {
            session_id: session_material.session_id.clone(),
            local_account_id: local_account_id.to_string(),
            local_device_id: local_device_id.to_string(),
            peer_account_id: peer_account_id.to_string(),
            peer_device_id: peer_device_id.to_string(),
            send_chain_key_b64: encode_bytes(send_chain_key.as_slice()),
            recv_chain_key_b64: encode_bytes(recv_chain_key.as_slice()),
            send_counter: 0,
            recv_counter: 0,
            established_at_unix: current_unix_seconds(),
        });
    }

    persist_session_store(profile_path, &store)
}

trait AwaitBlockingExt: std::future::Future {
    fn await_blocking(self) -> Self::Output
    where
        Self: Sized,
    {
        futures::executor::block_on(self)
    }
}

impl<F: std::future::Future> AwaitBlockingExt for F {}

fn libsignal_state_path(profile_path: &std::path::Path) -> std::path::PathBuf {
    let stem = profile_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("identity");
    profile_path.with_file_name(format!("{stem}.libsignal_state.json"))
}

struct GeneratedX25519KeyPair {
    key_id: u32,
    private: [u8; 32],
    public: [u8; 32],
}

fn generate_x25519_keypair(key_id: u32) -> GeneratedX25519KeyPair {
    let mut private = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut private);
    let public = x25519_public_from_private(&private);
    GeneratedX25519KeyPair {
        key_id,
        private,
        public,
    }
}

fn x25519_public_from_private(private: &[u8; 32]) -> [u8; 32] {
    let private = StaticSecret::from(*private);
    let public = X25519PublicKey::from(&private);
    public.to_bytes()
}

fn signed_pre_key_payload(
    signed_pre_key_id: u32,
    registration_id: u32,
    signed_pre_key_public: &[u8; 32],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + 4 + 32);
    payload.extend_from_slice(&signed_pre_key_id.to_be_bytes());
    payload.extend_from_slice(&registration_id.to_be_bytes());
    payload.extend_from_slice(signed_pre_key_public);
    payload
}

fn decode_base64_fixed_32(encoded: &str, field_name: &str) -> Result<[u8; 32]> {
    let decoded = decode_base64(encoded, field_name)?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{field_name} must contain exactly 32 bytes"))
}

fn decode_base64_fixed_12(encoded: &str, field_name: &str) -> Result<[u8; 12]> {
    let decoded = decode_base64(encoded, field_name)?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{field_name} must contain exactly 12 bytes"))
}

fn decode_base64(encoded: &str, field_name: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .with_context(|| format!("invalid {field_name}"))
}

fn encode_bytes(value: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}

fn x25519_shared_secret(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    let private = StaticSecret::from(*private);
    let public = X25519PublicKey::from(*public);
    private.diffie_hellman(&public).to_bytes()
}

fn combine_prekey_shared_secrets(
    signed_pre_key_secret: &[u8; 32],
    one_time_pre_key_secret: &[u8; 32],
) -> [u8; 64] {
    let mut combined = [0u8; 64];
    combined[0..32].copy_from_slice(signed_pre_key_secret);
    combined[32..64].copy_from_slice(one_time_pre_key_secret);
    combined
}

fn derive_prekey_message_key(
    shared_secret: &[u8],
    sender_account_id: &str,
    recipient_account_id: &str,
    recipient_one_time_pre_key_id: u32,
    message_id: &str,
) -> Result<[u8; 32]> {
    let mut info = Vec::new();
    info.extend_from_slice(PREKEY_MESSAGE_PROTOCOL.as_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(sender_account_id.as_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(recipient_account_id.as_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(&recipient_one_time_pre_key_id.to_be_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(message_id.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|_| anyhow!("failed to derive prekey message key"))?;
    Ok(key)
}

fn derive_session_material(
    shared_secret: &[u8],
    initiator_account_id: &str,
    initiator_device_id: &str,
    responder_account_id: &str,
    responder_device_id: &str,
    signed_pre_key_id: u32,
    one_time_pre_key_id: u32,
) -> Result<SessionMaterial> {
    let mut info = Vec::new();
    info.extend_from_slice(SESSION_MESSAGE_PROTOCOL.as_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(initiator_account_id.as_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(initiator_device_id.as_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(responder_account_id.as_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(responder_device_id.as_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(&signed_pre_key_id.to_be_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(&one_time_pre_key_id.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut output = [0u8; 80];
    hk.expand(&info, &mut output)
        .map_err(|_| anyhow!("failed to derive session material"))?;

    let mut session_id_raw = [0u8; 16];
    session_id_raw.copy_from_slice(&output[0..16]);
    let mut i2r = [0u8; 32];
    i2r.copy_from_slice(&output[16..48]);
    let mut r2i = [0u8; 32];
    r2i.copy_from_slice(&output[48..80]);

    Ok(SessionMaterial {
        session_id: hex::encode(session_id_raw),
        initiator_to_responder_chain_key: i2r,
        responder_to_initiator_chain_key: r2i,
    })
}

fn derive_session_message_key(
    chain_key: &[u8; 32],
    session_id: &str,
    counter: u64,
) -> Result<[u8; 32]> {
    let mut info = Vec::new();
    info.extend_from_slice(SESSION_MESSAGE_PROTOCOL.as_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(session_id.as_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(&counter.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(None, chain_key);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|_| anyhow!("failed to derive session message key"))?;
    Ok(key)
}

fn build_prekey_message_aad(
    protocol: &str,
    sender_account_id: &str,
    sender_device_id: &str,
    recipient_account_id: &str,
    recipient_device_id: &str,
    recipient_signed_pre_key_id: u32,
    recipient_one_time_pre_key_id: u32,
    message_id: &str,
    user_aad: &[u8],
) -> Result<Vec<u8>> {
    let meta = PreKeyMessageMeta {
        protocol,
        sender_account_id,
        sender_device_id,
        recipient_account_id,
        recipient_device_id,
        recipient_signed_pre_key_id,
        recipient_one_time_pre_key_id,
        message_id,
    };
    let mut aad = serde_json::to_vec(&meta).context("failed to serialize prekey message aad")?;
    aad.extend_from_slice(user_aad);
    Ok(aad)
}

fn build_session_message_aad(
    session_id: &str,
    sender_account_id: &str,
    sender_device_id: &str,
    recipient_account_id: &str,
    recipient_device_id: &str,
    counter: u64,
    message_id: &str,
    user_aad: &[u8],
) -> Result<Vec<u8>> {
    let meta = SessionMessageMeta {
        protocol: SESSION_MESSAGE_PROTOCOL,
        session_id,
        sender_account_id,
        sender_device_id,
        recipient_account_id,
        recipient_device_id,
        counter,
        message_id,
    };
    let mut aad = serde_json::to_vec(&meta).context("failed to serialize session message aad")?;
    aad.extend_from_slice(user_aad);
    Ok(aad)
}

fn aead_encrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).context("failed to initialize AEAD cipher")?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("failed to encrypt prekey message"))
}

fn aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).context("failed to initialize AEAD cipher")?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("failed to decrypt prekey message"))
}

// ----- libsignal persistence/runtime helpers -----

use libsignal_protocol::{
    kem, message_decrypt, message_encrypt, process_prekey_bundle, CiphertextMessage, DeviceId,
    GenericSignedPreKey, IdentityKeyPair, IdentityKeyStore, InMemSignalProtocolStore, KeyPair,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord,
    PreKeySignalMessage, PreKeyStore, ProtocolAddress, SessionRecord, SessionStore, SignalMessage,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};

fn device_id_from_string(device_id: &str) -> Result<DeviceId> {
    let mut hasher = Sha256::new();
    hasher.update(device_id.as_bytes());
    let hash = hasher.finalize();
    let b = hash[0];
    let v = ((b % 127) as u8).saturating_add(1).max(1);
    DeviceId::new(v).map_err(|_| anyhow!("invalid device id"))
}

pub fn load_or_create_libsignal_store(
    profile_path: &Path,
    target_prekey_count: usize,
) -> Result<(StoredLibsignalState, InMemSignalProtocolStore)> {
    let path = libsignal_state_path(profile_path);
    if path.exists() {
        let mut state = load_libsignal_state(&path)?;
        let mut store = restore_libsignal_store_from_state(&state)?;
        replenish_libsignal_prekeys_if_needed(&mut state, &mut store, target_prekey_count)?;
        capture_libsignal_store_state(&mut state, &mut store, None)?;
        persist_libsignal_state(&path, &state)?;
        return Ok((state, store));
    }
    create_libsignal_store(&path, target_prekey_count)
}

pub fn create_libsignal_store(
    path: &Path,
    target_prekey_count: usize,
) -> Result<(StoredLibsignalState, InMemSignalProtocolStore)> {
    let mut csprng = rand09::rngs::OsRng.unwrap_err();
    let identity = IdentityKeyPair::generate(&mut csprng);
    let registration_id = (csprng.random::<u16>() as u32) & 0x3fff;

    let mut store = InMemSignalProtocolStore::new(identity, registration_id)
        .map_err(|e| anyhow!("failed to create libsignal store: {}", e))?;

    let identity_key_pair = store
        .get_identity_key_pair()
        .await_blocking()
        .map_err(|e| anyhow!("get_identity_key_pair: {}", e))?;

    let signed_pre_key_pair = KeyPair::generate(&mut csprng);
    let signed_pre_key_id = 1u32;
    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
    let signed_pre_key_signature = identity_key_pair
        .private_key()
        .calculate_signature(&signed_pre_key_public, &mut csprng)
        .map_err(|e| anyhow!("signed pre-key signature: {}", e))?;

    let kyber_pre_key_id = 1u32;
    let kyber_pre_key_record = KyberPreKeyRecord::generate(
        kem::KeyType::Kyber1024,
        kyber_pre_key_id.into(),
        identity_key_pair.private_key(),
    )
    .map_err(|e| anyhow!("KyberPreKeyRecord::generate: {}", e))?;

    store
        .save_signed_pre_key(
            signed_pre_key_id.into(),
            &SignedPreKeyRecord::new(
                signed_pre_key_id.into(),
                Timestamp::from_epoch_millis(
                    current_unix_seconds()
                        .checked_mul(1000)
                        .ok_or_else(|| anyhow!("timestamp overflow"))?,
                ),
                &signed_pre_key_pair,
                signed_pre_key_signature.as_ref(),
            ),
        )
        .await_blocking()
        .map_err(|e| anyhow!("save_signed_pre_key: {}", e))?;

    store
        .save_kyber_pre_key(kyber_pre_key_id.into(), &kyber_pre_key_record)
        .await_blocking()
        .map_err(|e| anyhow!("save_kyber_pre_key: {}", e))?;

    let mut state = StoredLibsignalState {
        schema_version: LIBSIGNAL_STATE_SCHEMA_VERSION,
        registration_id,
        identity_key_pair_b64: encode_bytes(
            store
                .get_identity_key_pair()
                .await_blocking()
                .map_err(|e| anyhow!("get_identity_key_pair: {}", e))?
                .serialize()
                .as_ref(),
        ),
        next_pre_key_id: 1000,
        next_signed_pre_key_id: 2,
        next_kyber_pre_key_id: 2,
        active_signed_pre_key_id: signed_pre_key_id,
        active_kyber_pre_key_id: kyber_pre_key_id,
        pre_keys: vec![],
        signed_pre_keys: vec![],
        kyber_pre_keys: vec![],
        sessions: vec![],
        trusted_identities: vec![],
        generated_at_unix: current_unix_seconds(),
    };

    replenish_libsignal_prekeys_if_needed(&mut state, &mut store, target_prekey_count)?;
    capture_libsignal_store_state(&mut state, &mut store, None)?;
    persist_libsignal_state(path, &state)?;

    Ok((state, store))
}

pub fn load_libsignal_state(path: &Path) -> Result<StoredLibsignalState> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read libsignal state: {}", path.display()))?;
    let state: StoredLibsignalState = serde_json::from_str(&raw)
        .with_context(|| format!("invalid libsignal state json: {}", path.display()))?;
    validate_libsignal_state(&state)?;
    Ok(state)
}

pub fn validate_libsignal_state(state: &StoredLibsignalState) -> Result<()> {
    if state.schema_version != LIBSIGNAL_STATE_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported libsignal state schema version: {}",
            state.schema_version
        ));
    }
    if state.registration_id == 0 {
        return Err(anyhow!("libsignal state registration_id cannot be zero"));
    }
    decode_base64(&state.identity_key_pair_b64, "identity_key_pair_b64")?;
    for rec in &state.pre_keys {
        decode_base64(&rec.record_b64, "pre_key.record_b64")?;
    }
    for rec in &state.signed_pre_keys {
        decode_base64(&rec.record_b64, "signed_pre_key.record_b64")?;
    }
    for rec in &state.kyber_pre_keys {
        decode_base64(&rec.record_b64, "kyber_pre_key.record_b64")?;
    }
    for rec in &state.sessions {
        if rec.peer_account_id.trim().is_empty() || rec.peer_device_id.trim().is_empty() {
            return Err(anyhow!("libsignal session peer fields cannot be empty"));
        }
        decode_base64(&rec.record_b64, "session.record_b64")?;
    }
    for rec in &state.trusted_identities {
        if rec.peer_account_id.trim().is_empty() || rec.peer_device_id.trim().is_empty() {
            return Err(anyhow!(
                "libsignal trusted identity peer fields cannot be empty"
            ));
        }
        decode_base64(&rec.identity_key_b64, "trusted_identity.identity_key_b64")?;
    }
    Ok(())
}

pub fn restore_libsignal_store_from_state(
    state: &StoredLibsignalState,
) -> Result<InMemSignalProtocolStore> {
    let identity_bytes = decode_base64(&state.identity_key_pair_b64, "identity_key_pair_b64")?;
    let identity = IdentityKeyPair::try_from(identity_bytes.as_slice())
        .map_err(|e| anyhow!("deserialize identity_key_pair: {}", e))?;

    let mut store = InMemSignalProtocolStore::new(identity, state.registration_id)
        .map_err(|e| anyhow!("InMemSignalProtocolStore::new: {}", e))?;

    for rec in &state.pre_keys {
        let key_id: PreKeyId = rec.key_id.into();
        let record = PreKeyRecord::deserialize(
            decode_base64(&rec.record_b64, "pre_key.record_b64")?.as_slice(),
        )
        .map_err(|e| anyhow!("PreKeyRecord::deserialize: {}", e))?;
        store
            .save_pre_key(key_id, &record)
            .await_blocking()
            .map_err(|e| anyhow!("save_pre_key: {}", e))?;
    }

    for rec in &state.signed_pre_keys {
        let key_id: SignedPreKeyId = rec.key_id.into();
        let record = SignedPreKeyRecord::deserialize(
            decode_base64(&rec.record_b64, "signed_pre_key.record_b64")?.as_slice(),
        )
        .map_err(|e| anyhow!("SignedPreKeyRecord::deserialize: {}", e))?;
        store
            .save_signed_pre_key(key_id, &record)
            .await_blocking()
            .map_err(|e| anyhow!("save_signed_pre_key: {}", e))?;
    }

    for rec in &state.kyber_pre_keys {
        let key_id: KyberPreKeyId = rec.key_id.into();
        let record = KyberPreKeyRecord::deserialize(
            decode_base64(&rec.record_b64, "kyber_pre_key.record_b64")?.as_slice(),
        )
        .map_err(|e| anyhow!("KyberPreKeyRecord::deserialize: {}", e))?;
        store
            .save_kyber_pre_key(key_id, &record)
            .await_blocking()
            .map_err(|e| anyhow!("save_kyber_pre_key: {}", e))?;
    }

    for rec in &state.sessions {
        let addr = libsignal_protocol_address(&rec.peer_account_id, &rec.peer_device_id)?;
        let record = SessionRecord::deserialize(
            decode_base64(&rec.record_b64, "session.record_b64")?.as_slice(),
        )
        .map_err(|e| anyhow!("SessionRecord::deserialize: {}", e))?;
        store
            .store_session(&addr, &record)
            .await_blocking()
            .map_err(|e| anyhow!("store_session: {}", e))?;
    }

    Ok(store)
}

pub fn capture_libsignal_store_state(
    state: &mut StoredLibsignalState,
    store: &mut InMemSignalProtocolStore,
    touched_peer: Option<(&str, &str)>,
) -> Result<()> {
    state.registration_id = store
        .get_local_registration_id()
        .await_blocking()
        .map_err(|e| anyhow!("get_local_registration_id: {}", e))?;

    state.identity_key_pair_b64 = encode_bytes(
        store
            .get_identity_key_pair()
            .await_blocking()
            .map_err(|e| anyhow!("get_identity_key_pair: {}", e))?
            .serialize()
            .as_ref(),
    );

    state.pre_keys.clear();
    for id in store.all_pre_key_ids() {
        let record = store
            .get_pre_key(*id)
            .await_blocking()
            .map_err(|e| anyhow!("get_pre_key: {}", e))?;
        state.pre_keys.push(StoredLibsignalKeyRecord {
            key_id: (*id).into(),
            record_b64: encode_bytes(
                &record
                    .serialize()
                    .map_err(|e| anyhow!("pre_key serialize: {}", e))?,
            ),
        });
    }

    state.signed_pre_keys.clear();
    for id in store.all_signed_pre_key_ids() {
        let record = store
            .get_signed_pre_key(*id)
            .await_blocking()
            .map_err(|e| anyhow!("get_signed_pre_key: {}", e))?;
        state.signed_pre_keys.push(StoredLibsignalKeyRecord {
            key_id: (*id).into(),
            record_b64: encode_bytes(
                &record
                    .serialize()
                    .map_err(|e| anyhow!("signed_pre_key serialize: {}", e))?,
            ),
        });
    }

    state.kyber_pre_keys.clear();
    for id in store.all_kyber_pre_key_ids() {
        let record = store
            .get_kyber_pre_key(*id)
            .await_blocking()
            .map_err(|e| anyhow!("get_kyber_pre_key: {}", e))?;
        state.kyber_pre_keys.push(StoredLibsignalKeyRecord {
            key_id: (*id).into(),
            record_b64: encode_bytes(
                &record
                    .serialize()
                    .map_err(|e| anyhow!("kyber_pre_key serialize: {}", e))?,
            ),
        });
    }

    if let Some((account_id, device_id)) = touched_peer {
        let addr = libsignal_protocol_address(account_id, device_id)?;
        if let Some(session) = store
            .load_session(&addr)
            .await_blocking()
            .map_err(|e| anyhow!("load_session: {}", e))?
        {
            let serialized = session
                .serialize()
                .map_err(|e| anyhow!("session serialize: {}", e))?;
            state
                .sessions
                .retain(|s| !(s.peer_account_id == account_id && s.peer_device_id == device_id));
            state.sessions.push(StoredLibsignalSessionRecord {
                peer_account_id: account_id.to_string(),
                peer_device_id: device_id.to_string(),
                record_b64: encode_bytes(&serialized),
            });
        } else {
            state
                .sessions
                .retain(|s| !(s.peer_account_id == account_id && s.peer_device_id == device_id));
            state
                .trusted_identities
                .retain(|t| !(t.peer_account_id == account_id && t.peer_device_id == device_id));
        }

        if let Some(identity_key) = store
            .get_identity(&addr)
            .await_blocking()
            .map_err(|e| anyhow!("get_identity: {}", e))?
        {
            state
                .trusted_identities
                .retain(|t| !(t.peer_account_id == account_id && t.peer_device_id == device_id));
            state
                .trusted_identities
                .push(StoredLibsignalIdentityRecord {
                    peer_account_id: account_id.to_string(),
                    peer_device_id: device_id.to_string(),
                    identity_key_b64: encode_bytes(identity_key.serialize().as_ref()),
                });
        }
    }

    state.generated_at_unix = current_unix_seconds();
    Ok(())
}

pub fn replenish_libsignal_prekeys_if_needed(
    state: &mut StoredLibsignalState,
    store: &mut InMemSignalProtocolStore,
    target_count: usize,
) -> Result<()> {
    let target_count = target_count.max(1);
    let current = store.all_pre_key_ids().count();
    if current >= target_count {
        return Ok(());
    }

    let mut csprng = rand09::rngs::OsRng.unwrap_err();
    let to_create = target_count - current;
    for _ in 0..to_create {
        let key_id = state.next_pre_key_id;
        state.next_pre_key_id = state.next_pre_key_id.saturating_add(1);
        let key_pair = KeyPair::generate(&mut csprng);
        let record = PreKeyRecord::new(key_id.into(), &key_pair);
        store
            .save_pre_key(key_id.into(), &record)
            .await_blocking()
            .map_err(|e| anyhow!("save_pre_key: {}", e))?;
    }

    capture_libsignal_store_state(state, store, None)?;
    Ok(())
}

pub fn persist_libsignal_state(path: &Path, state: &StoredLibsignalState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create libsignal state directory: {}",
                parent.display()
            )
        })?;
    }

    let json =
        serde_json::to_string_pretty(state).context("failed to serialize libsignal state")?;
    let temp_path = temporary_path(path);

    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }

    let mut file = options.open(&temp_path).with_context(|| {
        format!(
            "failed to create temp libsignal state: {}",
            temp_path.display()
        )
    })?;
    file.write_all(json.as_bytes())
        .context("failed to write libsignal state data")?;
    file.sync_all()
        .context("failed to fsync libsignal state data")?;

    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to move libsignal state into place: {} -> {}",
            temp_path.display(),
            path.display()
        )
    })?;

    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms).with_context(|| {
            format!(
                "failed to set libsignal state permissions to 0600: {}",
                path.display()
            )
        })?;
    }

    Ok(())
}

pub fn libsignal_protocol_address(account_id: &str, device_id: &str) -> Result<ProtocolAddress> {
    let dev_id = device_id_from_string(device_id)?;
    Ok(ProtocolAddress::new(account_id.to_string(), dev_id))
}

pub fn derive_libsignal_session_id(
    sender_account_id: &str,
    sender_device_id: &str,
    recipient_account_id: &str,
    recipient_device_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(LIBSIGNAL_MESSAGE_PROTOCOL.as_bytes());
    hasher.update(b"|");
    hasher.update(sender_account_id.as_bytes());
    hasher.update(b"|");
    hasher.update(sender_device_id.as_bytes());
    hasher.update(b"|");
    hasher.update(recipient_account_id.as_bytes());
    hasher.update(b"|");
    hasher.update(recipient_device_id.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[0..16])
}

pub fn encode_libsignal_inner_payload(plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let payload = LibsignalInnerPayload {
        plaintext_b64: encode_bytes(plaintext),
        aad_b64: encode_bytes(aad),
    };
    serde_json::to_vec(&payload).context("failed to encode libsignal inner payload")
}

pub fn decode_libsignal_inner_payload(encoded: &[u8]) -> Result<LibsignalInnerPayload> {
    serde_json::from_slice(encoded).context("failed to decode libsignal inner payload")
}

pub fn validate_libsignal_message(encoded_message: &[u8]) -> Result<LibsignalMessageRecord> {
    let record: LibsignalMessageRecord = serde_json::from_slice(encoded_message)
        .context("failed to decode libsignal message json")?;

    if record.schema_version != E2EE_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported libsignal message schema version: {}",
            record.schema_version
        ));
    }
    if record.protocol != LIBSIGNAL_MESSAGE_PROTOCOL {
        return Err(anyhow!("unsupported libsignal message protocol"));
    }
    if record.sender_account_id.trim().is_empty()
        || record.sender_device_id.trim().is_empty()
        || record.recipient_account_id.trim().is_empty()
        || record.recipient_device_id.trim().is_empty()
    {
        return Err(anyhow!("libsignal message identity fields cannot be empty"));
    }
    if record.session_id.len() < 16 {
        return Err(anyhow!("invalid libsignal message session_id"));
    }
    if record.message_id.len() < 16 {
        return Err(anyhow!("invalid libsignal message_id"));
    }
    if record.ciphertext_kind != LIBSIGNAL_MESSAGE_KIND_PREKEY
        && record.ciphertext_kind != LIBSIGNAL_MESSAGE_KIND_SESSION
    {
        return Err(anyhow!("invalid libsignal message ciphertext_kind"));
    }

    PeerId::from_str(&record.sender_account_id).context("invalid sender_account_id")?;
    PeerId::from_str(&record.recipient_account_id).context("invalid recipient_account_id")?;
    decode_base64(&record.ciphertext_b64, "ciphertext_b64")?;
    decode_base64(&record.aad_b64, "aad_b64")?;

    Ok(record)
}

pub fn has_complete_libsignal_bundle_fields(bundle: &PreKeyBundleRecord) -> bool {
    bundle.libsignal_identity_key_b64.is_some()
        && bundle.libsignal_signed_pre_key_id.is_some()
        && bundle.libsignal_signed_pre_key_public_b64.is_some()
        && bundle.libsignal_signed_pre_key_signature_b64.is_some()
        && bundle.libsignal_kyber_pre_key_id.is_some()
        && bundle.libsignal_kyber_pre_key_public_b64.is_some()
        && bundle.libsignal_kyber_pre_key_signature_b64.is_some()
}

fn build_libsignal_message_auto(
    profile_path: &Path,
    profile: &IdentityProfile,
    recipient_bundle: &PreKeyBundleRecord,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<OutboundMessage> {
    let (mut state, mut store) =
        load_or_create_libsignal_store(profile_path, DEFAULT_ONE_TIME_PREKEY_COUNT)?;
    let recipient_address =
        libsignal_protocol_address(&recipient_bundle.account_id, &recipient_bundle.device_id)?;

    let session_exists = store
        .load_session(&recipient_address)
        .await_blocking()
        .map_err(|e| anyhow!("load_session: {}", e))?
        .is_some();

    if !session_exists {
        let bundle = build_libsignal_bundle_from_record(recipient_bundle)?;
        let mut csprng = rand09::rngs::OsRng.unwrap_err();
        process_prekey_bundle(
            &recipient_address,
            &mut store.session_store,
            &mut store.identity_store,
            &bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await_blocking()
        .map_err(|e| anyhow!("process_prekey_bundle: {}", e))?;
    }

    let inner = encode_libsignal_inner_payload(plaintext, aad)?;
    let mut csprng = rand09::rngs::OsRng.unwrap_err();
    let ciphertext = message_encrypt(
        &inner,
        &recipient_address,
        &mut store.session_store,
        &mut store.identity_store,
        SystemTime::now(),
        &mut csprng,
    )
    .await_blocking()
    .map_err(|e| anyhow!("message_encrypt: {}", e))?;

    let (ciphertext_kind, ciphertext_bytes, recipient_one_time_pre_key_id) = match &ciphertext {
        CiphertextMessage::PreKeySignalMessage(m) => {
            let pre_key_id = m.pre_key_id().map(|id| id.into());
            (
                LIBSIGNAL_MESSAGE_KIND_PREKEY.to_string(),
                m.serialized().to_vec(),
                pre_key_id,
            )
        }
        CiphertextMessage::SignalMessage(m) => (
            LIBSIGNAL_MESSAGE_KIND_SESSION.to_string(),
            m.serialized().to_vec(),
            None,
        ),
        _ => {
            return Err(anyhow!(
                "unsupported ciphertext message type: {:?}",
                ciphertext.message_type()
            ))
        }
    };

    let session_id = derive_libsignal_session_id(
        &profile.account_id,
        &profile.device_id,
        &recipient_bundle.account_id,
        &recipient_bundle.device_id,
    );
    let used_session = ciphertext_kind == LIBSIGNAL_MESSAGE_KIND_SESSION;

    let mut message_id_raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut message_id_raw);

    let record = LibsignalMessageRecord {
        schema_version: E2EE_SCHEMA_VERSION,
        protocol: LIBSIGNAL_MESSAGE_PROTOCOL.to_string(),
        sender_account_id: profile.account_id.clone(),
        sender_device_id: profile.device_id.clone(),
        recipient_account_id: recipient_bundle.account_id.clone(),
        recipient_device_id: recipient_bundle.device_id.clone(),
        session_id: session_id.clone(),
        message_id: hex::encode(message_id_raw),
        created_at_unix: current_unix_seconds(),
        ciphertext_kind,
        recipient_one_time_pre_key_id,
        aad_b64: encode_bytes(aad),
        ciphertext_b64: encode_bytes(&ciphertext_bytes),
    };

    capture_libsignal_store_state(
        &mut state,
        &mut store,
        Some((&recipient_bundle.account_id, &recipient_bundle.device_id)),
    )?;
    persist_libsignal_state(&libsignal_state_path(profile_path), &state)?;

    Ok(OutboundMessage {
        payload: serde_json::to_vec(&record).context("failed to encode LibsignalMessageRecord")?,
        session_id,
        used_session,
    })
}

fn decrypt_libsignal_message_auto(profile_path: &Path, payload: &[u8]) -> Result<DecryptedMessage> {
    let record = validate_libsignal_message(payload)?;
    let profile = load_or_create_profile(profile_path)?;
    if record.recipient_account_id != profile.account_id
        || record.recipient_device_id != profile.device_id
    {
        return Err(anyhow!(
            "libsignal message is not addressed to this account/device"
        ));
    }

    let (mut state, mut store) =
        load_or_create_libsignal_store(profile_path, DEFAULT_ONE_TIME_PREKEY_COUNT)?;
    let sender_address =
        libsignal_protocol_address(&record.sender_account_id, &record.sender_device_id)?;

    let ciphertext_bytes = decode_base64(&record.ciphertext_b64, "ciphertext_b64")?;
    let ciphertext = match record.ciphertext_kind.as_str() {
        LIBSIGNAL_MESSAGE_KIND_PREKEY => CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(ciphertext_bytes.as_slice())
                .map_err(|e| anyhow!("PreKeySignalMessage::try_from: {}", e))?,
        ),
        LIBSIGNAL_MESSAGE_KIND_SESSION => CiphertextMessage::SignalMessage(
            SignalMessage::try_from(ciphertext_bytes.as_slice())
                .map_err(|e| anyhow!("SignalMessage::try_from: {}", e))?,
        ),
        _ => {
            return Err(anyhow!(
                "invalid ciphertext_kind: {}",
                record.ciphertext_kind
            ))
        }
    };

    let mut csprng = rand09::rngs::OsRng.unwrap_err();
    let inner_bytes = message_decrypt(
        &ciphertext,
        &sender_address,
        &mut store.session_store,
        &mut store.identity_store,
        &mut store.pre_key_store,
        &store.signed_pre_key_store,
        &mut store.kyber_pre_key_store,
        &mut csprng,
    )
    .await_blocking()
    .map_err(|e| anyhow!("message_decrypt: {}", e))?;

    let inner = decode_libsignal_inner_payload(&inner_bytes)?;
    let plaintext = decode_base64(&inner.plaintext_b64, "plaintext_b64")?;

    let kind = match record.ciphertext_kind.as_str() {
        LIBSIGNAL_MESSAGE_KIND_PREKEY => DecryptedMessageKind::PreKey,
        LIBSIGNAL_MESSAGE_KIND_SESSION => DecryptedMessageKind::Session,
        _ => DecryptedMessageKind::PreKey,
    };

    replenish_libsignal_prekeys_if_needed(&mut state, &mut store, DEFAULT_ONE_TIME_PREKEY_COUNT)?;
    capture_libsignal_store_state(
        &mut state,
        &mut store,
        Some((&record.sender_account_id, &record.sender_device_id)),
    )?;
    persist_libsignal_state(&libsignal_state_path(profile_path), &state)?;

    if kind == DecryptedMessageKind::PreKey {
        if let Some(used_id) = record.recipient_one_time_pre_key_id {
            if let Ok(mut legacy_state) = load_or_create_signal_state(
                profile_path,
                &profile,
                DEFAULT_ONE_TIME_PREKEY_COUNT,
                false,
            ) {
                if let Some(idx) = legacy_state
                    .one_time_pre_keys
                    .iter()
                    .position(|k| k.key_id == used_id)
                {
                    legacy_state.one_time_pre_keys.remove(idx);
                    let _ = maybe_replenish_one_time_pre_keys(
                        &mut legacy_state,
                        DEFAULT_ONE_TIME_PREKEY_COUNT,
                    );
                    let _ = persist_signal_state(&signal_state_path(profile_path), &legacy_state);
                }
            }
        }
    }

    Ok(DecryptedMessage { plaintext, kind })
}

pub fn build_libsignal_bundle_from_record(record: &PreKeyBundleRecord) -> Result<PreKeyBundle> {
    if !has_complete_libsignal_bundle_fields(record) {
        return Err(anyhow!("prekey bundle missing required libsignal fields"));
    }

    let identity_key_b64 = record
        .libsignal_identity_key_b64
        .as_ref()
        .ok_or_else(|| anyhow!("libsignal_identity_key_b64"))?;
    let identity_key_bytes = decode_base64(identity_key_b64, "libsignal_identity_key_b64")?;
    let identity_key = libsignal_protocol::IdentityKey::decode(&identity_key_bytes)
        .map_err(|e| anyhow!("identity key decode: {}", e))?;

    let dev_id = device_id_from_string(&record.device_id)?;

    let signed_pre_key_id: SignedPreKeyId = record
        .libsignal_signed_pre_key_id
        .ok_or_else(|| anyhow!("libsignal_signed_pre_key_id"))?
        .into();
    let signed_pre_key_public = libsignal_protocol::PublicKey::deserialize(&decode_base64(
        &record
            .libsignal_signed_pre_key_public_b64
            .as_ref()
            .ok_or_else(|| anyhow!("libsignal_signed_pre_key_public_b64"))?,
        "libsignal_signed_pre_key_public_b64",
    )?)
    .map_err(|e| anyhow!("signed pre-key public: {}", e))?;
    let signed_pre_key_signature = decode_base64(
        &record
            .libsignal_signed_pre_key_signature_b64
            .as_ref()
            .ok_or_else(|| anyhow!("libsignal_signed_pre_key_signature_b64"))?,
        "libsignal_signed_pre_key_signature_b64",
    )?;

    let kyber_pre_key_id: KyberPreKeyId = record
        .libsignal_kyber_pre_key_id
        .ok_or_else(|| anyhow!("libsignal_kyber_pre_key_id"))?
        .into();
    let kyber_pre_key_public = kem::PublicKey::deserialize(&decode_base64(
        &record
            .libsignal_kyber_pre_key_public_b64
            .as_ref()
            .ok_or_else(|| anyhow!("libsignal_kyber_pre_key_public_b64"))?,
        "libsignal_kyber_pre_key_public_b64",
    )?)
    .map_err(|e| anyhow!("kyber pre-key public: {}", e))?;
    let kyber_pre_key_signature = decode_base64(
        &record
            .libsignal_kyber_pre_key_signature_b64
            .as_ref()
            .ok_or_else(|| anyhow!("libsignal_kyber_pre_key_signature_b64"))?,
        "libsignal_kyber_pre_key_signature_b64",
    )?;

    let pre_key = match (
        record.libsignal_pre_key_id,
        record.libsignal_pre_key_public_b64.as_ref(),
    ) {
        (Some(id), Some(pub_b64)) => {
            let pk = libsignal_protocol::PublicKey::deserialize(&decode_base64(
                pub_b64,
                "libsignal_pre_key_public_b64",
            )?)
            .map_err(|e| anyhow!("pre_key public deserialize: {}", e))?;
            Some((id.into(), pk))
        }
        _ => None,
    };

    PreKeyBundle::new(
        record.registration_id,
        dev_id,
        pre_key,
        signed_pre_key_id,
        signed_pre_key_public,
        signed_pre_key_signature,
        kyber_pre_key_id,
        kyber_pre_key_public,
        kyber_pre_key_signature,
        identity_key,
    )
    .map_err(|e| anyhow!("PreKeyBundle::new: {}", e))
}
