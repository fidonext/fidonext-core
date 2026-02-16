use anyhow::{anyhow, Context, Result};
use base64::Engine;
use cabi_rust_libp2p::{
    e2ee, DhtQueryError, DiscoveryQueue, MessageQueue, PeerManager, PeerManagerHandle,
    TransportConfig, DEFAULT_DISCOVERY_QUEUE_CAPACITY, DEFAULT_MESSAGE_QUEUE_CAPACITY,
};
use libp2p::Multiaddr;
use serde_json::Value;
use std::{
    fs,
    path::Path,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    task::JoinHandle,
    time::{sleep, Duration, Instant},
};

struct TestNode {
    name: &'static str,
    handle: PeerManagerHandle,
    message_queue: MessageQueue,
    task: JoinHandle<Result<()>>,
}

impl TestNode {
    async fn shutdown(self) -> Result<()> {
        self.handle
            .shutdown()
            .await
            .with_context(|| format!("{}: failed to request shutdown", self.name))?;
        let task_result = self
            .task
            .await
            .with_context(|| format!("{}: failed to join manager task", self.name))?;
        task_result.with_context(|| format!("{}: peer manager exited with error", self.name))
    }
}

async fn spawn_node(
    name: &'static str,
    listen_addr: &str,
    bootstrap_peers: Vec<Multiaddr>,
    profile_path: &Path,
) -> Result<TestNode> {
    let profile = e2ee::load_or_create_profile(profile_path)
        .with_context(|| format!("{name}: failed to load/create profile"))?;
    let config = TransportConfig::new(false, false).with_identity_seed(profile.libp2p_seed);

    let message_queue = MessageQueue::new(DEFAULT_MESSAGE_QUEUE_CAPACITY);
    let discovery_queue = DiscoveryQueue::new(DEFAULT_DISCOVERY_QUEUE_CAPACITY);
    let (manager, handle) = PeerManager::new(
        config,
        message_queue.sender(),
        discovery_queue.sender(),
        bootstrap_peers,
    )
    .with_context(|| format!("{name}: failed to initialize peer manager"))?;
    let task = tokio::spawn(async move { manager.run().await });

    handle
        .start_listening(Multiaddr::from_str(listen_addr).context("invalid listen multiaddr")?)
        .await
        .with_context(|| format!("{name}: failed to start listening"))?;

    Ok(TestNode {
        name,
        handle,
        message_queue,
        task,
    })
}

async fn wait_for_payload(node: &mut TestNode, timeout: Duration) -> Result<Vec<u8>> {
    let start = Instant::now();
    loop {
        if let Some(payload) = node.message_queue.try_dequeue() {
            return Ok(payload);
        }
        if start.elapsed() > timeout {
            return Err(anyhow!("{}: timed out waiting for payload", node.name));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn tamper_ciphertext(payload: &[u8]) -> Result<Vec<u8>> {
    let mut value: Value =
        serde_json::from_slice(payload).context("failed to parse message json for tampering")?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow!("message payload is not a json object"))?;
    let ciphertext_b64 = object
        .get("ciphertext_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("message json missing ciphertext_b64"))?;
    let mut ciphertext = base64::engine::general_purpose::STANDARD
        .decode(ciphertext_b64)
        .context("failed to decode ciphertext_b64 for tampering")?;
    if ciphertext.is_empty() {
        return Err(anyhow!("cannot tamper empty ciphertext"));
    }
    ciphertext[0] ^= 0x01;
    let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(ciphertext);
    object.insert("ciphertext_b64".to_string(), Value::String(tampered_b64));
    serde_json::to_vec(&value).context("failed to encode tampered message")
}

fn extract_u32_field(payload: &[u8], field: &str) -> Result<u32> {
    let value: Value = serde_json::from_slice(payload).context("failed to parse message json")?;
    let raw = value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("message json missing numeric field: {field}"))?;
    u32::try_from(raw).context("numeric field does not fit into u32")
}

fn bundle_contains_one_time_key_id(bundle_payload: &[u8], key_id: u32) -> Result<bool> {
    let value: Value =
        serde_json::from_slice(bundle_payload).context("failed to parse prekey bundle json")?;
    let one_time = value
        .get("one_time_pre_keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("prekey bundle missing one_time_pre_keys array"))?;
    Ok(one_time.iter().any(|entry| {
        entry
            .get("key_id")
            .and_then(Value::as_u64)
            .is_some_and(|raw| raw == u64::from(key_id))
    }))
}

fn strip_libsignal_fields_from_bundle(bundle_payload: &[u8]) -> Result<Vec<u8>> {
    let mut value: Value =
        serde_json::from_slice(bundle_payload).context("failed to parse prekey bundle json")?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow!("prekey bundle payload is not a json object"))?;
    for field in [
        "libsignal_identity_key_b64",
        "libsignal_pre_key_id",
        "libsignal_pre_key_public_b64",
        "libsignal_signed_pre_key_id",
        "libsignal_signed_pre_key_public_b64",
        "libsignal_signed_pre_key_signature_b64",
        "libsignal_kyber_pre_key_id",
        "libsignal_kyber_pre_key_public_b64",
        "libsignal_kyber_pre_key_signature_b64",
    ] {
        object.remove(field);
    }
    serde_json::to_vec(&value).context("failed to encode legacy-only prekey bundle")
}

fn unix_seconds_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs())
}

async fn wait_for_dht_record(
    handle: &PeerManagerHandle,
    key: Vec<u8>,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let start = Instant::now();
    loop {
        match handle.dht_get_record(key.clone()).await {
            Ok(value) => return Ok(value),
            Err(DhtQueryError::NotFound | DhtQueryError::Timeout) => {
                if start.elapsed() > timeout {
                    return Err(anyhow!("timed out waiting for dht record"));
                }
                sleep(Duration::from_millis(400)).await;
            }
            Err(DhtQueryError::Internal(message)) => {
                return Err(anyhow!("dht get failed: {message}"));
            }
        }
    }
}

async fn put_dht_record_with_retry(
    handle: &PeerManagerHandle,
    key: Vec<u8>,
    value: Vec<u8>,
    ttl_seconds: u64,
    timeout: Duration,
) -> Result<()> {
    let start = Instant::now();
    loop {
        match handle
            .dht_put_record(key.clone(), value.clone(), ttl_seconds)
            .await
        {
            Ok(()) => return Ok(()),
            Err(err @ DhtQueryError::Internal(_)) | Err(err @ DhtQueryError::Timeout) => {
                if start.elapsed() > timeout {
                    return Err(anyhow!("timed out publishing dht record: {err:?}"));
                }
                sleep(Duration::from_millis(400)).await;
            }
            Err(err) => return Err(anyhow!("failed to publish dht record: {err:?}")),
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let temp_root = std::env::temp_dir().join("fidonext-e2ee-local-mesh-rust");
    if temp_root.exists() {
        fs::remove_dir_all(&temp_root)
            .with_context(|| format!("failed to clear temp dir: {}", temp_root.display()))?;
    }
    fs::create_dir_all(&temp_root)
        .with_context(|| format!("failed to create temp dir: {}", temp_root.display()))?;

    let relay_profile = temp_root.join("relay_profile.json");
    let leaf_a_profile = temp_root.join("leaf_a_profile.json");
    let leaf_b_profile = temp_root.join("leaf_b_profile.json");

    let relay_listen = "/ip4/127.0.0.1/tcp/43100";
    let leaf_a_listen = "/ip4/127.0.0.1/tcp/43101";
    let leaf_b_listen = "/ip4/127.0.0.1/tcp/43102";

    let mut relay: Option<TestNode> = None;
    let mut leaf_a: Option<TestNode> = None;
    let mut leaf_b: Option<TestNode> = None;

    let run_result: Result<()> = async {
        relay = Some(spawn_node("relay", relay_listen, vec![], &relay_profile).await?);
        let relay_peer_id = relay
            .as_ref()
            .ok_or_else(|| anyhow!("relay not initialized"))?
            .handle
            .local_peer_id();
        let bootstrap_addr = Multiaddr::from_str(&format!("{relay_listen}/p2p/{relay_peer_id}"))
            .context("invalid relay bootstrap address")?;
        println!("[e2ee-local-mesh] relay peer_id={relay_peer_id}");

        leaf_b = Some(
            spawn_node(
                "leaf_b",
                leaf_b_listen,
                vec![bootstrap_addr.clone()],
                &leaf_b_profile,
            )
            .await?,
        );
        leaf_b
            .as_ref()
            .ok_or_else(|| anyhow!("leaf_b not initialized"))?
            .handle
            .dial(bootstrap_addr.clone())
            .await
            .context("leaf_b failed to dial relay")?;

        leaf_a = Some(
            spawn_node(
                "leaf_a",
                leaf_a_listen,
                vec![bootstrap_addr.clone()],
                &leaf_a_profile,
            )
            .await?,
        );
        leaf_a
            .as_ref()
            .ok_or_else(|| anyhow!("leaf_a not initialized"))?
            .handle
            .dial(bootstrap_addr.clone())
            .await
            .context("leaf_a failed to dial relay")?;

        sleep(Duration::from_secs(2)).await;

        let leaf_a_identity = e2ee::load_or_create_profile(&leaf_a_profile)
            .context("failed to load leaf_a profile")?;
        let leaf_a_prekey_bundle = e2ee::build_prekey_bundle(&leaf_a_profile, 16, 3600)
            .context("failed to build leaf_a prekey bundle")?;
        let leaf_a_prekey_bundle_key =
            e2ee::prekey_bundle_dht_key(&leaf_a_identity.account_id, &leaf_a_identity.device_id)
                .context("failed to derive leaf_a prekey bundle dht key")?;
        put_dht_record_with_retry(
            &leaf_a
                .as_ref()
                .ok_or_else(|| anyhow!("leaf_a not initialized"))?
                .handle,
            leaf_a_prekey_bundle_key.clone(),
            leaf_a_prekey_bundle.clone(),
            3600,
            Duration::from_secs(20),
        )
        .await
        .context("failed to publish leaf_a prekey bundle to dht")?;

        let prekey_bundle = e2ee::build_prekey_bundle(&leaf_b_profile, 16, 3600)
            .context("failed to build prekey bundle")?;
        let leaf_b_identity = e2ee::load_or_create_profile(&leaf_b_profile)
            .context("failed to load leaf_b profile for dht publication")?;
        let prekey_bundle_key =
            e2ee::prekey_bundle_dht_key(&leaf_b_identity.account_id, &leaf_b_identity.device_id)
                .context("failed to derive prekey bundle dht key")?;
        put_dht_record_with_retry(
            &leaf_b
                .as_ref()
                .ok_or_else(|| anyhow!("leaf_b not initialized"))?
                .handle,
            prekey_bundle_key.clone(),
            prekey_bundle.clone(),
            3600,
            Duration::from_secs(20),
        )
        .await
        .context("failed to publish prekey bundle to dht")?;
        let key_update_revision = e2ee::resolve_key_update_revision(&leaf_b_profile, 0)
            .context("failed to resolve key update revision")?;
        let key_update = e2ee::build_key_update(
            &leaf_b_identity,
            &leaf_b
                .as_ref()
                .ok_or_else(|| anyhow!("leaf_b not initialized"))?
                .handle
                .local_peer_id(),
            key_update_revision,
            3600,
        )
        .context("failed to build key update")?;
        let key_update_key =
            e2ee::key_update_dht_key(&leaf_b_identity.account_id, &leaf_b_identity.device_id)
                .context("failed to derive key update dht key")?;
        put_dht_record_with_retry(
            &leaf_b
                .as_ref()
                .ok_or_else(|| anyhow!("leaf_b not initialized"))?
                .handle,
            key_update_key.clone(),
            key_update.clone(),
            3600,
            Duration::from_secs(20),
        )
        .await
        .context("failed to publish key update to dht")?;
        let fetched_prekey_bundle = wait_for_dht_record(
            &leaf_a
                .as_ref()
                .ok_or_else(|| anyhow!("leaf_a not initialized"))?
                .handle,
            prekey_bundle_key,
            Duration::from_secs(20),
        )
        .await
        .context("leaf_a failed to fetch prekey bundle from dht")?;
        let _ = e2ee::validate_prekey_bundle(&fetched_prekey_bundle, unix_seconds_now()?)
            .context("fetched prekey bundle validation failed")?;
        println!("[e2ee-local-mesh] prekey bundle published/fetched via dht");

        let fetched_key_update = wait_for_dht_record(
            &leaf_a
                .as_ref()
                .ok_or_else(|| anyhow!("leaf_a not initialized"))?
                .handle,
            key_update_key,
            Duration::from_secs(20),
        )
        .await
        .context("leaf_a failed to fetch key update from dht")?;
        let _ = e2ee::validate_key_update(&fetched_key_update, unix_seconds_now()?)
            .context("fetched key update validation failed")?;
        println!("[e2ee-local-mesh] key update published/fetched via dht");

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before unix epoch")?
            .as_secs();
        let expired_bundle_result = e2ee::validate_prekey_bundle(
            &prekey_bundle,
            now_unix.saturating_add(30 * 24 * 60 * 60),
        );
        if expired_bundle_result.is_ok() {
            return Err(anyhow!("expired bundle validation unexpectedly succeeded"));
        }
        println!("[e2ee-local-mesh] expired bundle rejected as expected");

        let prekey_plaintext = b"hello-from-rust-prekey".to_vec();
        let legacy_only_bundle = strip_libsignal_fields_from_bundle(&fetched_prekey_bundle)
            .context("failed to derive legacy-only bundle fixture")?;
        let legacy_auto_result = e2ee::build_message_auto(
            &leaf_a_profile,
            &legacy_only_bundle,
            &prekey_plaintext,
            b"rust-mesh-smoke",
        );
        if legacy_auto_result.is_ok() {
            return Err(anyhow!(
                "strict libsignal auto mode unexpectedly accepted a legacy-only bundle"
            ));
        }
        println!("[e2ee-local-mesh] strict auto mode rejects legacy-only bundle");

        let outbound_prekey = e2ee::build_message_auto(
            &leaf_a_profile,
            &fetched_prekey_bundle,
            &prekey_plaintext,
            b"rust-mesh-smoke",
        )
        .context("failed to build automatic outbound prekey message")?;
        let used_one_time_key_id =
            extract_u32_field(&outbound_prekey.payload, "recipient_one_time_pre_key_id")
                .context("failed to extract recipient_one_time_pre_key_id from prekey message")?;
        if outbound_prekey.used_session {
            return Err(anyhow!(
                "auto mode unexpectedly used session for first contact"
            ));
        }
        let wrong_recipient_result =
            e2ee::decrypt_message_auto(&relay_profile, &outbound_prekey.payload);
        if wrong_recipient_result.is_ok() {
            return Err(anyhow!(
                "wrong-recipient check failed: relay decrypted leaf_b prekey message"
            ));
        }
        println!("[e2ee-local-mesh] wrong recipient rejected as expected");

        leaf_a
            .as_ref()
            .ok_or_else(|| anyhow!("leaf_a not initialized"))?
            .handle
            .publish(outbound_prekey.payload.clone())
            .await
            .context("leaf_a failed to publish prekey message")?;

        let inbound_prekey = wait_for_payload(
            leaf_b.as_mut().ok_or_else(|| anyhow!("leaf_b not initialized"))?,
            Duration::from_secs(15),
        )
        .await?;
        let decrypted_prekey = e2ee::decrypt_message_auto(&leaf_b_profile, &inbound_prekey)
            .context("leaf_b failed to decrypt automatic prekey message")?;
        if decrypted_prekey.kind != e2ee::DecryptedMessageKind::PreKey {
            return Err(anyhow!("expected prekey message on first contact"));
        }
        if decrypted_prekey.plaintext != prekey_plaintext {
            return Err(anyhow!("prekey plaintext mismatch"));
        }
        println!("[e2ee-local-mesh] prekey message decrypted on leaf_b");
        let legacy_payload = e2ee::build_prekey_message(
            &leaf_a_profile,
            &fetched_prekey_bundle,
            b"legacy-prekey-should-fail",
            b"rust-mesh-smoke",
        )
        .context("failed to build legacy prekey fixture payload")?;
        let legacy_decrypt_result = e2ee::decrypt_message_auto(&leaf_b_profile, &legacy_payload);
        if legacy_decrypt_result.is_ok() {
            return Err(anyhow!(
                "strict libsignal auto mode unexpectedly decrypted legacy prekey payload"
            ));
        }
        println!("[e2ee-local-mesh] strict auto decrypt rejects legacy payload");
        let refreshed_bundle = e2ee::build_prekey_bundle(&leaf_b_profile, 16, 3600)
            .context("failed to rebuild prekey bundle after prekey decrypt")?;
        if bundle_contains_one_time_key_id(&refreshed_bundle, used_one_time_key_id)? {
            return Err(anyhow!(
                "one-time pre-key was not consumed after first contact (key_id={used_one_time_key_id})"
            ));
        }
        println!("[e2ee-local-mesh] one-time pre-key consumption verified");

        let leaf_a_bundle = wait_for_dht_record(
            &leaf_b
                .as_ref()
                .ok_or_else(|| anyhow!("leaf_b not initialized"))?
                .handle,
            leaf_a_prekey_bundle_key,
            Duration::from_secs(20),
        )
        .await
        .context("leaf_b failed to fetch leaf_a prekey bundle from dht")?;
        let reply_plaintext = b"reply-from-leaf-b";
        let outbound_reply = e2ee::build_message_auto(
            &leaf_b_profile,
            &leaf_a_bundle,
            reply_plaintext,
            b"rust-mesh-smoke",
        )
        .context("failed to build leaf_b reply to leaf_a")?;
        leaf_b
            .as_ref()
            .ok_or_else(|| anyhow!("leaf_b not initialized"))?
            .handle
            .publish(outbound_reply.payload.clone())
            .await
            .context("leaf_b failed to publish reply to leaf_a")?;

        let inbound_reply = wait_for_payload(
            leaf_a.as_mut().ok_or_else(|| anyhow!("leaf_a not initialized"))?,
            Duration::from_secs(15),
        )
        .await?;
        let decrypted_reply =
            e2ee::decrypt_message_auto(&leaf_a_profile, &inbound_reply)
                .context("leaf_a failed to decrypt reply from leaf_b")?;
        if decrypted_reply.plaintext != reply_plaintext {
            return Err(anyhow!("reply plaintext mismatch"));
        }
        println!("[e2ee-local-mesh] leaf_a received reply from leaf_b (session acknowledged)");

        let session_plaintext = b"hello-from-rust-session".to_vec();
        let outbound_session = e2ee::build_message_auto(
            &leaf_a_profile,
            &fetched_prekey_bundle,
            &session_plaintext,
            b"rust-mesh-smoke",
        )
        .context("failed to build automatic outbound session message")?;
        if !outbound_session.used_session {
            return Err(anyhow!("auto mode did not switch to session message"));
        }
        if outbound_prekey.session_id != outbound_session.session_id {
            return Err(anyhow!(
                "auto mode produced inconsistent session id across messages"
            ));
        }
        leaf_a
            .as_ref()
            .ok_or_else(|| anyhow!("leaf_a not initialized"))?
            .handle
            .publish(outbound_session.payload.clone())
            .await
            .context("leaf_a failed to publish session message")?;

        let inbound_session = wait_for_payload(
            leaf_b.as_mut().ok_or_else(|| anyhow!("leaf_b not initialized"))?,
            Duration::from_secs(15),
        )
        .await?;
        let tampered_session = tamper_ciphertext(&inbound_session)?;
        let tampered_result = e2ee::decrypt_message_auto(&leaf_b_profile, &tampered_session);
        if tampered_result.is_ok() {
            return Err(anyhow!(
                "tampered payload check failed: modified session message decrypted"
            ));
        }
        println!("[e2ee-local-mesh] tampered payload rejected as expected");

        let decrypted_session = e2ee::decrypt_message_auto(&leaf_b_profile, &inbound_session)
            .context("leaf_b failed to decrypt automatic session message")?;
        if decrypted_session.kind != e2ee::DecryptedMessageKind::Session {
            return Err(anyhow!("expected session message after first contact"));
        }
        if decrypted_session.plaintext != session_plaintext {
            return Err(anyhow!("session plaintext mismatch"));
        }
        println!("[e2ee-local-mesh] session message decrypted on leaf_b");

        let replay_result = e2ee::decrypt_message_auto(&leaf_b_profile, &inbound_session);
        if replay_result.is_ok() {
            return Err(anyhow!("replay protection failed: duplicate session message decrypted"));
        }
        println!("[e2ee-local-mesh] replay protection verified");

        Ok(())
    }
    .await;

    let mut final_error = run_result.err();
    if let Some(node) = leaf_a.take() {
        if let Err(err) = node.shutdown().await {
            final_error.get_or_insert(err);
        }
    }
    if let Some(node) = leaf_b.take() {
        if let Err(err) = node.shutdown().await {
            final_error.get_or_insert(err);
        }
    }
    if let Some(node) = relay.take() {
        if let Err(err) = node.shutdown().await {
            final_error.get_or_insert(err);
        }
    }

    if let Some(err) = final_error {
        return Err(err);
    }

    println!(
        "[e2ee-local-mesh] success; temp data: {}",
        temp_root.display()
    );
    Ok(())
}
