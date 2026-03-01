use std::path::PathBuf;

use anyhow::{Context, Result};
use libp2p::PeerId;

use crate::messaging::DeliveryEnvelope;

const KEY_MSG_PREFIX: &str = "msg|";
const KEY_IDX_PREFIX: &str = "idx|";

#[derive(Debug, Clone, Copy)]
pub struct MailboxStoreLimits {
    pub max_messages_per_recipient: usize,
    pub max_bytes_per_recipient: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxStoreInsertOutcome {
    Stored,
    Duplicate,
    QuotaExceeded,
}

#[derive(Debug)]
pub struct PersistentMailboxStore {
    db: sled::Db,
}

impl PersistentMailboxStore {
    pub fn open(local_peer_id: &PeerId) -> Result<Self> {
        let base_dir = std::env::var("FIDONEXT_MAILBOX_DB_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/fidonext-mailbox"));
        let path = base_dir.join(local_peer_id.to_string());
        std::fs::create_dir_all(&path).with_context(|| {
            format!(
                "failed to create mailbox persistence directory: {}",
                path.display()
            )
        })?;
        let db = sled::open(&path)
            .with_context(|| format!("failed to open mailbox store at {}", path.display()))?;
        Ok(Self { db })
    }

    pub fn store_envelope(
        &self,
        recipient_peer_id: &PeerId,
        envelope: &DeliveryEnvelope,
        limits: MailboxStoreLimits,
    ) -> Result<MailboxStoreInsertOutcome> {
        let idx_key = idx_key(recipient_peer_id, &envelope.envelope_id);
        if self.db.contains_key(&idx_key)? {
            return Ok(MailboxStoreInsertOutcome::Duplicate);
        }

        let serialized = serde_json::to_vec(envelope).context("failed to serialize mailbox envelope")?;
        let (count, bytes) = self.recipient_usage(recipient_peer_id)?;
        if count >= limits.max_messages_per_recipient
            || bytes.saturating_add(serialized.len()) > limits.max_bytes_per_recipient
        {
            return Ok(MailboxStoreInsertOutcome::QuotaExceeded);
        }

        let msg_key = msg_key(recipient_peer_id, envelope.created_at_unix, &envelope.envelope_id);
        self.db.insert(&msg_key, serialized)?;
        self.db.insert(&idx_key, msg_key.as_bytes())?;
        Ok(MailboxStoreInsertOutcome::Stored)
    }

    pub fn fetch_envelopes(
        &self,
        recipient_peer_id: &PeerId,
        limit: usize,
        now_unix: u64,
    ) -> Result<Vec<DeliveryEnvelope>> {
        let mut envelopes = Vec::with_capacity(limit);
        let prefix = msg_prefix(recipient_peer_id);
        let mut expired = Vec::new();

        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (key, value) = item?;
            let mut envelope: DeliveryEnvelope = match serde_json::from_slice(&value) {
                Ok(v) => v,
                Err(_) => {
                    if let Some(envelope_id) = envelope_id_from_key(&key) {
                        expired.push((recipient_peer_id.to_string(), envelope_id));
                    }
                    continue;
                }
            };
            if envelope.expires_at_unix <= now_unix {
                expired.push((recipient_peer_id.to_string(), envelope.envelope_id.clone()));
                continue;
            }
            envelope.attempt = envelope.attempt.max(1);
            envelopes.push(envelope);
            if envelopes.len() >= limit {
                break;
            }
        }

        for (recipient, envelope_id) in expired {
            if let Ok(peer_id) = recipient.parse::<PeerId>() {
                let _ = self.remove_envelope(&peer_id, &envelope_id);
            }
        }

        Ok(envelopes)
    }

    pub fn remove_envelope(&self, recipient_peer_id: &PeerId, envelope_id: &str) -> Result<bool> {
        let idx_key = idx_key(recipient_peer_id, envelope_id);
        let Some(msg_key) = self.db.remove(&idx_key)? else {
            return Ok(false);
        };
        self.db.remove(msg_key)?;
        Ok(true)
    }

    pub fn prune_expired(&self, now_unix: u64) -> Result<()> {
        let mut expired = Vec::new();
        for item in self.db.scan_prefix(KEY_MSG_PREFIX.as_bytes()) {
            let (key, value) = item?;
            let envelope: DeliveryEnvelope = match serde_json::from_slice(&value) {
                Ok(v) => v,
                Err(_) => {
                    if let Some((recipient, envelope_id)) = recipient_and_envelope_from_key(&key) {
                        expired.push((recipient, envelope_id));
                    }
                    continue;
                }
            };
            if envelope.expires_at_unix <= now_unix {
                if let Some((recipient, envelope_id)) = recipient_and_envelope_from_key(&key) {
                    expired.push((recipient, envelope_id));
                }
            }
        }
        for (recipient, envelope_id) in expired {
            if let Ok(recipient_peer_id) = recipient.parse::<PeerId>() {
                let _ = self.remove_envelope(&recipient_peer_id, envelope_id.as_str());
            }
        }
        Ok(())
    }

    fn recipient_usage(&self, recipient_peer_id: &PeerId) -> Result<(usize, usize)> {
        let prefix = msg_prefix(recipient_peer_id);
        let mut count = 0usize;
        let mut bytes = 0usize;
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (_key, value) = item?;
            count = count.saturating_add(1);
            bytes = bytes.saturating_add(value.len());
        }
        Ok((count, bytes))
    }
}

fn msg_prefix(recipient_peer_id: &PeerId) -> String {
    format!("{KEY_MSG_PREFIX}{}|", recipient_peer_id)
}

fn msg_key(recipient_peer_id: &PeerId, created_at_unix: u64, envelope_id: &str) -> String {
    format!(
        "{KEY_MSG_PREFIX}{}|{:020}|{}",
        recipient_peer_id, created_at_unix, envelope_id
    )
}

fn idx_key(recipient_peer_id: &PeerId, envelope_id: &str) -> String {
    format!("{KEY_IDX_PREFIX}{}|{}", recipient_peer_id, envelope_id)
}

fn envelope_id_from_key(key: &[u8]) -> Option<String> {
    recipient_and_envelope_from_key(key).map(|(_, envelope_id)| envelope_id)
}

fn recipient_and_envelope_from_key(key: &[u8]) -> Option<(String, String)> {
    let raw = std::str::from_utf8(key).ok()?;
    if !raw.starts_with(KEY_MSG_PREFIX) {
        return None;
    }
    let mut parts = raw.split('|');
    let prefix = parts.next()?;
    if prefix != "msg" {
        return None;
    }
    let recipient = parts.next()?.to_string();
    let _created = parts.next()?;
    let envelope_id = parts.next()?.to_string();
    Some((recipient, envelope_id))
}
