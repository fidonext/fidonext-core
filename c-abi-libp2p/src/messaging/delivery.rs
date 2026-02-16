use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

pub const DELIVERY_SCHEMA: &str = "fidonext-delivery-v1";
pub const DEFAULT_DELIVERY_TTL_SECONDS: u64 = 300;
pub const MIN_DELIVERY_TTL_SECONDS: u64 = 10;
pub const MAX_DELIVERY_TTL_SECONDS: u64 = 86_400;
pub const DEFAULT_MAILBOX_FETCH_LIMIT: u32 = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeliveryFrame {
    Envelope(DeliveryEnvelope),
    Ack(DeliveryAck),
    Nack(DeliveryNack),
    MailboxFetch(DeliveryMailboxFetch),
}

impl DeliveryFrame {
    pub fn schema(&self) -> &str {
        match self {
            Self::Envelope(value) => &value.schema,
            Self::Ack(value) => &value.schema,
            Self::Nack(value) => &value.schema,
            Self::MailboxFetch(value) => &value.schema,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryEnvelope {
    pub schema: String,
    pub envelope_id: String,
    pub sender_peer_id: String,
    pub recipient_peer_id: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub attempt: u32,
    pub ack_required: bool,
    pub payload_b64: String,
}

impl DeliveryEnvelope {
    pub fn sender(&self) -> Option<PeerId> {
        PeerId::from_str(self.sender_peer_id.as_str()).ok()
    }

    pub fn recipient(&self) -> Option<PeerId> {
        PeerId::from_str(self.recipient_peer_id.as_str()).ok()
    }

    pub fn payload_bytes(&self) -> Option<Vec<u8>> {
        BASE64_STANDARD.decode(self.payload_b64.as_bytes()).ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAck {
    pub schema: String,
    pub envelope_id: String,
    pub sender_peer_id: String,
    pub recipient_peer_id: String,
    #[serde(default = "default_ack_kind")]
    pub ack_kind: DeliveryAckKind,
    pub acked_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryAckKind {
    Stored,
    Delivered,
}

fn default_ack_kind() -> DeliveryAckKind {
    DeliveryAckKind::Delivered
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryNack {
    pub schema: String,
    pub envelope_id: String,
    pub sender_peer_id: String,
    pub recipient_peer_id: String,
    pub reason: DeliveryNackReason,
    pub retry_after_seconds: Option<u64>,
    pub nacked_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryNackReason {
    Expired,
    QuotaExceeded,
    InvalidRecipient,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryMailboxFetch {
    pub schema: String,
    pub requester_peer_id: String,
    pub recipient_peer_id: String,
    pub request_unix: u64,
    pub limit: u32,
}

#[derive(Debug, Deserialize)]
struct OutgoingPayloadProbe {
    to_peer_id: String,
    #[serde(default)]
    payload_type: Option<String>,
    #[serde(default)]
    message_id: Option<String>,
    #[serde(default)]
    created_at_unix: Option<u64>,
    #[serde(default)]
    delivery_ttl_seconds: Option<u64>,
}

pub fn now_unix_seconds() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}

pub fn encode_frame(frame: &DeliveryFrame) -> Option<Vec<u8>> {
    serde_json::to_vec(frame).ok()
}

pub fn parse_frame(payload: &[u8]) -> Option<DeliveryFrame> {
    let frame: DeliveryFrame = serde_json::from_slice(payload).ok()?;
    if frame.schema() != DELIVERY_SCHEMA {
        return None;
    }
    Some(frame)
}

pub fn is_addressed_payload(payload: &[u8]) -> bool {
    let parsed: OutgoingPayloadProbe = match serde_json::from_slice(payload) {
        Ok(value) => value,
        Err(_) => return false,
    };
    !parsed.to_peer_id.trim().is_empty()
}

pub fn build_envelope_from_payload(
    local_peer_id: &PeerId,
    payload: &[u8],
    sequence: u64,
    now_unix: u64,
) -> Option<DeliveryEnvelope> {
    let parsed: OutgoingPayloadProbe = serde_json::from_slice(payload).ok()?;
    if parsed.payload_type.as_deref()? != "libsignal" {
        return None;
    }
    let recipient_peer_id = PeerId::from_str(parsed.to_peer_id.trim()).ok()?;
    let envelope_id = parsed
        .message_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("env-{now_unix}-{sequence}"));
    let created_at_unix = parsed.created_at_unix.unwrap_or(now_unix);
    let ttl_seconds = sanitize_ttl(
        parsed
            .delivery_ttl_seconds
            .unwrap_or(DEFAULT_DELIVERY_TTL_SECONDS),
    );

    Some(DeliveryEnvelope {
        schema: DELIVERY_SCHEMA.to_string(),
        envelope_id,
        sender_peer_id: local_peer_id.to_string(),
        recipient_peer_id: recipient_peer_id.to_string(),
        created_at_unix,
        expires_at_unix: created_at_unix.saturating_add(ttl_seconds),
        attempt: 1,
        ack_required: true,
        payload_b64: BASE64_STANDARD.encode(payload),
    })
}

pub fn build_ack(
    envelope: &DeliveryEnvelope,
    local_peer_id: &PeerId,
    ack_kind: DeliveryAckKind,
    now_unix: u64,
) -> DeliveryAck {
    DeliveryAck {
        schema: DELIVERY_SCHEMA.to_string(),
        envelope_id: envelope.envelope_id.clone(),
        sender_peer_id: local_peer_id.to_string(),
        recipient_peer_id: envelope.sender_peer_id.clone(),
        ack_kind,
        acked_at_unix: now_unix,
    }
}

pub fn build_nack(
    envelope: &DeliveryEnvelope,
    local_peer_id: &PeerId,
    reason: DeliveryNackReason,
    retry_after_seconds: Option<u64>,
    now_unix: u64,
) -> DeliveryNack {
    DeliveryNack {
        schema: DELIVERY_SCHEMA.to_string(),
        envelope_id: envelope.envelope_id.clone(),
        sender_peer_id: local_peer_id.to_string(),
        recipient_peer_id: envelope.sender_peer_id.clone(),
        reason,
        retry_after_seconds,
        nacked_at_unix: now_unix,
    }
}

pub fn build_mailbox_fetch(local_peer_id: &PeerId, now_unix: u64) -> DeliveryMailboxFetch {
    DeliveryMailboxFetch {
        schema: DELIVERY_SCHEMA.to_string(),
        requester_peer_id: local_peer_id.to_string(),
        recipient_peer_id: local_peer_id.to_string(),
        request_unix: now_unix,
        limit: DEFAULT_MAILBOX_FETCH_LIMIT,
    }
}

fn sanitize_ttl(ttl_seconds: u64) -> u64 {
    ttl_seconds.clamp(MIN_DELIVERY_TTL_SECONDS, MAX_DELIVERY_TTL_SECONDS)
}
