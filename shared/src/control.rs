use crate::custom_type::WireguardAnswered;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use libp2p::identity;
use rand08::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub const CONTROL_PROTOCOL_VERSION: u16 = 1;

pub fn topology_topic(network_id: &str, node_id: i32) -> String {
    format!("/cat4igp/topology/v1/{network_id}/{node_id}")
}

/// Sensitive credentials an operator gives a new client over a trusted channel.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentBundle {
    pub version: u16,
    pub bootstrap_addresses: Vec<String>,
    pub controller_peer_id: String,
    pub controller_signing_key: String,
    pub network_id: String,
    pub private_network_key: String,
    pub invitation_code: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovery_bootstrap_addresses: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MessageMeta {
    /// 16 random bytes encoded as 32 lowercase hexadecimal characters.
    pub message_id: String,
    pub network_id: String,
    pub recipient_node_id: i32,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub topology_revision: i64,
}

impl MessageMeta {
    pub fn validate(&self, now_ms: i64) -> Result<(), &'static str> {
        if self.message_id.len() != 32
            || !self
                .message_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("invalid message id");
        }
        if self.network_id.is_empty() || self.recipient_node_id <= 0 {
            return Err("invalid recipient");
        }
        if self.issued_at_ms > self.expires_at_ms
            || self
                .expires_at_ms
                .checked_sub(self.issued_at_ms)
                .is_none_or(|age| age > 60_000)
            || self.issued_at_ms > now_ms.saturating_add(30_000)
            || now_ms > self.expires_at_ms
        {
            return Err("expired message");
        }
        if self.topology_revision < 0 {
            return Err("invalid topology revision");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedEnvelope {
    pub meta: MessageMeta,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedEnvelope<'a> {
    meta: &'a MessageMeta,
    ephemeral_public_key: &'a str,
    nonce: &'a str,
    ciphertext: &'a str,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str, length: usize) -> Result<Vec<u8>, &'static str> {
    if value.len() != length * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid envelope encoding");
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| "invalid envelope encoding")
        })
        .collect()
}

fn envelope_bytes(envelope: &EncryptedEnvelope) -> Result<Vec<u8>, &'static str> {
    serde_json::to_vec(&UnsignedEnvelope {
        meta: &envelope.meta,
        ephemeral_public_key: &envelope.ephemeral_public_key,
        nonce: &envelope.nonce,
        ciphertext: &envelope.ciphertext,
    })
    .map_err(|_| "failed to encode envelope")
}

/// Verify immutable recipient ciphertext without possessing the recipient's secret.
pub fn verify_topology_relay(
    signing: &identity::PublicKey,
    network: &str,
    now_ms: i64,
    payload: &[u8],
) -> Result<EncryptedEnvelope, &'static str> {
    if payload.len() > 64 * 1024 {
        return Err("relay payload exceeds limit");
    }
    let envelope: EncryptedEnvelope =
        serde_json::from_slice(payload).map_err(|_| "invalid relay envelope")?;
    envelope.meta.validate(now_ms)?;
    if envelope.meta.network_id != network {
        return Err("wrong relay network");
    }
    hex_decode(&envelope.ephemeral_public_key, 32)?;
    hex_decode(&envelope.nonce, 12)?;
    if envelope.ciphertext.len() < 32 {
        return Err("invalid relay ciphertext");
    }
    hex_decode(&envelope.ciphertext, envelope.ciphertext.len() / 2)?;
    if !signing.verify(
        &envelope_bytes(&envelope)?,
        &hex_decode(&envelope.signature, 64)?,
    ) {
        return Err("invalid relay signature");
    }
    Ok(envelope)
}

fn key(shared_secret: [u8; 32], purpose: &[u8]) -> Result<[u8; 32], &'static str> {
    let mut output = [0; 32];
    Hkdf::<Sha256>::new(Some(b"cat4igp/control/v1"), &shared_secret)
        .expand(purpose, &mut output)
        .map_err(|_| "failed to derive envelope key")?;
    Ok(output)
}

pub fn seal_topology_snapshot(
    signing_key: &identity::Keypair,
    recipient_encryption_key: &str,
    meta: MessageMeta,
    snapshot: &TopologySnapshot,
) -> Result<EncryptedEnvelope, &'static str> {
    let recipient: [u8; 32] = hex_decode(recipient_encryption_key, 32)?
        .try_into()
        .map_err(|_| "invalid envelope encoding")?;
    let ephemeral = x25519_dalek::StaticSecret::random_from_rng(rand08::rngs::OsRng);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral);
    let mut nonce = [0; 12];
    rand08::rngs::OsRng.fill_bytes(&mut nonce);
    let mut envelope = EncryptedEnvelope {
        meta,
        ephemeral_public_key: hex_encode(ephemeral_public.as_bytes()),
        nonce: hex_encode(&nonce),
        ciphertext: String::new(),
        signature: String::new(),
    };
    let aad = envelope_bytes(&envelope)?;
    let cipher = ChaCha20Poly1305::new(
        (&key(
            ephemeral
                .diffie_hellman(&x25519_dalek::PublicKey::from(recipient))
                .to_bytes(),
            b"topology",
        )?)
            .into(),
    );
    envelope.ciphertext = hex_encode(
        &cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &serde_json::to_vec(snapshot).map_err(|_| "failed to encode snapshot")?,
                    aad: &aad,
                },
            )
            .map_err(|_| "failed to encrypt snapshot")?,
    );
    envelope.signature = hex_encode(
        &signing_key
            .sign(&envelope_bytes(&envelope)?)
            .map_err(|_| "failed to sign envelope")?,
    );
    Ok(envelope)
}

pub fn open_topology_snapshot(
    controller_signing_key: &str,
    recipient_private_key: &str,
    expected_network_id: &str,
    expected_node_id: i32,
    now_ms: i64,
    envelope: &EncryptedEnvelope,
) -> Result<TopologySnapshot, &'static str> {
    envelope.meta.validate(now_ms)?;
    if envelope.meta.network_id != expected_network_id
        || envelope.meta.recipient_node_id != expected_node_id
    {
        return Err("unexpected recipient");
    }
    let signing = identity::PublicKey::try_decode_protobuf(&hex_decode(
        controller_signing_key,
        controller_signing_key.len() / 2,
    )?)
    .map_err(|_| "invalid controller signing key")?;
    let signature = hex_decode(&envelope.signature, 64)?;
    if !signing.verify(&envelope_bytes(envelope)?, &signature) {
        return Err("invalid envelope signature");
    }
    let private: [u8; 32] = hex_decode(recipient_private_key, 32)?
        .try_into()
        .map_err(|_| "invalid envelope encoding")?;
    let ephemeral: [u8; 32] = hex_decode(&envelope.ephemeral_public_key, 32)?
        .try_into()
        .map_err(|_| "invalid envelope encoding")?;
    let nonce = hex_decode(&envelope.nonce, 12)?;
    let ciphertext = hex_decode(&envelope.ciphertext, envelope.ciphertext.len() / 2)?;
    let aad = serde_json::to_vec(&UnsignedEnvelope {
        meta: &envelope.meta,
        ephemeral_public_key: &envelope.ephemeral_public_key,
        nonce: &envelope.nonce,
        ciphertext: "",
    })
    .map_err(|_| "failed to encode envelope")?;
    let cipher = ChaCha20Poly1305::new(
        (&key(
            x25519_dalek::StaticSecret::from(private)
                .diffie_hellman(&x25519_dalek::PublicKey::from(ephemeral))
                .to_bytes(),
            b"topology",
        )?)
            .into(),
    );
    serde_json::from_slice(
        &cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| "failed to decrypt snapshot")?,
    )
    .map_err(|_| "invalid snapshot")
    .and_then(|snapshot: TopologySnapshot| {
        if snapshot.node_id != envelope.meta.recipient_node_id
            || snapshot.revision != envelope.meta.topology_revision
        {
            return Err("snapshot metadata mismatch");
        }
        Ok(snapshot)
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnrollmentRequest {
    /// Empty legacy IDs are durably scoped to the authenticated client identity.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request_id: String,
    pub node_name: String,
    pub invitation_code: String,
    pub client_peer_id: String,
    pub client_signing_key: String,
    pub client_encryption_key: String,
    pub wireguard_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnrollmentResponse {
    pub node_id: i32,
    pub topology_revision: i64,
    pub network_id: String,
    pub controller_signing_key: String,
    pub controller_encryption_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WireguardTunnelInfo {
    pub tunnel_id: i32,
    pub peer_node_id: i32,
    pub public_key: String,
    pub preferred_port: u16,
    pub remote_endpoint: Option<String>,
    pub local_answered: WireguardAnswered,
    pub remote_response: WireguardAnswered,
    pub mtu: i32,
    pub endpoint_ipv6: bool,
    pub fec: bool,
    pub faketcp: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TopologySnapshot {
    pub node_id: i32,
    pub revision: i64,
    pub tunnels: Vec<WireguardTunnelInfo>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TunnelAnswer {
    pub tunnel_id: i32,
    pub decline_type: Option<i16>,
    pub endpoint: Option<String>,
}

pub fn seal_tunnel_answer(
    signing_key: &identity::Keypair,
    controller_encryption_key: &str,
    meta: MessageMeta,
    answer: &TunnelAnswer,
) -> Result<EncryptedEnvelope, &'static str> {
    let recipient: [u8; 32] = hex_decode(controller_encryption_key, 32)?
        .try_into()
        .map_err(|_| "invalid envelope encoding")?;
    let ephemeral = x25519_dalek::StaticSecret::random_from_rng(rand08::rngs::OsRng);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral);
    let mut nonce = [0; 12];
    rand08::rngs::OsRng.fill_bytes(&mut nonce);
    let mut envelope = EncryptedEnvelope {
        meta,
        ephemeral_public_key: hex_encode(ephemeral_public.as_bytes()),
        nonce: hex_encode(&nonce),
        ciphertext: String::new(),
        signature: String::new(),
    };
    let aad = envelope_bytes(&envelope)?;
    let cipher = ChaCha20Poly1305::new(
        (&key(
            ephemeral
                .diffie_hellman(&x25519_dalek::PublicKey::from(recipient))
                .to_bytes(),
            b"tunnel-answer",
        )?)
            .into(),
    );
    envelope.ciphertext = hex_encode(
        &cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &serde_json::to_vec(answer)
                        .map_err(|_| "failed to encode tunnel answer")?,
                    aad: &aad,
                },
            )
            .map_err(|_| "failed to encrypt tunnel answer")?,
    );
    envelope.signature = hex_encode(
        &signing_key
            .sign(&envelope_bytes(&envelope)?)
            .map_err(|_| "failed to sign envelope")?,
    );
    Ok(envelope)
}

pub fn open_tunnel_answer(
    client_signing_key: &str,
    controller_private_key: &str,
    expected_network_id: &str,
    expected_node_id: i32,
    now_ms: i64,
    envelope: &EncryptedEnvelope,
) -> Result<TunnelAnswer, &'static str> {
    envelope.meta.validate(now_ms)?;
    if envelope.meta.network_id != expected_network_id
        || envelope.meta.recipient_node_id != expected_node_id
    {
        return Err("unexpected recipient");
    }
    let signing = identity::PublicKey::try_decode_protobuf(&hex_decode(
        client_signing_key,
        client_signing_key.len() / 2,
    )?)
    .map_err(|_| "invalid client signing key")?;
    if !signing.verify(
        &envelope_bytes(envelope)?,
        &hex_decode(&envelope.signature, 64)?,
    ) {
        return Err("invalid envelope signature");
    }
    let private: [u8; 32] = hex_decode(controller_private_key, 32)?
        .try_into()
        .map_err(|_| "invalid envelope encoding")?;
    let ephemeral: [u8; 32] = hex_decode(&envelope.ephemeral_public_key, 32)?
        .try_into()
        .map_err(|_| "invalid envelope encoding")?;
    let nonce = hex_decode(&envelope.nonce, 12)?;
    let ciphertext = hex_decode(&envelope.ciphertext, envelope.ciphertext.len() / 2)?;
    let aad = serde_json::to_vec(&UnsignedEnvelope {
        meta: &envelope.meta,
        ephemeral_public_key: &envelope.ephemeral_public_key,
        nonce: &envelope.nonce,
        ciphertext: "",
    })
    .map_err(|_| "failed to encode envelope")?;
    let cipher = ChaCha20Poly1305::new(
        (&key(
            x25519_dalek::StaticSecret::from(private)
                .diffie_hellman(&x25519_dalek::PublicKey::from(ephemeral))
                .to_bytes(),
            b"tunnel-answer",
        )?)
            .into(),
    );
    serde_json::from_slice(
        &cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| "failed to decrypt tunnel answer")?,
    )
    .map_err(|_| "invalid tunnel answer")
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ControlRequest {
    Enroll(EnrollmentRequest),
    Snapshot,
    TunnelAnswerEnvelope(EncryptedEnvelope),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ControlResponse {
    Enrolled(EnrollmentResponse),
    SnapshotEnvelope(EncryptedEnvelope),
    Accepted,
    Rejected(String),
}

pub fn accept_revision(current: i64, received: i64) -> Result<bool, &'static str> {
    if received < 0 {
        return Err("invalid topology revision");
    }
    Ok(received > current)
}

#[cfg(test)]
#[path = "control_test.rs"]
mod tests;
