use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

pub const CONTROL_KIND_HELLO: u8 = 1;
pub const CONTROL_KIND_HELLO_ACK: u8 = 2;
pub const CONTROL_KIND_RESUME: u8 = 3;
pub const CONTROL_KIND_RESUME_ACK: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Server,
    Client,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    Hello(Hello),
    HelloAck(HelloAck),
    Resume(Resume),
    ResumeAck(ResumeAck),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub session_id: u64,
    pub timestamp_ms: u64,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAck {
    pub session_id: u64,
    pub timestamp_ms: u64,
    pub public_key: [u8; 32],
    pub role: Role,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resume {
    pub session_id: u64,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeAck {
    pub session_id: u64,
    pub accepted: bool,
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("control payload too short")]
    TooShort,
    #[error("unknown control message kind: {0}")]
    UnknownKind(u8),
    #[error("invalid control payload")]
    InvalidPayload,
    #[error("crypto error")]
    Crypto,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn random_u64() -> u64 {
    let mut rng = OsRng;
    rng.next_u64()
}

pub fn generate_local_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

pub fn derive_shared_key(local_secret: [u8; 32], remote_public: [u8; 32], local_session: u64, remote_session: u64) -> [u8; 32] {
    let secret = StaticSecret::from(local_secret);
    let remote = PublicKey::from(remote_public);
    let shared = secret.diffie_hellman(&remote);

    let mut hasher = Sha256::new();
    hasher.update(shared.as_bytes());
    hasher.update(local_session.to_be_bytes());
    hasher.update(remote_session.to_be_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    key
}

pub fn encrypt_with_key(key: [u8; 32], nonce: [u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::from_slice(&nonce);
    cipher.encrypt(nonce, plaintext).map_err(|_| HandshakeError::Crypto)
}

pub fn decrypt_with_key(key: [u8; 32], nonce: [u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::from_slice(&nonce);
    cipher.decrypt(nonce, ciphertext).map_err(|_| HandshakeError::Crypto)
}

pub fn random_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn encode_control_message(msg: &ControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    match msg {
        ControlMessage::Hello(v) => {
            out.push(CONTROL_KIND_HELLO);
            out.extend_from_slice(&v.session_id.to_be_bytes());
            out.extend_from_slice(&v.timestamp_ms.to_be_bytes());
            out.extend_from_slice(&v.public_key);
        }
        ControlMessage::HelloAck(v) => {
            out.push(CONTROL_KIND_HELLO_ACK);
            out.extend_from_slice(&v.session_id.to_be_bytes());
            out.extend_from_slice(&v.timestamp_ms.to_be_bytes());
            out.extend_from_slice(&v.public_key);
            out.push(match v.role {
                Role::Server => 1,
                Role::Client => 2,
            });
        }
        ControlMessage::Resume(v) => {
            out.push(CONTROL_KIND_RESUME);
            out.extend_from_slice(&v.session_id.to_be_bytes());
            out.extend_from_slice(&v.nonce);
            out.extend_from_slice(&(v.ciphertext.len() as u16).to_be_bytes());
            out.extend_from_slice(&v.ciphertext);
        }
        ControlMessage::ResumeAck(v) => {
            out.push(CONTROL_KIND_RESUME_ACK);
            out.extend_from_slice(&v.session_id.to_be_bytes());
            out.push(if v.accepted { 1 } else { 0 });
        }
    }
    out
}

pub fn decode_control_message(buf: &[u8]) -> Result<ControlMessage, HandshakeError> {
    if buf.is_empty() {
        return Err(HandshakeError::TooShort);
    }

    match buf[0] {
        CONTROL_KIND_HELLO => {
            if buf.len() < 1 + 8 + 8 + 32 {
                return Err(HandshakeError::TooShort);
            }
            let session_id = u64::from_be_bytes(buf[1..9].try_into().map_err(|_| HandshakeError::InvalidPayload)?);
            let timestamp_ms = u64::from_be_bytes(buf[9..17].try_into().map_err(|_| HandshakeError::InvalidPayload)?);
            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&buf[17..49]);
            Ok(ControlMessage::Hello(Hello {
                session_id,
                timestamp_ms,
                public_key,
            }))
        }
        CONTROL_KIND_HELLO_ACK => {
            if buf.len() < 1 + 8 + 8 + 32 + 1 {
                return Err(HandshakeError::TooShort);
            }
            let session_id = u64::from_be_bytes(buf[1..9].try_into().map_err(|_| HandshakeError::InvalidPayload)?);
            let timestamp_ms = u64::from_be_bytes(buf[9..17].try_into().map_err(|_| HandshakeError::InvalidPayload)?);
            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&buf[17..49]);
            let role = match buf[49] {
                1 => Role::Server,
                2 => Role::Client,
                _ => return Err(HandshakeError::InvalidPayload),
            };
            Ok(ControlMessage::HelloAck(HelloAck {
                session_id,
                timestamp_ms,
                public_key,
                role,
            }))
        }
        CONTROL_KIND_RESUME => {
            if buf.len() < 1 + 8 + 12 + 2 {
                return Err(HandshakeError::TooShort);
            }
            let session_id = u64::from_be_bytes(buf[1..9].try_into().map_err(|_| HandshakeError::InvalidPayload)?);
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&buf[9..21]);
            let ciphertext_len = u16::from_be_bytes(buf[21..23].try_into().map_err(|_| HandshakeError::InvalidPayload)?) as usize;
            if buf.len() != 23 + ciphertext_len {
                return Err(HandshakeError::InvalidPayload);
            }
            Ok(ControlMessage::Resume(Resume {
                session_id,
                nonce,
                ciphertext: buf[23..].to_vec(),
            }))
        }
        CONTROL_KIND_RESUME_ACK => {
            if buf.len() < 1 + 8 + 1 {
                return Err(HandshakeError::TooShort);
            }
            let session_id = u64::from_be_bytes(buf[1..9].try_into().map_err(|_| HandshakeError::InvalidPayload)?);
            let accepted = buf[9] == 1;
            Ok(ControlMessage::ResumeAck(ResumeAck {
                session_id,
                accepted,
            }))
        }
        other => Err(HandshakeError::UnknownKind(other)),
    }
}

pub fn choose_server_role(local_timestamp: u64, remote_timestamp: u64, local_session: u64, remote_session: u64) -> Role {
    if local_timestamp < remote_timestamp {
        Role::Server
    } else if local_timestamp > remote_timestamp {
        Role::Client
    } else if local_session <= remote_session {
        Role::Server
    } else {
        Role::Client
    }
}

pub fn encode_resume_plaintext(local_session: u64, remote_session: u64, timestamp_ms: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&local_session.to_be_bytes());
    out.extend_from_slice(&remote_session.to_be_bytes());
    out.extend_from_slice(&timestamp_ms.to_be_bytes());
    out
}

pub fn decode_resume_plaintext(buf: &[u8]) -> Result<(u64, u64, u64), HandshakeError> {
    if buf.len() != 24 {
        return Err(HandshakeError::InvalidPayload);
    }
    let local_session = u64::from_be_bytes(buf[0..8].try_into().map_err(|_| HandshakeError::InvalidPayload)?);
    let remote_session = u64::from_be_bytes(buf[8..16].try_into().map_err(|_| HandshakeError::InvalidPayload)?);
    let timestamp_ms = u64::from_be_bytes(buf[16..24].try_into().map_err(|_| HandshakeError::InvalidPayload)?);
    Ok((local_session, remote_session, timestamp_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_roundtrip() {
        let hello = ControlMessage::Hello(Hello {
            session_id: 10,
            timestamp_ms: 20,
            public_key: [7u8; 32],
        });
        let encoded = encode_control_message(&hello);
        let decoded = decode_control_message(&encoded).expect("decode hello");
        assert_eq!(decoded, hello);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [9u8; 32];
        let nonce = [3u8; 12];
        let plaintext = b"resume-data";
        let encrypted = encrypt_with_key(key, nonce, plaintext).expect("encrypt");
        let decrypted = decrypt_with_key(key, nonce, &encrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }
}
