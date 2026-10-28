//! Signed, recipient-sealed CAT4IGP control-plane messages.

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

pub const VERSION: u16 = 1;
pub const MAX_ENROLLMENT_PAYLOAD_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct NetworkId(String);

impl NetworkId {
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 {
            return Err(Error::InvalidNetworkId);
        }
        Ok(Self(value))
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    pub fn from_command_key(key: &PublicKey) -> Self {
        Self(STANDARD_NO_PAD.encode(blake3::hash(key.as_bytes()).as_bytes()))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesiredState {
    pub node_id: NodeId,
    pub revision: u64,
    pub wireguard: Vec<WireGuardPeer>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WireGuardPeer {
    /// Existing local interface dedicated to this point-to-point link.
    pub interface: String,
    pub public_key: String,
    pub endpoint: String,
    pub fec_enabled: bool,
    /// Cryptokey-routing selectors only. The node must never install OS routes.
    pub allowed_ips: [String; 2],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedCommand {
    pub version: u16,
    pub network_id: NetworkId,
    pub recipient: NodeId,
    pub revision: u64,
    pub expires_at_unix: u64,
    pub ephemeral_public_key: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedCommand {
    pub command: SealedCommand,
    pub signature: Vec<u8>,
}

/// Request-response payload used only for one-time controller enrollment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub token: String,
    pub libp2p_peer_id: String,
    pub command_public_key: [u8; 32],
    pub wireguard_public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub node_id: NodeId,
    pub network_id: NetworkId,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("network ID must be 1–128 bytes")]
    InvalidNetworkId,
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("invalid server signature")]
    InvalidSignature,
    #[error("signature has invalid length")]
    InvalidSignatureLength,
    #[error("command is expired")]
    Expired,
    #[error("command revision is not newer than accepted revision")]
    StaleRevision,
    #[error("command network does not match")]
    WrongNetwork,
    #[error("command recipient does not match")]
    WrongRecipient,
    #[error("desired state does not match its command metadata")]
    StateMismatch,
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("command encryption/decryption failed")]
    Cryptography,
    #[error("enrollment payload exceeds the size limit")]
    EnrollmentTooLarge,
}

pub fn decode_enrollment_request(payload: &[u8]) -> Result<EnrollmentRequest, Error> {
    if payload.len() > MAX_ENROLLMENT_PAYLOAD_BYTES {
        return Err(Error::EnrollmentTooLarge);
    }
    Ok(serde_json::from_slice(payload)?)
}

pub fn encode_enrollment_response(response: &EnrollmentResponse) -> Result<Vec<u8>, Error> {
    let payload = serde_json::to_vec(response)?;
    if payload.len() > MAX_ENROLLMENT_PAYLOAD_BYTES {
        return Err(Error::EnrollmentTooLarge);
    }
    Ok(payload)
}

pub fn seal_and_sign<T: Serialize>(
    state: &T,
    network_id: NetworkId,
    recipient_key: &PublicKey,
    revision: u64,
    expires_at_unix: u64,
    server_key: &SigningKey,
) -> Result<SignedCommand, Error> {
    let recipient = NodeId::from_command_key(recipient_key);
    let plaintext = serde_json::to_vec(state)?;
    let ephemeral_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public_key = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(recipient_key);
    let cipher = ChaCha20Poly1305::new_from_slice(blake3::hash(shared.as_bytes()).as_bytes())
        .map_err(|_| Error::Cryptography)?;
    let mut nonce = [0; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let command = SealedCommand {
        version: VERSION,
        network_id,
        recipient,
        revision,
        expires_at_unix,
        ephemeral_public_key: *ephemeral_public_key.as_bytes(),
        nonce,
        ciphertext: cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|_| Error::Cryptography)?,
    };
    let signature = server_key.sign(&canonical(&command)?).to_bytes().to_vec();
    Ok(SignedCommand { command, signature })
}

pub fn verify_and_open<T: DeserializeOwned>(
    signed: &SignedCommand,
    expected_network: &NetworkId,
    recipient_secret: &StaticSecret,
    server_key: &VerifyingKey,
    now_unix: u64,
) -> Result<T, Error> {
    if signed.command.version != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if &signed.command.network_id != expected_network {
        return Err(Error::WrongNetwork);
    }
    if signed.command.expires_at_unix < now_unix {
        return Err(Error::Expired);
    }
    let signature =
        Signature::from_slice(&signed.signature).map_err(|_| Error::InvalidSignatureLength)?;
    server_key
        .verify(&canonical(&signed.command)?, &signature)
        .map_err(|_| Error::InvalidSignature)?;
    let recipient = NodeId::from_command_key(&PublicKey::from(recipient_secret));
    if signed.command.recipient != recipient {
        return Err(Error::WrongRecipient);
    }
    let peer = PublicKey::from(signed.command.ephemeral_public_key);
    let shared = recipient_secret.diffie_hellman(&peer);
    let cipher = ChaCha20Poly1305::new_from_slice(blake3::hash(shared.as_bytes()).as_bytes())
        .map_err(|_| Error::Cryptography)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&signed.command.nonce),
            signed.command.ciphertext.as_ref(),
        )
        .map_err(|_| Error::Cryptography)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

/// Opens desired state and binds its target and revision to the signed envelope.
pub fn verify_desired_state(
    signed: &SignedCommand,
    expected_network: &NetworkId,
    recipient_secret: &StaticSecret,
    server_key: &VerifyingKey,
    now_unix: u64,
) -> Result<DesiredState, Error> {
    let state: DesiredState = verify_and_open(
        signed,
        expected_network,
        recipient_secret,
        server_key,
        now_unix,
    )?;
    if state.node_id != signed.command.recipient || state.revision != signed.command.revision {
        return Err(Error::StateMismatch);
    }
    if state
        .wireguard
        .iter()
        .any(|peer| peer.allowed_ips[0] != "0.0.0.0/0" || peer.allowed_ips[1] != "::/0")
    {
        return Err(Error::StateMismatch);
    }
    Ok(state)
}

/// Rejects a replayed command before host-network state is reconciled.
pub fn require_newer_revision(revision: u64, accepted_revision: u64) -> Result<(), Error> {
    if revision <= accepted_revision {
        return Err(Error::StaleRevision);
    }
    Ok(())
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn canonical(command: &SealedCommand) -> Result<Vec<u8>, Error> {
    Ok(serde_json::to_vec(command)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_command_rejects_tampering_and_wrong_network() {
        let server = SigningKey::generate(&mut rand::rngs::OsRng);
        let recipient = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let network = NetworkId::new("test-network").unwrap();
        let state = DesiredState {
            node_id: NodeId::from_command_key(&PublicKey::from(&recipient)),
            revision: 1,
            wireguard: vec![],
        };
        let mut command = seal_and_sign(
            &state,
            network.clone(),
            &PublicKey::from(&recipient),
            1,
            2,
            &server,
        )
        .unwrap();
        assert_eq!(
            verify_desired_state(&command, &network, &recipient, &server.verifying_key(), 1)
                .unwrap(),
            state
        );
        command.command.revision = 2;
        assert!(matches!(
            verify_and_open::<DesiredState>(
                &command,
                &network,
                &recipient,
                &server.verifying_key(),
                1
            ),
            Err(Error::InvalidSignature)
        ));
        let command =
            seal_and_sign(&state, network, &PublicKey::from(&recipient), 1, 2, &server).unwrap();
        assert!(matches!(
            verify_and_open::<DesiredState>(
                &command,
                &NetworkId::new("other").unwrap(),
                &recipient,
                &server.verifying_key(),
                1
            ),
            Err(Error::WrongNetwork)
        ));
        assert!(require_newer_revision(2, 1).is_ok());
        assert!(matches!(
            require_newer_revision(1, 1),
            Err(Error::StaleRevision)
        ));
    }
}
