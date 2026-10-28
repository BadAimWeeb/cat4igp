use crate::keys::{
    load_or_create_command_key, load_or_create_libp2p, load_or_create_wireguard_key,
    wireguard_public_key,
};
use cat4igp_protocol::{EnrollmentRequest, Error};
use std::{io, path::Path};
use x25519_dalek::PublicKey;

/// Builds a request-response enrollment payload from the node's persistent,
/// separate transport, command-encryption, and WireGuard identities.
pub fn build_request(
    token: String,
    libp2p_key_path: impl AsRef<Path>,
    command_key_path: impl AsRef<Path>,
    wireguard_key_path: impl AsRef<Path>,
) -> io::Result<EnrollmentRequest> {
    let libp2p = load_or_create_libp2p(libp2p_key_path)?;
    let command = load_or_create_command_key(command_key_path)?;
    let wireguard = load_or_create_wireguard_key(wireguard_key_path)?;
    Ok(EnrollmentRequest {
        token,
        libp2p_peer_id: libp2p.public().to_peer_id().to_string(),
        command_public_key: *PublicKey::from(&command).as_bytes(),
        wireguard_public_key: wireguard_public_key(&wireguard),
    })
}

/// Serializes enrollment for the libp2p request-response protocol.
pub fn encode_request(request: &EnrollmentRequest) -> Result<Vec<u8>, Error> {
    let payload = serde_json::to_vec(request)?;
    if payload.len() > cat4igp_protocol::MAX_ENROLLMENT_PAYLOAD_BYTES {
        return Err(Error::EnrollmentTooLarge);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::{build_request, encode_request};

    #[test]
    fn request_uses_persistent_separate_identities() {
        let directory = std::env::temp_dir().join(format!("cat4igp-enroll-{}", std::process::id()));
        let first = build_request(
            "token".into(),
            directory.join("p2p"),
            directory.join("command"),
            directory.join("wg"),
        )
        .unwrap();
        let second = build_request(
            "token".into(),
            directory.join("p2p"),
            directory.join("command"),
            directory.join("wg"),
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.wireguard_public_key.len(), 44);
        assert_eq!(
            serde_json::from_slice::<cat4igp_protocol::EnrollmentRequest>(
                &encode_request(&first).unwrap()
            )
            .unwrap(),
            first
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
