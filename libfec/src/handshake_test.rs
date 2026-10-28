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

#[test]
fn static_tunnel_key_and_resume_key_agree_on_both_ends() {
    let (a_private, a_public) = generate_local_keypair();
    let (b_private, b_public) = generate_local_keypair();
    assert_eq!(
        tunnel_psk(a_private, b_public, 9),
        tunnel_psk(b_private, a_public, 9)
    );
    assert_ne!(
        tunnel_psk(a_private, b_public, 9),
        tunnel_psk(b_private, a_public, 10)
    );
    assert_eq!(
        derive_shared_key(a_private, b_public, 1, 2),
        derive_shared_key(b_private, a_public, 2, 1)
    );
    assert!(tunnel_psk(a_private, [0; 32], 9).is_none());
}
