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
