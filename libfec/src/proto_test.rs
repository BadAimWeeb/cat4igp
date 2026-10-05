use super::*;

#[test]
fn roundtrip() {
    let payload = b"hello world";
    let encoded = encode_packet(0b0000_0011, payload).expect("encode should succeed");
    let decoded = decode_packet(&encoded).expect("decode should succeed");
    assert_eq!(decoded.header.flags, 0b0000_0011);
    assert_eq!(decoded.payload, payload);
}

#[test]
fn control_flag_constant_is_single_bit() {
    assert_eq!(FLAG_CONTROL, 0b0000_0001);
}
