use super::*;

#[test]
fn test_detector_creation() {
    let detector = PublicIpDetector::new();
    assert_eq!(detector.ipv4_servers.len(), 0);
    assert_eq!(detector.ipv6_servers.len(), 0);
}

#[test]
fn test_detector_with_timeout() {
    let detector = PublicIpDetector::new().with_timeout(Duration::from_secs(10));
    assert_eq!(detector.timeout, Duration::from_secs(10));
}

#[test]
fn parses_xor_mapped_ipv4_socket_address() {
    let detector = PublicIpDetector::new();
    let mut response = vec![0x01, 0x01, 0, 12, 0x21, 0x12, 0xa4, 0x42];
    response.extend_from_slice(&[0; 12]);
    response.extend_from_slice(&[0, 0x20, 0, 8, 0, 1, 0x21 ^ 0x12, 0x12 ^ 0x34]);
    response.extend_from_slice(&[0x21 ^ 203, 0x12 ^ 0, 0xa4 ^ 113, 0x42 ^ 9]);
    assert_eq!(
        detector.parse_mapped_socket_addr(&response).unwrap(),
        "203.0.113.9:4660".parse().unwrap()
    );
}

fn stun_response(attribute: u16, data: &[u8]) -> Vec<u8> {
    let mut response = vec![0x01, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42];
    response.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    response.extend_from_slice(&attribute.to_be_bytes());
    response.extend_from_slice(&(data.len() as u16).to_be_bytes());
    response.extend_from_slice(data);
    response.resize(response.len().next_multiple_of(4), 0);
    let length = (response.len() - 20) as u16;
    response[2..4].copy_from_slice(&length.to_be_bytes());
    response
}

#[test]
fn decodes_ipv6_using_cookie_and_transaction_id() {
    let detector = PublicIpDetector::new();
    let response = stun_response(
        0x0020,
        &[
            0, 2, 0x33, 0x26, 0x01, 0x13, 0xa9, 0xfa, 0x13, 0x36, 0x55, 0x7c, 0x95, 0xad, 0xca,
            0xe7, 0x19, 0x2a, 0x3b, 0x4c,
        ],
    );
    let expected: std::net::SocketAddr = "[2001:db8:1234:5678:90ab:cdef:1020:3040]:4660"
        .parse()
        .unwrap();
    assert_eq!(
        detector.parse_mapped_socket_addr(&response).unwrap(),
        expected
    );
    assert_eq!(
        detector.parse_stun_response(&response, false).unwrap(),
        expected.ip()
    );
    assert!(detector.parse_stun_response(&response, true).is_err());
}

#[test]
fn rejects_malformed_stun_headers_and_attribute_bounds() {
    let detector = PublicIpDetector::new();
    let response = stun_response(0x0020, &[0, 1, 0x33, 0x26, 0xea, 0x12, 0xd5, 0x4b]);
    for length in 0..response.len() {
        assert!(
            detector
                .parse_mapped_socket_addr(&response[..length])
                .is_err()
        );
        assert!(
            detector
                .parse_stun_response(&response[..length], true)
                .is_err()
        );
    }
    for (offset, value) in [(0, 0), (4, 0), (3, 0), (3, 11), (3, 16), (23, 20)] {
        let mut malformed = response.clone();
        malformed[offset] = value;
        assert!(
            detector.parse_mapped_socket_addr(&malformed).is_err(),
            "{malformed:?}"
        );
        assert!(
            detector.parse_stun_response(&malformed, true).is_err(),
            "{malformed:?}"
        );
    }
    let mut malformed = stun_response(0x8022, b"x");
    malformed[23] = 20;
    assert!(detector.parse_mapped_socket_addr(&malformed).is_err());
}

#[test]
fn rejects_invalid_mapped_address_lengths_and_families() {
    let detector = PublicIpDetector::new();
    for attribute in [0x0020, 0x0001] {
        for family in [1, 2, 3] {
            for length in 0..=24 {
                if (family == 1 && length == 8) || (family == 2 && length == 20) {
                    continue;
                }
                let mut data = vec![0; length];
                if length >= 2 {
                    data[1] = family;
                }
                let response = stun_response(attribute, &data);
                assert!(detector.parse_mapped_socket_addr(&response).is_err());
                assert!(detector.parse_stun_response(&response, true).is_err());
                assert!(detector.parse_stun_response(&response, false).is_err());
            }
        }
    }
}

#[test]
fn supports_mapped_fallback_and_padded_unknown_attributes() {
    let detector = PublicIpDetector::new();
    for (data, expected) in [
        (vec![0, 1, 0x12, 0x34, 203, 0, 113, 9], "203.0.113.9:4660"),
        (
            vec![
                0, 2, 0x12, 0x34, 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
            ],
            "[2001:db8::9]:4660",
        ),
    ] {
        let expected: std::net::SocketAddr = expected.parse().unwrap();
        let mut response = stun_response(0x8022, b"x");
        response.extend_from_slice(&stun_response(0x0001, &data)[20..]);
        let length = (response.len() - 20) as u16;
        response[2..4].copy_from_slice(&length.to_be_bytes());
        assert_eq!(
            detector.parse_mapped_socket_addr(&response).unwrap(),
            expected
        );
        assert_eq!(
            detector
                .parse_stun_response(&response, expected.is_ipv4())
                .unwrap(),
            expected.ip()
        );
    }
}
