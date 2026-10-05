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
