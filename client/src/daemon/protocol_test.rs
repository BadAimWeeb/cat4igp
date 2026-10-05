use super::*;

#[test]
fn test_generate_secret() {
    let secret = SharedSecret::generate();
    assert_eq!(secret.len(), 32);
}

#[test]
fn test_verify_secret() {
    let secret = SharedSecret::generate();
    let shared = SharedSecret {
        secret: secret.clone(),
    };
    assert!(shared.verify(&secret));
    assert!(!shared.verify("wrong"));
}

#[test]
fn test_daemon_request_serialization() {
    let req = DaemonRequest::SetServer {
        address: "https://example.com".to_string(),
        invite_code: "abc123".to_string(),
    };
    let json = serde_json::to_string(&req).unwrap();
    let deserialized: DaemonRequest = serde_json::from_str(&json).unwrap();
    match deserialized {
        DaemonRequest::SetServer {
            address,
            invite_code,
        } => {
            assert_eq!(address, "https://example.com");
            assert_eq!(invite_code, "abc123");
        }
        _ => panic!("Wrong request type"),
    }
}
