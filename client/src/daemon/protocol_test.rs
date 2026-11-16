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
    let req = DaemonRequest::RegisterBundle { bundle: "sensitive-bundle".into() };
    let json = serde_json::to_string(&req).unwrap();
    let deserialized: DaemonRequest = serde_json::from_str(&json).unwrap();
    match deserialized {
        DaemonRequest::RegisterBundle { bundle } => assert_eq!(bundle, "sensitive-bundle"),
        _ => panic!("Wrong request type"),
    }
    assert!(serde_json::from_str::<DaemonRequest>(r#"{"SetServer":{"address":"a","invite_code":"i"}}"#).is_err());
    assert!(serde_json::from_str::<DaemonRequest>(r#"{"Register":{"address":"a","invite_code":"i"}}"#).is_err());
}

#[test]
fn status_age_round_trips_and_old_daemons_are_unknown() {
    let response = DaemonResponse::Status {
        running: true,
        server_configured: true,
        node_key_present: true,
        controller_snapshot_age_seconds: Some(42),
        message: None,
    };
    let encoded = serde_json::to_string(&response).unwrap();
    assert!(matches!(serde_json::from_str::<DaemonResponse>(&encoded).unwrap(), DaemonResponse::Status { controller_snapshot_age_seconds: Some(42), .. }));
    let old = r#"{"Status":{"running":true,"server_configured":true,"node_key_present":true,"message":null}}"#;
    assert!(matches!(serde_json::from_str::<DaemonResponse>(old).unwrap(), DaemonResponse::Status { controller_snapshot_age_seconds: None, .. }));
}
