use super::*;

#[test]
fn test_ipc_message_serialization() {
    let message = IpcMessage {
        secret: "test-secret".to_string(),
        request: DaemonRequest::Status,
    };

    let serialized = serde_json::to_string(&message).unwrap();
    let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.secret, "test-secret");
}
