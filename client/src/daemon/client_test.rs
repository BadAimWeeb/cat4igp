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

#[test]
fn peer_policy_accepts_only_root_or_caller() {
    assert!(trusted_peer(0, 1000));
    assert!(trusted_peer(1000, 1000));
    assert!(!trusted_peer(1001, 1000));
    assert!(!trusted_peer(1000, 0));
}

#[tokio::test]
async fn peer_credentials_come_from_connected_socket() {
    let (client, server) = UnixStream::pair().unwrap();
    let uid = unsafe { libc::geteuid() };
    assert_eq!(client.peer_cred().unwrap().uid(), uid);
    assert!(trusted_peer(client.peer_cred().unwrap().uid(), uid));
    drop(server);
}
