use super::*;
use cat4igp_shared::control::*;


async fn wire_server(
    key: &libp2p::identity::Keypair,
    psk: PreSharedKey,
) -> (Swarm<ControlBehaviour>, libp2p::Multiaddr) {
    let transport = tcp::tokio::Transport::new(tcp::Config::default())
        .and_then(move |socket, _| PnetConfig::new(psk).handshake(socket))
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(key).unwrap())
        .multiplex(yamux::Config::default())
        .boxed();
    let peer = key.public().to_peer_id();
    let mut swarm = Swarm::new(
        transport,
        ControlBehaviour {
            request_response: json::Behaviour::new(
                [(
                    StreamProtocol::new(CONTROL_PROTOCOL),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            ),
            gossipsub: gossipsub(key).unwrap(),
        },
        peer,
        SwarmConfig::with_tokio_executor(),
    );
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    loop {
        if let libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } =
            swarm.select_next_some().await
        {
            return (swarm, address.with(libp2p::multiaddr::Protocol::P2p(peer)));
        }
    }
}

#[tokio::test]
async fn unreachable_bootstrap_does_not_block_reachable_address() {
    let authority = libp2p::identity::Keypair::generate_ed25519();
    let psk = format!("/key/swarm/psk/1.0.0/\n/base16/\n{}", "12".repeat(32));
    let (mut swarm, address) = wire_server(&authority, psk.parse().unwrap()).await;
    let server = tokio::spawn(async move {
        loop {
            if let libp2p::swarm::SwarmEvent::Behaviour(ControlBehaviourEvent::RequestResponse(
                request_response::Event::Message { message: request_response::Message::Request { channel, .. }, .. }
            )) = swarm.select_next_some().await {
                swarm.behaviour_mut().request_response.send_response(channel, ControlResponse::Rejected("received".into())).unwrap();
            }
        }
    });
    let mut config = crate::config::ServerConfig::new(String::new(), String::new());
    config.control_private_network_key = Some(psk);
    let unreachable = format!("/ip4/192.0.2.1/tcp/65000/p2p/{}", authority.public().to_peer_id());
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), request_to_bootstraps(
        &mut config, &[unreachable, address.to_string()], ControlRequest::Snapshot,
    )).await.unwrap().unwrap();
    assert!(matches!(response, ControlResponse::Rejected(message) if message == "received"));
    server.abort();
}

#[tokio::test]
async fn invalid_enrollment_fields_do_not_commit_identity() {
    for (node_id, topology_revision, network_id) in [(0, 3, "default"), (7, -1, "default"), (7, 3, "")] {
        let authority = libp2p::identity::Keypair::generate_ed25519();
        let signing: String = authority.public().encode_protobuf().iter().map(|byte| format!("{byte:02x}")).collect();
        let psk = format!("/key/swarm/psk/1.0.0/\n/base16/\n{}", "12".repeat(32));
        let (mut swarm, address) = wire_server(&authority, psk.parse().unwrap()).await;
        let response = EnrollmentResponse {
            node_id, topology_revision, network_id: network_id.into(),
            controller_signing_key: signing, controller_encryption_key: "23".repeat(32),
        };
        let server = tokio::spawn(async move {
            loop {
                if let libp2p::swarm::SwarmEvent::Behaviour(ControlBehaviourEvent::RequestResponse(
                    request_response::Event::Message { message: request_response::Message::Request { channel, .. }, .. }
                )) = swarm.select_next_some().await {
                    swarm.behaviour_mut().request_response.send_response(channel, ControlResponse::Enrolled(response.clone())).unwrap();
                }
            }
        });
        let mut config = crate::config::ServerConfig::new(String::new(), String::new());
        config.control_private_network_key = Some(psk);
        config.ensure_wireguard_keypair().unwrap();
        let result = enroll(&mut config, &[address.to_string()], "test".into()).await;
        assert_eq!(result.unwrap_err(), "invalid controller enrollment identity");
        assert!(config.control_node_id.is_none());
        assert!(config.controller_encryption_key.is_none());
        server.abort();
    }
}

pub(crate) async fn ipc_process_kill_retries_durable_wire_result<
    F: std::future::Future<Output = Result<(), String>> + Send,
>(
    ipc: impl Fn(std::path::PathBuf, String) -> F + Copy + Send + 'static,
    secret: impl Fn(&std::path::Path) -> String,
) {
    use std::os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        process::ExitStatusExt,
    };
    use std::{
        io::{BufRead, Read, Write},
        process::{Child, Command, Stdio},
        time::Duration,
    };
    struct Process(Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    async fn child(directory: &std::path::Path, hostname: &str) -> Process {
        let mut child = Process(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "daemon::tests::ipc_process_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("CAT4IGP_IPC_CHILD", directory)
                .env("HOSTNAME", hostname)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (ready, waiting) = tokio::sync::oneshot::channel();
        let reader = std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout.take(8192));
            let mut bytes = Vec::new();
            for _ in 0..8 {
                bytes.clear();
                if reader.read_until(b'\n', &mut bytes).unwrap() == 0 {
                    break;
                }
                assert!(bytes.len() <= 8192);
                if bytes == b"IPC_READY\n" {
                    let _ = ready.send(());
                    return;
                }
            }
        });
        tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .unwrap()
            .unwrap();
        reader.join().unwrap();
        child
    }
    tokio::time::timeout(Duration::from_secs(45), async {
        let directory = tempfile::TempDir::new().unwrap();
        let authority = libp2p::identity::Keypair::generate_ed25519();
        let pin: String = authority
            .public()
            .encode_protobuf()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let psk = format!("/key/swarm/psk/1.0.0/\n/base16/\n{}", "12".repeat(32));
        let (mut swarm, address) = wire_server(&authority, psk.parse().unwrap()).await;
        let bundle = serde_json::to_string(&EnrollmentBundle {
            version: CONTROL_PROTOCOL_VERSION,
            network_id: "default".into(),
            controller_peer_id: authority.public().to_peer_id().to_string(),
            controller_signing_key: pin.clone(),
            private_network_key: psk,
            invitation_code: "one-use-invite".into(),
            bootstrap_addresses: vec![address.to_string()],
        })
        .unwrap();
        let result = EnrollmentResponse {
            node_id: 42,
            topology_revision: 7,
            network_id: "default".into(),
            controller_signing_key: pin,
            controller_encryption_key: "23".repeat(32),
        };
        let receipt = directory.path().join("wire-result.json");
        let (committed, waiting) = tokio::sync::oneshot::channel();
        let (replayed, replay) = tokio::sync::oneshot::channel();
        // This fixture persists a committed-like wire result before dropping the reply.
        let responder = tokio::spawn(async move {
            let mut committed = Some(committed);
            let mut replayed = Some(replayed);
            loop {
                if let libp2p::swarm::SwarmEvent::Behaviour(
                    ControlBehaviourEvent::RequestResponse(request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Request {
                                request: ControlRequest::Enroll(request),
                                channel,
                                ..
                            },
                        ..
                    }),
                ) = swarm.select_next_some().await
                {
                    assert_eq!(request.request_id, peer.to_string());
                    let fingerprint = serde_json::to_value((&peer, &request)).unwrap();
                    if let Some(committed) = committed.take() {
                        let mut file = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(&receipt)
                            .unwrap();
                        file.write_all(&serde_json::to_vec(&(&fingerprint, &result)).unwrap())
                            .unwrap();
                        file.sync_all().unwrap();
                        std::fs::File::open(receipt.parent().unwrap())
                            .unwrap()
                            .sync_all()
                            .unwrap();
                        committed.send(()).unwrap();
                        // Unknown result: deliberately never return the first committed response.
                        drop(channel);
                    } else {
                        let (original, response): (serde_json::Value, EnrollmentResponse) =
                            serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
                        assert_eq!(fingerprint, original);
                        assert_eq!(
                            serde_json::to_value(&response).unwrap(),
                            serde_json::to_value(&result).unwrap()
                        );
                        swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, ControlResponse::Enrolled(response))
                            .unwrap();
                        if let Some(replayed) = replayed.take() {
                            replayed.send(()).unwrap();
                        }
                    }
                }
            }
        });
        let mut first = child(directory.path(), "original-name").await;
        let first_bundle = bundle.clone();
        let first_directory = directory.path().to_path_buf();
        let attempt = tokio::spawn(async move { ipc(first_directory, first_bundle).await });
        waiting.await.unwrap();
        let before = crate::config::ServerConfig::load(directory.path()).unwrap();
        assert!(before.control_node_id.is_none());
        assert_eq!(
            before.enrollment_node_name.as_deref(),
            Some("original-name")
        );
        assert_eq!(
            before.enrollment_bootstrap_addresses,
            vec![address.to_string()]
        );
        let original_secret = secret(directory.path());
        first.0.kill().unwrap();
        assert_eq!(first.0.wait().unwrap().signal(), Some(9));
        assert!(
            attempt.await.unwrap().is_err(),
            "lost result must not report success"
        );
        let _second = child(directory.path(), "different-name").await;
        assert_eq!(secret(directory.path()), original_secret);
        assert_eq!(
            serde_json::to_value(crate::config::ServerConfig::load(directory.path()).unwrap())
                .unwrap(),
            serde_json::to_value(&before).unwrap()
        );
        assert!(
            ipc(
                directory.path().to_path_buf(),
                bundle.replace("one-use-invite", "changed-invite")
            )
            .await
            .unwrap_err()
            .contains("Pending registration differs")
        );
        ipc(directory.path().to_path_buf(), bundle).await.unwrap();
        replay.await.unwrap();
        let after = crate::config::ServerConfig::load(directory.path()).unwrap();
        assert_eq!(after.control_node_id, Some(42));
        assert_eq!(after.topology_revision, 7);
        assert!(after.invite_code.is_empty());
        let mut expected = serde_json::to_value(&before).unwrap();
        expected["control_node_id"] = serde_json::json!(42);
        expected["topology_revision"] = serde_json::json!(7);
        expected["revision_journal"] = serde_json::json!(true);
        expected["controller_encryption_key"] = serde_json::json!("23".repeat(32));
        expected["invite_code"] = serde_json::json!("");
        assert_eq!(serde_json::to_value(after).unwrap(), expected);
        assert_eq!(
            std::fs::metadata(directory.path().join("server.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!std::fs::read_dir(directory.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
        responder.abort();
        assert!(responder.await.unwrap_err().is_cancelled());
    })
    .await
    .expect("bounded subprocess IPC retry");
}

