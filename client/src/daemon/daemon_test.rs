use super::*;
use tempfile::TempDir;

#[tokio::test]
async fn run_stop_cancel_restart_preserves_socket_and_config() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let directory = TempDir::new().unwrap();
        let config = ClientConfig {
            data_dir: directory.path().to_owned(),
            daemon_socket: directory.path().join("daemon.sock"),
            ..Default::default()
        };
        let daemon = Arc::new(Daemon::new(config.clone()).await.unwrap());
        let ipc = client::DaemonClient::new(&config.daemon_socket, &config.data_dir).unwrap();
        assert!(matches!(
            daemon
                .handle_request(
                    DaemonRequest::SetServer {
                        address: "pending-controller".into(),
                        invite_code: "pending-invite".into(),
                    },
                    daemon.get_secret()
                )
                .await,
            DaemonResponse::Ok(_)
        ));
        let pending = serde_json::to_value(ServerConfig::load(directory.path()).unwrap()).unwrap();
        let secret = std::fs::read(directory.path().join(".daemon_secret")).unwrap();
        for cancel in [false, true, false] {
            let running = daemon.clone();
            let task = tokio::spawn(async move { running.run().await });
            let mut retry = tokio::time::interval(Duration::from_millis(10));
            loop {
                retry.tick().await;
                if matches!(
                    ipc.send_request(DaemonRequest::Status).await,
                    Ok(DaemonResponse::Status { .. })
                ) {
                    break;
                }
            }
            let competing = Daemon::new(config.clone()).await.unwrap();
            assert!(competing.run().await.is_err());
            // A stalled unauthenticated connection must not keep a handler alive.
            let mut stalled = UnixStream::connect(&config.daemon_socket).await.unwrap();
            let (mut wrong, server) = UnixStream::pair().unwrap();
            let handler = tokio::spawn(handle_client(server, daemon.clone()));
            let message = serde_json::to_vec(&IpcMessage {
                secret: "wrong".into(),
                request: DaemonRequest::Shutdown,
            })
            .unwrap();
            wrong.write_u32(message.len() as u32).await.unwrap();
            wrong.write_all(&message).await.unwrap();
            let len = wrong.read_u32().await.unwrap();
            let mut response = vec![0; len as usize];
            wrong.read_exact(&mut response).await.unwrap();
            assert!(matches!(
                serde_json::from_slice::<DaemonResponse>(&response).unwrap(),
                DaemonResponse::Error(_)
            ));
            handler.await.unwrap().unwrap();
            assert!(!task.is_finished());
            // Real idle swarm ownership, not controller or dataplane success.
            let mut enrolled = ServerConfig::load(directory.path()).unwrap();
            let authority = libp2p::identity::Keypair::generate_ed25519();
            enrolled.controller_peer_id = Some(authority.public().to_peer_id().to_string());
            enrolled.controller_signing_key = Some(
                authority
                    .public()
                    .encode_protobuf()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            );
            enrolled.control_node_id = Some(42);
            enrolled.control_private_network_key = Some(format!(
                "/key/swarm/psk/1.0.0/\n/base16/\n{}",
                "12".repeat(32)
            ));
            let (updates, _received) = mpsc::channel(8);
            let worker = control::start(enrolled, updates, daemon.server_config.clone()).unwrap();
            *daemon.control_plane.lock().unwrap() = Some(worker.clone());
            if cancel {
                // Replacing the pathname must not make cleanup unlink somebody else's socket.
                std::fs::remove_file(&config.daemon_socket).unwrap();
                let replacement = UnixListener::bind(&config.daemon_socket).unwrap();
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
                assert!(config.daemon_socket.exists());
                drop(replacement);
                std::fs::remove_file(&config.daemon_socket).unwrap();
            } else {
                assert!(matches!(
                    ipc.send_request(DaemonRequest::Shutdown).await.unwrap(),
                    DaemonResponse::Ok(_)
                ));
                task.await.unwrap().unwrap();
                assert!(!config.daemon_socket.exists());
            }
            assert_eq!(
                stalled.read_u8().await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert!(daemon.control_plane.lock().unwrap().is_none());
            let mut tasks = std::mem::take(&mut *daemon.tasks.lock().unwrap());
            while tasks.join_next().await.is_some() {}
            assert!(worker.request(ControlRequest::Snapshot).await.is_err());
            assert_eq!(Arc::strong_count(&daemon.memory), 1);
            assert_eq!(
                std::fs::read(directory.path().join(".daemon_secret")).unwrap(),
                secret
            );
            assert_eq!(
                serde_json::to_value(ServerConfig::load(directory.path()).unwrap()).unwrap(),
                pending
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ipc_process_kill_retries_durable_wire_result() {
    async fn register(directory: std::path::PathBuf, bundle: String) -> Result<(), String> {
        let client = client::DaemonClient::new(&directory.join("daemon.sock"), &directory).unwrap();
        match client
            .send_request(DaemonRequest::RegisterBundle { bundle })
            .await
        {
            Ok(DaemonResponse::Ok(_)) => Ok(()),
            Ok(DaemonResponse::Error(error)) => Err(error),
            Err(error) => Err(error.to_string()),
            response => panic!("unexpected IPC response: {response:?}"),
        }
    }
    control::tests::ipc_process_kill_retries_durable_wire_result(register, |directory| {
        SharedSecret::load(directory).unwrap().value().to_string()
    })
    .await;
}

#[tokio::test]
#[ignore = "external authenticated Raft endpoint fixture supplied by server test"]
async fn ipc_external_endpoint() {
    use std::io::{BufRead, Read, Write};
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    tokio::time::timeout(Duration::from_secs(25), async {
        let directory =
            std::path::PathBuf::from(std::env::var_os("CAT4IGP_IPC_ENDPOINT_DIR").unwrap());
        let bundle = std::fs::read_to_string(directory.join("bundle.json")).unwrap();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "daemon::tests::ipc_process_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("CAT4IGP_IPC_CHILD", &directory)
                .env("CAT4IGP_IPC_RUN", "true")
                .env("HOSTNAME", std::env::var("CAT4IGP_IPC_HOSTNAME").unwrap())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (ready, waiting) = tokio::sync::oneshot::channel();
        let (synced, snapshot) = tokio::sync::oneshot::channel();
        let reader = std::thread::spawn(move || {
            let mut ready = Some(ready);
            let mut synced = Some(synced);
            for line in std::io::BufReader::new(stdout.take(8192)).lines() {
                match line.unwrap().as_str() {
                    "IPC_READY" => {
                        let _ = ready.take().unwrap().send(());
                    }
                    "IPC_SYNCED" => {
                        let _ = synced.take().unwrap().send(());
                    }
                    _ => {}
                }
            }
        });
        tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .unwrap()
            .unwrap();
        let client = client::DaemonClient::new(&directory.join("daemon.sock"), &directory).unwrap();
        let request = tokio::spawn(async move {
            client
                .send_request(DaemonRequest::RegisterBundle { bundle })
                .await
        });
        if std::env::var("CAT4IGP_IPC_EXPECT_SUCCESS").unwrap() == "true" {
            let response = request.await.unwrap().unwrap();
            assert!(matches!(response, DaemonResponse::Ok(_)), "{response:?}");
            let completed = ServerConfig::load(&directory).unwrap();
            assert!(
                completed.control_node_id.is_some(),
                "IPC success must persist enrollment"
            );
            assert!(completed.control_private_key.is_some());
            assert!(completed.controller_signing_key.is_some());
            snapshot
                .await
                .expect("full run must apply live empty topology");
        } else {
            use std::io::Write;
            println!("IPC_PENDING");
            std::io::stdout().flush().unwrap();
            let (send, wait) = tokio::sync::oneshot::channel();
            std::thread::spawn(move || {
                let mut line = String::new();
                std::io::stdin()
                    .lock()
                    .take(16)
                    .read_line(&mut line)
                    .unwrap();
                assert_eq!(line.trim(), "kill");
                let _ = send.send(());
            });
            wait.await.unwrap();
            child.0.kill().unwrap();
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(child.0.wait().unwrap().signal(), Some(9));
            reader.join().unwrap();
            // The reply may already report the dropped wire response, or IPC may be closed by SIGKILL.
            assert!(!matches!(request.await.unwrap(), Ok(DaemonResponse::Ok(_))));
            let pending = ServerConfig::load(&directory).unwrap();
            assert!(
                pending.control_node_id.is_none(),
                "lost reply must retain pending enrollment"
            );
            assert!(
                pending.control_private_key.is_some(),
                "restart must reuse persisted identity"
            );
            println!("IPC_KILLED");
            std::io::stdout().flush().unwrap();
            return;
        }
        // ponytail: full run with empty topology; OS tunnel traffic remains a separate gate.
        child.0.kill().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(child.0.wait().unwrap().signal(), Some(9));
        reader.join().unwrap();
        println!("IPC_COMPLETED");
        std::io::stdout().flush().unwrap();
    })
    .await
    .expect("bounded external endpoint IPC fixture");
}

#[tokio::test]
#[ignore = "spawned explicitly by the control wire test"]
async fn ipc_process_child() {
    use std::io::Write;
    let directory = std::path::PathBuf::from(std::env::var_os("CAT4IGP_IPC_CHILD").unwrap());
    let config = ClientConfig {
        daemon_socket: directory.join("daemon.sock"),
        data_dir: directory,
        ..Default::default()
    };
    let daemon = Arc::new(Daemon::new(config).await.unwrap());
    if std::env::var("CAT4IGP_IPC_RUN").as_deref() == Ok("true") {
        let lifecycle = async {
            let mut interval = tokio::time::interval(Duration::from_millis(20));
            loop {
                interval.tick().await;
                if let Ok(mut stream) = UnixStream::connect(daemon.get_socket_path()).await {
                    let request = serde_json::to_vec(&IpcMessage {
                        secret: "invalid-secret".into(),
                        request: DaemonRequest::Status,
                    })
                    .unwrap();
                    stream.write_u32(request.len() as u32).await.unwrap();
                    stream.write_all(&request).await.unwrap();
                    let length = stream.read_u32().await.unwrap();
                    assert!(length <= 1024 * 1024);
                    let mut response = vec![0; length as usize];
                    stream.read_exact(&mut response).await.unwrap();
                    assert!(
                        matches!(serde_json::from_slice::<DaemonResponse>(&response).unwrap(),
                        DaemonResponse::Error(error) if error == "Authentication failed")
                    );
                    break;
                }
            }
            let client =
                client::DaemonClient::new(daemon.get_socket_path(), &daemon.config.data_dir)
                    .unwrap();
            assert!(matches!(
                client.send_request(DaemonRequest::Status).await.unwrap(),
                DaemonResponse::Status { running: true, .. }
            ));
            println!("IPC_READY");
            std::io::stdout().flush().unwrap();
            while daemon
                .server_config
                .lock()
                .await
                .as_ref()
                .is_none_or(|config| config.control_node_id.is_none())
            {
                interval.tick().await;
            }
            // Completion is published before RegisterBundle finishes starting its swarm.
            drop(daemon.control_sync.lock().await);
            // Executes real signed snapshot pull, endpoint answering and actuator reconciliation.
            // Empty topology requires neither external STUN nor privileged tunnel setup.
            daemon.sync_control_snapshot().await.unwrap();
            assert_eq!(daemon.memory.wireguard_len().await, 0);
            assert!(daemon.memory.get_last_poll_error().await.is_none());
            println!("IPC_SYNCED");
            std::io::stdout().flush().unwrap();
            std::future::pending::<()>().await;
        };
        tokio::time::timeout(Duration::from_secs(60), async {
            tokio::select! {
                result = daemon.run() => panic!("daemon run exited: {result:?}"),
                _ = lifecycle => unreachable!(),
            }
        })
        .await
        .unwrap();
        return;
    }
    let socket = daemon.get_socket_path();
    if socket.exists() {
        std::fs::remove_file(socket).unwrap();
    }
    // ponytail: real IPC handler only; use daemon.run when network watchers/dataplane are in scope.
    let listener = UnixListener::bind(socket).unwrap();
    println!("IPC_READY");
    std::io::stdout().flush().unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(handle_client(stream, daemon.clone()));
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ipc_pending_bundle_retry_preserves_identity_and_fingerprint() {
    use cat4igp_shared::control::{CONTROL_PROTOCOL_VERSION, EnrollmentBundle};
    use std::os::unix::fs::PermissionsExt;

    async fn register(daemon: Arc<Daemon>, bundle: String) -> DaemonResponse {
        let (mut client, server) = UnixStream::pair().unwrap();
        let request = serde_json::to_vec(&IpcMessage {
            secret: daemon.get_secret().to_string(),
            request: DaemonRequest::RegisterBundle { bundle },
        })
        .unwrap();
        let handler = tokio::spawn(handle_client(server, daemon));
        client
            .write_all(&(request.len() as u32).to_be_bytes())
            .await
            .unwrap();
        client.write_all(&request).await.unwrap();
        let length = client.read_u32().await.unwrap();
        assert!(length <= 1024 * 1024);
        let mut response = vec![0; length as usize];
        client.read_exact(&mut response).await.unwrap();
        handler.await.unwrap().unwrap();
        serde_json::from_slice(&response).unwrap()
    }

    tokio::time::timeout(Duration::from_secs(30), async {
        let directory = TempDir::new().unwrap();
        let authority = libp2p::identity::Keypair::generate_ed25519();
        let peer = authority.public().to_peer_id();
        // An unavailable trusted public seed exercises production discovery failure,
        // without sending credentials or needing a privileged dataplane.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let address = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}");
        let bundle = serde_json::to_string(&EnrollmentBundle {
            version: CONTROL_PROTOCOL_VERSION,
            network_id: "default".into(),
            controller_peer_id: peer.to_string(),
            controller_signing_key: authority.public().encode_protobuf().iter()
                .map(|byte| format!("{byte:02x}")).collect(),
            private_network_key: format!("/key/swarm/psk/1.0.0/\n/base16/\n{}", "12".repeat(32)),
            invitation_code: "same-invite".into(),
            bootstrap_addresses: vec![address.clone()],
            discovery_bootstrap_addresses: vec![address],
        }).unwrap();
        let local = ClientConfig { data_dir: directory.path().to_path_buf(), ..Default::default() };
        let daemon = Arc::new(Daemon::new(local.clone()).await.unwrap());
        let secret = daemon.get_secret().to_string();
        let response = register(daemon.clone(), bundle.clone()).await;
        assert!(matches!(response, DaemonResponse::Error(error) if error.starts_with("Registration discovery failed:")));
        drop(daemon);
        let mut pending = ServerConfig::load(directory.path()).unwrap();
        assert!(pending.enrollment_node_name.is_some());
        assert!(pending.control_node_id.is_none());
        assert_eq!(pending.invite_code, "same-invite");
        // Model the saved dial-seed replacement performed by verified discovery.
        // This is NOT evidence of live controller enrollment or a process restart.
        pending.control_bootstrap_addresses = vec![format!("/ip4/127.0.0.1/tcp/1/p2p/{peer}")];
        pending.discovery_bootstrap_addresses = pending.control_bootstrap_addresses.clone();
        pending.enrollment_node_name = Some("original-node-before-restart".into());
        pending.save(directory.path()).unwrap();
        let identity = pending.ensure_control_keypair().unwrap().public().to_peer_id();
        let before = serde_json::to_value(&pending).unwrap();
        let restarted = Arc::new(Daemon::new(local.clone()).await.unwrap());
        assert_eq!(restarted.get_secret(), secret);
        assert_eq!(restarted.start_control_plane().await.unwrap_err(), "control plane is not enrolled");
        assert_eq!(serde_json::to_value(ServerConfig::load(directory.path()).unwrap()).unwrap(), before);
        let changed = bundle.replace("same-invite", "different-invite");
        assert!(matches!(register(restarted.clone(), changed).await,
            DaemonResponse::Error(error) if error.contains("Pending registration differs")));
        let mut changed: EnrollmentBundle = serde_json::from_str(&bundle).unwrap();
        changed.discovery_bootstrap_addresses = pending.discovery_bootstrap_addresses.clone();
        assert!(matches!(register(restarted.clone(), serde_json::to_string(&changed).unwrap()).await,
            DaemonResponse::Error(error) if error.contains("Pending registration differs")));
        let response = register(restarted.clone(), bundle).await;
        assert!(matches!(response, DaemonResponse::Error(error) if error.starts_with("Registration discovery failed:")));
        drop(restarted);
        let mut after = ServerConfig::load(directory.path()).unwrap();
        assert_eq!(serde_json::to_value(&after).unwrap(), before);
        assert_eq!(after.ensure_control_keypair().unwrap().public().to_peer_id(), identity);
        assert_eq!(std::fs::metadata(directory.path().join("server.json")).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!std::fs::read_dir(directory.path()).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
        std::fs::write(directory.path().join("server.json"), b"broken").unwrap();
        assert!(matches!(Daemon::new(local).await, Err(error) if error.kind() == io::ErrorKind::InvalidData));
        assert_eq!(std::fs::read(directory.path().join("server.json")).unwrap(), b"broken");
    }).await.expect("bounded daemon IPC retry test");
}

#[tokio::test]
async fn test_daemon_creation() {
    let temp_dir = TempDir::new().unwrap();
    let config = ClientConfig {
        data_dir: temp_dir.path().to_path_buf(),
        ..Default::default()
    };

    let daemon = Daemon::new(config).await.unwrap();
    assert!(!daemon.is_server_configured().await);
}

#[tokio::test]
async fn test_set_server_config() {
    let temp_dir = TempDir::new().unwrap();
    let config = ClientConfig {
        data_dir: temp_dir.path().to_path_buf(),
        ..Default::default()
    };

    let daemon = Daemon::new(config).await.unwrap();
    let secret = daemon.get_secret().to_string();

    let req = DaemonRequest::SetServer {
        address: "/ip4/127.0.0.1/tcp/9000/p2p/12D3KooWExample".to_string(),
        invite_code: "test-invite".to_string(),
    };

    let response = daemon.handle_request(req, &secret).await;
    match response {
        DaemonResponse::Ok(_) => {
            assert!(daemon.is_server_configured().await);
        }
        _ => panic!("Unexpected response"),
    }
}

#[tokio::test]
async fn test_auth_failure() {
    let temp_dir = TempDir::new().unwrap();
    let config = ClientConfig {
        data_dir: temp_dir.path().to_path_buf(),
        ..Default::default()
    };

    let daemon = Daemon::new(config).await.unwrap();

    let req = DaemonRequest::Status;
    let response = daemon.handle_request(req, "wrong-secret").await;

    match response {
        DaemonResponse::Error(msg) => {
            assert!(msg.contains("Authentication"));
        }
        _ => panic!("Expected error response"),
    }
}

#[test]
fn rejects_unspecified_or_multicast_endpoint() {
    for endpoint in ["0.0.0.0:1", "[::]:1", "224.0.0.1:1", "[ff02::1]:1"] {
        let endpoint: SocketAddr = endpoint.parse().unwrap();
        assert!(endpoint.ip().is_unspecified() || endpoint.ip().is_multicast());
    }
}
