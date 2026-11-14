use super::*;
use tempfile::TempDir;

#[tokio::test]
async fn ipc_modify_config_updates_and_persists_hostnames() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    async fn request(daemon: Arc<Daemon>, request: DaemonRequest, secret: &str) -> DaemonResponse {
        let (mut client, server) = UnixStream::pair().unwrap();
        let handler = tokio::spawn(handle_client(server, daemon));
        let message = serde_json::to_vec(&IpcMessage {
            secret: secret.into(),
            request,
        })
        .unwrap();
        client.write_u32(message.len() as u32).await.unwrap();
        client.write_all(&message).await.unwrap();
        let length = client.read_u32().await.unwrap();
        let mut response = vec![0; length as usize];
        client.read_exact(&mut response).await.unwrap();
        handler.await.unwrap().unwrap();
        serde_json::from_slice(&response).unwrap()
    }
    fn modify(v4: Option<&str>, v6: Option<&str>) -> DaemonRequest {
        DaemonRequest::ModifyConfig {
            public_hostname_ipv4: v4.map(str::to_owned),
            public_hostname_ipv6: v6.map(str::to_owned),
        }
    }
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("client.toml");
    let config = ClientConfig {
        data_dir: directory.path().to_owned(),
        daemon_socket: directory.path().join("daemon.sock"),
        public_hostname_ipv4: Some("old.example".into()),
        ..Default::default()
    };
    config.save_to_file(&path).unwrap();
    let original = format!(
        "# keep this comment\n{}\n# keep this too\n",
        std::fs::read_to_string(&path).unwrap()
    );
    std::fs::write(&path, &original).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let daemon = Arc::new(
        Daemon::new_with_config_path(config, Some(path.clone()))
            .await
            .unwrap(),
    );
    let secret = daemon.get_secret().to_owned();
    assert!(matches!(
        request(daemon.clone(), modify(Some("new.example"), None), "wrong").await,
        DaemonResponse::Error(_)
    ));
    for bad in [
        modify(None, None),
        modify(Some("not a host"), None),
        modify(Some("127.0.0.1"), Some("0.0.0.0")),
        modify(None, Some("[::1]")),
        modify(None, Some("ff02::1")),
    ] {
        assert!(matches!(
            request(daemon.clone(), bad, &secret).await,
            DaemonResponse::Error(_)
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }
    assert!(matches!(
        request(
            daemon.clone(),
            modify(Some("127.0.0.1"), Some("::1")),
            &secret
        )
        .await,
        DaemonResponse::Ok(_)
    ));
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(saved.contains("# keep this comment") && saved.contains("# keep this too"));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    let saved_config = ClientConfig::from_file(&path).unwrap();
    assert_eq!(
        saved_config.public_hostname_ipv4.as_deref(),
        Some("127.0.0.1")
    );
    assert_eq!(saved_config.public_hostname_ipv6.as_deref(), Some("::1"));
    assert!(
        matches!(request(daemon.clone(), DaemonRequest::GetConfig, &secret).await, DaemonResponse::Config(value) if value["public_hostname_ipv6"] == "::1")
    );
    let mut tunnel = cat4igp_shared::control::WireguardTunnelInfo {
        tunnel_id: 1,
        peer_node_id: 2,
        public_key: String::new(),
        preferred_port: 0,
        remote_endpoint: None,
        local_answered: WireguardAnswered::Unanswered,
        remote_response: WireguardAnswered::Unanswered,
        mtu: 1420,
        endpoint_ipv6: false,
        fec: false,
        faketcp: false,
        created_at: 0,
        updated_at: 0,
    };
    assert_eq!(
        daemon
            .local_endpoint(&tunnel)
            .await
            .unwrap()
            .ip()
            .to_string(),
        "127.0.0.1"
    );
    tunnel.endpoint_ipv6 = true;
    assert_eq!(
        daemon
            .local_endpoint(&tunnel)
            .await
            .unwrap()
            .ip()
            .to_string(),
        "::1"
    );
    assert!(matches!(
        request(daemon.clone(), modify(Some("next.example"), None), &secret).await,
        DaemonResponse::Ok(_)
    ));
    assert_eq!(
        ClientConfig::from_file(&path)
            .unwrap()
            .public_hostname_ipv6
            .as_deref(),
        Some("::1")
    );
    assert!(matches!(
        request(daemon.clone(), modify(None, Some("")), &secret).await,
        DaemonResponse::Ok(_)
    ));
    assert_eq!(
        ClientConfig::from_file(&path).unwrap().public_hostname_ipv6,
        None
    );
    assert!(matches!(
        request(daemon.clone(), DaemonRequest::GetConfig, &secret).await,
        DaemonResponse::Config(value) if value["public_hostname_ipv6"].is_null()
    ));
    assert!(matches!(
        request(daemon.clone(), modify(None, Some("::1")), &secret).await,
        DaemonResponse::Ok(_)
    ));
    let restarted =
        Daemon::new_with_config_path(ClientConfig::from_file(&path).unwrap(), Some(path.clone()))
            .await
            .unwrap();
    assert!(
        matches!(restarted.handle_request(DaemonRequest::GetConfig, restarted.get_secret()).await, DaemonResponse::Config(value) if value["public_hostname_ipv4"] == "next.example")
    );
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let name = c"user.cat4igp-test";
        let result =
            unsafe { libc::setxattr(path_c.as_ptr(), name.as_ptr(), b"x".as_ptr().cast(), 1, 0) };
        if result == 0 {
            let before = std::fs::read(&path).unwrap();
            assert!(matches!(
                request(daemon.clone(), modify(None, Some("v6.example")), &secret).await,
                DaemonResponse::Error(error) if error.contains("extended attributes")
            ));
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert_eq!(
                unsafe { libc::removexattr(path_c.as_ptr(), name.as_ptr()) },
                0
            );
        } else {
            let error = io::Error::last_os_error();
            assert_eq!(error.raw_os_error(), Some(libc::ENOTSUP));
        }
    }
    let edited = std::fs::read_to_string(&path)
        .unwrap()
        .replace("next.example", "external.example");
    std::fs::write(&path, &edited).unwrap();
    assert!(matches!(
        request(daemon.clone(), modify(None, Some("v6.example")), &secret).await,
        DaemonResponse::Error(error) if error.contains("changed on disk")
    ));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);
    std::fs::remove_file(&path).unwrap();
    symlink(directory.path().join("missing"), &path).unwrap();
    assert!(matches!(
        request(daemon.clone(), modify(Some("fail.example"), None), &secret).await,
        DaemonResponse::Error(_)
    ));
    assert!(
        matches!(request(daemon, DaemonRequest::GetConfig, &secret).await, DaemonResponse::Config(value) if value["public_hostname_ipv4"] == "next.example")
    );
    assert!(!directory.path().join("missing").exists());
}

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
        // An unavailable controller exercises failed enrollment without releasing credentials.
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
            bootstrap_addresses: vec![address],
        }).unwrap();
        let local = ClientConfig { data_dir: directory.path().to_path_buf(), ..Default::default() };
        let daemon = Arc::new(Daemon::new(local.clone()).await.unwrap());
        let secret = daemon.get_secret().to_string();
        let response = register(daemon.clone(), bundle.clone()).await;
        assert!(matches!(response, DaemonResponse::Error(_)));
        drop(daemon);
        let mut pending = ServerConfig::load(directory.path()).unwrap();
        assert!(pending.enrollment_node_name.is_some());
        assert!(pending.control_node_id.is_none());
        assert_eq!(pending.invite_code, "same-invite");
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
        changed.bootstrap_addresses = vec![format!("/ip4/127.0.0.1/tcp/1/p2p/{peer}")];
        assert!(matches!(register(restarted.clone(), serde_json::to_string(&changed).unwrap()).await,
            DaemonResponse::Error(error) if error.contains("Pending registration differs")));
        let response = register(restarted.clone(), bundle).await;
        assert!(matches!(response, DaemonResponse::Error(_)));
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
async fn set_server_preserves_pending_and_completed_enrollment() {
    let directory = TempDir::new().unwrap();
    let config = ClientConfig {
        data_dir: directory.path().to_owned(),
        ..Default::default()
    };
    let daemon = Daemon::new(config).await.unwrap();
    let request = || DaemonRequest::SetServer {
        address: "original-controller".into(),
        invite_code: "original-invite".into(),
    };
    assert!(matches!(
        daemon.handle_request(request(), daemon.get_secret()).await,
        DaemonResponse::Ok(_)
    ));
    let authority = libp2p::identity::Keypair::generate_ed25519();
    for stage in 0..3 {
        let mut saved = ServerConfig::load(directory.path()).unwrap();
        if stage >= 1 {
            saved.controller_peer_id = Some(authority.public().to_peer_id().to_string());
            saved.controller_signing_key = Some(
                authority
                    .public()
                    .encode_protobuf()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            );
            saved.enrollment_node_name = Some("original-node".into());
        }
        if stage == 2 {
            saved.control_node_id = Some(42);
            saved.topology_revision = 7;
            saved.invite_code.clear();
        }
        saved.save(directory.path()).unwrap();
        *daemon.server_config.lock().await = Some(saved);
        let before = std::fs::read(directory.path().join("server.json")).unwrap();
        let memory_before = serde_json::to_value(&*daemon.server_config.lock().await).unwrap();
        for attempt in [
            request(),
            DaemonRequest::SetServer {
                address: "replacement-controller".into(),
                invite_code: "replacement-invite".into(),
            },
        ] {
            assert!(matches!(
                daemon.handle_request(attempt, daemon.get_secret()).await,
                DaemonResponse::Error(error) if error.contains("refusing to overwrite enrollment")
            ));
            assert_eq!(
                std::fs::read(directory.path().join("server.json")).unwrap(),
                before
            );
            assert_eq!(
                serde_json::to_value(&*daemon.server_config.lock().await).unwrap(),
                memory_before
            );
        }
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
