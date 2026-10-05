use super::*;
use cat4igp_shared::{control::*, discovery::*};

#[tokio::test]
async fn trusted_public_seed_repair_survives_bootstrap_loss() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let authority = libp2p::identity::Keypair::generate_ed25519();
        let server_key = libp2p::identity::Keypair::generate_ed25519();
        let peer = server_key.public().to_peer_id();
        let mut public = transport::swarm(&server_key).unwrap();
        public
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let seed = loop {
            if let libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } =
                public.select_next_some().await
            {
                break address.with(libp2p::multiaddr::Protocol::P2p(peer));
            }
        };
        // Hold real private/unverified listeners: neither may receive a public dial.
        let private = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let malicious = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        private.set_nonblocking(true).unwrap();
        malicious.set_nonblocking(true).unwrap();
        let private_address = format!(
            "/ip4/127.0.0.1/tcp/{}/p2p/{peer}",
            private.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();
        let unverified = format!(
            "/ip4/127.0.0.1/tcp/{}/p2p/{peer}",
            malicious.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_seed = format!(
            "/ip4/127.0.0.1/tcp/{}/p2p/{peer}",
            dead.local_addr().unwrap().port()
        );
        drop(dead);
        let mut config = crate::config::ServerConfig::new(String::new(), "invite".into());
        let requester = config
            .ensure_control_keypair()
            .unwrap()
            .public()
            .to_peer_id();
        config.controller_signing_key = Some(
            authority
                .public()
                .encode_protobuf()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        );
        config.controller_peer_id = Some(authority.public().to_peer_id().to_string());
        config.discovery_bootstrap_addresses = vec![dead_seed.clone()];
        let pins = (
            config.controller_peer_id.clone(),
            config.controller_signing_key.clone(),
        );
        let now = now_ms().unwrap();
        let endpoint = ControllerEndpoint {
            peer_id: peer,
            addresses: vec![private_address],
        };
        let roster = ControllerRoster {
            version: VERSION,
            cluster_id: "default".into(),
            revision: 7,
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            controllers: vec![endpoint.clone()],
            discovery_endpoints: vec![ControllerEndpoint {
                peer_id: peer,
                addresses: vec![seed.clone()],
            }],
        }
        .sign(&authority)
        .unwrap();
        let proof = ControllerAvailable {
            version: VERSION,
            cluster_id: "default".into(),
            role: Role::Client,
            recipient: requester,
            nonce: [1; 16],
            issued_at_ms: now,
            expires_at_ms: now + 1000,
            endpoint,
            roster: roster.clone(),
        }
        .sign(&authority)
        .unwrap();
        let mut forged = proof.clone();
        forged.body.roster.body.discovery_endpoints[0].addresses = vec![unverified];
        let unchanged = serde_json::to_value(&config).unwrap();
        assert!(config.accept_discovery_proof(forged, now).is_err());
        assert_eq!(serde_json::to_value(&config).unwrap(), unchanged);
        config.accept_discovery_proof(proof, now).unwrap();
        assert_eq!(
            config.discovery_bootstrap_addresses,
            vec![seed.to_string(), dead_seed]
        );
        let directory = tempfile::TempDir::new().unwrap();
        config.save(directory.path()).unwrap();
        let mut config = crate::config::ServerConfig::load(directory.path()).unwrap();
        let task = tokio::spawn(transport::serve_with(
            public,
            "default",
            move |query, source| {
                std::future::ready(transport::respond(
                    &authority,
                    &roster,
                    peer,
                    &query,
                    source,
                    now_ms().unwrap(),
                ))
            },
        ));
        let result = refresh_discovery(&mut config).await;
        task.abort();
        let _ = task.await;
        result.unwrap();
        assert_eq!(
            (
                config.controller_peer_id.clone(),
                config.controller_signing_key.clone()
            ),
            pins
        );
        assert_eq!(
            config
                .discovery_proof
                .as_ref()
                .unwrap()
                .body
                .roster
                .body
                .revision,
            7
        );
        assert_eq!(
            private.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            malicious.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    })
    .await
    .unwrap();
}

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
            discovery_bootstrap_addresses: vec![],
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
        // ponytail: fsynced committed-like wire fixture, NOT Raft; actual controller commit/failover has a separate server test.
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

#[tokio::test]
async fn authorized_replica_noise_wire_failover() {
    let authority = libp2p::identity::Keypair::generate_ed25519();
    let mut config = crate::config::ServerConfig::new(String::new(), "invite".into());
    config.controller_peer_id = Some(authority.public().to_peer_id().to_string());
    config.controller_signing_key = Some(
        authority
            .public()
            .encode_protobuf()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    );
    config.control_private_network_key = Some(format!(
        "/key/swarm/psk/1.0.0/\n/base16/\n{}",
        "12".repeat(32)
    ));
    config.ensure_wireguard_keypair().unwrap();
    let client = config
        .ensure_control_keypair()
        .unwrap()
        .public()
        .to_peer_id();
    let recipient = config.ensure_control_encryption_key().unwrap();
    let mut endpoints = Vec::new();
    let mut servers = Vec::new();
    let (requests, mut received) = mpsc::channel(8);
    for _ in 0..2 {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let peer = key.public().to_peer_id();
        let psk: PreSharedKey = config
            .control_private_network_key
            .as_ref()
            .unwrap()
            .parse()
            .unwrap();
        let (mut swarm, address) = wire_server(&key, psk).await;
        endpoints.push(ControllerEndpoint {
            peer_id: peer,
            addresses: vec![address],
        });
        let authority = authority.clone();
        let recipient = recipient.clone();
        let requests = requests.clone();
        servers.push(tokio::spawn(async move {
            loop {
                if let libp2p::swarm::SwarmEvent::Behaviour(
                    ControlBehaviourEvent::RequestResponse(request_response::Event::Message {
                        peer: principal,
                        message:
                            request_response::Message::Request {
                                request, channel, ..
                            },
                        ..
                    }),
                ) = swarm.select_next_some().await
                {
                    assert_eq!(principal, client);
                    let response = match request {
                        ControlRequest::Enroll(request) => {
                            assert_eq!(request.request_id, client.to_string());
                            requests.send(request.request_id).await.unwrap();
                            ControlResponse::Enrolled(EnrollmentResponse {
                                node_id: 1,
                                topology_revision: 1,
                                network_id: "default".into(),
                                controller_signing_key: authority
                                    .public()
                                    .encode_protobuf()
                                    .iter()
                                    .map(|b| format!("{b:02x}"))
                                    .collect(),
                                controller_encryption_key: "23".repeat(32),
                            })
                        }
                        ControlRequest::Snapshot => {
                            let now = now_ms().unwrap();
                            ControlResponse::SnapshotEnvelope(
                                seal_topology_snapshot(
                                    &authority,
                                    &recipient,
                                    MessageMeta {
                                        message_id: "ab".repeat(16),
                                        network_id: "default".into(),
                                        recipient_node_id: 1,
                                        issued_at_ms: now,
                                        expires_at_ms: now + 60_000,
                                        topology_revision: 1,
                                    },
                                    &TopologySnapshot {
                                        node_id: 1,
                                        revision: 1,
                                        tunnels: vec![],
                                    },
                                )
                                .unwrap(),
                            )
                        }
                        _ => ControlResponse::Rejected("unauthorized".into()),
                    };
                    swarm
                        .behaviour_mut()
                        .request_response
                        .send_response(channel, response)
                        .unwrap();
                }
            }
        }));
    }
    let now = now_ms().unwrap();
    let roster = ControllerRoster {
        version: VERSION,
        cluster_id: "default".into(),
        revision: 1,
        issued_at_ms: now,
        expires_at_ms: now + 240_000,
        controllers: endpoints.clone(),
        discovery_endpoints: vec![],
    }
    .sign(&authority)
    .unwrap();
    config
        .accept_discovery_proof(
            ControllerAvailable {
                version: VERSION,
                cluster_id: "default".into(),
                role: Role::Client,
                recipient: client,
                nonce: [1; 16],
                issued_at_ms: now,
                expires_at_ms: now + 1000,
                endpoint: endpoints[0].clone(),
                roster,
            }
            .sign(&authority)
            .unwrap(),
            now,
        )
        .unwrap();
    let directory = tempfile::TempDir::new().unwrap();
    config.save(directory.path()).unwrap();
    let first = vec![endpoints[0].addresses[0].to_string()];
    let mut attempt = config.clone();
    assert!(matches!(
        enroll(&mut attempt, &first, "node".into()).await.unwrap(),
        ControlResponse::Enrolled(_)
    ));
    // Lost completion persistence: restart from the same pending key/request, then choose another Noise PeerId.
    servers[0].abort();
    let mut config = crate::config::ServerConfig::load(directory.path()).unwrap();
    let second = vec![endpoints[1].addresses[0].to_string()];
    assert!(matches!(
        enroll(&mut config, &second, "node".into()).await.unwrap(),
        ControlResponse::Enrolled(_)
    ));
    assert_eq!(
        received.recv().await.unwrap(),
        received.recv().await.unwrap()
    );
    assert_eq!(
        config.controller_peer_id,
        Some(authority.public().to_peer_id().to_string())
    );
    let (updates, _) = mpsc::channel(1);
    let plane = start(
        config.clone(),
        updates,
        std::sync::Arc::new(tokio::sync::Mutex::new(Some(config.clone()))),
    )
    .unwrap();
    let response = plane.request(ControlRequest::Snapshot).await.unwrap();
    let ControlResponse::SnapshotEnvelope(envelope) = response else {
        panic!("missing signed snapshot")
    };
    assert_eq!(
        open_topology_snapshot(
            config.controller_signing_key.as_ref().unwrap(),
            config.control_encryption_private_key.as_ref().unwrap(),
            "default",
            1,
            now_ms().unwrap(),
            &envelope
        )
        .unwrap()
        .revision,
        1
    );
    assert!(
        open_topology_snapshot(
            &"00".repeat(32),
            config.control_encryption_private_key.as_ref().unwrap(),
            "default",
            1,
            now_ms().unwrap(),
            &envelope
        )
        .is_err()
    );
    let unauthorized = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id();
    assert!(
        request_to_bootstraps(
            &mut config,
            &[format!("/ip4/127.0.0.1/tcp/1/p2p/{unauthorized}")],
            ControlRequest::Snapshot
        )
        .await
        .unwrap_err()
        .contains("not authorized")
    );
    servers[1].abort();
}
