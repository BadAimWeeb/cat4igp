fn reserve_startup_listener() -> std::net::TcpListener {
    // ponytail: Linux fixed-roster fixtures need a close/rebind handoff;
    // use native port 0 if startup ever supports binding before roster persistence.
    // Never reissue a port during another fixture's close/rebind handoff.
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1024);
    let range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").unwrap();
    let range: Vec<u16> = range
        .split_whitespace()
        .map(|p| p.parse().unwrap())
        .collect();
    assert_eq!(range.len(), 2);
    assert!(range[0] <= range[1]);
    while let Ok(port) = u16::try_from(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) {
        if (range[0]..=range[1]).contains(&port) {
            continue;
        }
        match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)) {
            Ok(listener) => return listener,
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => panic!("reserve startup port {port}: {error}"),
        }
    }
    panic!("no startup port outside outbound ephemeral range");
}

struct KilledChild(std::process::Child);
impl Drop for KilledChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn parallel_reserved_startup_binds_each_listener() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..4 {
            let listener = reserve_startup_listener();
            let socket_address = listener.local_addr().unwrap();
            assert_eq!(
                std::net::TcpListener::bind(socket_address)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::AddrInUse
            );
            tasks.spawn(async move {
                let root = tempfile::tempdir().unwrap();
                let identity = root.path().join("replica.key");
                let key = crate::raft_network::replica_identity(&identity).unwrap();
                let address: libp2p::Multiaddr =
                    format!("/ip4/127.0.0.1/tcp/{}", socket_address.port())
                        .parse()
                        .unwrap();
                let config = Config {
                    cluster_id: "parallel-startup".into(),
                    node_id: 1,
                    mode: Mode::Join,
                    identity_file: identity.to_str().unwrap().into(),
                    listen: address.clone(),
                    replicas: BTreeMap::from([(
                        1,
                        Replica {
                            peer_id: key.public().to_peer_id(),
                            address,
                        },
                    )]),
                    learner: None,
                    cluster_psk: None,
                    transport_generation: 0,
                    legacy_import: None,
                };
                let database = root
                    .path()
                    .join("replica.sqlite")
                    .to_str()
                    .unwrap()
                    .to_owned();
                let mut conn = diesel::SqliteConnection::establish(&database).unwrap();
                crate::db::migrate(&mut conn, true).unwrap();
                drop(conn);
                let (node, store, task, service) = start_inner(
                    config,
                    database,
                    libp2p::pnet::PreSharedKey::new([54; 32]),
                    Some(listener),
                )
                .await
                .unwrap();
                assert_eq!(
                    std::net::TcpListener::bind(socket_address)
                        .unwrap_err()
                        .kind(),
                    std::io::ErrorKind::AddrInUse
                );
                node.shutdown().await.unwrap();
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
                drop((service, store));
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    })
    .await
    .expect("parallel startup deadline");
}

#[tokio::test]
async fn occupied_startup_port_reports_stage_and_recovers_binding() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let root = tempfile::tempdir().unwrap();
        let database = root
            .path()
            .join("replica.sqlite")
            .to_str()
            .unwrap()
            .to_owned();
        let identity = root.path().join("replica.key");
        let key = crate::raft_network::replica_identity(&identity).unwrap();
        let peer = key.public().to_peer_id();
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address: libp2p::Multiaddr =
            format!("/ip4/127.0.0.1/tcp/{}", socket.local_addr().unwrap().port())
                .parse()
                .unwrap();
        let psk = libp2p::pnet::PreSharedKey::new([53; 32]);
        let config = |mode| Config {
            cluster_id: "startup-port".into(),
            node_id: 1,
            mode,
            identity_file: identity.to_str().unwrap().into(),
            listen: address.clone(),
            replicas: BTreeMap::from([(
                1,
                Replica {
                    peer_id: peer,
                    address: address.clone(),
                },
            )]),
            learner: None,
            cluster_psk: None,
            transport_generation: 0,
            legacy_import: None,
        };
        let mut conn = diesel::SqliteConnection::establish(&database).unwrap();
        crate::db::migrate(&mut conn, true).unwrap();
        drop(conn);

        // ponytail: deterministically occupy the released-port race window;
        // this identifies a possible empty error, not the historical flake's cause.
        let error = match Network::start(
            1,
            "startup-port".into(),
            key,
            psk,
            BTreeMap::from([(
                1,
                Binding {
                    peer,
                    address: address.clone(),
                },
            )]),
            address.clone(),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("occupied listener unexpectedly bound"),
        };
        assert_eq!(error.to_string(), "", "pinned libp2p transport Display");
        assert!(format!("{error:?}").contains("AddrInUse"));
        let error = match start(config(Mode::Join), database.clone(), psk).await {
            Err(error) => error,
            Ok(_) => panic!("occupied startup unexpectedly succeeded"),
        };
        assert!(
            error.starts_with("cluster transport startup node 1:"),
            "{error}"
        );
        assert!(error.contains("AddrInUse"), "{error}");
        let store = Store::open(database.clone()).await.unwrap();
        let binding = store
            .run(|conn| {
                assert!(crate::raft_storage::get::<serde_json::Value>(conn, "vote")?.is_none());
                assert!(crate::raft_storage::get::<serde_json::Value>(conn, "applied")?.is_none());
                assert!(
                    crate::raft_storage::get::<serde_json::Value>(conn, "membership")?.is_none()
                );
                crate::raft_storage::get::<serde_json::Value>(conn, "replica_binding")
            })
            .await
            .unwrap()
            .expect("pre-transport binding is durable");
        drop(store);
        drop(socket);

        // Join/recover cannot wait for a quorum here: peers may start sequentially.
        let (node, store, task, service) =
            start(config(Mode::Recover), database, psk).await.unwrap();
        node.wait(Some(DEADLINE))
            .state(
                openraft::ServerState::Learner,
                "pristine recovered core started",
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .run(|conn| crate::raft_storage::get::<serde_json::Value>(conn, "replica_binding"))
                .await
                .unwrap(),
            Some(binding)
        );
        assert!(node.metrics().borrow().current_leader.is_none());
        node.shutdown().await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        drop(service);
        drop(store);
    })
    .await
    .expect("bounded occupied-port startup/recovery");
}

#[tokio::test]
#[ignore = "subprocess helper; requires explicit private test directory"]
async fn process_kill_child() {
    use diesel::{QueryDsl, RunQueryDsl};
    use futures_util::StreamExt;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let root =
        std::path::PathBuf::from(std::env::var_os("CAT4IGP_KILL_CHILD").expect("child mode"));
    if let Some(config) = std::env::var_os("CAT4IGP_QUORUM_CONFIG") {
        tokio::time::timeout(Duration::from_secs(120), async {
            let config: Config =
                serde_json::from_reader(std::fs::File::open(config).unwrap()).unwrap();
            let database = root.join("replica.sqlite").to_str().unwrap().to_owned();
            let mut conn = diesel::SqliteConnection::establish(&database).unwrap();
            crate::db::migrate(&mut conn, true).unwrap();
            drop(conn);
            let key =
                crate::raft_network::replica_identity(std::path::Path::new(&config.identity_file))
                    .unwrap();
            let (node, store, _transport, service) =
                start(config, database, libp2p::pnet::PreSharedKey::new([9; 32]))
                    .await
                    .unwrap();
            let wire: (String, String, cat4igp_shared::discovery::ControllerRoster) =
                serde_json::from_reader(std::fs::File::open(root.join("wire.json")).unwrap())
                    .unwrap();
            let serving = key.public().to_peer_id();
            let listener_service = service.clone();
            let listener_key = key.clone();
            let private = wire.0.clone();
            let drop_enrollment: EnrollmentDrop = Arc::new(std::sync::Mutex::new(None));
            let listener_drop = drop_enrollment.clone();
            let _control = tokio::spawn(async move {
                private_control_inner(
                    listener_service,
                    listener_key,
                    &private,
                    libp2p::pnet::PreSharedKey::new([0x12; 32]),
                    Some(listener_drop),
                )
                .await
            });
            let mut public = cat4igp_shared::discovery::transport::swarm(&key).unwrap();
            public.listen_on(wire.1.parse().unwrap()).unwrap();
            loop {
                if matches!(
                    public.select_next_some().await,
                    libp2p::swarm::SwarmEvent::NewListenAddr { .. }
                ) {
                    break;
                }
            }
            let discovery_service = service.clone();
            let _discovery = tokio::spawn(async move {
                cat4igp_shared::discovery::transport::serve_with_join(
                    public,
                    "quorum-process-kill",
                    move |query, source| {
                        let service = discovery_service.clone();
                        async move {
                            match service
                                .submit(Operation::Discovery {
                                    query,
                                    source,
                                    serving,
                                })
                                .await
                            {
                                Outcome::Discovery(result) => result,
                                _ => Err("unavailable".into()),
                            }
                        }
                    },
                    |_, _| async { cat4igp_shared::discovery::join::Response::Unavailable },
                )
                .await
            });
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            std::thread::spawn(move || {
                use std::io::BufRead;
                for line in std::io::stdin().lock().lines() {
                    if tx.send(line.unwrap()).is_err() {
                        break;
                    }
                }
            });
            println!("CAT4IGP_STARTED");
            std::io::stdout().flush().unwrap();
            while let Some(command) = rx.recv().await {
                tokio::time::timeout(Duration::from_secs(20), async {
                    if let Some(peer) = command.strip_prefix("drop-enrollment ") {
                        *drop_enrollment.lock().unwrap() =
                            Some((peer.parse().unwrap(), root.join("dropped.json"), true));
                        println!("CAT4IGP_ARMED");
                    } else if let Some(peer) = command.strip_prefix("record-enrollment ") {
                        *drop_enrollment.lock().unwrap() =
                            Some((peer.parse().unwrap(), root.join("replayed.json"), false));
                        println!("CAT4IGP_ARMED");
                    } else if command == "wire" {
                        assert!(matches!(
                            service.submit(Operation::Roster(wire.2.clone())).await,
                            Outcome::Roster(Ok(()))
                        ));
                        let authority = store.run(read_authority).await.unwrap();
                        let mut receipt = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(root.join("authority.json"))
                            .unwrap();
                        serde_json::to_writer(&mut receipt, &authority).unwrap();
                        receipt.sync_all().unwrap();
                        println!("CAT4IGP_WIRE");
                    } else if command == "ready" {
                        let mut retry = tokio::time::interval(Duration::from_millis(100));
                        loop {
                            retry.tick().await;
                            if matches!(service.submit(Operation::Ready).await, Outcome::Ready) {
                                if let Some(leader) = node.metrics().borrow().current_leader {
                                    println!("CAT4IGP_LEADER {leader}");
                                    break;
                                }
                            }
                        }
                    } else if let Some(expected_node) = command.strip_prefix("state ") {
                        let expected_node: i32 = expected_node.parse().unwrap();
                        let mut retry = tokio::time::interval(Duration::from_millis(100));
                        loop {
                            retry.tick().await;
                            let codes = store
                                .run(|conn| {
                                    let mut codes: Vec<_> = crate::db::get_invites(conn)?
                                        .into_iter()
                                        .map(|i| i.code)
                                        .collect();
                                    codes.sort();
                                    Ok(codes)
                                })
                                .await
                                .unwrap();
                            if codes.len() == 2 {
                                store
                                    .run(move |conn| {
                                        use diesel::dsl::count_star;
                                        assert_eq!(
                                            crate::schema::nodes::table
                                                .select(count_star())
                                                .first::<i64>(conn)?,
                                            1
                                        );
                                        assert_eq!(
                                            crate::schema::nodes::table
                                                .select(crate::schema::nodes::id)
                                                .first::<i32>(conn)?,
                                            expected_node
                                        );
                                        assert_eq!(
                                            crate::db::get_invites(conn)?
                                                .iter()
                                                .map(|i| i.used_count)
                                                .sum::<i32>(),
                                            1
                                        );
                                        Ok(())
                                    })
                                    .await
                                    .unwrap();
                                let mut receipt = std::fs::OpenOptions::new()
                                    .write(true)
                                    .create_new(true)
                                    .mode(0o600)
                                    .open(root.join("state.json"))
                                    .unwrap();
                                serde_json::to_writer(&mut receipt, &codes).unwrap();
                                receipt.sync_all().unwrap();
                                println!("CAT4IGP_STATE");
                                break;
                            }
                        }
                    } else {
                        assert!(matches!(command.as_str(), "quorum-retry" | "quorum-next"));
                        let code = match service
                            .submit(Operation::Invite {
                                request_id: command.clone(),
                                expires_at: None,
                                max_uses: Some(1),
                                join_mesh: None,
                            })
                            .await
                        {
                            Outcome::Invite(Ok(code)) => code,
                            _ => panic!("child operator write unavailable"),
                        };
                        let mut receipt = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(root.join(format!("{command}.json")))
                            .unwrap();
                        serde_json::to_writer(&mut receipt, &code).unwrap();
                        receipt.sync_all().unwrap();
                        println!("CAT4IGP_COMMITTED");
                    }
                    std::io::stdout().flush().unwrap();
                })
                .await
                .expect("child command deadline");
            }
        })
        .await
        .expect("quorum child deadline");
        return;
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        let database = root.join("replica.sqlite").to_str().unwrap().to_owned();
        let identity = root.join("replica.key");
        let key = crate::raft_network::replica_identity(&identity).unwrap();
        let mut conn = diesel::SqliteConnection::establish(&database).unwrap();
        crate::db::migrate(&mut conn, true).unwrap();
        drop(conn);
        let (node, store, _transport, service) = start(
            Config {
                cluster_id: "process-kill".into(),
                node_id: 1,
                mode: Mode::Initialize,
                identity_file: identity.to_str().unwrap().into(),
                listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
                replicas: BTreeMap::from([(
                    1,
                    Replica {
                        peer_id: key.public().to_peer_id(),
                        address: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
                    },
                )]),
                learner: None,
                cluster_psk: None,
                transport_generation: 0,
                legacy_import: None,
            },
            database,
            libp2p::pnet::PreSharedKey::new([9; 32]),
        )
        .await
        .unwrap();
        node.wait(Some(DEADLINE))
            .current_leader(1, "child elected")
            .await
            .unwrap();
        let code = match service
            .submit(Operation::Invite {
                request_id: "kill-retry".into(),
                expires_at: None,
                max_uses: Some(1),
                join_mesh: None,
            })
            .await
        {
            Outcome::Invite(Ok(code)) => code,
            _ => panic!("child write failed"),
        };
        let metadata = store
            .run(|conn| {
                Ok(["vote", "committed", "applied", "membership"]
                    .map(|key| crate::raft_storage::get::<serde_json::Value>(conn, key).unwrap()))
            })
            .await
            .unwrap();
        assert!(metadata.iter().all(Option::is_some));
        let mut receipt = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("receipt.json"))
            .unwrap();
        serde_json::to_writer(&mut receipt, &(metadata, code)).unwrap();
        receipt.sync_all().unwrap();
        println!("CAT4IGP_COMMITTED");
        std::io::stdout().flush().unwrap();
        // Keep the actual runtime/SQLite worker alive until the parent kills this process.
        std::future::pending::<()>().await;
    })
    .await
    .expect("child deadline");
}

#[tokio::test]
async fn process_kill_recovers_acknowledged_invite() {
    use openraft::{RaftLogReader, storage::RaftLogStorage};
    use std::io::{BufRead, Read};
    // ponytail: singleton OS kill after acknowledgement, not power loss;
    // add injected pre-commit/fsync faults separately.
    let root = tempfile::tempdir().unwrap();
    let mut child = KilledChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cluster::tests::process_kill_child",
                "--ignored",
                "--nocapture",
            ])
            .env("CAT4IGP_KILL_CHILD", root.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut output = std::io::BufReader::new(stdout.take(8192));
        let mut line = String::new();
        while output.read_line(&mut line).unwrap() != 0 {
            if line.trim() == "CAT4IGP_COMMITTED" {
                let _ = tx.send(());
                return;
            }
            line.clear();
        }
    });
    let ready = rx.recv_timeout(Duration::from_secs(45));
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    reader.join().unwrap();
    ready.expect("bounded child commit handshake");
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9));
    tokio::time::timeout(Duration::from_secs(30), async {
        let (expected, code): ([Option<serde_json::Value>; 4], String) =
            serde_json::from_reader(std::fs::File::open(root.path().join("receipt.json")).unwrap())
                .unwrap();
        let database = root
            .path()
            .join("replica.sqlite")
            .to_str()
            .unwrap()
            .to_owned();
        let mut reopened = Store::open(database.clone()).await.unwrap();
        let actual = reopened
            .run(|conn| {
                Ok(["vote", "committed", "applied", "membership"]
                    .map(|key| crate::raft_storage::get::<serde_json::Value>(conn, key).unwrap()))
            })
            .await
            .unwrap();
        assert_eq!(actual, expected);
        let applied: openraft::LogId<u64> =
            serde_json::from_value(actual[2].clone().unwrap()).unwrap();
        assert_eq!(
            reopened.get_log_state().await.unwrap().last_log_id,
            Some(applied)
        );
        let entries = reopened
            .try_get_log_entries(applied.index..=applied.index)
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert!(
            matches!(&entries[0].payload, openraft::EntryPayload::Normal(Command::Invite(command))
            if command.request_id == "kill-retry")
        );
        drop(reopened);
        let identity = root.path().join("replica.key");
        let key = crate::raft_network::replica_identity(&identity).unwrap();
        let (node, store, transport, service) = start(
            Config {
                cluster_id: "process-kill".into(),
                node_id: 1,
                mode: Mode::Recover,
                identity_file: identity.to_str().unwrap().into(),
                listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
                replicas: BTreeMap::from([(
                    1,
                    Replica {
                        peer_id: key.public().to_peer_id(),
                        address: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
                    },
                )]),
                learner: None,
                cluster_psk: None,
                transport_generation: 0,
                legacy_import: None,
            },
            database,
            libp2p::pnet::PreSharedKey::new([9; 32]),
        )
        .await
        .unwrap();
        node.wait(Some(DEADLINE))
            .current_leader(1, "killed singleton recovered")
            .await
            .unwrap();
        assert!(matches!(service.submit(Operation::Invite {
            request_id: "kill-retry".into(), expires_at: None, max_uses: Some(1), join_mesh: None,
        }).await, Outcome::Invite(Ok(retry)) if retry == code));
        assert_eq!(
            store
                .run(|conn| Ok(crate::db::get_invites(conn)?.len()))
                .await
                .unwrap(),
            1
        );
        assert!(matches!(service.submit(Operation::Invite {
            request_id: "after-kill".into(), expires_at: None, max_uses: Some(1), join_mesh: None,
        }).await, Outcome::Invite(Ok(next)) if next != code));
        assert_eq!(
            store
                .run(|conn| Ok(crate::db::get_invites(conn)?.len()))
                .await
                .unwrap(),
            2
        );
        node.shutdown().await.unwrap();
        transport.abort();
        let _ = transport.await;
    })
    .await
    .expect("recovery deadline");
}

#[test]
fn three_process_leader_kill_recovers_invites() {
    use diesel::{QueryDsl, RunQueryDsl};
    use std::io::{BufRead, Read, Write};
    use std::os::unix::process::ExitStatusExt;
    // ponytail: shipped control wire after SIGKILL, not OS dataplane or power loss;
    // add privileged traffic/storage fault rehearsals separately.
    let root = tempfile::tempdir().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(100);
    let listeners: Vec<_> = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let addresses: Vec<libp2p::Multiaddr> = listeners
        .iter()
        .map(|l| {
            format!("/ip4/127.0.0.1/tcp/{}", l.local_addr().unwrap().port())
                .parse()
                .unwrap()
        })
        .collect();
    let directories: Vec<_> = (0..3)
        .map(|i| {
            let directory = root.path().join(i.to_string());
            std::fs::create_dir(&directory).unwrap();
            directory
        })
        .collect();
    let keys: Vec<_> = directories
        .iter()
        .map(|d| crate::raft_network::replica_identity(&d.join("replica.key")).unwrap())
        .collect();
    let wire_sockets: Vec<_> = (0..6)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let wire_addresses: Vec<String> = wire_sockets
        .iter()
        .map(|s| format!("/ip4/127.0.0.1/tcp/{}", s.local_addr().unwrap().port()))
        .collect();
    let now = chrono::Utc::now().timestamp_millis();
    let roster = cat4igp_shared::discovery::ControllerRoster {
        version: 1,
        cluster_id: "quorum-process-kill".into(),
        revision: 1,
        issued_at_ms: now,
        expires_at_ms: now + 180_000,
        discovery_endpoints: (0..3)
            .map(|i| cat4igp_shared::discovery::ControllerEndpoint {
                peer_id: keys[i].public().to_peer_id(),
                addresses: vec![
                    format!(
                        "{}/p2p/{}",
                        wire_addresses[i * 2 + 1],
                        keys[i].public().to_peer_id()
                    )
                    .parse()
                    .unwrap(),
                ],
            })
            .collect(),
        controllers: (0..3)
            .map(|i| cat4igp_shared::discovery::ControllerEndpoint {
                peer_id: keys[i].public().to_peer_id(),
                addresses: vec![
                    format!(
                        "{}/p2p/{}",
                        wire_addresses[i * 2],
                        keys[i].public().to_peer_id()
                    )
                    .parse()
                    .unwrap(),
                ],
            })
            .collect(),
    };
    for i in 0..3 {
        std::fs::write(
            directories[i].join("wire.json"),
            serde_json::to_vec(&(
                wire_addresses[i * 2].clone(),
                wire_addresses[i * 2 + 1].clone(),
                &roster,
            ))
            .unwrap(),
        )
        .unwrap();
    }
    drop(wire_sockets);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut configs: Vec<_> = (0..3)
        .map(|i| Config {
            cluster_id: "quorum-process-kill".into(),
            node_id: i as u64 + 1,
            mode: if i == 2 { Mode::Initialize } else { Mode::Join },
            identity_file: directories[i].join("replica.key").to_str().unwrap().into(),
            listen: addresses[i].clone(),
            replicas: (0..3)
                .map(|j| {
                    (
                        j as u64 + 1,
                        Replica {
                            peer_id: keys[j].public().to_peer_id(),
                            address: addresses[j].clone(),
                        },
                    )
                })
                .collect(),
            learner: None,
            cluster_psk: None,
            transport_generation: 0,
            legacy_import: None,
        })
        .collect();
    drop(listeners);
    let spawn = |i: usize, config: &Config| {
        let path = directories[i].join("config.json");
        std::fs::write(&path, serde_json::to_vec(config).unwrap()).unwrap();
        let mut child = KilledChild(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cluster::tests::process_kill_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("CAT4IGP_KILL_CHILD", &directories[i])
                .env("CAT4IGP_QUORUM_CONFIG", path)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut output = std::io::BufReader::new(stdout.take(8192));
            let mut line = String::new();
            while output.read_line(&mut line).unwrap() != 0 {
                if line.starts_with("CAT4IGP_") && tx.send(line.trim().to_owned()).is_err() {
                    break;
                }
                line.clear();
            }
        });
        (child, rx, reader)
    };
    let receive = |rx: &std::sync::mpsc::Receiver<String>| {
        rx.recv_timeout(
            deadline
                .saturating_duration_since(std::time::Instant::now())
                .min(Duration::from_secs(25)),
        )
        .expect("bounded subprocess handshake")
    };
    let mut children: Vec<_> = configs
        .iter()
        .enumerate()
        .map(|(i, c)| spawn(i, c))
        .collect();
    for (_, rx, _) in &children {
        assert_eq!(receive(rx), "CAT4IGP_STARTED");
    }
    let command = |child: &mut (
        KilledChild,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ),
                   text: &str| {
        writeln!(child.0.0.stdin.as_mut().unwrap(), "{text}").unwrap();
        child.0.0.stdin.as_mut().unwrap().flush().unwrap();
        receive(&child.1)
    };
    let leader = command(&mut children[0], "ready")
        .strip_prefix("CAT4IGP_LEADER ")
        .unwrap()
        .parse::<usize>()
        .unwrap()
        - 1;
    assert!(leader < 3);
    let follower = (leader + 1) % 3;
    assert_eq!(
        command(&mut children[follower], "ready"),
        format!("CAT4IGP_LEADER {}", leader + 1)
    );
    assert_eq!(
        command(&mut children[follower], "quorum-retry"),
        "CAT4IGP_COMMITTED"
    );
    let receipt = |i: usize, name: &str| -> String {
        serde_json::from_reader(
            std::fs::File::open(directories[i].join(format!("{name}.json"))).unwrap(),
        )
        .unwrap()
    };
    let original = receipt(follower, "quorum-retry");
    assert_eq!(command(&mut children[follower], "wire"), "CAT4IGP_WIRE");
    let authority: Authority = serde_json::from_reader(
        std::fs::File::open(directories[follower].join("authority.json")).unwrap(),
    )
    .unwrap();
    let client_dir = root.path().join("client");
    let endpoint = roster.controllers[follower].addresses[0].to_string();
    let mut client = crate::client_config::ServerConfig::new(endpoint.clone(), original.clone());
    client.controller_signing_key = Some(authority.signing_key.clone());
    client.controller_peer_id = Some(
        libp2p::identity::PublicKey::try_decode_protobuf(
            &crate::hex_decode(&authority.signing_key).unwrap(),
        )
        .unwrap()
        .to_peer_id()
        .to_string(),
    );
    client.controller_encryption_key = Some(authority.encryption_key.clone());
    client.control_network_id = "quorum-process-kill".into();
    client.control_private_network_key =
        Some(libp2p::pnet::PreSharedKey::new([0x12; 32]).to_key_file());
    client.ensure_wireguard_keypair().unwrap();
    client.ensure_control_keypair().unwrap();
    client.ensure_control_encryption_key().unwrap();
    client.discovery_bootstrap_addresses = vec![format!(
        "{}/p2p/{}",
        wire_addresses[follower * 2 + 1],
        keys[follower].public().to_peer_id()
    )];
    client.save(&client_dir).unwrap();
    runtime.block_on(async {
        crate::client_control::refresh_discovery(&mut client)
            .await
            .unwrap();
        client.save(&client_dir).unwrap();
    });
    let preserved = serde_json::to_value(&client).unwrap();
    let peer = client
        .ensure_control_keypair()
        .unwrap()
        .public()
        .to_peer_id();
    let binary = std::env::var_os("CAT4IGP_CLIENT_TEST_BINARY")
        .map(|binary| std::fs::canonicalize(binary).expect("supplied client test executable"));
    let ipc_dir = root.path().join("ipc-client");
    let spawn_ipc = |success: bool| {
        let mut fixture = KilledChild(
            std::process::Command::new(binary.as_ref().unwrap())
                .args([
                    "--exact",
                    "daemon::tests::ipc_external_endpoint",
                    "--ignored",
                    "--nocapture",
                ])
                .env("CAT4IGP_IPC_ENDPOINT_DIR", &ipc_dir)
                .env(
                    "CAT4IGP_IPC_HOSTNAME",
                    if success {
                        "different-restart-name"
                    } else {
                        "process-client"
                    },
                )
                .env("CAT4IGP_IPC_EXPECT_SUCCESS", success.to_string())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stdout = fixture.0.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout.take(8192)).lines() {
                let line = line.unwrap();
                if line.starts_with("IPC_") {
                    let _ = tx.send(line);
                }
            }
        });
        (fixture, rx, reader)
    };
    let mut ipc_bundle = None;
    let mut ipc_pending_before = None;
    let mut ipc_fixture = None;
    if binary.is_some() {
        // ponytail: actual daemon IPC handler processes, not Daemon::run/dataplane or power loss.
        let bundle = cat4igp_shared::control::EnrollmentBundle {
            version: 1,
            bootstrap_addresses: client.control_bootstrap_addresses.clone(),
            controller_peer_id: client.controller_peer_id.clone().unwrap(),
            controller_signing_key: authority.signing_key.clone(),
            network_id: client.control_network_id.clone(),
            private_network_key: client.control_private_network_key.clone().unwrap(),
            invitation_code: original.clone(),
            discovery_bootstrap_addresses: vec![format!(
                "{}/p2p/{}",
                wire_addresses[leader * 2 + 1],
                keys[leader].public().to_peer_id()
            )],
        };
        // Same pending identity/request as the default wire fixture; no successful enrollment yet.
        let mut pending = client.clone();
        pending.enrollment_node_name = Some("process-client".into());
        pending.enrollment_bootstrap_addresses = bundle.bootstrap_addresses.clone();
        pending.discovery_bootstrap_addresses = bundle.discovery_bootstrap_addresses.clone();
        pending.discovery_proof = None;
        ipc_pending_before = Some(serde_json::to_value(&pending).unwrap());
        pending.save(&ipc_dir).unwrap();
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(ipc_dir.join("bundle.json"))
            .unwrap();
        serde_json::to_writer(&mut file, &bundle).unwrap();
        file.sync_all().unwrap();
        assert_eq!(
            command(&mut children[follower], &format!("drop-enrollment {peer}")),
            "CAT4IGP_ARMED"
        );
        assert_eq!(
            std::fs::metadata(ipc_dir.join("server.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let fixture = spawn_ipc(false);
        assert_eq!(receive(&fixture.1), "IPC_PENDING");
        ipc_fixture = Some(fixture);
        ipc_bundle = Some(bundle);
    } else {
        assert_eq!(
            command(&mut children[follower], &format!("drop-enrollment {peer}")),
            "CAT4IGP_ARMED"
        );
        let failed = runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                crate::client_control::enroll(&mut client, &[endpoint], "process-client".into()),
            )
            .await
            .expect("wire closure must fail promptly")
        });
        assert!(
            failed.is_err(),
            "lost response must not complete enrollment"
        );
        assert!(client.control_node_id.is_none());
    }
    assert_eq!(receive(&children[follower].1), "CAT4IGP_DROPPED");
    let (original_enrollment, original_snapshot): (
        cat4igp_shared::control::ControlResponse,
        cat4igp_shared::control::ControlResponse,
    ) = serde_json::from_reader(
        std::fs::File::open(directories[follower].join("dropped.json")).unwrap(),
    )
    .unwrap();
    let cat4igp_shared::control::ControlResponse::Enrolled(enrollment) = &original_enrollment
    else {
        panic!("missing committed enrollment receipt");
    };
    // Receipt is written only after actual Raft application and a quorum-backed snapshot read.
    // Confirm the live leader DB before allowing the daemon SIGKILL (not merely IPC_PENDING).
    let mut committed = diesel::SqliteConnection::establish(
        directories[leader].join("replica.sqlite").to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        crate::schema::nodes::table
            .select(crate::schema::nodes::id)
            .load::<i32>(&mut committed)
            .unwrap(),
        vec![enrollment.node_id]
    );
    assert_eq!(
        crate::db::get_invites(&mut committed)
            .unwrap()
            .iter()
            .map(|invite| invite.used_count)
            .sum::<i32>(),
        1
    );
    drop(committed);
    if let Some(mut fixture) = ipc_fixture.take() {
        assert_eq!(command(&mut fixture, "kill"), "IPC_KILLED");
        assert!(fixture.0.0.wait().unwrap().success());
        fixture.2.join().unwrap();
        let pending = crate::client_config::ServerConfig::load(&ipc_dir).unwrap();
        assert!(pending.control_node_id.is_none());
        let mut expected = ipc_pending_before.take().unwrap();
        expected["enrollment_discovery_bootstrap_addresses"] =
            serde_json::to_value(&ipc_bundle.as_ref().unwrap().discovery_bootstrap_addresses)
                .unwrap();
        expected["discovery_proof"] = serde_json::to_value(&pending.discovery_proof).unwrap();
        expected["control_bootstrap_addresses"] =
            serde_json::to_value(&pending.control_bootstrap_addresses).unwrap();
        expected["discovery_bootstrap_addresses"] =
            serde_json::to_value(&pending.discovery_bootstrap_addresses).unwrap();
        assert_eq!(serde_json::to_value(&pending).unwrap(), expected);
    }
    let cat4igp_shared::control::ControlResponse::SnapshotEnvelope(envelope) = original_snapshot
    else {
        panic!("missing committed snapshot receipt");
    };
    let before = serde_json::to_value(
        cat4igp_shared::control::open_topology_snapshot(
            &authority.signing_key,
            client.control_encryption_private_key.as_deref().unwrap(),
            "quorum-process-kill",
            enrollment.node_id,
            chrono::Utc::now().timestamp_millis(),
            &envelope,
        )
        .unwrap(),
    )
    .unwrap();
    let snapshot = |config: crate::client_config::ServerConfig| {
        runtime.block_on(async {
            use cat4igp_shared::control::{ControlRequest, ControlResponse};
            let (updates, _rx) = tokio::sync::mpsc::channel(1);
            let current = Arc::new(tokio::sync::Mutex::new(Some(config.clone())));
            let control = crate::client_control::start(config.clone(), updates, current).unwrap();
            let response = control.request(ControlRequest::Snapshot).await.unwrap();
            let ControlResponse::SnapshotEnvelope(envelope) = response else {
                panic!("snapshot unavailable");
            };
            let snapshot = cat4igp_shared::control::open_topology_snapshot(
                &authority.signing_key,
                config.control_encryption_private_key.as_deref().unwrap(),
                "quorum-process-kill",
                config.control_node_id.unwrap(),
                chrono::Utc::now().timestamp_millis(),
                &envelope,
            )
            .unwrap();
            drop(control);
            serde_json::to_value(snapshot).unwrap()
        })
    };
    children[leader].0.0.kill().unwrap();
    assert_eq!(children[leader].0.0.wait().unwrap().signal(), Some(9));
    let survivor = (leader + 2) % 3;
    let new_leader = command(&mut children[survivor], "ready")
        .strip_prefix("CAT4IGP_LEADER ")
        .unwrap()
        .parse::<usize>()
        .unwrap()
        - 1;
    assert!(new_leader < 3 && new_leader != leader);
    if let Some(bundle) = ipc_bundle {
        use std::os::unix::fs::PermissionsExt;
        let pending = crate::client_config::ServerConfig::load(&ipc_dir).unwrap();
        let original_pending = serde_json::to_value(&pending).unwrap();
        // Original bundle has ONLY the killed leader seed; signed public seeds survive on disk.
        assert_eq!(bundle.discovery_bootstrap_addresses.len(), 1);
        assert!(pending.discovery_bootstrap_addresses.contains(&format!(
            "{}/p2p/{}",
            wire_addresses[survivor * 2 + 1],
            keys[survivor].public().to_peer_id()
        )));
        let bundle_bytes = std::fs::read(ipc_dir.join("bundle.json")).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bundle_bytes).unwrap(),
            serde_json::to_value(&bundle).unwrap()
        );
        // Discovery returns the original roster order; the first reachable private peer is recorded.
        let replay_server = (0..3).find(|i| *i != leader).unwrap();
        assert_eq!(
            command(
                &mut children[replay_server],
                &format!("record-enrollment {peer}")
            ),
            "CAT4IGP_ARMED"
        );
        let fixture = spawn_ipc(true);
        let (mut child, rx, reader) = fixture;
        assert_eq!(receive(&rx), "IPC_COMPLETED");
        assert!(
            child.0.wait().unwrap().success(),
            "external IPC retry failed"
        );
        reader.join().unwrap();
        assert_eq!(
            std::fs::read(ipc_dir.join("bundle.json")).unwrap(),
            bundle_bytes
        );
        let completed = crate::client_config::ServerConfig::load(&ipc_dir).unwrap();
        assert_eq!(completed.control_node_id, Some(enrollment.node_id));
        assert_eq!(completed.topology_revision, enrollment.topology_revision);
        assert!(completed.invite_code.is_empty());
        let mut expected = original_pending;
        let actual = serde_json::to_value(&completed).unwrap();
        for field in [
            "control_node_id",
            "topology_revision",
            "controller_encryption_key",
            "invite_code",
            "discovery_proof",
            "control_bootstrap_addresses",
            "discovery_bootstrap_addresses",
        ] {
            expected[field] = actual[field].clone();
        }
        assert_eq!(
            expected, actual,
            "restart changed identity/name/original seeds/trust"
        );
        assert_eq!(
            std::fs::metadata(ipc_dir.join("server.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let read = |i: usize, name: &str| -> serde_json::Value {
            serde_json::from_reader(std::fs::File::open(directories[i].join(name)).unwrap())
                .unwrap()
        };
        assert_eq!(
            read(follower, "dropped.request.json"),
            read(replay_server, "replayed.request.json")
        );
        assert_eq!(
            read(replay_server, "replayed.json")[0],
            serde_json::to_value(&original_enrollment).unwrap()
        );
        assert_eq!(snapshot(completed), before);
    }
    let mut client = crate::client_config::ServerConfig::load(&client_dir).unwrap();
    assert_eq!(serde_json::to_value(&client).unwrap(), preserved);
    assert!(client.control_node_id.is_none());
    assert_eq!(
        client
            .ensure_control_keypair()
            .unwrap()
            .public()
            .to_peer_id(),
        peer
    );
    // Reloaded signed PUBLIC seeds repair reachability without an operator survivor edit.
    assert!(client.discovery_bootstrap_addresses.contains(&format!(
        "{}/p2p/{}",
        wire_addresses[survivor * 2 + 1],
        keys[survivor].public().to_peer_id()
    )));
    runtime
        .block_on(crate::client_control::refresh_discovery(&mut client))
        .unwrap();
    let discovered_peer = client
        .discovery_proof
        .as_ref()
        .unwrap()
        .body
        .endpoint
        .peer_id;
    assert!(
        (0..3).any(|i| i != leader && keys[i].public().to_peer_id() == discovered_peer),
        "automatic discovery must use a live authorized replica, not one fixed survivor"
    );
    client.control_bootstrap_addresses =
        vec![roster.controllers[survivor].addresses[0].to_string()];
    let retry = runtime
        .block_on(crate::client_control::enroll(
            &mut client,
            &[roster.controllers[survivor].addresses[0].to_string()],
            "process-client".into(),
        ))
        .unwrap();
    assert_eq!(
        serde_json::to_value(retry).unwrap(),
        serde_json::to_value(&original_enrollment).unwrap()
    );
    assert_eq!(client.control_node_id, Some(enrollment.node_id));
    assert_eq!(client.topology_revision, enrollment.topology_revision);
    client.save(&client_dir).unwrap();
    let client = crate::client_config::ServerConfig::load(&client_dir).unwrap();
    let after = serde_json::to_value(&client).unwrap();
    for field in [
        "controller_peer_id",
        "controller_signing_key",
        "controller_encryption_key",
        "control_private_key",
        "control_encryption_private_key",
        "wg_private_key",
        "wg_public_key",
        "control_network_id",
        "control_enrollment_request_id",
    ] {
        assert_eq!(preserved[field], after[field], "changed {field}");
    }
    assert_eq!(snapshot(client), before);
    let retry_follower = if new_leader == follower {
        survivor
    } else {
        follower
    };
    assert_eq!(
        command(&mut children[retry_follower], "ready"),
        format!("CAT4IGP_LEADER {}", new_leader + 1)
    );
    // Receipts are local acknowledgements, not the replicated dedup state.
    let retry_receipt = directories[retry_follower].join("quorum-retry.json");
    if retry_receipt.exists() {
        std::fs::remove_file(retry_receipt).unwrap();
    }
    assert_eq!(
        command(&mut children[retry_follower], "quorum-retry"),
        "CAT4IGP_COMMITTED"
    );
    assert_eq!(receipt(retry_follower, "quorum-retry"), original);
    assert_eq!(
        command(&mut children[retry_follower], "quorum-next"),
        "CAT4IGP_COMMITTED"
    );
    let next = receipt(retry_follower, "quorum-next");
    assert_ne!(original, next);
    configs[leader].mode = Mode::Recover;
    let old = std::mem::replace(&mut children[leader], spawn(leader, &configs[leader]));
    drop(old.0);
    old.2.join().unwrap();
    assert_eq!(receive(&children[leader].1), "CAT4IGP_STARTED");
    assert_eq!(
        command(&mut children[leader], "ready"),
        format!("CAT4IGP_LEADER {}", new_leader + 1)
    );
    let mut expected = vec![original.clone(), next];
    expected.sort();
    let state_command = format!("state {}", enrollment.node_id);
    for (i, child) in children.iter_mut().enumerate() {
        assert_eq!(command(child, &state_command), "CAT4IGP_STATE");
        let actual: Vec<String> = serde_json::from_reader(
            std::fs::File::open(directories[i].join("state.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(actual, expected);
    }
    assert_eq!(
        command(&mut children[leader], "quorum-retry"),
        "CAT4IGP_COMMITTED"
    );
    assert_eq!(receipt(leader, "quorum-retry"), original);
    std::fs::remove_file(directories[leader].join("state.json")).unwrap();
    assert_eq!(
        command(&mut children[leader], &state_command),
        "CAT4IGP_STATE"
    );
    let recovered: Vec<String> = serde_json::from_reader(
        std::fs::File::open(directories[leader].join("state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(recovered, expected);
    for (child, _, reader) in children {
        drop(child); // kill/reap before joining the bounded pipe reader, including on assertion failure.
        reader.join().unwrap();
    }
}

#[tokio::test]
async fn three_node_offline_transport_rotation_rehearsal() {
    // ponytail: real in-process Raft/swarm stop-all; subprocess kill/power-loss is a separate rehearsal.
    tokio::time::timeout(Duration::from_secs(90), async {
        let root = tempfile::tempdir().unwrap();
        let listeners: Vec<_> = (0..3)
            .map(|_| reserve_startup_listener())
            .collect();
        let addresses: Vec<libp2p::Multiaddr> = listeners.iter()
            .map(|l| format!("/ip4/127.0.0.1/tcp/{}", l.local_addr().unwrap().port()).parse().unwrap())
            .collect();
        let identities: Vec<_> = (0..3).map(|i| root.path().join(format!("{i}.key"))).collect();
        let keys: Vec<_> = identities.iter().map(|p| crate::raft_network::replica_identity(p).unwrap()).collect();
        let databases: Vec<_> = (0..3).map(|i| root.path().join(format!("{i}.sqlite")).to_str().unwrap().to_owned()).collect();
        let old = libp2p::pnet::PreSharedKey::new([41; 32]);
        let new = libp2p::pnet::PreSharedKey::new([42; 32]);
        let next = credential("rotation-rehearsal", 1, new);
        let config = |i: usize, mode| Config {
            cluster_id: "rotation-rehearsal".into(), node_id: i as u64 + 1, mode,
            identity_file: identities[i].to_str().unwrap().into(), listen: addresses[i].clone(),
            replicas: (0..3).map(|j| (j as u64 + 1, Replica {
                peer_id: keys[j].public().to_peer_id(), address: addresses[j].clone(),
            })).collect(),
            learner: None, cluster_psk: Some(old.to_key_file()), transport_generation: 0, legacy_import: None,
        };
        let mut running = Vec::new();
        for (i, (database, listener)) in databases.iter().zip(listeners).enumerate() {
            let mut conn = diesel::SqliteConnection::establish(database).unwrap();
            crate::db::migrate(&mut conn, true).unwrap();
            drop(conn);
            running.push(start_inner(config(i, if i == 2 { Mode::Initialize } else { Mode::Join }), database.clone(), old, Some(listener)).await.unwrap());
        }
        let leader = loop {
            if let Some(id) = running.iter().find_map(|r| r.0.metrics().borrow().current_leader) { break id as usize - 1; }
            tokio::task::yield_now().await;
        };
        let follower = (leader + 1) % 3;
        running[follower].0.wait(Some(DEADLINE)).current_leader(leader as u64 + 1, "initial follower").await.unwrap();
        let code = invite(&running[leader].0, &running[leader].1, "rotation-preserved-invite".into(), None, Some(3), None)
            .await.unwrap().unwrap();
        let preserved = running[leader].1.run(|conn| {
            Ok(["control_private_key", "control_encryption_private_key", "control_network_id"]
                .into_iter().map(|key| crate::db::get_setting(conn, key)).collect::<Result<Vec<_>, _>>()?)
        }).await.unwrap();
        assert!(matches!(running[follower].3.submit(Operation::PrepareTransport(next.clone())).await, Outcome::Transport(Ok(_))));
        assert!(matches!(running[follower].3.submit(Operation::CompleteTransport).await, Outcome::Transport(Err(_))));
        for (_, store, _, service) in &running {
            loop {
                if store.run(read_transport).await.unwrap().is_some_and(|s| s.next.as_ref() == Some(&next)) { break; }
                tokio::task::yield_now().await;
            }
            assert_eq!(service.transport_credential, credential("rotation-rehearsal", 0, old));
        }
        // ponytail: public OpenRaft 0.9.25 change_membership commits both stages;
        // joint-stage interruption needs a native library seam, not fabricated SQL state.
        // Interrupt this committed preparation before any offline credential publication.
        running[leader].0.shutdown().await.unwrap();
        running[leader].2.abort();
        assert!((&mut running[leader].2).await.unwrap_err().is_cancelled());
        running[leader] = start(config(leader, Mode::Recover), databases[leader].clone(), old).await.unwrap();
        let recovered = running[leader].1.run(read_transport).await.unwrap().unwrap();
        assert_eq!(recovered.active, credential("rotation-rehearsal", 0, old));
        assert_eq!(recovered.next.as_ref(), Some(&next));
        let recovered_leader = loop {
            let current_leader = running[leader].0.metrics().borrow().current_leader;
            if let Some(id) = current_leader {
                let i = id as usize - 1;
                if matches!(running[i].3.submit(Operation::Ready).await, Outcome::Ready) { break i; }
            }
            tokio::task::yield_now().await;
        };
        let retry_follower = (recovered_leader + 1) % 3;
        running[retry_follower].0.wait(Some(DEADLINE)).current_leader(recovered_leader as u64 + 1, "prepared rotation recovery").await.unwrap();
        assert!(matches!(running[retry_follower].3.submit(Operation::PrepareTransport(next.clone())).await, Outcome::Transport(Ok(s)) if s.active == recovered.active && s.next == recovered.next));
        assert!(matches!(running[retry_follower].3.submit(Operation::CompleteTransport).await, Outcome::Transport(Err(_))));
        for (node, _, _, _) in &running {
            let metrics = node.metrics().borrow().clone();
            assert_eq!(metrics.membership_config.membership().get_joint_config().len(), 1);
            assert_eq!(metrics.membership_config.membership().voter_ids().collect::<std::collections::BTreeSet<_>>(), std::collections::BTreeSet::from([1, 2, 3]));
        }
        // Stop and join EVERY Raft core and private transport before the offline helper.
        for (node, _, task, _) in &running {
            node.shutdown().await.unwrap();
            task.abort();
        }
        for (_, _, task, _) in running.drain(..) {
            assert!(task.await.unwrap_err().is_cancelled());
        }
        let next_key = root.path().join("next.psk");
        publish_transport_config(next_key.to_str().unwrap(), new.to_key_file().as_bytes()).unwrap();
        let mut rotated = Vec::new();
        for i in 0..3 {
            let input = root.path().join(format!("{i}.json"));
            let output = root.path().join(format!("{i}-generation-1.json"));
            publish_transport_config(input.to_str().unwrap(), &serde_json::to_vec(&config(i, Mode::Recover)).unwrap()).unwrap();
            assert!(apply_offline_transport(input.to_str().unwrap(), next_key.to_str().unwrap(), &databases[i], output.to_str().unwrap(), false).is_err());
            apply_offline_transport(input.to_str().unwrap(), next_key.to_str().unwrap(), &databases[i], output.to_str().unwrap(), true).unwrap();
            let selected: Config = serde_json::from_slice(&protected_read(output.to_str().unwrap()).unwrap()).unwrap();
            assert_eq!(selected.transport_generation, 1);
            assert_eq!(selected.cluster_psk.as_deref(), Some(new.to_key_file().as_str()));
            assert_eq!(selected.node_id, i as u64 + 1);
            assert_eq!(crate::raft_network::replica_identity(&identities[i]).unwrap().public().to_peer_id(), keys[i].public().to_peer_id());
            rotated.push(selected);
            // Offline publication must not mutate local credential or application state.
            let mut conn = diesel::SqliteConnection::establish(&databases[i]).unwrap();
            assert_eq!(crate::raft_storage::get::<TransportCredential>(&mut conn, "transport_credential").unwrap().unwrap(), credential("rotation-rehearsal", 0, old));
        }
        let first = rotated.remove(0);
        running.push(start(first, databases[0].clone(), new).await.unwrap());
        assert!(matches!(running[0].3.submit(Operation::CompleteTransport).await, Outcome::Unavailable));
        assert!(!matches!(running[0].3.submit(Operation::Ready).await, Outcome::Ready));
        assert!(!matches!(running[0].3.submit(Operation::PrepareTransport(next.clone())).await, Outcome::Transport(Ok(_))));
        let minority = running[0].1.run(read_transport).await.unwrap().unwrap();
        assert_eq!(minority.active, recovered.active);
        assert_eq!(minority.next, recovered.next, "minority must not complete or mutate preparation");
        for (i, selected) in rotated.into_iter().enumerate() {
            running.push(start(selected, databases[i + 1].clone(), new).await.unwrap());
        }
        let leader = loop {
            if let Some(id) = running.iter().find_map(|r| r.0.metrics().borrow().current_leader) {
                let i = id as usize - 1;
                if running[i].0.ensure_linearizable().await.is_ok() { break i; }
            }
            tokio::task::yield_now().await;
        };
        let follower = (leader + 1) % 3;
        running[follower].0.wait(Some(DEADLINE)).current_leader(leader as u64 + 1, "new-key follower").await.unwrap();
        assert!(matches!(running[follower].3.submit(Operation::CompleteTransport).await, Outcome::Transport(Ok(s)) if s.active == next && s.next.is_none()));
        assert_eq!(invite(&running[leader].0, &running[leader].1, "rotation-preserved-invite".into(), None, Some(3), None).await.unwrap().unwrap(), code);
        for (i, (_, store, _, service)) in running.iter().enumerate() {
            loop {
                if store.run(read_transport).await.unwrap().is_some_and(|s| s.active == next && s.next.is_none()) { break; }
                tokio::task::yield_now().await;
            }
            assert_eq!(service.transport_credential, next);
            assert_eq!(store.run(|conn| {
                Ok(["control_private_key", "control_encryption_private_key", "control_network_id"]
                    .into_iter().map(|key| crate::db::get_setting(conn, key)).collect::<Result<Vec<_>, _>>()?)
            }).await.unwrap(), preserved);
            assert_eq!(store.run(|conn| Ok(crate::db::get_invites(conn)?.len())).await.unwrap(), 1);
            assert!(start(config(i, Mode::Recover), databases[i].clone(), old).await.is_err());
        }
        // ponytail: bounded learner startup/restart; promotion and serving need a separate rehearsal.
        use futures_util::StreamExt;
        use cat4igp_shared::discovery::{transport, join};
        use openraft::storage::RaftStateMachine;
        let authority = match running[follower].3.submit(Operation::Authority).await {
            Outcome::Authority(Ok(authority)) => authority,
            _ => panic!("postrotation authority unavailable"),
        };
        let pin = libp2p::identity::PublicKey::try_decode_protobuf(&crate::hex_decode(&authority.signing_key).unwrap()).unwrap();
        let mut public = transport::swarm(&keys[follower]).unwrap();
        public.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
        let public_address = loop {
            if let libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } = public.select_next_some().await {
                break address.with(libp2p::multiaddr::Protocol::P2p(keys[follower].public().to_peer_id()));
            }
        };
        let now = chrono::Utc::now().timestamp_millis();
        let serving = keys[follower].public().to_peer_id();
        let roster = ControllerRoster { version: 1, cluster_id: "rotation-rehearsal".into(), revision: 1,
            issued_at_ms: now, expires_at_ms: now + 240_000, discovery_endpoints: vec![],
            controllers: vec![cat4igp_shared::discovery::ControllerEndpoint { peer_id: serving, addresses: vec![public_address.clone()] }] };
        assert!(matches!(running[follower].3.submit(Operation::Roster(roster)).await, Outcome::Roster(Ok(()))));
        let discovery_service = running[follower].3.clone();
        let join_service = discovery_service.clone();
        let mut responder = tokio::spawn(async move {
            transport::serve_with_join(public, "rotation-rehearsal", move |query, source| {
                let service = discovery_service.clone();
                async move { match service.submit(Operation::Discovery { query, source, serving }).await {
                    Outcome::Discovery(result) => result, _ => Err("unavailable".into()),
                } }
            }, move |request, source| {
                let service = join_service.clone();
                async move { match service.submit(Operation::Join { source, request }).await {
                    Outcome::Join(result) => result, _ => join::Response::Unavailable,
                } }
            }).await
        });
        let replica_code = match running[follower].3.submit(Operation::ReplicaCode { rotate_generation: None }).await {
            Outcome::ReplicaCode(Ok(code)) => code, _ => panic!("postrotation replica code unavailable"),
        };
        let joining_path = root.path().join("postrotation.key");
        let joining_key = crate::raft_network::replica_identity(&joining_path).unwrap();
        let joining_peer = joining_key.public().to_peer_id();
        let joining_listener = reserve_startup_listener();
        let joining_address: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", joining_listener.local_addr().unwrap().port()).parse().unwrap();
        let request = join::Request { application_version: join::APPLICATION_VERSION,
            cluster_id: "rotation-rehearsal".into(), request_id: "postrotation-join".into(), node_id: 9,
            address: joining_address.clone().with(libp2p::multiaddr::Protocol::P2p(joining_peer)), code: replica_code.code };
        let bootstraps = [public_address];
        let response = tokio::select! {
            result = join::request(&joining_key, &pin, &bootstraps, 1, request.clone()) => result.unwrap(),
            result = &mut responder => panic!("postrotation responder terminated: {result:?}"),
        };
        assert!(matches!(&response, join::Response::Bootstrap { cluster_psk, transport_generation: 1, node_id: 9, peer_id, .. }
            if *cluster_psk == new.to_key_file() && *cluster_psk != old.to_key_file() && *peer_id == joining_peer));
        assert_eq!(join::request(&joining_key, &pin, &bootstraps, 1, request.clone()).await.unwrap(), response);
        let joined_config = root.path().join("postrotation.json");
        save_join(joined_config.to_str().unwrap(), joining_path.to_str().unwrap().into(), joining_address, &request, &response).unwrap();
        let selected: Config = serde_json::from_slice(&protected_read(joined_config.to_str().unwrap()).unwrap()).unwrap();
        assert_eq!(selected.transport_generation, 1);
        assert_eq!(selected.cluster_psk.as_deref(), Some(new.to_key_file().as_str()));
        assert!(running[leader].0.metrics().borrow().membership_config.membership().nodes().all(|(id, _)| *id != 9), "credential delivery must not activate membership");
        responder.abort();
        assert!(responder.await.unwrap_err().is_cancelled());
        let learner_database = root.path().join("postrotation.sqlite").to_str().unwrap().to_owned();
        let mut conn = diesel::SqliteConnection::establish(&learner_database).unwrap();
        crate::db::migrate(&mut conn, true).unwrap();
        drop(conn);
        let config_bytes = protected_read(joined_config.to_str().unwrap()).unwrap();
        let mut reservation = Some(joining_listener);
        let mut retained_applied = None;
        let mut retained_authority = None;
        for restart in 0..3 {
            let mut selected: Config = serde_json::from_slice(&protected_read(joined_config.to_str().unwrap()).unwrap()).unwrap();
            if restart > 0 { selected.mode = Mode::Recover; }
            let psk = selected.cluster_psk.as_ref().unwrap().parse().unwrap();
            assert_eq!(crate::raft_network::replica_identity(&joining_path).unwrap().public().to_peer_id(), joining_peer);
            let (node, mut store, task, service) = start_inner(selected, learner_database.clone(), psk, reservation.take()).await.unwrap();
            if restart < 2 {
                node.wait(Some(DEADLINE)).state(openraft::ServerState::Learner, "pristine postrotation learner").await.unwrap();
                assert!(node.metrics().borrow().current_leader.is_none());
                assert!(node.metrics().borrow().membership_config.membership().nodes().next().is_none());
                assert!(store.applied_state().await.unwrap().0.is_none());
                assert!(store.run(read_transport).await.unwrap().is_none());
                assert_eq!(service.transport_credential, next);
                assert!(!matches!(service.submit(Operation::Ready).await, Outcome::Ready));
                assert!(matches!(service.submit(Operation::Authority).await, Outcome::Unavailable));
                assert!(matches!(service.submit(Operation::Invite { request_id: "pristine-no-write".into(), expires_at: None, max_uses: Some(1), join_mesh: None }).await, Outcome::Unavailable));
                assert!(store.run(|conn| {
                    use diesel::OptionalExtension;
                    Ok(crate::db::get_invites(conn)?.is_empty()
                    && ["control_private_key", "control_encryption_private_key", "control_network_id", "controller_roster", "controller_admitted"]
                        .into_iter().map(|key| crate::db::get_setting(conn, key).optional()).collect::<Result<Vec<_>, _>>()?.iter().all(Option::is_none))
                }).await.unwrap());
            }
            if restart == 0 {
                node.shutdown().await.unwrap();
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
                drop(service);
                drop(store);
                for (generation, rejected_psk) in [(0, new), (2, new), (1, old)] {
                    let mut rejected: Config = serde_json::from_slice(&config_bytes).unwrap();
                    rejected.mode = Mode::Recover;
                    rejected.transport_generation = generation;
                    assert!(start(rejected, learner_database.clone(), rejected_psk).await.is_err(), "pristine recovery must reject changed generation/PSK");
                    let mut reopened = Store::open(learner_database.clone()).await.unwrap();
                    assert_eq!(reopened.run(|conn| crate::raft_storage::get::<TransportCredential>(conn, "transport_credential")).await.unwrap(), Some(next.clone()));
                    assert!(reopened.applied_state().await.unwrap().0.is_none());
                    assert!(reopened.run(read_transport).await.unwrap().is_none());
                }
                assert_eq!(protected_read(joined_config.to_str().unwrap()).unwrap(), config_bytes);
                continue;
            } else if restart == 1 {
                assert!(matches!(running[follower].3.submit(Operation::ActivateLearner(9)).await, Outcome::Learner(Ok(()))));
            } else {
                assert!(store.applied_state().await.unwrap().0.unwrap().index >= retained_applied.unwrap());
            }
            let index = running[leader].0.metrics().borrow().last_applied.unwrap().index;
            node.wait(Some(DEADLINE)).applied_index(Some(index), "postrotation learner catchup/restart").await.unwrap();
            node.wait(Some(DEADLINE)).state(openraft::ServerState::Learner, "postrotation remains learner").await.unwrap();
            let metrics = node.metrics().borrow().clone();
            assert_eq!(metrics.membership_config.membership().get_joint_config().len(), 1);
            assert_eq!(metrics.membership_config.membership().voter_ids().collect::<std::collections::BTreeSet<_>>(), std::collections::BTreeSet::from([1, 2, 3]));
            assert!(metrics.membership_config.membership().nodes().any(|(id, _)| *id == 9));
            let learned = store.run(read_authority).await.unwrap();
            assert_eq!(learned.signing_key, authority.signing_key);
            assert_eq!(learned.encryption_key, authority.encryption_key);
            assert_eq!(learned.network_id, authority.network_id);
            let roster = learned.roster.as_ref().unwrap();
            assert!(!roster.body.controllers.iter().chain(&roster.body.discovery_endpoints).any(|e| e.peer_id == joining_peer));
            let learned = serde_json::to_vec(&learned).unwrap();
            if let Some(retained) = &retained_authority { assert_eq!(&learned, retained); }
            retained_authority = Some(learned);
            assert_eq!(store.run(|conn| {
                Ok(["control_private_key", "control_encryption_private_key", "control_network_id"]
                    .into_iter().map(|key| crate::db::get_setting(conn, key)).collect::<Result<Vec<_>, _>>()?)
            }).await.unwrap(), preserved);
            assert_eq!(store.run(|conn| Ok(crate::db::get_invites(conn)?.len())).await.unwrap(), 1);
            let rotation = store.run(read_transport).await.unwrap().unwrap();
            assert_eq!(rotation.active, next);
            assert!(rotation.next.is_none());
            assert_eq!(service.transport_credential, next);
            retained_applied = Some(store.applied_state().await.unwrap().0.unwrap().index);
            node.shutdown().await.unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            drop(service);
            drop(store);
            assert_eq!(protected_read(joined_config.to_str().unwrap()).unwrap(), config_bytes);
        }
        // ponytail: actual private enrollment/retry, not daemon restart or response-loss injection.
        use cat4igp_shared::control::{ControlRequest, ControlResponse};
        let client_code = match running[follower].3.submit(Operation::Invite {
            request_id: "postrotation-client-invite".into(), expires_at: None, max_uses: Some(1), join_mesh: None,
        }).await {
            Outcome::Invite(Ok(code)) => code, other => panic!("{other:?}"),
        };
        assert_ne!(client_code, code);
        let client_path = root.path().join("postrotation-client.key");
        let client_key = crate::raft_network::replica_identity(&client_path).unwrap();
        let principal = client_key.public().to_peer_id();
        let client_secret = x25519_dalek::StaticSecret::from([7; 32]);
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let private_address = format!("/ip4/127.0.0.1/tcp/{}", socket.local_addr().unwrap().port());
        let endpoint = format!("{private_address}/p2p/{serving}");
        let mut roster = running[follower].1.run(read_authority).await.unwrap().roster.unwrap().body;
        roster.revision += 1;
        roster.issued_at_ms = chrono::Utc::now().timestamp_millis();
        roster.expires_at_ms += 60_000;
        roster.controllers[0].addresses = vec![endpoint.parse().unwrap()];
        roster.discovery_endpoints = vec![cat4igp_shared::discovery::ControllerEndpoint { peer_id: serving, addresses: bootstraps.to_vec() }];
        let committed = running[follower].3.submit(Operation::Roster(roster)).await;
        assert!(matches!(committed, Outcome::Roster(Ok(()))), "{committed:?}");
        let mut client = crate::client_config::ServerConfig::new(endpoint.clone(), client_code.clone());
        client.controller_peer_id = Some(pin.to_peer_id().to_string());
        client.controller_signing_key = Some(authority.signing_key.clone());
        client.controller_encryption_key = Some(authority.encryption_key.clone());
        client.control_network_id = authority.network_id.clone();
        let client_psk = libp2p::pnet::PreSharedKey::new([0x12; 32]);
        assert_ne!(client_psk.to_key_file(), new.to_key_file());
        client.control_private_network_key = Some(client_psk.to_key_file());
        client.control_private_key = Some(crate::hex_encode(&client_key.to_protobuf_encoding().unwrap()));
        client.control_encryption_private_key = Some(crate::hex_encode(&client_secret.to_bytes()));
        client.ensure_wireguard_keypair().unwrap();
        client.discovery_proof = Some(match running[follower].3.submit(Operation::Discovery {
            query: cat4igp_shared::discovery::FindControllers::new(authority.network_id.clone(), cat4igp_shared::discovery::Role::Client, principal, chrono::Utc::now().timestamp_millis()).unwrap(),
            source: principal, serving,
        }).await { Outcome::Discovery(Ok(proof)) => proof, other => panic!("{other:?}") });
        assert!(client.control_peer_authorized(serving, chrono::Utc::now().timestamp_millis()));
        let pending_directory = root.path().join("postrotation-client");
        client.save(&pending_directory).unwrap();
        let pending = serde_json::to_value(&client).unwrap();
        let listener_service = running[follower].3.clone();
        let listener_key = keys[follower].clone();
        drop(socket);
        let listener = tokio::spawn(async move { private_control_at(listener_service, listener_key, &private_address, client_psk).await });
        let original = match crate::client_control::enroll(&mut client, &[endpoint.clone()], "postrotation-client".into()).await.unwrap() {
            ControlResponse::Enrolled(response) => response,
            other => panic!("{other:?}"),
        };
        assert_eq!(crate::raft_network::replica_identity(&client_path).unwrap().public().to_peer_id(), principal);
        client = crate::client_config::ServerConfig::load(&pending_directory).unwrap();
        assert_eq!(serde_json::to_value(&client).unwrap(), pending);
        assert!(matches!(crate::client_control::enroll(&mut client, &[endpoint], "postrotation-client".into()).await.unwrap(),
            ControlResponse::Enrolled(response) if serde_json::to_value(&response).unwrap() == serde_json::to_value(&original).unwrap()));
        let after = serde_json::to_value(&client).unwrap();
        for field in ["control_private_network_key", "controller_peer_id", "controller_signing_key", "control_private_key", "control_encryption_private_key", "wg_private_key", "wg_public_key", "discovery_proof"] {
            assert_eq!(after[field], pending[field], "changed {field}");
        }
        listener.abort();
        assert!(listener.await.unwrap_err().is_cancelled());
        assert_eq!(running[leader].1.run(move |conn| {
            let invites = crate::db::get_invites(conn)?;
            Ok((invites.len(), invites.iter().find(|i| i.code == client_code).unwrap().used_count,
                invites.iter().find(|i| i.code == code).unwrap().used_count))
        }).await.unwrap(), (2, 1, 0));
        let envelope = match running[follower].3.submit(Operation::Client {
            principal, serving, request: ControlRequest::Snapshot,
        }).await {
            Outcome::Client(ControlResponse::SnapshotEnvelope(envelope)) => envelope,
            other => panic!("{other:?}"),
        };
        cat4igp_shared::control::open_topology_snapshot(
            &authority.signing_key, &crate::hex_encode(&client_secret.to_bytes()),
            &authority.network_id, original.node_id, chrono::Utc::now().timestamp_millis(), &envelope,
        ).unwrap();
        let unchanged = running[leader].1.run(read_authority).await.unwrap();
        assert_eq!(unchanged.signing_key, authority.signing_key);
        assert_eq!(unchanged.encryption_key, authority.encryption_key);
        assert_eq!(unchanged.network_id, authority.network_id);
        // Same admitted identity/NodeId and cluster: only the obsolete pnet PSK differs.
        let bindings = (0..3).map(|i| (i as u64 + 1, Binding {
            peer: keys[i].public().to_peer_id(), address: addresses[i].clone(),
        })).collect();
        let (obsolete, _, obsolete_attach, obsolete_task) = Network::start(1, "rotation-rehearsal".into(), keys[0].clone(), old, bindings, "/ip4/127.0.0.1/tcp/0".parse().unwrap()).await.unwrap();
        obsolete_attach.send_replace(Some(running[0].0.clone()));
        assert!(matches!(obsolete.forward(2, Operation::Authority).await, Outcome::Unavailable));
        assert!(!obsolete_task.is_finished(), "obsolete transport must be live during rejection probe");
        obsolete_task.abort();
        assert!(obsolete_task.await.unwrap_err().is_cancelled());
        assert!(matches!(running[follower].3.submit(Operation::Authority).await, Outcome::Authority(Ok(_))));
        for (node, _, task, _) in &running { node.shutdown().await.unwrap(); task.abort(); }
        for (_, _, task, _) in running { assert!(task.await.unwrap_err().is_cancelled()); }
    }).await.expect("bounded three-node rotation rehearsal");
}

#[test]
fn maintenance_transport_validation_and_protected_publication() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite");
    let mut conn = diesel::SqliteConnection::establish(path.to_str().unwrap()).unwrap();
    crate::db::migrate(&mut conn, true).unwrap();
    setting(&mut conn, "control_network_id", "maintenance").unwrap();
    let old = credential("maintenance", 0, libp2p::pnet::PreSharedKey::new([1; 32]));
    let next = credential("maintenance", 1, libp2p::pnet::PreSharedKey::new([2; 32]));
    validate_transport(&mut conn, &old, false).unwrap();
    assert!(
        apply_transport(&mut conn, &old, &next, true)
            .unwrap()
            .is_err()
    );
    assert!(
        apply_transport(&mut conn, &old, &next, false)
            .unwrap()
            .is_ok()
    );
    assert!(
        apply_transport(&mut conn, &old, &next, false)
            .unwrap()
            .is_ok()
    );
    let wrong = credential("other", 1, libp2p::pnet::PreSharedKey::new([2; 32]));
    assert!(
        apply_transport(&mut conn, &old, &wrong, false)
            .unwrap()
            .is_err()
    );
    assert!(validate_transport(&mut conn, &wrong, false).is_err());
    let wrong_key = credential("maintenance", 1, libp2p::pnet::PreSharedKey::new([3; 32]));
    assert!(
        apply_transport(&mut conn, &old, &wrong_key, false)
            .unwrap()
            .is_err()
    );
    assert!(validate_transport(&mut conn, &wrong_key, false).is_err());
    validate_transport(&mut conn, &old, false).unwrap(); // preparation never invalidates running old key
    drop(conn);
    let mut conn = diesel::SqliteConnection::establish(path.to_str().unwrap()).unwrap();
    validate_transport(&mut conn, &next, false).unwrap(); // explicit restart selection
    assert!(validate_transport(&mut conn, &old, false).is_err()); // persisted local anti-rollback
    assert!(
        apply_transport(&mut conn, &old, &next, true)
            .unwrap()
            .is_ok()
    );
    assert!(
        apply_transport(&mut conn, &old, &next, true)
            .unwrap()
            .is_ok()
    );
    assert!(
        apply_transport(&mut conn, &old, &next, false)
            .unwrap()
            .is_err()
    );
    assert!(validate_transport(&mut conn, &old, false).is_err());
    let secret = dir.path().join("generation-1.json");
    publish_transport_config(secret.to_str().unwrap(), b"protected").unwrap();
    assert_eq!(
        std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        protected_read(secret.to_str().unwrap()).unwrap(),
        b"protected"
    );
    assert!(publish_transport_config(secret.to_str().unwrap(), b"replacement").is_err());
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(protected_read(secret.to_str().unwrap()).is_err());
}
use super::*;
use diesel::Connection;

#[test]
fn roster_renewal_clock_boundaries() {
    let roster = ControllerRoster {
        version: 1,
        cluster_id: "clock".into(),
        revision: 7,
        issued_at_ms: 1000,
        expires_at_ms: 241_000,
        controllers: vec![],
        discovery_endpoints: vec![],
    };
    assert!(renewed_roster(&roster, 999).is_none());
    assert!(renewed_roster(&roster, 180_999).is_none());
    let renewed = renewed_roster(&roster, 181_000).unwrap();
    assert_eq!(renewed.revision, 8);
    assert_eq!(renewed.expires_at_ms, 421_000);
    assert!(renewed_roster(&renewed, 181_000).is_none());
    // Restart/new leader reconciles an already expired lease, not a local extension.
    assert_eq!(
        renewed_roster(&roster, 500_000).unwrap().issued_at_ms,
        500_000
    );
    assert!(renewed_roster(&roster, i64::MAX).is_none());
    assert!(
        renewed_roster(
            &ControllerRoster {
                revision: u64::MAX,
                ..roster
            },
            181_000
        )
        .is_none()
    );
}

#[test]
fn replica_code_expiry_and_deterministic_rotation() {
    let mut conn = diesel::SqliteConnection::establish(":memory:").unwrap();
    crate::db::migrate(&mut conn, true).unwrap();
    let first = CodeRotation {
        expected_generation: 0,
        code: "ab".repeat(32),
        activated_at_ms: 1000,
        expires_at_ms: 1000 + CODE_LIFETIME_MS,
    };
    assert!(apply_code_rotation(&mut conn, &first).unwrap().is_ok());
    let state = read_code(&mut conn).unwrap().unwrap();
    assert!(valid_code(&state, &first.code, 1000));
    assert!(!valid_code(&state, &first.code, 999));
    assert!(!valid_code(&state, &first.code, first.expires_at_ms));
    assert!(!valid_code(&state, "client-invite", 1000));
    let second = CodeRotation {
        expected_generation: 1,
        code: "cd".repeat(32),
        activated_at_ms: first.expires_at_ms + CODE_GRACE_MS + 1,
        expires_at_ms: first.expires_at_ms + CODE_GRACE_MS + 1 + CODE_LIFETIME_MS,
    };
    assert!(apply_code_rotation(&mut conn, &second).unwrap().is_ok());
    let state = read_code(&mut conn).unwrap().unwrap();
    assert!(!valid_code(&state, &first.code, second.activated_at_ms));
    assert!(apply_code_rotation(&mut conn, &second).unwrap().is_ok());
    assert_eq!(read_code(&mut conn).unwrap().unwrap().generation, 2);
    let third = CodeRotation {
        expected_generation: 2,
        code: "ef".repeat(32),
        activated_at_ms: second.activated_at_ms + 1000,
        expires_at_ms: second.activated_at_ms + 1000 + CODE_LIFETIME_MS,
    };
    assert!(apply_code_rotation(&mut conn, &third).unwrap().is_ok());
    let state = read_code(&mut conn).unwrap().unwrap();
    assert!(valid_code(
        &state,
        &second.code,
        third.activated_at_ms + CODE_GRACE_MS - 1
    ));
    assert!(!valid_code(
        &state,
        &second.code,
        third.activated_at_ms + CODE_GRACE_MS
    ));
    assert!(!valid_code(&state, &first.code, third.activated_at_ms));
    assert!(!format!("{third:?}").contains(&third.code));
}

#[tokio::test]
async fn follower_retry_failover_and_minority() {
    follower_retry_rehearsal(false).await;
}

#[tokio::test]
async fn joint_removal_surviving_leader_authority() {
    follower_retry_rehearsal(true).await;
}

async fn expect_rejection(
    services: &[Service],
    nodes: &[Node],
    source: usize,
    operation: Operation,
    rejected: fn(&Outcome) -> bool,
    stage: &str,
) {
    // ponytail: quorum-ready negative checks retry only Unavailable under the
    // existing deadline; successful unauthorized operations always fail.
    let mut diagnostic = String::new();
    let result = tokio::time::timeout(DEADLINE, async {
        loop {
            let before: Vec<_> = nodes.iter().map(|n| n.metrics().borrow().clone()).collect();
            let outcome = services[source].submit(operation.clone()).await;
            let busy: Vec<_> = services.iter().map(|s| s.allocation.try_lock().is_err()).collect();
            let ready = services[source].submit(Operation::Ready).await;
            diagnostic = format!("{stage}: {outcome:?}; ready={ready:?}; allocation_busy={busy:?}; before={before:?}; after={:?}", nodes.iter().map(|n| n.metrics().borrow().clone()).collect::<Vec<_>>());
            if rejected(&outcome) { return; }
            assert!(matches!(outcome, Outcome::Unavailable), "{diagnostic}");
            eprintln!("transient negative assertion: {diagnostic}");
            tokio::task::yield_now().await;
        }
    }).await;
    assert!(result.is_ok(), "rejection deadline: {diagnostic}");
}

async fn follower_retry_rehearsal(surviving_election: bool) {
    tokio::time::timeout(Duration::from_secs(90), async {
        let root = std::env::temp_dir().join(format!("cat4igp-forward-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let listeners: Vec<_> = (0..3).map(|_| reserve_startup_listener()).collect();
        let addresses: Vec<libp2p::Multiaddr> = listeners.iter().map(|l| format!("/ip4/127.0.0.1/tcp/{}", l.local_addr().unwrap().port()).parse().unwrap()).collect();
        let identities: Vec<_> = (0..3).map(|i| root.join(format!("{i}.key"))).collect();
        let keys: Vec<_> = identities.iter().map(|p| crate::raft_network::replica_identity(p).unwrap()).collect();
        let mut nodes = Vec::new();
        let mut stores = Vec::new();
        let mut transports = Vec::new();
        let mut services = Vec::new();
        for (i, listener) in listeners.into_iter().enumerate() {
            let database = root.join(format!("{i}.sqlite")).to_str().unwrap().to_owned();
            let mut conn = diesel::SqliteConnection::establish(&database).unwrap();
            crate::db::migrate(&mut conn, true).unwrap();
            drop(conn);
            let config = Config {
                learner: None, cluster_psk: None, transport_generation: 0, legacy_import: None,
                cluster_id: "forward-test".into(), node_id: i as u64 + 1,
                mode: if i == 2 { Mode::Initialize } else { Mode::Join },
                identity_file: identities[i].to_str().unwrap().into(), listen: addresses[i].clone(),
                replicas: (0..3).map(|j| (j as u64 + 1, Replica { peer_id: keys[j].public().to_peer_id(), address: addresses[j].clone() })).collect(),
            };
            let (node, store, task, service) = start_inner(config, database, libp2p::pnet::PreSharedKey::new([19; 32]), Some(listener)).await.unwrap();
            nodes.push(node); stores.push(store); transports.push(task); services.push(service);
        }
        let mut leader = loop {
            if let Some(id) = nodes.iter().find_map(|n| n.metrics().borrow().current_leader) { break id as usize - 1; }
            tokio::task::yield_now().await;
        };
        let follower = (leader + 1) % 3;
        nodes[follower].wait(Some(DEADLINE)).current_leader(leader as u64 + 1, "follower learns leader").await.unwrap();
        let initial = match services[follower].submit(Operation::Authority).await { Outcome::Authority(Ok(a)) => a, other => panic!("{other:?}") };
        // Recover a committed deadline, not a fresh per-process timer. No operator
        // retrieval triggers this rotation: the running leader scheduler must do it.
        let expiry = chrono::Utc::now().timestamp_millis() + 1000;
        nodes[leader].client_write(Command::ReplicaCode(CodeRotation {
            expected_generation: 0, code: "ab".repeat(32),
            activated_at_ms: expiry - CODE_LIFETIME_MS, expires_at_ms: expiry,
        })).await.unwrap().data.unwrap();
        let schedulers: Vec<_> = services.iter().cloned().map(|service| tokio::spawn(async move { service.schedule_codes().await })).collect();
        let mut ticker = tokio::time::interval(Duration::from_millis(50));
        let code = loop {
            ticker.tick().await;
            if let Some(code) = stores[leader].run(read_code).await.unwrap() {
                if code.generation == 2 { break code; }
            }
        };
        assert!(code.activated_at_ms >= expiry);
        let shared = match services[leader].submit(Operation::ReplicaCode { rotate_generation: None }).await { Outcome::ReplicaCode(Ok(c)) => c, _ => panic!("code unavailable") };
        assert!(code == shared);
        assert!(matches!(services[follower].submit(Operation::VerifyReplicaCode(code.code.clone())).await, Outcome::VerifiedReplicaCode(true)));
        assert!(matches!(services[follower].submit(Operation::VerifyReplicaCode("01".repeat(32))).await, Outcome::VerifiedReplicaCode(false)));
        let rotated = match services[follower].submit(Operation::ReplicaCode { rotate_generation: Some(code.generation) }).await { Outcome::ReplicaCode(Ok(c)) => c, _ => panic!("rotation unavailable") };
        assert_eq!(rotated.generation, code.generation + 1);
        assert!(matches!(services[follower].submit(Operation::VerifyReplicaCode(code.code.clone())).await, Outcome::VerifiedReplicaCode(true)));
        let retried = match services[follower].submit(Operation::ReplicaCode { rotate_generation: Some(code.generation) }).await { Outcome::ReplicaCode(Ok(c)) => c, _ => panic!("retry unavailable") };
        assert!(retried == rotated);
        assert!(!keys.iter().any(|k| crate::hex_encode(&k.public().encode_protobuf()) == initial.signing_key));
        use futures_util::StreamExt;
        use cat4igp_shared::discovery::{transport, FindControllers, Role};
        let pin = libp2p::identity::PublicKey::try_decode_protobuf(&crate::hex_decode(&initial.signing_key).unwrap()).unwrap();
        let requester = libp2p::identity::Keypair::generate_ed25519();
        let mut public = transport::swarm(&keys[follower]).unwrap();
        public.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
        let public_address = loop {
            if let libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } = public.select_next_some().await {
                break address.with(libp2p::multiaddr::Protocol::P2p(keys[follower].public().to_peer_id()));
            }
        };
        let discovery_service = services[follower].clone();
        let join_service = discovery_service.clone();
        let serving = keys[follower].public().to_peer_id();
        let responder = tokio::spawn(async move {
            transport::serve_with_join(public, "forward-test", move |query, source| {
                let service = discovery_service.clone();
                async move {
                    match service.submit(Operation::Discovery { query, source, serving }).await {
                        Outcome::Discovery(result) => result,
                        _ => Err("unavailable".into()),
                    }
                }
            }, move |request, source| {
                let service = join_service.clone();
                async move {
                    match service.submit(Operation::Join { source, request }).await {
                        Outcome::Join(result) => result,
                        _ => cat4igp_shared::discovery::join::Response::Unavailable,
                    }
                }
            }).await
        });
        let now = chrono::Utc::now().timestamp_millis();
        let mut roster = ControllerRoster { version: 1, cluster_id: "forward-test".into(), revision: 1, issued_at_ms: now, expires_at_ms: now + 240_000, discovery_endpoints: vec![],
            controllers: (0..3).map(|i| cat4igp_shared::discovery::ControllerEndpoint { peer_id: keys[i].public().to_peer_id(), addresses: vec![addresses[i].clone().with(libp2p::multiaddr::Protocol::P2p(keys[i].public().to_peer_id()))] }).collect() };
        roster.controllers[follower].addresses = vec![public_address.clone()];
        assert!(matches!(services[follower].submit(Operation::Roster(roster.clone())).await, Outcome::Roster(Ok(()))));
        let proof = transport::discover(&requester, &pin, "forward-test", Role::Client, &[public_address.clone()], 1).await.unwrap();
        assert_eq!(proof.body.endpoint.peer_id, serving);
        assert_ne!(serving, pin.to_peer_id());
        assert_eq!(proof.body.roster.body.revision, 1);
        use cat4igp_shared::discovery::join::{self, Request as JoinRequest, Response as JoinResponse};
        let join_key = crate::raft_network::replica_identity(&root.join("joining.key")).unwrap();
        let join_peer = join_key.public().to_peer_id();
        let join_socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let join_port = join_socket.local_addr().unwrap().port();
        drop(join_socket);
        let join_request = JoinRequest {
            application_version: cat4igp_shared::discovery::join::APPLICATION_VERSION,
            cluster_id: "forward-test".into(), request_id: "durable-join-1".into(), node_id: 9,
            address: format!("/ip4/127.0.0.1/tcp/{join_port}/p2p/{join_peer}").parse().unwrap(),
            code: rotated.code.clone(),
        };
        let mut incompatible = join_request.clone();
        incompatible.application_version = 2;
        let before = stores[leader].run(|conn| Ok(crate::db::get_setting(conn, "replica_pending_admissions").ok())).await.unwrap();
        assert!(matches!(services[leader].submit(Operation::Join { source: join_peer, request: incompatible }).await, Outcome::Join(JoinResponse::Rejected)));
        assert_eq!(stores[leader].run(|conn| Ok(crate::db::get_setting(conn, "replica_pending_admissions").ok())).await.unwrap(), before);
        let mut missing = serde_json::to_value(&join_request).unwrap();
        missing.as_object_mut().unwrap().remove("application_version");
        assert!(serde_json::from_value::<JoinRequest>(missing).is_err());
        let pending = join::request(&join_key, &pin, &[public_address.clone()], 1, join_request.clone()).await.unwrap();
        assert!(matches!(&pending, JoinResponse::Bootstrap { request_id, node_id: 9, peer_id, cluster_id, cluster_psk, .. } if request_id == "durable-join-1" && *peer_id == join_peer && cluster_id == "forward-test" && *cluster_psk == libp2p::pnet::PreSharedKey::new([19; 32]).to_key_file()));
        assert!(!format!("{pending:?}").contains(&"13".repeat(32)));
        let mut substituted = pending.clone();
        if let JoinResponse::Bootstrap { peer_id, .. } = &mut substituted { *peer_id = pin.to_peer_id(); }
        assert!(substituted.validate(&join_request, join_peer).is_err());
        let mut malformed = pending.clone();
        if let JoinResponse::Bootstrap { cluster_psk, .. } = &mut malformed { *cluster_psk = "é".repeat(64); }
        assert!(malformed.validate(&join_request, join_peer).is_err());
        let mut wrong_cluster = pending.clone();
        if let JoinResponse::Bootstrap { cluster_id, .. } = &mut wrong_cluster { *cluster_id = "other".into(); }
        assert!(wrong_cluster.validate(&join_request, join_peer).is_err());
        let reopened_key = crate::raft_network::replica_identity(&root.join("joining.key")).unwrap();
        assert_eq!(join::request(&reopened_key, &pin, &[public_address.clone()], 1, join_request.clone()).await.unwrap(), pending);
        let wrong_key = libp2p::identity::Keypair::generate_ed25519();
        let wrong_peer = wrong_key.public().to_peer_id();
        let mut stolen = join_request.clone();
        stolen.address = format!("/ip4/127.0.0.1/tcp/19009/p2p/{wrong_peer}").parse().unwrap();
        assert_eq!(join::request(&wrong_key, &pin, &[public_address.clone()], 1, stolen.clone()).await.unwrap(), JoinResponse::Rejected);
        assert!(matches!(services[follower].submit(Operation::Join { source: wrong_peer, request: stolen }).await, Outcome::Join(JoinResponse::Rejected)));
        let mut conflict = join_request.clone(); conflict.node_id = 10;
        assert!(matches!(services[follower].submit(Operation::Join { source: join_peer, request: conflict }).await, Outcome::Join(JoinResponse::Rejected)));
        let mut invalid = join_request.clone(); invalid.request_id = "bad-code".into(); invalid.node_id = 11;
        invalid.address = format!("/ip4/127.0.0.1/tcp/19011/p2p/{wrong_peer}").parse().unwrap(); invalid.code = "01".repeat(32);
        assert_eq!(join::request(&wrong_key, &pin, &[public_address.clone()], 1, invalid.clone()).await.unwrap(), JoinResponse::Rejected);
        assert!(matches!(services[follower].submit(Operation::Join { source: wrong_peer, request: invalid }).await, Outcome::Join(JoinResponse::Rejected)));
        let mut expired = join_request.clone(); expired.request_id = "expired-code".into(); expired.node_id = 12;
        expired.address = format!("/ip4/127.0.0.1/tcp/19012/p2p/{wrong_peer}").parse().unwrap();
        let expired_reply = nodes[leader].client_write(Command::Admission(Admission {
            source: wrong_peer, request: expired, at_ms: rotated.expires_at_ms,
        })).await.unwrap();
        assert_eq!(expired_reply.data.unwrap_err(), "invalid or expired replica code");
        let admission_index = nodes[leader].metrics().borrow().last_applied.unwrap().index;
        nodes[follower].wait(Some(DEADLINE)).applied_index(Some(admission_index), "pending admission replicated").await.unwrap();
        let durable = stores[follower].run(|conn| Ok(crate::db::get_setting(conn, "replica_pending_admissions")?)).await.unwrap();
        assert_eq!(serde_json::from_str::<Vec<Admission>>(&durable).unwrap().len(), 1);
        let reopened = Store::open(root.join(format!("{follower}.sqlite")).to_str().unwrap().into()).await.unwrap();
        assert_eq!(reopened.run(|conn| Ok(crate::db::get_setting(conn, "replica_pending_admissions")?)).await.unwrap(), durable);
        assert!(!nodes[leader].metrics().borrow().membership_config.membership().nodes().any(|(id, _)| *id == 9));
        // Expiry does not erase a committed retry identity, and does not grant membership.
        nodes[leader].client_write(Command::Admission(Admission {
            source: join_peer, request: join_request.clone(), at_ms: rotated.expires_at_ms,
        })).await.unwrap().data.unwrap();
        // Use the actual direct Noise reply, secure local config, and production startup.
        let fourth_path = root.join("learner.sqlite").to_str().unwrap().to_owned();
        let mut conn = diesel::SqliteConnection::establish(&fourth_path).unwrap();
        crate::db::migrate(&mut conn, true).unwrap(); drop(conn);
        let config_path = root.join("learner.json");
        let persist = || save_join(config_path.to_str().unwrap(), root.join("joining.key").to_str().unwrap().into(), format!("/ip4/127.0.0.1/tcp/{join_port}").parse().unwrap(), &join_request, &pending);
        persist().unwrap(); persist().unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&config_path).unwrap().permissions().mode() & 0o777, 0o600);
        let config: Config = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
        let psk = config.cluster_psk.as_ref().unwrap().parse().unwrap();
        let grant = ServingGrant {
            node_id: 9,
            public_address: format!("/ip4/127.0.0.1/tcp/19090/p2p/{join_peer}").parse().unwrap(),
            control_address: format!("/ip4/127.0.0.1/tcp/19091/p2p/{join_peer}").parse().unwrap(),
        };
        assert!(matches!(services[follower].submit(Operation::GrantServing(grant.clone())).await, Outcome::Roster(Err(_))));
        let mut unknown_grant = grant.clone(); unknown_grant.node_id = 99;
        assert!(matches!(services[follower].submit(Operation::GrantServing(unknown_grant)).await, Outcome::Roster(Err(_))));
        assert!(matches!(services[follower].submit(Operation::PromoteLearner(9)).await, Outcome::Promotion(Err(_))));
        assert!(matches!(services[follower].submit(Operation::ActivateLearner(9)).await, Outcome::Learner(Ok(()))));
        expect_rejection(&services, &nodes, follower, Operation::PromoteLearner(9),
            |outcome| matches!(outcome, Outcome::Promotion(Err(error)) if error == "learner has not caught up"),
            "unstarted learner promotion").await;
        assert!(matches!(services[follower].submit(Operation::GrantServing(grant.clone())).await, Outcome::Roster(Err(_))));
        let (fourth_node, fourth_store, fourth_task, fourth_service) = start(config, fourth_path.clone(), psk).await.unwrap();
        assert!(matches!(services[follower].submit(Operation::PromoteLearner(99)).await, Outcome::Promotion(Err(_))));
        assert!(matches!(services[follower].submit(Operation::ActivateLearner(99)).await, Outcome::Learner(Err(_))));
        assert!(matches!(services[follower].submit(Operation::ActivateLearner(9)).await, Outcome::Learner(Ok(()))));
        assert!(matches!(services[follower].submit(Operation::ActivateLearner(9)).await, Outcome::Learner(Ok(()))));
        let learner_index = nodes[leader].metrics().borrow().last_applied.unwrap().index;
        fourth_node.wait(Some(DEADLINE)).applied_index(Some(learner_index), "fourth learner caught up").await.unwrap();
        assert!(!nodes[leader].metrics().borrow().membership_config.membership().voter_ids().any(|id| id == 9));
        assert_eq!(fourth_store.run(read_authority).await.unwrap().signing_key, initial.signing_key);
        // ponytail: connection-local uniform-log abort, not process/powerloss
        // or competing-leader recovery; keep native consensus untouched.
        async fn interrupt_uniform(store: &Store) {
            store.run(|conn| {
                use diesel::connection::SimpleConnection;
                conn.batch_execute("CREATE TEMP TRIGGER interrupt_uniform BEFORE INSERT ON raft_logs
                    WHEN json_array_length((SELECT value FROM raft_meta WHERE key = 'membership'), '$.membership.configs') = 2
                     AND json_array_length(NEW.value, '$.payload.Membership.configs') = 1
                    BEGIN SELECT RAISE(ABORT, 'interrupted uniform membership'); END;")?;
                Ok(())
            }).await.unwrap();
        }
        use openraft::storage::RaftLogStorage;
        for node in &nodes { node.runtime_config().elect(false); }
        fourth_node.runtime_config().elect(false);
        interrupt_uniform(&stores[leader]).await;
        let interrupted = services[leader].submit(Operation::PromoteLearner(9)).await;
        assert!(matches!(interrupted, Outcome::Unavailable), "{interrupted:?}");
        let joint = stores[leader].clone().applied_state().await.unwrap();
        assert_eq!(joint.1.membership().get_joint_config(), &vec![
            std::collections::BTreeSet::from([1, 2, 3]),
            std::collections::BTreeSet::from([1, 2, 3, 9]),
        ]);
        let joint_index = joint.1.log_id().unwrap().index;
        assert_eq!(joint.0.unwrap().index, joint_index);
        assert_eq!(stores[leader].clone().get_log_state().await.unwrap().last_log_id, joint.0);
        for (node, store) in nodes.iter().zip(&stores).filter(|(n, _)| n.metrics().borrow().id != leader as u64 + 1)
            .chain(std::iter::once((&fourth_node, &fourth_store))) {
            node.wait(Some(DEADLINE)).applied_index(Some(joint_index), "joint promotion committed before recovery").await.unwrap();
            assert_eq!(store.clone().applied_state().await.unwrap().1, joint.1);
        }
        assert!(!fourth_store.run(read_authority).await.unwrap().roster.unwrap().body.controllers.iter().any(|e| e.peer_id == join_peer));
        // Fatal storage failure stops the writer. The new connection has no TEMP
        // trigger; same durable DB/identity recovers without rewriting membership.
        schedulers[leader].abort();
        nodes[leader].shutdown().await.unwrap();
        transports[leader].abort(); let _ = (&mut transports[leader]).await;
        let recover = Config {
            learner: None, cluster_psk: None, transport_generation: 0, legacy_import: None,
            cluster_id: "forward-test".into(), node_id: leader as u64 + 1, mode: Mode::Recover,
            identity_file: identities[leader].to_str().unwrap().into(), listen: addresses[leader].clone(),
            replicas: (0..3).map(|j| (j as u64 + 1, Replica { peer_id: keys[j].public().to_peer_id(), address: addresses[j].clone() })).collect(),
        };
        let (node, store, task, service) = start(recover, root.join(format!("{leader}.sqlite")).to_str().unwrap().into(), libp2p::pnet::PreSharedKey::new([19; 32])).await.unwrap();
        nodes[leader] = node; stores[leader] = store; transports[leader] = task; services[leader] = service;
        assert_eq!(stores[leader].clone().applied_state().await.unwrap().1, joint.1);
        tokio::time::timeout(DEADLINE, async {
            loop {
                if matches!(services[leader].submit(Operation::Ready).await, Outcome::Ready) { break; }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert_eq!(stores[leader].clone().applied_state().await.unwrap().1, joint.1);
        nodes[follower].wait(Some(DEADLINE)).current_leader(leader as u64 + 1, "joint writer recovered").await.unwrap();
        let promoted = tokio::time::timeout(DEADLINE, async {
            loop {
                if matches!(services[follower].submit(Operation::PromoteLearner(9)).await, Outcome::Promotion(Ok(()))) { break; }
                tokio::task::yield_now().await;
            }
        }).await;
        assert!(promoted.is_ok());
        for node in &nodes { node.runtime_config().elect(true); }
        fourth_node.runtime_config().elect(true);
        assert!(matches!(services[follower].submit(Operation::PromoteLearner(9)).await, Outcome::Promotion(Ok(()))));
        let promotion_index = nodes[leader].metrics().borrow().last_applied.unwrap().index;
        fourth_node.wait(Some(DEADLINE)).applied_index(Some(promotion_index), "promotion committed on fourth voter").await.unwrap();
        for (node, store) in nodes.iter().zip(&stores).chain(std::iter::once((&fourth_node, &fourth_store))) {
            node.wait(Some(DEADLINE)).applied_index(Some(promotion_index), "uniform promotion retry replicated").await.unwrap();
            let uniform = store.clone().applied_state().await.unwrap().1;
            assert_eq!(uniform.membership().get_joint_config(), &vec![std::collections::BTreeSet::from([1, 2, 3, 9])]);
        }
        assert_eq!(nodes[leader].metrics().borrow().membership_config.membership().get_joint_config().len(), 1);
        assert!(fourth_node.metrics().borrow().membership_config.membership().voter_ids().any(|id| id == 9));
        assert!(!fourth_store.run(read_authority).await.unwrap().roster.unwrap().body.controllers.iter().any(|e| e.peer_id == join_peer));
        let mut invalid_grant = grant.clone(); invalid_grant.public_address = format!("/ip4/0.0.0.0/tcp/1/p2p/{join_peer}").parse().unwrap();
        assert!(matches!(services[follower].submit(Operation::GrantServing(invalid_grant)).await, Outcome::Roster(Err(_))));
        let mut private_grant = grant.clone(); private_grant.public_address = grant.control_address.clone();
        assert!(matches!(services[follower].submit(Operation::GrantServing(private_grant)).await, Outcome::Roster(Err(_))));
        tokio::time::timeout(DEADLINE, async {
            loop {
                if matches!(services[follower].submit(Operation::GrantServing(grant.clone())).await, Outcome::Roster(Ok(()))) { break; }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        let granted = stores[leader].run(read_authority).await.unwrap().roster.unwrap();
        let granted_revision = granted.body.revision;
        assert!(granted.body.controllers.iter().any(|e| e.peer_id == join_peer && e.addresses == vec![grant.public_address.clone(), grant.control_address.clone()]));
        assert!(granted.body.discovery_endpoints.iter().any(|e| e.peer_id == join_peer && e.addresses == vec![grant.public_address.clone()]));
        tokio::time::timeout(DEADLINE, async {
            loop {
                if matches!(services[follower].submit(Operation::GrantServing(grant.clone())).await, Outcome::Roster(Ok(()))) { break; }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert_eq!(stores[leader].run(read_authority).await.unwrap().roster.unwrap().body.revision, granted_revision);
        let mut conflict_grant = grant.clone(); conflict_grant.control_address = format!("/ip4/127.0.0.1/tcp/19092/p2p/{join_peer}").parse().unwrap();
        assert!(matches!(services[follower].submit(Operation::GrantServing(conflict_grant)).await, Outcome::Roster(Err(_))));
        let query = FindControllers::new("forward-test".into(), Role::Client, requester.public().to_peer_id(), chrono::Utc::now().timestamp_millis()).unwrap();
        let authorized = match services[follower].submit(Operation::Discovery { query: query.clone(), source: query.requester, serving: join_peer }).await {
            Outcome::Discovery(Ok(proof)) => proof,
            other => panic!("fourth voter discovery: {other:?}"),
        };
        authorized.validate(&pin, &query, join_peer, granted_revision, chrono::Utc::now().timestamp_millis()).unwrap();
        let promotion_snapshot = fourth_store.clone().build_snapshot().await.unwrap();
        // Reopen the learner's durable log/application state without another admission.
        fourth_node.shutdown().await.unwrap(); fourth_task.abort(); let _ = fourth_task.await;
        drop(fourth_service);
        let serving_index = nodes[leader].client_write(Command::Roster(granted.clone())).await.unwrap().log_id.index;
        assert!(matches!(services[follower].submit(Operation::GrantServing(grant.clone())).await, Outcome::Roster(Err(_))));
        let config: Config = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
        let psk = config.cluster_psk.as_ref().unwrap().parse().unwrap();
        let (restarted, _, restart_task, restart_service) = start(config, fourth_path.clone(), psk).await.unwrap();
        restarted.wait(Some(DEADLINE)).applied_index(Some(serving_index), "voter restart retained state").await.unwrap();
        assert!(restarted.metrics().borrow().membership_config.membership().voter_ids().any(|id| id == 9));
        // Real follower-forwarded removal of the fourth promoted voter.
        // Recovery/restart can elect another writer. Never forward an old
        // writer's ID: that requests legitimate removal, not self-revocation.
        leader = tokio::time::timeout(DEADLINE, async {
            loop {
                for (candidate, node) in nodes.iter().enumerate() {
                    let metrics = node.metrics().borrow().clone();
                    if metrics.state != openraft::ServerState::Leader { continue; }
                    if !matches!(services[candidate].local(Operation::Ready).await, Outcome::Ready) { continue; }
                    let outcome = services[candidate].local(Operation::RevokeReplica(metrics.id)).await;
                    if matches!(outcome, Outcome::Unavailable | Outcome::Redirect(_)) { continue; }
                    assert!(matches!(outcome, Outcome::Revocation(Err(ref error)) if error == "self or last-voter removal unsupported"),
                        "self-revocation: {outcome:?}; before={metrics:?}; after={:?}", node.metrics().borrow().clone());
                    return candidate;
                }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        for store in stores.iter().chain(std::iter::once(&fourth_store)) {
            assert!(store.run(read_revocations).await.unwrap().is_empty());
            assert_eq!(store.clone().applied_state().await.unwrap().1.membership().get_joint_config(),
                &vec![std::collections::BTreeSet::from([1, 2, 3, 9])]);
        }
        // ponytail: one committed roster-first interruption, not SIGKILL/powerloss
        // or interruption inside joint consensus; add process gates separately.
        services[leader].interrupt_revocation.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(services[leader].submit(Operation::RevokeReplica(9)).await, Outcome::Unavailable));
        assert!(!services[leader].interrupt_revocation.load(std::sync::atomic::Ordering::SeqCst));
        let interrupted_index = nodes[leader].metrics().borrow().last_applied.unwrap().index;
        for (node, store) in nodes.iter().zip(&stores).chain(std::iter::once((&restarted, &fourth_store))) {
            node.wait(Some(DEADLINE)).applied_index(Some(interrupted_index), "pending revocation committed").await.unwrap();
            let tombstones = store.run(read_revocations).await.unwrap();
            assert_eq!(tombstones.get(&9).unwrap().peer, join_peer);
            assert!(!tombstones.get(&9).unwrap().complete);
            let withdrawn = store.run(read_authority).await.unwrap().roster.unwrap();
            assert_eq!(withdrawn.body.revision, granted_revision + 1);
            assert!(!withdrawn.body.controllers.iter().chain(&withdrawn.body.discovery_endpoints).any(|e| e.peer_id == join_peer));
            assert_eq!(node.metrics().borrow().membership_config.membership().get_joint_config().len(), 1);
            assert!(node.metrics().borrow().membership_config.membership().voter_ids().any(|id| id == 9));
        }
        // Restart the stage-one writer with its existing DB/identity; no admission,
        // initialize, local membership rewrite or automatic completion on startup.
        schedulers[leader].abort();
        nodes[leader].shutdown().await.unwrap();
        transports[leader].abort(); let _ = (&mut transports[leader]).await;
        let recover = Config {
            learner: None, cluster_psk: None, transport_generation: 0, legacy_import: None,
            cluster_id: "forward-test".into(), node_id: leader as u64 + 1, mode: Mode::Recover,
            identity_file: identities[leader].to_str().unwrap().into(), listen: addresses[leader].clone(),
            replicas: (0..3).map(|j| (j as u64 + 1, Replica { peer_id: keys[j].public().to_peer_id(), address: addresses[j].clone() })).collect(),
        };
        let (node, store, task, service) = start(recover, root.join(format!("{leader}.sqlite")).to_str().unwrap().into(), libp2p::pnet::PreSharedKey::new([19; 32])).await.unwrap();
        nodes[leader] = node; stores[leader] = store; transports[leader] = task; services[leader] = service;
        nodes[leader].wait(Some(DEADLINE)).applied_index(Some(interrupted_index), "pending revocation survives recovery").await.unwrap();
        assert!(!stores[leader].run(read_revocations).await.unwrap().get(&9).unwrap().complete);
        let recovered_roster = stores[leader].run(read_authority).await.unwrap().roster.unwrap();
        assert_eq!(recovered_roster.body.revision, granted_revision + 1);
        assert!(!recovered_roster.body.controllers.iter().chain(&recovered_roster.body.discovery_endpoints).any(|e| e.peer_id == join_peer));
        assert!(nodes[leader].metrics().borrow().membership_config.membership().voter_ids().any(|id| id == 9));
        leader = tokio::time::timeout(DEADLINE, async {
            loop {
                if let Some(id) = nodes.iter().find_map(|n| {
                    let m = n.metrics().borrow().clone();
                    (m.current_leader == Some(m.id)).then_some(m.id)
                }) {
                    let candidate = id as usize - 1;
                    if matches!(services[candidate].submit(Operation::Ready).await, Outcome::Ready) { break candidate; }
                }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert!(matches!(services[leader].submit(Operation::Join { source: join_peer, request: join_request.clone() }).await, Outcome::Join(JoinResponse::Rejected)));
        expect_rejection(&services, &nodes, leader, Operation::ActivateLearner(9),
            |outcome| matches!(outcome, Outcome::Learner(Err(error)) if error == "no committed pending admission"),
            "revoked learner activation").await;
        assert!(matches!(services[leader].submit(Operation::PromoteLearner(9)).await, Outcome::Promotion(Err(_))));
        assert!(matches!(services[leader].submit(Operation::GrantServing(grant.clone())).await, Outcome::Roster(Err(_))));
        assert!(matches!(services[leader].submit(Operation::Discovery { query: query.clone(), source: query.requester, serving: join_peer }).await, Outcome::Discovery(Err(_))));
        // Resume the roster-first revoke into actual native joint removal, then
        // fail-stop its writer before uniform membership/tombstone completion.
        for node in &nodes { node.runtime_config().elect(false); }
        restarted.runtime_config().elect(false);
        interrupt_uniform(&stores[leader]).await;
        let interrupted = services[leader].submit(Operation::RevokeReplica(9)).await;
        assert!(matches!(interrupted, Outcome::Unavailable), "{interrupted:?}");
        assert!(nodes[leader].metrics().borrow().running_state.is_err());
        let removal_joint = stores[leader].clone().applied_state().await.unwrap();
        assert_eq!(removal_joint.1.membership().get_joint_config(), &vec![
            std::collections::BTreeSet::from([1, 2, 3, 9]),
            std::collections::BTreeSet::from([1, 2, 3]),
        ]);
        let removal_index = removal_joint.1.log_id().unwrap().index;
        assert_eq!(removal_joint.0.unwrap().index, removal_index);
        assert_eq!(stores[leader].clone().get_log_state().await.unwrap().last_log_id, removal_joint.0);
        for (node, store) in nodes.iter().zip(&stores).filter(|(n, _)| n.metrics().borrow().id != leader as u64 + 1)
            .chain(std::iter::once((&restarted, &fourth_store))) {
            node.wait(Some(DEADLINE)).applied_index(Some(removal_index), "joint removal committed before recovery").await.unwrap();
            assert_eq!(store.clone().applied_state().await.unwrap().1, removal_joint.1);
            assert!(!store.run(read_revocations).await.unwrap().get(&9).unwrap().complete);
            let withdrawn = store.run(read_authority).await.unwrap().roster.unwrap();
            assert_eq!(withdrawn.body.revision, granted_revision + 1);
            assert!(!withdrawn.body.controllers.iter().chain(&withdrawn.body.discovery_endpoints).any(|e| e.peer_id == join_peer));
        }
        // Reconciliation must retain the pending target's consensus transport.
        let target_network = restart_service.network.as_ref().unwrap();
        target_network.reconcile_store(&fourth_store).await.unwrap();
        assert!(target_network.bootstrap_endpoints().contains_key(&9));
        assert!(!restart_task.is_finished());
        nodes[leader].shutdown().await.unwrap();
        transports[leader].abort(); let _ = (&mut transports[leader]).await;
        if surviving_election {
            // Both original survivors AND voter9 are required: 3/4 old, 2/3 new.
            // ponytail: native storage fail-stop; process/powerloss remains separate.
            let survivor = (leader + 1) % 3;
            nodes[survivor].runtime_config().elect(true);
            nodes[survivor].wait(Some(DEADLINE)).state(openraft::ServerState::Leader, "survivor elected under joint removal").await.unwrap();
            let survivor_id = survivor as u64 + 1;
            for (node, store) in nodes.iter().zip(&stores).filter(|(n, _)| n.metrics().borrow().id != leader as u64 + 1)
                .chain(std::iter::once((&restarted, &fourth_store))) {
                node.wait(Some(DEADLINE)).current_leader(survivor_id, "joint survivors recognize elected leader").await.unwrap();
                assert_eq!(node.metrics().borrow().membership_config.as_ref(), &removal_joint.1);
                assert_eq!(store.clone().applied_state().await.unwrap().1, removal_joint.1);
            }
            assert!(matches!(services[survivor].submit(Operation::Ready).await, Outcome::Ready));
            let authority = match services[survivor].submit(Operation::Authority).await {
                Outcome::Authority(Ok(authority)) => authority,
                other => panic!("surviving joint leader authority: {other:?}"),
            };
            assert_eq!(authority.signing_key, initial.signing_key);
            assert_eq!(authority.encryption_key, initial.encryption_key);
            let withdrawn = authority.roster.unwrap();
            assert_eq!(withdrawn.body.revision, granted_revision + 1);
            assert!(!withdrawn.body.controllers.iter().chain(&withdrawn.body.discovery_endpoints).any(|e| e.peer_id == join_peer));
            assert_eq!(nodes[survivor].metrics().borrow().membership_config.as_ref(), &removal_joint.1);
            assert!(!stores[survivor].run(read_revocations).await.unwrap().get(&9).unwrap().complete);
            assert!(nodes[leader].metrics().borrow().running_state.is_err());
            assert!(transports[leader].is_finished());
            let retry_follower = (0..3).find(|&i| i != leader && i != survivor).unwrap();
            assert_eq!(nodes[retry_follower].metrics().borrow().state, openraft::ServerState::Follower);
            assert!(matches!(services[retry_follower].submit(Operation::Join { source: join_peer, request: join_request.clone() }).await, Outcome::Join(JoinResponse::Rejected)));
            tokio::time::timeout(DEADLINE, async {
                loop {
                    let removal = services[retry_follower].submit(Operation::RevokeReplica(9)).await;
                    if matches!(removal, Outcome::Revocation(Ok(()))) { break; }
                    assert!(matches!(removal, Outcome::Unavailable), "surviving leader removal retry: {removal:?}");
                    tokio::task::yield_now().await;
                }
            }).await.unwrap();
            assert!(matches!(services[retry_follower].submit(Operation::RevokeReplica(9)).await, Outcome::Revocation(Ok(()))));
            let completed_index = nodes[survivor].metrics().borrow().last_applied.unwrap().index;
            for i in (0..3).filter(|&i| i != leader) {
                nodes[i].wait(Some(DEADLINE)).applied_index(Some(completed_index), "surviving replicas apply completed removal").await.unwrap();
                let reopened = Store::open(root.join(format!("{i}.sqlite")).to_str().unwrap().into()).await.unwrap();
                let uniform = reopened.clone().applied_state().await.unwrap().1;
                assert_eq!(uniform.membership().get_joint_config(), &vec![std::collections::BTreeSet::from([1, 2, 3])]);
                assert!(!uniform.membership().nodes().any(|(id, _)| *id == 9));
                assert_eq!(nodes[i].metrics().borrow().membership_config.as_ref(), &uniform);
                let tombstones = reopened.run(read_revocations).await.unwrap();
                assert_eq!(tombstones.get(&9).unwrap().peer, join_peer);
                assert!(tombstones.get(&9).unwrap().complete);
                let authority = reopened.run(read_authority).await.unwrap();
                assert_eq!(authority.signing_key, initial.signing_key);
                assert_eq!(authority.encryption_key, initial.encryption_key);
                let withdrawn = authority.roster.unwrap();
                assert_eq!(withdrawn.body.revision, granted_revision + 1);
                assert!(!withdrawn.body.controllers.iter().chain(&withdrawn.body.discovery_endpoints).any(|e| e.peer_id == join_peer));
            }
            assert!(!services[survivor].network.as_ref().unwrap().bootstrap_endpoints().contains_key(&9));
            assert!(matches!(services[retry_follower].submit(Operation::Join { source: join_peer, request: join_request.clone() }).await, Outcome::Join(JoinResponse::Rejected)));
            assert!(matches!(services[retry_follower].submit(Operation::ActivateLearner(9)).await, Outcome::Learner(Err(_))));
            assert!(matches!(services[retry_follower].submit(Operation::PromoteLearner(9)).await, Outcome::Promotion(Err(_))));
            assert!(matches!(services[retry_follower].submit(Operation::GrantServing(grant.clone())).await, Outcome::Roster(Err(_))));
            assert!(matches!(services[retry_follower].submit(Operation::Discovery { query: query.clone(), source: query.requester, serving: join_peer }).await, Outcome::Discovery(Err(_))));
            assert_eq!(stores[leader].clone().applied_state().await.unwrap().1, removal_joint.1);
            assert!(!stores[leader].run(read_revocations).await.unwrap().get(&9).unwrap().complete);
            assert!(nodes[leader].metrics().borrow().running_state.is_err());
            assert!(transports[leader].is_finished());
            let recover = Config {
                learner: None, cluster_psk: None, transport_generation: 0, legacy_import: None,
                cluster_id: "forward-test".into(), node_id: leader as u64 + 1, mode: Mode::Recover,
                identity_file: identities[leader].to_str().unwrap().into(), listen: addresses[leader].clone(),
                replicas: (0..3).map(|j| (j as u64 + 1, Replica { peer_id: keys[j].public().to_peer_id(), address: addresses[j].clone() })).collect(),
            };
            let (node, store, mut task, service) = start(recover,
                root.join(format!("{leader}.sqlite")).to_str().unwrap().into(),
                libp2p::pnet::PreSharedKey::new([19; 32])).await.unwrap();
            node.runtime_config().elect(false);
            node.wait(Some(DEADLINE)).applied_index_at_least(Some(completed_index), "former writer catches up after removal").await.unwrap();
            assert_eq!(store.clone().applied_state().await.unwrap().1.membership().get_joint_config(),
                &vec![std::collections::BTreeSet::from([1, 2, 3])]);
            assert!(store.run(read_revocations).await.unwrap().get(&9).unwrap().complete);
            assert!(matches!(service.submit(Operation::Ready).await, Outcome::Ready));
            assert!(matches!(service.submit(Operation::Join { source: join_peer, request: join_request.clone() }).await,
                Outcome::Join(JoinResponse::Rejected)));
            node.shutdown().await.unwrap();
            task.abort(); let _ = (&mut task).await;
            for scheduler in &schedulers { scheduler.abort(); }
            responder.abort(); let _ = responder.await;
            for i in 0..3 {
                if i == leader { continue; }
                nodes[i].shutdown().await.unwrap();
                transports[i].abort(); let _ = (&mut transports[i]).await;
            }
            restarted.shutdown().await.unwrap(); restart_task.abort(); let _ = restart_task.await;
            return;
        }
        let recover = Config {
            learner: None, cluster_psk: None, transport_generation: 0, legacy_import: None,
            cluster_id: "forward-test".into(), node_id: leader as u64 + 1, mode: Mode::Recover,
            identity_file: identities[leader].to_str().unwrap().into(), listen: addresses[leader].clone(),
            replicas: (0..3).map(|j| (j as u64 + 1, Replica { peer_id: keys[j].public().to_peer_id(), address: addresses[j].clone() })).collect(),
        };
        let (node, store, task, service) = start(recover, root.join(format!("{leader}.sqlite")).to_str().unwrap().into(), libp2p::pnet::PreSharedKey::new([19; 32])).await.unwrap();
        nodes[leader] = node; stores[leader] = store; transports[leader] = task; services[leader] = service;
        assert_eq!(stores[leader].clone().applied_state().await.unwrap().1, removal_joint.1);
        tokio::time::timeout(DEADLINE, async {
            loop {
                if matches!(services[leader].submit(Operation::Ready).await, Outcome::Ready) { break; }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert_eq!(stores[leader].clone().applied_state().await.unwrap().1, removal_joint.1);
        assert!(!stores[leader].run(read_revocations).await.unwrap().get(&9).unwrap().complete);
        assert!(stores[leader].clone().applied_state().await.unwrap().1.membership().nodes().any(|(id, _)| *id == 9));
        nodes[follower].wait(Some(DEADLINE)).current_leader(leader as u64 + 1, "joint removal writer recovered").await.unwrap();
        assert!(matches!(services[follower].submit(Operation::Join { source: join_peer, request: join_request.clone() }).await, Outcome::Join(JoinResponse::Rejected)));
        assert!(matches!(services[follower].submit(Operation::ActivateLearner(9)).await, Outcome::Learner(Err(_))));
        assert!(matches!(services[follower].submit(Operation::PromoteLearner(9)).await, Outcome::Promotion(Err(_))));
        assert!(matches!(services[follower].submit(Operation::GrantServing(grant.clone())).await, Outcome::Roster(Err(_))));
        tokio::time::timeout(DEADLINE, async {
            loop {
                let removal = services[follower].submit(Operation::RevokeReplica(9)).await;
                if matches!(removal, Outcome::Revocation(Ok(()))) { break; }
                assert!(matches!(removal, Outcome::Unavailable), "{removal:?}");
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        for node in &nodes { node.runtime_config().elect(true); }
        restarted.runtime_config().elect(true);
        assert!(matches!(services[follower].submit(Operation::RevokeReplica(9)).await, Outcome::Revocation(Ok(()))));
        assert_eq!(stores[leader].run(read_authority).await.unwrap().roster.unwrap().body.revision, granted_revision + 1);
        assert_eq!(stores[leader].clone().applied_state().await.unwrap().1.membership().get_joint_config(), &vec![std::collections::BTreeSet::from([1, 2, 3])]);
        assert!(!services[leader].network.as_ref().unwrap().bootstrap_endpoints().contains_key(&9));
        assert!(!nodes[leader].metrics().borrow().membership_config.membership().nodes().any(|(id, _)| *id == 9));
        assert!(matches!(services[follower].submit(Operation::Join { source: join_peer, request: join_request.clone() }).await, Outcome::Join(cat4igp_shared::discovery::join::Response::Rejected)));
        assert!(matches!(services[follower].submit(Operation::ActivateLearner(9)).await, Outcome::Learner(Err(_))));
        assert!(matches!(services[follower].submit(Operation::PromoteLearner(9)).await, Outcome::Promotion(Err(_))));
        assert!(matches!(services[follower].submit(Operation::GrantServing(grant.clone())).await, Outcome::Roster(Err(_))));
        let reopened_leader = Store::open(root.join(format!("{leader}.sqlite")).to_str().unwrap().to_owned()).await.unwrap();
        assert!(reopened_leader.run(read_revocations).await.unwrap().get(&9).unwrap().complete);
        restarted.shutdown().await.unwrap(); restart_task.abort(); let _ = restart_task.await; drop(restart_service);
        let mut fourth_reopened = Store::open(fourth_path).await.unwrap();
        use openraft::storage::RaftStateMachine;
        assert!(fourth_reopened.applied_state().await.unwrap().0.unwrap().index >= learner_index);
        let snapshot = promotion_snapshot;
        let restored_path = root.join("authorization-snapshot.sqlite").to_str().unwrap().to_owned();
        let mut conn = diesel::SqliteConnection::establish(&restored_path).unwrap();
        crate::db::migrate(&mut conn, true).unwrap(); drop(conn);
        let mut restored = Store::open(restored_path).await.unwrap();
        restored.install_snapshot(&snapshot.meta, snapshot.snapshot).await.unwrap();
        assert!(restored.applied_state().await.unwrap().1.membership().voter_ids().any(|id| id == 9));
        // Never install a pre-revocation authorization snapshot into a live transport.
        // The old snapshot above only verifies historical promotion persistence.
        services[leader].network.as_ref().unwrap().reconcile_store(&stores[leader]).await.unwrap();
        let query = FindControllers::new("forward-test".into(), Role::Client, requester.public().to_peer_id(), chrono::Utc::now().timestamp_millis()).unwrap();
        assert!(matches!(services[follower].submit(Operation::Discovery { query: query.clone(), source: serving, serving }).await, Outcome::Discovery(Err(_))));
        assert!(matches!(services[follower].submit(Operation::Discovery { query: query.clone(), source: query.requester, serving: requester.public().to_peer_id() }).await, Outcome::Discovery(Err(_))));
        let mut expired_query = query.clone(); expired_query.issued_at_ms -= 300_000; expired_query.expires_at_ms -= 300_000;
        assert!(matches!(services[follower].submit(Operation::Discovery { query: expired_query, source: query.requester, serving }).await, Outcome::Discovery(Err(_))));
        let applied = nodes[leader].metrics().borrow().last_applied.unwrap().index;
        for i in 0..3 {
            nodes[i].wait(Some(DEADLINE)).applied_index(Some(applied), "authority replicated").await.unwrap();
            assert!(stores[i].run(read_revocations).await.unwrap().get(&9).unwrap().complete);
            assert_eq!(stores[i].clone().applied_state().await.unwrap().1.membership().get_joint_config(), &vec![std::collections::BTreeSet::from([1, 2, 3])]);
            assert!(!nodes[i].metrics().borrow().membership_config.membership().nodes().any(|(id, _)| *id == 9));
            let state = stores[i].run(read_authority).await.unwrap();
            assert_eq!(state.signing_key, initial.signing_key);
            assert_eq!(state.encryption_key, initial.encryption_key);
            state.roster.unwrap().validate(&pin, "forward-test", 1, chrono::Utc::now().timestamp_millis()).unwrap();
        }
        let mut rogue = roster.clone();
        let peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        rogue.controllers[0] = cat4igp_shared::discovery::ControllerEndpoint { peer_id: peer, addresses: vec![addresses[0].clone().with(libp2p::multiaddr::Protocol::P2p(peer))] };
        let rejected = services[follower].submit(Operation::Roster(rogue)).await;
        assert!(matches!(rejected, Outcome::Roster(Err(_))), "{rejected:?}");
        roster = stores[leader].run(read_authority).await.unwrap().roster.unwrap().body;
        roster.revision += 1; roster.issued_at_ms = chrono::Utc::now().timestamp_millis(); roster.expires_at_ms += 1;
        assert!(matches!(services[follower].submit(Operation::Roster(roster.clone())).await, Outcome::Roster(Ok(()))));
        let refreshed = transport::discover(&requester, &pin, "forward-test", Role::Replica, &[public_address], 2).await.unwrap();
        assert_eq!(refreshed.body.roster.body.revision, roster.revision);
        let mut rollback = roster.clone(); rollback.revision = 1;
        let rejected = services[follower].submit(Operation::Roster(rollback)).await;
        assert!(matches!(rejected, Outcome::Roster(Err(_))), "rollback: {rejected:?}");
        let mut expired = roster.clone(); expired.issued_at_ms -= 300_000; expired.expires_at_ms -= 300_000;
        assert!(matches!(services[follower].submit(Operation::Roster(expired)).await, Outcome::Roster(Err(_))));
        let mesh = Command::Mesh { id: 1, name: "wire-mesh".into(), mtu: 1280, created_at: chrono::Utc::now().naive_utc() };
        assert!(nodes[leader].client_write(mesh.clone()).await.unwrap().data.is_ok());
        assert!(nodes[leader].client_write(mesh.clone()).await.unwrap().data.is_ok());
        let mut conflict_mesh = mesh.clone();
        if let Command::Mesh { mtu, .. } = &mut conflict_mesh { *mtu = 1400; }
        assert!(nodes[leader].client_write(conflict_mesh).await.unwrap().data.is_err());
        let mut invalid_mesh = mesh;
        if let Command::Mesh { id, mtu, .. } = &mut invalid_mesh { *id = 2; *mtu = 0; }
        assert!(nodes[leader].client_write(invalid_mesh).await.unwrap().data.is_err());
        let operation = Operation::Invite { request_id: "lost-response".into(), expires_at: None, max_uses: Some(1), join_mesh: Some(1) };
        let code = match services[follower].submit(operation.clone()).await { Outcome::Invite(Ok(code)) => code, other => panic!("{other:?}") };
        assert!(matches!(services[follower].submit(Operation::Ready).await, Outcome::Ready));
        assert!(matches!(services[follower].submit(operation.clone()).await, Outcome::Invite(Ok(retry)) if retry == code));
        let conflict = Operation::Invite { request_id: "lost-response".into(), expires_at: None, max_uses: Some(2), join_mesh: None };
        assert!(matches!(services[follower].submit(conflict).await, Outcome::Invite(Err(_))));
        // Exercise shipped enrollment code against the real follower listener and Raft.
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let private_address: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", socket.local_addr().unwrap().port()).parse().unwrap();
        drop(socket);
        let endpoint = private_address.clone().with(libp2p::multiaddr::Protocol::P2p(serving)).to_string();
        let relay_replica = (follower + 1) % 3;
        // All forwarding hops validate against the committed logical authority, even
        // when this harness has no local client listener on the third replica.
        for service in &services {
            service.network.as_ref().unwrap().reconcile_store(&service.store).await.unwrap();
            let _ = service.network.as_ref().unwrap().listen_topology();
        }
        let relay_socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_address: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", relay_socket.local_addr().unwrap().port()).parse().unwrap();
        drop(relay_socket);
        let relay_endpoint = relay_address.clone().with(libp2p::multiaddr::Protocol::P2p(keys[relay_replica].public().to_peer_id())).to_string();
        roster.revision += 1;
        roster.issued_at_ms = chrono::Utc::now().timestamp_millis();
        roster.expires_at_ms += 60_000;
        roster.controllers[follower].addresses = vec![endpoint.parse().unwrap()];
        roster.controllers[relay_replica].addresses = vec![relay_endpoint.parse().unwrap()];
        assert!(matches!(services[follower].submit(Operation::Roster(roster.clone())).await, Outcome::Roster(Ok(()))));
        let wire_invite = match services[follower].submit(Operation::Invite {
            request_id: "real-wire-invite".into(), expires_at: None, max_uses: Some(1), join_mesh: Some(1),
        }).await { Outcome::Invite(Ok(code)) => code, other => panic!("{other:?}") };
        let mut wire_config = crate::client_config::ServerConfig::new(endpoint.clone(), wire_invite);
        wire_config.controller_peer_id = Some(pin.to_peer_id().to_string());
        wire_config.controller_signing_key = Some(initial.signing_key.clone());
        wire_config.controller_encryption_key = Some(initial.encryption_key.clone());
        wire_config.control_network_id = "forward-test".into();
        wire_config.discovery_proof = Some(match services[follower].submit(Operation::Discovery {
            query: FindControllers::new("forward-test".into(), Role::Client, requester.public().to_peer_id(), chrono::Utc::now().timestamp_millis()).unwrap(),
            source: requester.public().to_peer_id(), serving,
        }).await { Outcome::Discovery(Ok(proof)) => proof, other => panic!("{other:?}") });
        wire_config.control_private_network_key = Some(format!("/key/swarm/psk/1.0.0/\n/base16/\n{}", "12".repeat(32)));
        wire_config.ensure_wireguard_keypair().unwrap();
        wire_config.ensure_control_keypair().unwrap();
        wire_config.ensure_control_encryption_key().unwrap();
        let pending_directory = root.join("wire-client");
        wire_config.save(&pending_directory).unwrap();
        let listener_service = services[follower].clone();
        let listener_key = keys[follower].clone();
        let private_listener = tokio::spawn(async move {
            private_control_at(listener_service, listener_key, &private_address.to_string(), libp2p::pnet::PreSharedKey::new([0x12; 32])).await
        });
        let wire_response = crate::client_control::enroll(&mut wire_config, &[endpoint.clone()], "wire-client".into()).await.unwrap();
        assert!(matches!(wire_response, cat4igp_shared::control::ControlResponse::Enrolled(_)));
        let retry_response = crate::client_control::enroll(&mut wire_config, &[endpoint], "wire-client".into()).await.unwrap();
        assert_eq!(serde_json::to_value(&wire_response).unwrap(), serde_json::to_value(retry_response).unwrap());
        use cat4igp_shared::control::{ControlRequest, ControlResponse, EnrollmentRequest};
        let client_key = libp2p::identity::Keypair::generate_ed25519();
        let principal = client_key.public().to_peer_id();
        let client_secret = x25519_dalek::StaticSecret::from([7; 32]);
        let request = ControlRequest::Enroll(EnrollmentRequest {
            request_id: "enrollment-lost-reply".into(), node_name: "ha-client".into(),
            invitation_code: code.clone(), client_peer_id: principal.to_string(),
            client_signing_key: crate::hex_encode(&client_key.public().encode_protobuf()),
            client_encryption_key: crate::hex_encode(x25519_dalek::PublicKey::from(&client_secret).as_bytes()), wireguard_public_key: "wg-test".into(),
        });
        let enrollment = Operation::Client { principal, serving, request: request.clone() };
        assert!(matches!(services[follower].submit(Operation::VerifyReplicaCode(code.clone())).await, Outcome::Unavailable | Outcome::VerifiedReplicaCode(false)));
        let mut replica_as_client = request.clone();
        let rejected_key = libp2p::identity::Keypair::generate_ed25519();
        let rejected_principal = rejected_key.public().to_peer_id();
        if let ControlRequest::Enroll(ref mut request) = replica_as_client {
            request.request_id = "replica-code-not-client-invite".into();
            request.invitation_code = rotated.code.clone();
            request.client_peer_id = rejected_principal.to_string();
            request.client_signing_key = crate::hex_encode(&rejected_key.public().encode_protobuf());
        }
        assert!(matches!(services[follower].submit(Operation::Client { principal: rejected_principal, serving, request: replica_as_client }).await, Outcome::Client(ControlResponse::Rejected(_))));
        let original_enrollment = match services[follower].submit(enrollment.clone()).await {
            Outcome::Client(ControlResponse::Enrolled(response)) => serde_json::to_value(response).unwrap(),
            other => panic!("{other:?}"),
        };
        assert!(matches!(services[follower].submit(enrollment.clone()).await,
            Outcome::Client(ControlResponse::Enrolled(response)) if serde_json::to_value(&response).unwrap() == original_enrollment));
        let (updates, mut updates_rx) = tokio::sync::mpsc::channel(1);
        let current = Arc::new(tokio::sync::Mutex::new(Some(wire_config.clone())));
        let wire_control = crate::client_control::start(wire_config.clone(), updates, current).unwrap();
        let relay_service = services[relay_replica].clone();
        let relay_key = keys[relay_replica].clone();
        let relay_listener = tokio::spawn(async move {
            private_control_at(relay_service, relay_key, &relay_address.to_string(), libp2p::pnet::PreSharedKey::new([0x12; 32])).await
        });
        let mut relay_config = wire_config.clone();
        relay_config.address = relay_endpoint.clone();
        relay_config.control_bootstrap_addresses = vec![relay_endpoint.clone()];
        let (relay_updates, mut relay_updates_rx) = tokio::sync::mpsc::channel(1);
        let relay_current = Arc::new(tokio::sync::Mutex::new(Some(relay_config.clone())));
        let relay_control = crate::client_control::start(relay_config, relay_updates, relay_current).unwrap();
        let mut other_config = wire_config.clone();
        other_config.address = relay_endpoint.clone();
        other_config.control_bootstrap_addresses = vec![relay_endpoint.clone()];
        other_config.control_private_key = Some(crate::hex_encode(&client_key.to_protobuf_encoding().unwrap()));
        other_config.control_encryption_private_key = Some(crate::hex_encode(&client_secret.to_bytes()));
        other_config.control_node_id = Some(original_enrollment["node_id"].as_i64().unwrap() as i32);
        let (other_updates, mut other_updates_rx) = tokio::sync::mpsc::channel(1);
        let other_current = Arc::new(tokio::sync::Mutex::new(Some(other_config.clone())));
        let other_control = crate::client_control::start(other_config.clone(), other_updates, other_current).unwrap();
        let other_before = loop {
            if let ControlResponse::SnapshotEnvelope(envelope) = other_control.request(ControlRequest::Snapshot).await.unwrap() {
                break cat4igp_shared::control::open_topology_snapshot(
                    &initial.signing_key, other_config.control_encryption_private_key.as_deref().unwrap(),
                    "forward-test", other_config.control_node_id.unwrap(), chrono::Utc::now().timestamp_millis(), &envelope,
                ).unwrap();
            }
            tokio::task::yield_now().await;
        };
        let open_wire = |response: ControlResponse| {
            let ControlResponse::SnapshotEnvelope(envelope) = response else { panic!("{response:?}"); };
            cat4igp_shared::control::open_topology_snapshot(
                wire_config.controller_signing_key.as_deref().unwrap(),
                wire_config.control_encryption_private_key.as_deref().unwrap(),
                &wire_config.control_network_id, wire_config.control_node_id.unwrap(),
                chrono::Utc::now().timestamp_millis(), &envelope,
            ).unwrap()
        };
        let before_answer = loop {
            let response = wire_control.request(ControlRequest::Snapshot).await.unwrap();
            if matches!(response, ControlResponse::SnapshotEnvelope(_)) { break open_wire(response); }
            tokio::task::yield_now().await;
        };
        loop {
            if matches!(relay_control.request(ControlRequest::Snapshot).await.unwrap(), ControlResponse::SnapshotEnvelope(_)) { break; }
            tokio::task::yield_now().await;
        }
        // Allow the shipped push swarm's subscription to propagate, not just its RPC connection.
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(before_answer.tunnels.len(), 2);
        let tunnel_id = before_answer.tunnels.iter().find(|t| !t.endpoint_ipv6).unwrap().tunnel_id;
        let answer_time = chrono::Utc::now().timestamp_millis();
        let signed_answer = cat4igp_shared::control::seal_tunnel_answer(
            &wire_config.clone().ensure_control_keypair().unwrap(), &initial.encryption_key,
            cat4igp_shared::control::MessageMeta {
                message_id: "ab".repeat(16), network_id: "forward-test".into(),
                recipient_node_id: before_answer.node_id, issued_at_ms: answer_time,
                expires_at_ms: answer_time + 60_000, topology_revision: before_answer.revision,
            }, &cat4igp_shared::control::TunnelAnswer { tunnel_id, decline_type: None, endpoint: Some("127.0.0.1:51820".into()) },
        ).unwrap();
        let answer_response = wire_control.request(ControlRequest::TunnelAnswerEnvelope(signed_answer.clone())).await.unwrap();
        assert!(matches!(answer_response, ControlResponse::Accepted), "{answer_response:?}");
        let answered = loop {
            let response = wire_control.request(ControlRequest::Snapshot).await.unwrap();
            if matches!(response, ControlResponse::SnapshotEnvelope(_)) { break open_wire(response); }
            tokio::task::yield_now().await;
        };
        assert_eq!(answered.revision, before_answer.revision + 1);
        assert_eq!(answered.tunnels.iter().find(|t| t.tunnel_id == tunnel_id).unwrap().preferred_port, 51820);
        let pushed = tokio::time::timeout(Duration::from_secs(5), updates_rx.recv()).await.unwrap().unwrap();
        assert_eq!(serde_json::to_value(&pushed).unwrap(), serde_json::to_value(&answered).unwrap());
        // Actual private cluster pubsub -> another listener -> shipped client decryption.
        let relayed = tokio::time::timeout(Duration::from_secs(5), relay_updates_rx.recv()).await.unwrap().unwrap();
        assert_eq!(serde_json::to_value(&relayed).unwrap(), serde_json::to_value(&answered).unwrap());
        let other_pushed = tokio::time::timeout(Duration::from_secs(5), other_updates_rx.recv()).await.unwrap().unwrap();
        assert_eq!(other_pushed.node_id, other_before.node_id);
        assert_eq!(other_pushed.revision, other_before.revision + 1);
        let wire_principal = wire_config.clone().ensure_control_keypair().unwrap().public().to_peer_id();
        let Outcome::AffectedSnapshots(envelopes) = services[follower].submit(Operation::AffectedSnapshots {
            principal: wire_principal, serving, envelope: signed_answer.clone(),
        }).await else { panic!("affected read unavailable"); };
        assert_eq!(envelopes.len(), 2);
        assert_ne!(envelopes[0].ciphertext, envelopes[1].ciphertext);
        for envelope in &envelopes {
            let config = if envelope.meta.recipient_node_id == answered.node_id { &wire_config } else { &other_config };
            let snapshot = cat4igp_shared::control::open_topology_snapshot(
                &initial.signing_key, config.control_encryption_private_key.as_deref().unwrap(),
                "forward-test", config.control_node_id.unwrap(), chrono::Utc::now().timestamp_millis(), envelope,
            ).unwrap();
            assert_eq!(snapshot.revision, envelope.meta.topology_revision);
            assert_eq!(snapshot.revision, if snapshot.node_id == answered.node_id { answered.revision } else { other_pushed.revision });
            let wrong = if snapshot.node_id == answered.node_id { &other_config } else { &wire_config };
            assert!(cat4igp_shared::control::open_topology_snapshot(
                &initial.signing_key, wrong.control_encryption_private_key.as_deref().unwrap(),
                "forward-test", snapshot.node_id, chrono::Utc::now().timestamp_millis(), envelope,
            ).is_err());
        }
        assert!(matches!(wire_control.request(ControlRequest::TunnelAnswerEnvelope(signed_answer.clone())).await.unwrap(), ControlResponse::Accepted));
        let retried = loop {
            let response = wire_control.request(ControlRequest::Snapshot).await.unwrap();
            if matches!(response, ControlResponse::SnapshotEnvelope(_)) { break open_wire(response); }
            tokio::task::yield_now().await;
        };
        assert_eq!(serde_json::to_value(retried).unwrap(), serde_json::to_value(&answered).unwrap());
        assert!(tokio::time::timeout(Duration::from_secs(2), updates_rx.recv()).await.is_err());
        assert!(tokio::time::timeout(Duration::from_millis(300), relay_updates_rx.recv()).await.is_err());
        assert!(tokio::time::timeout(Duration::from_millis(300), other_updates_rx.recv()).await.is_err());
        drop(other_control);
        // Discard the notification: the same authoritative snapshot repairs a missed push.
        let recovered = loop {
            let response = relay_control.request(ControlRequest::Snapshot).await.unwrap();
            if matches!(response, ControlResponse::SnapshotEnvelope(_)) { break open_wire(response); }
            tokio::task::yield_now().await;
        };
        assert_eq!(serde_json::to_value(recovered).unwrap(), serde_json::to_value(&answered).unwrap());
        drop(relay_control);
        relay_listener.abort();
        assert!(relay_listener.await.unwrap_err().is_cancelled());
        drop(wire_control);
        private_listener.abort();
        assert!(private_listener.await.unwrap_err().is_cancelled());
        assert!(matches!(services[follower].submit(Operation::Client {
            principal: requester.public().to_peer_id(), serving, request: request.clone(),
        }).await, Outcome::Client(ControlResponse::Rejected(_))));
        assert!(!matches!(services[follower].submit(Operation::Client {
            principal, serving: requester.public().to_peer_id(), request: ControlRequest::Snapshot,
        }).await, Outcome::Client(ControlResponse::SnapshotEnvelope(_))));
        let snapshot_response = services[follower].submit(Operation::Client {
            principal, serving, request: ControlRequest::Snapshot,
        }).await;
        let Outcome::Client(ControlResponse::SnapshotEnvelope(envelope)) = snapshot_response else {
            panic!("{snapshot_response:?}");
        };
        cat4igp_shared::control::open_topology_snapshot(
            &initial.signing_key, &crate::hex_encode(&client_secret.to_bytes()),
            "forward-test", envelope.meta.recipient_node_id,
            chrono::Utc::now().timestamp_millis(), &envelope,
        ).unwrap();
        let envelope = cat4igp_shared::control::seal_tunnel_answer(
            &client_key, &initial.encryption_key,
            cat4igp_shared::control::MessageMeta {
                message_id: "cd".repeat(16), network_id: "forward-test".into(),
                recipient_node_id: original_enrollment["node_id"].as_i64().unwrap() as i32,
                issued_at_ms: now, expires_at_ms: now + 60_000, topology_revision: 0,
            }, &cat4igp_shared::control::TunnelAnswer { tunnel_id: 999, decline_type: Some(1), endpoint: None },
        ).unwrap();
        let mut forged = envelope.clone(); forged.signature = "00".into();
        assert!(matches!(services[follower].submit(Operation::AffectedSnapshots {
            principal, serving, envelope: forged.clone(),
        }).await, Outcome::Unavailable));
        assert!(matches!(services[follower].submit(Operation::Client {
            principal, serving, request: ControlRequest::TunnelAnswerEnvelope(forged),
        }).await, Outcome::Client(ControlResponse::Rejected(_))));
        assert!(matches!(services[follower].submit(Operation::Client {
            principal, serving, request: ControlRequest::TunnelAnswerEnvelope(envelope.clone()),
        }).await, Outcome::Client(ControlResponse::Rejected(_))));
        assert!(matches!(services[follower].submit(Operation::AffectedSnapshots {
            principal, serving, envelope,
        }).await, Outcome::AffectedSnapshots(envelopes) if envelopes.is_empty()));
        use openraft::RaftSnapshotBuilder;
        let mut snapshot_store = stores[leader].clone();
        let snapshot = snapshot_store.build_snapshot().await.unwrap();
        let restored_path = root.join("enrollment-snapshot.sqlite").to_str().unwrap().to_owned();
        let mut conn = diesel::SqliteConnection::establish(&restored_path).unwrap();
        crate::db::migrate(&mut conn, true).unwrap(); drop(conn);
        let mut restored = Store::open(restored_path).await.unwrap();
        restored.install_snapshot(&snapshot.meta, snapshot.snapshot).await.unwrap();
        let restored_code = restored.run(read_code).await.unwrap().unwrap();
        assert!(restored_code == rotated);
        let retry_admission = Admission { source: join_peer, request: join_request.clone(), at_ms: rotated.expires_at_ms };
        restored.run(move |conn| {
            assert_eq!(crate::db::get_setting(conn, "replica_pending_admissions")?, durable);
            assert!(read_revocations(conn)?.get(&9).unwrap().complete);
            assert!(apply_admission(conn, &retry_admission)?.is_err());
            Ok(())
        }).await.unwrap();
        let expected_answered = answered.clone();
        let wire_peer = wire_config.ensure_control_keypair().unwrap().public().to_peer_id();
        restored.run(move |conn| {
            let identity = crate::db::control_identity_for_peer(conn, &wire_peer.to_string())?;
            assert_eq!(identity.topology_revision, expected_answered.revision);
            assert_eq!(crate::db::apply_answer(conn, &crate::db::AnswerCommand {
                node_id: expected_answered.node_id, request_id: "ab".repeat(16),
                answer: cat4igp_shared::control::TunnelAnswer { tunnel_id, decline_type: None, endpoint: Some("127.0.0.1:51820".into()) },
                applied_at: chrono::Utc::now().naive_utc(),
            })?, "accepted");
            assert_eq!(crate::db::control_identity_for_peer(conn, &wire_peer.to_string())?.topology_revision, expected_answered.revision);
            let topology = crate::db::topology_snapshot(conn, expected_answered.node_id, expected_answered.revision)?;
            assert_eq!(serde_json::to_value(topology)?, serde_json::to_value(expected_answered)?);
            Ok(())
        }).await.unwrap();
        restored.run(move |conn| {
            assert_eq!(crate::db::control_identity_for_peer(conn, &principal.to_string())?.node_id, original_enrollment["node_id"].as_i64().unwrap() as i32);
            let ControlRequest::Enroll(request) = request else { unreachable!() };
            let authority = read_authority(conn)?;
            let allocation = crate::db::prepare_enrollment_allocation(conn, &request.invitation_code)?;
            let response = crate::db::apply_enrollment(conn, &crate::db::EnrollmentCommand {
                allocation,
                request, node_id: 999, auth_key: "unused-retry-selection".into(), applied_at: chrono::Utc::now().naive_utc(),
                response: cat4igp_shared::control::EnrollmentResponse { node_id: 999, topology_revision: 0,
                    network_id: authority.network_id, controller_signing_key: authority.signing_key,
                    controller_encryption_key: authority.encryption_key },
            })?.0;
            let ControlResponse::Enrolled(response) = response else { panic!("snapshot retry failed") };
            assert_eq!(serde_json::to_value(response)?, original_enrollment);
            Ok(())
        }).await.unwrap();
        drop(restored);
        nodes[leader].shutdown().await.unwrap();
        transports[leader].abort();
        let new_leader = loop {
            if let Some(id) = nodes.iter().enumerate().filter(|(i,_)| *i != leader).find_map(|(_,n)| n.metrics().borrow().current_leader.filter(|id| *id != leader as u64 + 1)) { break id as usize - 1; }
            tokio::task::yield_now().await;
        };
        let remaining_follower = (0..3).find(|i| *i != leader && *i != new_leader).unwrap();
        nodes[remaining_follower].wait(Some(DEADLINE)).current_leader(new_leader as u64 + 1, "failover").await.unwrap();
        let recovered = match services[remaining_follower].submit(Operation::ReplicaCode { rotate_generation: None }).await { Outcome::ReplicaCode(Ok(c)) => c, _ => panic!("failover code unavailable") };
        assert!(recovered == rotated);
        let failover_rotation = match services[remaining_follower].submit(Operation::ReplicaCode { rotate_generation: Some(rotated.generation) }).await { Outcome::ReplicaCode(Ok(c)) => c, _ => panic!("failover rotation unavailable") };
        assert_eq!(failover_rotation.generation, rotated.generation + 1);
        // Reload the pre-send identity/request, not the completed enrollment.
        let completed_config = wire_config;
        let mut wire_config = crate::client_config::ServerConfig::load(&pending_directory).unwrap();
        assert_eq!(wire_config.control_node_id, None);
        assert_eq!(wire_config.control_private_key, completed_config.control_private_key);
        assert_eq!(wire_config.control_encryption_private_key, completed_config.control_encryption_private_key);
        assert_eq!(wire_config.controller_signing_key, completed_config.controller_signing_key);
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let private_address: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", socket.local_addr().unwrap().port()).parse().unwrap();
        drop(socket);
        let recovered_replica = (0..3).find(|i| *i != leader && *i != follower).unwrap();
        let recovered_serving = keys[recovered_replica].public().to_peer_id();
        assert_ne!(recovered_serving, serving);
        let endpoint = private_address.clone().with(libp2p::multiaddr::Protocol::P2p(recovered_serving)).to_string();
        roster.revision += 1;
        roster.issued_at_ms = chrono::Utc::now().timestamp_millis();
        roster.expires_at_ms = (roster.expires_at_ms + 1).max(roster.issued_at_ms + 240_000);
        roster.controllers[recovered_replica].addresses = vec![endpoint.parse().unwrap()];
        assert!(matches!(services[remaining_follower].submit(Operation::Roster(roster.clone())).await, Outcome::Roster(Ok(()))));
        let wire_peer = wire_config.ensure_control_keypair().unwrap().public().to_peer_id();
        let proof = match services[recovered_replica].submit(Operation::Discovery {
            query: FindControllers::new("forward-test".into(), Role::Client, wire_peer, chrono::Utc::now().timestamp_millis()).unwrap(),
            source: wire_peer, serving: recovered_serving,
        }).await { Outcome::Discovery(Ok(proof)) => proof, other => panic!("{other:?}") };
        wire_config.accept_discovery_proof(proof, chrono::Utc::now().timestamp_millis()).unwrap();
        wire_config.save(&pending_directory).unwrap();
        let listener_service = services[recovered_replica].clone();
        let listener_key = keys[recovered_replica].clone();
        let recovered_listener = tokio::spawn(async move {
            private_control_at(listener_service, listener_key, &private_address.to_string(), libp2p::pnet::PreSharedKey::new([0x12; 32])).await
        });
        let recovered_response = crate::client_control::enroll(&mut wire_config, &[endpoint], "wire-client".into()).await.unwrap();
        assert_eq!(serde_json::to_value(&wire_response).unwrap(), serde_json::to_value(recovered_response).unwrap());
        wire_config.save(&pending_directory).unwrap();
        let wire_config = crate::client_config::ServerConfig::load(&pending_directory).unwrap();
        let (updates, _updates_rx) = tokio::sync::mpsc::channel(1);
        let current = std::sync::Arc::new(tokio::sync::Mutex::new(Some(wire_config.clone())));
        let control = crate::client_control::start(wire_config.clone(), updates, current).unwrap();
        let response = control.request(ControlRequest::Snapshot).await.unwrap();
        let ControlResponse::SnapshotEnvelope(envelope) = response else { panic!("{response:?}"); };
        let topology = cat4igp_shared::control::open_topology_snapshot(
            wire_config.controller_signing_key.as_deref().unwrap(),
            wire_config.control_encryption_private_key.as_deref().unwrap(),
            &wire_config.control_network_id, wire_config.control_node_id.unwrap(),
            chrono::Utc::now().timestamp_millis(), &envelope,
        ).unwrap();
        assert_eq!(topology.node_id, completed_config.control_node_id.unwrap());
        assert_eq!(serde_json::to_value(&topology).unwrap(), serde_json::to_value(&answered).unwrap());
        assert!(matches!(control.request(ControlRequest::TunnelAnswerEnvelope(signed_answer.clone())).await.unwrap(), ControlResponse::Accepted));
        let response = control.request(ControlRequest::Snapshot).await.unwrap();
        let ControlResponse::SnapshotEnvelope(retried) = response else { panic!("{response:?}"); };
        assert_eq!(retried.meta.topology_revision, answered.revision);
        // A rejected signed request over the real wire must not mutate topology.
        let mut unauthorized_answer = cat4igp_shared::control::seal_tunnel_answer(
            &wire_config.clone().ensure_control_keypair().unwrap(),
            wire_config.controller_encryption_key.as_deref().unwrap(),
            cat4igp_shared::control::MessageMeta {
                message_id: "ef".repeat(16),
                network_id: wire_config.control_network_id.clone(),
                recipient_node_id: topology.node_id,
                issued_at_ms: chrono::Utc::now().timestamp_millis(),
                expires_at_ms: chrono::Utc::now().timestamp_millis() + 60_000,
                topology_revision: 0,
            },
            &cat4igp_shared::control::TunnelAnswer {
                tunnel_id: 999, decline_type: Some(1), endpoint: None,
            },
        ).unwrap();
        assert!(matches!(control.request(ControlRequest::TunnelAnswerEnvelope(unauthorized_answer.clone())).await.unwrap(), ControlResponse::Rejected(_)));
        unauthorized_answer.signature = "00".into();
        assert!(matches!(control.request(ControlRequest::TunnelAnswerEnvelope(unauthorized_answer)).await.unwrap(), ControlResponse::Rejected(_)));
        let response = control.request(ControlRequest::Snapshot).await.unwrap();
        let ControlResponse::SnapshotEnvelope(after_rejection) = response else { panic!("{response:?}"); };
        assert_eq!(after_rejection.meta.topology_revision, envelope.meta.topology_revision);
        drop(control);
        recovered_listener.abort();
        assert!(recovered_listener.await.unwrap_err().is_cancelled());
        assert!(matches!(services[remaining_follower].submit(operation).await, Outcome::Invite(Ok(retry)) if retry == code));
        let mut enrollment = enrollment;
        if let Operation::Client { serving, .. } = &mut enrollment {
            *serving = keys[remaining_follower].public().to_peer_id();
        }
        assert!(matches!(services[remaining_follower].submit(enrollment.clone()).await,
            Outcome::Client(ControlResponse::Enrolled(_))));
        assert!(matches!(services[remaining_follower].submit(Operation::Client {
            principal, serving: keys[remaining_follower].public().to_peer_id(),
            request: ControlRequest::Snapshot,
        }).await, Outcome::Client(ControlResponse::SnapshotEnvelope(_))));
        let committed = nodes[new_leader].metrics().borrow().last_applied.unwrap().index;
        nodes[remaining_follower].wait(Some(DEADLINE)).applied_index(Some(committed), "enrollment replicated after failover").await.unwrap();
        for i in [new_leader, remaining_follower] {
            stores[i].run(|conn| {
                use diesel::prelude::*;
                assert_eq!(crate::schema::nodes::table.count().get_result::<i64>(conn)?, 2);
                assert_eq!(crate::db::get_invites(conn)?[0].used_count, 1);
                Ok(())
            }).await.unwrap();
        }
        assert_eq!(stores[new_leader].run(|conn| Ok(crate::db::get_invites(conn)?.len())).await.unwrap(), 2);
        let prepared = credential("forward-test", 1, libp2p::pnet::PreSharedKey::new([77;32]));
        assert!(matches!(services[remaining_follower].submit(Operation::PrepareTransport(prepared.clone())).await, Outcome::Transport(Ok(_))));
        assert!(matches!(services[remaining_follower].submit(Operation::PrepareTransport(prepared.clone())).await, Outcome::Transport(Ok(_))));
        let conflict = credential("forward-test", 1, libp2p::pnet::PreSharedKey::new([78;32]));
        assert!(matches!(services[remaining_follower].submit(Operation::PrepareTransport(conflict)).await, Outcome::Transport(Err(_))));
        assert!(matches!(services[remaining_follower].submit(Operation::CompleteTransport).await, Outcome::Transport(Err(_))));
        assert!(matches!(services[remaining_follower].submit(Operation::Join { source: join_peer, request: join_request.clone() }).await, Outcome::Join(cat4igp_shared::discovery::join::Response::Unavailable)));
        assert_eq!(services[new_leader].cluster_psk.to_key_file(), libp2p::pnet::PreSharedKey::new([19;32]).to_key_file());
        nodes[remaining_follower].shutdown().await.unwrap();
        transports[remaining_follower].abort();
        assert!(!matches!(services[new_leader].submit(Operation::Ready).await, Outcome::Ready));
        assert!(!matches!(services[new_leader].submit(Operation::GrantServing(grant)).await, Outcome::Roster(Ok(()))));
        let minority = Operation::Invite { request_id: "minority-refused".into(), expires_at: None, max_uses: Some(1), join_mesh: None };
        assert!(matches!(services[new_leader].submit(Operation::Join { source: join_peer, request: join_request }).await, Outcome::Unavailable));
        assert!(matches!(services[new_leader].submit(Operation::ReplicaCode { rotate_generation: Some(failover_rotation.generation) }).await, Outcome::Unavailable));
        assert!(matches!(services[new_leader].submit(Operation::VerifyReplicaCode(failover_rotation.code.clone())).await, Outcome::Unavailable));
        assert!(stores[new_leader].run(read_code).await.unwrap().unwrap() == failover_rotation);
        assert!(!matches!(services[new_leader].submit(minority.clone()).await, Outcome::Invite(Ok(_))));
        assert!(!matches!(services[new_leader].submit(minority).await, Outcome::Invite(Ok(_))));
        assert!(!matches!(services[new_leader].submit(Operation::PrepareTransport(prepared)).await, Outcome::Transport(Ok(_))));
        let before = stores[new_leader].run(read_authority).await.unwrap().roster;
        assert!(matches!(services[new_leader].submit(Operation::RenewRoster).await, Outcome::Unavailable));
        assert_eq!(serde_json::to_value(stores[new_leader].run(read_authority).await.unwrap().roster).unwrap(), serde_json::to_value(before).unwrap());
        assert!(!matches!(services[new_leader].submit(Operation::ActivateLearner(9)).await, Outcome::Learner(Ok(()))));
        let membership_before = nodes[new_leader].metrics().borrow().membership_config.clone();
        let revoked_before = stores[new_leader].run(read_revocations).await.unwrap();
        let offline_id = nodes[remaining_follower].metrics().borrow().id;
        assert!(!matches!(services[new_leader].submit(Operation::RevokeReplica(offline_id)).await, Outcome::Revocation(Ok(()))));
        assert_eq!(serde_json::to_string(&stores[new_leader].run(read_revocations).await.unwrap()).unwrap(), serde_json::to_string(&revoked_before).unwrap());
        assert!(!matches!(services[new_leader].submit(Operation::PromoteLearner(9)).await, Outcome::Promotion(Ok(()))));
        assert_eq!(nodes[new_leader].metrics().borrow().membership_config, membership_before);
        assert!(nodes[new_leader].metrics().borrow().running_state.is_ok());
        assert!(!matches!(services[new_leader].submit(Operation::Authority).await, Outcome::Authority(Ok(_))));
        assert!(!matches!(services[new_leader].submit(enrollment).await, Outcome::Client(ControlResponse::Enrolled(_))));
        assert!(!matches!(services[new_leader].submit(Operation::Client {
            principal, serving: keys[new_leader].public().to_peer_id(), request: ControlRequest::Snapshot,
        }).await, Outcome::Client(ControlResponse::SnapshotEnvelope(_))));
        assert!(!matches!(services[new_leader].submit(Operation::Client {
            principal: wire_peer, serving: keys[new_leader].public().to_peer_id(),
            request: ControlRequest::TunnelAnswerEnvelope(signed_answer.clone()),
        }).await, Outcome::Client(ControlResponse::Accepted)));
        assert!(matches!(services[new_leader].submit(Operation::AffectedSnapshots {
            principal: wire_peer, serving: keys[new_leader].public().to_peer_id(), envelope: signed_answer,
        }).await, Outcome::Unavailable));
        assert_eq!(stores[new_leader].run(move |conn| {
            Ok(crate::db::control_identity_for_peer(conn, &wire_peer.to_string())?.topology_revision)
        }).await.unwrap(), answered.revision);
        let query = FindControllers::new("forward-test".into(), Role::Client, requester.public().to_peer_id(), chrono::Utc::now().timestamp_millis()).unwrap();
        assert!(!matches!(services[new_leader].submit(Operation::Discovery { source: query.requester, query, serving: keys[new_leader].public().to_peer_id() }).await, Outcome::Discovery(Ok(_))));
        roster.revision = 3; roster.expires_at_ms += 1;
        assert!(!matches!(services[new_leader].submit(Operation::Roster(roster)).await, Outcome::Roster(Ok(()))));
        assert_eq!(stores[new_leader].run(|conn| Ok(crate::db::get_invites(conn)?.len())).await.unwrap(), 2);
        nodes[new_leader].shutdown().await.unwrap();
        for scheduler in schedulers { scheduler.abort(); }
        transports[new_leader].abort();
        responder.abort();
        assert!(responder.await.unwrap_err().is_cancelled());
        drop(services); drop(nodes); drop(stores);
        std::fs::remove_dir_all(root).unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn legacy_import_existing_client_cutover() {
    use cat4igp_shared::control::{
        ControlRequest, ControlResponse, EnrollmentRequest, EnrollmentResponse,
    };
    use cat4igp_shared::discovery::{ControllerEndpoint, FindControllers, Role, transport};
    use diesel::connection::SimpleConnection;
    use futures_util::StreamExt;
    tokio::time::timeout(Duration::from_secs(90), async {
        // ponytail: three real in-process voters and Node::shutdown, not SIGKILL, WireGuard traffic or power loss.
        let root = std::env::temp_dir().join(format!("cat4igp-cutover-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("legacy.sqlite");
        let client_dir = root.join("client");
        let logical = new_authority("cutover-test".into(), BTreeMap::new()).identity;
        let mut conn = diesel::SqliteConnection::establish(source.to_str().unwrap()).unwrap();
        crate::db::configure_connection(&mut conn).unwrap();
        use diesel::{migration::MigrationSource, QueryDsl, RunQueryDsl};
        use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
        const HISTORICAL: EmbeddedMigrations = embed_migrations!("migrations");
        let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&HISTORICAL).unwrap();
        migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
        assert!(conn.applied_migrations().unwrap().is_empty());
        conn.run_migrations(&migrations[..8]).unwrap();
        crate::db::apply_initialization(&mut conn, &logical).unwrap();
        let before = read_authority(&mut conn).unwrap();
        let pin = libp2p::identity::PublicKey::try_decode_protobuf(&crate::hex_decode(&before.signing_key).unwrap()).unwrap();
        let legacy_endpoint = format!("/ip4/127.0.0.1/tcp/1/p2p/{}", pin.to_peer_id());
        let mut config = crate::client_config::ServerConfig::new(legacy_endpoint.clone(), "".into());
        config.controller_peer_id = Some(pin.to_peer_id().to_string());
        config.controller_signing_key = Some(before.signing_key.clone());
        config.controller_encryption_key = Some(before.encryption_key.clone());
        config.control_network_id = before.network_id.clone();
        config.control_bootstrap_addresses = vec![legacy_endpoint];
        config.control_private_network_key = Some(format!("/key/swarm/psk/1.0.0/\n/base16/\n{}", "12".repeat(32)));
        config.ensure_wireguard_keypair().unwrap();
        let client_key = config.ensure_control_keypair().unwrap();
        let encryption = config.ensure_control_encryption_key().unwrap();
        conn.batch_execute("INSERT INTO invites(id,code,max_uses,override_join_mesh,created_at) VALUES(1,'legacy-invite',1,1,'2026-01-01 00:00:00'); INSERT INTO mesh_groups(id,name,auto_wireguard,auto_wireguard_mtu,created_at) VALUES(1,'legacy-mesh',1,1280,'2026-01-01 00:00:00'); INSERT INTO nodes(id,name,auth_key,created_at) VALUES(1,'other','other-auth','2026-01-01 00:00:00'); INSERT INTO node_control_identities(node_id,peer_id,signing_key,encryption_key,created_at,updated_at) VALUES(1,'other-peer','other-signing','other-encryption','2026-01-01 00:00:00','2026-01-01 00:00:00'); INSERT INTO mesh_group_memberships(mesh_group_id,node_id,created_at) VALUES(1,1,'2026-01-01 00:00:00'); INSERT INTO wireguard_static_key(node_id,public_key) VALUES(1,'other-wg');").unwrap();
        let command = crate::db::EnrollmentCommand {
            allocation: crate::db::prepare_enrollment_allocation(&mut conn, "legacy-invite").unwrap(),
            request: EnrollmentRequest {
                request_id: "old-enrollment".into(), node_name: "existing-client".into(), invitation_code: "legacy-invite".into(),
                client_peer_id: client_key.public().to_peer_id().to_string(),
                client_signing_key: crate::hex_encode(&client_key.public().encode_protobuf()),
                client_encryption_key: encryption,
                wireguard_public_key: config.wg_public_key.clone().unwrap(),
            },
            node_id: 42, auth_key: "preserved-auth".into(), applied_at: chrono::Utc::now().naive_utc(),
            response: EnrollmentResponse { node_id: 42, topology_revision: 0, network_id: before.network_id.clone(), controller_signing_key: before.signing_key.clone(), controller_encryption_key: before.encryption_key.clone() },
        };
        assert!(matches!(crate::db::apply_enrollment(&mut conn, &command).unwrap().0, ControlResponse::Enrolled(_)));
        conn.batch_execute("UPDATE node_control_identities SET topology_revision=73 WHERE node_id=42").unwrap();
        // Actual previous schema: enrolled identity, consumed invite and retry result survive upgrade.
        assert_eq!(conn.applied_migrations().unwrap().len(), 8);
        assert!(crate::db::migrate(&mut conn, false).is_err());
        crate::db::migrate(&mut conn, true).unwrap();
        assert_eq!(conn.applied_migrations().unwrap().len(), 9);
        assert_eq!(read_authority(&mut conn).unwrap().signing_key, before.signing_key);
        assert_eq!(read_authority(&mut conn).unwrap().encryption_key, before.encryption_key);
        assert_eq!(crate::db::control_identity_for_peer(&mut conn, &command.request.client_peer_id).unwrap().topology_revision, 73);
        assert!(matches!(crate::db::apply_enrollment(&mut conn, &command).unwrap().0, ControlResponse::Enrolled(_)));
        assert_eq!(crate::schema::invites::table.select(crate::schema::invites::used_count).first::<i32>(&mut conn).unwrap(), 1);
        config.control_node_id = Some(42);
        config.topology_revision = 73;
        let expected = crate::db::topology_snapshot(&mut conn, 42, 73).unwrap();
        assert!(!expected.tunnels.is_empty());
        config.save(&client_dir).unwrap();
        // Actual pre-HA JSON lacks these fields. Loading must default them, not replace pins/identity.
        let mut old_json = serde_json::to_value(&config).unwrap();
        old_json.as_object_mut().unwrap().remove("discovery_proof");
        old_json.as_object_mut().unwrap().remove("discovery_bootstrap_addresses");
        old_json.as_object_mut().unwrap().remove("control_bootstrap_addresses");
        let config_file = client_dir.join("server.json");
        std::fs::write(&config_file, serde_json::to_vec(&old_json).unwrap()).unwrap();
        let mut config = crate::client_config::ServerConfig::load(&client_dir).unwrap();
        let preserved = serde_json::to_value(&config).unwrap();
        let identity_file = root.join("replica.key");
        let key = crate::raft_network::replica_identity(&identity_file).unwrap();
        let serving = key.public().to_peer_id();
        assert_ne!(serving, pin.to_peer_id());
        let raft_socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let raft_address: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", raft_socket.local_addr().unwrap().port()).parse().unwrap();
        drop(raft_socket);
        drop(conn); // Offline source before invoking the real import/start path.
        assert!(crate::raft_storage::verify_recovery(source.to_str().unwrap(), "database", "cutover-test", &before.signing_key, &before.encryption_key).unwrap().contains("legacy-application"));
        let (node, store, cluster_task, service) = start(Config {
            cluster_id: "cutover-test".into(), node_id: 1, mode: Mode::Initialize,
            identity_file: identity_file.to_str().unwrap().into(), listen: raft_address.clone(),
            replicas: BTreeMap::from([(1, Replica { peer_id: serving, address: raft_address })]),
            learner: None, cluster_psk: None, transport_generation: 0,
            legacy_import: Some(LegacyImport { source: source.to_str().unwrap().into(), backup: root.join("backup.sqlite").to_str().unwrap().into() }),
        }, root.join("raft.sqlite").to_str().unwrap().into(), libp2p::pnet::PreSharedKey::new([9;32])).await.unwrap();
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let private_address = format!("/ip4/127.0.0.1/tcp/{}", socket.local_addr().unwrap().port());
        drop(socket);
        let endpoint: libp2p::Multiaddr = format!("{private_address}/p2p/{serving}").parse().unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        assert!(matches!(service.submit(Operation::Roster(ControllerRoster {
            version: 1, cluster_id: "cutover-test".into(), revision: 1, issued_at_ms: now, expires_at_ms: now+120_000,
            controllers: vec![ControllerEndpoint { peer_id: serving, addresses: vec![endpoint.clone()] }],
            discovery_endpoints: vec![],
        })).await, Outcome::Roster(Ok(()))));
        let mut public = transport::swarm(&key).unwrap();
        public.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
        let seed = loop {
            if let libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } = public.select_next_some().await {
                break address.with(libp2p::multiaddr::Protocol::P2p(serving)).to_string();
            }
        };
        let discovery_service = service.clone();
        let responder = tokio::spawn(async move {
            transport::serve_with_join(public, "cutover-test", move |query, source| {
                let service = discovery_service.clone();
                async move { match service.submit(Operation::Discovery { query, source, serving }).await {
                    Outcome::Discovery(result) => result, _ => Err("unavailable".into()),
                } }
            }, |_, _| async { cat4igp_shared::discovery::join::Response::Unavailable }).await
        });
        config.discovery_bootstrap_addresses = vec![seed]; // Explicit operator-provided reachability, never a new pin.
        assert!(!config.control_peer_authorized(serving, now));
        crate::client_control::refresh_discovery(&mut config).await.unwrap();
        assert_eq!(config.control_bootstrap_addresses, vec![endpoint.to_string()]);
        assert_eq!(config.discovery_proof.as_ref().unwrap().body.roster.body.revision, 1);
        let mut wrong_pin = config.clone();
        let untrusted = libp2p::identity::Keypair::generate_ed25519();
        wrong_pin.controller_peer_id = Some(untrusted.public().to_peer_id().to_string());
        wrong_pin.controller_signing_key = Some(crate::hex_encode(&untrusted.public().encode_protobuf()));
        assert!(wrong_pin.accept_discovery_proof(config.discovery_proof.clone().unwrap(), chrono::Utc::now().timestamp_millis()).is_err());
        let mut forged = config.discovery_proof.clone().unwrap();
        forged.body.roster.body.revision += 1;
        let accepted = serde_json::to_value(&config).unwrap();
        assert!(config.accept_discovery_proof(forged, chrono::Utc::now().timestamp_millis()).is_err());
        assert_eq!(serde_json::to_value(&config).unwrap(), accepted);
        config.save(&client_dir).unwrap(); // Same atomic save-before-start sequence as the shipped daemon.
        let config = crate::client_config::ServerConfig::load(&client_dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&config_file).unwrap().permissions().mode() & 0o777, 0o600);
        let after = serde_json::to_value(&config).unwrap();
        for field in ["controller_peer_id", "controller_signing_key", "controller_encryption_key", "control_private_key", "control_encryption_private_key", "wg_private_key", "wg_public_key", "control_node_id", "control_network_id", "topology_revision"] {
            assert_eq!(preserved[field], after[field], "changed {field}");
        }
        let listener_service = service.clone();
        let listener = tokio::spawn(async move { private_control_at(listener_service, key, &private_address, libp2p::pnet::PreSharedKey::new([0x12;32])).await });
        let (updates, _received) = tokio::sync::mpsc::channel(1);
        let current = Arc::new(tokio::sync::Mutex::new(Some(config.clone())));
        let control = crate::client_control::start(config.clone(), updates, current).unwrap();
        let envelope = match control.request(ControlRequest::Snapshot).await.unwrap() {
            ControlResponse::SnapshotEnvelope(envelope) => envelope, other => panic!("{other:?}"),
        };
        let snapshot = cat4igp_shared::control::open_topology_snapshot(&before.signing_key, config.control_encryption_private_key.as_deref().unwrap(), "cutover-test", 42, chrono::Utc::now().timestamp_millis(), &envelope).unwrap();
        assert_eq!(serde_json::to_value(&snapshot).unwrap(), serde_json::to_value(&expected).unwrap());
        // Admit and activate empty learners through the shipped committed helpers, never initialize extra voters.
        use cat4igp_shared::discovery::join::{Request as JoinRequest, Response as JoinResponse};
        let code = match service.submit(Operation::ReplicaCode { rotate_generation: None }).await {
            Outcome::ReplicaCode(Ok(code)) => code, other => panic!("{other:?}"),
        };
        let mut learners = Vec::new();
        let mut learner_keys = Vec::new();
        for id in 2..=3 {
            let identity = root.join(format!("replica-{id}.key"));
            let key = crate::raft_network::replica_identity(&identity).unwrap();
            let peer = key.public().to_peer_id();
            let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", socket.local_addr().unwrap().port()).parse().unwrap();
            let request = JoinRequest { application_version: cat4igp_shared::discovery::join::APPLICATION_VERSION, cluster_id: "cutover-test".into(), request_id: format!("cutover-join-{id}"), node_id: id,
                address: address.clone().with(libp2p::multiaddr::Protocol::P2p(peer)), code: code.code.clone() };
            let pending = match service.submit(Operation::Join { source: peer, request: request.clone() }).await {
                Outcome::Join(response @ JoinResponse::Bootstrap { .. }) => response, other => panic!("{other:?}"),
            };
            let path = root.join(format!("replica-{id}.json"));
            save_join(path.to_str().unwrap(), identity.to_str().unwrap().into(), address, &request, &pending).unwrap();
            let selected: Config = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            let psk = selected.cluster_psk.as_ref().unwrap().parse().unwrap();
            let database = root.join(format!("replica-{id}.sqlite"));
            let mut conn = diesel::SqliteConnection::establish(database.to_str().unwrap()).unwrap();
            crate::db::migrate(&mut conn, true).unwrap(); drop(conn); drop(socket);
            assert!(matches!(service.submit(Operation::ActivateLearner(id)).await, Outcome::Learner(Ok(()))));
            let running = start(selected, database.to_str().unwrap().into(), psk).await.unwrap();
            let index = node.metrics().borrow().last_applied.unwrap().index;
            running.0.wait(Some(DEADLINE)).applied_index(Some(index), "imported learner caught up").await.unwrap();
            assert!(!node.metrics().borrow().membership_config.membership().voter_ids().any(|v| v == id));
            tokio::time::timeout(DEADLINE, async {
                loop {
                    if matches!(service.submit(Operation::PromoteLearner(id)).await, Outcome::Promotion(Ok(()))) { break; }
                    tokio::task::yield_now().await;
                }
            }).await.expect("caught-up learner promotion");
            learners.push(running); learner_keys.push(key);
        }
        assert_eq!(node.metrics().borrow().membership_config.membership().get_joint_config(), &vec![std::collections::BTreeSet::from([1,2,3])]);
        node.wait(Some(DEADLINE)).current_leader(1, "original imported leader").await.unwrap();
        let recovered_serving = learner_keys[0].public().to_peer_id();
        assert_ne!(recovered_serving, serving);
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let recovered_private = format!("/ip4/127.0.0.1/tcp/{}", socket.local_addr().unwrap().port());
        drop(socket);
        let recovered_endpoint: libp2p::Multiaddr = format!("{recovered_private}/p2p/{recovered_serving}").parse().unwrap();
        let mut public = transport::swarm(&learner_keys[0]).unwrap();
        public.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
        let recovered_seed = loop {
            if let libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } = public.select_next_some().await {
                break address.with(libp2p::multiaddr::Protocol::P2p(recovered_serving));
            }
        };
        let now = chrono::Utc::now().timestamp_millis();
        assert!(matches!(service.submit(Operation::Roster(ControllerRoster {
            version: 1, cluster_id: "cutover-test".into(), revision: 2, issued_at_ms: now, expires_at_ms: now+120_000,
            controllers: vec![ControllerEndpoint { peer_id: serving, addresses: vec![endpoint] },
                ControllerEndpoint { peer_id: recovered_serving, addresses: vec![recovered_endpoint.clone(), recovered_seed.clone()] }],
            discovery_endpoints: vec![ControllerEndpoint { peer_id: recovered_serving, addresses: vec![recovered_seed.clone()] }],
        })).await, Outcome::Roster(Ok(()))));
        let index = node.metrics().borrow().last_applied.unwrap().index;
        for (replica, _, _, _) in &learners {
            replica.wait(Some(DEADLINE)).applied_index(Some(index), "three-voter serving roster committed").await.unwrap();
            assert_eq!(replica.metrics().borrow().membership_config.membership().get_joint_config(), &vec![std::collections::BTreeSet::from([1,2,3])]);
        }
        drop(control);
        listener.abort(); responder.abort();
        assert!(listener.await.unwrap_err().is_cancelled());
        assert!(responder.await.unwrap_err().is_cancelled());
        node.shutdown().await.unwrap(); cluster_task.abort();
        assert!(cluster_task.await.unwrap_err().is_cancelled());
        let elected = tokio::time::timeout(DEADLINE, async {
            loop {
                if let Some(id) = learners.iter().find_map(|r| r.0.metrics().borrow().current_leader.filter(|id| *id != 1)) {
                    if learners[id as usize - 2].0.ensure_linearizable().await.is_ok() { break id; }
                }
                tokio::task::yield_now().await;
            }
        }).await.expect("remaining majority elects and serves");
        for (replica, _, _, _) in &learners {
            replica.wait(Some(DEADLINE)).current_leader(elected, "surviving replica knows new leader").await.unwrap();
        }
        tokio::time::timeout(DEADLINE, async {
            loop {
                let query = FindControllers::new("cutover-test".into(), Role::Client, client_key.public().to_peer_id(), chrono::Utc::now().timestamp_millis()).unwrap();
                match learners[0].3.submit(Operation::Discovery { source: query.requester, query, serving: recovered_serving }).await {
                    Outcome::Discovery(Ok(_)) => break,
                    Outcome::Unavailable => tokio::task::yield_now().await,
                    other => panic!("{other:?}"),
                }
            }
        }).await.expect("recovered serving replica becomes authoritative");
        let discovery_service = learners[0].3.clone();
        let mut responder = tokio::spawn(async move {
            transport::serve_with_join(public, "cutover-test", move |query, source| {
                let service = discovery_service.clone();
                async move { match service.submit(Operation::Discovery { query, source, serving: recovered_serving }).await {
                    Outcome::Discovery(result) => {
                        if let Err(error) = &result { eprintln!("cutover discovery authority: {error}"); }
                        result
                    }, other => { eprintln!("cutover discovery outcome: {other:?}"); Err("unavailable".into()) },
                } }
            }, |_, _| async { JoinResponse::Unavailable }).await
        });
        let mut config = crate::client_config::ServerConfig::load(&client_dir).unwrap();
        config.discovery_bootstrap_addresses = vec![recovered_seed.to_string()]; // Operator reachability only; original pins unchanged.
        tokio::select! {
            result = crate::client_control::refresh_discovery(&mut config) => result.unwrap(),
            result = &mut responder => panic!("cutover discovery task stopped: {result:?}"),
        }
        assert_eq!(config.discovery_proof.as_ref().unwrap().body.endpoint.peer_id, recovered_serving);
        assert_eq!(config.discovery_proof.as_ref().unwrap().body.roster.body.revision, 2);
        config.save(&client_dir).unwrap();
        let config = crate::client_config::ServerConfig::load(&client_dir).unwrap();
        let after = serde_json::to_value(&config).unwrap();
        for field in ["controller_peer_id", "controller_signing_key", "controller_encryption_key", "control_private_key", "control_encryption_private_key", "wg_private_key", "wg_public_key", "control_node_id", "control_network_id", "topology_revision"] {
            assert_eq!(preserved[field], after[field], "failover changed {field}");
        }
        let listener_service = learners[0].3.clone();
        let listener_key = learner_keys[0].clone();
        let listener = tokio::spawn(async move { private_control_at(listener_service, listener_key, &recovered_private, libp2p::pnet::PreSharedKey::new([0x12;32])).await });
        let (updates, _received) = tokio::sync::mpsc::channel(1);
        let current = Arc::new(tokio::sync::Mutex::new(Some(config.clone())));
        let control = crate::client_control::start(config.clone(), updates, current).unwrap();
        let envelope = match control.request(ControlRequest::Snapshot).await.unwrap() {
            ControlResponse::SnapshotEnvelope(envelope) => envelope, other => panic!("{other:?}"),
        };
        let snapshot = cat4igp_shared::control::open_topology_snapshot(&before.signing_key, config.control_encryption_private_key.as_deref().unwrap(), "cutover-test", 42, chrono::Utc::now().timestamp_millis(), &envelope).unwrap();
        assert_eq!(serde_json::to_value(snapshot).unwrap(), serde_json::to_value(&expected).unwrap());
        for (_, replica_store, _, _) in &learners {
            let expected = serde_json::to_value(&expected).unwrap();
            let logical = logical.clone();
            replica_store.run(move |conn| {
                assert_eq!(crate::db::get_setting(conn, "control_private_key")?, logical.signing_private_key);
                assert_eq!(crate::db::get_setting(conn, "control_encryption_private_key")?, logical.encryption_private_key);
                assert_eq!(crate::db::get_node_list(conn)?.len(), 2);
                assert_eq!(crate::db::get_invites(conn)?[0].used_count, 1);
                assert_eq!(serde_json::to_value(crate::db::topology_snapshot(conn, 42, 73)?)?, expected);
                Ok(())
            }).await.unwrap();
        }
        store.run(move |conn| {
            let authority = read_authority(conn)?;
            assert_eq!(authority.signing_key, before.signing_key);
            assert_eq!(authority.encryption_key, before.encryption_key);
            assert_eq!(crate::db::get_setting(conn, "control_private_key")?, logical.signing_private_key);
            assert_eq!(crate::db::get_setting(conn, "control_encryption_private_key")?, logical.encryption_private_key);
            assert_eq!(crate::db::get_node_list(conn)?.len(), 2);
            assert_eq!(crate::db::get_invites(conn)?[0].used_count, 1);
            Ok(())
        }).await.unwrap();
        let mut source_conn = diesel::SqliteConnection::establish(source.to_str().unwrap()).unwrap();
        assert_eq!(serde_json::to_value(crate::db::topology_snapshot(&mut source_conn, 42, 73).unwrap()).unwrap(), serde_json::to_value(expected).unwrap());
        drop(source_conn);
        drop(control);
        listener.abort(); responder.abort();
        assert!(listener.await.unwrap_err().is_cancelled());
        assert!(responder.await.unwrap_err().is_cancelled());
        for (replica, _, task, _) in &learners { replica.shutdown().await.unwrap(); task.abort(); }
        for (_, _, task, _) in learners { assert!(task.await.unwrap_err().is_cancelled()); }
        drop(service); drop(node); drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn legacy_initialize_preserves_identity_revisions_and_retries() {
    use diesel::QueryDsl;
    use diesel::connection::SimpleConnection;
    use openraft::storage::RaftStateMachine;
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("cat4igp-import-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let source = root.join("legacy.sqlite").to_str().unwrap().to_owned();
    let backup = root.join("backup.sqlite").to_str().unwrap().to_owned();
    let destination = root.join("cluster.sqlite").to_str().unwrap().to_owned();
    let identity = root.join("replica.key").to_str().unwrap().to_owned();
    let key = crate::raft_network::replica_identity(std::path::Path::new(&identity)).unwrap();
    let logical = new_authority("import-test".into(), BTreeMap::new()).identity;
    let mut conn = diesel::SqliteConnection::establish(&source).unwrap();
    crate::db::configure_connection(&mut conn).unwrap();
    crate::db::migrate(&mut conn, true).unwrap();
    crate::db::apply_initialization(&mut conn, &logical).unwrap();
    conn.batch_execute("INSERT INTO nodes(id,name,auth_key,created_at) VALUES(42,'preserved','auth','2026-01-01 00:00:00'); INSERT INTO node_control_identities(node_id,peer_id,signing_key,encryption_key,topology_revision,created_at,updated_at) VALUES(42,'existing-peer','existing-key','existing-encryption',73,'2026-01-01 00:00:00','2026-01-01 00:00:00'); INSERT INTO control_enrollment_results(peer_id,request_id,fingerprint,result) VALUES('existing-peer','retry','fingerprint','original-response'); INSERT INTO invites(id,code,created_at,used_count) VALUES(7,'preserved-invite','2026-01-01 00:00:00',2);").unwrap();
    let before = read_authority(&mut conn).unwrap();
    let config = |mode, import: bool| Config {
        cluster_id: "import-test".into(),
        node_id: 1,
        mode,
        identity_file: identity.clone(),
        listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        replicas: BTreeMap::from([(
            1,
            Replica {
                peer_id: key.public().to_peer_id(),
                address: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
            },
        )]),
        learner: None,
        cluster_psk: None,
        transport_generation: 0,
        legacy_import: import.then(|| LegacyImport {
            source: source.clone(),
            backup: backup.clone(),
        }),
    };
    assert!(
        start(
            config(Mode::Join, true),
            destination.clone(),
            libp2p::pnet::PreSharedKey::new([9; 32])
        )
        .await
        .is_err()
    );
    assert!(!std::path::Path::new(&backup).exists());
    let (node, store, transport, _) = start(
        config(Mode::Initialize, true),
        destination.clone(),
        libp2p::pnet::PreSharedKey::new([9; 32]),
    )
    .await
    .unwrap();
    assert_eq!(
        std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let imported = store
        .run(|conn| {
            assert_eq!(
                crate::schema::node_control_identities::table
                    .find(42)
                    .select(crate::schema::node_control_identities::topology_revision)
                    .first::<i64>(conn)?,
                73
            );
            assert_eq!(crate::db::get_invites(conn)?[0].used_count, 2);
            Ok(read_authority(conn)?)
        })
        .await
        .unwrap();
    assert_eq!(before.signing_key, imported.signing_key);
    assert_eq!(before.encryption_key, imported.encryption_key);
    assert_eq!(before.network_id, imported.network_id);
    assert_ne!(
        key.public().to_peer_id().to_string(),
        libp2p::identity::PublicKey::try_decode_protobuf(
            &crate::hex_decode(&before.signing_key).unwrap()
        )
        .unwrap()
        .to_peer_id()
        .to_string()
    );
    assert!(
        start(
            config(Mode::Initialize, true),
            destination.clone(),
            libp2p::pnet::PreSharedKey::new([9; 32])
        )
        .await
        .is_err()
    );
    // Replay the same committed import on an independent empty store, then reject conflicts.
    let tables = crate::raft_storage::legacy_backup(
        &source,
        root.join("retry.sqlite").to_str().unwrap(),
        "import-test",
    )
    .unwrap();
    for name in ["replay.sqlite", "rollback.sqlite"] {
        let mut conn =
            diesel::SqliteConnection::establish(root.join(name).to_str().unwrap()).unwrap();
        crate::db::migrate(&mut conn, true).unwrap();
    }
    let mut replica = Store::open(root.join("replay.sqlite").to_str().unwrap().into())
        .await
        .unwrap();
    let entry = |index, tables| openraft::Entry {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), index),
        payload: openraft::EntryPayload::Normal(Command::LegacyImport(tables)),
    };
    assert!(
        replica
            .apply([entry(1, tables.clone()), entry(2, tables.clone())])
            .await
            .unwrap()
            .iter()
            .all(Result::is_ok)
    );
    let mut conflicting = tables.clone();
    conflicting[1][0][1] = serde_json::json!("different");
    assert!(replica.apply([entry(3, conflicting)]).await.unwrap()[0].is_err());
    let mut broken = tables.clone();
    broken[1][0] = serde_json::json!([]);
    let mut empty = Store::open(root.join("rollback.sqlite").to_str().unwrap().into())
        .await
        .unwrap();
    assert!(empty.apply([entry(1, broken)]).await.is_err());
    assert!(empty.apply([entry(1, tables)]).await.unwrap()[0].is_ok());
    assert!(crate::raft_storage::legacy_backup(&source, &backup, "import-test").is_err());
    assert!(
        crate::raft_storage::legacy_backup(
            &source,
            root.join("wrong.sqlite").to_str().unwrap(),
            "wrong"
        )
        .is_err()
    );
    assert_eq!(
        crate::schema::node_control_identities::table
            .find(42)
            .select(crate::schema::node_control_identities::topology_revision)
            .first::<i64>(&mut conn)
            .unwrap(),
        73
    );
    node.shutdown().await.unwrap();
    transport.abort();
    let (recovered, recovered_store, task, _) = start(
        config(Mode::Recover, false),
        destination.clone(),
        libp2p::pnet::PreSharedKey::new([9; 32]),
    )
    .await
    .unwrap();
    assert_eq!(
        recovered_store
            .run(|conn| Ok(crate::schema::node_control_identities::table
                .find(42)
                .select(crate::schema::node_control_identities::topology_revision)
                .first::<i64>(conn)?))
            .await
            .unwrap(),
        73
    );
    recovered.shutdown().await.unwrap();
    task.abort();
    assert!(
        crate::raft_storage::legacy_backup(
            &destination,
            root.join("reject-raft.sqlite").to_str().unwrap(),
            "import-test"
        )
        .is_err()
    );
    drop(conn);
    drop(store);
    drop(replica);
    drop(empty);
    drop(recovered_store);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn committed_route_reopens_and_minority_refuses() {
    let root = std::env::temp_dir().join(format!("cat4igp-runtime-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let database = root.join("replica.sqlite").to_str().unwrap().to_owned();
    let identity = root.join("replica.key").to_str().unwrap().to_owned();
    let key = crate::raft_network::replica_identity(std::path::Path::new(&identity)).unwrap();
    let mut conn = diesel::SqliteConnection::establish(&database).unwrap();
    crate::db::migrate(&mut conn, true).unwrap();
    drop(conn);
    let config = |mode| Config {
        learner: None,
        cluster_psk: None,
        transport_generation: 0,
        legacy_import: None,
        cluster_id: "runtime-test".into(),
        node_id: 1,
        mode,
        identity_file: identity.clone(),
        listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        replicas: BTreeMap::from([(
            1,
            Replica {
                peer_id: key.public().to_peer_id(),
                address: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
            },
        )]),
    };
    let (node, store, transport, service) = start(
        config(Mode::Initialize),
        database.clone(),
        libp2p::pnet::PreSharedKey::new([9; 32]),
    )
    .await
    .unwrap();
    let mut wrong = config(Mode::Recover);
    wrong.cluster_id = "wrong-cluster".into();
    assert!(
        start(
            wrong,
            database.clone(),
            libp2p::pnet::PreSharedKey::new([9; 32])
        )
        .await
        .is_err()
    );
    node.wait(Some(DEADLINE))
        .current_leader(1, "singleton elected")
        .await
        .unwrap();
    let original = store.run(read_authority).await.unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let roster = ControllerRoster {
        version: 1,
        cluster_id: "runtime-test".into(),
        revision: 1,
        issued_at_ms: now,
        expires_at_ms: now + 30_000,
        discovery_endpoints: vec![],
        controllers: vec![cat4igp_shared::discovery::ControllerEndpoint {
            peer_id: key.public().to_peer_id(),
            addresses: vec![
                "/ip4/127.0.0.1/tcp/1234"
                    .parse::<libp2p::Multiaddr>()
                    .unwrap()
                    .with(libp2p::multiaddr::Protocol::P2p(key.public().to_peer_id())),
            ],
        }],
    };
    let forged = roster
        .clone()
        .sign(&libp2p::identity::Keypair::generate_ed25519())
        .unwrap();
    assert!(
        node.client_write(Command::Roster(forged))
            .await
            .unwrap()
            .data
            .is_err()
    );
    assert!(matches!(
        service.submit(Operation::Roster(roster.clone())).await,
        Outcome::Roster(Ok(()))
    ));
    let saved = store.run(read_authority).await.unwrap();
    let mut update = roster.clone();
    update.revision = 2;
    update.issued_at_ms += 1;
    update.expires_at_ms += 1;
    let signed = store
        .run(move |conn| {
            let key = libp2p::identity::Keypair::from_protobuf_encoding(&crate::hex_decode(
                &crate::db::get_setting(conn, "control_private_key")?,
            )?)?;
            Ok(update.sign(&key)?)
        })
        .await
        .unwrap();
    store.run(move |conn| {
        diesel::sql_query("CREATE TEMP TRIGGER reject_roster BEFORE UPDATE ON settings WHEN NEW.key = 'controller_roster' BEGIN SELECT RAISE(ABORT, 'injected'); END").execute(conn)?;
        assert!(apply_roster(conn, &signed).is_err());
        diesel::sql_query("DROP TRIGGER reject_roster").execute(conn)?;
        Ok(())
    }).await.unwrap();
    assert_eq!(
        serde_json::to_value(store.run(read_authority).await.unwrap()).unwrap(),
        serde_json::to_value(&saved).unwrap()
    );
    let mut replacement = roster.clone();
    replacement.controllers[0].addresses = vec![
        "/ip4/127.0.0.1/tcp/5678"
            .parse::<libp2p::Multiaddr>()
            .unwrap()
            .with(libp2p::multiaddr::Protocol::P2p(key.public().to_peer_id())),
    ];
    assert!(matches!(
        service.submit(Operation::Roster(replacement)).await,
        Outcome::Roster(Err(_))
    ));
    assert!(matches!(
        service.submit(Operation::RevokeReplica(1)).await,
        Outcome::Revocation(Err(_))
    ));
    store.run(|conn| {
        // Serving withdrawal is atomic with the pending tombstone; an interrupted
        // operation retains transport and rejects both NodeId and PeerId reuse.
        let peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let mut admitted: BTreeMap<u64, libp2p::PeerId> = serde_json::from_str(&crate::db::get_setting(conn, "controller_admitted")?)?;
        admitted.insert(2, peer);
        setting(conn, "controller_admitted", &serde_json::to_string(&admitted)?)?;
        let mut roster = read_authority(conn)?.roster.unwrap().body;
        roster.controllers.push(cat4igp_shared::discovery::ControllerEndpoint {
            peer_id: peer, addresses: vec![format!("/ip4/127.0.0.1/tcp/1235/p2p/{peer}").parse()?],
        });
        let key = libp2p::identity::Keypair::from_protobuf_encoding(&crate::hex_decode(&crate::db::get_setting(conn, "control_private_key")?)?)?;
        let previous = roster.clone().sign(&key)?;
        setting(conn, "controller_roster", &serde_json::to_string(&previous)?)?;
        diesel::sql_query("CREATE TEMP TRIGGER reject_revocation BEFORE INSERT ON settings WHEN NEW.key = 'replica_revocations' BEGIN SELECT RAISE(ABORT, 'injected'); END").execute(conn)?;
        assert!(conn.immediate_transaction::<_, Box<dyn std::error::Error + Send + Sync>, _>(|conn| apply_revocation(conn, 2, false)).is_err());
        assert_eq!(serde_json::to_value(read_authority(conn)?.roster.unwrap())?, serde_json::to_value(&previous)?);
        assert!(read_revocations(conn)?.is_empty());
        diesel::sql_query("DROP TRIGGER reject_revocation").execute(conn)?;
        assert!(apply_revocation(conn, 2, false)?.is_ok());
        assert!(!read_revocations(conn)?.get(&2).unwrap().complete);
        let removed = read_authority(conn)?.roster.unwrap();
        assert!(!removed.body.controllers.iter().any(|e| e.peer_id == peer));
        removed.validate(&key.public(), "runtime-test", 1, removed.body.issued_at_ms)?;
        assert!(apply_revocation(conn, 2, false)?.is_ok());
        assert_eq!(serde_json::to_value(read_authority(conn)?.roster.unwrap())?, serde_json::to_value(&removed)?);
        let mut resurrect = removed.body.clone();
        resurrect.revision += 1; resurrect.expires_at_ms += 1;
        resurrect.controllers = previous.body.controllers;
        assert!(apply_roster(conn, &resurrect.sign(&key)?)?.is_err());
        assert!(apply_revocation(conn, 2, true)?.is_ok());
        // Restore unrelated singleton authority assertions without removing tombstones.
        admitted.remove(&2);
        setting(conn, "controller_admitted", &serde_json::to_string(&admitted)?)?;
        Ok(())
    }).await.unwrap();
    let withdrawn = store.run(read_authority).await.unwrap().roster.unwrap();
    assert!(matches!(
        service.submit(Operation::RenewRoster).await,
        Outcome::Roster(Ok(()))
    ));
    let renewed = store.run(read_authority).await.unwrap().roster.unwrap();
    assert_eq!(renewed.body.controllers, withdrawn.body.controllers);
    assert_eq!(renewed.body.revision, withdrawn.body.revision + 1);
    assert!(renewed.body.expires_at_ms > withdrawn.body.expires_at_ms);
    assert!(matches!(
        service.submit(Operation::RenewRoster).await,
        Outcome::Roster(Ok(()))
    ));
    assert_eq!(
        serde_json::to_value(store.run(read_authority).await.unwrap().roster).unwrap(),
        serde_json::to_value(Some(&renewed)).unwrap()
    );
    let saved = store.run(read_authority).await.unwrap();
    use openraft::{RaftSnapshotBuilder, storage::RaftStateMachine};
    let mut snapshot_store = store.clone();
    let snapshot = snapshot_store.build_snapshot().await.unwrap();
    let snapshot_database = root.join("snapshot.sqlite").to_str().unwrap().to_owned();
    let mut snapshot_conn = diesel::SqliteConnection::establish(&snapshot_database).unwrap();
    crate::db::migrate(&mut snapshot_conn, true).unwrap();
    drop(snapshot_conn);
    let mut restored = Store::open(snapshot_database).await.unwrap();
    restored
        .install_snapshot(&snapshot.meta, snapshot.snapshot)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(restored.run(read_authority).await.unwrap()).unwrap(),
        serde_json::to_value(&saved).unwrap()
    );
    assert!(
        restored
            .run(read_revocations)
            .await
            .unwrap()
            .get(&2)
            .unwrap()
            .complete
    );
    drop(restored);
    let (jobs, mut work) = tokio::sync::mpsc::channel(1);
    let n = node.clone();
    let s = store.clone();
    let worker = tokio::spawn(async move {
        if let Some(crate::DatabaseJob::Invite {
            request_id,
            expires_at,
            max_uses,
            join_mesh,
            reply,
        }) = work.recv().await
        {
            let _ = reply.send(invite(&n, &s, request_id, expires_at, max_uses, join_mesh).await);
        }
    });
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("Idempotency-Key", "runtime-retry".parse().unwrap());
    let response = crate::router::operator::create_invite(
        axum::extract::State(jobs),
        headers,
        axum::Json(cat4igp_shared::rest::operator::CreateInvitePayload {
            expires_at: None,
            max_uses: Some(1),
            join_mesh: None,
        }),
    )
    .await
    .ok()
    .unwrap();
    worker.await.unwrap();
    let code = response.0.invite_code;
    node.shutdown().await.unwrap();
    transport.abort();
    drop(store);
    drop(node);
    assert!(
        start(
            config(Mode::Initialize),
            database.clone(),
            libp2p::pnet::PreSharedKey::new([9; 32])
        )
        .await
        .is_err()
    );
    let (node, store, transport, _service) = start(
        config(Mode::Recover),
        database.clone(),
        libp2p::pnet::PreSharedKey::new([9; 32]),
    )
    .await
    .unwrap();
    node.wait(Some(DEADLINE))
        .current_leader(1, "recovered election")
        .await
        .unwrap();
    let recovered = store.run(read_authority).await.unwrap();
    assert_eq!(recovered.signing_key, original.signing_key);
    assert_eq!(recovered.encryption_key, original.encryption_key);
    assert_eq!(
        serde_json::to_value(recovered).unwrap(),
        serde_json::to_value(saved).unwrap()
    );
    assert_eq!(
        invite(&node, &store, "runtime-retry".into(), None, Some(1), None)
            .await
            .unwrap()
            .unwrap(),
        code
    );
    let rows = store
        .run(|conn| Ok(crate::db::get_invites(conn)?.len()))
        .await
        .unwrap();
    assert_eq!(rows, 1);
    node.shutdown().await.unwrap();
    transport.abort();
    drop(node);
    drop(store);
    let minority_database = root.join("minority.sqlite").to_str().unwrap().to_owned();
    let mut conn = diesel::SqliteConnection::establish(&minority_database).unwrap();
    crate::db::migrate(&mut conn, true).unwrap();
    drop(conn);
    let mut minority = config(Mode::Join);
    for id in [2, 3] {
        minority.replicas.insert(
            id,
            Replica {
                peer_id: libp2p::identity::Keypair::generate_ed25519()
                    .public()
                    .to_peer_id(),
                address: format!("/ip4/127.0.0.1/tcp/{id}").parse().unwrap(),
            },
        );
    }
    let (node, store, transport, _service) = start(
        minority,
        minority_database,
        libp2p::pnet::PreSharedKey::new([9; 32]),
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(
            DEADLINE,
            invite(&node, &store, "minority".into(), None, Some(1), None)
        )
        .await
        .map_or(true, |r| r.is_err())
    );
    assert_eq!(
        store
            .run(|conn| Ok(crate::db::get_invites(conn)?.len()))
            .await
            .unwrap(),
        0
    );
    node.shutdown().await.unwrap();
    transport.abort();
    drop(node);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}
