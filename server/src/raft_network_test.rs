use super::*;
use crate::raft_storage::{Command, Store};
use diesel::{Connection, RunQueryDsl};
use openraft::{RaftSnapshotBuilder, Vote, storage::RaftStateMachine};
use tokio::io::AsyncReadExt;

fn vote(id: u64) -> Rpc {
    Rpc::Vote(VoteRequest {
        vote: Vote::new(1, id),
        last_log_id: None,
    })
}
fn addresses(count: usize) -> Vec<Multiaddr> {
    let listeners: Vec<_> = (0..count)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    listeners
        .iter()
        .map(|l| {
            format!("/ip4/127.0.0.1/tcp/{}", l.local_addr().unwrap().port())
                .parse()
                .unwrap()
        })
        .collect()
}
#[tokio::test]
async fn committed_live_verifier_refresh_expiry_rollback_and_revocation() {
    use cat4igp_shared::discovery::{ControllerEndpoint, ControllerRoster};
    let addresses = addresses(2);
    let keys: Vec<_> = (0..2)
        .map(|_| identity::Keypair::generate_ed25519())
        .collect();
    let bindings: BTreeMap<_, _> = (0..2)
        .map(|i| {
            (
                i as u64 + 1,
                Binding {
                    peer: keys[i].public().to_peer_id(),
                    address: addresses[i].clone(),
                },
            )
        })
        .collect();
    let db = Database::new();
    let mut store = Store::open(db.0.clone()).await.unwrap();
    let init = crate::cluster::new_authority(
        "refresh-test".into(),
        bindings.iter().map(|(id, b)| (*id, b.peer)).collect(),
    );
    let signing = identity::Keypair::from_protobuf_encoding(
        &crate::hex_decode(&init.identity.signing_private_key).unwrap(),
    )
    .unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let mut roster = ControllerRoster {
        version: 1,
        cluster_id: "refresh-test".into(),
        revision: 1,
        issued_at_ms: now - 2000,
        expires_at_ms: now - 1,
        discovery_endpoints: vec![],
        controllers: bindings
            .values()
            .map(|b| ControllerEndpoint {
                peer_id: b.peer,
                addresses: vec![
                    b.address
                        .clone()
                        .with(libp2p::multiaddr::Protocol::P2p(b.peer)),
                ],
            })
            .collect(),
    };
    let mut index = 0;
    async fn apply(
        store: &mut Store,
        index: &mut u64,
        command: Command,
    ) -> Result<Option<String>, String> {
        *index += 1;
        store
            .apply([openraft::Entry {
                log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), *index),
                payload: openraft::EntryPayload::Normal(command),
            }])
            .await
            .unwrap()
            .remove(0)
    }
    apply(&mut store, &mut index, Command::AuthorityInit(init))
        .await
        .unwrap();
    apply(
        &mut store,
        &mut index,
        Command::Roster(roster.clone().sign(&signing).unwrap()),
    )
    .await
    .unwrap();
    let (network, _, attach, task) = Network::start(
        1,
        "refresh-test".into(),
        keys[0].clone(),
        PreSharedKey::new([7; 32]),
        bindings,
        addresses[0].clone(),
    )
    .await
    .unwrap();
    let mut live = network.authority();
    network.reconcile_store(&store).await.unwrap();
    live.changed().await.unwrap();
    assert!(!live.borrow().permits(keys[0].public().to_peer_id(), now));
    roster.revision = 2;
    roster.issued_at_ms = now;
    roster.expires_at_ms = now + 240_000;
    let renewed = roster.clone().sign(&signing).unwrap();
    // A signed hint alone cannot replace applied authority.
    assert!(!live.borrow().permits(keys[0].public().to_peer_id(), now));
    apply(&mut store, &mut index, Command::Roster(renewed.clone()))
        .await
        .unwrap();
    network.reconcile_store(&store).await.unwrap();
    live.changed().await.unwrap();
    assert!(live.borrow().permits(keys[0].public().to_peer_id(), now));
    assert!(
        !live
            .borrow()
            .permits(keys[0].public().to_peer_id(), now + 240_001)
    );
    let encryption = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([8; 32]));
    let envelope = cat4igp_shared::control::seal_topology_snapshot(
        &signing,
        &crate::hex_encode(encryption.as_bytes()),
        cat4igp_shared::control::MessageMeta {
            message_id: "a".repeat(32),
            network_id: "refresh-test".into(),
            recipient_node_id: 7,
            issued_at_ms: now,
            expires_at_ms: now + 1000,
            topology_revision: 1,
        },
        &cat4igp_shared::control::TopologySnapshot {
            node_id: 7,
            revision: 1,
            tunnels: vec![],
        },
    )
    .unwrap();
    let payload = serde_json::to_vec(&envelope).unwrap();
    assert!(valid_relay(&network, &payload));
    let mut state = store.run(crate::cluster::read_authority).await.unwrap();
    let mut continuity = live.borrow().clone();
    state.signing_key = crate::hex_encode(&keys[1].public().encode_protobuf());
    continuity.refresh(Some(state));
    assert!(!continuity.permits(keys[0].public().to_peer_id(), now));
    continuity.refresh(store.run(crate::cluster::read_authority).await.ok());
    assert!(continuity.permits(keys[0].public().to_peer_id(), now));
    let mut rollback = roster.clone();
    rollback.revision = 1;
    assert!(
        apply(
            &mut store,
            &mut index,
            Command::Roster(rollback.clone().sign(&signing).unwrap())
        )
        .await
        .is_err()
    );
    let mut state = store.run(crate::cluster::read_authority).await.unwrap();
    state.roster = Some(rollback.sign(&signing).unwrap());
    continuity.refresh(Some(state));
    assert!(!continuity.permits(keys[0].public().to_peer_id(), now));
    continuity.refresh(None);
    assert!(!continuity.permits(keys[0].public().to_peer_id(), now));
    roster.revision = 3;
    roster.issued_at_ms += 1;
    roster.expires_at_ms += 1;
    roster.controllers.remove(1);
    apply(
        &mut store,
        &mut index,
        Command::Roster(roster.sign(&signing).unwrap()),
    )
    .await
    .unwrap();
    network.reconcile_store(&store).await.unwrap();
    assert!(
        !live
            .borrow()
            .permits(keys[1].public().to_peer_id(), now + 1)
    );
    assert!(
        live.borrow()
            .permits(keys[0].public().to_peer_id(), now + 1)
    );
    store
        .run(|conn| {
            diesel::sql_query(
                "UPDATE settings SET value = 'malformed' WHERE key = 'controller_roster'",
            )
            .execute(conn)?;
            Ok(())
        })
        .await
        .unwrap();
    network.reconcile_store(&store).await.unwrap();
    assert!(
        !live
            .borrow()
            .permits(keys[0].public().to_peer_id(), now + 1)
    );
    assert!(!valid_relay(&network, &payload));
    drop(attach);
    task.await.unwrap();
}

#[tokio::test]
async fn dynamic_authorization_reopen_collision_and_revocation() {
    let addresses = addresses(3);
    let keys: Vec<_> = (0..3)
        .map(|_| identity::Keypair::generate_ed25519())
        .collect();
    let bootstrap = BTreeMap::from([(
        1,
        Binding {
            peer: keys[0].public().to_peer_id(),
            address: addresses[0].clone(),
        },
    )]);
    let db = Database::new();
    let mut store = Store::open(db.0.clone()).await.unwrap();
    let initial_bootstrap = bootstrap.clone();
    store.run(move |conn| {
        // An orphaned tombstone must not suppress a newly configured bootstrap.
        diesel::sql_query("INSERT INTO settings(key,value,created_at,updated_at) VALUES ('replica_revocations', ?, '1970-01-01', '1970-01-01')")
            .bind::<diesel::sql_types::Text, _>(serde_json::to_string(&BTreeMap::from([(1, crate::cluster::Revocation {
                peer: initial_bootstrap[&1].peer, complete: true,
            })]))?).execute(conn)?;
        assert!(committed_bindings(conn, "authorization-test", &initial_bootstrap)? == initial_bootstrap);
        diesel::sql_query("DELETE FROM settings WHERE key = 'replica_revocations'").execute(conn)?;
        Ok(())
    }).await.unwrap();
    let init = crate::cluster::new_authority(
        "authorization-test".into(),
        BTreeMap::from([(1, keys[0].public().to_peer_id())]),
    );
    let code = serde_json::from_value(serde_json::json!({
        "expected_generation": 0, "code": "ab".repeat(32),
        "activated_at_ms": 1000, "expires_at_ms": 1000 + 15 * 60 * 1000
    }))
    .unwrap();
    let admission = crate::cluster::Admission {
        source: keys[1].public().to_peer_id(),
        at_ms: 1001,
        request: cat4igp_shared::discovery::join::Request {
            application_version: cat4igp_shared::discovery::join::APPLICATION_VERSION,
            cluster_id: "authorization-test".into(),
            request_id: "join-2".into(),
            node_id: 2,
            address: addresses[1].clone().with(libp2p::multiaddr::Protocol::P2p(
                keys[1].public().to_peer_id(),
            )),
            code: "ab".repeat(32),
        },
    };
    let entries = [
        Command::AuthorityInit(init),
        Command::ReplicaCode(code),
        Command::Admission(admission),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, command)| openraft::Entry {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), i as u64 + 1),
        payload: openraft::EntryPayload::Normal(command),
    });
    assert!(
        store
            .apply(entries)
            .await
            .unwrap()
            .iter()
            .all(Result::is_ok)
    );
    let (network, _, attach, task) = Network::start(
        1,
        "authorization-test".into(),
        keys[0].clone(),
        PreSharedKey::new([7; 32]),
        bootstrap.clone(),
        addresses[0].clone(),
    )
    .await
    .unwrap();
    network.reconcile_store(&store).await.unwrap();
    let request = Request {
        application_version: cat4igp_shared::discovery::join::APPLICATION_VERSION,
        cluster: "authorization-test".into(),
        source: 2,
        target: 1,
        rpc: vote(2),
    };
    assert!(authorized(
        &network,
        keys[1].public().to_peer_id(),
        &request
    ));
    assert!(!authorized(
        &network,
        keys[2].public().to_peer_id(),
        &request
    ));
    let privileged = Request {
        rpc: Rpc::Operator(crate::cluster::Operation::Ready),
        ..request
    };
    assert!(!authorized(
        &network,
        keys[1].public().to_peer_id(),
        &privileged
    ));
    let promotion = Request {
        application_version: cat4igp_shared::discovery::join::APPLICATION_VERSION,
        rpc: Rpc::Operator(crate::cluster::Operation::PromoteLearner(2)),
        cluster: privileged.cluster.clone(),
        source: privileged.source,
        target: privileged.target,
    };
    assert!(!authorized(
        &network,
        keys[1].public().to_peer_id(),
        &promotion
    ));
    assert!(!authorized(
        &network,
        keys[2].public().to_peer_id(),
        &promotion
    ));
    let before = network.bindings.borrow().clone();
    let mut conflicting = before.clone();
    conflicting.insert(
        3,
        Binding {
            peer: keys[1].public().to_peer_id(),
            address: addresses[2].clone(),
        },
    );
    assert!(network.reconcile(conflicting).await.is_err());
    assert!(network.bindings.borrow().eq(&before));
    let mut incompatible = bootstrap.clone();
    incompatible.get_mut(&1).unwrap().peer = keys[2].public().to_peer_id();
    assert!(
        store
            .run(move |conn| committed_bindings(conn, "authorization-test", &incompatible))
            .await
            .is_err()
    );
    // Reopen reconstructs from durable application state, not an in-memory admission cache.
    let reopened = Store::open(db.0.clone()).await.unwrap();
    network.reconcile(bootstrap.clone()).await.unwrap();
    assert!(!authorized(
        &network,
        keys[1].public().to_peer_id(),
        &Request {
            rpc: vote(2),
            ..privileged
        }
    ));
    network.reconcile_store(&reopened).await.unwrap();
    assert!(network.bindings.borrow().contains_key(&2));
    network.reconcile(bootstrap).await.unwrap();
    assert!(!network.bindings.borrow().contains_key(&2));
    assert!(
        network
            .call::<RaftError<u64>>(2, vote(1), RPCOption::new(DEADLINE))
            .await
            .is_err()
    );
    drop(attach);
    task.abort();
    let _ = task.await;
}
struct Database(String);
impl Database {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("cat4igp-rpc-{}.sqlite", uuid::Uuid::new_v4()));
        let path = path.to_str().unwrap().to_owned();
        let mut conn = diesel::SqliteConnection::establish(&path).unwrap();
        crate::db::configure_connection(&mut conn).unwrap();
        crate::db::migrate(&mut conn, true).unwrap();
        Self(path)
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0));
        }
    }
}

#[tokio::test]
async fn encrypted_genuine_nodes_vote_commit_snapshot_and_reject_intruders() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let addresses = addresses(6);
        let keys: Vec<_> = (0..6)
            .map(|_| identity::Keypair::generate_ed25519())
            .collect();
        let bindings: BTreeMap<_, _> = (0..4)
            .map(|i| {
                (
                    i as u64 + 1,
                    Binding {
                        peer: keys[i].public().to_peer_id(),
                        address: addresses[i].clone(),
                    },
                )
            })
            .collect();
        let config = Arc::new(
            openraft::Config {
                heartbeat_interval: 100,
                election_timeout_min: 500,
                election_timeout_max: 1000,
                snapshot_max_chunk_size: 64 * 1024,
                max_payload_entries: 16,
                ..Default::default()
            }
            .validate()
            .unwrap(),
        );
        let mut networks = Vec::new();
        let mut nodes = Vec::new();
        let mut stores = Vec::new();
        let mut databases = Vec::new();
        let mut attachments = Vec::new();
        let mut tasks = Vec::new();
        for i in 0..4 {
            let db = Database::new();
            let store = Store::open(db.0.clone()).await.unwrap();
            let (network, _, attach, task) = Network::start(
                i as u64 + 1,
                "cluster-a".into(),
                keys[i].clone(),
                PreSharedKey::new([7; 32]),
                bindings.clone(),
                addresses[i].clone(),
            )
            .await
            .unwrap();
            let node = Node::new(
                i as u64 + 1,
                config.clone(),
                network.clone(),
                store.clone(),
                store.clone(),
            )
            .await
            .unwrap();
            attach.send(Some(node.clone())).unwrap();
            networks.push(network);
            nodes.push(node);
            stores.push(store);
            databases.push(db);
            attachments.push(attach);
            tasks.push(task);
        }
        // Actual adapter vote RPC reaches a genuine OpenRaft instance before initialization.
        let mut client = networks[0].new_client(2, &BasicNode::default()).await;
        let result = client
            .vote(
                VoteRequest {
                    vote: Vote::new(1, 1),
                    last_log_id: None,
                },
                RPCOption::new(DEADLINE),
            )
            .await
            .unwrap();
        assert!(result.vote_granted);
        nodes[0]
            .initialize(BTreeMap::from([
                (1, BasicNode::default()),
                (2, BasicNode::default()),
                (3, BasicNode::default()),
            ]))
            .await
            .unwrap();
        let leader = loop {
            if let Some(id) = nodes
                .iter()
                .find_map(|n| n.metrics().borrow().current_leader)
            {
                break id as usize - 1;
            }
            tokio::task::yield_now().await;
        };
        let applied_at = chrono::DateTime::from_timestamp(1_800_000_000, 0)
            .unwrap()
            .naive_utc();
        let command = Command::Invite(crate::db::InviteCommand {
            request_id: "rpc-commit".into(),
            id: 1,
            code: "secret-invite-over-noise".into(),
            expires_at: None,
            max_uses: Some(2),
            join_mesh: None,
            applied_at,
        });
        let committed = nodes[leader].client_write(command).await.unwrap();
        assert_eq!(committed.data, Ok(Some("secret-invite-over-noise".into())));
        for store in &mut stores[..3] {
            loop {
                if store.applied_state().await.unwrap().0 >= Some(committed.log_id) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
        // Send a real logical snapshot through the adapter, not a mocked RPC handler.
        let mut snapshot = stores[leader].build_snapshot().await.unwrap();
        let mut bytes = Vec::new();
        snapshot.snapshot.read_to_end(&mut bytes).await.unwrap();
        // Fresh admitted non-voter avoids equal-applied-index snapshot elision.
        let target = 3;
        let mut client = networks[leader]
            .new_client(target as u64 + 1, &BasicNode::default())
            .await;
        let committed_vote = nodes[leader].metrics().borrow().vote;
        for (i, chunk) in bytes.chunks(64 * 1024).enumerate() {
            client
                .install_snapshot(
                    InstallSnapshotRequest {
                        vote: committed_vote,
                        meta: snapshot.meta.clone(),
                        offset: (i * 64 * 1024) as u64,
                        data: chunk.to_vec(),
                        done: (i + 1) * 64 * 1024 >= bytes.len(),
                    },
                    RPCOption::new(DEADLINE),
                )
                .await
                .unwrap();
        }
        assert_eq!(
            stores[target]
                .get_current_snapshot()
                .await
                .unwrap()
                .unwrap()
                .meta,
            snapshot.meta
        );
        let mut wrong_cluster = networks[leader].clone();
        wrong_cluster.cluster = "other-cluster".into();
        assert!(matches!(
            wrong_cluster
                .call::<RaftError<u64>>(4, vote(leader as u64 + 1), RPCOption::new(DEADLINE))
                .await
                .unwrap(),
            Response::Rejected
        ));
        // Knowing the private PSK alone does not authorize an unadmitted Noise identity.
        for (i, psk) in [(4, [7; 32]), (5, [8; 32])] {
            let mut outsider_bindings = bindings.clone();
            outsider_bindings.insert(
                5,
                Binding {
                    peer: keys[i].public().to_peer_id(),
                    address: addresses[i].clone(),
                },
            );
            let (outsider, _, attach, task) = Network::start(
                5,
                "cluster-a".into(),
                keys[i].clone(),
                PreSharedKey::new(psk),
                outsider_bindings,
                addresses[i].clone(),
            )
            .await
            .unwrap();
            let result = outsider
                .call::<RaftError<u64>>(1, vote(5), RPCOption::new(Duration::from_millis(400)))
                .await;
            assert!(result.is_err() || matches!(result, Ok(Response::Rejected)));
            drop(attach);
            task.await.unwrap();
        }
        for node in nodes {
            node.shutdown().await.unwrap();
        }
        drop(attachments);
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn binding_cluster_bounds_deadline_overload_and_persistent_identity() {
    let paths: Vec<_> = (0..2)
        .map(|_| std::env::temp_dir().join(format!("cat4igp-replica-{}", uuid::Uuid::new_v4())))
        .collect();
    let a = replica_identity(&paths[0]).unwrap();
    let b = replica_identity(&paths[1]).unwrap();
    assert_eq!(a.public(), replica_identity(&paths[0]).unwrap().public());
    assert_ne!(a.public(), b.public());
    std::fs::write(&paths[0], b"corrupt").unwrap();
    assert!(replica_identity(&paths[0]).is_err());
    for path in paths {
        std::fs::remove_file(path).unwrap();
    }
    let addresses = addresses(2);
    let bindings = Arc::new(BTreeMap::from([
        (
            1,
            Binding {
                peer: a.public().to_peer_id(),
                address: addresses[0].clone(),
            },
        ),
        (
            2,
            Binding {
                peer: b.public().to_peer_id(),
                address: addresses[1].clone(),
            },
        ),
    ]));
    let (tx, mut rx) = mpsc::channel(CAPACITY);
    let network = Network {
        id: 2,
        cluster: "a".into(),
        bindings: watch::channel((*bindings).clone()).0,
        bootstrap: bindings.clone(),
        updates: mpsc::channel(1).0,
        tx,
        service: watch::channel(None).0,
        relay: mpsc::channel(CAPACITY).0,
        notifications: tokio::sync::broadcast::channel(CAPACITY).0,
        relay_authority: watch::channel(RelayAuthority::default()).0,
    };
    let mut request = Request {
        application_version: cat4igp_shared::discovery::join::APPLICATION_VERSION,
        cluster: "a".into(),
        source: 1,
        target: 2,
        rpc: vote(1),
    };
    assert!(authorized(&network, a.public().to_peer_id(), &request));
    request.application_version = 2;
    assert!(!authorized(&network, a.public().to_peer_id(), &request));
    request.application_version = cat4igp_shared::discovery::join::APPLICATION_VERSION;
    let mut missing = serde_json::to_value(&request).unwrap();
    missing
        .as_object_mut()
        .unwrap()
        .remove("application_version");
    assert!(serde_json::from_value::<Request>(missing).is_err());
    assert!(!authorized(&network, b.public().to_peer_id(), &request));
    request.rpc = Rpc::Operator(crate::cluster::Operation::Ready);
    assert!(authorized(&network, a.public().to_peer_id(), &request));
    assert!(!authorized(&network, b.public().to_peer_id(), &request));
    request.rpc = vote(1);
    request.cluster = "b".into();
    assert!(!authorized(&network, a.public().to_peer_id(), &request));
    request.cluster = "a".into();
    request.source = 2;
    assert!(!authorized(&network, a.public().to_peer_id(), &request));
    request.source = 1;
    request.target = 1;
    assert!(!authorized(&network, a.public().to_peer_id(), &request));
    assert!(
        network
            .call::<RaftError<u64>>(1, vote(2), RPCOption::new(Duration::from_millis(10)))
            .await
            .is_err()
    );
    assert!(rx.recv().await.unwrap().reply.is_closed());
    for _ in 0..CAPACITY {
        let (reply, _) = oneshot::channel();
        network
            .tx
            .try_send(Call {
                cluster: network.cluster.clone(),
                target: 1,
                rpc: vote(2),
                expires: Instant::now() + DEADLINE,
                reply,
            })
            .unwrap();
    }
    let start = Instant::now();
    assert!(
        network
            .call::<RaftError<u64>>(1, vote(2), RPCOption::new(DEADLINE))
            .await
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_millis(100));
    assert!(
        network
            .call::<RaftError<u64>>(99, vote(2), RPCOption::new(DEADLINE))
            .await
            .is_err()
    );
    let snapshot = Rpc::Snapshot(InstallSnapshotRequest {
        vote: Vote::new(1, 2),
        meta: Default::default(),
        offset: 0,
        data: vec![0; LIMIT],
        done: true,
    });
    assert!(
        network
            .call::<RaftError<u64>>(1, snapshot, RPCOption::new(DEADLINE))
            .await
            .is_err()
    );
}
