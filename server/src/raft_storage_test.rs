use super::*;
use diesel::connection::SimpleConnection;
use openraft::{
    Membership,
    storage::RaftLogStorageExt,
    testing::{StoreBuilder, Suite},
};

struct Database(String);
impl Database {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("cat4igp-raft-{}.sqlite", uuid::Uuid::new_v4()));
        let path = path.to_str().unwrap().to_owned();
        let mut conn = SqliteConnection::establish(&path).unwrap();
        crate::db::configure_connection(&mut conn).unwrap();
        crate::db::migrate(&mut conn, true).unwrap();
        Self(path)
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        // Worker shutdown may still be draining; Linux unlink is safe for its open handle.
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0));
        }
    }
}
struct Builder;

#[tokio::test]
async fn lifecycle_receipts_prevent_delayed_prepare_retry() {
    let db = Database::new();
    let mut store = Store::open(db.0.clone()).await.unwrap();
    let membership = Membership::new(vec![std::collections::BTreeSet::from([1])], None);
    let initial = entry(0, EntryPayload::Membership(membership.clone()));
    store.apply([initial.clone()]).await.unwrap();
    let captured = StoredMembership::new(Some(initial.log_id), membership);
    let prepare = Command::FenceLifecycle { request_id: "admin:1:prepare".into(), action: FenceLifecycle::Prepare { target: 2 }, membership: Some(captured.clone()) };
    let original = store.apply([entry(1, EntryPayload::Normal(prepare.clone()))]).await.unwrap().remove(0);
    assert!(original.is_ok());
    let cancel = Command::FenceLifecycle { request_id: "admin:1:cancel".into(), action: FenceLifecycle::Cancel { prepare_log_id: entry(1, EntryPayload::Blank).log_id }, membership: None };
    let cancelled = store.apply([entry(2, EntryPayload::Normal(cancel.clone()))]).await.unwrap().remove(0);
    assert!(cancelled.is_ok());
    let snapshot = store.build_snapshot().await.unwrap();
    let restored_db = Database::new();
    let mut restored = Store::open(restored_db.0.clone()).await.unwrap();
    restored.install_snapshot(&snapshot.meta, snapshot.snapshot).await.unwrap();
    assert_eq!(restored.apply([entry(3, EntryPayload::Normal(prepare.clone()))]).await.unwrap().remove(0), original);
    assert!(restored.run(|conn| get::<FencePrepare>(conn, "fence_prepare")).await.unwrap().is_none());
    assert_eq!(store.apply([entry(3, EntryPayload::Normal(prepare))]).await.unwrap().remove(0), original);
    assert!(store.run(|conn| get::<FencePrepare>(conn, "fence_prepare")).await.unwrap().is_none());
    assert_eq!(store.apply([entry(4, EntryPayload::Normal(cancel))]).await.unwrap().remove(0), cancelled);
    let conflict = Command::FenceLifecycle { request_id: "admin:1:prepare".into(), action: FenceLifecycle::Prepare { target: 3 }, membership: Some(captured) };
    assert!(store.apply([entry(5, EntryPayload::Normal(conflict))]).await.unwrap()[0].is_err());
}

#[tokio::test]
async fn preparation_rejects_incomplete_revocation() {
    let db = Database::new();
    let mut store = Store::open(db.0.clone()).await.unwrap();
    let membership = Membership::new(vec![std::collections::BTreeSet::from([1])], None);
    let initial = entry(0, EntryPayload::Membership(membership.clone()));
    store.apply([initial.clone()]).await.unwrap();
    store.run(|conn| {
        let revoked = std::collections::BTreeMap::from([(2u64, crate::cluster::Revocation {
            peer: libp2p::identity::Keypair::generate_ed25519().public().to_peer_id(), complete: false,
        })]);
        crate::db::set_setting(conn, "replica_revocations", &serde_json::to_string(&revoked)?)?;
        Ok(())
    }).await.unwrap();
    let command = Command::PrepareReaderFence { target: 2, membership: StoredMembership::new(Some(initial.log_id), membership) };
    assert!(store.apply([entry(1, EntryPayload::Normal(command))]).await.unwrap()[0].is_err());
    assert!(store.run(|conn| get::<FencePrepare>(conn, "fence_prepare")).await.unwrap().is_none());
}

#[tokio::test]
async fn attestation_is_bound_to_preparation_and_survives_snapshot() {
    let db = Database::new();
    let mut store = Store::open(db.0.clone()).await.unwrap();
    let membership = Membership::new(vec![std::collections::BTreeSet::from([1])], None);
    let initial = entry(0, EntryPayload::Membership(membership.clone()));
    store.apply([initial.clone()]).await.unwrap();
    let prepare = FencePrepare { target: 2, log_id: entry(1, EntryPayload::Blank).log_id,
        membership: StoredMembership::new(Some(initial.log_id), membership) };
    store.apply([entry(1, EntryPayload::Normal(Command::PrepareReaderFence {
        target: prepare.target, membership: prepare.membership.clone(),
    }))]).await.unwrap();
    let mutation = crate::admin::Mutation { request_id: "admin:1:attestation".into(),
        action: crate::admin::Action::AttestUpgradeFence { prepare: prepare.clone(), externally_fenced: true },
        applied_at: chrono::Utc::now().naive_utc() };
    let recorded = store.apply([entry(2, EntryPayload::Normal(Command::Admin(mutation.clone())))]).await.unwrap().remove(0);
    assert!(recorded.is_ok());
    store.apply([entry(3, EntryPayload::Normal(Command::CancelReaderFence { prepare_log_id: prepare.log_id }))]).await.unwrap();
    let retry = store.apply([entry(4, EntryPayload::Normal(Command::Admin(mutation.clone())))]).await.unwrap().remove(0);
    assert_eq!(retry, recorded);
    let mut stale = mutation;
    stale.request_id = "admin:1:stale".into();
    assert!(store.apply([entry(5, EntryPayload::Normal(Command::Admin(stale)))]).await.unwrap()[0].is_err());
    let snapshot = store.build_snapshot().await.unwrap();
    let target = Database::new();
    let mut restored = Store::open(target.0.clone()).await.unwrap();
    restored.install_snapshot(&snapshot.meta, snapshot.snapshot).await.unwrap();
    assert_eq!(restored.run(|conn| Ok(crate::schema::administrator_results::table.count().get_result::<i64>(conn)?)).await.unwrap(), 2);
    assert_eq!(restored.run(|conn| get::<u8>(conn, "reader_fence")).await.unwrap(), Some(INITIAL_READER_FENCE));
}

#[tokio::test]
async fn fence_prepare_persists_and_membership_change_invalidates_it() {
    let db = Database::new();
    let mut store = Store::open(db.0.clone()).await.unwrap();
    let membership = Membership::new(vec![std::collections::BTreeSet::from([1, 2])], None);
    let initial = entry(0, EntryPayload::Membership(membership.clone()));
    store.apply([initial.clone()]).await.unwrap();
    let old = store.build_snapshot().await.unwrap();
    let captured = StoredMembership::new(Some(initial.log_id), membership.clone());
    let prepare = Command::PrepareReaderFence { target: 2, membership: captured.clone() };
    assert!(store.apply([entry(1, EntryPayload::Normal(prepare.clone()))]).await.unwrap()[0].is_ok());
    assert!(store.install_snapshot(&old.meta, old.snapshot).await.is_err());
    assert!(store.run(|conn| get::<FencePrepare>(conn, "fence_prepare")).await.unwrap().is_some());
    assert!(store.apply([entry(2, EntryPayload::Normal(prepare))]).await.unwrap()[0].is_err());
    let snapshot = store.build_snapshot().await.unwrap();
    let other = Database::new();
    let mut restored = Store::open(other.0.clone()).await.unwrap();
    restored.install_snapshot(&snapshot.meta, snapshot.snapshot).await.unwrap();
    assert_eq!(restored.run(|conn| get::<FencePrepare>(conn, "fence_prepare")).await.unwrap().unwrap().membership, captured);
    restored.apply([entry(3, EntryPayload::Membership(membership))]).await.unwrap();
    assert!(restored.run(|conn| get::<FencePrepare>(conn, "fence_prepare")).await.unwrap().is_none());
    assert!(restored.apply([entry(4, EntryPayload::Normal(Command::PrepareReaderFence { target: 2, membership: captured }))]).await.unwrap()[0].is_err());
    let current = restored.applied_state().await.unwrap().1;
    assert!(restored.apply([entry(5, EntryPayload::Normal(Command::PrepareReaderFence { target: 2, membership: current.clone() }))]).await.unwrap()[0].is_ok());
    assert!(restored.apply([entry(6, EntryPayload::Normal(Command::CancelReaderFence { prepare_log_id: entry(1, EntryPayload::Blank).log_id }))]).await.unwrap()[0].is_err());
    assert!(restored.run(|conn| get::<FencePrepare>(conn, "fence_prepare")).await.unwrap().is_some());
    assert!(restored.apply([entry(7, EntryPayload::Normal(Command::CancelReaderFence { prepare_log_id: entry(5, EntryPayload::Blank).log_id }))]).await.unwrap()[0].is_ok());
    assert!(restored.run(|conn| get::<FencePrepare>(conn, "fence_prepare")).await.unwrap().is_none());
    assert!(restored.apply([entry(8, EntryPayload::Normal(Command::PrepareReaderFence { target: 2, membership: current }))]).await.unwrap()[0].is_ok());
}

#[tokio::test]
async fn committed_unsupported_fence_blocks_startup_before_replay() {
    let db = Database::new();
    let store = Store::open(db.0.clone()).await.unwrap();
    store.run(|conn| {
        for index in 0..=70 {
            let payload = if index == 70 {
                EntryPayload::Normal(Command::ReaderFence { target: MAX_READER_FENCE + 1 })
            } else {
                EntryPayload::Blank
            };
            let entry = entry(index, payload);
            diesel::sql_query("INSERT INTO raft_logs(idx,value) VALUES (?,?)")
                .bind::<Text, _>(format!("{index:016x}"))
                .bind::<Text, _>(serde_json::to_string(&entry)?).execute(conn)?;
        }
        put(conn, "committed", &Some(entry(69, EntryPayload::Blank).log_id))
    }).await.unwrap();
    assert!(preflight_application_version(&db.0).is_ok());
    assert!(Store::open(db.0.clone()).await.is_ok());
    store.run(|conn| {
        diesel::sql_query("DELETE FROM raft_logs WHERE idx = '0000000000000000'").execute(conn)?;
        Ok(())
    }).await.unwrap();
    assert!(preflight_application_version(&db.0).is_err());
    store.run(|conn| {
        let first = entry(0, EntryPayload::Blank);
        diesel::sql_query("INSERT INTO raft_logs(idx,value) VALUES ('0000000000000000', ?)")
            .bind::<Text, _>(serde_json::to_string(&first)?).execute(conn)?;
        Ok(())
    }).await.unwrap();
    store.run(|conn| put(conn, "committed", &Some(entry(70, EntryPayload::Blank).log_id))).await.unwrap();
    assert!(preflight_application_version(&db.0).is_err());
    assert!(Store::open(db.0.clone()).await.is_err());
    assert!(store.run(|conn| Ok(get::<Option<LogId<u64>>>(conn, "applied")?.flatten())).await.unwrap().is_none());
    store.run(|conn| {
        diesel::sql_query("DELETE FROM raft_logs WHERE idx = '0000000000000045'").execute(conn)?;
        put(conn, "committed", &Some(entry(69, EntryPayload::Blank).log_id))
    }).await.unwrap();
    assert!(preflight_application_version(&db.0).is_err());
    store.run(|conn| {
        let applied = entry(1, EntryPayload::Blank).log_id;
        let conflicting = LogId::new(openraft::CommittedLeaderId::new(3, 1), 1);
        put(conn, "applied", &Some(applied))?;
        put(conn, "committed", &Some(conflicting))
    }).await.unwrap();
    assert!(preflight_application_version(&db.0).is_err());
}

#[tokio::test]
async fn supported_committed_fence_replays_on_raft_startup() {
    use crate::raft_network::{Binding, Network};
    let db = Database::new();
    let store = Store::open(db.0.clone()).await.unwrap();
    store.run(|conn| {
        for index in 0..=70 {
            let payload = if index == 70 {
                EntryPayload::Normal(Command::ReaderFence { target: INITIAL_READER_FENCE })
            } else {
                EntryPayload::Blank
            };
            let entry = entry(index, payload);
            diesel::sql_query("INSERT INTO raft_logs(idx,value) VALUES (?,?)")
                .bind::<Text, _>(format!("{index:016x}"))
                .bind::<Text, _>(serde_json::to_string(&entry)?).execute(conn)?;
        }
        put(conn, "committed", &Some(entry(70, EntryPayload::Blank).log_id))
    }).await.unwrap();
    let key = libp2p::identity::Keypair::generate_ed25519();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", listener.local_addr().unwrap().port()).parse().unwrap();
    drop(listener);
    let bindings = std::collections::BTreeMap::from([(1, Binding { peer: key.public().to_peer_id(), address: address.clone() })]);
    let (network, _, attach, task) = Network::start(1, "replay-fence".into(), key,
        libp2p::pnet::PreSharedKey::new([21; 32]), bindings, address).await.unwrap();
    let node = openraft::Raft::<TypeConfig>::new(1, std::sync::Arc::new(openraft::Config::default().validate().unwrap()),
        network, store.clone(), store.clone()).await.unwrap();
    assert_eq!(store.run(|conn| get::<Option<LogId<u64>>>(conn, "applied")).await.unwrap(),
        Some(Some(entry(70, EntryPayload::Blank).log_id)));
    node.shutdown().await.unwrap();
    drop(attach);
    task.abort();
}

#[tokio::test]
async fn reader_fence_command_is_monotonic_and_unsupported_batches_roll_back() {
    let db = Database::new();
    let mut store = Store::open(db.0.clone()).await.unwrap();
    let result = store.apply([
        entry(1, EntryPayload::Normal(Command::ReaderFence { target: INITIAL_READER_FENCE })),
        entry(2, EntryPayload::Normal(Command::ReaderFence { target: 0 })),
    ]).await.unwrap();
    assert!(result[0].is_ok());
    assert!(result[1].is_err());
    let before = store.run(|conn| Ok((
        get::<u8>(conn, "reader_fence")?,
        get::<Option<LogId<u64>>>(conn, "applied")?,
        crate::db::get_invites(conn)?.len(),
    ))).await.unwrap();
    assert!(store.apply([
        entry(3, EntryPayload::Normal(invite("fence-rollback", 1))),
        entry(4, EntryPayload::Normal(Command::ReaderFence { target: MAX_READER_FENCE + 1 })),
        entry(5, EntryPayload::Blank),
    ]).await.is_err());
    let reopened = Store::open(db.0.clone()).await.unwrap();
    let after = reopened.run(|conn| Ok((
        get::<u8>(conn, "reader_fence")?,
        get::<Option<LogId<u64>>>(conn, "applied")?,
        crate::db::get_invites(conn)?.len(),
    ))).await.unwrap();
    assert_eq!(after, before);
}

#[tokio::test]
async fn snapshot_reader_fence_rejects_invalid_and_legacy_images() {
    assert!(check_snapshot_fence(1, 1).is_ok());
    assert!(check_snapshot_fence(1, 2).is_ok());
    assert!(check_snapshot_fence(2, 1).is_err());
    let source_db = Database::new();
    let target_db = Database::new();
    let mut source = Store::open(source_db.0.clone()).await.unwrap();
    let mut target = Store::open(target_db.0.clone()).await.unwrap();
    let mixed = EpochWindow::Mixed { epoch: 6, minimum_peer: 5 };
    let stable = EpochWindow::Stable { epoch: 6 };
    for (store, window) in [(&mut source, mixed.clone()), (&mut target, stable.clone())] {
        assert!(store.apply([entry(1, EntryPayload::Normal(Command::EpochWindow(window)))]).await.unwrap()[0].is_ok());
    }
    let snapshot = source.build_snapshot().await.unwrap();
    let image: serde_json::Value = serde_json::from_slice(snapshot.snapshot.0.get_ref()).unwrap();
    assert_eq!(image["version"], 4);
    assert_eq!(image["reader_fence"], INITIAL_READER_FENCE);
    assert_eq!(image["epoch_window"], serde_json::to_value(&mixed).unwrap());
    for fence in [None, Some(serde_json::json!(null)), Some(serde_json::json!(0)), Some(serde_json::json!(2))] {
        let mut invalid = image.clone();
        match fence {
            Some(fence) => invalid["reader_fence"] = fence,
            None => { invalid.as_object_mut().unwrap().remove("reader_fence"); },
        }
        assert!(install(&target, snapshot.meta.clone(), serde_json::to_vec(&invalid).unwrap()).await.is_err());
        assert_eq!(target.run(|conn| get::<EpochWindow>(conn, "epoch_window")).await.unwrap(), Some(stable.clone()));
    }
    for mutation in 0..3 {
        let mut invalid = image.clone();
        match mutation {
            0 => { invalid.as_object_mut().unwrap().remove("epoch_window"); },
            1 => invalid["epoch_window"]["epoch"] = 4.into(),
            _ => invalid["meta"]["last_log_id"] = serde_json::Value::Null,
        }
        assert!(install(&target, snapshot.meta.clone(), serde_json::to_vec(&invalid).unwrap()).await.is_err());
        assert_eq!(target.run(read_window).await.unwrap(), Some(stable.clone()));
    }
    target.install_snapshot(&snapshot.meta, snapshot.snapshot).await.unwrap();
    assert_eq!(target.run(read_window).await.unwrap(), Some(mixed));
    assert_eq!(target.run(|conn| get::<u8>(conn, "reader_fence")).await.unwrap(), Some(INITIAL_READER_FENCE));
    let empty_db = Database::new();
    let mut empty = Store::open(empty_db.0.clone()).await.unwrap();
    empty.apply([entry(2, EntryPayload::Blank)]).await.unwrap();
    let empty_snapshot = empty.build_snapshot().await.unwrap();
    target.install_snapshot(&empty_snapshot.meta, empty_snapshot.snapshot).await.unwrap();
    assert_eq!(target.run(read_window).await.unwrap(), None);
    drop(target);
    assert_eq!(Store::open(target_db.0.clone()).await.unwrap().run(read_window).await.unwrap(), None);
}

#[tokio::test]
async fn old_epoch_store_and_snapshot_are_rejected_even_with_fence() {
    let db = Database::new();
    let mut store = Store::open(db.0.clone()).await.unwrap();
    let snapshot = store.build_snapshot().await.unwrap();
    let mut old: serde_json::Value = serde_json::from_slice(snapshot.snapshot.0.get_ref()).unwrap();
    old["application_version"] = 5.into();
    assert!(install(&store, snapshot.meta, serde_json::to_vec(&old).unwrap()).await.is_err());
    store.run(|conn| put(conn, "application_version", &5u8)).await.unwrap();
    assert!(preflight_application_version(&db.0).is_err());
    assert!(Store::open(db.0.clone()).await.is_err());
}

#[tokio::test]
async fn reader_fence_preflight_and_reopen_fail_closed() {
    let db = Database::new();
    let mut store = Store::open(db.0.clone()).await.unwrap();
    store.build_snapshot().await.unwrap();
    for value in [None, Some("null"), Some("0"), Some("2"), Some("invalid")] {
        store.run(move |conn| {
            match value {
                Some(value) => { diesel::sql_query("UPDATE raft_meta SET value = ? WHERE key = 'reader_fence'")
                    .bind::<Text, _>(value).execute(conn)?; },
                None => { diesel::sql_query("DELETE FROM raft_meta WHERE key = 'reader_fence'").execute(conn)?; },
            }
            Ok(())
        }).await.unwrap();
        assert!(preflight_application_version(&db.0).is_err());
        assert!(Store::open(db.0.clone()).await.is_err());
        assert!(store.build_snapshot().await.is_err());
        assert!(store.get_current_snapshot().await.is_err());
        let before = store.run(|conn| Ok((
            get::<Option<LogId<u64>>>(conn, "applied")?,
            get::<StoredMembership<u64, openraft::BasicNode>>(conn, "membership")?,
            crate::db::get_invites(conn)?.len(),
        ))).await.unwrap();
        assert!(store.apply([entry(1, EntryPayload::Normal(invite("blocked", 1)))]).await.is_err());
        assert!(store.apply([entry(1, EntryPayload::Membership(Membership::default()))]).await.is_err());
        let after = store.run(|conn| Ok((
            get::<Option<LogId<u64>>>(conn, "applied")?,
            get::<StoredMembership<u64, openraft::BasicNode>>(conn, "membership")?,
            crate::db::get_invites(conn)?.len(),
        ))).await.unwrap();
        assert_eq!(after, before);
        store.run(|conn| put(conn, "reader_fence", &INITIAL_READER_FENCE)).await.unwrap();
    }
    assert!(preflight_application_version(&db.0).is_ok());
    assert!(Store::open(db.0.clone()).await.is_ok());
}

#[tokio::test]
async fn mesh_fec_snapshot_round_trip() {
    let db = Database::new();
    let mut store = Store::open(db.0.clone()).await.unwrap();
    let create = Command::Admin(crate::admin::Mutation {
        request_id: "fec-mesh".into(),
        action: crate::admin::Action::CreateMesh {
            name: "fec".into(), auto_wireguard: true, mtu: 1420, fec: true,
        },
        applied_at: chrono::Utc::now().naive_utc(),
    });
    assert!(store.apply([entry(1, EntryPayload::Normal(create))]).await.unwrap()[0].is_ok());
    let snapshot = store.build_snapshot().await.unwrap();
    let target = Database::new();
    let mut restored = Store::open(target.0.clone()).await.unwrap();
    restored.install_snapshot(&snapshot.meta, snapshot.snapshot).await.unwrap();
    restored.run(|conn| {
        assert_eq!(crate::admin::read(conn, crate::admin::Operation::Inventory)?["meshes"][0]["fec"], true);
        Ok(())
    }).await.unwrap();
}

#[tokio::test]
async fn explicit_mesh_replay_and_deleted_highest_id_nonreuse() {
    let db = Database::new();
    let mut store = Store::open(db.0.clone()).await.unwrap();
    let at = chrono::Utc::now().naive_utc();
    let mesh = Command::Mesh {
        id: 5,
        name: "highest".into(),
        mtu: 1280,
        created_at: at,
    };
    for index in 1..=2 {
        assert!(
            store
                .apply([entry(index, EntryPayload::Normal(mesh.clone()))])
                .await
                .unwrap()[0]
                .is_ok()
        );
    }
    assert!(
        store
            .apply([entry(
                3,
                EntryPayload::Normal(Command::Admin(crate::admin::Mutation {
                    request_id: "delete-highest".into(),
                    action: crate::admin::Action::DeleteMesh { id: 5 },
                    applied_at: at,
                }))
            )])
            .await
            .unwrap()[0]
            .is_ok()
    );
    for (index, id) in [(4, 5), (5, 4), (6, 6)] {
        let result = store
            .apply([entry(
                index,
                EntryPayload::Normal(Command::Mesh {
                    id,
                    name: "replacement".into(),
                    mtu: 1280,
                    created_at: at,
                }),
            )])
            .await
            .unwrap();
        assert_eq!(result[0].is_ok(), id == 6);
    }
    store
        .run(|conn| {
            assert_eq!(
                crate::schema::mesh_groups::table
                    .select(crate::schema::mesh_groups::id)
                    .load::<i32>(conn)?,
                vec![6]
            );
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn management_overlap_revocation_replay_snapshot_and_rollback() {
    use crate::admin::{Action, IntentKind, Mutation};
    let db = Database::new();
    let mut store = Store::open(db.0.clone()).await.unwrap();
    store.run(|conn| {
        conn.batch_execute("INSERT INTO nodes(id,name,auth_key) VALUES(1,'one','one'),(2,'two','two');
            INSERT INTO node_control_identities(node_id,peer_id,signing_key,encryption_key) VALUES(1,'peer1','key','key'),(2,'peer2','key','key');
            INSERT INTO wireguard_static_key(node_id,public_key) VALUES(1,'key'),(2,'key');
            INSERT INTO mesh_groups(id,name,auto_wireguard,auto_wireguard_mtu,created_at) VALUES(1,'a',1,1280,'2026-10-05 00:00:00'),(2,'b',1,1420,'2026-10-05 00:00:00');
            INSERT INTO invites(code,override_join_mesh) VALUES('mesh-a',1);
            INSERT INTO control_enrollment_results(peer_id,request_id,fingerprint,result) VALUES('peer2','old','{}','{\"Enrolled\":{\"node_id\":2}}');")?;
        Ok(())
    }).await.unwrap();
    let at = chrono::DateTime::from_timestamp(1_790_812_800, 0)
        .unwrap()
        .naive_utc();
    let command = |key: &str, action| {
        Command::Admin(Mutation {
            request_id: key.into(),
            action,
            applied_at: at,
        })
    };
    let mut index = 0;
    for (key, action) in [
        (
            "a1",
            Action::AddMembership {
                mesh_id: 1,
                node_id: 1,
            },
        ),
        (
            "a2",
            Action::AddMembership {
                mesh_id: 1,
                node_id: 2,
            },
        ),
        (
            "b1",
            Action::AddMembership {
                mesh_id: 2,
                node_id: 1,
            },
        ),
        (
            "b2",
            Action::AddMembership {
                mesh_id: 2,
                node_id: 2,
            },
        ),
        ("delete-a", Action::DeleteMesh { id: 1 }),
    ] {
        index += 1;
        assert!(
            store
                .apply([entry(index, EntryPayload::Normal(command(key, action)))])
                .await
                .unwrap()[0]
                .is_ok()
        );
    }
    store
        .run(|conn| {
            let inv = crate::admin::read(conn, crate::admin::Operation::Inventory)?;
            assert_eq!(inv["tunnels"].as_array().unwrap().len(), 2);
            assert!(
                inv["tunnels"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|t| t["mtu"] == 1280 && t["intents"].as_array().unwrap().len() == 1)
            );
            assert!(inv["invites"].as_array().unwrap().is_empty());
            assert_eq!(
                crate::db::control_identity_for_node(conn, 1)?.topology_revision,
                1
            );
            // Unknown historical ownership is explicitly retained through membership removal.
            conn.batch_execute(
                "INSERT INTO tunnel_intents SELECT id,'legacy',0 FROM wireguard_tunnels;",
            )?;
            Ok(())
        })
        .await
        .unwrap();
    index += 1;
    store
        .apply([entry(
            index,
            EntryPayload::Normal(command(
                "remove-b",
                Action::RemoveMembership {
                    mesh_id: 2,
                    node_id: 2,
                },
            )),
        )])
        .await
        .unwrap();
    let before = store.build_snapshot().await.unwrap();
    store.run(|conn| {
        let inv = crate::admin::read(conn,crate::admin::Operation::Inventory)?;
        assert_eq!(inv["tunnels"].as_array().unwrap().len(),2);
        conn.batch_execute("CREATE TRIGGER management_abort BEFORE DELETE ON nodes BEGIN SELECT RAISE(ABORT,'rollback'); END;")?;
        Ok(())
    }).await.unwrap();
    let deletion = command("delete-node", Action::DeleteNode { id: 2 });
    assert!(
        store
            .apply([entry(index + 1, EntryPayload::Normal(deletion.clone()))])
            .await
            .is_err()
    );
    let after = store.build_snapshot().await.unwrap();
    let before: Image = serde_json::from_slice(before.snapshot.0.get_ref()).unwrap();
    let after: Image = serde_json::from_slice(after.snapshot.0.get_ref()).unwrap();
    assert_eq!(before.tables, after.tables);
    store
        .run(|conn| {
            conn.batch_execute("DROP TRIGGER management_abort")?;
            Ok(())
        })
        .await
        .unwrap();
    // Explicit legacy confirmation removes only the selected address family.
    index += 1;
    store
        .apply([entry(
            index,
            EntryPayload::Normal(command(
                "confirm",
                Action::RemoveTunnelIntent {
                    tunnel_id: 1,
                    kind: IntentKind::Legacy,
                },
            )),
        )])
        .await
        .unwrap();
    store
        .run(|conn| {
            assert_eq!(
                crate::admin::read(conn, crate::admin::Operation::Inventory)?["tunnels"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            Ok(())
        })
        .await
        .unwrap();
    index += 1;
    let result = store
        .apply([entry(index, EntryPayload::Normal(deletion.clone()))])
        .await
        .unwrap();
    assert!(result[0].is_ok());
    store
        .run(|conn| {
            assert!(crate::db::identity_revoked(conn, "peer2")?);
            assert!(crate::db::control_identity_for_peer(conn, "peer2").is_err());
            let retry = crate::db::EnrollmentCommand {
                request: cat4igp_shared::control::EnrollmentRequest {
                    request_id: "old".into(), node_name: "two".into(), invitation_code: "mesh-a".into(),
                    client_peer_id: "peer2".into(), client_signing_key: "key".into(),
                    client_encryption_key: "key".into(), wireguard_public_key: "key".into(),
                },
                node_id: 3, auth_key: "new".into(), applied_at: chrono::Utc::now().naive_utc(),
                allocation: crate::db::EnrollmentAllocation { membership: None, tunnels: vec![] },
                response: cat4igp_shared::control::EnrollmentResponse {
                    node_id: 3, topology_revision: 0, network_id: "test".into(),
                    controller_signing_key: "key".into(), controller_encryption_key: "key".into(),
                },
            };
            assert!(matches!(crate::db::apply_enrollment(conn, &retry)?.0,
                cat4igp_shared::control::ControlResponse::Rejected(reason) if reason == "identity permanently revoked"));
            assert!(crate::db::authenticate(conn, "two").is_err());
            assert_eq!(crate::db::next_management_id(conn, "node")?, 3);
            let inv = crate::admin::read(conn, crate::admin::Operation::Inventory)?;
            assert!(inv["tunnels"].as_array().unwrap().is_empty());
            assert_eq!(
                crate::db::control_identity_for_node(conn, 1)?.topology_revision,
                3
            );
            Ok(())
        })
        .await
        .unwrap();
    let restored = Database::new();
    let mut receiver = Store::open(restored.0.clone()).await.unwrap();
    let snap = store.build_snapshot().await.unwrap();
    receiver
        .install_snapshot(&snap.meta, snap.snapshot)
        .await
        .unwrap();
    assert_eq!(
        receiver
            .apply([entry(index + 1, EntryPayload::Normal(deletion))])
            .await
            .unwrap(),
        result
    );
    receiver
        .run(|conn| {
            assert!(crate::db::identity_revoked(conn, "peer2")?);
            assert_eq!(crate::db::next_management_id(conn, "node")?, 3);
            Ok(())
        })
        .await
        .unwrap();
}
impl StoreBuilder<TypeConfig, Store, Store, Database> for Builder {
    async fn build(&self) -> Result<(Database, Store, Store), StorageError<u64>> {
        let db = Database::new();
        let store = Store::open(db.0.clone()).await?;
        Ok((db, store.clone(), store))
    }
}
#[test]
fn openraft_storage_conformance() {
    Suite::test_all(Builder).unwrap();
}

#[tokio::test]
async fn incompatible_application_rejects_without_mutation() {
    let db = Database::new();
    let mut store = Store::open(db.0.clone()).await.unwrap();
    store
        .apply([entry(1, EntryPayload::Normal(invite("retained", 1)))])
        .await
        .unwrap();
    let good = store.build_snapshot().await.unwrap();
    let before = store
        .run(|conn| {
            Ok((
                get::<Image>(conn, "snapshot")?.map(|v| serde_json::to_value(v).unwrap()),
                get::<Option<LogId<u64>>>(conn, "applied")?,
                crate::db::get_invites(conn)?.len(),
            ))
        })
        .await
        .unwrap();
    for future in [false, true] {
        let mut image: serde_json::Value =
            serde_json::from_slice(good.snapshot.0.get_ref()).unwrap();
        if future {
            image["application_version"] =
                (cat4igp_shared::discovery::join::APPLICATION_VERSION + 1).into();
        } else {
            image.as_object_mut().unwrap().remove("application_version");
        }
        assert!(
            install(
                &store,
                good.meta.clone(),
                serde_json::to_vec(&image).unwrap()
            )
            .await
            .is_err()
        );
        let after = store
            .run(|conn| {
                Ok((
                    get::<Image>(conn, "snapshot")?.map(|v| serde_json::to_value(v).unwrap()),
                    get::<Option<LogId<u64>>>(conn, "applied")?,
                    crate::db::get_invites(conn)?.len(),
                ))
            })
            .await
            .unwrap();
        assert_eq!(after, before);
    }
    for future in [false, true] {
        store
            .run(move |conn| {
                if future {
                    put(
                        conn,
                        "application_version",
                        &(cat4igp_shared::discovery::join::APPLICATION_VERSION + 1),
                    )?;
                } else {
                    diesel::sql_query("DELETE FROM raft_meta WHERE key='application_version'")
                        .execute(conn)?;
                }
                Ok(())
            })
            .await
            .unwrap();
        let before = std::fs::read(&db.0).unwrap();
        assert!(Store::open(db.0.clone()).await.is_err());
        assert_eq!(std::fs::read(&db.0).unwrap(), before);
    }
    store
        .run(|conn| {
            put(
                conn,
                "application_version",
                &cat4igp_shared::discovery::join::APPLICATION_VERSION,
            )
        })
        .await
        .unwrap();
    store
        .run(|conn| {
            diesel::sql_query(
                "INSERT INTO __diesel_schema_migrations(version) VALUES ('99999999999999')",
            )
            .execute(conn)?;
            Ok(())
        })
        .await
        .unwrap();
    let before = std::fs::read(&db.0).unwrap();
    assert!(Store::open(db.0.clone()).await.is_err());
    assert_eq!(std::fs::read(&db.0).unwrap(), before);
}

fn entry(index: u64, payload: EntryPayload<TypeConfig>) -> Entry<TypeConfig> {
    Entry {
        log_id: LogId::new(openraft::CommittedLeaderId::new(2, 1), index),
        payload,
    }
}
fn invite(request: &str, id: i32) -> Command {
    Command::Invite(crate::db::InviteCommand {
        request_id: request.into(),
        id,
        code: format!("code-{id}"),
        expires_at: None,
        max_uses: Some(1),
        join_mesh: None,
        applied_at: chrono::DateTime::from_timestamp(1_790_812_800, 0)
            .unwrap()
            .naive_utc(),
    })
}

#[tokio::test]
async fn enrollment_answer_replay_rollback_and_snapshot_retry() {
    use cat4igp_shared::control::{EnrollmentRequest, EnrollmentResponse, TunnelAnswer};
    let left = Database::new();
    let right = Database::new();
    let mut a = Store::open(left.0.clone()).await.unwrap();
    let mut b = Store::open(right.0.clone()).await.unwrap();
    for store in [&a, &b] {
        store.run(|conn| {
            conn.batch_execute("INSERT INTO invites (code, max_uses, override_join_mesh) VALUES ('invite', 1, 1);
                INSERT INTO mesh_groups (id, name, auto_wireguard, auto_wireguard_mtu, created_at) VALUES (1, 'mesh', 1, 1280, '2026-01-01 00:00:00');
                INSERT INTO nodes (id, name, auth_key) VALUES (1, 'existing', 'existing');
                INSERT INTO node_control_identities (node_id, peer_id, signing_key, encryption_key) VALUES (1, 'existing', 'key', 'key');
                INSERT INTO mesh_group_memberships (id, mesh_group_id, node_id, created_at) VALUES (40, 1, 1, '2026-01-01 00:00:00');
                INSERT INTO wireguard_static_key (node_id, public_key) VALUES (1, 'key');")?;
            Ok(())
        }).await.unwrap();
    }
    let key = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = key.public().to_peer_id().to_string();
    let time = chrono::DateTime::from_timestamp(1_790_812_800, 0)
        .unwrap()
        .naive_utc();
    let allocation = a
        .run(|conn| Ok(crate::db::prepare_enrollment_allocation(conn, "invite")?))
        .await
        .unwrap();
    let enrollment = Command::Enrollment {
        peer_id: peer_id.clone(),
        command: crate::db::EnrollmentCommand {
            request: EnrollmentRequest {
                request_id: "enroll".into(),
                node_name: "new".into(),
                invitation_code: "invite".into(),
                client_peer_id: peer_id.clone(),
                client_signing_key: crate::hex_encode(&key.public().encode_protobuf()),
                client_encryption_key: "01".repeat(32),
                wireguard_public_key: "wg".into(),
            },
            node_id: 2,
            auth_key: "explicit".into(),
            applied_at: time,
            allocation,
            response: EnrollmentResponse {
                node_id: 2,
                topology_revision: 0,
                network_id: "network".into(),
                controller_signing_key: "controller".into(),
                controller_encryption_key: "encryption".into(),
            },
        },
    };
    // Serialization is the actual command boundary; IDs/time/key material survive it.
    let enrollment: Command =
        serde_json::from_slice(&serde_json::to_vec(&enrollment).unwrap()).unwrap();
    let answer = Command::Answer {
        peer_id: peer_id.clone(),
        command: crate::db::AnswerCommand {
            node_id: 2,
            request_id: "answer".into(),
            applied_at: time,
            answer: TunnelAnswer {
                tunnel_id: 1,
                endpoint: Some("192.0.2.1:1234".into()),
                decline_type: None,
            },
        },
    };
    let entries = [
        entry(1, EntryPayload::Normal(enrollment.clone())),
        entry(2, EntryPayload::Normal(answer.clone())),
    ];
    let original = a.apply(entries.clone()).await.unwrap();
    assert!(original.iter().all(Result::is_ok));
    assert_eq!(b.apply(entries).await.unwrap(), original);
    let sa = a.build_snapshot().await.unwrap();
    let sb = b.build_snapshot().await.unwrap();
    let ia: Image = serde_json::from_slice(sa.snapshot.0.get_ref()).unwrap();
    let ib: Image = serde_json::from_slice(sb.snapshot.0.get_ref()).unwrap();
    assert_eq!(ia.tables, ib.tables);
    assert_eq!(
        a.applied_state().await.unwrap(),
        b.applied_state().await.unwrap()
    );
    let restored = Database::new();
    b = Store::open(restored.0.clone()).await.unwrap();
    b.install_snapshot(&sa.meta, sa.snapshot).await.unwrap();
    assert_eq!(
        b.apply([
            entry(3, EntryPayload::Normal(enrollment)),
            entry(4, EntryPayload::Normal(answer.clone()))
        ])
        .await
        .unwrap(),
        original
    );
    let before = b.build_snapshot().await.unwrap();
    b.run(|conn| { conn.batch_execute("CREATE TRIGGER fail_applied BEFORE UPDATE ON raft_meta WHEN NEW.key = 'applied' BEGIN SELECT RAISE(ABORT, 'failure'); END;")?; Ok(()) }).await.unwrap();
    let mut changed = answer.clone();
    if let Command::Answer { command, .. } = &mut changed {
        command.request_id = "rollback".into();
        command.answer.endpoint = Some("192.0.2.2:1234".into());
    }
    assert!(
        b.apply([entry(5, EntryPayload::Normal(changed))])
            .await
            .is_err()
    );
    b.run(|conn| {
        conn.batch_execute("DROP TRIGGER fail_applied")?;
        Ok(())
    })
    .await
    .unwrap();
    let after = b.build_snapshot().await.unwrap();
    let before: Image = serde_json::from_slice(before.snapshot.0.get_ref()).unwrap();
    let after: Image = serde_json::from_slice(after.snapshot.0.get_ref()).unwrap();
    assert_eq!(before.tables, after.tables);
    assert_eq!(before.meta.last_log_id, after.meta.last_log_id);
    let mut forged = answer;
    if let Command::Answer { peer_id, .. } = &mut forged {
        *peer_id = "unknown".into();
    }
    assert!(
        b.apply([entry(5, EntryPayload::Normal(forged))])
            .await
            .unwrap()[0]
            .is_err()
    );
    assert_eq!(b.applied_state().await.unwrap().0.unwrap().index, 5);
}

#[tokio::test]
async fn reopen_atomic_apply_dedup_snapshot_and_local_isolation() {
    let db = Database::new();
    let mut store = Store::open(db.0.clone()).await.unwrap();
    let membership = entry(
        0,
        EntryPayload::Membership(Membership::new(
            vec![std::collections::BTreeSet::from([1, 2, 3])],
            None,
        )),
    );
    let first = entry(1, EntryPayload::Normal(invite("retry", 1)));
    store.save_vote(&Vote::new(2, 1)).await.unwrap();
    store
        .blocking_append([membership.clone(), first.clone()])
        .await
        .unwrap();
    store
        .apply([membership.clone(), first.clone()])
        .await
        .unwrap();
    let mut reopened = Store::open(db.0.clone()).await.unwrap();
    assert_eq!(reopened.read_vote().await.unwrap(), Some(Vote::new(2, 1)));
    assert_eq!(reopened.try_get_log_entries(..).await.unwrap().len(), 2);
    assert_eq!(
        reopened.applied_state().await.unwrap().0,
        Some(first.log_id)
    );
    // New committed log, same logical request: original response, no second invite.
    assert_eq!(
        reopened
            .apply([entry(2, EntryPayload::Normal(invite("retry", 99)))])
            .await
            .unwrap(),
        vec![Ok(Some("code-1".into()))]
    );
    reopened.run(|conn| {
                            conn.batch_execute("CREATE TRIGGER fail_applied BEFORE UPDATE ON raft_meta WHEN NEW.key = 'applied' BEGIN SELECT RAISE(ABORT, 'failure'); END;")?;
                            Ok(())
                        }).await.unwrap();
    assert!(
        reopened
            .apply([entry(3, EntryPayload::Normal(invite("rollback", 2)))])
            .await
            .is_err()
    );
    reopened.run(|conn| {
                            assert_eq!(crate::db::get_invites(conn)?.len(), 1);
                            assert!(diesel::sql_query("SELECT result AS value FROM operator_invite_results WHERE request_id = 'rollback'").get_result::<Row>(conn).optional()?.is_none());
                            conn.batch_execute("DROP TRIGGER fail_applied")?;
                            Ok(())
                        }).await.unwrap();
    assert_eq!(reopened.applied_state().await.unwrap().0.unwrap().index, 2);
    let snap = reopened.build_snapshot().await.unwrap();
    let current = Store::open(db.0.clone())
        .await
        .unwrap()
        .get_current_snapshot()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.meta, snap.meta);
    assert_eq!(current.snapshot.0.get_ref(), snap.snapshot.0.get_ref());

    let target = Database::new();
    let mut receiver = Store::open(target.0.clone()).await.unwrap();
    receiver.save_vote(&Vote::new(9, 9)).await.unwrap();
    receiver.save_committed(Some(first.log_id)).await.unwrap();
    receiver.blocking_append([first.clone()]).await.unwrap();
    receiver
        .run(|conn| {
            crate::db::set_setting(conn, "replica_transport_key", "local-only")?;
            Ok(())
        })
        .await
        .unwrap();
    let bytes = snap.snapshot.0.get_ref().clone();
    receiver
        .install_snapshot(&snap.meta, snap.snapshot)
        .await
        .unwrap();
    assert_eq!(receiver.read_vote().await.unwrap(), Some(Vote::new(9, 9)));
    assert_eq!(receiver.read_committed().await.unwrap(), Some(first.log_id));
    assert_eq!(receiver.try_get_log_entries(..).await.unwrap().len(), 1);
    receiver
        .run(|conn| {
            assert_eq!(
                crate::db::get_setting(conn, "replica_transport_key")?,
                "local-only"
            );
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        receiver.applied_state().await.unwrap(),
        reopened.applied_state().await.unwrap()
    );
    assert_eq!(
        receiver
            .apply([entry(3, EntryPayload::Normal(invite("retry", 88)))])
            .await
            .unwrap(),
        vec![Ok(Some("code-1".into()))]
    );
    let before = receiver.applied_state().await.unwrap();
    let mut bad: Image = serde_json::from_slice(&bytes).unwrap();
    bad.tables[0].push(serde_json::json!([
        "replica_transport_key",
        "attacker",
        "time",
        "time"
    ]));
    assert!(
        receiver
            .install_snapshot(
                &bad.meta,
                Box::new(SnapshotData(Cursor::new(serde_json::to_vec(&bad).unwrap())))
            )
            .await
            .is_err()
    );
    assert_eq!(receiver.applied_state().await.unwrap(), before);
    assert_eq!(
        receiver
            .get_current_snapshot()
            .await
            .unwrap()
            .unwrap()
            .snapshot
            .0
            .get_ref(),
        &bytes
    );
    // SQL failure after deletion must restore previous application rows and snapshot metadata.
    receiver.run(|conn| { conn.batch_execute("CREATE TRIGGER fail_restore BEFORE INSERT ON invites BEGIN SELECT RAISE(ABORT, 'failure'); END;")?; Ok(()) }).await.unwrap();
    assert!(
        receiver
            .install_snapshot(&current.meta, current.snapshot)
            .await
            .is_err()
    );
    receiver
        .run(|conn| {
            assert_eq!(crate::db::get_invites(conn)?.len(), 1);
            conn.batch_execute("DROP TRIGGER fail_restore")?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(receiver.applied_state().await.unwrap(), before);
    let mut data = receiver.begin_receiving_snapshot().await.unwrap();
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    data.seek(std::io::SeekFrom::Start(SNAPSHOT_LIMIT as u64))
        .await
        .unwrap();
    assert!(data.write_all(&[1]).await.is_err());
    receiver.purge(first.log_id).await.unwrap();
    let mut reopened = Store::open(target.0.clone()).await.unwrap();
    assert_eq!(
        reopened.get_log_state().await.unwrap().last_purged_log_id,
        Some(first.log_id)
    );
    assert!(reopened.try_get_log_entries(..).await.unwrap().is_empty());
}

#[tokio::test]
async fn snapshot_install_abort_rolls_back_and_retry_survives_reopen() {
    fn state(conn: &mut SqliteConnection) -> Result<serde_json::Value, Error> {
        let meta =
            diesel::sql_query("SELECT json_array(key,value) AS value FROM raft_meta ORDER BY key")
                .load::<Row>(conn)?
                .into_iter()
                .map(|r| r.value)
                .collect::<Vec<_>>();
        let logs =
            diesel::sql_query("SELECT json_array(idx,value) AS value FROM raft_logs ORDER BY idx")
                .load::<Row>(conn)?
                .into_iter()
                .map(|r| r.value)
                .collect::<Vec<_>>();
        Ok(serde_json::json!([
            application_tables(conn)?,
            meta,
            logs,
            crate::db::get_setting(conn, "replica_transport_key")?
        ]))
    }
    let source = Database::new();
    let target = Database::new();
    let mut sender = Store::open(source.0.clone()).await.unwrap();
    let mut receiver = Store::open(target.0.clone()).await.unwrap();
    for (store, voters, index, request, id) in [
        (&mut sender, [4, 5, 6], 10, "incoming", 2),
        (&mut receiver, [1, 2, 3], 0, "old", 1),
    ] {
        let entries = [
            entry(
                index,
                EntryPayload::Membership(Membership::new(
                    vec![std::collections::BTreeSet::from(voters)],
                    None,
                )),
            ),
            entry(index + 1, EntryPayload::Normal(invite(request, id))),
        ];
        store.blocking_append(entries.clone()).await.unwrap();
        assert!(
            store
                .apply(entries)
                .await
                .unwrap()
                .iter()
                .all(Result::is_ok)
        );
    }
    receiver.save_vote(&Vote::new(9, 9)).await.unwrap();
    receiver
        .save_committed(Some(entry(1, EntryPayload::Blank).log_id))
        .await
        .unwrap();
    receiver
        .run(|conn| {
            put(conn, "purged", &entry(0, EntryPayload::Blank).log_id)?;
            put(
                conn,
                "replica_binding",
                &("local-cluster", 1u64, "local-peer"),
            )?;
            put(conn, "transport_bootstrap", &"local-bootstrap")?;
            put(conn, "transport_credential", &"local-credential")?;
            crate::db::set_setting(conn, "replica_transport_key", "local-only")?;
            Ok(())
        })
        .await
        .unwrap();
    let old = receiver.build_snapshot().await.unwrap();
    let incoming = sender.build_snapshot().await.unwrap();
    let bytes = incoming.snapshot.0.get_ref().clone();
    let before = receiver.run(state).await.unwrap();
    let applied = receiver.applied_state().await.unwrap();
    assert_ne!(applied, sender.applied_state().await.unwrap());
    // Native abort at the LAST metadata write: all application/dedup rows, applied ID
    // and membership have already been replaced inside the uncommitted transaction.
    receiver.run(|conn| {
        conn.batch_execute("CREATE TEMP TRIGGER abort_install BEFORE UPDATE ON raft_meta
            WHEN NEW.key = 'snapshot'
              AND EXISTS(SELECT 1 FROM invites WHERE code = 'code-2')
              AND NOT EXISTS(SELECT 1 FROM invites WHERE code = 'code-1')
              AND EXISTS(SELECT 1 FROM operator_invite_results WHERE request_id = 'incoming')
              AND NOT EXISTS(SELECT 1 FROM operator_invite_results WHERE request_id = 'old')
              AND (SELECT value FROM raft_meta WHERE key = 'applied') != json_extract(OLD.value, '$.meta.last_log_id')
              AND (SELECT value FROM raft_meta WHERE key = 'membership') != json_extract(OLD.value, '$.meta.last_membership')
            BEGIN SELECT RAISE(ABORT, 'uncommitted snapshot install'); END;")?;
        Ok(())
    }).await.unwrap();
    assert!(
        receiver
            .install_snapshot(&incoming.meta, incoming.snapshot)
            .await
            .is_err()
    );
    assert_eq!(receiver.run(state).await.unwrap(), before);
    assert_eq!(receiver.applied_state().await.unwrap(), applied);
    let retained = receiver.get_current_snapshot().await.unwrap().unwrap();
    assert_eq!(retained.meta, old.meta);
    assert_eq!(retained.snapshot.0.get_ref(), old.snapshot.0.get_ref());
    receiver
        .run(|conn| {
            conn.batch_execute("DROP TRIGGER abort_install")?;
            Ok(())
        })
        .await
        .unwrap();
    drop(receiver);
    let mut receiver = Store::open(target.0.clone()).await.unwrap();
    assert_eq!(receiver.run(state).await.unwrap(), before);
    receiver
        .install_snapshot(
            &incoming.meta,
            Box::new(SnapshotData(Cursor::new(bytes.clone()))),
        )
        .await
        .unwrap();
    let installed = receiver.run(state).await.unwrap();
    let expected: Image = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(installed[0], serde_json::json!(expected.tables));
    assert_eq!(installed[2], before[2]); // Exact local log bytes, not only row count.
    assert_eq!(installed[3], before[3]);
    receiver
        .run(|conn| {
            assert_eq!(get::<Vote<u64>>(conn, "vote")?, Some(Vote::new(9, 9)));
            assert_eq!(
                get::<LogId<u64>>(conn, "committed")?,
                Some(entry(1, EntryPayload::Blank).log_id)
            );
            assert_eq!(
                get::<LogId<u64>>(conn, "purged")?,
                Some(entry(0, EntryPayload::Blank).log_id)
            );
            assert_eq!(
                get::<(String, u64, String)>(conn, "replica_binding")?,
                Some(("local-cluster".into(), 1, "local-peer".into()))
            );
            assert_eq!(
                get::<String>(conn, "transport_bootstrap")?.as_deref(),
                Some("local-bootstrap")
            );
            assert_eq!(
                get::<String>(conn, "transport_credential")?.as_deref(),
                Some("local-credential")
            );
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        receiver.applied_state().await.unwrap(),
        sender.applied_state().await.unwrap()
    );
    drop(receiver);
    let mut receiver = Store::open(target.0.clone()).await.unwrap();
    assert_eq!(receiver.run(state).await.unwrap(), installed);
    assert_eq!(
        receiver
            .get_current_snapshot()
            .await
            .unwrap()
            .unwrap()
            .snapshot
            .0
            .get_ref(),
        &bytes
    );
    assert_eq!(
        receiver
            .apply([entry(12, EntryPayload::Normal(invite("incoming", 99)))])
            .await
            .unwrap(),
        vec![Ok(Some("code-2".into()))]
    );
    // ponytail: deterministic SQL abort + connection reopen, not SIGKILL/powerloss;
    // add a bounded child handshake if testing process interruption at this boundary.
}

#[tokio::test]
async fn snapshot_preserves_all_application_tables_and_initialization() {
    let source = Database::new();
    let target = Database::new();
    let mut store = Store::open(source.0.clone()).await.unwrap();
    let init = crate::db::InitializeCommand {
        signing_private_key: crate::hex_encode(
            &libp2p::identity::Keypair::generate_ed25519()
                .to_protobuf_encoding()
                .unwrap(),
        ),
        encryption_private_key: "01".repeat(32),
        network_id: "network".into(),
        applied_at: chrono::DateTime::from_timestamp(1_790_812_800, 0)
            .unwrap()
            .naive_utc(),
    };
    store
        .apply([entry(0, EntryPayload::Normal(Command::Initialize(init)))])
        .await
        .unwrap();
    store.run(|conn| {
        conn.batch_execute("INSERT INTO nodes(id,name,auth_key) VALUES(1,'n','auth');
            INSERT INTO invites(id,code) VALUES(1,'invite');
            INSERT INTO mesh_groups(id,name,auto_wireguard,auto_wireguard_mtu,created_at) VALUES(1,'mesh',1,1280,'2026-10-02');
            INSERT INTO mesh_group_memberships(id,mesh_group_id,node_id,created_at) VALUES(1,1,1,'2026-10-02');
            INSERT INTO node_control_identities(node_id,peer_id,signing_key,encryption_key,topology_revision) VALUES(1,'peer','sign','enc',7);
            INSERT INTO wireguard_static_key(node_id,public_key) VALUES(1,'wg');
            INSERT INTO wireguard_tunnels(id,node_id_peer1,node_id_peer2,endpoint_ipv6) VALUES(1,1,2,0);
            INSERT INTO control_answer_results(node_id,request_id,fingerprint,result,expires_at) VALUES(1,'answer','f','accepted','2026-10-03');
            INSERT INTO control_enrollment_results(peer_id,request_id,fingerprint,result) VALUES('peer','enroll','f','{}');
            INSERT INTO operator_invite_results(request_id,fingerprint,result) VALUES('invite','f','{}');
            INSERT INTO administrator(id,username,password_hash) VALUES(1,'admin','hash');
            INSERT INTO administrator_results(request_id,fingerprint,result) VALUES('admin','f','{}');
            INSERT INTO node_revocations(peer_id,node_id,revoked_at) VALUES('deleted',3,'2026-10-05');
            INSERT INTO tunnel_intents(tunnel_id,kind,mesh_id) VALUES(1,'legacy',0);")?;
        Ok(())
    }).await.unwrap();
    let at = chrono::Utc::now().naive_utc();
    let rename = crate::admin::Mutation {
        request_id: "snapshot-rename".into(),
        action: crate::admin::Action::RenameMesh {
            id: 1,
            name: "renamed".into(),
        },
        applied_at: at,
    };
    let invalidate = crate::admin::Mutation {
        request_id: "snapshot-invalidate".into(),
        action: crate::admin::Action::InvalidateInvite { id: 2 },
        applied_at: at,
    };
    let invite = crate::db::InviteCommand {
        request_id: "snapshot-invite".into(),
        id: 2,
        code: "snapshot-secret".into(),
        expires_at: None,
        max_uses: None,
        join_mesh: Some(1),
        applied_at: at,
    };
    let saved_invite = invite.clone();
    store
        .run(move |conn| {
            assert!(crate::db::apply_invite(conn, &saved_invite)?.is_ok());
            Ok(())
        })
        .await
        .unwrap();
    for (index, command) in [rename.clone(), invalidate.clone()].into_iter().enumerate() {
        assert!(
            store
                .apply([entry(
                    index as u64 + 1,
                    EntryPayload::Normal(Command::Admin(command))
                )])
                .await
                .unwrap()[0]
                .is_ok()
        );
    }
    let snap = store.build_snapshot().await.unwrap();
    let original: Image = serde_json::from_slice(snap.snapshot.0.get_ref()).unwrap();
    assert!(original.tables.iter().all(|rows| !rows.is_empty()));
    let mut receiver = Store::open(target.0.clone()).await.unwrap();
    receiver
        .install_snapshot(&snap.meta, snap.snapshot)
        .await
        .unwrap();
    let restored = receiver.build_snapshot().await.unwrap();
    let restored: Image = serde_json::from_slice(restored.snapshot.0.get_ref()).unwrap();
    assert_eq!(original.tables, restored.tables);
    assert_eq!(original.meta.last_log_id, restored.meta.last_log_id);
    drop(receiver);
    let mut receiver = Store::open(target.0.clone()).await.unwrap();
    for (index, command) in [rename.clone(), invalidate.clone()].into_iter().enumerate() {
        assert_eq!(
            receiver
                .apply([entry(
                    index as u64 + 3,
                    EntryPayload::Normal(Command::Admin(command))
                )])
                .await
                .unwrap(),
            vec![Ok(Some("{\"committed\":true}".into()))]
        );
    }
    receiver
        .run(move |conn| {
            assert_eq!(
                crate::db::apply_invite(conn, &invite)?,
                Err("invite invalidated by administrator".into())
            );
            assert!(crate::db::get_invites(conn)?.iter().all(|i| i.id != 2));
            let mut changed = rename;
            changed.action = crate::admin::Action::RenameMesh {
                id: 1,
                name: "changed".into(),
            };
            assert_eq!(
                crate::admin::apply(conn, &changed)?,
                Err("idempotency key conflict".into())
            );
            let mut changed = invalidate;
            changed.action = crate::admin::Action::InvalidateInvite { id: 1 };
            assert_eq!(
                crate::admin::apply(conn, &changed)?,
                Err("idempotency key conflict".into())
            );
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn offline_recovery_verifies_and_restores_fresh_application_without_local_identity() {
    use cat4igp_shared::control::{EnrollmentRequest, EnrollmentResponse};
    let source = Database::new();
    let target = Database::new();
    let key = libp2p::identity::Keypair::generate_ed25519();
    let transport = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id();
    let mut sender = Store::open(source.0.clone()).await.unwrap();
    sender
        .apply([
            entry(
                0,
                EntryPayload::Membership(Membership::new(
                    vec![std::collections::BTreeSet::from([1, 2, 3])],
                    None,
                )),
            ),
            entry(
                1,
                EntryPayload::Normal(Command::Initialize(crate::db::InitializeCommand {
                    signing_private_key: crate::hex_encode(&key.to_protobuf_encoding().unwrap()),
                    encryption_private_key: "01".repeat(32),
                    network_id: "recovery-test".into(),
                    applied_at: chrono::Utc::now().naive_utc(),
                })),
            ),
            entry(2, EntryPayload::Normal(invite("original", 1))),
        ])
        .await
        .unwrap();
    let authority = sender
        .run(|conn| crate::cluster::read_authority(conn))
        .await
        .unwrap();
    let signing = authority.signing_key.clone();
    let encryption = authority.encryption_key.clone();
    let check = |path: &str, kind: &str| {
        verify_recovery(path, kind, "recovery-test", &signing, &encryption)
    };
    let legacy = Database::new();
    let mut legacy_conn = SqliteConnection::establish(&legacy.0).unwrap();
    crate::db::apply_initialization(
        &mut legacy_conn,
        &crate::db::InitializeCommand {
            signing_private_key: crate::hex_encode(&key.to_protobuf_encoding().unwrap()),
            encryption_private_key: "01".repeat(32),
            network_id: "recovery-test".into(),
            applied_at: chrono::Utc::now().naive_utc(),
        },
    )
    .unwrap();
    drop(legacy_conn);
    let before = std::fs::read(&legacy.0).unwrap();
    assert!(
        check(&legacy.0, "database")
            .unwrap()
            .contains("legacy-application")
    );
    assert_eq!(std::fs::read(&legacy.0).unwrap(), before);
    let client = libp2p::identity::Keypair::generate_ed25519();
    let peer = client.public().to_peer_id().to_string();
    let enrollment = Command::Enrollment {
        peer_id: peer.clone(),
        command: crate::db::EnrollmentCommand {
            request: EnrollmentRequest {
                request_id: "enrollment".into(),
                node_name: "retained".into(),
                invitation_code: "code-1".into(),
                client_peer_id: peer,
                client_signing_key: crate::hex_encode(&client.public().encode_protobuf()),
                client_encryption_key: "02".repeat(32),
                wireguard_public_key: "wg".into(),
            },
            node_id: 42,
            auth_key: "auth".into(),
            applied_at: chrono::Utc::now().naive_utc(),
            allocation: sender
                .run(|conn| Ok(crate::db::prepare_enrollment_allocation(conn, "code-1")?))
                .await
                .unwrap(),
            response: EnrollmentResponse {
                node_id: 42,
                topology_revision: 0,
                network_id: authority.network_id,
                controller_signing_key: signing.clone(),
                controller_encryption_key: encryption.clone(),
            },
        },
    };
    let original = sender
        .apply([entry(3, EntryPayload::Normal(enrollment.clone()))])
        .await
        .unwrap();
    assert!(original[0].is_ok());
    sender.save_vote(&Vote::new(2, 1)).await.unwrap();
    sender
        .run(move |conn| {
            put(
                conn,
                "replica_binding",
                &("recovery-test", 1u64, transport.to_string()),
            )
        })
        .await
        .unwrap();
    let snap = sender.build_snapshot().await.unwrap();
    assert!(
        check(&source.0, "database")
            .unwrap()
            .contains("local_vote=true")
    );
    let file = format!("{}.snapshot", source.0);
    let bytes = snap.snapshot.0.get_ref().clone();
    std::fs::write(&file, &bytes).unwrap();
    let report = check(&file, "snapshot").unwrap();
    assert!(report.contains("local_vote=false"));
    assert!(!report.contains("code-1") && !report.contains(&signing));
    let id_table = TABLES.iter().position(|(name, _)| *name == "management_ids").unwrap();
    let receiver_db = Database::new();
    let receiver = Store::open(receiver_db.0.clone()).await.unwrap();
    let before = receiver.run(application_tables).await.unwrap();
    for mutation in 0..3 {
        let mut image: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let ids = image["tables"][id_table].as_array_mut().unwrap();
        match mutation {
            0 => ids.retain(|row| row[0] != "node"),
            1 => ids.iter_mut().find(|row| row[0] == "node").unwrap()[1] = 0.into(),
            _ => ids.push(ids[0].clone()),
        }
        let invalid = serde_json::to_vec(&image).unwrap();
        std::fs::write(&file, &invalid).unwrap();
        assert!(check(&file, "snapshot").is_err());
        assert!(install(&receiver, snap.meta.clone(), invalid).await.is_err());
        assert_eq!(receiver.run(application_tables).await.unwrap(), before);
    }
    for mutation in [0, 1, 2, 3, 4, 5, 6] {
        let mut image: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        match mutation {
            0 => image["version"] = 1.into(),
            1 => image["tables"][0][0][0] = "replica_transport_key".into(),
            2 => image["meta"]["last_log_id"] = serde_json::Value::Null,
            3 => image["tables"][9][0][3] = "broken dedup".into(),
            4 => image["tables"][0] = serde_json::json!([]),
            5 => image["reader_fence"] = 2.into(),
            _ => { image.as_object_mut().unwrap().remove("reader_fence"); },
        }
        std::fs::write(&file, serde_json::to_vec(&image).unwrap()).unwrap();
        assert!(check(&file, "snapshot").is_err(), "mutation {mutation}");
    }
    std::fs::write(&file, &bytes[..bytes.len() / 2]).unwrap();
    assert!(check(&file, "snapshot").is_err());
    std::fs::write(&file, &bytes).unwrap();
    if let Ok(binary) = std::env::var("CAT4IGP_RECOVERY_TEST_BINARY") {
        let command = || {
            let mut command = std::process::Command::new(&binary);
            command
                .arg("verify-recovery")
                .env("CLUSTER_MAINTENANCE_STOPPED", "true")
                .env("RECOVERY_FILE", &file)
                .env("RECOVERY_KIND", "snapshot")
                .env("DISCOVERY_CLUSTER_ID", "recovery-test")
                .env("DISCOVERY_SIGNING_KEY", &signing)
                .env("RECOVERY_ENCRYPTION_KEY", &encryption);
            command
        };
        let output = command().output().unwrap();
        assert!(
            output.status.success(),
            "offline CLI rejected valid snapshot"
        );
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("verified raft-application")
        );
        assert!(
            !command()
                .env("CLUSTER_MAINTENANCE_STOPPED", "false")
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(
            !command()
                .env("DISCOVERY_CLUSTER_ID", "wrong-cluster")
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    assert!(verify_recovery(&file, "snapshot", "wrong-cluster", &signing, &encryption).is_err());
    assert!(
        verify_recovery(
            &file,
            "snapshot",
            "recovery-test",
            &"00".repeat(32),
            &encryption
        )
        .is_err()
    );
    let mut receiver = Store::open(target.0.clone()).await.unwrap();
    receiver
        .install_snapshot(&snap.meta, snap.snapshot)
        .await
        .unwrap();
    receiver
        .run(|conn| {
            assert!(get::<Vote<u64>>(conn, "vote")?.is_none());
            assert!(get::<serde_json::Value>(conn, "replica_binding")?.is_none());
            assert!(
                crate::db::get_setting(conn, "replica_transport_key")
                    .optional()?
                    .is_none()
            );
            Ok(())
        })
        .await
        .unwrap();
    let restored = receiver.build_snapshot().await.unwrap();
    let restored: Image = serde_json::from_slice(restored.snapshot.0.get_ref()).unwrap();
    let original_image: Image = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored.tables, original_image.tables);
    assert_eq!(
        receiver
            .apply([entry(4, EntryPayload::Normal(enrollment))])
            .await
            .unwrap(),
        original
    );
    assert_eq!(
        receiver
            .apply([entry(5, EntryPayload::Normal(invite("original", 99)))])
            .await
            .unwrap(),
        vec![Ok(Some("code-1".into()))]
    );
    sender
        .run(|conn| {
            diesel::sql_query(
                "INSERT INTO __diesel_schema_migrations(version) VALUES ('99999999999999')",
            )
            .execute(conn)?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(check(&source.0, "database").is_err());
    let truncated = format!("{}.truncated", source.0);
    std::fs::write(&truncated, &std::fs::read(&source.0).unwrap()[..100]).unwrap();
    assert!(check(&truncated, "database").is_err());
    std::fs::remove_file(truncated).unwrap();
    std::fs::remove_file(file).unwrap();
}
