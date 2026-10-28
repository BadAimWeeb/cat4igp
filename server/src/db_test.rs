use super::*;
use diesel::{connection::SimpleConnection, migration::MigrationSource};

#[test]
fn mesh_mtu_updates_owned_tunnels_revisions_and_future_members() {
    use crate::admin::{Action, Mutation, Operation};
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    migrate(&mut conn, true).unwrap();
    conn.batch_execute("INSERT INTO nodes(id,name,auth_key) VALUES(1,'a','a'),(2,'b','b'),(3,'c','c'),(4,'d','d');
        INSERT INTO wireguard_static_key(node_id,public_key) VALUES(1,'a'),(2,'b'),(3,'c'),(4,'d');
        INSERT INTO node_control_identities(node_id,peer_id,signing_key,encryption_key) VALUES(1,'a','a','a'),(2,'b','b','b'),(3,'c','c','c'),(4,'d','d','d');").unwrap();
    let at = chrono::NaiveDate::from_ymd_opt(2026, 10, 26).unwrap().and_hms_opt(12, 0, 0).unwrap();
    let command = |key: &str, action| Mutation { request_id: key.into(), action, applied_at: at };
    for id in 1..=2 {
        assert_eq!(create_mesh_group(&mut conn, &format!("mesh-{id}"), true, 1420).unwrap(), id);
        for node in [1, 2] {
            join_mesh_at(&mut conn, node, id, at - chrono::Duration::hours(1)).unwrap();
        }
    }
    let disabled = create_mesh_group(&mut conn, "no-auto", false, 0).unwrap();
    // A manual intent on a shared tunnel does not exclude it; manual-only tunnels stay unchanged.
    create_wireguard_tunnel(&mut conn, 1, 2, 1420, false).unwrap();
    create_wireguard_tunnel(&mut conn, 1, 3, 1420, false).unwrap();
    let before = crate::admin::read(&mut conn, Operation::Inventory).unwrap();
    let snapshots: Vec<_> = (1..=4).map(|id| serde_json::to_value(topology_snapshot(&mut conn, id, 0).unwrap()).unwrap()).collect();
    let revisions: Vec<_> = (1..=4).map(|id| control_identity_for_node(&mut conn, id).unwrap().topology_revision).collect();
    let update = command("mtu", Action::SetMeshMtu { id: 1, mtu: 1380 });
    conn.batch_execute("CREATE TRIGGER fail_mtu BEFORE INSERT ON administrator_results BEGIN SELECT RAISE(ABORT,'failure'); END;").unwrap();
    assert!(crate::admin::apply(&mut conn, &update).is_err());
    assert_eq!(crate::admin::read(&mut conn, Operation::Inventory).unwrap(), before);
    for id in 1..=4 {
        assert_eq!(serde_json::to_value(topology_snapshot(&mut conn, id, 0).unwrap()).unwrap(), snapshots[(id - 1) as usize]);
        assert_eq!(control_identity_for_node(&mut conn, id).unwrap().topology_revision, revisions[(id - 1) as usize]);
    }
    conn.batch_execute("DROP TRIGGER fail_mtu;").unwrap();
    let result = crate::admin::apply(&mut conn, &update).unwrap();
    let receipt: serde_json::Value = serde_json::from_str(result.as_ref().unwrap().as_ref().unwrap()).unwrap();
    assert_eq!(receipt["affected_nodes"], serde_json::json!([1, 2]));
    assert_eq!(crate::admin::apply(&mut conn, &update).unwrap(), result);
    assert!(crate::admin::apply(&mut conn, &command("same-mtu", Action::SetMeshMtu { id: 1, mtu: 1380 })).unwrap().is_ok());
    for id in 1..=4 {
        assert_eq!(control_identity_for_node(&mut conn, id).unwrap().topology_revision,
            revisions[(id - 1) as usize] + if id <= 2 { 1 } else { 0 });
    }
    let after = crate::admin::read(&mut conn, Operation::Inventory).unwrap();
    let mut expected = before;
    expected["meshes"][0]["mtu"] = 1380.into();
    for t in expected["tunnels"].as_array_mut().unwrap() {
        if t["intents"].as_array().unwrap().iter().any(|i| i["kind"] == "mesh" && i["mesh_id"] == 1) {
            t["mtu"] = 1380.into();
        }
    }
    assert_eq!(after, expected);
    let snapshot = topology_snapshot(&mut conn, 2, 0).unwrap();
    assert_eq!(snapshot.tunnels.len(), 2);
    assert!(snapshot.tunnels.iter().all(|t| t.mtu == 1380 && t.updated_at == at.and_utc().timestamp_millis()));
    for (index, (id, mtu)) in [(0, 1380), (999, 1380), (disabled, 1380), (1, 1279), (1, 9001)].into_iter().enumerate() {
        assert!(crate::admin::apply(&mut conn, &command(&format!("bad-{index}"), Action::SetMeshMtu { id, mtu })).unwrap().is_err());
        assert_eq!(crate::admin::read(&mut conn, Operation::Inventory).unwrap(), after);
    }
    assert_eq!(crate::admin::apply(&mut conn, &command("mtu", Action::SetMeshMtu { id: 1, mtu: 1400 })).unwrap(), Err("idempotency key conflict".into()));
    assert!(crate::admin::apply(&mut conn, &command("join-later", Action::AddMembership { mesh_id: 1, node_id: 4 })).unwrap().is_ok());
    let future = topology_snapshot(&mut conn, 4, 0).unwrap();
    assert_eq!(future.tunnels.len(), 4);
    assert!(future.tunnels.iter().all(|t| t.mtu == 1380));
    // A newer explicit update from an overlapping mesh wins, but replaying an old receipt never reverts it.
    assert!(crate::admin::apply(&mut conn, &command("shared", Action::SetMeshMtu { id: 2, mtu: 1400 })).unwrap().is_ok());
    assert_eq!(crate::admin::apply(&mut conn, &update).unwrap(), result);
    assert!(topology_snapshot(&mut conn, 2, 0).unwrap().tunnels.iter().all(|t| t.mtu == if t.peer_node_id == 1 { 1400 } else { 1380 }));
}

#[test]
fn mesh_fec_policy_shared_tunnels_revisions_and_rollback() {
    use crate::admin::{Action, Mutation, Operation};
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    migrate(&mut conn, true).unwrap();
    conn.batch_execute("INSERT INTO nodes(id,name,auth_key) VALUES(1,'a','a'),(2,'b','b'),(3,'c','c');
        INSERT INTO wireguard_static_key(node_id,public_key) VALUES(1,'a'),(2,'b'),(3,'c');
        INSERT INTO node_control_identities(node_id,peer_id,signing_key,encryption_key) VALUES(1,'a','a','a'),(2,'b','b','b'),(3,'c','c','c');").unwrap();
    let at = chrono::Utc::now().naive_utc();
    let command = |key: &str, action| Mutation { request_id: key.into(), action, applied_at: at };
    for (id, fec) in [(1, false), (2, true)] {
        let create = command(&format!("create-{id}"), Action::CreateMesh {
            name: format!("mesh-{id}"), auto_wireguard: true, mtu: 1420, fec,
        });
        assert!(crate::admin::apply(&mut conn, &create).unwrap().is_ok());
        for node_id in [1, 2] {
            assert!(crate::admin::apply(&mut conn, &command(&format!("join-{id}-{node_id}"),
                Action::AddMembership { mesh_id: id, node_id })).unwrap().is_ok());
        }
    }
    let snapshot = topology_snapshot(&mut conn, 1, 0).unwrap();
    assert_eq!(snapshot.tunnels.len(), 2);
    assert!(snapshot.tunnels.iter().all(|t| t.fec));
    assert!(snapshot.tunnels.iter().any(|t| t.endpoint_ipv6));
    assert!(snapshot.tunnels.iter().any(|t| !t.endpoint_ipv6));
    // Manual-only tunnels and explicit per-tunnel FEC are independent of mesh policy.
    create_wireguard_tunnel(&mut conn, 1, 3, 1420, false).unwrap();
    conn.batch_execute("UPDATE wireguard_tunnels SET fec=1 WHERE endpoint_ipv6=1;").unwrap();
    let disable = command("disable", Action::SetMeshFec { id: 2, fec: false });
    let before = crate::admin::read(&mut conn, Operation::Inventory).unwrap();
    let revision = control_identity_for_node(&mut conn, 1).unwrap().topology_revision;
    conn.batch_execute("CREATE TRIGGER fail_fec BEFORE INSERT ON administrator_results BEGIN SELECT RAISE(ABORT,'failure'); END;").unwrap();
    assert!(crate::admin::apply(&mut conn, &disable).is_err());
    assert_eq!(crate::admin::read(&mut conn, Operation::Inventory).unwrap(), before);
    assert_eq!(control_identity_for_node(&mut conn, 1).unwrap().topology_revision, revision);
    conn.batch_execute("DROP TRIGGER fail_fec;").unwrap();
    let result = crate::admin::apply(&mut conn, &disable).unwrap();
    let receipt: serde_json::Value = serde_json::from_str(result.as_ref().unwrap().as_ref().unwrap()).unwrap();
    assert_eq!(receipt["affected_nodes"], serde_json::json!([1, 2]));
    assert_eq!(crate::admin::apply(&mut conn, &disable).unwrap(), result);
    assert_eq!(control_identity_for_node(&mut conn, 1).unwrap().topology_revision, revision + 1);
    for tunnel in topology_snapshot(&mut conn, 1, 0).unwrap().tunnels {
        assert_eq!(tunnel.fec, tunnel.endpoint_ipv6);
    }
    assert!(crate::admin::apply(&mut conn, &command("enable-first", Action::SetMeshFec { id: 1, fec: true })).unwrap().is_ok());
    assert!(crate::admin::apply(&mut conn, &command("enable-second", Action::SetMeshFec { id: 2, fec: true })).unwrap().is_ok());
    assert!(crate::admin::apply(&mut conn, &command("disable-first", Action::SetMeshFec { id: 1, fec: false })).unwrap().is_ok());
    assert!(topology_snapshot(&mut conn, 2, 0).unwrap().tunnels.iter().all(|t| t.fec));
    // Leaving the FEC-owning mesh restores the remaining mesh's policy.
    assert!(crate::admin::apply(&mut conn, &command("leave", Action::RemoveMembership { mesh_id: 2, node_id: 2 })).unwrap().is_ok());
    assert!(topology_snapshot(&mut conn, 2, 0).unwrap().tunnels.iter().all(|t| t.fec == t.endpoint_ipv6));
    // Missing FEC retains old creation fingerprints and defaults to disabled.
    let old = r#"{"action":"create_mesh","name":"legacy","auto_wireguard":true,"mtu":1420}"#;
    let action: Action = serde_json::from_str(old).unwrap();
    assert_eq!(serde_json::to_string(&action).unwrap(), old);
    assert!(crate::admin::apply(&mut conn, &command("legacy", action)).unwrap().is_ok());
    assert_eq!(crate::admin::read(&mut conn, Operation::Inventory).unwrap()["meshes"][2]["fec"], false);
    assert!(crate::admin::apply(&mut conn, &command("no-auto", Action::CreateMesh {
        name: "no-auto".into(), auto_wireguard: false, mtu: 0, fec: false,
    })).unwrap().is_ok());
    for (key, action) in [
        ("bad-create", Action::CreateMesh { name: "bad".into(), auto_wireguard: false, mtu: 0, fec: true }),
        ("bad-update", Action::SetMeshFec { id: 4, fec: true }),
        ("missing", Action::SetMeshFec { id: 999, fec: true }),
    ] {
        assert!(crate::admin::apply(&mut conn, &command(key, action)).unwrap().is_err());
    }
}

#[test]
fn rename_mesh_and_invalidate_invite_receipts_and_rollback() {
    use crate::admin::{Action, Mutation, Operation};
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    migrate(&mut conn, true).unwrap();
    let at = chrono::Utc::now().naive_utc();
    let mesh = create_mesh_group(&mut conn, "original", true, 1280).unwrap();
    let rename = Mutation {
        request_id: "rename".into(),
        action: Action::RenameMesh {
            id: mesh,
            name: "renamed".into(),
        },
        applied_at: at,
    };
    let invite = InviteCommand {
        request_id: "invite".into(),
        id: 1,
        code: "secret".into(),
        expires_at: None,
        max_uses: None,
        join_mesh: Some(mesh),
        applied_at: at,
    };
    assert!(apply_invite(&mut conn, &invite).unwrap().is_ok());
    // Multiple cached successes can depend on the same code; preserve every fingerprint.
    conn.batch_execute("INSERT INTO operator_invite_results SELECT 'alias',fingerprint,result FROM operator_invite_results WHERE request_id='invite';
        CREATE TEMP TABLE original_fingerprints AS SELECT request_id,fingerprint FROM operator_invite_results;
        CREATE TRIGGER fail_receipt BEFORE INSERT ON administrator_results BEGIN SELECT RAISE(ABORT,'failure'); END;").unwrap();
    let before = crate::admin::read(&mut conn, Operation::Inventory).unwrap();
    assert!(crate::admin::apply(&mut conn, &rename).is_err());
    assert_eq!(
        crate::admin::read(&mut conn, Operation::Inventory).unwrap(),
        before
    );
    let invalidate = Mutation {
        request_id: "invalidate".into(),
        action: Action::InvalidateInvite { id: 1 },
        applied_at: at,
    };
    assert!(crate::admin::apply(&mut conn, &invalidate).is_err());
    assert_eq!(
        apply_invite(&mut conn, &invite).unwrap(),
        Ok("secret".into())
    );
    assert_eq!(
        crate::admin::read(&mut conn, Operation::Inventory).unwrap(),
        before
    );
    conn.batch_execute("DROP TRIGGER fail_receipt").unwrap();
    for command in [&rename, &invalidate] {
        let result = crate::admin::apply(&mut conn, command).unwrap();
        assert!(result.is_ok());
        assert_eq!(crate::admin::apply(&mut conn, command).unwrap(), result);
    }
    let renamed = crate::admin::read(&mut conn, Operation::Inventory).unwrap();
    let mut expected = before;
    expected["meshes"][0]["name"] = "renamed".into();
    expected["invites"] = serde_json::json!([]);
    assert_eq!(renamed, expected);
    for request_id in ["invite", "alias"] {
        assert_eq!(
            apply_invite(
                &mut conn,
                &InviteCommand {
                    request_id: request_id.into(),
                    ..invite.clone()
                }
            )
            .unwrap(),
            Err("invite invalidated by administrator".into())
        );
    }
    conn.batch_execute("CREATE TEMP TABLE fingerprint_check(n INTEGER CHECK(n=0)); INSERT INTO fingerprint_check SELECT COUNT(*) FROM operator_invite_results r JOIN original_fingerprints o USING(request_id) WHERE r.fingerprint!=o.fingerprint;").unwrap();
    assert!(get_invites(&mut conn).unwrap().is_empty());
    for action in [
        Action::RenameMesh {
            id: mesh,
            name: "different".into(),
        },
        Action::InvalidateInvite { id: 2 },
    ] {
        let request_id = if matches!(action, Action::RenameMesh { .. }) {
            "rename"
        } else {
            "invalidate"
        };
        assert_eq!(
            crate::admin::apply(
                &mut conn,
                &Mutation {
                    request_id: request_id.into(),
                    action,
                    applied_at: at
                }
            )
            .unwrap(),
            Err("idempotency key conflict".into())
        );
    }
    for (index, action) in [
        Action::RenameMesh {
            id: 0,
            name: "valid".into(),
        },
        Action::RenameMesh {
            id: i32::MAX,
            name: "valid".into(),
        },
        Action::RenameMesh {
            id: mesh,
            name: " \t".into(),
        },
        Action::RenameMesh {
            id: mesh,
            name: "a\nb".into(),
        },
        Action::RenameMesh {
            id: mesh,
            name: "é".repeat(129),
        },
        Action::InvalidateInvite { id: -1 },
        Action::InvalidateInvite { id: i32::MAX },
    ]
    .into_iter()
    .enumerate()
    {
        let command = Mutation {
            request_id: format!("invalid-{index}"),
            action,
            applied_at: at,
        };
        let result = crate::admin::apply(&mut conn, &command).unwrap();
        assert!(result.is_err());
        assert_eq!(crate::admin::apply(&mut conn, &command).unwrap(), result);
        assert_eq!(
            crate::admin::read(&mut conn, Operation::Inventory).unwrap(),
            renamed
        );
    }
}

#[test]
fn management_rejection_invite_invalidation_and_implicit_id_nonreuse() {
    use crate::admin::{Action, IntentKind, Mutation};
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    migrate(&mut conn, true).unwrap();
    conn.batch_execute("INSERT INTO nodes(id,name,auth_key) VALUES(1,'a','a'),(2,'b','b');
        INSERT INTO wireguard_tunnels(id,node_id_peer1,node_id_peer2,endpoint_ipv6) VALUES(1,1,2,0);").unwrap();
    let at = chrono::Utc::now().naive_utc();
    for (index, action) in [
        Action::AddMembership {
            mesh_id: 99,
            node_id: 1,
        },
        Action::RemoveMembership {
            mesh_id: 99,
            node_id: 1,
        },
        Action::DeleteMesh { id: 99 },
        Action::DeleteNode { id: 99 },
        Action::RemoveTunnelIntent {
            tunnel_id: 99,
            kind: IntentKind::Legacy,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let before = crate::admin::read(&mut conn, crate::admin::Operation::Inventory).unwrap();
        assert!(
            crate::admin::apply(
                &mut conn,
                &Mutation {
                    request_id: format!("rejected-{index}"),
                    action,
                    applied_at: at,
                }
            )
            .unwrap()
            .is_err()
        );
        assert_eq!(
            crate::admin::read(&mut conn, crate::admin::Operation::Inventory).unwrap(),
            before
        );
    }
    let mesh = create_mesh_group(&mut conn, "mesh", false, 1280).unwrap();
    let invite = InviteCommand {
        request_id: "mesh-invite".into(),
        id: 1,
        code: "mesh-code".into(),
        expires_at: None,
        max_uses: Some(2),
        join_mesh: Some(mesh),
        applied_at: at,
    };
    assert!(apply_invite(&mut conn, &invite).unwrap().is_ok());
    #[derive(QueryableByName)]
    struct Fingerprint {
        #[diesel(sql_type = diesel::sql_types::Text)]
        fingerprint: String,
    }
    let fingerprint = diesel::sql_query(
        "SELECT fingerprint FROM operator_invite_results WHERE request_id='mesh-invite'",
    )
    .get_result::<Fingerprint>(&mut conn)
    .unwrap()
    .fingerprint;
    conn.batch_execute("CREATE TRIGGER fail_mesh_delete BEFORE DELETE ON mesh_groups BEGIN SELECT RAISE(ABORT,'failure'); END;").unwrap();
    let deletion = Mutation {
        request_id: "delete-mesh".into(),
        action: Action::DeleteMesh { id: mesh },
        applied_at: at,
    };
    assert!(crate::admin::apply(&mut conn, &deletion).is_err());
    assert_eq!(
        apply_invite(&mut conn, &invite).unwrap(),
        Ok("mesh-code".into())
    );
    assert_eq!(get_invites(&mut conn).unwrap().len(), 1);
    conn.batch_execute("DROP TRIGGER fail_mesh_delete").unwrap();
    assert!(crate::admin::apply(&mut conn, &deletion).unwrap().is_ok());
    assert_eq!(
        apply_invite(&mut conn, &invite).unwrap(),
        Err("invite invalidated by mesh deletion".into())
    );
    assert!(get_invites(&mut conn).unwrap().is_empty());
    assert_eq!(
        diesel::sql_query(
            "SELECT fingerprint FROM operator_invite_results WHERE request_id='mesh-invite'"
        )
        .get_result::<Fingerprint>(&mut conn)
        .unwrap()
        .fingerprint,
        fingerprint
    );
    assert!(create_mesh_group(&mut conn, "replacement", false, 1280).unwrap() > mesh);
    conn.batch_execute("INSERT INTO invites(code) VALUES('node-invite');")
        .unwrap();
    let highest = register_node(&mut conn, "highest", "node-invite")
        .unwrap()
        .0;
    assert!(
        crate::admin::apply(
            &mut conn,
            &Mutation {
                request_id: "delete-highest-node".into(),
                action: Action::DeleteNode { id: highest },
                applied_at: at,
            }
        )
        .unwrap()
        .is_ok()
    );
    assert!(
        register_node(&mut conn, "replacement", "node-invite")
            .unwrap()
            .0
            > highest
    );
}

#[test]
fn invite_settings_retry_restart_conflict_rollback_and_determinism() {
    let path = std::env::temp_dir().join(format!("cat4igp-invite-{}.sqlite", Uuid::new_v4()));
    let mut first = SqliteConnection::establish(path.to_str().unwrap()).unwrap();
    let mut second = SqliteConnection::establish(":memory:").unwrap();
    let time = chrono::DateTime::from_timestamp(1_790_812_800, 0)
        .unwrap()
        .naive_utc();
    let init = InitializeCommand {
        signing_private_key: crate::hex_encode(
            &libp2p::identity::Keypair::generate_ed25519()
                .to_protobuf_encoding()
                .unwrap(),
        ),
        encryption_private_key: "01".repeat(32),
        network_id: "network".into(),
        applied_at: time,
    };
    let mut command = InviteCommand {
        request_id: "retry".into(),
        id: 7,
        code: "selected-code".into(),
        expires_at: None,
        max_uses: Some(1),
        join_mesh: None,
        applied_at: time,
    };
    for conn in [&mut first, &mut second] {
        migrate(conn, true).unwrap();
        conn.batch_execute("CREATE TRIGGER fail_setting BEFORE INSERT ON settings WHEN NEW.key = 'control_network_id' BEGIN SELECT RAISE(ABORT, 'failure'); END;").unwrap();
        assert!(apply_initialization(conn, &init).is_err());
        assert!(matches!(
            get_setting(conn, "control_private_key"),
            Err(diesel::result::Error::NotFound)
        ));
        conn.batch_execute("DROP TRIGGER fail_setting").unwrap();
        apply_initialization(conn, &init).unwrap();
        conn.batch_execute("CREATE TRIGGER fail_invite_result BEFORE INSERT ON operator_invite_results BEGIN SELECT RAISE(ABORT, 'failure'); END;").unwrap();
        assert!(apply_invite(conn, &command).is_err());
        assert!(get_invites(conn).unwrap().is_empty());
        conn.batch_execute("DROP TRIGGER fail_invite_result")
            .unwrap();
        assert_eq!(
            apply_invite(conn, &command).unwrap(),
            Ok("selected-code".into())
        );
        assert_eq!(
            apply_invite(conn, &command).unwrap(),
            Ok("selected-code".into())
        );
    }
    let serialized = serde_json::to_string(&command).unwrap();
    let replay: InviteCommand = serde_json::from_str(&serialized).unwrap();
    fn raft_command<T: openraft::AppData>(_: &T) {}
    raft_command(&replay);
    raft_command(&init);
    assert_eq!(
        apply_invite(&mut second, &replay).unwrap(),
        Ok("selected-code".into())
    );
    let a = get_invites(&mut first).unwrap().remove(0);
    let b = get_invites(&mut second).unwrap().remove(0);
    assert_eq!(
        (a.id, a.code, a.created_at, a.used_count),
        (b.id, b.code, b.created_at, b.used_count)
    );
    assert_eq!(
        get_setting(&mut first, "control_private_key").unwrap(),
        get_setting(&mut second, "control_private_key").unwrap()
    );
    drop(first);
    let mut first = SqliteConnection::establish(path.to_str().unwrap()).unwrap();
    command.id = 8;
    command.code = "new-randomness".into();
    command.applied_at += chrono::Duration::days(1);
    assert_eq!(
        apply_invite(&mut first, &command).unwrap(),
        Ok("selected-code".into())
    );
    command.max_uses = Some(2);
    assert!(apply_invite(&mut first, &command).unwrap().is_err());
    assert_eq!(get_invites(&mut first).unwrap().len(), 1);
    command.request_id = "invalid-mesh".into();
    command.join_mesh = Some(99);
    assert!(apply_invite(&mut first, &command).unwrap().is_err());
    first.batch_execute("INSERT INTO mesh_groups (id, name, auto_wireguard, auto_wireguard_mtu, created_at) VALUES (99, 'mesh', 0, 0, '2026-01-01')").unwrap();
    assert!(apply_invite(&mut first, &command).unwrap().is_err());
    let replacement = InitializeCommand {
        network_id: "replacement".into(),
        applied_at: command.applied_at,
        ..init
    };
    apply_initialization(&mut first, &replacement).unwrap();
    assert_eq!(
        get_setting(&mut first, "control_network_id").unwrap(),
        "network"
    );
    drop(first);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn schema_repairs_preserve_legacy_data() {
    for duplicates in [
        "INSERT INTO settings (key, value, created_at, updated_at) VALUES ('key', 'a', '2026-01-01', '2026-01-01'), ('key', 'b', '2026-01-01', '2026-01-01')",
        "INSERT INTO mesh_group_memberships (mesh_group_id, node_id, created_at) VALUES (1, 2, '2026-01-01'), (1, 2, '2026-01-01')",
    ] {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        let mut migrations =
            <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(
                &MIGRATIONS,
            )
            .unwrap();
        migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
        assert!(conn.applied_migrations().unwrap().is_empty());
        conn.run_migrations(&migrations[..5]).unwrap();
        conn.batch_execute(duplicates).unwrap();
        let error = migrate(&mut conn, true).unwrap_err();
        assert!(error.contains("repair_duplicate"), "{error}");
        assert_eq!(conn.applied_migrations().unwrap().len(), 5);
        let count = if duplicates.contains("settings") {
            crate::schema::settings::table
                .count()
                .get_result::<i64>(&mut conn)
                .unwrap()
        } else {
            crate::schema::mesh_group_memberships::table
                .count()
                .get_result::<i64>(&mut conn)
                .unwrap()
        };
        assert_eq!(count, 2);
    }
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    migrate(&mut conn, true).unwrap();
    set_setting(&mut conn, "key", "a").unwrap();
    set_setting(&mut conn, "key", "b").unwrap();
    assert_eq!(get_setting(&mut conn, "key").unwrap(), "b");
    let mesh = create_mesh_group(&mut conn, "mesh", false, 1280).unwrap();
    join_mesh(&mut conn, 1, mesh).unwrap();
    join_mesh(&mut conn, 1, mesh).unwrap();
    assert_eq!(
        crate::schema::mesh_group_memberships::table
            .count()
            .get_result::<i64>(&mut conn)
            .unwrap(),
        1
    );
}

#[test]
fn deterministic_answer_retry_and_atomic_rollback() {
    let command = AnswerCommand {
        node_id: 1,
        request_id: "retry-1".into(),
        answer: cat4igp_shared::control::TunnelAnswer {
            tunnel_id: 1,
            endpoint: Some("192.0.2.1:1234".into()),
            decline_type: None,
        },
        applied_at: chrono::DateTime::from_timestamp(1_790_812_800, 0)
            .unwrap()
            .naive_utc(),
    };
    let setup = || {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        migrate(&mut conn, true).unwrap();
        conn.batch_execute("INSERT INTO nodes (id, name, auth_key) VALUES (1, 'a', 'a'), (2, 'b', 'b');
            INSERT INTO node_control_identities (node_id, peer_id, signing_key, encryption_key) VALUES (1, 'a', 'a', 'a'), (2, 'b', 'b', 'b');
            INSERT INTO wireguard_tunnels (id, node_id_peer1, node_id_peer2, endpoint_ipv6) VALUES (1, 1, 2, 0);").unwrap();
        conn
    };
    let mut first = setup();
    let mut second = setup();
    for conn in [&mut first, &mut second] {
        assert_eq!(apply_answer(conn, &command).unwrap(), "accepted");
        assert_eq!(apply_answer(conn, &command).unwrap(), "accepted");
        assert_eq!(
            control_identity_for_node(conn, 1)
                .unwrap()
                .topology_revision,
            1
        );
        assert_eq!(
            control_identity_for_node(conn, 2)
                .unwrap()
                .topology_revision,
            1
        );
    }
    let rows = |conn: &mut SqliteConnection| {
        crate::schema::wireguard_tunnels::table
            .select((
                crate::schema::wireguard_tunnels::endpoint_peer1,
                crate::schema::wireguard_tunnels::updated_at,
            ))
            .first::<(Option<String>, chrono::NaiveDateTime)>(conn)
            .unwrap()
    };
    assert_eq!(rows(&mut first), rows(&mut second));
    let mut conflict = command;
    conflict.answer.endpoint = Some("192.0.2.2:1234".into());
    assert_eq!(
        apply_answer(&mut first, &conflict).unwrap(),
        "request ID reused with different answer"
    );
    conflict.request_id = "retry-2".into();
    first.batch_execute("CREATE TRIGGER fail_result BEFORE INSERT ON control_answer_results BEGIN SELECT RAISE(ABORT, 'disk failure'); END;").unwrap();
    assert!(apply_answer(&mut first, &conflict).is_err());
    assert_eq!(rows(&mut first), rows(&mut second));
    assert_eq!(
        control_identity_for_node(&mut first, 1)
            .unwrap()
            .topology_revision,
        1
    );
    first.batch_execute("DROP TRIGGER fail_result").unwrap();
    assert_eq!(apply_answer(&mut first, &conflict).unwrap(), "accepted");
    conflict.node_id = 3;
    assert_eq!(
        apply_answer(&mut first, &conflict).unwrap(),
        "unknown tunnel or unauthorized peer"
    );
}

#[test]
fn enrollment_retry_restart_conflict_and_rollback() {
    use cat4igp_shared::control::{ControlResponse, EnrollmentRequest, EnrollmentResponse};
    let path = std::env::temp_dir().join(format!("cat4igp-enrollment-{}.sqlite", Uuid::new_v4()));
    let setup = |conn: &mut SqliteConnection| {
        migrate(conn, true).unwrap();
        conn.batch_execute("INSERT INTO invites (code, max_uses, override_join_mesh) VALUES ('invite', 1, 1);
            INSERT INTO mesh_groups (id, name, auto_wireguard, auto_wireguard_mtu, created_at, auto_wireguard_fec) VALUES (1, 'mesh', 1, 1280, '2026-01-01 00:00:00', 1);
            INSERT INTO nodes (id, name, auth_key) VALUES (1, 'existing', 'existing');
            INSERT INTO node_control_identities (node_id, peer_id, signing_key, encryption_key) VALUES (1, 'existing', 'key', 'key');
            INSERT INTO mesh_group_memberships (mesh_group_id, node_id, created_at) VALUES (1, 1, '2026-01-01 00:00:00');
            INSERT INTO wireguard_static_key (node_id, public_key) VALUES (1, 'key');").unwrap();
    };
    let mut conn = SqliteConnection::establish(path.to_str().unwrap()).unwrap();
    setup(&mut conn);
    let mut command = EnrollmentCommand {
        allocation: prepare_enrollment_allocation(&mut conn, "invite").unwrap(),
        request: EnrollmentRequest {
            request_id: "retry".into(),
            node_name: "new".into(),
            invitation_code: "invite".into(),
            client_peer_id: "peer".into(),
            client_signing_key: "signing".into(),
            client_encryption_key: "encryption".into(),
            wireguard_public_key: "wg".into(),
        },
        node_id: 2,
        auth_key: "explicit-auth".into(),
        applied_at: chrono::DateTime::from_timestamp(1_790_812_800, 0)
            .unwrap()
            .naive_utc(),
        response: EnrollmentResponse {
            node_id: 2,
            topology_revision: 0,
            network_id: "network".into(),
            controller_signing_key: "controller".into(),
            controller_encryption_key: "controller-encryption".into(),
        },
    };
    conn.batch_execute("CREATE TRIGGER fail_enrollment BEFORE INSERT ON control_enrollment_results BEGIN SELECT RAISE(ABORT, 'disk failure'); END;").unwrap();
    assert!(apply_enrollment(&mut conn, &command).is_err());
    assert_eq!(get_invites(&mut conn).unwrap()[0].used_count, 0);
    assert_eq!(get_node_list(&mut conn).unwrap().len(), 1);
    assert_eq!(
        control_identity_for_node(&mut conn, 1)
            .unwrap()
            .topology_revision,
        0
    );
    assert!(get_wireguard_answers(&mut conn, 1).unwrap().is_empty());
    conn.batch_execute("DROP TRIGGER fail_enrollment").unwrap();
    let (original, snapshots) = apply_enrollment(&mut conn, &command).unwrap();
    assert!(
        matches!(&original, ControlResponse::Enrolled(result) if result.node_id == 2 && result.topology_revision == 1)
    );
    assert_eq!(snapshots.len(), 2);
    assert!(snapshots.iter().all(|s| s.tunnels.len() == 2 && s.tunnels.iter().all(|t| t.fec)));
    let mut replica = SqliteConnection::establish(":memory:").unwrap();
    setup(&mut replica);
    let replay = apply_enrollment(&mut replica, &command).unwrap();
    assert_eq!(
        serde_json::to_string(&snapshots).unwrap(),
        serde_json::to_string(&replay.1).unwrap()
    );
    drop(conn);
    let mut conn = SqliteConnection::establish(path.to_str().unwrap()).unwrap();
    // New ingress randomness/time and subsequent revisions cannot change the original reply.
    command.auth_key = "different".into();
    command.node_id = 3;
    command.applied_at += chrono::Duration::days(1);
    command.response.network_id = "changed-ingress-context".into();
    bump_control_revision(&mut conn, 2).unwrap();
    let (retry, pushes) = apply_enrollment(&mut conn, &command).unwrap();
    assert_eq!(
        serde_json::to_string(&original).unwrap(),
        serde_json::to_string(&retry).unwrap()
    );
    assert!(pushes.is_empty());
    command.request.client_peer_id = "different-principal".into();
    assert!(matches!(
        apply_enrollment(&mut conn, &command).unwrap().0,
        ControlResponse::Rejected(_)
    ));
    command.request.client_peer_id = "peer".into();
    command.request.wireguard_public_key = "conflicting".into();
    assert!(matches!(
        apply_enrollment(&mut conn, &command).unwrap().0,
        ControlResponse::Rejected(_)
    ));
    command.request.request_id = "another-id".into();
    assert!(matches!(
        apply_enrollment(&mut conn, &command).unwrap().0,
        ControlResponse::Rejected(_)
    ));
    assert_eq!(get_invites(&mut conn).unwrap()[0].used_count, 1);
    assert_eq!(get_node_list(&mut conn).unwrap().len(), 2);
    assert_eq!(get_wireguard_answers(&mut conn, 2).unwrap().len(), 2);
    // Capacity/expiry and invalid legacy mesh references are durable outcomes too.
    command.request.client_peer_id = "rejected-peer".into();
    command.request.request_id = "rejected-request".into();
    let rejected = apply_enrollment(&mut conn, &command).unwrap().0;
    assert!(matches!(rejected, ControlResponse::Rejected(_)));
    conn.batch_execute("UPDATE invites SET max_uses = 10")
        .unwrap();
    drop(conn);
    let mut conn = SqliteConnection::establish(path.to_str().unwrap()).unwrap();
    assert_eq!(
        serde_json::to_string(&rejected).unwrap(),
        serde_json::to_string(&apply_enrollment(&mut conn, &command).unwrap().0).unwrap()
    );
    for (peer, update) in [
        (
            "expired",
            "UPDATE invites SET expires_at = '2026-01-01 00:00:00'",
        ),
        (
            "missing-mesh",
            "UPDATE invites SET expires_at = NULL, override_join_mesh = 999",
        ),
    ] {
        conn.batch_execute(update).unwrap();
        command.request.client_peer_id = peer.into();
        command.request.request_id = peer.into();
        assert!(matches!(
            apply_enrollment(&mut conn, &command).unwrap().0,
            ControlResponse::Rejected(_)
        ));
    }
    assert_eq!(get_invites(&mut conn).unwrap()[0].used_count, 1);
    assert_eq!(get_node_list(&mut conn).unwrap().len(), 2);
    drop(conn);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn embedded_migration_lifecycle() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    assert!(migrate(&mut conn, false).is_err());
    migrate(&mut conn, true).unwrap();
    assert_eq!(conn.applied_migrations().unwrap().len(), 12);
    migrate(&mut conn, true).unwrap();
    migrate(&mut conn, false).unwrap();
    assert_eq!(conn.applied_migrations().unwrap().len(), 12);
    crate::schema::node_control_identities::table
        .count()
        .get_result::<i64>(&mut conn)
        .unwrap();

    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations =
        <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS)
            .unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..3]).unwrap();
    conn.batch_execute("INSERT INTO wireguard_tunnels (id, node_id_peer1, node_id_peer2, endpoint_ipv6) VALUES (1, 10, 20, 0);
        ALTER TABLE wireguard_tunnels ADD COLUMN faketcp BOOL NOT NULL DEFAULT 0;").unwrap();
    // The UDP migration adds fec before hitting this deliberately conflicting column.
    assert!(migrate(&mut conn, true).is_err());
    assert_eq!(conn.applied_migrations().unwrap().len(), 3);
    assert!(
        conn.batch_execute("SELECT fec FROM wireguard_tunnels")
            .is_err()
    );
    conn.batch_execute("ALTER TABLE wireguard_tunnels DROP COLUMN faketcp")
        .unwrap();
    migrate(&mut conn, true).unwrap();
    use crate::schema::wireguard_tunnels::dsl::*;
    assert_eq!(
        wireguard_tunnels
            .select((id, node_id_peer1, node_id_peer2, fec, faketcp))
            .first::<(i32, i32, i32, bool, bool)>(&mut conn)
            .unwrap(),
        (1, 10, 20, false, false)
    );
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.batch_execute("SELECT override_join_mesh FROM invites")
        .unwrap();
    migrate(&mut conn, true).unwrap();
}
