use super::*;
use diesel::{connection::SimpleConnection, migration::MigrationSource};

#[test]
fn capability_reports_distinguish_unknown_and_unsupported() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    migrate(&mut conn, true).unwrap();
    assert_eq!(feature_support(&mut conn, 7).unwrap(), None);
    let mut features = cat4igp_shared::control::FeatureSupport::default();
    set_feature_support(&mut conn, 7, features).unwrap();
    assert_eq!(feature_support(&mut conn, 7).unwrap(), Some(features));
    features.wireguard = true;
    set_feature_support(&mut conn, 7, features).unwrap();
    assert_eq!(feature_support(&mut conn, 7).unwrap(), Some(features));
}

#[test]
fn global_tunnel_ids_remap_and_allocate() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    let target = migrations.iter().position(|migration| migration.name().version().to_string() == "202611140000000000").unwrap();
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..target]).unwrap();
    conn.batch_execute("INSERT INTO wireguard_tunnels(id,node_id_peer1,node_id_peer2,endpoint_ipv6) VALUES(1,1,2,0); INSERT INTO l2tpv2_tunnels VALUES(1,1,2,'a','b',1701,1702,'10.0.0.1','10.0.0.2','secret',1400,NULL),(3,1,2,'a','b',1701,1702,'10.0.0.1','10.0.0.2','secret',1400,NULL); INSERT INTO l2tpv3_tunnels VALUES(1,'static',1,2,'a','b',1,2,1,2,'0123456789abcdef','fedcba9876543210','pure',NULL,1500),(3,'static',1,2,'a','b',1,2,1,2,'0123456789abcdef','fedcba9876543210','pure',NULL,1500),(4,'static',1,2,'a','b',1,2,1,2,'0123456789abcdef','fedcba9876543210','pure',NULL,1500); INSERT INTO application_kv VALUES('l2tp_active/1','true'),('management_id/l2tp','20'),('management_id/l2tpv2','30'),('administrator_result/historical',json_object('fingerprint','f','result','old')); INSERT INTO node_control_identities(node_id,peer_id,signing_key,encryption_key) VALUES(1,'a','a','a'),(2,'b','b','b');").unwrap();
    conn.run_migrations(&migrations[target..=target]).unwrap();
    conn.batch_execute("CREATE TEMP TABLE verify_global(ok INTEGER NOT NULL CHECK(ok=1)); INSERT INTO verify_global SELECT count(*)=1 FROM wireguard_tunnels WHERE id=1; INSERT INTO verify_global SELECT count(*)=2 FROM l2tpv2_tunnels WHERE id IN (3,31); INSERT INTO verify_global SELECT count(*)=3 FROM l2tpv3_tunnels WHERE id IN (4,32,33); INSERT INTO verify_global SELECT count(*)=1 FROM application_kv WHERE key='l2tp_active/32' AND value='true'; INSERT INTO verify_global SELECT count(*)=1 FROM application_kv WHERE key='administrator_result/historical' AND json_extract(value,'$.result')='old'; INSERT INTO verify_global SELECT count(*)=2 FROM node_control_identities WHERE topology_revision=1;").unwrap();
    assert_eq!(next_management_id(&mut conn, "tunnel").unwrap(), 34);
    assert!(conn.batch_execute("INSERT INTO l2tpv2_tunnels SELECT 1,node_id_peer1,node_id_peer2,endpoint_peer1,endpoint_peer2,udp_port_peer1,udp_port_peer2,address_peer1,address_peer2,secret,mtu,wireguard_tunnel_id FROM l2tpv2_tunnels WHERE id=3;").is_err());
    assert!(conn.batch_execute("UPDATE l2tpv3_tunnels SET id=3 WHERE id=4;").is_err());
    assert!(conn.revert_last_migration(MIGRATIONS).is_err());
    conn.batch_execute("INSERT INTO l2tpv2_tunnels SELECT 34,node_id_peer1,node_id_peer2,endpoint_peer1,endpoint_peer2,udp_port_peer1,udp_port_peer2,address_peer1,address_peer2,secret,mtu,wireguard_tunnel_id FROM l2tpv2_tunnels WHERE id=3; DELETE FROM l2tpv2_tunnels WHERE id=34;").unwrap();
    conn.batch_execute("UPDATE l2tpv2_tunnels SET wireguard_tunnel_id=1 WHERE id=3; INSERT INTO verify_global SELECT count(*)=1 FROM tunnel_dependencies WHERE child_id=3 AND parent_id=1; UPDATE l2tpv2_tunnels SET wireguard_tunnel_id=99 WHERE id=3; INSERT INTO verify_global SELECT count(*)=1 FROM tunnel_dependencies WHERE child_id=3 AND parent_id=99; UPDATE l2tpv2_tunnels SET wireguard_tunnel_id=NULL WHERE id=3; INSERT INTO verify_global SELECT count(*)=0 FROM tunnel_dependencies WHERE child_id=3;").unwrap();
    assert_eq!(next_management_id(&mut conn, "tunnel").unwrap(), 35);
}

#[test]
fn global_tunnel_id_migration_rejects_invalid_counter_and_overflow_atomically() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    let target = migrations.iter().position(|migration| migration.name().version().to_string() == "202611140000000000").unwrap();
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..target]).unwrap();
    conn.batch_execute("INSERT INTO wireguard_tunnels(id,node_id_peer1,node_id_peer2,endpoint_ipv6) VALUES(1,1,2,0); INSERT INTO l2tpv2_tunnels VALUES(1,1,2,'a','b',1701,1702,'10.0.0.1','10.0.0.2','secret',1400,NULL); INSERT INTO application_kv VALUES('management_id/l2tp','\"invalid\"');").unwrap();
    assert!(conn.run_migrations(&migrations[target..=target]).is_err());
    conn.batch_execute("UPDATE application_kv SET value='2147483647' WHERE key='management_id/l2tp';").unwrap();
    assert!(conn.run_migrations(&migrations[target..=target]).is_err());
    conn.batch_execute("CREATE TEMP TABLE verify_rollback(ok INTEGER NOT NULL CHECK(ok=1)); INSERT INTO verify_rollback SELECT count(*)=1 FROM l2tpv2_tunnels WHERE id=1; INSERT INTO verify_rollback SELECT count(*)=1 FROM wireguard_tunnels WHERE id=1;").unwrap();
    conn.batch_execute("UPDATE application_kv SET value='10' WHERE key='management_id/l2tp';").unwrap();
    conn.run_migrations(&migrations[target..=target]).unwrap();
    assert_eq!(next_management_id(&mut conn, "tunnel").unwrap(), 12);
}

#[test]
fn migration_rejects_unknown_schema_before_pending_changes() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    let target = migrations.iter().position(|migration| migration.name().version().to_string() == "202611110000000000").unwrap();
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..target]).unwrap();
    conn.batch_execute("INSERT INTO __diesel_schema_migrations(version) VALUES('99999999999999'); INSERT INTO l2tpv3_tunnels VALUES(1,'static',1,2,'a','b',1,2,1,2,'0123456789abcdef','fedcba9876543210','pure',NULL,1500);").unwrap();
    let before = conn.applied_migrations().unwrap();
    assert!(migrate(&mut conn, true).unwrap_err().contains("coordinated upgrade required"));
    assert_eq!(conn.applied_migrations().unwrap(), before);
    // The pending cookie trigger must not have been installed, and data remains intact.
    conn.batch_execute("UPDATE l2tpv3_tunnels SET cookie_peer1='0123456789abcdef'||char(0)||'x' WHERE id=1; CREATE TEMP TABLE data_check(ok INTEGER CHECK(ok=1)); INSERT INTO data_check SELECT count(*)=1 FROM l2tpv3_tunnels WHERE id=1 AND cookie_peer2='fedcba9876543210';").unwrap();
}

#[test]
fn l2tpv3_cookie_migration_validation_and_downgrade() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    let target = migrations.iter().position(|migration| migration.name().version().to_string() == "202611110000000000").unwrap();
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..target]).unwrap();
    let insert = "INSERT INTO l2tpv3_tunnels VALUES(1,'static',1,2,'a','b',1,2,1,2,'0123456789abcdef','fedcba9876543210','pure',NULL,1500)";
    conn.batch_execute(insert).unwrap();
    for column in ["cookie_peer1", "cookie_peer2"] {
        for value in ["'0123456789abcdef'||char(0)||'x'", "x'30313233343536373839616263646566'"] {
            // Bypass the old constraints to model malformed legacy databases of all types.
            conn.batch_execute("PRAGMA ignore_check_constraints=ON;").unwrap();
            conn.batch_execute(&format!("UPDATE l2tpv3_tunnels SET {column}={value} WHERE id=1;")).unwrap();
            conn.batch_execute("PRAGMA ignore_check_constraints=OFF;").unwrap();
            assert!(conn.run_migrations(&migrations[target..=target]).is_err());
            conn.batch_execute(&format!("CREATE TEMP TABLE data_check(ok INTEGER CHECK(ok=1)); INSERT INTO data_check SELECT CASE WHEN count(*)=1 AND {column} IS {value} THEN 1 ELSE 0 END FROM l2tpv3_tunnels; DROP TABLE data_check;")).unwrap();
            conn.batch_execute(&format!("UPDATE l2tpv3_tunnels SET {column}='0123456789abcdef' WHERE id=1;")).unwrap();
        }
    }
    conn.run_migrations(&migrations[target..=target]).unwrap();
    for column in ["cookie_peer1", "cookie_peer2"] {
        for value in ["'0123456789abcdef'||char(0)||'x'", "'0123456789abcde'||char(0)", "x'30313233343536373839616263646566'", "NULL", "'0123456789abcdeF'"] {
            assert!(conn.batch_execute(&format!("UPDATE l2tpv3_tunnels SET {column}={value} WHERE id=1;")).is_err());
            assert!(conn.batch_execute(&format!("INSERT INTO l2tpv3_tunnels SELECT 2,construction,node_id_peer1,node_id_peer2,endpoint_peer1,endpoint_peer2,udp_port_peer1,udp_port_peer2,session_id_peer1,session_id_peer2,{}, {},security_mode,wireguard_tunnel_id,mtu FROM l2tpv3_tunnels WHERE id=1;", if column == "cookie_peer1" { value } else { "cookie_peer1" }, if column == "cookie_peer2" { value } else { "cookie_peer2" })).is_err());
        }
    }
    conn.batch_execute("UPDATE l2tpv3_tunnels SET cookie_peer2='fedcba9876543210' WHERE id=1; INSERT INTO l2tpv3_tunnels SELECT 2,construction,node_id_peer1,node_id_peer2,endpoint_peer1,endpoint_peer2,udp_port_peer1,udp_port_peer2,session_id_peer1,session_id_peer2,cookie_peer1,cookie_peer2,security_mode,wireguard_tunnel_id,mtu FROM l2tpv3_tunnels WHERE id=1;").unwrap();
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.batch_execute("UPDATE l2tpv3_tunnels SET cookie_peer1='0123456789abcdef'||char(0)||'x' WHERE id=1; CREATE TEMP TABLE downgrade_check(ok INTEGER CHECK(ok=1)); INSERT INTO downgrade_check SELECT count(*)=2 FROM l2tpv3_tunnels;").unwrap();
}

#[test]
fn tunnel_intent_kv_preserves_owners_and_conflicts() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    let target = migrations.iter().position(|migration| migration.name().version().to_string() == "202611100000000000").unwrap();
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..target]).unwrap();
    conn.batch_execute("INSERT INTO tunnel_intents VALUES(1,'mesh',7),(1,'manual',0),(10,'legacy',-3);").unwrap();
    conn.run_migrations(&migrations[target..=target]).unwrap();
    assert!(conn.batch_execute("INSERT INTO tunnel_intents VALUES(1,'mesh',7);").is_err());
    conn.batch_execute("INSERT OR IGNORE INTO tunnel_intents VALUES(1,'mesh',7); INSERT INTO tunnel_intents VALUES(1,'legacy',0);").unwrap();
    assert!(conn.batch_execute("INSERT INTO tunnel_intents VALUES(1,'legacy',NULL);").is_err());
    assert!(conn.batch_execute("INSERT INTO application_kv VALUES('tunnel_intent/1/mesh/8','[2,\"mesh\",8]');").is_err());
    assert!(conn.batch_execute("UPDATE application_kv SET value='[2,\"mesh\",7]' WHERE key='tunnel_intent/1/mesh/7';").is_err());
    assert!(conn.batch_execute("INSERT INTO tunnel_intents VALUES(1,'invalid',0);").is_err());
    conn.batch_execute("DELETE FROM tunnel_intents WHERE tunnel_id=1 AND kind='manual';").unwrap();
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.batch_execute("CREATE TEMP TABLE intent_check(ok INTEGER CHECK(ok=1)); INSERT INTO intent_check SELECT CASE WHEN count(*)=3 THEN 1 ELSE 0 END FROM tunnel_intents; INSERT INTO intent_check SELECT CASE WHEN count(*)=1 THEN 1 ELSE 0 END FROM tunnel_intents WHERE tunnel_id=10 AND kind='legacy' AND mesh_id=-3;").unwrap();
}

#[test]
fn enrollment_kv_migration_preserves_global_request_uniqueness() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    let target = migrations.iter().position(|migration| migration.name().version().to_string() == "202611090000000000").unwrap();
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..target]).unwrap();
    conn.batch_execute("INSERT INTO control_enrollment_results VALUES('peer/1','request','fingerprint','result'),('peer2','','f','r'),('peer3','','f','r');").unwrap();
    conn.run_migrations(&migrations[target..=target]).unwrap();
    assert!(conn.batch_execute("INSERT INTO application_kv VALUES('control_enrollment_result/other',json_object('request_id','request','fingerprint','f','result','r'));").is_err());
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.batch_execute("CREATE TEMP TABLE enrollment_check(ok INTEGER CHECK(ok=1)); INSERT INTO enrollment_check SELECT CASE WHEN count(*)=1 THEN 1 ELSE 0 END FROM control_enrollment_results WHERE peer_id='peer/1' AND request_id='request' AND fingerprint='fingerprint' AND result='result';").unwrap();
}

#[test]
fn answer_receipt_kv_round_trip_keeps_composite_keys() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    let target = migrations.iter().position(|migration| migration.name().version().to_string() == "202611080000000000").unwrap();
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..target]).unwrap();
    conn.batch_execute("INSERT INTO control_answer_results VALUES(1,'a/%_','fingerprint','accepted','2026-11-01 12:00:00'),(10,'a/%_','other','accepted','2026-11-01 12:00:00');").unwrap();
    conn.run_migrations(&migrations[target..=target]).unwrap();
    conn.batch_execute("DELETE FROM application_kv WHERE substr(key,1,length('control_answer_result/1/'))='control_answer_result/1/';").unwrap();
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.batch_execute("CREATE TEMP TABLE answer_check(ok INTEGER CHECK(ok=1)); INSERT INTO answer_check SELECT CASE WHEN count(*)=1 THEN 1 ELSE 0 END FROM control_answer_results WHERE node_id=10 AND request_id='a/%_' AND fingerprint='other' AND expires_at='2026-11-01 12:00:00';").unwrap();
}

#[test]
fn wireguard_key_kv_migration_preserves_key_and_timestamp() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    let target = migrations.iter().position(|migration| migration.name().version().to_string() == "202611070000000000").unwrap();
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..target]).unwrap();
    conn.batch_execute("INSERT INTO wireguard_static_key VALUES(42,'public-key','2026-11-01 12:00:00');").unwrap();
    conn.run_migrations(&migrations[target..=target]).unwrap();
    assert_eq!(get_wireguard_pubkey(&mut conn, 42).unwrap(), "public-key");
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.batch_execute("CREATE TEMP TABLE key_check(ok INTEGER CHECK(ok=1)); INSERT INTO key_check SELECT CASE WHEN count(*)=1 THEN 1 ELSE 0 END FROM wireguard_static_key WHERE node_id=42 AND public_key='public-key' AND created_at='2026-11-01 12:00:00';").unwrap();
}

#[test]
fn invite_receipt_kv_migration_round_trip() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    let target = migrations.iter().position(|migration| migration.name().version().to_string() == "202611060000000000").unwrap();
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..target]).unwrap();
    conn.batch_execute("INSERT INTO operator_invite_results VALUES('id/one','[null,null,null]','{\"Ok\":\"code\"}');").unwrap();
    conn.run_migrations(&migrations[target..=target]).unwrap();
    conn.batch_execute("CREATE TEMP TABLE check_receipt (ok INTEGER CHECK(ok=1)); INSERT INTO check_receipt SELECT CASE WHEN count(*)=1 THEN 1 ELSE 0 END FROM application_kv WHERE key='operator_invite_result/id/one' AND json_extract(value,'$.result')='{\"Ok\":\"code\"}';").unwrap();
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.batch_execute("INSERT INTO check_receipt SELECT CASE WHEN count(*)=1 THEN 1 ELSE 0 END FROM operator_invite_results WHERE request_id='id/one' AND fingerprint='[null,null,null]' AND result='{\"Ok\":\"code\"}';").unwrap();
}

#[test]
fn administrator_receipt_kv_migration_preserves_retry() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    let target = migrations.iter().position(|migration| migration.name().version().to_string() == "202611050000000000").unwrap();
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..target]).unwrap();
    conn.batch_execute("INSERT INTO administrator_results VALUES('id/one','fingerprint','{\"Ok\":null}');").unwrap();
    conn.run_migrations(&migrations[target..=target]).unwrap();
    assert_eq!(crate::admin::serving_receipt(&mut conn, "id/one", "fingerprint").unwrap(), Some(Ok(None)));
    assert_eq!(crate::admin::serving_receipt(&mut conn, "id/one", "other").unwrap(), Some(Err("idempotency key conflict".into())));
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.batch_execute("CREATE TEMP TABLE verify_receipt (ok INTEGER CHECK(ok = 1)); INSERT INTO verify_receipt SELECT CASE WHEN count(*)=1 THEN 1 ELSE 0 END FROM administrator_results WHERE request_id='id/one' AND fingerprint='fingerprint' AND result='{\"Ok\":null}';").unwrap();
}

#[test]
fn management_kv_preserves_deleted_id_and_downgrade() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    let target = migrations.iter().position(|migration| migration.name().version().to_string() == "202611040000000000").unwrap();
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..target]).unwrap();
    conn.batch_execute("INSERT INTO nodes(id,name,auth_key) VALUES(42,'deleted','key'); DELETE FROM nodes WHERE id=42;").unwrap();
    conn.run_migrations(&migrations[target..=target]).unwrap();
    assert_eq!(next_management_id(&mut conn, "node").unwrap(), 43);
    conn.batch_execute("INSERT INTO nodes(id,name,auth_key) VALUES(50,'new','key'); DELETE FROM nodes WHERE id=50;").unwrap();
    assert_eq!(next_management_id(&mut conn, "node").unwrap(), 51);
    conn.batch_execute("UPDATE application_kv SET value='\"invalid\"' WHERE key='management_id/node';").unwrap();
    assert!(conn.batch_execute("INSERT INTO nodes(id,name,auth_key) VALUES(51,'bad','key');").is_err());
    conn.batch_execute("UPDATE application_kv SET value='50' WHERE key='management_id/node';").unwrap();
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.batch_execute("CREATE TEMP TABLE verify_management (ok INTEGER CHECK(ok = 1)); INSERT INTO verify_management SELECT CASE WHEN high_water=50 THEN 1 ELSE 0 END FROM management_ids WHERE kind='node';").unwrap();
}

#[test]
fn revocation_migration_round_trip_preserves_identity() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    let target = migrations.iter().position(|migration| migration.name().version().to_string() == "202611030000000000").unwrap();
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..target]).unwrap();
    conn.batch_execute("INSERT INTO node_revocations VALUES ('peer/α', 17, '2026-11-01 12:00:00');").unwrap();
    conn.run_migrations(&migrations[target..=target]).unwrap();
    assert!(identity_revoked(&mut conn, "peer/α").unwrap());
    assert!(!identity_revoked(&mut conn, "peer").unwrap());
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.batch_execute("CREATE TEMP TABLE verify_revocation (ok INTEGER CHECK(ok = 1)); INSERT INTO verify_revocation SELECT CASE WHEN count(*) = 1 THEN 1 ELSE 0 END FROM node_revocations WHERE peer_id = 'peer/α' AND node_id = 17 AND revoked_at = '2026-11-01 12:00:00';").unwrap();
}

#[test]
fn administrator_bootstrap_is_atomic_and_idempotent() {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    use crate::admin::{Action, Mutation, Operation};

    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    migrate(&mut conn, true).unwrap();
    let password_hash = Argon2::default()
        .hash_password(b"test password", &SaltString::generate(&mut rand08::rngs::OsRng))
        .unwrap().to_string();
    let command = Mutation {
        request_id: "bootstrap".into(),
        applied_at: chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap(),
        action: Action::Bootstrap { username: "admin".into(), password_hash: password_hash.clone() },
    };
    conn.batch_execute("CREATE TRIGGER fail_bootstrap BEFORE INSERT ON application_kv WHEN substr(NEW.key,1,21)='administrator_result/' BEGIN SELECT RAISE(ABORT,'failure'); END;").unwrap();
    assert!(crate::admin::apply(&mut conn, &command).is_err());
    assert_eq!(crate::admin::read(&mut conn, Operation::Account).unwrap(), serde_json::Value::Null);
    conn.batch_execute("DROP TRIGGER fail_bootstrap;").unwrap();
    let result = crate::admin::apply(&mut conn, &command).unwrap();
    assert!(result.is_ok());
    assert_eq!(crate::admin::apply(&mut conn, &command).unwrap(), result);
    assert_eq!(crate::admin::read(&mut conn, Operation::Account).unwrap(),
        serde_json::json!({"username":"admin", "password_hash":password_hash}));
    let duplicate = Mutation { request_id: "other".into(), ..command };
    assert_eq!(crate::admin::apply(&mut conn, &duplicate).unwrap(), Err("administrator already exists".into()));
}

#[test]
fn l2tp_provisioning_reverses_peers_and_cascades_with_underlay() {
    use crate::admin::{Action, Mutation};
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    migrate(&mut conn, true).unwrap();
    conn.batch_execute("INSERT INTO nodes(id,name,auth_key) VALUES(1,'a','a'),(2,'b','b'); INSERT INTO application_kv SELECT 'wireguard_key/' || id, json_object('public_key',auth_key,'created_at','2026-01-01') FROM nodes; INSERT INTO node_control_identities(node_id,peer_id,signing_key,encryption_key) VALUES(1,'a','a','a'),(2,'b','b','b');").unwrap();
    for node in [1, 2] {
        set_feature_support(&mut conn, node, cat4igp_shared::control::FeatureSupport { wireguard: true, l2tp_v3: true, ..Default::default() }).unwrap();
    }
    create_wireguard_tunnel(&mut conn, 1, 2, 1420, false).unwrap();
    let wg = get_wireguard_answers(&mut conn, 1).unwrap()[0].id;
    let command = |key: &str, action| Mutation { request_id: key.into(), action, applied_at: chrono::Utc::now().naive_utc() };
    let create = command("create-l2tp", Action::CreateL2tpTunnel { node_id_peer1: 1, node_id_peer2: 2, endpoint_peer1: "10.10.0.1".into(), endpoint_peer2: "10.10.0.2".into(), udp_port_peer1: 1701, udp_port_peer2: 1702, session_id_peer1: 11, session_id_peer2: 22, cookie_peer1: "0123456789abcdef".into(), cookie_peer2: "fedcba9876543210".into(), security_mode: "wireguard".into(), wireguard_tunnel_id: Some(wg), mtu: 1400 });
    assert!(crate::admin::apply(&mut conn, &create).unwrap().is_ok());
    let a = topology_snapshot(&mut conn, 1, 0).unwrap().l2tp_tunnels.remove(0);
    let b = topology_snapshot(&mut conn, 2, 0).unwrap().l2tp_tunnels.remove(0);
    assert_eq!(a.local_session_id, b.remote_session_id);
    assert_eq!(a.remote_cookie, b.local_cookie);
    assert!(crate::admin::apply(&mut conn, &command("delete-node", Action::DeleteNode { id: 2 })).unwrap().is_ok());
    assert!(topology_snapshot(&mut conn, 1, 0).unwrap().l2tp_tunnels.is_empty());
}

#[test]
fn l2tpv2_migration_preserves_existing_data_and_rolls_back() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    let target = migrations.iter().position(|migration| migration.name().version().to_string() == "202611120000000000").unwrap();
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..target]).unwrap();
    conn.batch_execute("INSERT INTO l2tpv3_tunnels VALUES(1,'static',1,2,'a','b',1,2,1,2,'0123456789abcdef','fedcba9876543210','pure',NULL,1500);").unwrap();
    conn.run_migrations(&migrations[target..=target]).unwrap();
    conn.batch_execute("INSERT INTO l2tpv2_tunnels VALUES(1,1,2,'192.0.2.1','192.0.2.2',1701,1702,'10.0.0.1','10.0.0.2','secret',1400);").unwrap();
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.batch_execute("CREATE TEMP TABLE v3_check(ok INTEGER CHECK(ok=1)); INSERT INTO v3_check SELECT count(*) FROM l2tpv3_tunnels;").unwrap();
}

#[test]
fn l2tpv2_wireguard_migration_retains_rows_and_guards_downgrade() {
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    let mut migrations = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap();
    migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
    let target = migrations.iter().position(|migration| migration.name().version().to_string() == "202611130000000000").unwrap();
    assert!(conn.applied_migrations().unwrap().is_empty());
    conn.run_migrations(&migrations[..target]).unwrap();
    conn.batch_execute("INSERT INTO l2tpv2_tunnels VALUES(1,1,2,'192.0.2.1','192.0.2.2',1701,1702,'10.0.0.1','10.0.0.2','secret',1400);").unwrap();
    conn.run_migrations(&migrations[target..=target]).unwrap();
    let row = l2tp_v2_rows(&mut conn).unwrap().remove(0);
    assert_eq!((row.secret.as_str(), row.mtu, row.wireguard_tunnel_id), ("secret", 1400, None));
    conn.batch_execute("UPDATE l2tpv2_tunnels SET wireguard_tunnel_id=1, mtu=65000 WHERE id=1").unwrap();
    assert!(conn.revert_last_migration(MIGRATIONS).is_err());
    conn.batch_execute("UPDATE l2tpv2_tunnels SET wireguard_tunnel_id=NULL, mtu=1400 WHERE id=1").unwrap();
    conn.revert_last_migration(MIGRATIONS).unwrap();
    conn.batch_execute("CREATE TEMP TABLE retained(ok INTEGER CHECK(ok=1)); INSERT INTO retained SELECT count(*) FROM l2tpv2_tunnels WHERE secret='secret';").unwrap();
}

#[test]
fn l2tpv2_wireguard_validation_and_underlay_cascade() {
    use crate::admin::{Action, Mutation, Operation, IntentKind};
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    migrate(&mut conn, true).unwrap();
    conn.batch_execute("INSERT INTO nodes(id,name,auth_key) VALUES(1,'a','a'),(2,'b','b'),(3,'c','c'); INSERT INTO application_kv SELECT 'wireguard_key/' || id, json_object('public_key',auth_key,'created_at','2026-01-01') FROM nodes; INSERT INTO node_control_identities(node_id,peer_id,signing_key,encryption_key) VALUES(1,'a','a','a'),(2,'b','b','b'),(3,'c','c','c');").unwrap();
    for node in [1, 2] {
        set_feature_support(&mut conn, node, cat4igp_shared::control::FeatureSupport { wireguard: true, l2tp_v2: true, l2tp_v3: true, ..Default::default() }).unwrap();
    }
    create_wireguard_tunnel(&mut conn, 1, 2, 1420, false).unwrap();
    let wg = get_wireguard_answers(&mut conn, 1).unwrap()[0].id;
    conn.batch_execute("UPDATE wireguard_tunnels SET endpoint_peer1='198.51.100.1:51820' WHERE id=1").unwrap();
    let command = |key: &str, action| Mutation { request_id: key.into(), action, applied_at: chrono::Utc::now().naive_utc() };
    let create = |a: &str, b: &str, p: u16, mtu: i32, id: Option<i32>| Action::CreateL2tpV2Tunnel { node_id_peer1: 1, node_id_peer2: 2, endpoint_peer1: a.into(), endpoint_peer2: b.into(), udp_port_peer1: p, udp_port_peer2: p, address_peer1: "10.1.0.1".into(), address_peer2: "10.1.0.2".into(), secret: "private".into(), mtu, wireguard_tunnel_id: id };
    for (key, action) in [("outer", create("198.51.100.1", "10.9.0.2", 1701, 65000, Some(wg))), ("missing", create("10.9.0.1", "10.9.0.2", 1701, 65000, Some(wg + 100))), ("direct-mtu", create("10.9.0.1", "10.9.0.2", 1701, 1501, None)), ("large", create("10.9.0.1", "10.9.0.2", 1701, 65001, Some(wg)))] {
        assert!(crate::admin::apply(&mut conn, &command(key, action)).unwrap().is_err());
    }
    assert!(crate::admin::apply(&mut conn, &command("create", create("10.9.0.1", "10.9.0.2", 1701, 65000, Some(wg)))).unwrap().is_ok());
    let answer = AnswerCommand { node_id: 1, request_id: "outer-conflict".into(), answer: cat4igp_shared::control::TunnelAnswer { tunnel_id: wg, endpoint: Some("10.9.0.2:51820".into()), decline_type: None }, applied_at: chrono::Utc::now().naive_utc() };
    assert_eq!(apply_answer(&mut conn, &answer).unwrap(), "invalid tunnel endpoint");
    assert!(crate::admin::apply(&mut conn, &command("reuse", create("10.9.0.1", "10.9.0.3", 1703, 1400, Some(wg)))).unwrap().is_err());
    let v3 = Action::CreateL2tpTunnel { node_id_peer1: 1, node_id_peer2: 2, endpoint_peer1: "10.9.0.2".into(), endpoint_peer2: "10.9.0.3".into(), udp_port_peer1: 1703, udp_port_peer2: 1704, session_id_peer1: 11, session_id_peer2: 22, cookie_peer1: "0123456789abcdef".into(), cookie_peer2: "fedcba9876543210".into(), security_mode: "wireguard".into(), wireguard_tunnel_id: Some(wg), mtu: 1400 };
    assert!(crate::admin::apply(&mut conn, &command("v3-reuse", v3)).unwrap().is_err());
    let a = topology_snapshot(&mut conn, 1, 0).unwrap().l2tp_v2_tunnels.remove(0);
    let b = topology_snapshot(&mut conn, 2, 0).unwrap().l2tp_v2_tunnels.remove(0);
    assert_eq!(a.wireguard_tunnel_id, Some(wg));
    assert_eq!(a.local_endpoint, b.remote_endpoint);
    assert!(a.initiator && !b.initiator);
    assert!(crate::admin::read(&mut conn, Operation::Inventory).unwrap()["l2tp_v2_tunnels"][0].get("secret").is_none());
    assert!(crate::admin::apply(&mut conn, &command("remove", Action::RemoveTunnelIntent { tunnel_id: wg, kind: IntentKind::Manual })).unwrap().is_ok());
    assert!(topology_snapshot(&mut conn, 1, 0).unwrap().l2tp_v2_tunnels.is_empty());
}

#[test]
fn l2tpv2_provisioning_validation_snapshots_and_cascade() {
    use crate::admin::{Action, Mutation, Operation};
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    migrate(&mut conn, true).unwrap();
    conn.batch_execute("INSERT INTO nodes(id,name,auth_key) VALUES(1,'a','a'),(2,'b','b'),(3,'c','c'); INSERT INTO node_control_identities(node_id,peer_id,signing_key,encryption_key) VALUES(1,'a','a','a'),(2,'b','b','b'),(3,'c','c','c');").unwrap();
    let command = |key: &str, action| Mutation { request_id: key.into(), action, applied_at: chrono::Utc::now().naive_utc() };
    let create = |secret: &str, mtu, endpoint: &str| Action::CreateL2tpV2Tunnel {
        node_id_peer1: 1, node_id_peer2: 2, endpoint_peer1: "192.0.2.1".into(), endpoint_peer2: endpoint.into(),
        udp_port_peer1: 1701, udp_port_peer2: 1702, address_peer1: "10.0.0.1".into(), address_peer2: "10.0.0.2".into(), secret: secret.into(), mtu, wireguard_tunnel_id: None,
    };
    assert!(crate::admin::apply(&mut conn, &command("unknown", create("secret", 1400, "192.0.2.2"))).unwrap().is_err());
    set_feature_support(&mut conn, 1, cat4igp_shared::control::FeatureSupport { l2tp_v2: true, ..Default::default() }).unwrap();
    set_feature_support(&mut conn, 2, cat4igp_shared::control::FeatureSupport::default()).unwrap();
    assert!(crate::admin::apply(&mut conn, &command("unsupported", create("secret", 1400, "192.0.2.2"))).unwrap().is_err());
    set_feature_support(&mut conn, 2, cat4igp_shared::control::FeatureSupport { l2tp_v2: true, ..Default::default() }).unwrap();
    for (i, (secret, mtu, endpoint)) in [("bad\nsecret", 1400, "192.0.2.2"), ("bad#secret", 1400, "192.0.2.2"), ("ok", 1279, "192.0.2.2"), ("ok", 1400, "::1")].into_iter().enumerate() {
        assert!(crate::admin::apply(&mut conn, &command(&format!("invalid-{i}"), create(secret, mtu, endpoint))).unwrap().is_err());
    }
    let action = command("v2-create", create("secret", 1400, "192.0.2.2"));
    assert!(crate::admin::apply(&mut conn, &action).unwrap().is_ok());
    assert!(crate::admin::apply(&mut conn, &action).unwrap().is_ok());
    assert!(crate::admin::apply(&mut conn, &command("duplicate-port", create("secret", 1400, "192.0.2.2"))).unwrap().is_err());
    let a = topology_snapshot(&mut conn, 1, 0).unwrap().l2tp_v2_tunnels.remove(0);
    let b = topology_snapshot(&mut conn, 2, 0).unwrap().l2tp_v2_tunnels.remove(0);
    assert!(a.initiator && !b.initiator);
    assert_eq!(a.local_endpoint, b.remote_endpoint);
    assert_eq!(a.local_port, b.remote_port);
    assert_eq!(a.local_address, b.remote_address);
    assert_eq!(a.secret, b.secret);
    assert!(topology_snapshot(&mut conn, 3, 0).unwrap().l2tp_v2_tunnels.is_empty());
    let inventory = crate::admin::read(&mut conn, Operation::Inventory).unwrap();
    assert!(inventory["l2tp_v2_tunnels"][0].get("secret").is_none());
    assert!(crate::admin::apply(&mut conn, &command("v2-delete", Action::DeleteL2tpV2Tunnel { id: a.tunnel_id })).unwrap().is_ok());
    assert!(topology_snapshot(&mut conn, 1, 0).unwrap().l2tp_v2_tunnels.is_empty());
    assert!(crate::admin::apply(&mut conn, &command("v2-recreate", create("secret", 1400, "192.0.2.2"))).unwrap().is_ok());
    let next = topology_snapshot(&mut conn, 1, 0).unwrap().l2tp_v2_tunnels[0].tunnel_id;
    assert!(next > a.tunnel_id);
    assert!(crate::admin::apply(&mut conn, &command("delete-v2-node", Action::DeleteNode { id: 2 })).unwrap().is_ok());
    assert!(topology_snapshot(&mut conn, 1, 0).unwrap().l2tp_v2_tunnels.is_empty());
}

#[test]
fn mesh_mtu_updates_owned_tunnels_revisions_and_future_members() {
    use crate::admin::{Action, Mutation, Operation};
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    migrate(&mut conn, true).unwrap();
    conn.batch_execute("INSERT INTO nodes(id,name,auth_key) VALUES(1,'a','a'),(2,'b','b'),(3,'c','c'),(4,'d','d');
        INSERT INTO application_kv SELECT 'wireguard_key/' || id, json_object('public_key',auth_key,'created_at','2026-01-01') FROM nodes;
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
    conn.batch_execute("CREATE TRIGGER fail_mtu BEFORE INSERT ON application_kv WHEN substr(NEW.key,1,21)='administrator_result/' BEGIN SELECT RAISE(ABORT,'failure'); END;").unwrap();
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
    assert!(snapshot.l2tp_availability.is_none());
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
        INSERT INTO application_kv SELECT 'wireguard_key/' || id, json_object('public_key',auth_key,'created_at','2026-01-01') FROM nodes;
        INSERT INTO node_control_identities(node_id,peer_id,signing_key,encryption_key) VALUES(1,'a','a','a'),(2,'b','b','b'),(3,'c','c','c');").unwrap();
    let at = chrono::Utc::now().naive_utc();
    let command = |key: &str, action| Mutation { request_id: key.into(), action, applied_at: at };
    for (id, fec) in [(1, false), (2, true)] {
        let create = command(&format!("create-{id}"), Action::CreateMesh {
            name: format!("mesh-{id}"), auto_wireguard: true, mtu: 1420, fec, faketcp: false,
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
    conn.batch_execute("CREATE TRIGGER fail_fec BEFORE INSERT ON application_kv WHEN substr(NEW.key,1,21)='administrator_result/' BEGIN SELECT RAISE(ABORT,'failure'); END;").unwrap();
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
        name: "no-auto".into(), auto_wireguard: false, mtu: 0, fec: false, faketcp: false,
    })).unwrap().is_ok());
    for (key, action) in [
        ("bad-create", Action::CreateMesh { name: "bad".into(), auto_wireguard: false, mtu: 0, fec: true, faketcp: false }),
        ("bad-update", Action::SetMeshFec { id: 4, fec: true }),
        ("missing", Action::SetMeshFec { id: 999, fec: true }),
    ] {
        assert!(crate::admin::apply(&mut conn, &command(key, action)).unwrap().is_err());
    }
}

#[test]
fn mesh_faketcp_policy_preserves_shared_and_explicit_settings() {
    use crate::admin::{Action, Mutation, Operation};
    let mut conn = SqliteConnection::establish(":memory:").unwrap();
    migrate(&mut conn, true).unwrap();
    conn.batch_execute("INSERT INTO nodes(id,name,auth_key) VALUES(1,'a','a'),(2,'b','b'),(3,'c','c');
        INSERT INTO application_kv SELECT 'wireguard_key/' || id, json_object('public_key',auth_key,'created_at','2026-01-01') FROM nodes;
        INSERT INTO node_control_identities(node_id,peer_id,signing_key,encryption_key) VALUES(1,'a','a','a'),(2,'b','b','b'),(3,'c','c','c');").unwrap();
    let at = chrono::Utc::now().naive_utc();
    let command = |key: &str, action| Mutation { request_id: key.into(), action, applied_at: at };
    for (id, faketcp) in [(1, false), (2, true)] {
        assert!(crate::admin::apply(&mut conn, &command(&format!("create-{id}"), Action::CreateMesh {
            name: format!("mesh-{id}"), auto_wireguard: true, mtu: 1420, fec: false, faketcp,
        })).unwrap().is_ok());
        for node_id in [1, 2] {
            assert!(crate::admin::apply(&mut conn, &command(&format!("join-{id}-{node_id}"), Action::AddMembership { mesh_id: id, node_id })).unwrap().is_ok());
        }
    }
    assert!(topology_snapshot(&mut conn, 1, 0).unwrap().tunnels.iter().all(|t| t.faketcp));
    create_wireguard_tunnel(&mut conn, 1, 3, 1420, false).unwrap();
    conn.batch_execute("UPDATE wireguard_tunnels SET faketcp=1 WHERE endpoint_ipv6=1").unwrap();
    let disable = command("disable", Action::SetMeshFaketcp { id: 2, faketcp: false });
    let revision = control_identity_for_node(&mut conn, 1).unwrap().topology_revision;
    let result = crate::admin::apply(&mut conn, &disable).unwrap();
    assert_eq!(crate::admin::apply(&mut conn, &disable).unwrap(), result);
    assert_eq!(control_identity_for_node(&mut conn, 1).unwrap().topology_revision, revision + 1);
    assert!(topology_snapshot(&mut conn, 1, 0).unwrap().tunnels.iter().all(|t| t.faketcp == t.endpoint_ipv6));
    assert!(crate::admin::apply(&mut conn, &command("enable-1", Action::SetMeshFaketcp { id: 1, faketcp: true })).unwrap().is_ok());
    assert!(crate::admin::apply(&mut conn, &command("enable-2", Action::SetMeshFaketcp { id: 2, faketcp: true })).unwrap().is_ok());
    assert!(crate::admin::apply(&mut conn, &command("disable-1", Action::SetMeshFaketcp { id: 1, faketcp: false })).unwrap().is_ok());
    assert!(topology_snapshot(&mut conn, 2, 0).unwrap().tunnels.iter().all(|t| t.faketcp));
    assert!(crate::admin::apply(&mut conn, &command("leave", Action::RemoveMembership { mesh_id: 2, node_id: 2 })).unwrap().is_ok());
    assert!(topology_snapshot(&mut conn, 2, 0).unwrap().tunnels.iter().all(|t| t.faketcp == t.endpoint_ipv6));
    let old = r#"{"action":"create_mesh","name":"legacy","auto_wireguard":false,"mtu":0}"#;
    let action: Action = serde_json::from_str(old).unwrap();
    assert_eq!(serde_json::to_string(&action).unwrap(), old);
    assert!(crate::admin::apply(&mut conn, &command("legacy", action)).unwrap().is_ok());
    assert_eq!(crate::admin::read(&mut conn, Operation::Inventory).unwrap()["meshes"][2]["faketcp"], false);
    for (key, action) in [
        ("bad-create", Action::CreateMesh { name: "bad".into(), auto_wireguard: false, mtu: 0, fec: false, faketcp: true }),
        ("bad-update", Action::SetMeshFaketcp { id: 3, faketcp: true }),
        ("missing", Action::SetMeshFaketcp { id: 999, faketcp: true }),
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
    conn.batch_execute("INSERT INTO application_kv SELECT 'operator_invite_result/alias',value FROM application_kv WHERE key='operator_invite_result/invite';
        CREATE TEMP TABLE original_fingerprints AS SELECT key,json_extract(value,'$.fingerprint') AS fingerprint FROM application_kv WHERE substr(key,1,23)='operator_invite_result/';
        CREATE TRIGGER fail_receipt BEFORE INSERT ON application_kv WHEN substr(NEW.key,1,21)='administrator_result/' BEGIN SELECT RAISE(ABORT,'failure'); END;").unwrap();
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
    conn.batch_execute("CREATE TEMP TABLE fingerprint_check(n INTEGER CHECK(n=0)); INSERT INTO fingerprint_check SELECT COUNT(*) FROM application_kv r JOIN original_fingerprints o USING(key) WHERE json_extract(r.value,'$.fingerprint')!=o.fingerprint;").unwrap();
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
        "SELECT json_extract(value,'$.fingerprint') AS fingerprint FROM application_kv WHERE key='operator_invite_result/mesh-invite'",
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
            "SELECT json_extract(value,'$.fingerprint') AS fingerprint FROM application_kv WHERE key='operator_invite_result/mesh-invite'"
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
        conn.batch_execute("CREATE TRIGGER fail_invite_result BEFORE INSERT ON application_kv WHEN substr(NEW.key,1,23)='operator_invite_result/' BEGIN SELECT RAISE(ABORT, 'failure'); END;").unwrap();
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
    first.batch_execute("CREATE TRIGGER fail_result BEFORE INSERT ON application_kv WHEN substr(NEW.key,1,22)='control_answer_result/' BEGIN SELECT RAISE(ABORT, 'disk failure'); END;").unwrap();
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
            INSERT INTO application_kv VALUES ('wireguard_key/1',json_object('public_key','key','created_at','2026-01-01'));").unwrap();
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
    conn.batch_execute("CREATE TRIGGER fail_enrollment BEFORE INSERT ON application_kv WHEN substr(NEW.key,1,26)='control_enrollment_result/' BEGIN SELECT RAISE(ABORT, 'disk failure'); END;").unwrap();
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
    let migration_count = <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS).unwrap().len();
    assert_eq!(conn.applied_migrations().unwrap().len(), migration_count);
    migrate(&mut conn, true).unwrap();
    migrate(&mut conn, false).unwrap();
    assert_eq!(conn.applied_migrations().unwrap().len(), migration_count);
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
