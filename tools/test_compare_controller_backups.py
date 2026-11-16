import json
from contextlib import closing, redirect_stdout, redirect_stderr
from dataclasses import replace
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import compare_controller_backups as diagnostic


def backup(path, *, revision=5, peer="peer", revoked=True, receipt=True, node_high_water=2):
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript("""
            CREATE TABLE __diesel_schema_migrations (version TEXT NOT NULL);
            INSERT INTO __diesel_schema_migrations VALUES
                ('202611020000000000'), ('202611030000000000'), ('202611040000000000'),
                ('202611050000000000'), ('202611060000000000'), ('202611070000000000'),
                ('202611080000000000'), ('202611090000000000');
            CREATE TABLE node_control_identities
                (node_id INTEGER, peer_id TEXT, signing_key TEXT, encryption_key TEXT, topology_revision INTEGER);
            CREATE TABLE application_kv (key TEXT, value TEXT);
            CREATE TABLE nodes (id INTEGER, name TEXT, auth_key TEXT, last_seen TEXT);
            INSERT INTO nodes VALUES (1, 'node', 'private-auth', NULL);
            CREATE TABLE mesh_groups (id INTEGER, name TEXT, auto_wireguard INTEGER);
            INSERT INTO mesh_groups VALUES (1, 'mesh', 1);
            CREATE TABLE mesh_group_memberships (id INTEGER, mesh_group_id INTEGER, node_id INTEGER);
            INSERT INTO mesh_group_memberships VALUES (1, 1, 1);
            CREATE TABLE wireguard_tunnels (id INTEGER, node_id_peer1 INTEGER, node_id_peer2 INTEGER, mtu INTEGER);
            INSERT INTO wireguard_tunnels VALUES (1, 1, 2, 1280);
            CREATE TABLE l2tpv3_tunnels (id INTEGER, cookie_peer1 TEXT);
            INSERT INTO l2tpv3_tunnels VALUES (2, 'private-cookie');
            CREATE TABLE tunnel_intents (tunnel_id INTEGER, kind TEXT, mesh_id INTEGER);
            INSERT INTO tunnel_intents VALUES (1, 'mesh', 1);
            CREATE TABLE invites (id INTEGER, code TEXT, expires_at TEXT, used_count INTEGER, max_uses INTEGER);
            CREATE TABLE settings (id INTEGER, key TEXT, value TEXT);
        """)
        db.execute("INSERT INTO node_control_identities VALUES (1, ?, 'sign', 'encrypt', ?)", (peer, revision))
        db.executemany("INSERT INTO application_kv VALUES (?, ?)", [
            ("management_id/node", json.dumps(node_high_water)),
            ("management_id/mesh", "1"), ("management_id/tunnel", "2"),
            ("wireguard_key/1", json.dumps({"public_key": "key", "created_at": "2026-01-01"})),
        ])
        if revoked:
            db.execute("INSERT INTO application_kv VALUES (?, ?)", (
                "node_revocation/old", json.dumps({"node_id": 2, "revoked_at": "2026-01-01"})))
        if receipt:
            db.execute("INSERT INTO application_kv VALUES (?, ?)", ("control_enrollment_result/peer", json.dumps({"request_id": "id"})))


class BackupComparisonTests(unittest.TestCase):
    def test_identical_backup_and_missing_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            snapshot = diagnostic.read_backup(path)
            result = diagnostic.compare(snapshot, snapshot)
            self.assertEqual(result["missing_identity_node_ids"], [])
            self.assertEqual(result["records"]["revocations"], {"missing": 0, "added": 0, "changed": 0})
            self.assertEqual(diagnostic.compare(snapshot, replace(snapshot, identities={}))[
                "missing_identity_node_ids"], [1])

    def test_rejects_consensus_state_that_standalone_controller_cannot_restore(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.executescript("""
                    CREATE TABLE raft_meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
                    CREATE TABLE raft_logs (idx TEXT PRIMARY KEY NOT NULL CHECK(length(idx) = 16), value TEXT NOT NULL);
                """)
            diagnostic.read_backup(path)
            for table, row in (("raft_meta", ("term", "1")), ("raft_logs", ("0000000000000001", "entry"))):
                with self.subTest(table=table):
                    with closing(sqlite3.connect(path)) as db, db:
                        db.execute(f"INSERT INTO {table} VALUES (?, ?)", row)
                    with self.assertRaisesRegex(diagnostic.InspectionError, "unsupported consensus state"):
                        diagnostic.read_backup(path)
                    with closing(sqlite3.connect(path)) as db, db:
                        db.execute(f"DELETE FROM {table}")
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("DROP TABLE raft_logs")
            with self.assertRaisesRegex(diagnostic.InspectionError, "incomplete consensus metadata"):
                diagnostic.read_backup(path)

    def test_detects_wireguard_refresh_state_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("INSERT INTO application_kv VALUES (?, ?)", (
                    "wireguard_refresh/1", json.dumps({"active_generation": 2, "pending": {"generation": 3}})))
            before = diagnostic.read_backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE application_kv SET value=? WHERE key='wireguard_refresh/1'",
                           (json.dumps({"active_generation": 1, "pending": None}),))
            changed = diagnostic.read_backup(path)
            self.assertEqual(diagnostic.compare(before, changed)["records"]["wireguard_refresh"],
                             {"missing": 0, "added": 0, "changed": 1})
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("DELETE FROM application_kv WHERE key='wireguard_refresh/1'")
            missing = diagnostic.read_backup(path)
            self.assertEqual(diagnostic.compare(before, missing)["records"]["wireguard_refresh"],
                             {"missing": 1, "added": 0, "changed": 0})
            self.assertEqual(diagnostic.compare(missing, before)["records"]["wireguard_refresh"],
                             {"missing": 0, "added": 1, "changed": 0})

    def test_detects_invalid_negative_zero_in_refresh_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("INSERT INTO application_kv VALUES (?, ?)",
                           ("wireguard_refresh/1", '{"active_generation":0}'))
            before = diagnostic.read_backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE application_kv SET value=? WHERE key='wireguard_refresh/1'",
                           ('{"active_generation":-0}',))
            self.assertEqual(diagnostic.compare(before, diagnostic.read_backup(path))["records"]["wireguard_refresh"],
                             {"missing": 0, "added": 0, "changed": 1})

    def test_detects_session_revocation_loss_and_rejects_invalid_value(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            before = diagnostic.read_backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("INSERT INTO application_kv VALUES (?, ?)", ("session_revocation/secret-session", "true"))
            revoked = diagnostic.read_backup(path)
            result = diagnostic.compare(revoked, before)
            self.assertEqual(result["records"]["session_revocations"], {"missing": 1, "added": 0, "changed": 0})
            self.assertNotIn("secret-session", json.dumps(result))
            self.assertEqual(diagnostic.compare(before, revoked)["records"]["session_revocations"],
                             {"missing": 0, "added": 1, "changed": 0})
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE application_kv SET value='false' WHERE key='session_revocation/secret-session'")
            with self.assertRaises(diagnostic.InspectionError):
                diagnostic.read_backup(path)

    def test_rejects_invalid_record_and_unsupported_schema(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE application_kv SET value='not json'")
            with self.assertRaises(diagnostic.InspectionError):
                diagnostic.read_backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("DELETE FROM __diesel_schema_migrations")
            with self.assertRaises(diagnostic.InspectionError):
                diagnostic.read_backup(path)

    def test_rejects_missing_security_record_migrations(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            for day in range(2, 10):
                version = f"202611{day:02}0000000000"
                with self.subTest(version=version):
                    with closing(sqlite3.connect(path)) as db, db:
                        db.execute("DELETE FROM __diesel_schema_migrations WHERE version=?", (version,))
                    with self.assertRaises(diagnostic.InspectionError):
                        diagnostic.read_backup(path)
                    with closing(sqlite3.connect(path)) as db, db:
                        db.execute("INSERT INTO __diesel_schema_migrations VALUES (?)", (version,))

    def test_rejects_unmigrated_administrator_receipt_differences(self):
        with tempfile.TemporaryDirectory() as temp:
            reference, candidate = Path(temp) / "reference.db", Path(temp) / "candidate.db"
            for path, result in ((reference, "accepted"), (candidate, "rejected")):
                backup(path)
                with closing(sqlite3.connect(path)) as db, db:
                    db.execute("DELETE FROM __diesel_schema_migrations WHERE version='202611050000000000'")
                    db.execute("CREATE TABLE administrator_results (request_id TEXT PRIMARY KEY NOT NULL, "
                               "fingerprint TEXT NOT NULL, result TEXT NOT NULL)")
                    db.execute("INSERT INTO administrator_results VALUES ('request', 'fingerprint', ?)", (result,))
                with self.assertRaises(diagnostic.InspectionError):
                    diagnostic.read_backup(path)

    def test_detects_losses_regression_and_identity_reassignment(self):
        with tempfile.TemporaryDirectory() as temp:
            reference, candidate = Path(temp) / "reference.db", Path(temp) / "candidate.db"
            backup(reference)
            backup(candidate, revision=3, peer="different", revoked=False, receipt=False)
            result = diagnostic.compare(diagnostic.read_backup(reference), diagnostic.read_backup(candidate))
            self.assertEqual(result["changed_identity_node_ids"], [1])
            self.assertEqual(result["regressed_revision_node_ids"], [1])
            self.assertEqual(result["records"]["revocations"]["missing"], 1)
            self.assertEqual(result["records"]["enrollment_receipts"]["missing"], 1)

    def test_rejects_sidecars_and_different_schemas(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            snapshot = diagnostic.read_backup(path)
            Path(str(path) + "-wal").touch()
            with self.assertRaises(diagnostic.InspectionError):
                diagnostic.read_backup(path)
            with self.assertRaises(diagnostic.InspectionError):
                diagnostic.compare(snapshot, replace(snapshot, migrations=frozenset({"other"})))

    def test_detects_allocation_rollback_without_live_node_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            reference, candidate = Path(temp) / "reference.db", Path(temp) / "candidate.db"
            backup(reference, node_high_water=70)
            backup(candidate, node_high_water=2)
            result = diagnostic.compare(diagnostic.read_backup(reference), diagnostic.read_backup(candidate))
            self.assertEqual(result["changed_allocation_high_water"], {
                "node": {"reference": 70, "candidate": 2}})
            self.assertEqual(result["changed_identity_node_ids"], [])

    def test_detects_legacy_tunnel_allocation_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            reference, candidate = Path(temp) / "reference.db", Path(temp) / "candidate.db"
            backup(reference)
            backup(candidate)
            for path, value in ((reference, "10"), (candidate, "5")):
                with closing(sqlite3.connect(path)) as db, db:
                    db.executemany("INSERT INTO application_kv VALUES (?, ?)",
                                   [("management_id/l2tp", value), ("management_id/l2tpv2", value)])
            result = diagnostic.compare(diagnostic.read_backup(reference), diagnostic.read_backup(candidate))
            self.assertEqual(result["changed_allocation_high_water"], {
                "l2tp": {"reference": 10, "candidate": 5},
                "l2tpv2": {"reference": 10, "candidate": 5}})

    def test_cli_rejects_unknown_allocation_key_without_disclosing_it(self):
        with tempfile.TemporaryDirectory() as temp:
            reference, candidate = Path(temp) / "reference.db", Path(temp) / "candidate.db"
            backup(reference)
            backup(candidate)
            with closing(sqlite3.connect(candidate)) as db, db:
                db.execute("INSERT INTO application_kv VALUES (?, ?)",
                           ("management_id/private-secret", "10"))
            out, err = io.StringIO(), io.StringIO()
            with patch("sys.argv", ["compare", str(reference), str(candidate)]), \
                    redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(diagnostic.main(), 1)
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(err.getvalue(), "inspection failed: invalid allocation high-water mark\n")

    def test_detects_topology_configuration_and_membership_changes_without_revision_change(self):
        with tempfile.TemporaryDirectory() as temp:
            reference, candidate = Path(temp) / "reference.db", Path(temp) / "candidate.db"
            backup(reference)
            backup(candidate)
            with closing(sqlite3.connect(candidate)) as db, db:
                db.executescript("""
                    UPDATE nodes SET auth_key='replacement-private-auth';
                    UPDATE mesh_groups SET auto_wireguard=0;
                    DELETE FROM mesh_group_memberships;
                    UPDATE wireguard_tunnels SET mtu=1400;
                    UPDATE l2tpv3_tunnels SET cookie_peer1='replacement-private-cookie';
                    DELETE FROM tunnel_intents;
                    INSERT INTO tunnel_intents VALUES (1, 'manual', 0);
                    UPDATE application_kv SET value='{"public_key":"replacement-key"}'
                        WHERE key='wireguard_key/1';
                """)
            result = diagnostic.compare(diagnostic.read_backup(reference), diagnostic.read_backup(candidate))
            self.assertEqual(result["regressed_revision_node_ids"], [])
            for table in ("nodes", "mesh_groups", "wireguard_tunnels", "l2tpv3_tunnels"):
                self.assertEqual(result["topology"][table]["changed"], 1)
            self.assertEqual(result["topology"]["mesh_group_memberships"]["missing"], 1)
            self.assertEqual(result["topology"]["tunnel_intents"], {"missing": 1, "added": 1, "changed": 0})
            self.assertEqual(result["records"]["wireguard_keys"]["changed"], 1)
            self.assertNotIn("private", json.dumps(result))

    def test_detects_candidate_only_state_and_advanced_revision(self):
        with tempfile.TemporaryDirectory() as temp:
            reference, candidate = Path(temp) / "reference.db", Path(temp) / "candidate.db"
            backup(reference, revoked=False, receipt=False)
            backup(candidate, revision=6)
            with closing(sqlite3.connect(candidate)) as db, db:
                db.execute("INSERT INTO node_control_identities VALUES (3, 'other', 'sign', 'encrypt', 0)")
                db.execute("INSERT INTO nodes VALUES (3, 'extra', 'secret', NULL)")
                db.execute("UPDATE application_kv SET value='3' WHERE key='management_id/node'")
            result = diagnostic.compare(diagnostic.read_backup(reference), diagnostic.read_backup(candidate))
            self.assertEqual(result["added_identity_node_ids"], [3])
            self.assertEqual(result["advanced_revision_node_ids"], [1])
            self.assertEqual(result["records"]["revocations"]["added"], 1)
            self.assertEqual(result["records"]["enrollment_receipts"]["added"], 1)
            self.assertEqual(result["topology"]["nodes"]["added"], 1)

    def test_ignores_liveness_timestamps(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            before = diagnostic.read_backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE nodes SET last_seen='2026-11-14'")
            self.assertEqual(diagnostic.compare(before, diagnostic.read_backup(path))["topology"]["nodes"],
                             {"missing": 0, "added": 0, "changed": 0})

    def test_detects_non_wireguard_timestamp_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.executescript("""
                    ALTER TABLE nodes ADD COLUMN created_at TEXT;
                    UPDATE nodes SET created_at='2026-01-01';
                    ALTER TABLE invites ADD COLUMN created_at TEXT;
                    INSERT INTO invites VALUES (1, 'secret', NULL, 0, NULL, '2026-01-01');
                    ALTER TABLE settings ADD COLUMN updated_at TEXT;
                    INSERT INTO settings VALUES (1, 'key', 'value', '2026-01-01');
                """)
            before = diagnostic.read_backup(path)
            for table, column in (("nodes", "created_at"), ("invites", "created_at"),
                                  ("settings", "updated_at")):
                with self.subTest(table=table, column=column):
                    with closing(sqlite3.connect(path)) as db, db:
                        db.execute(f"UPDATE {table} SET {column}='2026-01-02'")
                    self.assertEqual(diagnostic.compare(before, diagnostic.read_backup(path))["topology"][table],
                                     {"missing": 0, "added": 0, "changed": 1})
                    with closing(sqlite3.connect(path)) as db, db:
                        db.execute(f"UPDATE {table} SET {column}='2026-01-01'")

    def test_detects_wireguard_snapshot_timestamp_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("ALTER TABLE wireguard_tunnels ADD COLUMN created_at TEXT")
                db.execute("ALTER TABLE wireguard_tunnels ADD COLUMN updated_at TEXT")
                db.execute("UPDATE wireguard_tunnels SET created_at='2026-01-01', updated_at='2026-01-02'")
            before = diagnostic.read_backup(path)
            for column in ("created_at", "updated_at"):
                with self.subTest(column=column):
                    with closing(sqlite3.connect(path)) as db, db:
                        db.execute(f"UPDATE wireguard_tunnels SET {column}='2026-01-03'")
                    self.assertEqual(diagnostic.compare(before, diagnostic.read_backup(path))["topology"]["wireguard_tunnels"],
                                     {"missing": 0, "added": 0, "changed": 1})
                    with closing(sqlite3.connect(path)) as db, db:
                        db.execute(f"UPDATE wireguard_tunnels SET {column}=?", (
                            "2026-01-01" if column == "created_at" else "2026-01-02",))

    def test_rejects_invalid_high_water_and_ambiguous_recovery_json(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            for value in ('true', '-1', '2147483648', '1.0', '"2"', 'null'):
                with self.subTest(allocation=value):
                    with closing(sqlite3.connect(path)) as db, db:
                        db.execute("UPDATE application_kv SET value=? WHERE key='management_id/node'", (value,))
                    with self.assertRaises(diagnostic.InspectionError):
                        diagnostic.read_backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE application_kv SET value='2' WHERE key='management_id/node'")
            for value in ('{"node_id":2,"node_id":3,"revoked_at":"date"}',
                          '{"node_id":NaN,"revoked_at":"date"}',
                          '{"node_id":true,"revoked_at":"date"}', '{}'):
                with self.subTest(revocation=value):
                    with closing(sqlite3.connect(path)) as db, db:
                        db.execute("UPDATE application_kv SET value=? WHERE key='node_revocation/old'", (value,))
                    with self.assertRaises(diagnostic.InspectionError):
                        diagnostic.read_backup(path)

    def test_cli_rejects_deeply_nested_recovery_json_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp:
            reference, candidate = Path(temp) / "reference.db", Path(temp) / "candidate.db"
            backup(reference)
            backup(candidate)
            value = '{"secret":"private-secret"}'
            with closing(sqlite3.connect(candidate)) as db, db:
                db.execute("UPDATE application_kv SET value=? WHERE key='node_revocation/old'", (value,))
            out, err = io.StringIO(), io.StringIO()
            with patch("sys.argv", ["compare", str(reference), str(candidate)]), \
                    patch.object(diagnostic.json, "loads", side_effect=RecursionError), \
                    redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(diagnostic.main(), 1)
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(err.getvalue(), "inspection failed: invalid recovery record JSON\n")

    def test_cli_status_warning_and_read_only_inspection(self):
        with tempfile.TemporaryDirectory() as temp:
            reference, candidate = Path(temp) / "reference.db", Path(temp) / "candidate.db"
            backup(reference)
            backup(candidate)
            original = {path: path.read_bytes() for path in (reference, candidate)}
            for status, change in ((0, None), (2, "UPDATE mesh_groups SET name='changed'"),
                                   (1, "DELETE FROM application_kv WHERE key='management_id/node'")):
                if change:
                    with closing(sqlite3.connect(candidate)) as db, db:
                        db.execute(change)
                    original[candidate] = candidate.read_bytes()
                out, err = io.StringIO(), io.StringIO()
                with patch("sys.argv", ["compare", str(reference), str(candidate)]), \
                        redirect_stdout(out), redirect_stderr(err):
                    self.assertEqual(diagnostic.main(), status)
                if status != 1:
                    self.assertIn("no result proves recovery is safe", err.getvalue())
                    self.assertNotIn("private", out.getvalue())
                self.assertEqual({path: path.read_bytes() for path in original}, original)
                self.assertEqual(set(Path(temp).iterdir()), {reference, candidate})

    def test_cli_redacts_sqlite_text_decoding_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            reference, candidate = Path(temp) / "reference.db", Path(temp) / "candidate.db"
            backup(reference)
            backup(candidate)
            with closing(sqlite3.connect(candidate)) as db, db:
                db.execute("UPDATE nodes SET auth_key=CAST(? AS TEXT)", (b"private-secret\xff",))
            out, err = io.StringIO(), io.StringIO()
            with patch("sys.argv", ["compare", str(reference), str(candidate)]), \
                    redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(diagnostic.main(), 1)
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(err.getvalue(), "inspection failed: SQLite error\n")

    def test_detects_changed_revocations_and_json_types_but_ignores_json_formatting(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            before = diagnostic.read_backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE application_kv SET value=? WHERE key='node_revocation/old'",
                           ('{ "revoked_at": "2026-01-01", "node_id": 2 }',))
            self.assertEqual(diagnostic.compare(before, diagnostic.read_backup(path))[
                "records"]["revocations"]["changed"], 0)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE application_kv SET value=? WHERE key='node_revocation/old'",
                           ('{"revoked_at":"2026-01-02","node_id":2}',))
                db.execute("UPDATE application_kv SET value=? WHERE key='control_enrollment_result/peer'",
                           ('{"request_id":"id","extra":true}',))
            changed = diagnostic.read_backup(path)
            self.assertEqual(diagnostic.compare(before, changed)["records"]["revocations"]["changed"], 1)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE application_kv SET value=? WHERE key='control_enrollment_result/peer'",
                           ('{"request_id":"id","extra":1}',))
            self.assertEqual(diagnostic.compare(changed, diagnostic.read_backup(path))[
                "records"]["enrollment_receipts"]["changed"], 1)

    def test_rejects_missing_or_duplicate_topology_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("INSERT INTO nodes VALUES (1, 'duplicate', 'secret', NULL)")
            with self.assertRaises(diagnostic.InspectionError):
                diagnostic.read_backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.executescript("DROP TABLE nodes; CREATE TABLE nodes (name TEXT);")
            with self.assertRaises(diagnostic.InspectionError):
                diagnostic.read_backup(path)

    def test_rejects_mismatched_empty_topology_schema(self):
        with tempfile.TemporaryDirectory() as temp:
            reference, candidate = Path(temp) / "reference.db", Path(temp) / "candidate.db"
            backup(reference)
            backup(candidate)
            with closing(sqlite3.connect(candidate)) as db, db:
                db.execute("ALTER TABLE invites ADD COLUMN security_state TEXT")
            with self.assertRaisesRegex(diagnostic.InspectionError, "topology schemas differ"):
                diagnostic.compare(diagnostic.read_backup(reference), diagnostic.read_backup(candidate))

    def test_compares_tunnel_intents_backed_by_application_kv_view(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.executescript("""
                    DROP TABLE tunnel_intents;
                    INSERT INTO __diesel_schema_migrations VALUES ('202611100000000000');
                    INSERT INTO application_kv VALUES ('tunnel_intent/1/mesh/1', '[1,"mesh",1]');
                    CREATE VIEW tunnel_intents AS
                        SELECT json_extract(value,'$[0]') AS tunnel_id,
                               json_extract(value,'$[1]') AS kind,
                               json_extract(value,'$[2]') AS mesh_id
                        FROM application_kv WHERE substr(key,1,14)='tunnel_intent/';
                """)
            before = diagnostic.read_backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE application_kv SET key='tunnel_intent/2/mesh/1' WHERE key='tunnel_intent/1/mesh/1'")
            with self.assertRaisesRegex(diagnostic.InspectionError, "invalid tunnel intent record"):
                diagnostic.read_backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE application_kv SET key='tunnel_intent/1/mesh/1' WHERE key='tunnel_intent/2/mesh/1'")
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("DELETE FROM application_kv WHERE key='tunnel_intent/1/mesh/1'")
            self.assertEqual(diagnostic.compare(before, diagnostic.read_backup(path))["topology"]["tunnel_intents"],
                             {"missing": 1, "added": 0, "changed": 0})

    def test_detects_optional_l2tpv2_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            reference, candidate = Path(temp) / "reference.db", Path(temp) / "candidate.db"
            for path in (reference, candidate):
                backup(path)
                with closing(sqlite3.connect(path)) as db, db:
                    db.executescript("""
                        INSERT INTO __diesel_schema_migrations VALUES ('202611120000000000');
                        CREATE TABLE l2tpv2_tunnels (id INTEGER, secret TEXT);
                        INSERT INTO l2tpv2_tunnels VALUES (3, 'private-secret');
                    """)
            with closing(sqlite3.connect(candidate)) as db, db:
                db.execute("DELETE FROM l2tpv2_tunnels")
            result = diagnostic.compare(diagnostic.read_backup(reference), diagnostic.read_backup(candidate))
            self.assertEqual(result["topology"]["l2tpv2_tunnels"]["missing"], 1)

    def test_detects_tunnel_dependency_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.executescript("""
                    INSERT INTO __diesel_schema_migrations VALUES
                        ('202611120000000000'), ('202611140000000000');
                    CREATE TABLE l2tpv2_tunnels (id INTEGER, wireguard_tunnel_id INTEGER);
                    CREATE TABLE tunnel_dependencies (child_id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL);
                    CREATE TABLE tunnel_id_registry (id INTEGER PRIMARY KEY, kind TEXT NOT NULL);
                    INSERT INTO tunnel_id_registry VALUES (1, 'wireguard');
                    INSERT INTO tunnel_dependencies VALUES (2, 1);
                """)
            before = diagnostic.read_backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE tunnel_dependencies SET parent_id=3 WHERE child_id=2")
                db.execute("DELETE FROM tunnel_id_registry")
            changed = diagnostic.read_backup(path)
            self.assertEqual(diagnostic.compare(before, changed)["topology"]["tunnel_dependencies"],
                             {"missing": 0, "added": 0, "changed": 1})
            self.assertEqual(diagnostic.compare(before, changed)["topology"]["tunnel_id_registry"],
                             {"missing": 1, "added": 0, "changed": 0})
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("DELETE FROM tunnel_dependencies")
            self.assertEqual(diagnostic.compare(before, diagnostic.read_backup(path))["topology"]["tunnel_dependencies"],
                             {"missing": 1, "added": 0, "changed": 0})

    def test_detects_credential_receipt_feature_and_activation_losses(self):
        cases = (
            ("administrators", "administrator/1", {"username": "admin", "password_hash": "private-hash"}),
            ("administrator_receipts", "administrator_result/request", {"fingerprint": "private-command", "result": "ok"}),
            ("invite_receipts", "operator_invite_result/request", {"fingerprint": "private-invite", "result": "ok"}),
            ("answer_receipts", "control_answer_result/1/request", {"fingerprint": "private-answer", "result": "accepted", "expires_at": "2026-12-01"}),
            ("feature_support", "features/1", {"l2tpv3": True}),
            ("active_l2tp_tunnels", "l2tp_active/2", True),
        )
        with tempfile.TemporaryDirectory() as temp:
            reference, candidate = Path(temp) / "reference.db", Path(temp) / "candidate.db"
            backup(reference)
            backup(candidate)
            unchanged = diagnostic.read_backup(candidate)
            for label, key, value in cases:
                with self.subTest(record=label):
                    with closing(sqlite3.connect(reference)) as db, db:
                        db.execute("DELETE FROM application_kv WHERE key=?", (key,))
                        db.execute("INSERT INTO application_kv VALUES (?, ?)", (key, json.dumps(value)))
                    snapshot = diagnostic.read_backup(reference)
                    result = diagnostic.compare(snapshot, unchanged)
                    self.assertEqual(result["records"][label], {"missing": 1, "added": 0, "changed": 0})
                    self.assertEqual(diagnostic.compare(unchanged, snapshot)["records"][label],
                                     {"missing": 0, "added": 1, "changed": 0})
                    if isinstance(value, dict):
                        with closing(sqlite3.connect(reference)) as db, db:
                            db.execute("UPDATE application_kv SET value=? WHERE key=?",
                                       (json.dumps({**value, "extra": "private-change"}), key))
                        self.assertEqual(diagnostic.compare(snapshot, diagnostic.read_backup(reference))[
                            "records"][label]["changed"], 1)
                    out = io.StringIO()
                    with patch("sys.argv", ["compare", str(reference), str(candidate)]), \
                            redirect_stdout(out), redirect_stderr(io.StringIO()):
                        self.assertEqual(diagnostic.main(), 2)
                    self.assertNotIn("private", out.getvalue())
                    with closing(sqlite3.connect(reference)) as db, db:
                        db.execute("DELETE FROM application_kv WHERE key=?", (key,))

    def test_detects_invitation_and_settings_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            empty = diagnostic.read_backup(path)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("INSERT INTO invites VALUES (1, 'private-code', '2026-12-01', 0, 5)")
                db.execute("INSERT INTO settings VALUES (1, 'join_mesh', '1')")
            before = diagnostic.read_backup(path)
            for table in ("invites", "settings"):
                self.assertEqual(diagnostic.compare(empty, before)["topology"][table]["added"], 1)
                self.assertEqual(diagnostic.compare(before, empty)["topology"][table]["missing"], 1)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE invites SET used_count=1")
                db.execute("UPDATE settings SET value='2'")
            result = diagnostic.compare(before, diagnostic.read_backup(path))
            for table in ("invites", "settings"):
                self.assertEqual(result["topology"][table]["changed"], 1)
            self.assertNotIn("private", json.dumps(result))

    def test_rejects_malformed_newly_compared_recovery_records(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "backup.db"
            backup(path)
            for key, value in (("administrator/1", '"not an object"'),
                               ("administrator_result/request", '{"result":1,"result":2}'),
                               ("operator_invite_result/request", 'null'),
                               ("control_answer_result/1/request", '[]'),
                               ("features/1", '{"feature":NaN}'),
                               ("l2tp_active/2", 'false')):
                with self.subTest(record=key):
                    with closing(sqlite3.connect(path)) as db, db:
                        db.execute("INSERT INTO application_kv VALUES (?, ?)", (key, value))
                    with self.assertRaises(diagnostic.InspectionError):
                        diagnostic.read_backup(path)
                    with closing(sqlite3.connect(path)) as db, db:
                        db.execute("DELETE FROM application_kv WHERE key=?", (key,))


if __name__ == "__main__":
    unittest.main()
