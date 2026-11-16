#!/usr/bin/env python3
"""Compare consistent, offline standalone-controller SQLite backups; never repair them.

Use SQLite's backup API to create self-contained copies with no WAL sidecars.
Absence of reported differences does not establish that either backup is current,
complete, authentic, or safe to restore. Run only on protected copies.
Comparison covers stored identities, allocation high-water marks, recovery records,
administrator credentials, invitations, settings, and known topology state, not lost
events or client-side state. Differences are directional relative to the reference,
not a determination of which copy is newer.
"""
from contextlib import closing
from dataclasses import dataclass
import argparse
import json
import sqlite3
import sys
from pathlib import Path

RECORD_PREFIXES = (
    ("revocations", "node_revocation/"),
    ("session_revocations", "session_revocation/"),
    ("enrollment_receipts", "control_enrollment_result/"),
    ("wireguard_keys", "wireguard_key/"),
    ("wireguard_refresh", "wireguard_refresh/"),
    ("administrators", "administrator/"),
    ("administrator_receipts", "administrator_result/"),
    ("invite_receipts", "operator_invite_result/"),
    ("answer_receipts", "control_answer_result/"),
    ("feature_support", "features/"),
    ("active_l2tp_tunnels", "l2tp_active/"),
)


class InspectionError(Exception):
    pass


@dataclass(frozen=True)
class Backup:
    migrations: frozenset
    identities: dict
    records: dict
    allocations: dict
    topology: dict
    topology_columns: dict


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError("non-finite JSON number")


def json_integer(value):
    # serde_json treats -0 as a floating-point number, unlike Python's int parser.
    return -0.0 if value == "-0" else int(value)


def read_backup(path):
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise InspectionError("backup is not a regular file")
    if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise InspectionError("backup has SQLite sidecars; use a self-contained offline backup copy")
    # Immutable mode makes this strictly read-only, including avoiding SQLite sidecar creation.
    uri = path.as_uri() + "?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise InspectionError("SQLite integrity check failed")
        raft_tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_schema WHERE name IN ('raft_meta', 'raft_logs')"
        )}
        if raft_tables and raft_tables != {"raft_meta", "raft_logs"}:
            raise InspectionError("incomplete consensus metadata")
        if raft_tables and db.execute(
            "SELECT EXISTS(SELECT 1 FROM raft_meta) OR EXISTS(SELECT 1 FROM raft_logs)"
        ).fetchone()[0]:
            raise InspectionError("backup contains unsupported consensus state")
        migrations = frozenset(row[0] for row in db.execute("SELECT version FROM __diesel_schema_migrations"))
        required = {f"202611{day:02}0000000000" for day in range(2, 10)}
        if not required.issubset(migrations):
            raise InspectionError("backup predates the supported recovery-record schema")
        identities = {}
        for node, peer, signing, encryption, revision in db.execute(
            "SELECT node_id, peer_id, signing_key, encryption_key, topology_revision FROM node_control_identities"
        ):
            if (not isinstance(node, int) or node <= 0 or not isinstance(revision, int) or revision < 0
                    or not all(isinstance(x, str) and x for x in (peer, signing, encryption)) or node in identities):
                raise InspectionError("invalid control identity record")
            identities[node] = (peer, signing, encryption, revision)
        records, allocations = {}, {}
        prefixes = [prefix for _, prefix in RECORD_PREFIXES] + ["management_id/"]
        for key, value in db.execute(
            "SELECT key, value FROM application_kv WHERE "
            + " OR ".join("substr(key,1,length(?))=?" for _ in prefixes),
            [value for prefix in prefixes for value in (prefix, prefix)],
        ):
            if not isinstance(key, str) or not isinstance(value, str) or key in records:
                raise InspectionError("invalid recovery record")
            try:
                parsed = json.loads(value, object_pairs_hook=strict_object, parse_constant=invalid_constant,
                                    parse_int=json_integer)
                canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), allow_nan=False)
            except (ValueError, RecursionError) as error:
                raise InspectionError("invalid recovery record JSON") from error
            if key.startswith("management_id/"):
                kind = key.removeprefix("management_id/")
                if (kind not in {"node", "mesh", "tunnel", "l2tp", "l2tpv2"} or kind in allocations
                        or type(parsed) is not int or not 0 <= parsed <= 2147483647):
                    raise InspectionError("invalid allocation high-water mark")
                allocations[kind] = parsed
            else:
                if not key.split("/", 1)[1]:
                    raise InspectionError("invalid recovery record key")
                if key.startswith(("l2tp_active/", "session_revocation/")):
                    if parsed is not True:
                        raise InspectionError("invalid boolean recovery record")
                elif not isinstance(parsed, dict):
                    raise InspectionError("invalid recovery record JSON")
                if key.startswith("node_revocation/") and (
                        type(parsed.get("node_id")) is not int or not 0 < parsed["node_id"] <= 2147483647
                        or not isinstance(parsed.get("revoked_at"), str) or not parsed["revoked_at"]):
                    raise InspectionError("invalid revocation record")
                # Canonical JSON preserves type differences (Python considers True == 1).
                records[key] = canonical
        if not {"node", "mesh", "tunnel"}.issubset(allocations):
            raise InspectionError("missing allocation high-water mark")
        if "202611100000000000" in migrations:
            for key, value in db.execute(
                "SELECT key, value FROM application_kv WHERE substr(key,1,14)='tunnel_intent/'"
            ):
                try:
                    intent = json.loads(value, object_pairs_hook=strict_object, parse_constant=invalid_constant,
                                        parse_int=json_integer)
                    if (not isinstance(intent, list) or len(intent) != 3
                            or type(intent[0]) is not int or intent[0] <= 0 or intent[0] > 2147483647
                            or intent[1] not in ("mesh", "manual", "legacy")
                            or type(intent[2]) is not int
                            or key != f"tunnel_intent/{intent[0]}/{intent[1]}/{intent[2]}"):
                        raise ValueError("invalid tunnel intent")
                except (ValueError, TypeError, RecursionError) as error:
                    raise InspectionError("invalid tunnel intent record") from error
        topology, topology_columns = {}, {}
        tables = ["nodes", "mesh_groups", "mesh_group_memberships", "wireguard_tunnels",
                  "l2tpv3_tunnels", "tunnel_intents", "invites", "settings"]
        if "202611120000000000" in migrations:
            tables.append("l2tpv2_tunnels")
        if "202611140000000000" in migrations:
            tables.extend(("tunnel_dependencies", "tunnel_id_registry"))
        for table in tables:
            cursor = db.execute(f'SELECT * FROM "{table}"')
            columns = [column[0] for column in cursor.description]
            topology_columns[table] = tuple(columns)
            keys = (("tunnel_id", "kind", "mesh_id") if table == "tunnel_intents" else
                    ("child_id",) if table == "tunnel_dependencies" else ("id",))
            if not set(keys).issubset(columns):
                raise InspectionError("missing topology key columns")
            key_indices = [columns.index(key) for key in keys]
            # Liveness is volatile; other timestamps are persisted controller state.
            ignored = {"last_seen"}
            indices = [i for i, column in enumerate(columns) if column not in ignored]
            rows = {}
            for row in cursor:
                key = tuple(row[i] for i in key_indices)
                if (type(key[0]) is not int or not 0 < key[0] <= 2147483647
                        or (table == "tunnel_intents" and
                            (key[1] not in {"mesh", "manual", "legacy"} or type(key[2]) is not int))):
                    raise InspectionError("invalid topology record key")
                if key in rows:
                    raise InspectionError("duplicate topology record")
                rows[key] = tuple((columns[i], row[i]) for i in indices)
            topology[table] = rows
        return Backup(migrations, identities, records, allocations, topology, topology_columns)


def compare(reference, candidate):
    ref_migrations, ref_ids, ref_records = reference.migrations, reference.identities, reference.records
    migrations, ids, records = candidate.migrations, candidate.identities, candidate.records
    if not ref_migrations or ref_migrations != migrations:
        raise InspectionError("backup schema migrations differ or are empty; compare matching schemas")
    if reference.topology_columns != candidate.topology_columns:
        raise InspectionError("backup topology schemas differ; compare matching schemas")
    missing = sorted(ref_ids.keys() - ids.keys())
    added = sorted(ids.keys() - ref_ids.keys())
    changed = sorted(node for node in ref_ids.keys() & ids.keys() if ref_ids[node][:3] != ids[node][:3])
    regressed = sorted(node for node in ref_ids.keys() & ids.keys() if ids[node][3] < ref_ids[node][3])
    advanced = sorted(node for node in ref_ids.keys() & ids.keys() if ids[node][3] > ref_ids[node][3])
    record_added = records.keys() - ref_records.keys()
    record_missing = ref_records.keys() - records.keys()
    record_changed = {key for key in ref_records.keys() & records.keys() if ref_records[key] != records[key]}
    counts = {}
    for label, prefix in RECORD_PREFIXES:
        counts[label] = {
            "added": sum(key.startswith(prefix) for key in record_added),
            "missing": sum(key.startswith(prefix) for key in record_missing),
            "changed": sum(key.startswith(prefix) for key in record_changed),
        }
    allocations = {
        kind: {"reference": reference.allocations.get(kind), "candidate": candidate.allocations.get(kind)}
        for kind in sorted(reference.allocations.keys() | candidate.allocations.keys())
        if reference.allocations.get(kind) != candidate.allocations.get(kind)
    }
    topology = {}
    for table in sorted(reference.topology.keys() | candidate.topology.keys()):
        before, after = reference.topology.get(table, {}), candidate.topology.get(table, {})
        topology[table] = {
            "missing": len(before.keys() - after.keys()),
            "added": len(after.keys() - before.keys()),
            "changed": sum(before[key] != after[key] for key in before.keys() & after.keys()),
        }
    return {"missing_identity_node_ids": missing, "added_identity_node_ids": added,
            "changed_identity_node_ids": changed, "regressed_revision_node_ids": regressed,
            "advanced_revision_node_ids": advanced, "records": counts,
            "changed_allocation_high_water": allocations, "topology": topology}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", help="newer trusted, self-contained SQLite backup")
    parser.add_argument("candidate", help="candidate self-contained SQLite backup to inspect")
    args = parser.parse_args()
    try:
        result = compare(read_backup(args.reference), read_backup(args.candidate))
    except sqlite3.Error:
        # SQLite decoding errors can include the contents of secret-bearing columns.
        print("inspection failed: SQLite error", file=sys.stderr)
        return 1
    except (InspectionError, OSError) as error:
        print(f"inspection failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    print("WARNING: no result proves recovery is safe or either backup is current, complete or authentic; "
          "client cache high-water marks and lost events remain unverified.", file=sys.stderr)
    return 2 if any((result["missing_identity_node_ids"], result["added_identity_node_ids"],
                     result["changed_identity_node_ids"], result["regressed_revision_node_ids"],
                     result["advanced_revision_node_ids"], result["changed_allocation_high_water"],
                     *(n for group in result["records"].values() for n in group.values()),
                     *(n for group in result["topology"].values() for n in group.values()))) else 0


if __name__ == "__main__":
    sys.exit(main())
