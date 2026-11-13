CREATE TEMP TABLE revocation_migration_check (valid INTEGER NOT NULL CHECK(valid = 1));
INSERT INTO revocation_migration_check SELECT 0 FROM node_revocations WHERE peer_id = '' OR node_id <= 0;
INSERT INTO application_kv(key, value)
    SELECT 'node_revocation/' || peer_id, json_object('node_id', node_id, 'revoked_at', revoked_at)
    FROM node_revocations;
DROP TABLE revocation_migration_check;
DROP TABLE node_revocations;