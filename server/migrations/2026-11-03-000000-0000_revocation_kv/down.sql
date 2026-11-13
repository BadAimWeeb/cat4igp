CREATE TABLE node_revocations (peer_id TEXT PRIMARY KEY NOT NULL, node_id INTEGER NOT NULL, revoked_at TIMESTAMP NOT NULL);
INSERT INTO node_revocations(peer_id, node_id, revoked_at)
    SELECT substr(key, 17), json_extract(value, '$.node_id'), json_extract(value, '$.revoked_at')
    FROM application_kv WHERE substr(key, 1, 16) = 'node_revocation/';
DELETE FROM application_kv WHERE substr(key, 1, 16) = 'node_revocation/';