CREATE TEMP TABLE wireguard_key_migration_check (valid INTEGER NOT NULL CHECK(valid = 1));
INSERT INTO wireguard_key_migration_check SELECT 0 FROM wireguard_static_key WHERE node_id <= 0 OR node_id > 2147483647;
INSERT INTO application_kv(key,value) SELECT 'wireguard_key/' || node_id, json_object('public_key',public_key,'created_at',created_at) FROM wireguard_static_key;
DROP TABLE wireguard_key_migration_check;
DROP TABLE wireguard_static_key;