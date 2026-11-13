DROP TRIGGER management_node_id;
DROP TRIGGER management_mesh_id;
DROP TRIGGER management_tunnel_id;
CREATE TABLE management_ids (kind TEXT PRIMARY KEY NOT NULL, high_water INTEGER NOT NULL CHECK(high_water >= 0));
INSERT INTO management_ids SELECT substr(key, 15), CAST(value AS INTEGER) FROM application_kv WHERE key IN ('management_id/node', 'management_id/mesh', 'management_id/tunnel');
CREATE TRIGGER management_node_id AFTER INSERT ON nodes BEGIN UPDATE management_ids SET high_water=MAX(high_water,NEW.id) WHERE kind='node'; END;
CREATE TRIGGER management_mesh_id AFTER INSERT ON mesh_groups BEGIN UPDATE management_ids SET high_water=MAX(high_water,NEW.id) WHERE kind='mesh'; END;
CREATE TRIGGER management_tunnel_id AFTER INSERT ON wireguard_tunnels BEGIN UPDATE management_ids SET high_water=MAX(high_water,NEW.id) WHERE kind='tunnel'; END;
DELETE FROM application_kv WHERE key IN ('management_id/node', 'management_id/mesh', 'management_id/tunnel');