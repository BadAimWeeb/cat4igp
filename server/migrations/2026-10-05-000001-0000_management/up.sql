CREATE TABLE management_ids (kind TEXT PRIMARY KEY NOT NULL, high_water INTEGER NOT NULL CHECK(high_water >= 0));
INSERT INTO management_ids VALUES ('node',COALESCE((SELECT MAX(id) FROM nodes),0)),('mesh',COALESCE((SELECT MAX(id) FROM mesh_groups),0)),('tunnel',COALESCE((SELECT MAX(id) FROM wireguard_tunnels),0));
CREATE TRIGGER management_node_id AFTER INSERT ON nodes BEGIN UPDATE management_ids SET high_water=MAX(high_water,NEW.id) WHERE kind='node'; END;
CREATE TRIGGER management_mesh_id AFTER INSERT ON mesh_groups BEGIN UPDATE management_ids SET high_water=MAX(high_water,NEW.id) WHERE kind='mesh'; END;
CREATE TRIGGER management_tunnel_id AFTER INSERT ON wireguard_tunnels BEGIN UPDATE management_ids SET high_water=MAX(high_water,NEW.id) WHERE kind='tunnel'; END;
CREATE TABLE node_revocations (peer_id TEXT PRIMARY KEY NOT NULL, node_id INTEGER NOT NULL, revoked_at TIMESTAMP NOT NULL);
CREATE TABLE tunnel_intents (tunnel_id INTEGER NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('mesh','manual','legacy')), mesh_id INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(tunnel_id,kind,mesh_id));
-- ponytail: historical ownership cannot be proven; retain legacy intent even with mesh matches.
-- Remove it only through an explicit administrator confirmation, never by inference.
INSERT INTO tunnel_intents SELECT id,'legacy',0 FROM wireguard_tunnels;
INSERT OR IGNORE INTO tunnel_intents SELECT t.id,'mesh',m.id FROM wireguard_tunnels t JOIN mesh_groups m ON m.auto_wireguard=1 JOIN mesh_group_memberships a ON a.mesh_group_id=m.id AND a.node_id=t.node_id_peer1 JOIN mesh_group_memberships b ON b.mesh_group_id=m.id AND b.node_id=t.node_id_peer2;