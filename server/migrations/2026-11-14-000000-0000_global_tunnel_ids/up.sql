-- Keep WireGuard IDs fixed; give v2 priority over v3 for shared legacy IDs.
CREATE TEMP TABLE tunnel_id_guard (ok INTEGER NOT NULL CHECK(ok=1));
INSERT INTO tunnel_id_guard SELECT CASE WHEN
  EXISTS (SELECT 1 FROM application_kv WHERE key='management_id/tunnel') AND
  NOT EXISTS (SELECT 1 FROM application_kv WHERE key IN ('management_id/tunnel','management_id/l2tpv2','management_id/l2tp') AND CASE WHEN json_valid(value) THEN json_type(value)!='integer' OR CAST(value AS INTEGER) NOT BETWEEN 0 AND 2147483647 ELSE 1 END)
THEN 1 ELSE 0 END;
CREATE TEMP TABLE tunnel_id_base (id INTEGER NOT NULL);
INSERT INTO tunnel_id_base SELECT max(id) FROM (
  SELECT 0 AS id UNION ALL SELECT id FROM wireguard_tunnels UNION ALL SELECT id FROM l2tpv2_tunnels UNION ALL SELECT id FROM l2tpv3_tunnels
  UNION ALL SELECT CAST(value AS INTEGER) FROM application_kv WHERE key IN ('management_id/tunnel','management_id/l2tpv2','management_id/l2tp')
);
CREATE TEMP TABLE tunnel_id_remap (kind TEXT NOT NULL, old_id INTEGER NOT NULL, new_id INTEGER NOT NULL, PRIMARY KEY(kind,old_id));
INSERT INTO tunnel_id_remap
SELECT kind, old_id, (SELECT id FROM tunnel_id_base) + row_number() OVER (ORDER BY kind, old_id)
FROM (
  SELECT 'v2' AS kind, id AS old_id FROM l2tpv2_tunnels WHERE id IN (SELECT id FROM wireguard_tunnels)
  UNION ALL
  SELECT 'v3', id FROM l2tpv3_tunnels WHERE id IN (SELECT id FROM wireguard_tunnels UNION SELECT id FROM l2tpv2_tunnels)
);
INSERT INTO tunnel_id_guard SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM tunnel_id_remap WHERE new_id > 2147483647) THEN 1 ELSE 0 END;
INSERT INTO tunnel_id_guard SELECT CASE WHEN NOT EXISTS (
  SELECT 1 FROM node_control_identities WHERE topology_revision >= 9223372036854775807 AND node_id IN (
    SELECT node_id_peer1 FROM l2tpv2_tunnels WHERE id IN (SELECT old_id FROM tunnel_id_remap WHERE kind='v2')
    UNION SELECT node_id_peer2 FROM l2tpv2_tunnels WHERE id IN (SELECT old_id FROM tunnel_id_remap WHERE kind='v2')
    UNION SELECT node_id_peer1 FROM l2tpv3_tunnels WHERE id IN (SELECT old_id FROM tunnel_id_remap WHERE kind='v3') AND EXISTS (SELECT 1 FROM application_kv WHERE key='l2tp_active/' || l2tpv3_tunnels.id)
    UNION SELECT node_id_peer2 FROM l2tpv3_tunnels WHERE id IN (SELECT old_id FROM tunnel_id_remap WHERE kind='v3') AND EXISTS (SELECT 1 FROM application_kv WHERE key='l2tp_active/' || l2tpv3_tunnels.id)
  )
) THEN 1 ELSE 0 END;
UPDATE node_control_identities SET topology_revision=topology_revision+1, updated_at=CURRENT_TIMESTAMP WHERE node_id IN (
  SELECT node_id_peer1 FROM l2tpv2_tunnels WHERE id IN (SELECT old_id FROM tunnel_id_remap WHERE kind='v2')
  UNION SELECT node_id_peer2 FROM l2tpv2_tunnels WHERE id IN (SELECT old_id FROM tunnel_id_remap WHERE kind='v2')
  UNION SELECT node_id_peer1 FROM l2tpv3_tunnels WHERE id IN (SELECT old_id FROM tunnel_id_remap WHERE kind='v3') AND EXISTS (SELECT 1 FROM application_kv WHERE key='l2tp_active/' || l2tpv3_tunnels.id)
  UNION SELECT node_id_peer2 FROM l2tpv3_tunnels WHERE id IN (SELECT old_id FROM tunnel_id_remap WHERE kind='v3') AND EXISTS (SELECT 1 FROM application_kv WHERE key='l2tp_active/' || l2tpv3_tunnels.id)
);
UPDATE application_kv SET key='l2tp_active/' || (SELECT new_id FROM tunnel_id_remap WHERE kind='v3' AND key='l2tp_active/' || old_id) WHERE key IN (SELECT 'l2tp_active/' || old_id FROM tunnel_id_remap WHERE kind='v3');
UPDATE l2tpv2_tunnels SET id=(SELECT new_id FROM tunnel_id_remap WHERE kind='v2' AND old_id=id) WHERE id IN (SELECT old_id FROM tunnel_id_remap WHERE kind='v2');
UPDATE l2tpv3_tunnels SET id=(SELECT new_id FROM tunnel_id_remap WHERE kind='v3' AND old_id=id) WHERE id IN (SELECT old_id FROM tunnel_id_remap WHERE kind='v3');
UPDATE application_kv SET value=json(max((SELECT id FROM tunnel_id_base), coalesce((SELECT max(new_id) FROM tunnel_id_remap),0))) WHERE key='management_id/tunnel';
DELETE FROM application_kv WHERE key IN ('management_id/l2tp','management_id/l2tpv2');
DROP TABLE tunnel_id_remap;
DROP TABLE tunnel_id_base;
DROP TABLE tunnel_id_guard;

CREATE TABLE tunnel_id_registry (id INTEGER PRIMARY KEY, kind TEXT NOT NULL);
INSERT INTO tunnel_id_registry SELECT id,'wireguard' FROM wireguard_tunnels;
INSERT INTO tunnel_id_registry SELECT id,'v2' FROM l2tpv2_tunnels;
INSERT INTO tunnel_id_registry SELECT id,'v3' FROM l2tpv3_tunnels;
CREATE TABLE tunnel_dependencies (child_id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL);
INSERT INTO tunnel_dependencies SELECT id,wireguard_tunnel_id FROM l2tpv2_tunnels WHERE wireguard_tunnel_id IS NOT NULL;
INSERT INTO tunnel_dependencies SELECT id,wireguard_tunnel_id FROM l2tpv3_tunnels WHERE wireguard_tunnel_id IS NOT NULL;
CREATE TRIGGER tunnel_dependency_v2_insert AFTER INSERT ON l2tpv2_tunnels WHEN NEW.wireguard_tunnel_id IS NOT NULL BEGIN INSERT INTO tunnel_dependencies VALUES(NEW.id,NEW.wireguard_tunnel_id); END;
CREATE TRIGGER tunnel_dependency_v3_insert AFTER INSERT ON l2tpv3_tunnels WHEN NEW.wireguard_tunnel_id IS NOT NULL BEGIN INSERT INTO tunnel_dependencies VALUES(NEW.id,NEW.wireguard_tunnel_id); END;
CREATE TRIGGER tunnel_dependency_v2_update AFTER UPDATE OF wireguard_tunnel_id ON l2tpv2_tunnels BEGIN DELETE FROM tunnel_dependencies WHERE child_id=OLD.id; INSERT INTO tunnel_dependencies SELECT NEW.id,NEW.wireguard_tunnel_id WHERE NEW.wireguard_tunnel_id IS NOT NULL; END;
CREATE TRIGGER tunnel_dependency_v3_update AFTER UPDATE OF wireguard_tunnel_id ON l2tpv3_tunnels BEGIN DELETE FROM tunnel_dependencies WHERE child_id=OLD.id; INSERT INTO tunnel_dependencies SELECT NEW.id,NEW.wireguard_tunnel_id WHERE NEW.wireguard_tunnel_id IS NOT NULL; END;
CREATE TRIGGER tunnel_dependency_v2_delete AFTER DELETE ON l2tpv2_tunnels BEGIN DELETE FROM tunnel_dependencies WHERE child_id=OLD.id; END;
CREATE TRIGGER tunnel_dependency_v3_delete AFTER DELETE ON l2tpv3_tunnels BEGIN DELETE FROM tunnel_dependencies WHERE child_id=OLD.id; END;
DROP TRIGGER management_tunnel_id;
CREATE TRIGGER tunnel_registry_wireguard_insert AFTER INSERT ON wireguard_tunnels BEGIN
  SELECT CASE WHEN EXISTS (SELECT 1 FROM tunnel_id_registry WHERE id=NEW.id) THEN RAISE(ABORT,'duplicate tunnel ID') END;
  SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM application_kv WHERE key='management_id/tunnel' AND CASE WHEN json_valid(value) THEN json_type(value)='integer' AND CAST(value AS INTEGER) BETWEEN 0 AND 2147483647 ELSE 0 END) THEN RAISE(ABORT,'invalid management ID') END;
  INSERT INTO tunnel_id_registry VALUES(NEW.id,'wireguard');
  UPDATE application_kv SET value=json(max(CAST(value AS INTEGER),NEW.id)) WHERE key='management_id/tunnel';
END;
CREATE TRIGGER tunnel_registry_v2_insert AFTER INSERT ON l2tpv2_tunnels BEGIN
  SELECT CASE WHEN EXISTS (SELECT 1 FROM tunnel_id_registry WHERE id=NEW.id) THEN RAISE(ABORT,'duplicate tunnel ID') END;
  SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM application_kv WHERE key='management_id/tunnel' AND CASE WHEN json_valid(value) THEN json_type(value)='integer' AND CAST(value AS INTEGER) BETWEEN 0 AND 2147483647 ELSE 0 END) THEN RAISE(ABORT,'invalid management ID') END;
  INSERT INTO tunnel_id_registry VALUES(NEW.id,'v2');
  UPDATE application_kv SET value=json(max(CAST(value AS INTEGER),NEW.id)) WHERE key='management_id/tunnel';
END;
CREATE TRIGGER tunnel_registry_v3_insert AFTER INSERT ON l2tpv3_tunnels BEGIN
  SELECT CASE WHEN EXISTS (SELECT 1 FROM tunnel_id_registry WHERE id=NEW.id) THEN RAISE(ABORT,'duplicate tunnel ID') END;
  SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM application_kv WHERE key='management_id/tunnel' AND CASE WHEN json_valid(value) THEN json_type(value)='integer' AND CAST(value AS INTEGER) BETWEEN 0 AND 2147483647 ELSE 0 END) THEN RAISE(ABORT,'invalid management ID') END;
  INSERT INTO tunnel_id_registry VALUES(NEW.id,'v3');
  UPDATE application_kv SET value=json(max(CAST(value AS INTEGER),NEW.id)) WHERE key='management_id/tunnel';
END;
CREATE TRIGGER tunnel_registry_wireguard_delete AFTER DELETE ON wireguard_tunnels BEGIN DELETE FROM tunnel_id_registry WHERE id=OLD.id AND kind='wireguard'; END;
CREATE TRIGGER tunnel_registry_v2_delete AFTER DELETE ON l2tpv2_tunnels BEGIN DELETE FROM tunnel_id_registry WHERE id=OLD.id AND kind='v2'; END;
CREATE TRIGGER tunnel_registry_v3_delete AFTER DELETE ON l2tpv3_tunnels BEGIN DELETE FROM tunnel_id_registry WHERE id=OLD.id AND kind='v3'; END;
CREATE TRIGGER tunnel_registry_wireguard_update BEFORE UPDATE OF id ON wireguard_tunnels WHEN NEW.id!=OLD.id BEGIN SELECT RAISE(ABORT,'tunnel ID is immutable'); END;
CREATE TRIGGER tunnel_registry_v2_update BEFORE UPDATE OF id ON l2tpv2_tunnels WHEN NEW.id!=OLD.id BEGIN SELECT RAISE(ABORT,'tunnel ID is immutable'); END;
CREATE TRIGGER tunnel_registry_v3_update BEFORE UPDATE OF id ON l2tpv3_tunnels WHEN NEW.id!=OLD.id BEGIN SELECT RAISE(ABORT,'tunnel ID is immutable'); END;
