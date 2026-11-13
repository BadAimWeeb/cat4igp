CREATE TABLE tunnel_intents_restore (tunnel_id INTEGER NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('mesh','manual','legacy')), mesh_id INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(tunnel_id,kind,mesh_id));
INSERT INTO tunnel_intents_restore SELECT tunnel_id,kind,mesh_id FROM tunnel_intents;
DROP TRIGGER tunnel_intents_insert;
DROP TRIGGER tunnel_intents_delete;
DROP TRIGGER tunnel_intent_kv_insert;
DROP TRIGGER tunnel_intent_kv_update;
DROP VIEW tunnel_intents;
ALTER TABLE tunnel_intents_restore RENAME TO tunnel_intents;
DELETE FROM application_kv WHERE substr(key,1,14)='tunnel_intent/';