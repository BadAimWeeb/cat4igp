INSERT INTO application_kv(key,value) SELECT 'tunnel_intent/' || tunnel_id || '/' || kind || '/' || mesh_id,json_array(tunnel_id,kind,mesh_id) FROM tunnel_intents;
DROP TABLE tunnel_intents;
CREATE VIEW tunnel_intents AS SELECT json_extract(value,'$[0]') AS tunnel_id,json_extract(value,'$[1]') AS kind,json_extract(value,'$[2]') AS mesh_id FROM application_kv WHERE substr(key,1,14)='tunnel_intent/';
CREATE TRIGGER tunnel_intent_kv_insert BEFORE INSERT ON application_kv WHEN substr(NEW.key,1,14)='tunnel_intent/' BEGIN
  SELECT CASE WHEN json_type(NEW.value) != 'array' OR json_array_length(NEW.value) != 3 OR coalesce(json_type(NEW.value,'$[0]'),'') != 'integer' OR coalesce(json_type(NEW.value,'$[1]'),'') != 'text' OR coalesce(json_type(NEW.value,'$[2]'),'') != 'integer' OR json_extract(NEW.value,'$[1]') NOT IN ('mesh','manual','legacy') OR NEW.key != 'tunnel_intent/' || json_extract(NEW.value,'$[0]') || '/' || json_extract(NEW.value,'$[1]') || '/' || json_extract(NEW.value,'$[2]') THEN RAISE(ABORT,'invalid tunnel intent') END;
END;
CREATE TRIGGER tunnel_intent_kv_update BEFORE UPDATE ON application_kv WHEN substr(NEW.key,1,14)='tunnel_intent/' BEGIN
  SELECT CASE WHEN json_type(NEW.value) != 'array' OR json_array_length(NEW.value) != 3 OR coalesce(json_type(NEW.value,'$[0]'),'') != 'integer' OR coalesce(json_type(NEW.value,'$[1]'),'') != 'text' OR coalesce(json_type(NEW.value,'$[2]'),'') != 'integer' OR json_extract(NEW.value,'$[1]') NOT IN ('mesh','manual','legacy') OR NEW.key != 'tunnel_intent/' || json_extract(NEW.value,'$[0]') || '/' || json_extract(NEW.value,'$[1]') || '/' || json_extract(NEW.value,'$[2]') THEN RAISE(ABORT,'invalid tunnel intent') END;
END;
CREATE TRIGGER tunnel_intents_insert INSTEAD OF INSERT ON tunnel_intents BEGIN
  SELECT CASE WHEN typeof(NEW.tunnel_id) != 'integer' OR NEW.kind NOT IN ('mesh','manual','legacy') OR NEW.kind IS NULL OR typeof(NEW.mesh_id) != 'integer' THEN RAISE(ABORT,'invalid tunnel intent') END;
  INSERT INTO application_kv(key,value) VALUES('tunnel_intent/' || NEW.tunnel_id || '/' || NEW.kind || '/' || NEW.mesh_id,json_array(NEW.tunnel_id,NEW.kind,NEW.mesh_id));
END;
CREATE TRIGGER tunnel_intents_delete INSTEAD OF DELETE ON tunnel_intents BEGIN
  DELETE FROM application_kv WHERE key='tunnel_intent/' || OLD.tunnel_id || '/' || OLD.kind || '/' || OLD.mesh_id;
END;