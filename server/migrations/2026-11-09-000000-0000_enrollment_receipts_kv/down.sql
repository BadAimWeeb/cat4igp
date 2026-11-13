CREATE TABLE control_enrollment_results (peer_id TEXT PRIMARY KEY NOT NULL, request_id TEXT NOT NULL, fingerprint TEXT NOT NULL, result TEXT NOT NULL);
CREATE UNIQUE INDEX control_enrollment_request_id ON control_enrollment_results(request_id) WHERE request_id <> '';
INSERT INTO control_enrollment_results SELECT substr(key,27),json_extract(value,'$.request_id'),json_extract(value,'$.fingerprint'),json_extract(value,'$.result') FROM application_kv WHERE substr(key,1,26)='control_enrollment_result/';
DELETE FROM application_kv WHERE substr(key,1,26)='control_enrollment_result/';
DROP INDEX enrollment_request_id_kv;