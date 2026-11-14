CREATE UNIQUE INDEX enrollment_request_id_kv ON application_kv(json_extract(value,'$.request_id')) WHERE substr(key,1,26)='control_enrollment_result/' AND json_extract(value,'$.request_id') <> '';
