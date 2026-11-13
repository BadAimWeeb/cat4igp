CREATE TEMP TABLE answer_migration_check (valid INTEGER NOT NULL CHECK(valid=1));
INSERT INTO answer_migration_check SELECT 0 FROM control_answer_results WHERE node_id <= 0 OR node_id > 2147483647 OR request_id = '' OR length(CAST(request_id AS BLOB)) > 256;
INSERT INTO application_kv(key,value) SELECT 'control_answer_result/' || node_id || '/' || request_id, json_object('fingerprint',fingerprint,'result',result,'expires_at',expires_at) FROM control_answer_results;
DROP TABLE answer_migration_check;
DROP TABLE control_answer_results;