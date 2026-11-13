INSERT INTO application_kv(key, value)
    SELECT 'administrator_result/' || request_id, json_object('fingerprint', fingerprint, 'result', result) FROM administrator_results;
DROP TABLE administrator_results;