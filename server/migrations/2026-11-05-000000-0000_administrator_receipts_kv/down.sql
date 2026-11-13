CREATE TABLE administrator_results (request_id TEXT PRIMARY KEY NOT NULL, fingerprint TEXT NOT NULL, result TEXT NOT NULL);
INSERT INTO administrator_results(request_id, fingerprint, result)
    SELECT substr(key, 22), json_extract(value, '$.fingerprint'), json_extract(value, '$.result')
    FROM application_kv WHERE substr(key, 1, 21) = 'administrator_result/';
DELETE FROM application_kv WHERE substr(key, 1, 21) = 'administrator_result/';