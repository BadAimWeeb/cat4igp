CREATE TABLE administrator (id INTEGER PRIMARY KEY CHECK(id = 1), username TEXT NOT NULL, password_hash TEXT NOT NULL);
INSERT INTO administrator (id, username, password_hash)
    SELECT 1, json_extract(value, '$.username'), json_extract(value, '$.password_hash')
    FROM application_kv WHERE key = 'administrator/1';
DROP TABLE application_kv;