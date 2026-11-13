CREATE TABLE application_kv (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL CHECK(json_valid(value))
);
INSERT INTO application_kv (key, value)
    SELECT 'administrator/1', json_object('username', username, 'password_hash', password_hash)
    FROM administrator WHERE id = 1;
DROP TABLE administrator;