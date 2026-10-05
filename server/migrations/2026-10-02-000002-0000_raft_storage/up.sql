CREATE TABLE raft_meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
-- Fixed-width hexadecimal indices preserve the full u64 range and SQL ordering.
CREATE TABLE raft_logs (idx TEXT PRIMARY KEY NOT NULL CHECK(length(idx) = 16), value TEXT NOT NULL);