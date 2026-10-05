-- Fail closed on legacy duplicates; never discard controller keys or memberships.
CREATE TEMP TABLE ha_preflight (valid INTEGER CONSTRAINT repair_duplicate_settings_keys_before_migration CHECK (valid = 1));
INSERT INTO ha_preflight SELECT 0 FROM settings GROUP BY key HAVING COUNT(*) > 1;
DROP TABLE ha_preflight;
CREATE TEMP TABLE ha_preflight (valid INTEGER CONSTRAINT repair_duplicate_mesh_memberships_before_migration CHECK (valid = 1));
INSERT INTO ha_preflight SELECT 0 FROM mesh_group_memberships GROUP BY mesh_group_id, node_id HAVING COUNT(*) > 1;
DROP TABLE ha_preflight;
CREATE UNIQUE INDEX settings_key_unique ON settings(key);
CREATE UNIQUE INDEX mesh_membership_unique ON mesh_group_memberships(mesh_group_id, node_id);

CREATE TABLE control_answer_results (
    node_id INTEGER NOT NULL,
    request_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    result TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    PRIMARY KEY (node_id, request_id)
);