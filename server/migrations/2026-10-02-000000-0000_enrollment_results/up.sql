CREATE TABLE control_enrollment_results (
    peer_id TEXT PRIMARY KEY NOT NULL,
    request_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    result TEXT NOT NULL
);
-- Legacy empty IDs remain identity-scoped; explicit IDs cannot change principal.
CREATE UNIQUE INDEX control_enrollment_request_id
    ON control_enrollment_results(request_id) WHERE request_id <> '';