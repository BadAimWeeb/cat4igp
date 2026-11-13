use diesel::{connection::SimpleConnection, Connection, SqliteConnection};

#[test]
fn manual_migration_rejects_old_ha_before_writes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("old ?#%.sqlite");
    let mut conn = SqliteConnection::establish(path.to_str().unwrap()).unwrap();
    conn.batch_execute("CREATE TABLE raft_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE raft_logs(idx TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO raft_meta VALUES ('application_version', '1');").unwrap();
    drop(conn);
    let before = std::fs::read(&path).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cat4igp-server"))
        .arg("migrate").env_clear().env("DATABASE_URL", &path).current_dir(root.path()).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("compatibility preflight"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    for suffix in ["-wal", "-shm", "-journal"] {
        assert!(!std::path::Path::new(&format!("{}{suffix}", path.display())).exists());
    }
}