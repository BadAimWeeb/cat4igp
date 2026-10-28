use cat4igp_protocol::DesiredState;
use std::{fs, io, path::PathBuf};

#[derive(serde::Deserialize, serde::Serialize)]
struct StoredState {
    state: DesiredState,
    expires_at_unix: u64,
}

/// Stores verified desired state and its replay barrier atomically.
pub struct StateStore(PathBuf);

impl StateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    pub fn accepted_revision(&self) -> io::Result<u64> {
        check_owner_only(&self.0)?;
        match fs::read_to_string(&self.0) {
            Ok(value) => Ok(serde_json::from_str::<StoredState>(&value)
                .map_err(io::Error::other)?
                .state
                .revision),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(error),
        }
    }

    pub fn persist_state(&self, state: &DesiredState, expires_at_unix: u64) -> io::Result<()> {
        if let Some(parent) = self.0.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = self.0.with_extension("tmp");
        let value = serde_json::to_vec(&StoredState {
            state: state.clone(),
            expires_at_unix,
        })
        .map_err(io::Error::other)?;
        write_owner_only(&temporary, &value)?;
        fs::rename(temporary, &self.0)
    }

    pub fn desired_state(&self, now_unix: u64) -> io::Result<Option<DesiredState>> {
        check_owner_only(&self.0)?;
        match fs::read(&self.0) {
            Ok(value) => {
                let stored: StoredState =
                    serde_json::from_slice(&value).map_err(io::Error::other)?;
                Ok((stored.expires_at_unix >= now_unix).then_some(stored.state))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[cfg(unix)]
fn check_owner_only(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    match fs::metadata(path) {
        Ok(metadata) if metadata.permissions().mode() & 0o077 == 0 => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "persisted state must not be group/world accessible",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
fn check_owner_only(_: &std::path::Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_owner_only(path: &std::path::Path, value: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    io::Write::write_all(&mut file, value)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_owner_only(path: &std::path::Path, value: &[u8]) -> io::Result<()> {
    fs::write(path, value)
}

#[cfg(test)]
mod tests {
    use super::StateStore;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn persists_desired_state_and_revision() {
        let path = std::env::temp_dir().join(format!("cat4igp-state-{}", std::process::id()));
        let store = StateStore::new(&path);
        let state = cat4igp_protocol::DesiredState {
            node_id: cat4igp_protocol::NodeId::from_command_key(&x25519_dalek::PublicKey::from(
                [1; 32],
            )),
            revision: 7,
            wireguard: vec![],
        };
        store.persist_state(&state, 10).unwrap();
        assert_eq!(store.accepted_revision().unwrap(), 7);
        assert_eq!(store.desired_state(10).unwrap(), Some(state));
        assert_eq!(store.desired_state(11).unwrap(), None);
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_exposed_state() {
        let path =
            std::env::temp_dir().join(format!("cat4igp-exposed-state-{}", std::process::id()));
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(StateStore::new(&path).desired_state(0).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
