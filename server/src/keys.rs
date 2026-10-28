use ed25519_dalek::SigningKey;
use libp2p::identity::Keypair;
use rand::rngs::OsRng;
use std::{fs, io, path::Path};

/// Loads the persistent controller signing key or creates it with owner-only
/// permissions. Its public key is the node's independently pinned trust anchor.
pub fn load_or_create_signing_key(path: impl AsRef<Path>) -> io::Result<SigningKey> {
    let path = path.as_ref();
    match fs::read(path) {
        Ok(bytes) => Ok(SigningKey::from_bytes(&bytes.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid signing key length")
        })?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let key = SigningKey::generate(&mut OsRng);
            write_owner_only(path, &key.to_bytes())?;
            Ok(key)
        }
        Err(error) => Err(error),
    }
}

/// Loads the controller's persistent libp2p identity for stable relay and
/// rendezvous addressing. It is separate from the server signing key.
pub fn load_or_create_libp2p(path: impl AsRef<Path>) -> io::Result<Keypair> {
    let path = path.as_ref();
    match fs::read(path) {
        Ok(bytes) => Keypair::from_protobuf_encoding(&bytes).map_err(io::Error::other),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let key = Keypair::generate_ed25519();
            write_owner_only(path, &key.to_protobuf_encoding().map_err(io::Error::other)?)?;
            Ok(key)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn write_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    io::Write::write_all(&mut file, bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)
}

#[cfg(not(unix))]
fn write_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::{load_or_create_libp2p, load_or_create_signing_key};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn signing_key_is_persisted() {
        let directory =
            std::env::temp_dir().join(format!("cat4igp-server-key-{}", std::process::id()));
        let path = directory.join("signing.key");
        let first = load_or_create_signing_key(&path).unwrap().verifying_key();
        let second = load_or_create_signing_key(&path).unwrap().verifying_key();
        assert_eq!(first, second);
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn libp2p_identity_is_persisted() {
        let directory =
            std::env::temp_dir().join(format!("cat4igp-server-p2p-{}", std::process::id()));
        let path = directory.join("identity.key");
        let first = load_or_create_libp2p(&path).unwrap().public().to_peer_id();
        assert_eq!(
            first,
            load_or_create_libp2p(&path).unwrap().public().to_peer_id()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
