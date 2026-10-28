use base64::{Engine, engine::general_purpose::STANDARD};
use libp2p::identity::Keypair;
use std::{fs, io, path::Path};

/// Loads the node's persistent libp2p identity or creates it with owner-only
/// permissions. Do not place command-decryption or WireGuard private keys here.
pub fn load_or_create_libp2p(path: impl AsRef<Path>) -> io::Result<Keypair> {
    let path = path.as_ref();
    match fs::read(path) {
        Ok(bytes) => Keypair::from_protobuf_encoding(&bytes).map_err(io::Error::other),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let key = Keypair::generate_ed25519();
            let bytes = key.to_protobuf_encoding().map_err(io::Error::other)?;
            write_owner_only(path, &bytes)?;
            Ok(key)
        }
        Err(error) => Err(error),
    }
}

/// Loads the distinct X25519 command-decryption key used for server-sealed
/// state. It is deliberately not the libp2p transport identity.
pub fn load_or_create_command_key(
    path: impl AsRef<Path>,
) -> io::Result<x25519_dalek::StaticSecret> {
    let path = path.as_ref();
    match fs::read(path) {
        Ok(bytes) => Ok(x25519_dalek::StaticSecret::from(
            <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid command key length")
            })?,
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let key = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
            write_owner_only(path, &key.to_bytes())?;
            Ok(key)
        }
        Err(error) => Err(error),
    }
}

/// Loads the distinct Curve25519 key material for WireGuard. The caller passes
/// its standard base64 public form during enrollment; route policy is external.
pub fn load_or_create_wireguard_key(path: impl AsRef<Path>) -> io::Result<[u8; 32]> {
    let path = path.as_ref();
    match fs::read(path) {
        Ok(bytes) => <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid WireGuard key length")
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut key = [0; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
            key[0] &= 248;
            key[31] &= 127;
            key[31] |= 64;
            write_owner_only(path, &key)?;
            Ok(key)
        }
        Err(error) => Err(error),
    }
}

/// Returns the standard WireGuard base64 public key for enrollment and peers.
pub fn wireguard_public_key(private_key: &[u8; 32]) -> String {
    STANDARD.encode(x25519_dalek::PublicKey::from(*private_key).as_bytes())
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
    use super::{
        load_or_create_command_key, load_or_create_libp2p, load_or_create_wireguard_key,
        wireguard_public_key,
    };
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn identity_is_persisted() {
        let directory = std::env::temp_dir().join(format!("cat4igp-key-{}", std::process::id()));
        let path = directory.join("libp2p.key");
        let first = load_or_create_libp2p(&path).unwrap().public().to_peer_id();
        let second = load_or_create_libp2p(&path).unwrap().public().to_peer_id();
        assert_eq!(first, second);
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn command_key_is_persisted_separately() {
        let directory =
            std::env::temp_dir().join(format!("cat4igp-command-key-{}", std::process::id()));
        let path = directory.join("command.key");
        let first = x25519_dalek::PublicKey::from(&load_or_create_command_key(&path).unwrap());
        let second = x25519_dalek::PublicKey::from(&load_or_create_command_key(&path).unwrap());
        assert_eq!(first, second);
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn wireguard_key_is_persisted_and_clamped() {
        let directory = std::env::temp_dir().join(format!("cat4igp-wg-key-{}", std::process::id()));
        let path = directory.join("wireguard.key");
        let first = load_or_create_wireguard_key(&path).unwrap();
        assert_eq!(first, load_or_create_wireguard_key(&path).unwrap());
        assert_eq!(first[0] & 7, 0);
        assert_eq!(first[31] & 0x80, 0);
        assert_ne!(first[31] & 0x40, 0);
        assert_eq!(wireguard_public_key(&first).len(), 44);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
