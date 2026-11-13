use crate::config::ServerConfig;
use cat4igp_shared::control::TopologySnapshot;
use serde::{Deserialize, Serialize};
use std::{collections::{HashMap, HashSet}, fs, io::{self, Read, Write}, path::Path};

const CACHE_FILE: &str = "topology-cache.json";
const MAX_CACHE_SIZE: u64 = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    node_id: i32,
    network_id: String,
    controller_peer_id: String,
    controller_signing_key: String,
    controller_encryption_key: String,
    client_peer_id: String,
    client_encryption_key: String,
    wireguard_public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cache {
    version: u32,
    identity: Identity,
    snapshot: TopologySnapshot,
    #[serde(deserialize_with = "deserialize_ports")]
    ports: HashMap<i32, u16>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn identity(config: &ServerConfig) -> io::Result<Identity> {
    let required = |value: &Option<String>| value.clone().filter(|s| !s.is_empty()).ok_or_else(|| invalid("missing enrolled identity"));
    let node_id = config.control_node_id.ok_or_else(|| invalid("missing enrolled node id"))?;
    if config.control_network_id.is_empty() || config.topology_revision < 0 {
        return Err(invalid("invalid enrolled network or revision"));
    }
    // Never let the key helpers generate a new identity while loading a cache.
    required(&config.control_private_key)?;
    required(&config.control_encryption_private_key)?;
    required(&config.wg_private_key)?;
    let mut copy = config.clone();
    let client_peer_id = copy.ensure_control_keypair()?.public().to_peer_id().to_string();
    let client_encryption_key = copy.ensure_control_encryption_key()?;
    copy.ensure_wireguard_keypair()?;
    Ok(Identity {
        node_id,
        network_id: config.control_network_id.clone(),
        controller_peer_id: required(&config.controller_peer_id)?,
        controller_signing_key: required(&config.controller_signing_key)?,
        controller_encryption_key: required(&config.controller_encryption_key)?,
        client_peer_id,
        client_encryption_key,
        wireguard_public_key: copy.wg_public_key.ok_or_else(|| invalid("missing WireGuard identity"))?,
    })
}

fn deserialize_ports<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<HashMap<i32, u16>, D::Error> {
    struct Ports;
    impl<'de> serde::de::Visitor<'de> for Ports {
        type Value = HashMap<i32, u16>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a map of tunnel ids to ports")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut ports = HashMap::new();
            while let Some((id, port)) = map.next_entry()? {
                if ports.insert(id, port).is_some() {
                    return Err(serde::de::Error::custom("duplicate tunnel port"));
                }
            }
            Ok(ports)
        }
    }
    deserializer.deserialize_map(Ports)
}

fn validate(cache: &Cache, identity: &Identity, minimum_revision: i64) -> io::Result<()> {
    if cache.version != 1 || &cache.identity != identity || cache.snapshot.node_id != identity.node_id
        || cache.snapshot.revision < minimum_revision || cache.snapshot.revision < 0 {
        return Err(invalid("topology cache identity or revision mismatch"));
    }
    let ids: HashSet<_> = cache.snapshot.tunnels.iter().map(|t| t.tunnel_id).collect();
    let mut used = HashSet::new();
    if cache.ports.iter().any(|(id, port)| !ids.contains(id) || *port == 0 || !used.insert(*port)) {
        return Err(invalid("invalid cached tunnel ports"));
    }
    Ok(())
}

#[cfg(unix)]
fn check_private(file: &fs::File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o7777 != 0o600 || metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 {
        return Err(invalid("cache file is not private"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(file: &fs::File) -> io::Result<()> {
    if !file.metadata()?.is_file() { return Err(invalid("cache is not a regular file")); }
    Ok(())
}

fn private_options() -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    options
}

fn read_cache(data_dir: &Path) -> io::Result<Cache> {
    let file = private_options().read(true).open(data_dir.join(CACHE_FILE))?;
    check_private(&file)?;
    let mut data = Vec::new();
    file.take(MAX_CACHE_SIZE + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_CACHE_SIZE { return Err(invalid("topology cache is too large")); }
    let cache: Cache = serde_json::from_slice(&data).map_err(|_| invalid("invalid topology cache"))?;
    let raw: serde_json::Value = serde_json::from_slice(&data).map_err(|_| invalid("invalid topology cache"))?;
    if raw.get("snapshot") != Some(&serde_json::to_value(&cache.snapshot).map_err(|_| invalid("invalid topology snapshot"))?) {
        return Err(invalid("non-canonical topology snapshot"));
    }
    Ok(cache)
}

pub(super) fn load(data_dir: &Path, config: &ServerConfig) -> io::Result<(TopologySnapshot, HashMap<i32, u16>)> {
    let identity = identity(config)?;
    let cache = read_cache(data_dir)?;
    validate(&cache, &identity, config.topology_revision)?;
    Ok((cache.snapshot, cache.ports))
}

pub(super) fn save(data_dir: &Path, config: &ServerConfig, snapshot: &TopologySnapshot, ports: &HashMap<i32, u16>) -> io::Result<()> {
    save_inner(data_dir, config, snapshot, ports, |_| Ok(()))
}

fn save_inner(data_dir: &Path, config: &ServerConfig, snapshot: &TopologySnapshot, ports: &HashMap<i32, u16>, mut fault: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
    let identity = identity(config)?;
    let cache = Cache { version: 1, identity, snapshot: snapshot.clone(), ports: ports.clone() };
    validate(&cache, &cache.identity, config.topology_revision)?;
    let content = serde_json::to_vec(&cache).map_err(|_| invalid("cannot serialize topology cache"))?;
    if content.len() as u64 > MAX_CACHE_SIZE { return Err(invalid("topology cache is too large")); }
    fs::create_dir_all(data_dir)?;
    let directory = fs::File::open(data_dir)?;
    // Serialize writers across daemon processes as well as within one daemon.
    let lock = private_options().read(true).write(true).create(true).open(data_dir.join(".topology-cache.lock"))?;
    check_private(&lock)?;
    #[cfg(unix)]
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    match read_cache(data_dir) {
        Ok(previous) if previous.identity == cache.identity => {
            validate(&previous, &cache.identity, 0)?;
            if previous.snapshot.revision == cache.snapshot.revision
                && serde_json::to_vec(&previous.snapshot).map_err(|_| invalid("invalid previous snapshot"))?
                    != serde_json::to_vec(&cache.snapshot).map_err(|_| invalid("invalid snapshot"))?
            {
                return Err(invalid("refusing different topology at the same revision"));
            }
            if previous.snapshot.revision > cache.snapshot.revision {
                return Err(invalid("refusing to replace newer topology cache"));
            }
        }
        Ok(_) => {},
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => return Err(error),
    }
    let temporary = data_dir.join(format!(".topology-cache-{:032x}.tmp", rand::random::<u128>()));
    let mut file = private_options().write(true).create_new(true).open(&temporary)?;
    let result = (|| {
        file.write_all(&content[..content.len() / 2])?;
        fault("partial_write")?;
        file.write_all(&content[content.len() / 2..])?;
        file.sync_all()?;
        fault("publish")?;
        fs::rename(&temporary, data_dir.join(CACHE_FILE))?;
        fault("parent_sync")?;
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn config() -> ServerConfig {
        let mut config = ServerConfig::new(String::new(), String::new());
        config.ensure_control_keypair().unwrap();
        config.ensure_control_encryption_key().unwrap();
        config.ensure_wireguard_keypair().unwrap();
        config.control_node_id = Some(7);
        config.controller_peer_id = Some("controller".into());
        config.controller_signing_key = Some("signing".into());
        config.controller_encryption_key = Some("encryption".into());
        config.topology_revision = 3;
        config
    }

    fn snapshot(revision: i64) -> TopologySnapshot {
        TopologySnapshot { node_id: 7, revision, tunnels: vec![], l2tp_tunnels: vec![], l2tp_v2_tunnels: vec![], l2tp_availability: None }
    }

    #[test]
    fn round_trip_and_revision_floor() {
        let dir = TempDir::new().unwrap();
        let mut config = config();
        let ports = HashMap::new();
        save(dir.path(), &config, &snapshot(4), &ports).unwrap();
        let (loaded, loaded_ports) = load(dir.path(), &config).unwrap();
        assert_eq!(loaded.revision, 4);
        assert_eq!(loaded_ports, ports);
        assert!(save(dir.path(), &config, &snapshot(3), &ports).is_err());
        config.topology_revision = 5;
        assert!(load(dir.path(), &config).is_err());
        config.topology_revision = 4;
        assert_eq!(load(dir.path(), &config).unwrap().0.revision, 4);
    }

    #[test]
    fn ports_round_trip_and_equal_revision_cannot_change_topology() {
        let dir = TempDir::new().unwrap();
        let config = config();
        let mut snapshot = snapshot(3);
        snapshot.tunnels.push(serde_json::from_value(serde_json::json!({
            "tunnel_id": 10, "peer_node_id": 2, "public_key": "key", "preferred_port": 41000,
            "remote_endpoint": null, "local_answered": "Answered", "remote_response": "Answered",
            "mtu": 1420, "endpoint_ipv6": false, "fec": false, "faketcp": false,
            "created_at": 0, "updated_at": 0
        })).unwrap());
        let ports = HashMap::from([(10, 41001)]);
        save(dir.path(), &config, &snapshot, &ports).unwrap();
        assert_eq!(load(dir.path(), &config).unwrap().1, ports);
        let updated_ports = HashMap::from([(10, 41002)]);
        save(dir.path(), &config, &snapshot, &updated_ports).unwrap();
        assert_eq!(load(dir.path(), &config).unwrap().1, updated_ports);
        snapshot.tunnels[0].mtu = 1300;
        assert!(save(dir.path(), &config, &snapshot, &ports).is_err());
        assert_eq!(load(dir.path(), &config).unwrap().0.tunnels[0].mtu, 1420);
    }

    #[test]
    fn identity_and_network_must_match() {
        let dir = TempDir::new().unwrap();
        let original = config();
        save(dir.path(), &original, &snapshot(3), &HashMap::new()).unwrap();
        let mut changed = original.clone();
        changed.control_node_id = Some(8);
        assert!(load(dir.path(), &changed).is_err());
        changed = original.clone(); changed.control_network_id = "other".into();
        assert!(load(dir.path(), &changed).is_err());
        changed = original.clone(); changed.control_private_key = None;
        assert!(load(dir.path(), &changed).is_err());
        changed = original.clone(); changed.ensure_control_keypair().unwrap();
        changed.control_private_key = config().control_private_key;
        assert!(load(dir.path(), &changed).is_err());
        changed = original; changed.controller_signing_key = Some("other".into());
        assert!(load(dir.path(), &changed).is_err());
    }

    #[test]
    fn corrupt_and_invalid_cache_rejected() {
        let dir = TempDir::new().unwrap();
        let config = config();
        let path = dir.path().join(CACHE_FILE);
        save(dir.path(), &config, &snapshot(3), &HashMap::new()).unwrap();
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, b"{").unwrap();
        assert!(load(dir.path(), &config).is_err());
        fs::write(&path, &bytes).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["snapshot"]["node_id"] = 8.into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(load(dir.path(), &config).is_err());
        assert!(save(dir.path(), &config, &snapshot(3), &HashMap::from([(1, 0)])).is_err());
    }

    #[test]
    fn interrupted_publication_is_atomic() {
        let dir = TempDir::new().unwrap();
        let config = config();
        let ports = HashMap::new();
        save(dir.path(), &config, &snapshot(3), &ports).unwrap();
        for stage in ["partial_write", "publish"] {
            assert!(save_inner(dir.path(), &config, &snapshot(4), &ports, |at| if at == stage { Err(io::Error::other("injected")) } else { Ok(()) }).is_err());
            assert_eq!(load(dir.path(), &config).unwrap().0.revision, 3);
        }
        assert!(save_inner(dir.path(), &config, &snapshot(4), &ports, |at| if at == "parent_sync" { Err(io::Error::other("injected")) } else { Ok(()) }).is_err());
        assert_eq!(load(dir.path(), &config).unwrap().0.revision, 4);
    }

    #[cfg(unix)]
    #[test]
    fn cache_is_private_and_symlinks_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = TempDir::new().unwrap();
        let config = config();
        let path = dir.path().join(CACHE_FILE);
        save(dir.path(), &config, &snapshot(3), &HashMap::new()).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(dir.path(), &config).is_err());
        fs::remove_file(&path).unwrap();
        symlink("elsewhere", &path).unwrap();
        assert!(load(dir.path(), &config).is_err());
        assert!(save(dir.path(), &config, &snapshot(3), &HashMap::new()).is_err());
    }
}
