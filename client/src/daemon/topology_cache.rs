use crate::config::ServerConfig;
use cat4igp_shared::control::TopologySnapshot;
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use std::{collections::{HashMap, HashSet}, fs, io::{self, Read, Write}, path::Path};

const CACHE_FILE: &str = "topology-cache.json";
const JOURNAL_FILE: &str = "topology-revision.json";
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    identity: Identity,
    revision: i64,
    snapshot_hash: Option<String>,
    #[serde(default, deserialize_with = "deserialize_journal_ports", skip_serializing_if = "Option::is_none")]
    ports: Option<HashMap<i32, u16>>,
}

fn snapshot_hash(snapshot: &TopologySnapshot) -> io::Result<String> {
    let bytes = serde_json::to_vec(snapshot).map_err(|_| invalid("cannot serialize topology snapshot"))?;
    Ok(Blake2s256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect())
}

fn verify_journal(journal: &Journal, identity: &Identity, minimum_revision: i64) -> io::Result<()> {
    let mut used = HashSet::new();
    if !matches!((journal.version, &journal.ports), (1, None) | (2, Some(_)))
        || &journal.identity != identity || journal.revision < minimum_revision || journal.revision < 0
        || journal.ports.as_ref().is_some_and(|ports| ports.values().any(|port| *port == 0 || !used.insert(*port))
            || (journal.snapshot_hash.is_none() && !ports.is_empty()))
        || journal.snapshot_hash.as_ref().is_some_and(|hash|
            hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))) {
        return Err(invalid("revision journal identity or revision mismatch"));
    }
    Ok(())
}

fn check_snapshot(journal: &Journal, snapshot: &TopologySnapshot) -> io::Result<()> {
    if snapshot.revision < journal.revision {
        return Err(invalid("topology violates revision journal"));
    }
    if snapshot.revision == journal.revision {
        if journal.ports.as_ref().is_some_and(|ports|
            ports.keys().any(|id| !snapshot.tunnels.iter().any(|tunnel| tunnel.tunnel_id == *id))) {
            return Err(invalid("invalid journal tunnel ports"));
        }
        if let Some(hash) = &journal.snapshot_hash {
            if &snapshot_hash(snapshot)? != hash { return Err(invalid("topology violates revision journal")); }
        }
    }
    Ok(())
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

fn deserialize_journal_ports<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<HashMap<i32, u16>>, D::Error> {
    deserialize_ports(deserializer).map(Some)
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

fn read_journal(data_dir: &Path) -> io::Result<Journal> {
    let file = private_options().read(true).open(data_dir.join(JOURNAL_FILE))?;
    check_private(&file)?;
    let mut data = Vec::new();
    file.take(MAX_CACHE_SIZE + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_CACHE_SIZE { return Err(invalid("revision journal is too large")); }
    serde_json::from_slice(&data).map_err(|_| invalid("invalid revision journal"))
}

fn lock(data_dir: &Path) -> io::Result<fs::File> {
    let lock = private_options().read(true).write(true).create(true).open(data_dir.join(".topology-cache.lock"))?;
    check_private(&lock)?;
    #[cfg(unix)]
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(lock)
}

fn publish_journal(data_dir: &Path, directory: &fs::File, journal: &Journal, fault: &mut impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
    let content = serde_json::to_vec(journal).map_err(|_| invalid("cannot serialize revision journal"))?;
    if content.len() as u64 > MAX_CACHE_SIZE { return Err(invalid("revision journal is too large")); }
    let temporary = data_dir.join(format!(".topology-revision-{:032x}.tmp", rand::random::<u128>()));
    let mut file = private_options().write(true).create_new(true).open(&temporary)?;
    let result = (|| {
        file.write_all(&content)?;
        file.sync_all()?;
        fault("journal_publish")?;
        fs::rename(&temporary, data_dir.join(JOURNAL_FILE))?;
        fault("journal_parent_sync")?;
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    result
}

pub(super) fn initialize_journal(data_dir: &Path, config: &ServerConfig) -> io::Result<()> {
    let identity = identity(config)?;
    fs::create_dir_all(data_dir)?;
    let directory = fs::File::open(data_dir)?;
    let _lock = lock(data_dir)?;
    match read_journal(data_dir) {
        Ok(journal) => {
            verify_journal(&journal, &identity, config.topology_revision)?;
            directory.sync_all()
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if config.revision_journal {
                return Err(invalid("required revision journal missing"));
            }
            match read_cache(data_dir) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                Ok(_) => return Err(invalid("cannot initialize revision journal with an existing cache")),
                Err(error) => return Err(error),
            }
            publish_journal(data_dir, &directory, &Journal { version: 2, identity, revision: config.topology_revision, snapshot_hash: None, ports: Some(HashMap::new()) }, &mut |_| Ok(()))
        }
        Err(error) => Err(error),
    }
}

fn read_cache_data(data_dir: &Path) -> io::Result<Vec<u8>> {
    let file = private_options().read(true).open(data_dir.join(CACHE_FILE))?;
    check_private(&file)?;
    let mut data = Vec::new();
    file.take(MAX_CACHE_SIZE + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_CACHE_SIZE { return Err(invalid("topology cache is too large")); }
    Ok(data)
}

fn decode_cache(data: &[u8]) -> io::Result<Cache> {
    let cache: Cache = serde_json::from_slice(data).map_err(|_| invalid("invalid topology cache"))?;
    let raw: serde_json::Value = serde_json::from_slice(data).map_err(|_| invalid("invalid topology cache"))?;
    if raw.get("snapshot") != Some(&serde_json::to_value(&cache.snapshot).map_err(|_| invalid("invalid topology snapshot"))?) {
        return Err(invalid("non-canonical topology snapshot"));
    }
    Ok(cache)
}

fn read_cache(data_dir: &Path) -> io::Result<Cache> {
    decode_cache(&read_cache_data(data_dir)?)
}

pub(super) fn load(data_dir: &Path, config: &ServerConfig) -> io::Result<(TopologySnapshot, HashMap<i32, u16>)> {
    let identity = identity(config)?;
    let _lock = lock(data_dir)?;
    let journal = match read_journal(data_dir) {
        Ok(journal) => { verify_journal(&journal, &identity, config.topology_revision)?; Some(journal) }
        Err(error) if error.kind() == io::ErrorKind::NotFound && !config.revision_journal => None,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(invalid("required revision journal missing")),
        Err(error) => return Err(error),
    };
    let cache = read_cache(data_dir)?;
    validate(&cache, &identity, config.topology_revision)?;
    if let Some(journal) = journal {
        check_snapshot(&journal, &cache.snapshot)?;
        if cache.snapshot.revision != journal.revision || journal.snapshot_hash.is_none() {
            return Err(invalid("topology cache does not match revision journal"));
        }
        if journal.ports.as_ref().is_some_and(|ports| ports != &cache.ports) {
            return Err(invalid("topology cache ports do not match revision journal"));
        }
    }
    Ok((cache.snapshot, cache.ports))
}

// Only the journal survives a damaged cache. Legacy journals have no independent
// reservations; never infer local ports from the controller's preferred ports.
pub(super) fn load_reservations(data_dir: &Path, config: &ServerConfig, snapshot: &TopologySnapshot) -> io::Result<HashMap<i32, u16>> {
    let identity = identity(config)?;
    let _lock = lock(data_dir)?;
    let journal = match read_journal(data_dir) {
        Ok(journal) => journal,
        Err(error) if error.kind() == io::ErrorKind::NotFound && !config.revision_journal => return Ok(HashMap::new()),
        Err(error) => return Err(error),
    };
    verify_journal(&journal, &identity, config.topology_revision)?;
    check_snapshot(&journal, snapshot)?;
    if snapshot.node_id != identity.node_id { return Err(invalid("topology snapshot identity mismatch")); }
    let mut ports = journal.ports.unwrap_or_default();
    ports.retain(|id, _| snapshot.tunnels.iter().any(|tunnel| tunnel.tunnel_id == *id));
    Ok(ports)
}

// Callers must authenticate the incoming snapshot before saving. The local journal
// can prove recovery from cache damage, not a coordinated rollback of the state directory.
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
    let _lock = lock(data_dir)?;
    let journal = match read_journal(data_dir) {
        Ok(journal) => {
            verify_journal(&journal, &cache.identity, config.topology_revision)?;
            check_snapshot(&journal, snapshot)?;
            Some(journal)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && !config.revision_journal => None,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(invalid("required revision journal missing")),
        Err(error) => return Err(error),
    };
    let (previous, damaged) = match read_cache_data(data_dir) {
        Ok(data) => match decode_cache(&data) {
            Ok(previous) => (Some(previous), None),
            // check_snapshot already verified the exact hash; damaged state cannot advance it.
            // ponytail: recovery needs Unix flock; add an equivalent lock for other platforms.
            Err(_) if cfg!(unix) && journal.as_ref().is_some_and(|journal|
                journal.revision == snapshot.revision && journal.snapshot_hash.is_some()) => (None, Some(data)),
            Err(error) => return Err(error),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => (None, None),
        Err(error) => return Err(error),
    };
    match &previous {
        Some(previous) if previous.identity == cache.identity => {
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
        Some(_) => return Err(invalid("topology cache identity mismatch")),
        None => {},
    }
    if let Some(journal) = &journal {
        if let Some(reservations) = &journal.ports {
            let committed = previous.as_ref().is_some_and(|previous|
                previous.snapshot.revision == journal.revision && previous.ports == *reservations
                    && check_snapshot(journal, &previous.snapshot).is_ok());
            if !committed && reservations.iter().any(|(id, port)|
                snapshot.tunnels.iter().any(|tunnel| tunnel.tunnel_id == *id) && cache.ports.get(id) != Some(port)) {
                return Err(invalid("refusing to lose journal tunnel ports during recovery"));
            }
        }
    }
    if let Some(journal) = journal {
        if journal.revision != snapshot.revision || journal.snapshot_hash.is_none() || journal.ports.as_ref() != Some(&cache.ports) {
            let next = Journal { version: 2, identity: cache.identity, revision: snapshot.revision, snapshot_hash: Some(snapshot_hash(snapshot)?), ports: Some(cache.ports) };
            publish_journal(data_dir, &directory, &next, &mut fault)?;
        } else {
            // Repeat a possibly failed directory barrier before publishing the cache.
            directory.sync_all()?;
        }
    }
    if let Some(damaged) = damaged {
        // Keep the original in place until a private, non-overwriting diagnostic
        // copy is durable. A crash after cache replacement must retain that copy.
        let diagnostic = data_dir.join(format!("topology-cache-corrupt-{:032x}.json", rand::random::<u128>()));
        let mut file = private_options().write(true).create_new(true).open(&diagnostic)?;
        let written = (|| {
            file.write_all(&damaged[..damaged.len() / 2])?;
            fault("quarantine_partial_write")?;
            file.write_all(&damaged[damaged.len() / 2..])
        })();
        if let Err(error) = written {
            drop(file);
            let _ = fs::remove_file(&diagnostic);
            return Err(error);
        }
        fault("quarantine_sync")?;
        file.sync_all()?;
        fault("quarantine_parent_sync")?;
        directory.sync_all()?;
        fault("quarantine_durable")?;
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

    fn port_snapshot(revision: i64) -> TopologySnapshot {
        let mut snapshot = snapshot(revision);
        snapshot.tunnels.push(serde_json::from_value(serde_json::json!({
            "tunnel_id": 10, "peer_node_id": 2, "public_key": "key", "preferred_port": 41000,
            "remote_endpoint": null, "local_answered": "Answered", "remote_response": "Answered",
            "mtu": 1420, "endpoint_ipv6": false, "fec": false, "faketcp": false,
            "created_at": 0, "updated_at": 0
        })).unwrap());
        snapshot
    }

    #[cfg(unix)]
    #[test]
    fn damaged_cache_preserves_journal_ports_and_rejects_recovery_conflicts() {
        for missing in [false, true] {
            let dir = TempDir::new().unwrap();
            let mut config = config();
            initialize_journal(dir.path(), &config).unwrap();
            config.revision_journal = true;
            let incoming = port_snapshot(4);
            let ports = HashMap::from([(10, 41001)]);
            save(dir.path(), &config, &incoming, &ports).unwrap();
            let journal = fs::read(dir.path().join(JOURNAL_FILE)).unwrap();
            if missing { fs::remove_file(dir.path().join(CACHE_FILE)).unwrap(); }
            else { fs::write(dir.path().join(CACHE_FILE), b"damaged").unwrap(); }
            assert_eq!(load_reservations(dir.path(), &config, &incoming).unwrap(), ports);
            for conflicting in [HashMap::new(), HashMap::from([(10, 41002)])] {
                assert!(save(dir.path(), &config, &incoming, &conflicting).is_err());
                assert_eq!(fs::read(dir.path().join(JOURNAL_FILE)).unwrap(), journal);
                assert!(diagnostics(dir.path()).is_empty());
            }
            save(dir.path(), &config, &incoming, &ports).unwrap();
            assert_eq!(load(dir.path(), &config).unwrap().1, ports);
            assert_eq!(fs::read(dir.path().join(JOURNAL_FILE)).unwrap(), journal);
            assert_eq!(diagnostics(dir.path()).len(), usize::from(!missing));
        }
    }

    #[test]
    fn parseable_cache_without_journal_proof_cannot_release_reservations() {
        let dir = TempDir::new().unwrap();
        let mut config = config();
        initialize_journal(dir.path(), &config).unwrap();
        config.revision_journal = true;
        let ports = HashMap::from([(10, 41001)]);
        save(dir.path(), &config, &port_snapshot(4), &ports).unwrap();
        let path = dir.path().join(CACHE_FILE);
        let mut previous = read_cache(dir.path()).unwrap();
        previous.snapshot.tunnels[0].mtu = 1300;
        let bytes = serde_json::to_vec(&previous).unwrap();
        fs::write(&path, &bytes).unwrap();
        let journal = fs::read(dir.path().join(JOURNAL_FILE)).unwrap();
        assert!(load(dir.path(), &config).is_err());
        let incoming = port_snapshot(5);
        assert_eq!(load_reservations(dir.path(), &config, &incoming).unwrap(), ports);
        for conflicting in [HashMap::new(), HashMap::from([(10, 41002)])] {
            assert!(save(dir.path(), &config, &incoming, &conflicting).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(fs::read(dir.path().join(JOURNAL_FILE)).unwrap(), journal);
            assert!(diagnostics(dir.path()).is_empty());
        }
        save(dir.path(), &config, &incoming, &ports).unwrap();
        assert_eq!(load(dir.path(), &config).unwrap().1, ports);
    }

    #[cfg(unix)]
    #[test]
    fn port_journal_publication_is_crash_consistent_at_equal_and_new_revisions() {
        for revision in [3, 4] {
            for stage in ["journal_publish", "journal_parent_sync", "partial_write", "publish", "parent_sync"] {
                let dir = TempDir::new().unwrap();
                let mut config = config();
                initialize_journal(dir.path(), &config).unwrap();
                config.revision_journal = true;
                let old_ports = HashMap::from([(10, 41001)]);
                let new_ports = HashMap::from([(10, 41002)]);
                save(dir.path(), &config, &port_snapshot(3), &old_ports).unwrap();
                let incoming = port_snapshot(revision);
                let mut reached = false;
                assert!(save_inner(dir.path(), &config, &incoming, &new_ports, |at| {
                    if at == stage { reached = true; Err(io::Error::other("injected")) } else { Ok(()) }
                }).is_err(), "{revision}/{stage}");
                assert!(reached, "{revision}/{stage}");
                let expected = if stage == "journal_publish" { &old_ports } else { &new_ports };
                assert_eq!(&load_reservations(dir.path(), &config, &incoming).unwrap(), expected, "{revision}/{stage}");
                if stage == "journal_publish" {
                    assert_eq!(load(dir.path(), &config).unwrap().1, old_ports);
                } else if stage == "parent_sync" {
                    assert_eq!(load(dir.path(), &config).unwrap().1, new_ports);
                } else {
                    assert!(load(dir.path(), &config).is_err());
                    assert!(save(dir.path(), &config, &incoming, &old_ports).is_err());
                }
                fs::write(dir.path().join(CACHE_FILE), b"damaged").unwrap();
                let recovery = port_snapshot(if stage == "journal_publish" { 3 } else { revision });
                save(dir.path(), &config, &recovery, expected).unwrap();
                assert_eq!(&load(dir.path(), &config).unwrap().1, expected);
                assert!(save(dir.path(), &config, &port_snapshot(2), expected).is_err());
            }
        }
    }

    #[test]
    fn legacy_journals_load_and_upgrade_without_inventing_reservations() {
        let dir = TempDir::new().unwrap();
        let mut config = config();
        initialize_journal(dir.path(), &config).unwrap();
        config.revision_journal = true;
        let incoming = port_snapshot(4);
        let ports = HashMap::from([(10, 41001)]);
        save(dir.path(), &config, &incoming, &ports).unwrap();
        let journal_path = dir.path().join(JOURNAL_FILE);
        let mut journal: serde_json::Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
        journal["version"] = 1.into();
        journal.as_object_mut().unwrap().remove("ports");
        let legacy = serde_json::to_vec(&journal).unwrap();
        fs::write(&journal_path, &legacy).unwrap();
        assert_eq!(load(dir.path(), &config).unwrap().1, ports);
        assert!(load_reservations(dir.path(), &config, &incoming).unwrap().is_empty());
        initialize_journal(dir.path(), &config).unwrap();
        assert_eq!(fs::read(&journal_path).unwrap(), legacy);
        save(dir.path(), &config, &incoming, &ports).unwrap();
        assert_eq!(read_journal(dir.path()).unwrap().version, 2);
        assert_eq!(load_reservations(dir.path(), &config, &incoming).unwrap(), ports);
        assert_eq!(load(dir.path(), &config).unwrap().1, ports);
        fs::write(&journal_path, legacy).unwrap();
        fs::write(dir.path().join(CACHE_FILE), b"damaged").unwrap();
        assert!(load_reservations(dir.path(), &config, &incoming).unwrap().is_empty());
    }

    #[test]
    fn invalid_journal_ports_never_recover_a_damaged_cache() {
        for case in ["missing", "null", "duplicate_id", "duplicate_port", "zero", "overflow", "unknown_tunnel", "legacy_ports", "hashless"] {
            let dir = TempDir::new().unwrap();
            let mut config = config();
            initialize_journal(dir.path(), &config).unwrap();
            config.revision_journal = true;
            let incoming = port_snapshot(4);
            let ports = HashMap::from([(10, 41001)]);
            save(dir.path(), &config, &incoming, &ports).unwrap();
            let path = dir.path().join(JOURNAL_FILE);
            let original = fs::read(&path).unwrap();
            let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
            match case {
                "missing" => { value.as_object_mut().unwrap().remove("ports"); }
                "null" => value["ports"] = serde_json::Value::Null,
                "duplicate_id" => {},
                "duplicate_port" => value["ports"] = serde_json::json!({ "10": 41001, "11": 41001 }),
                "zero" => value["ports"] = serde_json::json!({ "10": 0 }),
                "overflow" => value["ports"] = serde_json::json!({ "10": 65536 }),
                "unknown_tunnel" => value["ports"] = serde_json::json!({ "11": 41001 }),
                "legacy_ports" => value["version"] = 1.into(),
                "hashless" => value["snapshot_hash"] = serde_json::Value::Null,
                _ => unreachable!(),
            }
            let bytes = if case == "duplicate_id" {
                String::from_utf8(original).unwrap().replace("\"ports\":{\"10\":41001}", "\"ports\":{\"10\":41001,\"10\":41002}").into_bytes()
            } else { serde_json::to_vec(&value).unwrap() };
            fs::write(&path, &bytes).unwrap();
            fs::write(dir.path().join(CACHE_FILE), b"damaged").unwrap();
            assert!(load_reservations(dir.path(), &config, &incoming).is_err(), "{case}");
            assert!(save(dir.path(), &config, &incoming, &ports).is_err(), "{case}");
            assert_eq!(fs::read(&path).unwrap(), bytes, "{case}");
            assert_eq!(fs::read(dir.path().join(CACHE_FILE)).unwrap(), b"damaged", "{case}");
            assert!(diagnostics(dir.path()).is_empty(), "{case}");
        }
    }

    fn diagnostics(data_dir: &Path) -> Vec<std::path::PathBuf> {
        let mut paths: Vec<_> = fs::read_dir(data_dir).unwrap().map(|entry| entry.unwrap().path())
            .filter(|path| path.file_name().unwrap().to_str().unwrap().starts_with("topology-cache-corrupt-"))
            .collect();
        paths.sort();
        paths
    }

    #[cfg(unix)]
    #[test]
    fn damaged_cache_recovers_only_the_journal_snapshot_and_preserves_diagnostics() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = TempDir::new().unwrap();
        let mut config = config();
        initialize_journal(dir.path(), &config).unwrap();
        config.revision_journal = true;
        let incoming = snapshot(4);
        save(dir.path(), &config, &incoming, &HashMap::new()).unwrap();
        let journal = fs::read(dir.path().join(JOURNAL_FILE)).unwrap();
        let damaged = b"{\"version\":1,\"snapshot\":";
        fs::write(dir.path().join(CACHE_FILE), damaged).unwrap();
        assert!(load(dir.path(), &config).is_err());
        assert!(diagnostics(dir.path()).is_empty());

        save(dir.path(), &config, &incoming, &HashMap::new()).unwrap();
        let (recovered, ports) = load(dir.path(), &config).unwrap();
        assert_eq!(snapshot_hash(&recovered).unwrap(), snapshot_hash(&incoming).unwrap());
        assert!(ports.is_empty());
        assert_eq!(fs::read(dir.path().join(JOURNAL_FILE)).unwrap(), journal);
        let preserved = diagnostics(dir.path());
        assert_eq!(preserved.len(), 1);
        assert_eq!(fs::read(&preserved[0]).unwrap(), damaged);
        let metadata = fs::metadata(&preserved[0]).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });

        save(dir.path(), &config, &incoming, &HashMap::new()).unwrap();
        assert_eq!(diagnostics(dir.path()), preserved);
        let mut changed = snapshot(4);
        changed.l2tp_availability = Some(cat4igp_shared::control::L2tpAvailability { v2: true, v3: false });
        assert!(save(dir.path(), &config, &changed, &HashMap::new()).is_err());
        assert!(save(dir.path(), &config, &snapshot(3), &HashMap::new()).is_err());
        save(dir.path(), &config, &snapshot(5), &HashMap::new()).unwrap();
        assert!(save(dir.path(), &config, &incoming, &HashMap::new()).is_err());
        assert_eq!(load(dir.path(), &config).unwrap().0.revision, 5);
        assert_eq!(fs::read(&preserved[0]).unwrap(), damaged);
    }

    #[test]
    fn damaged_cache_without_unambiguous_journal_proof_is_untouched() {
        for case in ["legacy", "missing", "hashless", "broken", "identity", "version", "negative",
            "hash_format", "hash_mismatch", "floor", "older", "newer", "different", "node", "ports"] {
            let dir = TempDir::new().unwrap();
            let mut config = config();
            initialize_journal(dir.path(), &config).unwrap();
            config.revision_journal = true;
            save(dir.path(), &config, &snapshot(4), &HashMap::new()).unwrap();
            let journal_path = dir.path().join(JOURNAL_FILE);
            let mut journal: serde_json::Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
            let mut incoming = snapshot(4);
            let mut ports = HashMap::new();
            match case {
                "legacy" => { config.revision_journal = false; fs::remove_file(&journal_path).unwrap(); }
                "missing" => fs::remove_file(&journal_path).unwrap(),
                "broken" => fs::write(&journal_path, b"broken").unwrap(),
                "floor" => config.topology_revision = 5,
                "older" => incoming.revision = 3,
                "newer" => incoming.revision = 5,
                "different" => incoming.l2tp_availability = Some(cat4igp_shared::control::L2tpAvailability { v2: true, v3: false }),
                "node" => incoming.node_id = 8,
                "ports" => { ports.insert(1, 41000); }
                _ => {
                    match case {
                        "hashless" => journal["snapshot_hash"] = serde_json::Value::Null,
                        "identity" => journal["identity"]["controller_signing_key"] = "other".into(),
                        "version" => journal["version"] = 3.into(),
                        "negative" => journal["revision"] = (-1).into(),
                        "hash_format" => journal["snapshot_hash"] = "not-a-hash".into(),
                        "hash_mismatch" => journal["snapshot_hash"] = "0".repeat(64).into(),
                        _ => unreachable!(),
                    }
                    fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
                }
            }
            let expected_journal = fs::read(&journal_path).ok();
            fs::write(dir.path().join(CACHE_FILE), b"damaged").unwrap();
            assert!(save(dir.path(), &config, &incoming, &ports).is_err(), "{case}");
            assert_eq!(fs::read(dir.path().join(CACHE_FILE)).unwrap(), b"damaged", "{case}");
            assert_eq!(fs::read(&journal_path).ok(), expected_journal, "{case}");
            assert!(diagnostics(dir.path()).is_empty(), "{case}");
            assert!(load(dir.path(), &config).is_err(), "{case}");
        }
    }

    #[test]
    fn parseable_cache_conflicts_are_not_recovered() {
        for case in ["identity", "version", "node", "negative", "ports", "newer", "different"] {
            let dir = TempDir::new().unwrap();
            let mut config = config();
            initialize_journal(dir.path(), &config).unwrap();
            config.revision_journal = true;
            save(dir.path(), &config, &snapshot(4), &HashMap::new()).unwrap();
            let path = dir.path().join(CACHE_FILE);
            let journal = fs::read(dir.path().join(JOURNAL_FILE)).unwrap();
            let mut previous: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            match case {
                "identity" => previous["identity"]["controller_signing_key"] = "other".into(),
                "version" => previous["version"] = 2.into(),
                "node" => previous["snapshot"]["node_id"] = 8.into(),
                "negative" => previous["snapshot"]["revision"] = (-1).into(),
                "ports" => previous["ports"] = serde_json::json!({ "1": 41000 }),
                "newer" => previous["snapshot"]["revision"] = 5.into(),
                "different" => previous["snapshot"]["l2tp_availability"] = serde_json::json!({ "v2": true, "v3": false }),
                _ => unreachable!(),
            }
            let bytes = serde_json::to_vec(&previous).unwrap();
            fs::write(&path, &bytes).unwrap();
            assert!(save(dir.path(), &config, &snapshot(4), &HashMap::new()).is_err(), "{case}");
            assert_eq!(fs::read(&path).unwrap(), bytes, "{case}");
            assert_eq!(fs::read(dir.path().join(JOURNAL_FILE)).unwrap(), journal, "{case}");
            assert!(diagnostics(dir.path()).is_empty(), "{case}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn recovery_interruptions_preserve_evidence_and_are_retryable_under_lock() {
        for stage in ["quarantine_sync", "quarantine_parent_sync", "quarantine_durable", "partial_write", "publish", "parent_sync"] {
            let dir = TempDir::new().unwrap();
            let mut config = config();
            initialize_journal(dir.path(), &config).unwrap();
            config.revision_journal = true;
            save(dir.path(), &config, &snapshot(4), &HashMap::new()).unwrap();
            let journal = fs::read(dir.path().join(JOURNAL_FILE)).unwrap();
            fs::write(dir.path().join(CACHE_FILE), b"damaged").unwrap();
            let mut reached = false;
            assert!(save_inner(dir.path(), &config, &snapshot(4), &HashMap::new(), |at| {
                let competing = private_options().read(true).write(true).open(dir.path().join(".topology-cache.lock"))?;
                assert_eq!(unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&competing), libc::LOCK_EX | libc::LOCK_NB) }, -1);
                assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
                if at == stage { reached = true; Err(io::Error::other("injected")) } else { Ok(()) }
            }).is_err(), "{stage}");
            assert!(reached, "{stage}");
            let preserved = diagnostics(dir.path());
            assert_eq!(preserved.len(), 1, "{stage}");
            assert_eq!(fs::read(&preserved[0]).unwrap(), b"damaged", "{stage}");
            assert_eq!(fs::read(dir.path().join(JOURNAL_FILE)).unwrap(), journal, "{stage}");
            if stage == "parent_sync" {
                assert_eq!(load(dir.path(), &config).unwrap().0.revision, 4);
            } else {
                assert_eq!(fs::read(dir.path().join(CACHE_FILE)).unwrap(), b"damaged", "{stage}");
                assert!(load(dir.path(), &config).is_err(), "{stage}");
            }
            save(dir.path(), &config, &snapshot(4), &HashMap::new()).unwrap();
            assert_eq!(load(dir.path(), &config).unwrap().0.revision, 4, "{stage}");
            assert_eq!(fs::read(dir.path().join(JOURNAL_FILE)).unwrap(), journal, "{stage}");
            for path in diagnostics(dir.path()) { assert_eq!(fs::read(path).unwrap(), b"damaged", "{stage}"); }
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_diagnostic_write_does_not_accumulate_partial_evidence() {
        let dir = TempDir::new().unwrap();
        let mut config = config();
        initialize_journal(dir.path(), &config).unwrap();
        config.revision_journal = true;
        save(dir.path(), &config, &snapshot(4), &HashMap::new()).unwrap();
        let journal = fs::read(dir.path().join(JOURNAL_FILE)).unwrap();
        fs::write(dir.path().join(CACHE_FILE), b"damaged").unwrap();
        for _ in 0..2 {
            let error = save_inner(dir.path(), &config, &snapshot(4), &HashMap::new(), |stage| {
                if stage == "quarantine_partial_write" {
                    let paths = diagnostics(dir.path());
                    assert_eq!(paths.len(), 1);
                    assert_eq!(fs::read(&paths[0])?, b"dam");
                    Err(io::Error::other("diagnostic write failed"))
                } else { Ok(()) }
            }).unwrap_err();
            assert_eq!(error.to_string(), "diagnostic write failed");
            assert!(diagnostics(dir.path()).is_empty());
            assert_eq!(fs::read(dir.path().join(CACHE_FILE)).unwrap(), b"damaged");
            assert_eq!(fs::read(dir.path().join(JOURNAL_FILE)).unwrap(), journal);
        }
        save(dir.path(), &config, &snapshot(4), &HashMap::new()).unwrap();
        assert_eq!(load(dir.path(), &config).unwrap().0.revision, 4);
        let paths = diagnostics(dir.path());
        assert_eq!(paths.len(), 1);
        assert_eq!(fs::read(&paths[0]).unwrap(), b"damaged");
    }

    #[cfg(unix)]
    #[test]
    fn journal_proof_does_not_bypass_cache_file_safety() {
        use std::os::unix::{ffi::OsStrExt, fs::{symlink, PermissionsExt}};
        for case in ["permissions", "symlink", "hardlink", "directory", "fifo", "oversized"] {
            let dir = TempDir::new().unwrap();
            let mut config = config();
            initialize_journal(dir.path(), &config).unwrap();
            config.revision_journal = true;
            save(dir.path(), &config, &snapshot(4), &HashMap::new()).unwrap();
            let path = dir.path().join(CACHE_FILE);
            let journal = fs::read(dir.path().join(JOURNAL_FILE)).unwrap();
            fs::write(&path, b"damaged").unwrap();
            let target = dir.path().join("target");
            match case {
                "permissions" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "symlink" => {
                    fs::rename(&path, &target).unwrap();
                    symlink(&target, &path).unwrap();
                }
                "hardlink" => fs::hard_link(&path, &target).unwrap(),
                "directory" => { fs::remove_file(&path).unwrap(); fs::create_dir(&path).unwrap(); }
                "fifo" => {
                    fs::remove_file(&path).unwrap();
                    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                "oversized" => fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(MAX_CACHE_SIZE + 1).unwrap(),
                _ => unreachable!(),
            }
            let before = fs::symlink_metadata(&path).unwrap();
            assert!(save(dir.path(), &config, &snapshot(4), &HashMap::new()).is_err(), "{case}");
            assert!(load(dir.path(), &config).is_err(), "{case}");
            assert!(diagnostics(dir.path()).is_empty(), "{case}");
            assert_eq!(fs::read(dir.path().join(JOURNAL_FILE)).unwrap(), journal, "{case}");
            let after = fs::symlink_metadata(&path).unwrap();
            assert_eq!(after.file_type(), before.file_type(), "{case}");
            assert_eq!(after.len(), before.len(), "{case}");
            if target.exists() { assert_eq!(fs::read(&target).unwrap(), b"damaged", "{case}"); }
        }
    }

    #[cfg(unix)]
    #[test]
    fn recovery_repeats_an_interrupted_journal_directory_barrier() {
        let dir = TempDir::new().unwrap();
        let mut config = config();
        initialize_journal(dir.path(), &config).unwrap();
        config.revision_journal = true;
        save(dir.path(), &config, &snapshot(3), &HashMap::new()).unwrap();
        assert!(save_inner(dir.path(), &config, &snapshot(4), &HashMap::new(), |stage|
            if stage == "journal_parent_sync" { Err(io::Error::other("injected")) } else { Ok(()) }).is_err());
        fs::write(dir.path().join(CACHE_FILE), b"damaged").unwrap();
        save(dir.path(), &config, &snapshot(4), &HashMap::new()).unwrap();
        assert_eq!(load(dir.path(), &config).unwrap().0.revision, 4);
        assert_eq!(fs::read(&diagnostics(dir.path())[0]).unwrap(), b"damaged");
        assert!(save(dir.path(), &config, &snapshot(3), &HashMap::new()).is_err());
    }

    #[test]
    fn enrollment_journal_retry_preserves_the_revision_floor() {
        let dir = TempDir::new().unwrap();
        let mut config = config();
        initialize_journal(dir.path(), &config).unwrap();
        let original = fs::read(dir.path().join(JOURNAL_FILE)).unwrap();
        // Enrollment may crash after journal publication but before server.json commits.
        initialize_journal(dir.path(), &config).unwrap();
        assert_eq!(fs::read(dir.path().join(JOURNAL_FILE)).unwrap(), original);
        config.revision_journal = true;
        save(dir.path(), &config, &snapshot(4), &HashMap::new()).unwrap();
        initialize_journal(dir.path(), &config).unwrap();
        assert!(save(dir.path(), &config, &snapshot(3), &HashMap::new()).is_err());
        fs::remove_file(dir.path().join(JOURNAL_FILE)).unwrap();
        fs::remove_file(dir.path().join(CACHE_FILE)).unwrap();
        assert!(initialize_journal(dir.path(), &config).is_err());
        assert!(!dir.path().join(JOURNAL_FILE).exists());
    }

    #[test]
    fn journal_guards_crashes_missing_and_damaged_state() {
        let dir = TempDir::new().unwrap();
        let mut config = config();
        let ports = HashMap::new();
        initialize_journal(dir.path(), &config).unwrap();
        config.revision_journal = true;
        save(dir.path(), &config, &snapshot(3), &ports).unwrap();
        let old_cache = fs::read(dir.path().join(CACHE_FILE)).unwrap();
        assert!(save_inner(dir.path(), &config, &snapshot(4), &ports, |stage|
            if stage == "journal_parent_sync" { Err(io::Error::other("injected")) } else { Ok(()) }).is_err());
        assert!(load(dir.path(), &config).is_err());
        assert!(save(dir.path(), &config, &snapshot(3), &ports).is_err());
        save(dir.path(), &config, &snapshot(4), &ports).unwrap();
        fs::write(dir.path().join(CACHE_FILE), &old_cache).unwrap();
        assert!(load(dir.path(), &config).is_err());
        assert!(save(dir.path(), &config, &snapshot(3), &ports).is_err());
        let mut changed = snapshot(4);
        changed.l2tp_availability = Some(cat4igp_shared::control::L2tpAvailability { v2: true, v3: false });
        assert!(save(dir.path(), &config, &changed, &ports).is_err());
        fs::write(dir.path().join(CACHE_FILE), b"damaged").unwrap();
        assert!(save(dir.path(), &config, &snapshot(5), &ports).is_err());
        assert_eq!(fs::read(dir.path().join(CACHE_FILE)).unwrap(), b"damaged");
        fs::remove_file(dir.path().join(JOURNAL_FILE)).unwrap();
        assert!(save(dir.path(), &config, &snapshot(5), &ports).is_err());
        assert!(load(dir.path(), &config).is_err());
    }

    #[test]
    fn journal_publication_before_cache_is_recoverable() {
        let dir = TempDir::new().unwrap();
        let mut config = config();
        initialize_journal(dir.path(), &config).unwrap();
        config.revision_journal = true;
        save(dir.path(), &config, &snapshot(3), &HashMap::new()).unwrap();
        for stage in ["journal_publish", "partial_write", "publish", "parent_sync"] {
            let revision = if stage == "journal_publish" { 4 } else { 5 };
            assert!(save_inner(dir.path(), &config, &snapshot(revision), &HashMap::new(), |at|
                if at == stage { Err(io::Error::other("injected")) } else { Ok(()) }).is_err());
            save(dir.path(), &config, &snapshot(revision), &HashMap::new()).unwrap();
            assert_eq!(load(dir.path(), &config).unwrap().0.revision, revision);
        }
    }
    #[test]
    fn journal_rejects_identity_changes_and_corruption() {
        let dir = TempDir::new().unwrap();
        let mut config = config();
        initialize_journal(dir.path(), &config).unwrap();
        config.revision_journal = true;
        save(dir.path(), &config, &snapshot(4), &HashMap::new()).unwrap();
        let mut other = config.clone();
        other.controller_signing_key = Some("other".into());
        assert!(load(dir.path(), &other).is_err());
        assert!(save(dir.path(), &other, &snapshot(5), &HashMap::new()).is_err());
        fs::write(dir.path().join(JOURNAL_FILE), b"broken").unwrap();
        assert!(load(dir.path(), &config).is_err());
        assert!(save(dir.path(), &config, &snapshot(5), &HashMap::new()).is_err());
        assert_eq!(fs::read(dir.path().join(JOURNAL_FILE)).unwrap(), b"broken");
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
