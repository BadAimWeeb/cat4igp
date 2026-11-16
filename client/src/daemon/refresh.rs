use super::{Daemon, ServerConfig};
use cat4igp_shared::control::{ControlRequest, ControlResponse, FeatureSupport, MessageMeta, RefreshAnswer, RefreshMode, RefreshOffer, RefreshStage, TopologySnapshot, TunnelAnswer, WireguardTunnelInfo};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::{self, Read, Write}, path::Path, time::{SystemTime, UNIX_EPOCH}};
use wireguard_control::Key;

const FILE: &str = "wireguard-refresh.json";
const REFRESH_INTERVAL: u64 = 6 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamingFlags { endpoint_ipv6: bool, fec: bool, faketcp: bool }
impl NamingFlags {
    fn from_tunnel(tunnel: &WireguardTunnelInfo) -> Self { Self { endpoint_ipv6: tunnel.endpoint_ipv6, fec: tunnel.fec, faketcp: tunnel.faketcp } }
    fn apply(self, tunnel: &WireguardTunnelInfo) -> WireguardTunnelInfo {
        let mut copy = tunnel.clone();
        copy.endpoint_ipv6 = self.endpoint_ipv6;
        copy.fec = self.fec;
        copy.faketcp = self.faketcp;
        copy
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Link {
    generation: u64,
    slot: u8,
    private_key: String,
    port: u16,
    offer: RefreshOffer,
    previous_public_key: String,
    #[serde(default)]
    previous_flags: Option<NamingFlags>,
    #[serde(default)]
    flags: Option<NamingFlags>,
    created_at: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    active: Option<Link>,
    previous: Option<Link>,
    candidate: Option<Link>,
    #[serde(default)]
    rejected_candidate: bool,
    next_attempt: u64,
    last_attempt: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Store {
    node_id: Option<i32>,
    controller_peer_id: String,
    controller_signing_key: String,
    controller_encryption_key: String,
    network_id: String,
    records: BTreeMap<i32, Record>,
}

enum AnswerError { Rejected(String), Unknown(String) }
impl From<AnswerError> for String {
    fn from(error: AnswerError) -> Self { match error { AnswerError::Rejected(error) | AnswerError::Unknown(error) => error } }
}
fn stale_candidate(candidate: u64, pending: Option<u64>, next: u64) -> bool {
    pending.unwrap_or(next) > candidate
}
fn discard_rejected_offer(error: &AnswerError, pending: bool) -> bool {
    !pending && matches!(error, AnswerError::Rejected(_))
}
fn may_cleanup_retired(pending: bool, candidate: bool) -> bool { !pending && !candidate }


fn invalid(message: &str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, message) }
fn now() -> Result<u64, String> { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).map_err(|_| "system clock before Unix epoch".into()) }

fn options() -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    options
}

fn check_directory(dir: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() { return Err(invalid("refresh state directory is not a directory")); }
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
            return Err(invalid("refresh state directory must be owned by the daemon user and not group/world writable"));
        }
    }
    Ok(())
}

impl Store {
    pub(super) fn load(dir: &Path) -> io::Result<Self> {
        match check_directory(dir) {
            Ok(()) => {},
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error),
        }
        let file = match options().read(true).open(dir.join(FILE)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error),
        };
        let meta = file.metadata()?;
        #[cfg(unix)] {
            use std::os::unix::fs::MetadataExt;
            if !meta.is_file() || meta.mode() & 0o7777 != 0o600 || meta.uid() != unsafe { libc::geteuid() } || meta.nlink() != 1 { return Err(invalid("refresh state is not private")); }
        }
        if !meta.is_file() || meta.len() > 4 * 1024 * 1024 { return Err(invalid("invalid refresh state file")); }
        let mut data = Vec::new();
        file.take(4 * 1024 * 1024 + 1).read_to_end(&mut data)?;
        let store: Self = serde_json::from_slice(&data).map_err(|_| invalid("invalid refresh state"))?;
        for record in store.records.values() {
            for link in [record.active.as_ref(), record.previous.as_ref(), record.candidate.as_ref()].into_iter().flatten() {
                let key = Key::from_base64(&link.private_key).map_err(|_| invalid("invalid refresh private key"))?;
                Key::from_base64(&link.previous_public_key).map_err(|_| invalid("invalid retired public key"))?;
                if link.slot > 1 || link.port == 0 || key.get_public().to_base64() != link.offer.public_key || link.offer.endpoint.parse::<std::net::SocketAddr>().is_err() { return Err(invalid("invalid refresh link")); }
            }
        }
        Ok(store)
    }

    fn bind(&mut self, config: &ServerConfig) -> Result<(), String> {
        let node = config.control_node_id.ok_or("control node id is not enrolled")?;
        let peer = config.controller_peer_id.as_deref().ok_or("controller peer id is not enrolled")?;
        let signing = config.controller_signing_key.as_deref().ok_or("controller signing key is not enrolled")?;
        let encryption = config.controller_encryption_key.as_deref().ok_or("controller encryption key is not enrolled")?;
        if let Some(existing) = self.node_id {
            if existing != node || self.network_id != config.control_network_id || self.controller_peer_id != peer || self.controller_signing_key != signing || self.controller_encryption_key != encryption { return Err("refresh state enrollment mismatch".into()); }
        } else {
            if !self.records.is_empty() { return Err("unbound refresh state contains records".into()); }
            self.node_id = Some(node);
            self.network_id = config.control_network_id.clone();
            self.controller_peer_id = peer.to_owned();
            self.controller_signing_key = signing.to_owned();
            self.controller_encryption_key = encryption.to_owned();
        }
        Ok(())
    }

    fn save(&self, dir: &Path) -> Result<(), String> {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        check_directory(dir).map_err(|e| e.to_string())?;
        let data = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if data.len() > 4 * 1024 * 1024 { return Err("refresh state is too large".into()); }
        let temp = dir.join(format!(".wireguard-refresh-{:032x}.tmp", rand08::random::<u128>()));
        let result = (|| -> io::Result<()> {
            let mut file = options().write(true).create_new(true).open(&temp)?;
            file.write_all(&data)?;
            file.sync_all()?;
            fs::rename(&temp, dir.join(FILE))?;
            fs::File::open(dir)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() { let _ = fs::remove_file(temp); }
        result.map_err(|e| e.to_string())
    }
}

impl Daemon {
    pub(super) async fn restore_rejected_candidate_ports(&self) -> Result<(), String> {
        let store = self.refresh_state.lock().await;
        for (&id, record) in &store.records {
            if record.rejected_candidate {
                let candidate = record.candidate.as_ref().ok_or("rejected refresh candidate missing")?;
                self.memory.protect_rejected_refresh_port(id, candidate.port).await?;
            }
        }
        Ok(())
    }

    pub(super) async fn trigger_network_refresh(&self) -> Result<(), String> {
        let mut store = self.refresh_state.lock().await;
        let now = now()?;
        for record in store.records.values_mut() {
            if record.candidate.is_none() && record.next_attempt != 0 {
                record.next_attempt = record.next_attempt.min(now.max(record.last_attempt.saturating_add(300)));
            }
        }
        if !store.records.is_empty() { store.save(&self.config.data_dir)?; }
        Ok(())
    }
    pub(super) async fn refresh_active_ports(&self, snapshot: &TopologySnapshot, ports: &mut std::collections::HashMap<i32, u16>) {
        let store = self.refresh_state.lock().await;
        for tunnel in &snapshot.tunnels {
            if let Some(record) = store.records.get(&tunnel.tunnel_id) {
                if let Some(link) = [record.active.as_ref(), record.previous.as_ref()].into_iter().flatten().find(|link| link.generation == tunnel.refresh.active_generation) {
                    ports.insert(tunnel.tunnel_id, link.port);
                }
            }
        }
    }

    pub(super) fn persisted_refresh_port_matches(&self, config: &ServerConfig, tunnel: &WireguardTunnelInfo, port: u16) -> Result<bool, String> {
        // Changing refresh mode does not retire an already-promoted key or port.
        if tunnel.refresh.active_generation == 0 { return Ok(false); }
        let mut store = Store::load(&self.config.data_dir).map_err(|error| error.to_string())?;
        if store.node_id.is_none() { return Ok(false); }
        // An already-bound store is checked without changing its enrollment.
        store.bind(config)?;
        Ok(store.records.get(&tunnel.tunnel_id).and_then(|record| record.active.as_ref()).is_some_and(|link|
            link.generation == tunnel.refresh.active_generation && link.slot == tunnel.refresh.active_slot && link.port == port))
    }


    pub(super) async fn restore_refresh_active(&self, snapshot: &TopologySnapshot) -> Result<(), String> {
        let mut store = self.refresh_state.lock().await;
        let config = self.server_config.lock().await.clone().ok_or("control plane is not enrolled")?;
        store.bind(&config)?;
        store.save(&self.config.data_dir)?;
        for tunnel in &snapshot.tunnels {
            if !store.records.contains_key(&tunnel.tunnel_id) {
                if tunnel.refresh.active_generation != 0 { return Err(format!("missing active refresh key for tunnel {}", tunnel.tunnel_id)); }
                continue;
            }
            let record = store.records.get_mut(&tunnel.tunnel_id).unwrap();
            if record.rejected_candidate && record.candidate.as_ref().is_some_and(|candidate| candidate.generation == tunnel.refresh.active_generation) {
                return Err(format!("rejected refresh candidate for tunnel {} is active on controller", tunnel.tunnel_id));
            }
            if record.active.as_ref().is_some_and(|active| active.generation != tunnel.refresh.active_generation)
                && !record.candidate.as_ref().is_some_and(|candidate| tunnel.refresh.pending.is_none() && candidate.generation == tunnel.refresh.active_generation) {
                if let Some(previous) = record.previous.as_ref().filter(|previous| previous.generation == tunnel.refresh.active_generation && previous.slot == tunnel.refresh.active_slot) {
                    self.memory.restore_active_wireguard(tunnel, &previous.private_key, previous.port, previous.slot == 1).await?;
                    self.memory.preserve_runtime(tunnel.tunnel_id, true).await;
                    continue;
                }
                if tunnel.refresh.active_generation == 0 { self.memory.preserve_runtime(tunnel.tunnel_id, true).await; continue; }
                return Err(format!("refresh active generation mismatch for tunnel {}", tunnel.tunnel_id));
            }
            if let Some(candidate) = &record.candidate {
                if tunnel.refresh.pending.is_none() && tunnel.refresh.active_generation == candidate.generation {
                    if candidate.slot != tunnel.refresh.active_slot { return Err(format!("refresh active generation mismatch for tunnel {}", tunnel.tunnel_id)); }
                    record.previous = record.active.take();
                    record.active = record.candidate.take();
                    record.next_attempt = now()?.saturating_add(REFRESH_INTERVAL);
                    store.save(&self.config.data_dir)?;
                }
            }
            if let Some(active) = store.records.get(&tunnel.tunnel_id).and_then(|r| r.active.as_ref()) {
                if active.generation != tunnel.refresh.active_generation || active.slot != tunnel.refresh.active_slot { return Err(format!("refresh active generation mismatch for tunnel {}", tunnel.tunnel_id)); }
                if tunnel.refresh.pending.is_some() && self.memory.refresh_is_switched(tunnel.tunnel_id).await { continue; }
                if self.memory.wireguard_is_active(tunnel.tunnel_id).await && !self.memory.active_matches(tunnel.tunnel_id, &active.offer.public_key).await? {
                    self.memory.reserve_refresh_port(tunnel.tunnel_id, Some(active.port)).await?;
                    let remote = RefreshOffer { public_key: tunnel.public_key.clone(), endpoint: tunnel.remote_endpoint.clone().ok_or("promoted peer endpoint missing")? };
                    self.memory.prepare_refresh(tunnel, &active.private_key, &remote, active.slot == 1).await?;
                    if !self.memory.refresh_connected(tunnel.tunnel_id).await { return Err(format!("promoted candidate handshake pending for tunnel {}", tunnel.tunnel_id)); }
                    self.memory.switch_refresh(tunnel.tunnel_id, snapshot).await?;
                }
                if may_cleanup_retired(tunnel.refresh.pending.is_some(), store.records[&tunnel.tunnel_id].candidate.is_some()) { self.memory.finish_refresh(tunnel.tunnel_id).await?; }
                self.memory.restore_active_wireguard(tunnel, &active.private_key, active.port, active.slot == 1).await?;
                if may_cleanup_retired(tunnel.refresh.pending.is_some(), store.records[&tunnel.tunnel_id].candidate.is_some()) {
                    let flags = active.previous_flags.ok_or("retired WireGuard naming flags missing; refusing unverified cleanup")?;
                    self.memory.cleanup_inactive_slot(&flags.apply(tunnel), active.slot == 0, &active.previous_public_key).await?;
                }
                if tunnel.refresh.pending.is_none() { self.memory.preserve_runtime(tunnel.tunnel_id, false).await; }
            } else if tunnel.refresh.active_generation != 0 {
                return Err(format!("missing active refresh key for tunnel {}", tunnel.tunnel_id));
            }
        }
        Ok(())
    }

    async fn send_refresh(&self, config: &mut ServerConfig, tunnel: i32, generation: u64, stage: RefreshStage, offer: Option<RefreshOffer>) -> Result<(), AnswerError> {
        let result: Result<_, String> = async {
            let node_id = config.control_node_id.ok_or("control node id is not enrolled")?;
            let signing_key = config.ensure_control_keypair().map_err(|e| e.to_string())?;
            let controller_key = config.controller_encryption_key.as_deref().ok_or("controller encryption key is not enrolled")?;
            let now_ms: i64 = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "system clock before Unix epoch")?.as_millis().try_into().map_err(|_| "system clock out of range")?;
            let answer = TunnelAnswer { tunnel_id: tunnel, endpoint: None, decline_type: None, refresh: Some(RefreshAnswer { generation, stage, offer }) };
            let envelope = cat4igp_shared::control::seal_tunnel_answer(&signing_key, controller_key, MessageMeta {
                message_id: format!("{:032x}", rand08::random::<u128>()), network_id: config.control_network_id.clone(), recipient_node_id: node_id, issued_at_ms: now_ms, expires_at_ms: now_ms + 60_000, topology_revision: config.topology_revision,
            }, &answer).map_err(str::to_string)?;
            let plane = self.control_plane.lock().unwrap().clone().ok_or("control plane is not enrolled")?;
            plane.request(ControlRequest::TunnelAnswerEnvelope(envelope)).await
        }.await;
        match result.map_err(AnswerError::Unknown)? {
            ControlResponse::Accepted => Ok(()),
            ControlResponse::Rejected(error) => Err(AnswerError::Rejected(error)),
            _ => Err(AnswerError::Unknown("unexpected refresh answer response".into())),
        }
    }

    async fn candidate_endpoint(&self, tunnel: &WireguardTunnelInfo, port: u16) -> Result<std::net::SocketAddr, String> {
        use std::net::ToSocketAddrs;
        let hostnames = self.hostnames.lock().await;
        let hostname = if tunnel.endpoint_ipv6 { &hostnames.1 } else { &hostnames.0 }.clone();
        drop(hostnames);
        if let Some(hostname) = hostname {
            let endpoint = (hostname.as_str(), port).to_socket_addrs().map_err(|e| e.to_string())?.find(|a| a.is_ipv6() == tunnel.endpoint_ipv6).ok_or("hostname has no requested address family")?;
            if endpoint.ip().is_unspecified() || endpoint.ip().is_multicast() { return Err("invalid refresh endpoint".into()); }
            return Ok(endpoint);
        }
        if tunnel.faketcp { return Err("FakeTCP refresh requires a public hostname and port forwarding".into()); }
        let mut detector = crate::network::PublicIpDetector::new();
        detector.init().await?;
        tokio::time::timeout(std::time::Duration::from_secs(15), self.memory.refresh_mapped_addr(tunnel.tunnel_id, &detector, tunnel.endpoint_ipv6)).await.map_err(|_| "refresh mapping discovery timed out".to_string())?
    }

    async fn cleanup_candidate(&self, tunnel: &WireguardTunnelInfo, candidate: &Link) -> Result<(), String> {
        let id = tunnel.tunnel_id;
        self.memory.reserve_refresh_port(id, Some(candidate.port)).await?;
        let flags = candidate.flags.ok_or("candidate WireGuard naming flags missing; refusing unverified cleanup")?;
        self.memory.teardown_refresh(id).await?;
        self.memory.cleanup_inactive_slot(&flags.apply(tunnel), candidate.slot == 1, &candidate.offer.public_key).await
    }

    async fn discard_rejected_candidate(&self, store: &mut Store, tunnel: &WireguardTunnelInfo, candidate: &Link) -> Result<(), String> {
        store.records.get_mut(&tunnel.tunnel_id).unwrap().rejected_candidate = true;
        let protection = self.memory.protect_rejected_refresh_port(tunnel.tunnel_id, candidate.port).await;
        store.save(&self.config.data_dir)?;
        protection?;
        self.cleanup_candidate(tunnel, candidate).await?;
        self.publish_rejected_candidate(store, tunnel.tunnel_id).await
    }

    async fn publish_rejected_candidate(&self, store: &mut Store, id: i32) -> Result<(), String> {
        let next_attempt = now()?.saturating_add(300);
        let record = store.records.get_mut(&id).unwrap();
        let previous = record.clone();
        record.candidate = None;
        record.rejected_candidate = false;
        record.next_attempt = next_attempt;
        if let Err(error) = store.save(&self.config.data_dir) {
            *store.records.get_mut(&id).unwrap() = previous;
            return Err(error);
        }
        self.memory.release_refresh_port(id).await;
        Ok(())
    }

    pub(super) async fn reconcile_refresh(&self, config: &mut ServerConfig, snapshot: &TopologySnapshot) -> Result<(), String> {
        let required = FeatureSupport { wireguard: true, refresh_dual_link: true, ..Default::default() };
        if !self.feature_support().supports(required) || !self.server_features.read().unwrap().is_some_and(|f| f.supports(required)) { return Ok(()); }
        let mut store = self.refresh_state.lock().await;
        store.bind(config)?;
        let mut in_flight = store.records.iter().filter(|(id, r)| r.candidate.is_some() && snapshot.tunnels.iter().any(|t| t.tunnel_id == **id)).count();
        for tunnel in snapshot.tunnels.iter().filter(|t| t.refresh_mode == RefreshMode::DualLink) {
            if !self.memory.wireguard_is_active(tunnel.tunnel_id).await { continue; }
            let id = tunnel.tunnel_id;
            let pending = tunnel.refresh.pending.as_ref();
            if store.records.get(&id).and_then(|record| record.active.as_ref()).is_some_and(|active| active.generation != tunnel.refresh.active_generation) { continue; }
            let record = store.records.entry(id).or_default();
            if record.rejected_candidate {
                let candidate = record.candidate.clone().ok_or("rejected refresh candidate missing")?;
                if pending.is_some() || tunnel.refresh.active_generation == candidate.generation {
                    return Err(format!("rejected refresh candidate for tunnel {id} is still referenced by controller"));
                }
                self.discard_rejected_candidate(&mut store, tunnel, &candidate).await?;
                in_flight = in_flight.saturating_sub(1);
                continue;
            }
            if let Some(pending) = pending.filter(|p| p.rolling_back) {
                self.memory.rollback_refresh(id, snapshot).await?;
                if !pending.local_rolled_back { self.send_refresh(config, id, pending.generation, RefreshStage::RolledBack, None).await?; }
                continue;
            }
            if record.candidate.as_ref().is_some_and(|candidate| stale_candidate(candidate.generation, pending.map(|p| p.generation), tunnel.refresh.next_generation)) {
                let stale = record.candidate.as_ref().unwrap().clone();
                self.cleanup_candidate(tunnel, &stale).await?;
                let next_attempt = now()?.saturating_add(REFRESH_INTERVAL);
                let previous = record.clone();
                record.candidate = None;
                record.next_attempt = next_attempt;
                if let Err(error) = store.save(&self.config.data_dir) {
                    *store.records.get_mut(&id).unwrap() = previous;
                    return Err(error);
                }
                self.memory.release_refresh_port(id).await;
                in_flight = in_flight.saturating_sub(1);
            }
            let record = store.records.get_mut(&id).unwrap();
            if pending.is_none() && record.next_attempt == 0 {
                record.next_attempt = now()?.saturating_add(REFRESH_INTERVAL);
                store.save(&self.config.data_dir)?;
            }
            let record = store.records.get(&id).unwrap();
            let initiate = pending.is_none() && (record.candidate.is_some() || (in_flight == 0 && now()? >= record.next_attempt));
            if pending.is_none() && !initiate { continue; }
            let generation = pending.map_or(tunnel.refresh.next_generation, |p| p.generation);
            if tunnel.refresh.active_slot > 1 { return Err(format!("invalid active slot for tunnel {id}")); }
            let slot = pending.map_or(1 - tunnel.refresh.active_slot, |p| p.slot);
            if slot > 1 || slot == tunnel.refresh.active_slot { return Err(format!("invalid candidate slot for tunnel {id}")); }
            if store.records[&id].candidate.is_none() {
                if pending.is_some_and(|p| p.local_offer.is_some()) {
                    self.send_refresh(config, id, generation, RefreshStage::Abort, None).await?;
                    return Err(format!("missing offered refresh key for tunnel {id}"));
                }
                let port = match self.memory.reserve_refresh_port(id, None).await {
                    Ok(port) => port,
                    Err(error) => {
                        if pending.is_some() { self.send_refresh(config, id, generation, RefreshStage::Abort, None).await?; }
                        return Err(error);
                    }
                };
                let endpoint = match self.candidate_endpoint(tunnel, port).await {
                    Ok(endpoint) => endpoint,
                    Err(error) => {
                        self.memory.abort_refresh(id).await?;
                        if pending.is_some() { self.send_refresh(config, id, generation, RefreshStage::Abort, None).await?; }
                        return Err(error);
                    }
                };
                let key = Key::generate_private();
                let previous_public_key = store.records[&id].active.as_ref().map(|link| link.offer.public_key.clone()).or_else(|| config.wg_public_key.clone()).ok_or("missing active WireGuard public key")?;
                let (endpoint_ipv6, fec, faketcp) = self.memory.active_transport_flags(id).await?;
                let previous_flags = Some(NamingFlags { endpoint_ipv6, fec, faketcp });
                let candidate = Link { generation, slot, private_key: key.to_base64(), port, created_at: now()?, previous_public_key, previous_flags, flags: Some(NamingFlags::from_tunnel(tunnel)), offer: RefreshOffer { endpoint: endpoint.to_string(), public_key: key.get_public().to_base64() } };
                store.records.get_mut(&id).unwrap().candidate = Some(candidate);
                store.records.get_mut(&id).unwrap().last_attempt = now()?;
                store.save(&self.config.data_dir)?;
                in_flight += 1;
            }
            let candidate = store.records[&id].candidate.as_ref().unwrap().clone();
            if candidate.generation != generation || candidate.slot != slot { return Err(format!("refresh candidate generation mismatch for tunnel {id}")); }
            store.save(&self.config.data_dir)?;
            self.memory.reserve_refresh_port(id, Some(candidate.port)).await?;
            if let Some(pending) = pending {
                if now()?.saturating_sub(candidate.created_at) >= 180 && (!pending.committed || !pending.local_switched) {
                    self.send_refresh(config, id, generation, RefreshStage::Abort, None).await?;
                    continue;
                }
            }
            if pending.and_then(|p| p.local_offer.as_ref()).is_none() {
                if let Err(error) = self.send_refresh(config, id, generation, RefreshStage::Offer, Some(candidate.offer.clone())).await {
                    if discard_rejected_offer(&error, pending.is_some()) {
                        self.discard_rejected_candidate(&mut store, tunnel, &candidate).await?;
                    }
                    return Err(error.into());
                }
                continue;
            }
            let pending = pending.unwrap();
            if pending.local_offer.as_ref() != Some(&candidate.offer) { return Err(format!("refresh offer mismatch for tunnel {id}")); }
            let Some(remote) = pending.remote_offer.as_ref() else { continue };
            if let Err(error) = self.memory.prepare_refresh(tunnel, &candidate.private_key, remote, slot == 1).await {
                self.send_refresh(config, id, generation, RefreshStage::Abort, None).await?;
                return Err(error);
            }
            if !pending.local_ready {
                if self.memory.refresh_connected(id).await { self.send_refresh(config, id, generation, RefreshStage::Ready, None).await?; }
                continue;
            }
            if !self.memory.refresh_is_switched(id).await && !self.memory.refresh_connected(id).await { continue; }
            if pending.committed {
                if let Err(error) = self.memory.switch_refresh(id, snapshot).await {
                    self.send_refresh(config, id, generation, RefreshStage::Abort, None).await?;
                    return Err(error);
                }
                if !pending.local_switched { self.send_refresh(config, id, generation, RefreshStage::Switched, None).await?; }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn state_round_trip_and_key_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let key = Key::generate_private();
        let link = Link { generation: 4, slot: 1, private_key: key.to_base64(), port: 12345, created_at: 1, previous_flags: Some(NamingFlags { endpoint_ipv6: true, fec: false, faketcp: true }), flags: Some(NamingFlags { endpoint_ipv6: false, fec: true, faketcp: false }), previous_public_key: Key::generate_private().get_public().to_base64(), offer: RefreshOffer { endpoint: "127.0.0.1:12345".into(), public_key: key.get_public().to_base64() } };
        let mut store = Store::default();
        store.records.insert(3, Record { candidate: Some(link), ..Default::default() });
        store.save(dir.path()).unwrap();
        assert_eq!(Store::load(dir.path()).unwrap().records[&3].candidate.as_ref().unwrap().generation, 4);
        let reloaded = Store::load(dir.path()).unwrap();
        let candidate = reloaded.records[&3].candidate.as_ref().unwrap();
        assert_eq!(candidate.previous_flags, Some(NamingFlags { endpoint_ipv6: true, fec: false, faketcp: true }));
        assert_eq!(candidate.flags, Some(NamingFlags { endpoint_ipv6: false, fec: true, faketcp: false }));
        store.records.get_mut(&3).unwrap().candidate.as_mut().unwrap().offer.public_key = Key::generate_private().get_public().to_base64();
        store.save(dir.path()).unwrap();
        assert!(Store::load(dir.path()).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn refresh_state_permissions_and_untrusted_directory_are_rejected() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let store = Store::default();
        store.save(dir.path()).unwrap();
        let path = dir.path().join(FILE);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Store::load(dir.path()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Store::load(dir.path()).is_err());
        assert!(store.save(dir.path()).is_err());
    }
    #[test]
    fn previous_generation_survives_promotion_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let old = Key::generate_private();
        let new = Key::generate_private();
        let link = |key: &Key, generation, slot, port| Link { generation, slot, port, private_key: key.to_base64(), created_at: 1, previous_flags: None, flags: None, previous_public_key: Key::generate_private().get_public().to_base64(), offer: RefreshOffer { endpoint: format!("127.0.0.1:{port}"), public_key: key.get_public().to_base64() } };
        let mut store = Store::default();
        store.records.insert(1, Record { active: Some(link(&old, 1, 1, 10001)), candidate: Some(link(&new, 2, 0, 10002)), ..Default::default() });
        let record = store.records.get_mut(&1).unwrap();
        record.previous = record.active.take();
        record.active = record.candidate.take();
        store.save(dir.path()).unwrap();
        let restored = Store::load(dir.path()).unwrap();
        assert_eq!(restored.records[&1].previous.as_ref().unwrap().private_key, old.to_base64());
        assert_eq!(restored.records[&1].active.as_ref().unwrap().private_key, new.to_base64());
    }
    #[tokio::test]
    async fn unbound_refresh_records_are_not_adopted_during_restore() {
        let dir = tempfile::tempdir().unwrap();
        let key = Key::generate_private();
        let mut store = Store::default();
        store.records.insert(1, Record { active: Some(Link {
            generation: 1, slot: 1, private_key: key.to_base64(), port: 12345, created_at: 1,
            previous_flags: None, flags: None, previous_public_key: Key::generate_private().get_public().to_base64(),
            offer: RefreshOffer { endpoint: "127.0.0.1:12345".into(), public_key: key.get_public().to_base64() },
        }), ..Default::default() });
        store.save(dir.path()).unwrap();
        let original = fs::read(dir.path().join(FILE)).unwrap();
        let daemon = Daemon::new(crate::config::ClientConfig {
            data_dir: dir.path().to_owned(), daemon_socket: dir.path().join("daemon.sock"), ..Default::default()
        }).await.unwrap();
        let mut config = ServerConfig::new(String::new(), String::new());
        config.control_node_id = Some(7);
        config.controller_peer_id = Some("controller".into());
        config.controller_signing_key = Some("signing".into());
        config.controller_encryption_key = Some("encryption".into());
        *daemon.server_config.lock().await = Some(config);
        let snapshot = TopologySnapshot { node_id: 7, revision: 1, tunnels: vec![], l2tp_tunnels: vec![], l2tp_v2_tunnels: vec![], l2tp_availability: None };
        assert!(daemon.restore_refresh_active(&snapshot).await.is_err());
        assert!(daemon.refresh_state.lock().await.node_id.is_none());
        assert_eq!(fs::read(dir.path().join(FILE)).unwrap(), original);
    }

    #[tokio::test]
    async fn mismatched_promoted_slot_does_not_destroy_candidate() {
        use cat4igp_shared::custom_type::WireguardAnswered;
        let dir = tempfile::tempdir().unwrap();
        let daemon = Daemon::new(crate::config::ClientConfig {
            data_dir: dir.path().to_owned(), daemon_socket: dir.path().join("daemon.sock"), ..Default::default()
        }).await.unwrap();
        let mut config = ServerConfig::new(String::new(), String::new());
        config.control_node_id = Some(7);
        config.controller_peer_id = Some("controller".into());
        config.controller_signing_key = Some("signing".into());
        config.controller_encryption_key = Some("encryption".into());
        *daemon.server_config.lock().await = Some(config.clone());
        let link = |generation, slot, port| {
            let key = Key::generate_private();
            Link { generation, slot, port, private_key: key.to_base64(), created_at: 1,
                previous_flags: None, flags: None, previous_public_key: Key::generate_private().get_public().to_base64(),
                offer: RefreshOffer { endpoint: format!("127.0.0.1:{port}"), public_key: key.get_public().to_base64() } }
        };
        {
            let mut store = daemon.refresh_state.lock().await;
            store.bind(&config).unwrap();
            store.records.insert(1, Record { active: Some(link(1, 1, 10001)), candidate: Some(link(2, 0, 10002)), ..Default::default() });
            store.save(dir.path()).unwrap();
        }
        let snapshot = TopologySnapshot {
            node_id: 7, revision: 1,
            tunnels: vec![WireguardTunnelInfo {
                tunnel_id: 1, peer_node_id: 2, public_key: String::new(), preferred_port: 0, remote_endpoint: None,
                local_answered: WireguardAnswered::Answered, remote_response: WireguardAnswered::Answered,
                mtu: 1420, endpoint_ipv6: false, fec: false, faketcp: false, created_at: 0, updated_at: 0,
                refresh_mode: Default::default(), refresh: cat4igp_shared::control::RefreshState {
                    active_generation: 2, active_slot: 1, ..Default::default()
                },
            }],
            l2tp_tunnels: vec![], l2tp_v2_tunnels: vec![], l2tp_availability: None,
        };
        assert!(daemon.restore_refresh_active(&snapshot).await.is_err());
        let store = Store::load(dir.path()).unwrap();
        let record = &store.records[&1];
        assert_eq!(record.active.as_ref().unwrap().generation, 1);
        assert_eq!(record.candidate.as_ref().unwrap().generation, 2);
        assert!(record.previous.is_none());
    }
    #[tokio::test]
    async fn rejected_candidate_after_restart_requires_verified_cleanup() {
        use cat4igp_shared::custom_type::WireguardAnswered;
        let dir = tempfile::tempdir().unwrap();
        let client = crate::config::ClientConfig {
            data_dir: dir.path().to_owned(), daemon_socket: dir.path().join("daemon.sock"), ..Default::default()
        };
        let daemon = Daemon::new(client.clone()).await.unwrap();
        let port = daemon.memory.reserve_refresh_port(1, None).await.unwrap();
        let key = Key::generate_private();
        let candidate = Link { generation: 1, slot: 1, private_key: key.to_base64(), port, created_at: 1,
            previous_flags: None, flags: None, previous_public_key: key.get_public().to_base64(),
            offer: RefreshOffer { endpoint: format!("127.0.0.1:{port}"), public_key: key.get_public().to_base64() } };
        {
            let mut store = daemon.refresh_state.lock().await;
            store.records.insert(1, Record { candidate: Some(candidate.clone()), ..Default::default() });
            store.save(dir.path()).unwrap();
        }
        drop(daemon);
        let daemon = Daemon::new(client.clone()).await.unwrap();
        let tunnel = WireguardTunnelInfo {
            tunnel_id: 1, peer_node_id: 2, public_key: String::new(), preferred_port: 0, remote_endpoint: None,
            local_answered: WireguardAnswered::Answered, remote_response: WireguardAnswered::Answered,
            mtu: 1420, endpoint_ipv6: false, fec: false, faketcp: false, created_at: 0, updated_at: 0,
            refresh_mode: Default::default(), refresh: Default::default(),
        };
        let mut store = daemon.refresh_state.lock().await;
        for _ in 0..2 {
            assert!(daemon.discard_rejected_candidate(&mut store, &tunnel, &candidate).await.unwrap_err().contains("naming flags missing"));
            assert!(store.records[&1].candidate.is_some());
            assert!(store.records[&1].rejected_candidate);
            assert!(Store::load(dir.path()).unwrap().records[&1].candidate.is_some());
            assert!(Store::load(dir.path()).unwrap().records[&1].rejected_candidate);
            assert!(daemon.memory.reserve_refresh_port(2, Some(port)).await.is_err());
        }
        drop(store);
        drop(daemon);
        let restarted = Daemon::new(client).await.unwrap();
        assert!(restarted.memory.reserve_refresh_port(2, Some(port)).await.is_err());
        assert_ne!(restarted.memory.reserve_tunnel_port(2).await.unwrap(), port);
    }
    #[tokio::test]
    async fn rejected_candidate_port_is_reserved_before_marking_can_fail() {
        use cat4igp_shared::custom_type::WireguardAnswered;
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let client = crate::config::ClientConfig {
            data_dir: state_dir.clone(), daemon_socket: dir.path().join("daemon.sock"), ..Default::default()
        };
        let port = client.port_range.min;
        let key = Key::generate_private();
        let candidate = Link { generation: 1, slot: 1, private_key: key.to_base64(), port, created_at: 1,
            previous_flags: None, flags: None, previous_public_key: key.get_public().to_base64(),
            offer: RefreshOffer { endpoint: format!("127.0.0.1:{port}"), public_key: key.get_public().to_base64() } };
        let mut store = Store::default();
        store.records.insert(1, Record { candidate: Some(candidate.clone()), ..Default::default() });
        store.save(&state_dir).unwrap();
        let daemon = Daemon::new(client).await.unwrap();
        let tunnel = WireguardTunnelInfo {
            tunnel_id: 1, peer_node_id: 2, public_key: String::new(), preferred_port: 0, remote_endpoint: None,
            local_answered: WireguardAnswered::Answered, remote_response: WireguardAnswered::Answered,
            mtu: 1420, endpoint_ipv6: false, fec: false, faketcp: false, created_at: 0, updated_at: 0,
            refresh_mode: Default::default(), refresh: Default::default(),
        };
        fs::rename(&state_dir, dir.path().join("moved")).unwrap();
        fs::write(&state_dir, b"not a directory").unwrap();
        let mut store = daemon.refresh_state.lock().await;
        assert!(daemon.discard_rejected_candidate(&mut store, &tunnel, &candidate).await.is_err());
        assert!(store.records[&1].rejected_candidate);
        assert!(daemon.memory.reserve_refresh_port(2, Some(port)).await.is_err());
        assert_ne!(daemon.memory.reserve_tunnel_port(2).await.unwrap(), port);
    }


    #[tokio::test]
    async fn rejected_candidate_remains_reserved_until_cleanup_is_durable() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        let daemon = Daemon::new(crate::config::ClientConfig {
            data_dir: state_dir.clone(), daemon_socket: dir.path().join("daemon.sock"), ..Default::default()
        }).await.unwrap();
        let port = daemon.memory.reserve_refresh_port(1, None).await.unwrap();
        let key = Key::generate_private();
        let candidate = Link { generation: 1, slot: 1, private_key: key.to_base64(), port, created_at: 1,
            previous_flags: None, flags: None, previous_public_key: key.get_public().to_base64(),
            offer: RefreshOffer { endpoint: format!("127.0.0.1:{port}"), public_key: key.get_public().to_base64() } };
        let mut store = daemon.refresh_state.lock().await;
        store.records.insert(1, Record { candidate: Some(candidate), ..Default::default() });
        store.save(&state_dir).unwrap();

        let moved = dir.path().join("moved");
        fs::rename(&state_dir, &moved).unwrap();
        fs::write(&state_dir, b"not a directory").unwrap();
        assert!(daemon.publish_rejected_candidate(&mut store, 1).await.is_err());
        assert!(store.records[&1].candidate.is_some());
        assert!(Store::load(&moved).unwrap().records[&1].candidate.is_some());
        assert!(daemon.memory.reserve_refresh_port(2, Some(port)).await.is_err());

        fs::remove_file(&state_dir).unwrap();
        fs::rename(&moved, &state_dir).unwrap();
        daemon.publish_rejected_candidate(&mut store, 1).await.unwrap();
        assert!(Store::load(&state_dir).unwrap().records[&1].candidate.is_none());
        assert_eq!(daemon.memory.reserve_refresh_port(2, Some(port)).await.unwrap(), port);
    }

    #[test]
    fn stale_and_rejected_offers_do_not_block_future_generations() {
        assert!(stale_candidate(4, None, 5));
        assert!(stale_candidate(4, Some(5), 6));
        assert!(!stale_candidate(4, None, 4));
        assert!(!stale_candidate(5, Some(4), 6));
        assert!(discard_rejected_offer(&AnswerError::Rejected("rejected".into()), false));
        assert!(!discard_rejected_offer(&AnswerError::Rejected("rejected".into()), true));
        assert!(!discard_rejected_offer(&AnswerError::Unknown("timeout".into()), false));
        assert!(!may_cleanup_retired(false, true));
        assert!(!may_cleanup_retired(true, true));
        assert!(!may_cleanup_retired(true, false));
        assert!(may_cleanup_retired(false, false));
    }
}
