use super::{DaemonMemory, wireguard::WireguardTunnelC};
use cat4igp_shared::control::{RefreshOffer, TopologySnapshot, WireguardTunnelInfo};
use crate::tunnel::shared::Tunnel;
use std::{net::SocketAddr, sync::Arc};

impl DaemonMemory {
    pub async fn active_transport_flags(&self, id: i32) -> Result<(bool, bool, bool), String> {
        self.wireguard.lock().await.get(&id).map(|tunnel| tunnel.transport_flags()).ok_or_else(|| format!("active WireGuard tunnel {id} missing"))
    }

    pub async fn preserve_runtime(&self, id: i32, preserve: bool) {
        let mut preserved = self.refresh_preserved.lock().await;
        if preserve { preserved.insert(id); } else { preserved.remove(&id); }
    }

    pub async fn active_matches(&self, id: i32, public_key: &str) -> Result<bool, String> {
        let active = self.wireguard.lock().await;
        match active.get(&id) {
            Some(tunnel) => Ok(tunnel.get_os_tun().matches_public_key(public_key).map_err(|e| e.to_string())? == Some(true)),
            None => Ok(false),
        }
    }

    pub async fn refresh_is_switched(&self, id: i32) -> bool {
        self.refresh_switched.lock().await.contains(&id)
    }

    pub async fn cleanup_inactive_slot(&self, info: &WireguardTunnelInfo, alternate: bool, expected_local_public_key: &str) -> Result<(), String> {
        use crate::tunnel::shared::Tunnel;
        let switched = self.refresh_switched.lock().await;
        if switched.contains(&info.tunnel_id) || self.refresh_wireguard.lock().await.contains_key(&info.tunnel_id) {
            return Err("refresh interface is still tracked".into());
        }
        let mut old = WireguardTunnelC::gen_new_wg_tunnel(Arc::new(info.clone()), String::new(), None, 0, 0, alternate);
        match old.matches_public_key(expected_local_public_key).map_err(|e| e.to_string())? {
            None => return Ok(()),
            Some(false) => return Err(format!("refusing to delete {}: WireGuard identity mismatch", old.get_interface_name())),
            Some(true) => {}
        }
        #[cfg(target_os = "linux")]
        super::refresh_guard::ensure_removable(old.get_interface_name()).await?;
        old.destroy_with_public_key(expected_local_public_key).await.map_err(|e| e.to_string())
    }

    pub async fn reserve_refresh_port(&self, id: i32, preferred: Option<u16>) -> Result<u16, String> {
        let mut ports = self.refresh_ports.lock().await;
        if let Some(&port) = ports.get(&id) {
            return if preferred.is_none_or(|p| p == port) { Ok(port) } else { Err("conflicting refresh port".into()) };
        }
        let port = self.port_mgmt.allocate(preferred).map_err(|e| e.to_string())?;
        if preferred.is_some_and(|p| p != port) {
            self.port_mgmt.release(port);
            return Err("requested refresh port is unavailable".into());
        }
        ports.insert(id, port);
        Ok(port)
    }

    pub(in crate::daemon) async fn protect_rejected_refresh_port(&self, id: i32, port: u16) -> Result<(), String> {
        let mut protected = self.rejected_refresh_ports.lock().await;
        self.reserve_refresh_port(id, Some(port)).await?;
        protected.insert(id);
        Ok(())
    }

    pub async fn refresh_mapped_addr(&self, id: i32, detector: &crate::network::PublicIpDetector, ipv6: bool) -> Result<SocketAddr, String> {
        let port = *self.refresh_ports.lock().await.get(&id).ok_or("refresh port not reserved")?;
        detector.mapped_addr_from_port(port, ipv6).await
    }

    pub async fn restore_active_wireguard(&self, info: &WireguardTunnelInfo, private_key: &str, port: u16, alternate: bool) -> Result<(), String> {
        let mut active = self.wireguard.lock().await;
        if let Some(existing) = active.get(&info.tunnel_id) {
            let expected = WireguardTunnelC::gen_new_wg_tunnel(Arc::new(info.clone()), private_key.to_owned(), None, 0, 0, alternate);
            let reserved = self.reserved_ports.lock().await.get(&info.tunnel_id).copied();
            if existing.get_os_tun().get_local_private_key() != private_key || existing.get_os_tun().get_interface_name() != expected.get_interface_name() || reserved != Some(port) {
                return Err(format!("active WireGuard tunnel {} conflicts with persisted refresh generation; refusing to overwrite the live link", info.tunnel_id));
            }
            return Ok(());
        }
        self.restore_ports(&[(info.tunnel_id, port)].into_iter().collect()).await?;
        let (mut tunnel, _) = WireguardTunnelC::new_with_port(Arc::new(info.clone()), private_key.to_owned(), port, alternate).await.map_err(|e| e.to_string())?;
        if let Err(error) = tunnel.activate().await.map_err(|e| e.to_string()) {
            if tunnel.teardown().await.is_err() { active.insert(info.tunnel_id, tunnel); }
            return Err(error);
        }
        active.insert(info.tunnel_id, tunnel);
        Ok(())
    }

    pub async fn prepare_refresh(&self, info: &WireguardTunnelInfo, private_key: &str, remote_offer: &RefreshOffer, alternate: bool) -> Result<(), String> {
        let switched = self.refresh_switched.lock().await;
        if switched.contains(&info.tunnel_id) { return Ok(()); }
        let active = self.wireguard.lock().await;
        if !active.contains_key(&info.tunnel_id) { return Err("active WireGuard tunnel missing".into()); }
        let mut candidates = self.refresh_wireguard.lock().await;
        if let Some(candidate) = candidates.get_mut(&info.tunnel_id) {
            return candidate.activate().await.map_err(|e| e.to_string());
        }
        let port = *self.refresh_ports.lock().await.get(&info.tunnel_id).ok_or("refresh port not reserved")?;
        let mut candidate_info = info.clone();
        candidate_info.public_key = remote_offer.public_key.clone();
        candidate_info.remote_endpoint = Some(remote_offer.endpoint.clone());
        let (mut candidate, _) = WireguardTunnelC::new_with_port(Arc::new(candidate_info), private_key.to_owned(), port, alternate).await.map_err(|e| e.to_string())?;
        if let Err(error) = candidate.activate().await.map_err(|e| e.to_string()) {
            if candidate.teardown().await.is_err() { candidates.insert(info.tunnel_id, candidate); }
            return Err(error);
        }
        candidates.insert(info.tunnel_id, candidate);
        Ok(())
    }

    pub async fn refresh_connected(&self, id: i32) -> bool {
        self.refresh_wireguard.lock().await.get(&id).is_some_and(|t| t.is_connected())
    }

    pub async fn switch_refresh(&self, id: i32, snapshot: &TopologySnapshot) -> Result<(), String> {
        let mut switched = self.refresh_switched.lock().await;
        if !switched.contains(&id) {
            #[cfg(target_os = "linux")]
            let mut l2tp = self.l2tp.lock().await;
            #[cfg(target_os = "linux")]
            let mut l2tp_v2 = self.l2tp_v2.lock().await;
            let mut active = self.wireguard.lock().await;
            let mut candidates = self.refresh_wireguard.lock().await;
            #[cfg(target_os = "linux")]
            super::refresh_guard::ensure_removable(active.get(&id).ok_or("active WireGuard tunnel missing")?.get_os_tun().get_interface_name()).await?;
            let candidate = candidates.remove(&id).ok_or("refresh candidate missing")?;
            let old = match active.insert(id, candidate) {
                Some(old) => old,
                None => { candidates.insert(id, active.remove(&id).unwrap()); return Err("active WireGuard tunnel missing".into()); }
            };
            candidates.insert(id, old);
            switched.insert(id);
            #[cfg(target_os = "linux")]
            {
                for tunnel in l2tp.values_mut() { tunnel.invalidate_underlay(id); }
                for tunnel in l2tp_v2.values_mut() { tunnel.invalidate_underlay(id); }
            }
        }
        #[cfg(target_os = "linux")]
        {
            self.reconcile_refresh_l2tp(snapshot).await?;
        }
        Ok(())
    }

    pub async fn rollback_refresh(&self, id: i32, snapshot: &TopologySnapshot) -> Result<(), String> {
        let mut switched = self.refresh_switched.lock().await;
        if switched.contains(&id) {
            #[cfg(target_os = "linux")]
            let mut l2tp = self.l2tp.lock().await;
            #[cfg(target_os = "linux")]
            let mut l2tp_v2 = self.l2tp_v2.lock().await;
            let mut active = self.wireguard.lock().await;
            let mut candidates = self.refresh_wireguard.lock().await;
            let old = candidates.remove(&id).ok_or("previous WireGuard link missing during rollback")?;
            let current = match active.insert(id, old) {
                Some(current) => current,
                None => { candidates.insert(id, active.remove(&id).unwrap()); return Err("active WireGuard tunnel missing".into()); }
            };
            candidates.insert(id, current);
            switched.remove(&id);
            #[cfg(target_os = "linux")]
            {
                for tunnel in l2tp.values_mut() { tunnel.invalidate_underlay(id); }
                for tunnel in l2tp_v2.values_mut() { tunnel.invalidate_underlay(id); }
            }
        }
        #[cfg(target_os = "linux")]
        {
            self.reconcile_refresh_l2tp(snapshot).await?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn reconcile_refresh_l2tp(&self, snapshot: &TopologySnapshot) -> Result<(), String> {
        let mut errors = Vec::new();
        if let Err(error) = self.remove_stale_l2tp(snapshot).await { errors.push(error); }
        if let Err(error) = self.remove_stale_l2tp_v2(snapshot).await { errors.push(error); }
        let mut blocked = self.l2tp_cleanup_pending_underlays().await;
        blocked.extend(self.pending_l2tp_v2_underlays().await);
        if let Err(error) = self.reconcile_l2tp_excluding(snapshot, &blocked).await { errors.push(error); }
        if let Err(error) = self.reconcile_l2tp_v2_excluding(snapshot, &blocked).await { errors.push(error); }
        if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
    }

    pub async fn finish_refresh(&self, id: i32) -> Result<(), String> {
        let mut switched = self.refresh_switched.lock().await;
        if !switched.contains(&id) { return Ok(()); }
        let mut candidates = self.refresh_wireguard.lock().await;
        if let Some(old) = candidates.get_mut(&id) {
            #[cfg(target_os = "linux")]
            super::refresh_guard::ensure_removable(old.get_os_tun().get_interface_name()).await?;
            old.teardown().await.map_err(|e| e.to_string())?;
        }
        candidates.remove(&id);
        let mut ports = self.refresh_ports.lock().await;
        let mut reserved = self.reserved_ports.lock().await;
        let port = ports.remove(&id).ok_or("refresh port not reserved")?;
        if let Some(old_port) = reserved.insert(id, port) { self.port_mgmt.release(old_port); }
        switched.remove(&id);
        Ok(())
    }

    pub(in crate::daemon) async fn teardown_refresh(&self, id: i32) -> Result<(), String> {
        let switched = self.refresh_switched.lock().await;
        self.teardown_refresh_locked(id, &switched).await
    }

    async fn teardown_refresh_locked(&self, id: i32, switched: &std::collections::HashSet<i32>) -> Result<(), String> {
        if switched.contains(&id) { return Err("cannot abort a switched refresh".into()); }
        let mut candidates = self.refresh_wireguard.lock().await;
        if let Some(candidate) = candidates.get_mut(&id) { candidate.teardown().await.map_err(|e| e.to_string())?; }
        candidates.remove(&id);
        Ok(())
    }

    pub(in crate::daemon) async fn release_refresh_port(&self, id: i32) {
        let mut protected = self.rejected_refresh_ports.lock().await;
        if let Some(port) = self.refresh_ports.lock().await.remove(&id) { self.port_mgmt.release(port); }
        protected.remove(&id);
    }

    pub async fn abort_refresh(&self, id: i32) -> Result<(), String> {
        let switched = self.refresh_switched.lock().await;
        self.teardown_refresh_locked(id, &switched).await?;
        self.release_refresh_port(id).await;
        Ok(())
    }
}

#[tokio::test]
async fn teardown_holds_switch_guard_until_candidate_is_removed() {
    let memory = DaemonMemory::new(crate::config::ClientConfig::default());
    let candidates = memory.refresh_wireguard.lock().await;
    let mut teardown = std::pin::pin!(memory.teardown_refresh(1));
    std::future::poll_fn(|cx| {
        assert!(Future::poll(teardown.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    }).await;
    assert!(memory.refresh_switched.try_lock().is_err());
    drop(candidates);
    teardown.await.unwrap();
}

#[tokio::test]
async fn abort_holds_switch_guard_until_port_is_released() {
    let memory = DaemonMemory::new(crate::config::ClientConfig::default());
    let port = memory.reserve_refresh_port(1, None).await.unwrap();
    let protected = memory.rejected_refresh_ports.lock().await;
    let mut abort = std::pin::pin!(memory.abort_refresh(1));
    std::future::poll_fn(|cx| {
        assert!(Future::poll(abort.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    }).await;
    let snapshot = TopologySnapshot { node_id: 0, revision: 0, tunnels: Vec::new(), l2tp_tunnels: Vec::new(), l2tp_v2_tunnels: Vec::new(), l2tp_availability: None };
    let mut switch = std::pin::pin!(memory.switch_refresh(1, &snapshot));
    std::future::poll_fn(|cx| {
        assert!(Future::poll(switch.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    }).await;
    drop(protected);
    abort.await.unwrap();
    assert!(switch.await.is_err());
    assert_eq!(memory.reserve_refresh_port(2, Some(port)).await.unwrap(), port);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn cancelled_rollback_does_not_swap_underlay_before_invalidation() {
    fn tunnel(name: &str) -> WireguardTunnelC {
        let os = crate::tunnel::wireguard::WireGuardTunnel::new(name.into(), String::new(), String::new(), None, None);
        WireguardTunnelC::new(1, 2, false, 1420, os, None)
    }

    let memory = DaemonMemory::new(crate::config::ClientConfig::default());
    memory.wireguard.lock().await.insert(1, tunnel("new"));
    memory.refresh_wireguard.lock().await.insert(1, tunnel("old"));
    memory.refresh_switched.lock().await.insert(1);
    let snapshot = TopologySnapshot { node_id: 0, revision: 0, tunnels: Vec::new(), l2tp_tunnels: Vec::new(), l2tp_v2_tunnels: Vec::new(), l2tp_availability: None };

    let l2tp = memory.l2tp.lock().await;
    let mut rollback = Box::pin(memory.rollback_refresh(1, &snapshot));
    std::future::poll_fn(|cx| {
        assert!(Future::poll(rollback.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    }).await;
    drop(rollback);
    drop(l2tp);

    assert!(memory.refresh_is_switched(1).await);
    assert_eq!(memory.wireguard.lock().await[&1].get_os_tun().get_interface_name(), "new");
    memory.rollback_refresh(1, &snapshot).await.unwrap();
    assert!(!memory.refresh_is_switched(1).await);
    assert_eq!(memory.wireguard.lock().await[&1].get_os_tun().get_interface_name(), "old");
}

#[tokio::test]
async fn cancelled_finish_keeps_refresh_port_for_retry() {
    let memory = DaemonMemory::new(crate::config::ClientConfig::default());
    let old_port = memory.reserve_tunnel_port(1).await.unwrap();
    let new_port = memory.reserve_refresh_port(1, None).await.unwrap();
    memory.refresh_switched.lock().await.insert(1);

    let reserved = memory.reserved_ports.lock().await;
    let mut finish = Box::pin(memory.finish_refresh(1));
    std::future::poll_fn(|cx| {
        assert!(Future::poll(finish.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    }).await;
    drop(finish);
    drop(reserved);

    assert_eq!(memory.refresh_ports.lock().await.get(&1), Some(&new_port));
    assert!(memory.refresh_is_switched(1).await);
    memory.finish_refresh(1).await.unwrap();
    assert_eq!(memory.reserve_tunnel_port(1).await.unwrap(), new_port);
    assert_eq!(memory.reserve_tunnel_port(2).await.unwrap(), old_port);
}

#[cfg(unix)]
#[tokio::test]
async fn rejected_candidate_reservation_survives_tunnel_removal_and_restart() {
    use crate::{config::ClientConfig, daemon::Daemon};
    use std::os::unix::fs::OpenOptionsExt;

    let dir = tempfile::tempdir().unwrap();
    let client = ClientConfig { data_dir: dir.path().to_owned(), daemon_socket: dir.path().join("daemon.sock"), ..Default::default() };
    let port = client.port_range.min;
    let key = wireguard_control::Key::generate_private();
    let state = serde_json::json!({
        "node_id": null, "network_id": "", "controller_peer_id": "", "controller_signing_key": "", "controller_encryption_key": "",
        "records": { "1": { "rejected_candidate": true, "candidate": {
            "generation": 1, "slot": 1, "private_key": key.to_base64(), "port": port,
            "offer": { "public_key": key.get_public().to_base64(), "endpoint": format!("127.0.0.1:{port}") },
            "previous_public_key": key.get_public().to_base64(), "created_at": 1
        }, "next_attempt": 0, "last_attempt": 0 } }
    });
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(dir.path().join("wireguard-refresh.json")).unwrap();
    std::io::Write::write_all(&mut file, &serde_json::to_vec(&state).unwrap()).unwrap();
    let daemon = Daemon::new(client.clone()).await.unwrap();
    for id in [1, 2] {
        let os = crate::tunnel::wireguard::WireGuardTunnel::new(format!("unused{id}"), String::new(), String::new(), None, None);
        daemon.memory.wireguard.lock().await.insert(id, WireguardTunnelC::new(id, id + 1, false, 1420, os, None));
    }
    let unrelated = daemon.memory.reserve_refresh_port(2, None).await.unwrap();
    let snapshot = TopologySnapshot { node_id: 1, revision: 1, tunnels: vec![], l2tp_tunnels: vec![], l2tp_v2_tunnels: vec![], l2tp_availability: None };
    daemon.memory.reconcile_wireguard_tunnels(&snapshot, "").await.unwrap();
    assert!(daemon.memory.wireguard.lock().await.is_empty());
    assert!(daemon.memory.reserve_refresh_port(3, Some(port)).await.is_err());
    assert_eq!(daemon.memory.reserve_refresh_port(3, Some(unrelated)).await.unwrap(), unrelated);
    drop(daemon);
    let restarted = Daemon::new(client).await.unwrap();
    assert!(restarted.memory.reserve_refresh_port(3, Some(port)).await.is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn failed_stale_cleanup_keeps_candidate_port_reserved() {
    use crate::{config::{ClientConfig, ServerConfig}, daemon::Daemon};
    use cat4igp_shared::{control::{FeatureSupport, RefreshMode}, custom_type::WireguardAnswered};
    use std::os::unix::fs::OpenOptionsExt;

    let dir = tempfile::tempdir().unwrap();
    let mut client = ClientConfig { data_dir: dir.path().to_owned(), daemon_socket: dir.path().join("daemon.sock"), ..Default::default() };
    client.tunnel_protocols.wireguard = true;
    let mut config = ServerConfig::new(String::new(), String::new());
    config.control_node_id = Some(7);
    config.controller_peer_id = Some("controller".into());
    config.controller_signing_key = Some("signing".into());
    config.controller_encryption_key = Some("encryption".into());
    let key = wireguard_control::Key::generate_private();
    let state = serde_json::json!({
        "node_id": config.control_node_id, "network_id": config.control_network_id,
        "controller_peer_id": config.controller_peer_id, "controller_signing_key": config.controller_signing_key,
        "controller_encryption_key": config.controller_encryption_key,
        "records": { "1": { "candidate": {
            "generation": 1, "slot": 1, "private_key": key.to_base64(), "port": client.port_range.min,
            "offer": { "public_key": key.get_public().to_base64(), "endpoint": "127.0.0.1:12345" },
            "previous_public_key": key.get_public().to_base64(), "created_at": 1
        }, "next_attempt": 0, "last_attempt": 0 } }
    });
    let path = dir.path().join("wireguard-refresh.json");
    let bytes = serde_json::to_vec(&state).unwrap();
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
    std::io::Write::write_all(&mut file, &bytes).unwrap();
    let daemon = Daemon::new(client).await.unwrap();
    *daemon.server_features.write().unwrap() = Some(FeatureSupport { wireguard: true, refresh_dual_link: true, ..Default::default() });
    let port = daemon.memory.reserve_refresh_port(1, None).await.unwrap();
    let info = WireguardTunnelInfo {
        tunnel_id: 1, peer_node_id: 2, public_key: String::new(), preferred_port: 0, remote_endpoint: None,
        local_answered: WireguardAnswered::Answered, remote_response: WireguardAnswered::Answered,
        mtu: 1420, endpoint_ipv6: false, fec: false, faketcp: false, created_at: 0, updated_at: 0,
        refresh_mode: RefreshMode::DualLink, refresh: cat4igp_shared::control::RefreshState { next_generation: 2, ..Default::default() },
    };
    let tunnel = WireguardTunnelC::gen_new_wg_tunnel(Arc::new(info.clone()), String::new(), None, 0, 0, false);
    daemon.memory.wireguard.lock().await.insert(1, WireguardTunnelC::new(1, 2, false, 1420, tunnel, None));
    let snapshot = TopologySnapshot { node_id: 7, revision: 1, tunnels: vec![info], l2tp_tunnels: vec![], l2tp_v2_tunnels: vec![], l2tp_availability: None };
    for _ in 0..2 {
        assert!(daemon.reconcile_refresh(&mut config, &snapshot).await.unwrap_err().contains("naming flags missing"));
        assert_eq!(daemon.memory.refresh_ports.lock().await.get(&1), Some(&port));
        assert_ne!(daemon.memory.reserve_tunnel_port(2).await.unwrap(), port);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    let mut client = ClientConfig { data_dir: dir.path().to_owned(), daemon_socket: dir.path().join("daemon.sock"), ..Default::default() };
    client.tunnel_protocols.wireguard = true;
    let restarted = Daemon::new(client).await.unwrap();
    *restarted.server_features.write().unwrap() = Some(FeatureSupport { wireguard: true, refresh_dual_link: true, ..Default::default() });
    let tunnel = WireguardTunnelC::gen_new_wg_tunnel(Arc::new(snapshot.tunnels[0].clone()), String::new(), None, 0, 0, false);
    restarted.memory.wireguard.lock().await.insert(1, WireguardTunnelC::new(1, 2, false, 1420, tunnel, None));
    assert!(restarted.reconcile_refresh(&mut config, &snapshot).await.unwrap_err().contains("naming flags missing"));
    assert_eq!(restarted.memory.refresh_ports.lock().await.get(&1), Some(&port));
    assert_ne!(restarted.memory.reserve_tunnel_port(2).await.unwrap(), port);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[tokio::test]
async fn completed_refresh_updates_journal_verified_cache_without_releasing_live_ports() {
    use crate::{config::{ClientConfig, ServerConfig}, daemon::{Daemon, topology_cache}};
    use cat4igp_shared::custom_type::WireguardAnswered;
    use std::{io::Write, os::unix::fs::{OpenOptionsExt, PermissionsExt}};

    let directory = tempfile::TempDir::new().unwrap();
    let daemon = Daemon::new(ClientConfig {
        data_dir: directory.path().to_owned(),
        daemon_socket: directory.path().join("daemon.sock"),
        ..Default::default()
    }).await.unwrap();
    let mut config = ServerConfig::new(String::new(), String::new());
    config.ensure_control_keypair().unwrap();
    config.ensure_control_encryption_key().unwrap();
    config.ensure_wireguard_keypair().unwrap();
    config.control_node_id = Some(7);
    config.controller_peer_id = Some("controller".into());
    config.controller_signing_key = Some("signing".into());
    config.controller_encryption_key = Some("encryption".into());
    topology_cache::initialize_journal(directory.path(), &config).unwrap();
    config.revision_journal = true;
    let mut snapshot = TopologySnapshot {
        node_id: 7, revision: 1,
        tunnels: vec![WireguardTunnelInfo {
            tunnel_id: 1, peer_node_id: 2, public_key: String::new(),
            preferred_port: 0, remote_endpoint: None,
            local_answered: WireguardAnswered::Answered,
            remote_response: WireguardAnswered::Answered,
            mtu: 1420, endpoint_ipv6: false, fec: false, faketcp: false,
            created_at: 0, updated_at: 0,
            refresh_mode: cat4igp_shared::control::RefreshMode::DualLink, refresh: Default::default(),
        }],
        l2tp_tunnels: vec![], l2tp_v2_tunnels: vec![], l2tp_availability: None,
    };
    let old_port = daemon.memory.reserve_tunnel_port(1).await.unwrap();
    daemon.cache_topology(&mut config, &snapshot).await.unwrap();
    let new_port = daemon.memory.reserve_refresh_port(1, None).await.unwrap();
    assert_ne!(old_port, new_port);
    snapshot.revision += 1;
    snapshot.tunnels[0].refresh.active_generation = 1;
    snapshot.tunnels[0].refresh.active_slot = 1;
    daemon.cache_topology(&mut config, &snapshot).await.unwrap();
    let cache_path = directory.path().join("topology-cache.json");
    let journal_path = directory.path().join("topology-revision.json");
    let old_cache = std::fs::read(&cache_path).unwrap();
    let old_journal = std::fs::read(&journal_path).unwrap();
    let key = wireguard_control::Key::generate_private();
    let state = serde_json::json!({
        "node_id": config.control_node_id, "network_id": config.control_network_id,
        "controller_peer_id": config.controller_peer_id, "controller_signing_key": config.controller_signing_key,
        "controller_encryption_key": config.controller_encryption_key,
        "records": { "1": {
            "active": {
                "generation": 1, "slot": 1, "private_key": key.to_base64(), "port": new_port,
                "offer": { "public_key": key.get_public().to_base64(), "endpoint": format!("127.0.0.1:{new_port}") },
                "previous_public_key": config.wg_public_key, "created_at": 1
            },
            "next_attempt": 1, "last_attempt": 1
        } }
    });
    let state_path = directory.path().join("wireguard-refresh.json");
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&state_path).unwrap();
    file.write_all(&serde_json::to_vec(&state).unwrap()).unwrap();
    file.sync_all().unwrap();
    // Finalize the reservation handoff after the retired link is gone.
    daemon.memory.refresh_switched.lock().await.insert(1);
    daemon.memory.finish_refresh(1).await.unwrap();
    assert_eq!(daemon.memory.reserve_tunnel_port(2).await.unwrap(), old_port);

    daemon.cache_topology(&mut config, &snapshot).await.unwrap();
    assert_eq!(topology_cache::load(directory.path(), &config).unwrap().1[&1], new_port);
    assert_eq!(topology_cache::load_reservations(directory.path(), &config, &snapshot).unwrap()[&1], new_port);
    assert_eq!(daemon.memory.reserve_tunnel_port(1).await.unwrap(), new_port);
    assert_eq!(daemon.memory.reserve_tunnel_port(2).await.unwrap(), old_port);
    let third_port = daemon.memory.reserve_tunnel_port(3).await.unwrap();
    assert_ne!(third_port, old_port);
    assert_ne!(third_port, new_port);

    // A restart after the persisted refresh handoff can retain the old cache.
    std::fs::write(&cache_path, &old_cache).unwrap();
    std::fs::write(&journal_path, &old_journal).unwrap();
    let restarted = Daemon::new(ClientConfig {
        data_dir: directory.path().to_owned(),
        daemon_socket: directory.path().join("daemon.sock"),
        ..Default::default()
    }).await.unwrap();
    restarted.memory.restore_ports(&[(1, new_port)].into_iter().collect()).await.unwrap();
    snapshot.revision += 1;
    for mode in [cat4igp_shared::control::RefreshMode::DualLink, cat4igp_shared::control::RefreshMode::Current, cat4igp_shared::control::RefreshMode::Proxy] {
        std::fs::write(&cache_path, &old_cache).unwrap();
        std::fs::write(&journal_path, &old_journal).unwrap();
        snapshot.tunnels[0].refresh_mode = mode;
        let mut transition_config = config.clone();
        restarted.cache_topology(&mut transition_config, &snapshot).await.unwrap();
        assert_eq!(topology_cache::load(directory.path(), &transition_config).unwrap().1[&1], new_port);
    }
    snapshot.tunnels[0].refresh_mode = cat4igp_shared::control::RefreshMode::DualLink;
    snapshot.revision -= 1;

    for case in ["damaged_cache", "missing_cache", "stale_cache", "legacy_journal", "unbound_refresh", "other_identity", "wrong_generation", "wrong_slot", "wrong_port", "bad_key"] {
        std::fs::write(&cache_path, &old_cache).unwrap();
        std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&journal_path, &old_journal).unwrap();
        let mut invalid_state = state.clone();
        match case {
            "damaged_cache" => std::fs::write(&cache_path, b"damaged").unwrap(),
            "missing_cache" => std::fs::remove_file(&cache_path).unwrap(),
            "stale_cache" => {
                let mut stale: serde_json::Value = serde_json::from_slice(&old_cache).unwrap();
                stale["snapshot"]["revision"] = 1.into();
                std::fs::write(&cache_path, serde_json::to_vec(&stale).unwrap()).unwrap();
            }
            "legacy_journal" => {
                let mut legacy: serde_json::Value = serde_json::from_slice(&old_journal).unwrap();
                legacy["version"] = 1.into();
                legacy.as_object_mut().unwrap().remove("ports");
                std::fs::write(&journal_path, serde_json::to_vec(&legacy).unwrap()).unwrap();
            }
            "unbound_refresh" => invalid_state["node_id"] = serde_json::Value::Null,
            "other_identity" => invalid_state["controller_peer_id"] = "other".into(),
            "wrong_generation" => invalid_state["records"]["1"]["active"]["generation"] = 2.into(),
            "wrong_slot" => invalid_state["records"]["1"]["active"]["slot"] = 0.into(),
            "wrong_port" => invalid_state["records"]["1"]["active"]["port"] = old_port.into(),
            "bad_key" => invalid_state["records"]["1"]["active"]["private_key"] = "invalid".into(),
            _ => unreachable!(),
        }
        let state_bytes = serde_json::to_vec(&invalid_state).unwrap();
        std::fs::write(&state_path, &state_bytes).unwrap();
        let previous_cache = std::fs::read(&cache_path).ok();
        let previous_journal = std::fs::read(&journal_path).unwrap();
        assert!(restarted.cache_topology(&mut config, &snapshot).await.is_err(), "{case}");
        assert_eq!(std::fs::read(&cache_path).ok(), previous_cache, "{case}");
        assert_eq!(std::fs::read(&journal_path).unwrap(), previous_journal, "{case}");
        assert_eq!(std::fs::read(&state_path).unwrap(), state_bytes, "{case}");
        assert_eq!(restarted.memory.reserve_tunnel_port(1).await.unwrap(), new_port, "{case}");
    }
}
