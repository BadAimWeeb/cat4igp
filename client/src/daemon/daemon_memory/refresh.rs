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
            drop(candidates);
            drop(active);
            #[cfg(target_os = "linux")]
            {
                self.invalidate_l2tp_underlay(id).await;
                self.invalidate_l2tp_v2_underlay(id).await;
            }
        }
        #[cfg(target_os = "linux")]
        {
            self.remove_stale_l2tp(snapshot).await?;
            self.remove_stale_l2tp_v2(snapshot).await?;
            self.reconcile_l2tp(snapshot).await?;
            self.reconcile_l2tp_v2(snapshot).await?;
        }
        Ok(())
    }

    pub async fn rollback_refresh(&self, id: i32, snapshot: &TopologySnapshot) -> Result<(), String> {
        let mut switched = self.refresh_switched.lock().await;
        if switched.contains(&id) {
            let mut active = self.wireguard.lock().await;
            let mut candidates = self.refresh_wireguard.lock().await;
            let old = candidates.remove(&id).ok_or("previous WireGuard link missing during rollback")?;
            let current = match active.insert(id, old) {
                Some(current) => current,
                None => { candidates.insert(id, active.remove(&id).unwrap()); return Err("active WireGuard tunnel missing".into()); }
            };
            candidates.insert(id, current);
            switched.remove(&id);
            drop(candidates);
            drop(active);
            #[cfg(target_os = "linux")]
            {
                self.invalidate_l2tp_underlay(id).await;
                self.invalidate_l2tp_v2_underlay(id).await;
            }
        }
        #[cfg(target_os = "linux")]
        {
            self.remove_stale_l2tp(snapshot).await?;
            self.remove_stale_l2tp_v2(snapshot).await?;
            self.reconcile_l2tp(snapshot).await?;
            self.reconcile_l2tp_v2(snapshot).await?;
        }
        Ok(())
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
        let port = self.refresh_ports.lock().await.remove(&id).ok_or("refresh port not reserved")?;
        if let Some(old_port) = self.reserved_ports.lock().await.insert(id, port) { self.port_mgmt.release(old_port); }
        switched.remove(&id);
        Ok(())
    }

    pub async fn abort_refresh(&self, id: i32) -> Result<(), String> {
        if self.refresh_switched.lock().await.contains(&id) { return Err("cannot abort a switched refresh".into()); }
        let mut candidates = self.refresh_wireguard.lock().await;
        if let Some(candidate) = candidates.get_mut(&id) { candidate.teardown().await.map_err(|e| e.to_string())?; }
        candidates.remove(&id);
        if let Some(port) = self.refresh_ports.lock().await.remove(&id) { self.port_mgmt.release(port); }
        Ok(())
    }
}
