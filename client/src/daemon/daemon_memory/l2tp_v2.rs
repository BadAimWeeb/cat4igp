use super::{DaemonMemory, l2tp::{add_host_address, delete_host_address, reject_address_conflict}, l2tp_v2_policy::Policy};
use crate::tunnel::{l2tp_v2::L2tpV2Tunnel, shared::Tunnel};
use cat4igp_shared::{control::{L2tpV2TunnelInfo, TopologySnapshot}, custom_type::WireguardAnswered};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub(super) struct ActiveL2tpV2 {
    info: L2tpV2TunnelInfo,
    tunnel: L2tpV2Tunnel,
    underlay: Option<String>,
    wg_flags: Option<(bool, bool)>,
    policy: Option<Policy>,
    owned_address: bool,
    cleanup_pending: bool,
}

impl ActiveL2tpV2 {
    async fn destroy(&mut self) -> Result<(), String> {
        self.cleanup_pending = true;
        self.tunnel.destroy().await.map_err(|e| e.to_string())?;
        if self.owned_address {
            let local: IpAddr = self.info.local_endpoint.parse().map_err(|_| "invalid L2TPv2 local address")?;
            delete_host_address(self.underlay.as_deref().ok_or("missing L2TPv2 underlay")?, local).await?;
            self.owned_address = false;
        }
        if let Some(policy) = &mut self.policy {
            policy.destroy().await?;
            self.policy = None;
        }
        Ok(())
    }
}

fn outer_conflict(snapshot: &TopologySnapshot, remote: Ipv4Addr) -> bool {
    snapshot.tunnels.iter().filter_map(|t| t.remote_endpoint.as_deref())
        .filter_map(|s| s.parse::<SocketAddr>().ok()).any(|endpoint| endpoint.ip() == IpAddr::V4(remote))
}

fn address_conflict(snapshot: &TopologySnapshot, info: &L2tpV2TunnelInfo) -> bool {
    let (Ok(local), Ok(remote)) = (info.local_endpoint.parse::<Ipv4Addr>(), info.remote_endpoint.parse::<Ipv4Addr>()) else { return true; };
    let overlaps = |a: &str, b: &str| [a, b].iter().filter_map(|s| s.parse::<Ipv4Addr>().ok()).any(|ip| ip == local || ip == remote);
    snapshot.l2tp_v2_tunnels.iter().any(|other| other.tunnel_id != info.tunnel_id && (info.wireguard_tunnel_id.is_some() || other.wireguard_tunnel_id.is_some()) && overlaps(&other.local_endpoint, &other.remote_endpoint))
        || snapshot.l2tp_tunnels.iter().any(|other| (info.wireguard_tunnel_id.is_some() || other.wireguard_tunnel_id.is_some()) && overlaps(&other.local_endpoint, &other.remote_endpoint))
}

impl DaemonMemory {
    pub(super) async fn cleanup_l2tp_v2(&self) -> Result<(), String> {
        let mut active = self.l2tp_v2.lock().await;
        while let Some(id) = active.keys().next().copied() {
            active.get_mut(&id).unwrap().destroy().await.map_err(|e| format!("failed to destroy L2TPv2 {id}: {e}"))?;
            active.remove(&id);
        }
        Ok(())
    }

    pub(super) async fn remove_stale_l2tp_v2(&self, snapshot: &TopologySnapshot) -> Result<(), String> {
        let mut active = self.l2tp_v2.lock().await;
        let stale: Vec<_> = active.iter().filter_map(|(id, existing)| {
            let dependency_changed = existing.info.wireguard_tunnel_id.is_some_and(|wg| {
                !snapshot.tunnels.iter().any(|t| t.tunnel_id == wg && t.peer_node_id == existing.info.peer_node_id
                    && matches!(t.local_answered, WireguardAnswered::Answered)
                    && matches!(t.remote_response, WireguardAnswered::Answered)
                    && existing.wg_flags == Some((t.endpoint_ipv6, t.fec)))
            });
            let conflict = address_conflict(snapshot, &existing.info) || (existing.underlay.is_some() && existing.info.remote_endpoint.parse().ok().is_some_and(|ip| outer_conflict(snapshot, ip)));
            (snapshot.l2tp_v2_tunnels.iter().find(|info| info.tunnel_id == *id) != Some(&existing.info)
                || dependency_changed || conflict || existing.cleanup_pending).then_some(*id)
        }).collect();
        for id in stale {
            active.get_mut(&id).unwrap().destroy().await.map_err(|e| format!("failed to destroy L2TPv2 {id}: {e}"))?;
            active.remove(&id);
        }
        Ok(())
    }

    pub(super) async fn reconcile_l2tp_v2(&self, snapshot: &TopologySnapshot) -> Result<(), String> {
        let mut active = self.l2tp_v2.lock().await;
        for info in &snapshot.l2tp_v2_tunnels {
            if !self.l2tp_enabled { return Err("L2TP disabled in client configuration".into()); }
            if info.wireguard_tunnel_id.is_none() && !self.allow_insecure_l2tp { return Err("unencrypted L2TPv2 requires allow_insecure_l2tp = true".into()); }
            if (self.l2tp_excluded_ports.0..self.l2tp_excluded_ports.1).contains(&info.local_port) {
                return Err(format!("L2TPv2 {} port {} conflicts with WireGuard port_range", info.tunnel_id, info.local_port));
            }
            let mut tunnel = L2tpV2Tunnel::new(format!("catp{:x}", info.tunnel_id), info.clone(), self.l2tp_v2_userspace).map_err(|e| e.to_string())?;
            let local: Ipv4Addr = info.local_endpoint.parse().map_err(|_| "invalid L2TPv2 local address")?;
            let remote: Ipv4Addr = info.remote_endpoint.parse().map_err(|_| "invalid L2TPv2 remote address")?;
            if address_conflict(snapshot, info) { return Err(format!("L2TPv2 local or remote address is reused for tunnel {}", info.tunnel_id)); }
            let (underlay, wg_flags) = if let Some(id) = info.wireguard_tunnel_id {
                if outer_conflict(snapshot, remote) { return Err("L2TPv2 remote address conflicts with a WireGuard outer endpoint".into()); }
                let dependency = snapshot.tunnels.iter().find(|t| t.tunnel_id == id && t.peer_node_id == info.peer_node_id
                    && matches!(t.local_answered, WireguardAnswered::Answered) && matches!(t.remote_response, WireguardAnswered::Answered))
                    .ok_or_else(|| format!("L2TPv2 {} requires a ready WireGuard tunnel {id}", info.tunnel_id))?;
                let flags = Some((dependency.endpoint_ipv6, dependency.fec));
                let wg = self.wireguard.lock().await;
                let dependency = wg.get(&id).ok_or_else(|| format!("L2TPv2 {} requires active WireGuard {id}", info.tunnel_id))?;
                if dependency.get_peer_node_id() != info.peer_node_id { return Err("L2TPv2 WireGuard peer mismatch".into()); }
                (Some(dependency.get_os_tun().get_interface_name().to_owned()), flags)
            } else { (None, None) };
            if let Some(existing) = active.get_mut(&info.tunnel_id) {
                if existing.info != *info || existing.underlay != underlay || existing.wg_flags != wg_flags || existing.cleanup_pending {
                    return Err("L2TPv2 dependency changed before cleanup".into());
                }
                existing.tunnel.setup().await.map_err(|e| format!("failed to start L2TPv2 {}: {e}", info.tunnel_id))?;
                continue;
            }
            let mut owned_address = false;
            let mut policy = None;
            if let Some(interface) = &underlay {
                let ip = IpAddr::V4(local);
                reject_address_conflict(interface, ip).await?;
                let addresses = crate::interface::get_addr(interface.clone()).await.map_err(|e| e.to_string())?;
                if addresses.iter().any(|a| a.addr() == ip) {
                    return Err(format!("L2TPv2 local address {local} already exists"));
                }
                policy = match Policy::setup(interface, local, remote, info.tunnel_id).await {
                    Ok(policy) => Some(policy),
                    Err((error, remaining)) => {
                        if let Some(policy) = remaining {
                            active.insert(info.tunnel_id, ActiveL2tpV2 { info: info.clone(), tunnel, underlay, wg_flags, policy: Some(policy), owned_address: false, cleanup_pending: true });
                        }
                        return Err(error);
                    }
                };
                if let Err(error) = add_host_address(interface, ip).await {
                    let mut state = ActiveL2tpV2 { info: info.clone(), tunnel, underlay, wg_flags, policy, owned_address, cleanup_pending: true };
                    if let Err(rollback) = state.destroy().await {
                        active.insert(info.tunnel_id, state);
                        return Err(format!("{error}; rollback: {rollback}"));
                    }
                    return Err(error);
                }
                owned_address = true;
            }
            if let Err(error) = tunnel.setup().await {
                let mut state = ActiveL2tpV2 { info: info.clone(), tunnel, underlay, wg_flags, policy, owned_address, cleanup_pending: true };
                if let Err(rollback) = state.destroy().await {
                    active.insert(info.tunnel_id, state);
                    return Err(format!("failed to start L2TPv2 {}: {error}; rollback: {rollback}", info.tunnel_id));
                }
                return Err(format!("failed to start L2TPv2 {}: {error}", info.tunnel_id));
            }
            active.insert(info.tunnel_id, ActiveL2tpV2 { info: info.clone(), tunnel, underlay, wg_flags, policy, owned_address, cleanup_pending: false });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientConfig;

    fn info() -> L2tpV2TunnelInfo {
        L2tpV2TunnelInfo {
            tunnel_id: 1, peer_node_id: 2, local_endpoint: "192.0.2.1".into(),
            remote_endpoint: "192.0.2.2".into(), local_port: 1701, remote_port: 1701,
            local_address: "10.0.0.1".into(), remote_address: "10.0.0.2".into(),
            secret: "test-secret".into(), mtu: 1400, initiator: true, wireguard_tunnel_id: None,
        }
    }

    fn snapshot(info: L2tpV2TunnelInfo) -> TopologySnapshot {
        TopologySnapshot { node_id: 1, revision: 1, tunnels: vec![], l2tp_tunnels: vec![], l2tp_v2_tunnels: vec![info], l2tp_availability: None }
    }

    #[tokio::test]
    async fn direct_ppp_requires_both_opt_ins() {
        let snapshot = snapshot(info());
        let mut config = ClientConfig::default();
        assert!(DaemonMemory::new(config.clone()).reconcile_l2tp_v2(&snapshot).await.unwrap_err().contains("disabled"));
        config.tunnel_protocols.l2tp = true;
        assert!(DaemonMemory::new(config).reconcile_l2tp_v2(&snapshot).await.unwrap_err().contains("allow_insecure_l2tp"));
    }

    #[tokio::test]
    async fn wireguard_ppp_requires_ready_peer_even_with_direct_opt_in() {
        let mut config = ClientConfig::default();
        config.tunnel_protocols.l2tp = true;
        config.allow_insecure_l2tp = true;
        let mut info = info();
        info.wireguard_tunnel_id = Some(1);
        assert!(DaemonMemory::new(config).reconcile_l2tp_v2(&snapshot(info)).await.unwrap_err().contains("ready WireGuard"));
    }

    #[tokio::test]
    async fn wireguard_ppp_rejects_reused_source() {
        let mut config = ClientConfig::default();
        config.tunnel_protocols.l2tp = true;
        let mut first = info();
        first.wireguard_tunnel_id = Some(1);
        let mut second = first.clone();
        second.tunnel_id = 2;
        let mut snapshot = snapshot(first);
        snapshot.l2tp_v2_tunnels.push(second);
        assert!(DaemonMemory::new(config).reconcile_l2tp_v2(&snapshot).await.unwrap_err().contains("reused"));
    }

    #[tokio::test]
    #[ignore = "requires root, xl2tpd, pppd and an isolated network namespace"]
    async fn wireguard_ppp_reconciler_creates_and_removes_resources() {
        use cat4igp_shared::control::WireguardTunnelInfo;
        let output = std::process::Command::new("ip").args(["link", "add", "wgtest", "type", "wireguard"]).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert!(std::process::Command::new("ip").args(["link", "set", "wgtest", "up"]).status().unwrap().success());
        let mut config = ClientConfig::default(); config.tunnel_protocols.l2tp = true;
        let memory = DaemonMemory::new(config);
        let os = crate::tunnel::wireguard::WireGuardTunnel::new("wgtest".into(), String::new(), String::new(), None, None);
        memory.wireguard.lock().await.insert(10, super::super::wireguard::WireguardTunnelC::new(10, 2, false, 1420, os, None));
        let mut value = info(); value.wireguard_tunnel_id = Some(10); value.mtu = 9000;
        let mut snapshot = snapshot(value);
        snapshot.tunnels.push(WireguardTunnelInfo { tunnel_id: 10, peer_node_id: 2, public_key: String::new(), preferred_port: 41000, remote_endpoint: Some("192.0.2.3:41000".into()), local_answered: WireguardAnswered::Answered, remote_response: WireguardAnswered::Answered, mtu: 1420, endpoint_ipv6: false, fec: false, faketcp: false, created_at: 0, updated_at: 0 });
        memory.reconcile_l2tp_v2(&snapshot).await.unwrap();
        memory.reconcile_l2tp_v2(&snapshot).await.unwrap();
        assert!(crate::interface::get_addr("wgtest".into()).await.unwrap().iter().any(|a| a.addr().to_string() == "192.0.2.1"));
        snapshot.tunnels.clear();
        memory.remove_stale_l2tp_v2(&snapshot).await.unwrap();
        assert!(memory.l2tp_v2.lock().await.is_empty());
        assert!(!crate::interface::get_addr("wgtest".into()).await.unwrap().iter().any(|a| a.addr().to_string() == "192.0.2.1"));
    }
}
