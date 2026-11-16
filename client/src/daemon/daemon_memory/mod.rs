use cat4igp_shared::control::TopologySnapshot;
use std::{
    collections::HashMap,
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock};

use crate::config::ClientConfig;
use crate::network::ports::PortRange;

pub mod wireguard;
mod refresh;
#[cfg(target_os = "linux")]
mod refresh_guard;
#[cfg(target_os = "linux")]
mod l2tp;
#[cfg(target_os = "linux")]
mod l2tp_v2;
#[cfg(target_os = "linux")]
pub(crate) mod l2tp_v2_policy;
#[cfg(all(test, target_os = "linux"))]
mod refresh_integration_test;
#[cfg(all(test, target_os = "linux"))]
mod nat_integration_test;
#[cfg(all(test, target_os = "linux"))]
mod l2tp_recovery_test;

#[derive(Clone)]
pub struct DaemonMemory {
    wireguard: Arc<Mutex<HashMap<i32, wireguard::WireguardTunnelC>>>,
    refresh_wireguard: Arc<Mutex<HashMap<i32, wireguard::WireguardTunnelC>>>,
    refresh_ports: Arc<Mutex<HashMap<i32, u16>>>,
    rejected_refresh_ports: Arc<Mutex<std::collections::HashSet<i32>>>,
    refresh_switched: Arc<Mutex<std::collections::HashSet<i32>>>,
    refresh_preserved: Arc<Mutex<std::collections::HashSet<i32>>>,
    #[cfg(target_os = "linux")]
    l2tp: Arc<Mutex<HashMap<i32, l2tp::ActiveL2tp>>>,
    #[cfg(target_os = "linux")]
    l2tp_v2: Arc<Mutex<HashMap<i32, l2tp_v2::ActiveL2tpV2>>>,
    wireguard_enabled: bool,
    l2tp_enabled: bool,
    l2tp_v2_userspace: bool,
    allow_insecure_l2tp: bool,
    l2tp_excluded_ports: (u16, u16),
    pub(crate) port_mgmt: Arc<PortRange>,
    reserved_ports: Arc<Mutex<HashMap<i32, u16>>>,
    advertised_endpoints: Arc<Mutex<HashMap<i32, String>>>,
    last_poll_error: Arc<RwLock<Option<String>>>,
}

impl DaemonMemory {
    #[cfg(target_os = "linux")]
    pub(super) async fn cleanup_l2tp(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        if let Err(error) = self.cleanup_l2tp_v2().await { errors.push(error); }
        if let Err(error) = self.remove_stale_l2tp(&cat4igp_shared::control::TopologySnapshot {
            node_id: 0, revision: 0, tunnels: Vec::new(), l2tp_tunnels: Vec::new(), l2tp_v2_tunnels: Vec::new(), l2tp_availability: None,
        }).await { errors.push(error); }
        if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
    }

    pub fn new(client_config: ClientConfig) -> Self {
        Self {
            wireguard: Arc::new(Mutex::new(HashMap::new())),
            refresh_wireguard: Arc::new(Mutex::new(HashMap::new())),
            refresh_ports: Arc::new(Mutex::new(HashMap::new())),
            rejected_refresh_ports: Arc::new(Mutex::new(std::collections::HashSet::new())),
            refresh_switched: Arc::new(Mutex::new(std::collections::HashSet::new())),
            refresh_preserved: Arc::new(Mutex::new(std::collections::HashSet::new())),
            #[cfg(target_os = "linux")]
            l2tp: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(target_os = "linux")]
            l2tp_v2: Arc::new(Mutex::new(HashMap::new())),
            wireguard_enabled: client_config.tunnel_protocols.wireguard,
            l2tp_enabled: client_config.tunnel_protocols.l2tp,
            l2tp_v2_userspace: client_config.l2tp_v2_userspace,
            allow_insecure_l2tp: client_config.allow_insecure_l2tp,
            l2tp_excluded_ports: (client_config.port_range.min, client_config.port_range.max),
            port_mgmt: Arc::new(PortRange::new(
                client_config.port_range.min,
                client_config.port_range.max,
            )),
            reserved_ports: Arc::new(Mutex::new(HashMap::new())),
            advertised_endpoints: Arc::new(Mutex::new(HashMap::new())),
            last_poll_error: Arc::new(RwLock::new(None)),
        }
    }


    /// Applies a verified control-plane snapshot through the existing actuator boundary.
    pub async fn apply_topology_snapshot(
        &self,
        snapshot: TopologySnapshot,
        local_private_key: &str,
    ) -> Result<(), String> {
        let mut errors = Vec::new();
        // Remove dependents before changing their WireGuard underlay. A failed
        // teardown blocks only that underlay, not unrelated tunnels.
        #[cfg(target_os = "linux")]
        {
            if let Err(error) = self.remove_stale_l2tp(&snapshot).await { errors.push(error); }
            if let Err(error) = self.remove_stale_l2tp_v2(&snapshot).await { errors.push(error); }
            let mut blocked = self.l2tp_cleanup_pending_underlays().await;
            blocked.extend(self.pending_l2tp_v2_underlays().await);
            let (result, failed) = self.reconcile_wireguard_tunnels_excluding(&snapshot, local_private_key, &blocked).await;
            if let Err(error) = result { errors.push(error); }
            blocked.extend(failed);
            if let Err(error) = self.reconcile_l2tp_excluding(&snapshot, &blocked).await { errors.push(error); }
            if let Err(error) = self.reconcile_l2tp_v2_excluding(&snapshot, &blocked).await { errors.push(error); }
        }
        #[cfg(not(target_os = "linux"))]
        {
            if let Err(error) = self.reconcile_wireguard_tunnels(&snapshot, local_private_key).await { errors.push(error); }
            if !snapshot.l2tp_tunnels.is_empty() || !snapshot.l2tp_v2_tunnels.is_empty() {
                errors.push("L2TP requires Linux".into());
            }
        }
        if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
    }

    pub async fn set_last_poll_error(&self, error: Option<String>) {
        *self.last_poll_error.write().await = error;
    }

    pub async fn get_last_poll_error(&self) -> Option<String> {
        self.last_poll_error.read().await.clone()
    }

    pub async fn wireguard_len(&self) -> usize {
        self.wireguard.lock().await.len()
    }

    pub async fn wireguard_is_active(&self, tunnel_id: i32) -> bool {
        self.wireguard.lock().await.contains_key(&tunnel_id)
    }

    pub async fn inactive_wireguard_mapped_addr(&self, tunnel_id: i32, detector: &crate::network::PublicIpDetector, port: u16, ipv6: bool) -> Result<std::net::SocketAddr, String> {
        let tunnels = self.wireguard.lock().await;
        if tunnels.contains_key(&tunnel_id) {
            return Err("tunnel became active before STUN mapping discovery".into());
        }
        detector.mapped_addr_from_port(port, ipv6).await
    }

    pub async fn disconnected_tunnel_ids(&self) -> Vec<i32> {
        self.wireguard
            .lock()
            .await
            .iter()
            .filter_map(|(id, tunnel)| (!tunnel.is_connected()).then_some(*id))
            .collect()
    }

    pub(super) async fn cached_ports(&self) -> HashMap<i32, u16> {
        self.reserved_ports.lock().await.clone()
    }

    pub(super) async fn restore_ports(&self, ports: &HashMap<i32, u16>) -> Result<(), String> {
        let mut reserved = self.reserved_ports.lock().await;
        let mut added = Vec::new();
        for (&id, &port) in ports {
            let result = if let Some(existing) = reserved.get(&id) {
                if *existing == port { Ok(()) } else { Err(format!("conflicting cached port for tunnel {id}")) }
            } else {
                match self.port_mgmt.allocate(Some(port)) {
                    Ok(allocated) if allocated == port => {
                        reserved.insert(id, port);
                        added.push((id, port));
                        Ok(())
                    }
                    Ok(allocated) => {
                        self.port_mgmt.release(allocated);
                        Err(format!("cached port {port} unavailable for tunnel {id}"))
                    }
                    Err(error) => Err(error.to_string()),
                }
            };
            if let Err(error) = result {
                for (id, port) in added { reserved.remove(&id); self.port_mgmt.release(port); }
                return Err(error);
            }
        }
        Ok(())
    }

    pub async fn reserve_tunnel_port(&self, tunnel_id: i32) -> Result<u16, String> {
        let mut reserved = self.reserved_ports.lock().await;
        if let Some(port) = reserved.get(&tunnel_id) {
            return Ok(*port);
        }
        let port = self
            .port_mgmt
            .allocate(None)
            .map_err(|error| error.to_string())?;
        reserved.insert(tunnel_id, port);
        Ok(port)
    }

    pub async fn release_tunnel_port(&self, tunnel_id: i32) {
        if let Some(port) = self.reserved_ports.lock().await.remove(&tunnel_id) {
            self.port_mgmt.release(port);
        }
    }

    pub async fn endpoint_changed(&self, tunnel_id: i32, endpoint: &str) -> bool {
        self.advertised_endpoints
            .lock()
            .await
            .get(&tunnel_id)
            .is_none_or(|previous| previous != endpoint)
    }

    pub async fn remember_endpoint(&self, tunnel_id: i32, endpoint: String) {
        self.advertised_endpoints
            .lock()
            .await
            .insert(tunnel_id, endpoint);
    }

}

#[tokio::test]
async fn empty_snapshot_releases_inactive_reservations() {
    let memory = DaemonMemory::new(ClientConfig::default());
    memory.reserve_tunnel_port(7).await.unwrap();
    memory.remember_endpoint(7, "127.0.0.1:1234".into()).await;
    memory
        .reconcile_wireguard_tunnels(
            &TopologySnapshot {
                node_id: 1,
                revision: 1,
                tunnels: vec![],
                l2tp_tunnels: vec![],
                l2tp_v2_tunnels: vec![],
                l2tp_availability: None,
            },
            "",
        )
        .await
        .unwrap();
    assert!(memory.reserved_ports.lock().await.is_empty());
    assert!(memory.advertised_endpoints.lock().await.is_empty());
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires an isolated network namespace, kernel WireGuard and CAP_NET_ADMIN"]
async fn two_port_exhaustion_preserves_active_tunnels_and_converges_after_removal() {
    use cat4igp_shared::{control::WireguardTunnelInfo, custom_type::WireguardAnswered};
    use wireguard_control::Key;
    let mut config = ClientConfig::default();
    config.port_range.min = 51820;
    config.port_range.max = 51822;
    let memory = DaemonMemory::new(config);
    let clone = memory.clone();
    let private = Key::generate_private().to_base64();
    let peer = Key::generate_private().get_public().to_base64();
    let info = |id| WireguardTunnelInfo {
        tunnel_id: id, peer_node_id: 100 + id, public_key: peer.clone(),
        preferred_port: 0, remote_endpoint: Some("192.0.2.2:51920".into()),
        local_answered: WireguardAnswered::Answered, remote_response: WireguardAnswered::Answered,
        mtu: 1420, endpoint_ipv6: false, fec: false, faketcp: false,
        created_at: 0, updated_at: 0, refresh_mode: Default::default(), refresh: Default::default(),
    };
    let snapshot = |ids: &[i32]| TopologySnapshot {
        node_id: 1, revision: 1, tunnels: ids.iter().map(|&id| info(id)).collect(),
        l2tp_tunnels: vec![], l2tp_v2_tunnels: vec![], l2tp_availability: None,
    };
    memory.apply_topology_snapshot(snapshot(&[1, 2]), &private).await.unwrap();
    assert_eq!(clone.wireguard_len().await, 2);
    let first = clone.reserve_tunnel_port(1).await.unwrap();
    let second = memory.reserve_tunnel_port(2).await.unwrap();
    assert_ne!(first, second);
    assert!([51820, 51821].contains(&first) && [51820, 51821].contains(&second));
    for _ in 0..2 {
        let error = clone.apply_topology_snapshot(snapshot(&[1, 2, 3]), &private).await.unwrap_err();
        assert!(error.contains("No available ports in range"), "{error}");
        assert!(memory.reserve_tunnel_port(3).await.is_err());
        assert_eq!(memory.reserve_tunnel_port(1).await.unwrap(), first);
        assert_eq!(clone.reserve_tunnel_port(2).await.unwrap(), second);
        assert_eq!(memory.wireguard_len().await, 2);
        assert!(!memory.wireguard_is_active(3).await);
    }
    clone.apply_topology_snapshot(snapshot(&[1, 3]), &private).await.unwrap();
    assert!(memory.wireguard_is_active(1).await && memory.wireguard_is_active(3).await);
    assert!(!clone.wireguard_is_active(2).await);
    assert_eq!(memory.reserve_tunnel_port(1).await.unwrap(), first);
    assert_eq!(clone.reserve_tunnel_port(3).await.unwrap(), second);
    assert!(memory.reserve_tunnel_port(2).await.is_err());
    memory.apply_topology_snapshot(snapshot(&[]), &private).await.unwrap();
    assert_eq!(clone.wireguard_len().await, 0);
    assert!(clone.cached_ports().await.is_empty());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn snapshot_reports_failures_across_l2tp_protocols() {
    use cat4igp_shared::control::{L2tpTunnelInfo, L2tpV2TunnelInfo};
    let mut config = ClientConfig::default();
    config.tunnel_protocols.l2tp = true;
    let snapshot = TopologySnapshot {
        node_id: 1, revision: 1, tunnels: vec![], l2tp_availability: None,
        l2tp_tunnels: vec![L2tpTunnelInfo {
            tunnel_id: 1, peer_node_id: 2, local_endpoint: "192.0.2.1".into(), remote_endpoint: "192.0.2.2".into(),
            local_port: 1701, remote_port: 1701, local_session_id: 1, remote_session_id: 2,
            local_cookie: "0101010101010101".into(), remote_cookie: "0202020202020202".into(),
            security_mode: "pure".into(), wireguard_tunnel_id: None, mtu: 1500,
        }],
        l2tp_v2_tunnels: vec![L2tpV2TunnelInfo {
            tunnel_id: 2, peer_node_id: 2, local_endpoint: "192.0.2.3".into(), remote_endpoint: "192.0.2.4".into(),
            local_port: 1701, remote_port: 1701, local_address: "10.0.0.1".into(), remote_address: "10.0.0.2".into(),
            secret: "test-secret".into(), mtu: 1400, initiator: true, wireguard_tunnel_id: None,
        }],
    };
    let error = DaemonMemory::new(config).apply_topology_snapshot(snapshot, "").await.unwrap_err();
    assert!(error.contains("L2TP 1:") && error.contains("L2TPv2 2:"), "{error}");
}
