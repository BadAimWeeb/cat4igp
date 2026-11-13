use cat4igp_shared::control::TopologySnapshot;
use std::{
    collections::HashMap,
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock};

use crate::config::ClientConfig;
use crate::network::ports::PortRange;

pub mod wireguard;
#[cfg(target_os = "linux")]
mod l2tp;
#[cfg(target_os = "linux")]
mod l2tp_v2;
#[cfg(target_os = "linux")]
pub(crate) mod l2tp_v2_policy;

#[derive(Clone)]
pub struct DaemonMemory {
    wireguard: Arc<Mutex<HashMap<i32, wireguard::WireguardTunnelC>>>,
    #[cfg(target_os = "linux")]
    l2tp: Arc<Mutex<HashMap<i32, l2tp::ActiveL2tp>>>,
    #[cfg(target_os = "linux")]
    l2tp_v2: Arc<Mutex<HashMap<i32, l2tp_v2::ActiveL2tpV2>>>,
    l2tp_enabled: bool,
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
        self.cleanup_l2tp_v2().await?;
        self.remove_stale_l2tp(&cat4igp_shared::control::TopologySnapshot {
            node_id: 0, revision: 0, tunnels: Vec::new(), l2tp_tunnels: Vec::new(), l2tp_v2_tunnels: Vec::new(), l2tp_availability: None,
        }).await
    }

    pub fn new(client_config: ClientConfig) -> Self {
        Self {
            wireguard: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(target_os = "linux")]
            l2tp: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(target_os = "linux")]
            l2tp_v2: Arc::new(Mutex::new(HashMap::new())),
            l2tp_enabled: client_config.tunnel_protocols.l2tp,
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
        // Remove dependents before changing the WireGuard underlay.
        #[cfg(target_os = "linux")]
        self.remove_stale_l2tp(&snapshot).await?;
        #[cfg(target_os = "linux")]
        self.remove_stale_l2tp_v2(&snapshot).await?;
        self.reconcile_wireguard_tunnels(&snapshot, local_private_key).await?;
        #[cfg(target_os = "linux")]
        self.reconcile_l2tp(&snapshot).await?;
        #[cfg(target_os = "linux")]
        self.reconcile_l2tp_v2(&snapshot).await?;
        #[cfg(not(target_os = "linux"))]
        if !snapshot.l2tp_tunnels.is_empty() || !snapshot.l2tp_v2_tunnels.is_empty() {
            return Err("L2TP requires Linux".into());
        }
        Ok(())
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
