use cat4igp_shared::control::TopologySnapshot;
use cat4igp_shared::custom_type::WireguardAnswered;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock};

use crate::config::ClientConfig;
use crate::network::ports::PortRange;

pub mod wireguard;

#[derive(Clone)]
pub struct DaemonMemory {
    wireguard: Arc<Mutex<HashMap<i32, wireguard::WireguardTunnelC>>>,
    pub(crate) port_mgmt: Arc<PortRange>,
    reserved_ports: Arc<Mutex<HashMap<i32, u16>>>,
    advertised_endpoints: Arc<Mutex<HashMap<i32, String>>>,
    wireguard_tunnels: Arc<RwLock<Option<TopologySnapshot>>>,
    last_poll_error: Arc<RwLock<Option<String>>>,
}

impl DaemonMemory {
    pub fn new(client_config: ClientConfig) -> Self {
        Self {
            wireguard: Arc::new(Mutex::new(HashMap::new())),
            port_mgmt: Arc::new(PortRange::new(
                client_config.port_range.min,
                client_config.port_range.max,
            )),
            reserved_ports: Arc::new(Mutex::new(HashMap::new())),
            advertised_endpoints: Arc::new(Mutex::new(HashMap::new())),
            wireguard_tunnels: Arc::new(RwLock::new(None)),
            last_poll_error: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn set_wireguard_tunnels(&self, wireguard_tunnels: TopologySnapshot) {
        *self.wireguard_tunnels.write().await = Some(wireguard_tunnels);
    }

    /// Applies a verified control-plane snapshot through the existing actuator boundary.
    pub async fn apply_topology_snapshot(
        &self,
        snapshot: TopologySnapshot,
        local_private_key: &str,
    ) -> Result<(), String> {
        self.set_wireguard_tunnels(snapshot.clone()).await;
        self.reconcile_wireguard_tunnels(&snapshot, local_private_key)
            .await
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

    pub async fn reconcile_wireguard_tunnels(
        &self,
        snapshot: &TopologySnapshot,
        local_private_key: &str,
    ) -> Result<(), String> {
        let mut active = self.wireguard.lock().await;
        let desired_ids: HashSet<i32> = snapshot
            .tunnels
            .iter()
            .filter(|t| {
                matches!(t.local_answered, WireguardAnswered::Answered)
                    && matches!(t.remote_response, WireguardAnswered::Answered)
            })
            .map(|t| t.tunnel_id)
            .collect();
        let memory_arc = Arc::new(self.clone());

        for tunnel in &snapshot.tunnels {
            let is_ready = matches!(tunnel.local_answered, WireguardAnswered::Answered)
                && matches!(tunnel.remote_response, WireguardAnswered::Answered);
            if !is_ready {
                continue;
            }

            let tunnel_arc = Arc::new(tunnel.clone());
            if let Some(existing) = active.get_mut(&tunnel.tunnel_id) {
                existing
                    .update_from_rest(tunnel_arc, memory_arc.clone())
                    .await
                    .map_err(|e| format!("failed to update tunnel {}: {}", tunnel.tunnel_id, e))?;
                existing.activate().await.map_err(|e| {
                    format!("failed to activate tunnel {}: {}", tunnel.tunnel_id, e)
                })?;
                continue;
            }

            let new_tunnel_result = wireguard::WireguardTunnelC::new_from_rest(
                tunnel_arc,
                local_private_key.to_string(),
                memory_arc.clone(),
            )
            .await
            .map(|(tunnel, _)| tunnel)
            .map_err(|error| error.to_string());
            let mut new_tunnel = match new_tunnel_result {
                Ok(tunnel) => tunnel,
                Err(error) => {
                    self.release_tunnel_port(tunnel.tunnel_id).await;
                    return Err(format!(
                        "failed to create tunnel {}: {error}",
                        tunnel.tunnel_id
                    ));
                }
            };

            let activation_result = new_tunnel
                .activate()
                .await
                .map_err(|error| error.to_string());
            if let Err(error) = activation_result {
                self.release_tunnel_port(tunnel.tunnel_id).await;
                return Err(format!(
                    "failed to setup tunnel {}: {error}",
                    tunnel.tunnel_id
                ));
            }
            active.insert(tunnel.tunnel_id, new_tunnel);
        }

        let stale_ids: Vec<i32> = active
            .keys()
            .copied()
            .filter(|id| !desired_ids.contains(id))
            .collect();

        for stale_id in stale_ids {
            if let Some(mut stale) = active.remove(&stale_id) {
                self.release_tunnel_port(stale_id).await;
                self.advertised_endpoints.lock().await.remove(&stale_id);
                if let Err(e) = stale.teardown().await {
                    eprintln!(
                        "[daemon] failed to teardown stale tunnel {}: {}",
                        stale_id, e
                    );
                }
            }
        }

        Ok(())
    }
}
