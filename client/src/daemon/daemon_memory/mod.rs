use std::{collections::{HashMap, HashSet}, sync::Arc};
use tokio::sync::{Mutex, RwLock};
use cat4igp_shared::rest::client as REST;
use cat4igp_shared::custom_type::WireguardAnswered;

use crate::config::ClientConfig;
use crate::network::ports::PortRange;

pub mod wireguard;

#[derive(Clone)]
pub struct DaemonMemory {
    wireguard: Arc<Mutex<HashMap<i32, wireguard::WireguardTunnelC>>>,
    pub(crate) port_mgmt: Arc<PortRange>,
    node_info: Arc<RwLock<Option<REST::NodeInfoResponse>>>,
    all_nodes: Arc<RwLock<Option<REST::AllNodesResponse>>>,
    wireguard_tunnels: Arc<RwLock<Option<REST::WireguardTunnelsResponse>>>,
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
            node_info: Arc::new(RwLock::new(None)),
            all_nodes: Arc::new(RwLock::new(None)),
            wireguard_tunnels: Arc::new(RwLock::new(None)),
            last_poll_error: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn set_node_info(&self, node_info: REST::NodeInfoResponse) {
        *self.node_info.write().await = Some(node_info);
    }

    pub async fn set_all_nodes(&self, all_nodes: REST::AllNodesResponse) {
        *self.all_nodes.write().await = Some(all_nodes);
    }

    pub async fn set_wireguard_tunnels(&self, wireguard_tunnels: REST::WireguardTunnelsResponse) {
        *self.wireguard_tunnels.write().await = Some(wireguard_tunnels);
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

    pub async fn reconcile_wireguard_tunnels(
        &self,
        snapshot: &REST::WireguardTunnelsResponse,
        local_private_key: &str,
    ) -> Result<(), String> {
        let mut active = self.wireguard.lock().await;
        let desired_ids: HashSet<i32> = snapshot.tunnels.iter().map(|t| t.tunnel_id).collect();
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
                existing
                    .activate()
                    .await
                    .map_err(|e| format!("failed to activate tunnel {}: {}", tunnel.tunnel_id, e))?;
                continue;
            }

            let (mut new_tunnel, _port) = wireguard::WireguardTunnelC::new_from_rest(
                tunnel_arc,
                local_private_key.to_string(),
                memory_arc.clone(),
            )
            .await
            .map_err(|e| format!("failed to create tunnel {}: {}", tunnel.tunnel_id, e))?;

            new_tunnel
                .activate()
                .await
                .map_err(|e| format!("failed to setup tunnel {}: {}", tunnel.tunnel_id, e))?;
            active.insert(tunnel.tunnel_id, new_tunnel);
        }

        let stale_ids: Vec<i32> = active
            .keys()
            .copied()
            .filter(|id| !desired_ids.contains(id))
            .collect();

        for stale_id in stale_ids {
            if let Some(mut stale) = active.remove(&stale_id) {
                if let Some(port) = stale.get_listen_port() {
                    self.port_mgmt.release(port);
                }
                if let Err(e) = stale.teardown().await {
                    eprintln!("[daemon] failed to teardown stale tunnel {}: {}", stale_id, e);
                }
            }
        }

        Ok(())
    }
}
