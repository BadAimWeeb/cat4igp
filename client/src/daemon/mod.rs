use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::io;
use std::future::Future;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::ClientConfig;
use crate::config::ServerConfig;
use crate::server_rest::client::ServerRestClient;

pub mod protocol;
pub mod client;
mod daemon_memory;

use protocol::{DaemonRequest, DaemonResponse, SharedSecret};

/// Daemon state and management
pub struct Daemon {
    config: Arc<ClientConfig>,
    server_config: Arc<Mutex<Option<ServerConfig>>>,
    secret: SharedSecret,
    memory: Arc<daemon_memory::DaemonMemory>,
}

/// IPC message envelope
#[derive(serde::Serialize, serde::Deserialize)]
struct IpcMessage {
    secret: String,
    request: DaemonRequest,
}

impl Daemon {
    /// Create a new daemon instance
    pub async fn new(config: ClientConfig) -> io::Result<Self> {
        // Load or create shared secret
        let secret = match SharedSecret::load(&config.data_dir) {
            Ok(s) => s,
            Err(_) => {
                let new_secret = SharedSecret::generate();
                let secret = SharedSecret {
                    secret: new_secret,
                };
                secret.save(&config.data_dir)?;
                secret
            }
        };

        // Load server configuration if it exists and ensure local WireGuard keypair is persisted.
        let mut server_config = ServerConfig::load(&config.data_dir).ok();
        if let Some(cfg) = server_config.as_mut() {
            cfg.ensure_wireguard_keypair()?;
            cfg.save(&config.data_dir)?;
        }

        let cfg_clone = config.clone();

        Ok(Daemon {
            config: Arc::new(config),
            server_config: Arc::new(Mutex::new(server_config)),
            secret,
            memory: Arc::new(daemon_memory::DaemonMemory::new(cfg_clone)),
        })
    }

    /// Handle a request from the CLI
    pub async fn handle_request(&self, req: DaemonRequest, auth_secret: &str) -> DaemonResponse {
        // Verify authentication
        if !self.secret.verify(auth_secret) {
            return DaemonResponse::Error("Authentication failed".to_string());
        }

        match req {
            DaemonRequest::Status => self.handle_status().await,
            DaemonRequest::SetServer {
                address,
                invite_code,
                verify_tls,
            } => self.handle_set_server(address, invite_code, verify_tls).await,
            DaemonRequest::Register {
                address,
                invite_code,
                verify_tls,
            } => self.handle_register(address, invite_code, verify_tls).await,
            DaemonRequest::Restart => self.handle_restart().await,
            DaemonRequest::Shutdown => self.handle_shutdown().await,
            DaemonRequest::GetConfig => self.handle_get_config().await,
            DaemonRequest::ModifyConfig {
                public_hostname_ipv4,
                public_hostname_ipv6,
            } => {
                self.handle_modify_config(public_hostname_ipv4, public_hostname_ipv6)
                    .await
            }
        }
    }

    async fn handle_status(&self) -> DaemonResponse {
        let (server_configured, node_key_present) = {
            let server_config = self.server_config.lock().await;
            let server_configured = server_config.is_some();
            let node_key_present = server_config
                .as_ref()
                .and_then(|s| s.node_key.clone())
                .is_some();
            (server_configured, node_key_present)
        };
        let poll_error = self.memory.get_last_poll_error().await;

        DaemonResponse::Status {
            running: true,
            server_configured,
            node_key_present,
            message: poll_error,
        }
    }

    async fn handle_set_server(
        &self,
        address: String,
        invite_code: String,
        verify_tls: bool,
    ) -> DaemonResponse {
        let mut server_config = self.server_config.lock().await;
        let mut config = ServerConfig {
            address,
            invite_code,
            verify_tls,
            node_key: None,
            wg_private_key: None,
            wg_public_key: None,
        };

        if let Err(e) = config.ensure_wireguard_keypair() {
            return DaemonResponse::Error(format!("Failed to generate WireGuard keypair: {}", e));
        }

        if let Err(e) = config.save(&self.config.data_dir) {
            return DaemonResponse::Error(format!("Failed to save server config: {}", e));
        }

        *server_config = Some(config);
        DaemonResponse::Ok(Some("Server configuration set".to_string()))
    }

    async fn handle_register(
        &self,
        address: String,
        invite_code: String,
        verify_tls: bool,
    ) -> DaemonResponse {
        let mut config = ServerConfig {
            address,
            invite_code,
            verify_tls,
            node_key: None,
            wg_private_key: None,
            wg_public_key: None,
        };

        if let Err(e) = config.ensure_wireguard_keypair() {
            return DaemonResponse::Error(format!("Failed to generate WireGuard keypair: {}", e));
        }

        let rest_client = match ServerRestClient::new(&config) {
            Ok(client) => client,
            Err(e) => {
                return DaemonResponse::Error(format!("Failed to create server client: {}", e));
            }
        };

        let node_name = std::env::var("HOSTNAME").unwrap_or_else(|_| "cat4igp-client".to_string());
        let registration = match rest_client.register(&node_name, &config.invite_code).await {
            Ok(response) => response,
            Err(e) => {
                return DaemonResponse::Error(format!("Registration failed: {}", e));
            }
        };

        if !registration.success {
            return DaemonResponse::Error("Registration failed: server returned unsuccessful response".to_string());
        }

        config.node_key = Some(registration.auth_key);

        if let Some(public_key) = config.wg_public_key.clone() {
            if let Err(e) = rest_client.update_wireguard_pubkey(&public_key).await {
                return DaemonResponse::Error(format!(
                    "Registration succeeded but failed to sync WireGuard public key: {}",
                    e
                ));
            }
        }

        if let Err(e) = config.save(&self.config.data_dir) {
            return DaemonResponse::Error(format!("Failed to save server config: {}", e));
        }

        let mut server_config = self.server_config.lock().await;
        *server_config = Some(config);

        DaemonResponse::Ok(Some("Registration successful".to_string()))
    }

    async fn handle_restart(&self) -> DaemonResponse {
        // In a real implementation, this would restart the daemon process
        DaemonResponse::Ok(Some("Restart signal sent".to_string()))
    }

    async fn handle_shutdown(&self) -> DaemonResponse {
        // In a real implementation, this would gracefully shutdown
        DaemonResponse::Ok(Some("Shutdown signal sent".to_string()))
    }

    async fn handle_get_config(&self) -> DaemonResponse {
        match serde_json::to_value(&*self.config) {
            Ok(value) => DaemonResponse::Config(value),
            Err(e) => DaemonResponse::Error(format!("Failed to serialize config: {}", e)),
        }
    }

    async fn handle_modify_config(
        &self,
        public_hostname_ipv4: Option<String>,
        public_hostname_ipv6: Option<String>,
    ) -> DaemonResponse {
        // In a real implementation, we would modify the config file
        // For now, just return success
        if public_hostname_ipv4.is_some() || public_hostname_ipv6.is_some() {
            DaemonResponse::Ok(Some("TODO: implement".to_string()))
        } else {
            DaemonResponse::Error("No configuration parameters provided".to_string())
        }
    }

    /// Get the shared secret value
    pub fn get_secret(&self) -> &str {
        self.secret.value()
    }

    /// Get the daemon socket path
    pub fn get_socket_path(&self) -> &Path {
        &self.config.daemon_socket
    }

    /// Check if server is configured
    pub async fn is_server_configured(&self) -> bool {
        self.server_config.lock().await.is_some()
    }

    /// Start the daemon's Unix socket server
    pub async fn run(&self) -> io::Result<()> {
        // Remove existing socket file if it exists
        if self.config.daemon_socket.exists() {
            std::fs::remove_file(&self.config.daemon_socket)?;
        }

        // Create parent directory if it doesn't exist
        if let Some(parent) = self.config.daemon_socket.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&self.config.daemon_socket)?;
        println!("✓ Listening on socket: {:?}", self.config.daemon_socket);

        if let Err(e) = self.sync_public_key_on_startup().await {
            eprintln!("[daemon] startup WireGuard public key sync failed: {}", e);
        }

        let daemon_for_updates = self.clone_for_handler();
        tokio::spawn(async move {
            daemon_for_updates.run_update_loop().await;
        });

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let daemon = self.clone_for_handler();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, daemon).await {
                            eprintln!("Error handling client: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                }
            }
        }
    }

    /// Clone the necessary state for a handler task
    fn clone_for_handler(&self) -> Arc<Self> {
        // We need to restructure to use Arc<Daemon> instead
        // For now, create a simplified approach
        Arc::new(Daemon {
            config: self.config.clone(),
            server_config: Arc::clone(&self.server_config),
            secret: SharedSecret {
                secret: self.secret.secret.clone(),
            },
            // do not clone memory! clone the Arc instead
            memory: Arc::clone(&self.memory),
        })
    }

    async fn run_update_loop(self: Arc<Self>) {
        let mut self_info_interval = tokio::time::interval(Duration::from_secs(300));
        let mut all_nodes_interval = tokio::time::interval(Duration::from_secs(300));
        let mut wg_tunnel_interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = self_info_interval.tick() => {
                    if let Err(e) = self.poll_self_info().await {
                        eprintln!("[daemon] self info poll failed: {}", e);
                        self.memory.set_last_poll_error(Some(format!("self poll failed: {}", e))).await;
                    } else {
                        self.memory.set_last_poll_error(None).await;
                    }
                }
                _ = all_nodes_interval.tick() => {
                    if let Err(e) = self.poll_all_nodes().await {
                        eprintln!("[daemon] all nodes poll failed: {}", e);
                        self.memory.set_last_poll_error(Some(format!("node list poll failed: {}", e))).await;
                    } else {
                        self.memory.set_last_poll_error(None).await;
                    }
                }
                _ = wg_tunnel_interval.tick() => {
                    if let Err(e) = self.poll_wireguard_tunnels().await {
                        eprintln!("[daemon] wireguard poll failed: {}", e);
                        self.memory.set_last_poll_error(Some(format!("wireguard poll failed: {}", e))).await;
                    } else {
                        self.memory.set_last_poll_error(None).await;
                    }
                }
            }
        }
    }

    async fn registered_server_config(&self) -> Result<ServerConfig, String> {
        let cfg = self.server_config.lock().await.clone();
        let cfg = cfg.ok_or_else(|| "server not configured".to_string())?;
        if cfg.node_key.as_deref().unwrap_or_default().is_empty() {
            return Err("server configured but not registered".to_string());
        }
        Ok(cfg)
    }

    async fn retry_with_backoff<T, F, Fut>(&self, label: &str, mut op: F) -> Result<T, String>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, Box<dyn std::error::Error + Send + Sync>>>,
    {
        let mut delay_secs = 1u64;
        for attempt in 1..=5 {
            match op().await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if attempt == 5 {
                        return Err(format!("{} failed after {} attempts: {}", label, attempt, e));
                    }
                    tokio::time::sleep(Duration::from_secs(delay_secs)).await;
                    delay_secs = (delay_secs * 2).min(60);
                }
            }
        }

        Err(format!("{} failed", label))
    }

    async fn poll_self_info(&self) -> Result<(), String> {
        let cfg = self.registered_server_config().await?;
        let client = ServerRestClient::new(&cfg).map_err(|e| e.to_string())?;
        let response = self
            .retry_with_backoff("/client/self", || {
                let client = client.clone();
                async move { client.get_self_info().await }
            })
            .await?;
        self.memory.set_node_info(response).await;
        Ok(())
    }

    async fn poll_all_nodes(&self) -> Result<(), String> {
        let cfg = self.registered_server_config().await?;
        let client = ServerRestClient::new(&cfg).map_err(|e| e.to_string())?;
        let response = self
            .retry_with_backoff("/client/all_nodes", || {
                let client = client.clone();
                async move { client.get_all_nodes().await }
            })
            .await?;
        self.memory.set_all_nodes(response).await;
        Ok(())
    }

    async fn poll_wireguard_tunnels(&self) -> Result<(), String> {
        let cfg = self.registered_server_config().await?;
        let client = ServerRestClient::new(&cfg).map_err(|e| e.to_string())?;
        let response = self
            .retry_with_backoff("/client/wg_tun", || {
                let client = client.clone();
                async move { client.get_wireguard_tunnels().await }
            })
            .await?;

        self.memory.set_wireguard_tunnels(response.clone()).await;

        let local_private_key = cfg
            .wg_private_key
            .clone()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| "wireguard private key missing from server configuration".to_string())?;

        self.memory
            .reconcile_wireguard_tunnels(&response, &local_private_key)
            .await?;

        Ok(())
    }

    async fn sync_public_key_on_startup(&self) -> Result<(), String> {
        let cfg = match self.server_config.lock().await.clone() {
            Some(cfg) => cfg,
            None => return Ok(()),
        };

        let node_key = cfg.node_key.as_deref().unwrap_or_default();
        if node_key.is_empty() {
            return Ok(());
        }

        let public_key = cfg
            .wg_public_key
            .as_deref()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| "wireguard public key missing from server configuration".to_string())?;

        let client = ServerRestClient::new(&cfg).map_err(|e| e.to_string())?;
        self.retry_with_backoff("/client/wg_pubkey", || {
            let client = client.clone();
            let public_key = public_key.to_string();
            async move { client.update_wireguard_pubkey(&public_key).await }
        })
        .await
        .map(|_| ())
    }
}

/// Handle a client connection
async fn handle_client(mut stream: UnixStream, daemon: Arc<Daemon>) -> io::Result<()> {
    // Read the request
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > 1024 * 1024 {
        // Max 1MB message
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Message too large",
        ));
    }

    let mut buffer = vec![0u8; len];
    stream.read_exact(&mut buffer).await?;

    let message: IpcMessage = serde_json::from_slice(&buffer).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("Invalid JSON: {}", e))
    })?;

    // Handle the request
    let response = daemon.handle_request(message.request, &message.secret).await;

    // Send the response
    let response_bytes = serde_json::to_vec(&response).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("Failed to serialize response: {}", e))
    })?;

    let response_len = (response_bytes.len() as u32).to_be_bytes();
    stream.write_all(&response_len).await?;
    stream.write_all(&response_bytes).await?;
    stream.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_daemon_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = ClientConfig {
            data_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let daemon = Daemon::new(config).await.unwrap();
        assert!(!daemon.is_server_configured().await);
    }

    #[tokio::test]
    async fn test_set_server_config() {
        let temp_dir = TempDir::new().unwrap();
        let config = ClientConfig {
            data_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let daemon = Daemon::new(config).await.unwrap();
        let secret = daemon.get_secret().to_string();

        let req = DaemonRequest::SetServer {
            address: "https://example.com".to_string(),
            invite_code: "test-invite".to_string(),
            verify_tls: true,
        };

        let response = daemon.handle_request(req, &secret).await;
        match response {
            DaemonResponse::Ok(_) => {
                assert!(daemon.is_server_configured().await);
            }
            _ => panic!("Unexpected response"),
        }
    }

    #[tokio::test]
    async fn test_auth_failure() {
        let temp_dir = TempDir::new().unwrap();
        let config = ClientConfig {
            data_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let daemon = Daemon::new(config).await.unwrap();

        let req = DaemonRequest::Status;
        let response = daemon.handle_request(req, "wrong-secret").await;

        match response {
            DaemonResponse::Error(msg) => {
                assert!(msg.contains("Authentication"));
            }
            _ => panic!("Expected error response"),
        }
    }
}
