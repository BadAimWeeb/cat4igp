use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::io;
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::ClientConfig;
use crate::config::ServerConfig;

pub mod protocol;
pub mod client;
mod daemon_memory;

use protocol::{DaemonRequest, DaemonResponse, SharedSecret};

/// Daemon state and management
pub struct Daemon {
    config: ClientConfig,
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

        // Load server configuration if it exists
        let server_config = ServerConfig::load(&config.data_dir).ok();

        Ok(Daemon {
            config,
            server_config: Arc::new(Mutex::new(server_config)),
            secret,
            memory: Arc::new(daemon_memory::DaemonMemory::new()),
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
            DaemonRequest::GetServer => self.handle_get_server().await,
            DaemonRequest::Register => self.handle_register().await,
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
        let server_config = self.server_config.lock().await;
        let server_configured = server_config.is_some();
        let node_key_present = server_config
            .as_ref()
            .and_then(|s| s.node_key.clone())
            .is_some();

        DaemonResponse::Status {
            running: true,
            server_configured,
            node_key_present,
            message: None,
        }
    }

    async fn handle_set_server(
        &self,
        address: String,
        invite_code: String,
        verify_tls: bool,
    ) -> DaemonResponse {
        let mut server_config = self.server_config.lock().await;
        let config = ServerConfig {
            address,
            invite_code,
            verify_tls,
            node_key: None,
        };

        if let Err(e) = config.save(&self.config.data_dir) {
            return DaemonResponse::Error(format!("Failed to save server config: {}", e));
        }

        *server_config = Some(config);
        DaemonResponse::Ok(Some("Server configuration set".to_string()))
    }

    async fn handle_get_server(&self) -> DaemonResponse {
        let server_config = self.server_config.lock().await;
        match server_config.as_ref() {
            Some(config) => DaemonResponse::ServerConfig {
                address: config.address.clone(),
                invite_code: config.invite_code.clone(),
                verify_tls: config.verify_tls,
                registered: config.node_key.is_some(),
            },
            None => DaemonResponse::Error("Server not configured".to_string()),
        }
    }

    async fn handle_register(&self) -> DaemonResponse {
        let mut server_config = self.server_config.lock().await;
        match server_config.as_mut() {
            Some(config) => {
                // In a real implementation, this would register with the server
                // and obtain a node key
                config.node_key = Some("generated-node-key".to_string());

                if let Err(e) = config.save(&self.config.data_dir) {
                    return DaemonResponse::Error(format!("Failed to save node key: {}", e));
                }

                DaemonResponse::Ok(Some("Registration successful".to_string()))
            }
            None => DaemonResponse::Error("Server not configured".to_string()),
        }
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
        match serde_json::to_value(&self.config) {
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
