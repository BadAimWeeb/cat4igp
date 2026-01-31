use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs;
use std::io;

/// Server configuration stored in the work directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server address (e.g., "https://example.com" or "http://127.0.0.1:8080")
    pub address: String,
    
    /// Whether to verify TLS certificates (only applies to HTTPS)
    #[serde(default = "default_tls_verify")]
    pub verify_tls: bool,
    
    /// Invite code for server registration
    pub invite_code: String,
    
    /// Node private key (generated during registration)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_key: Option<String>,
}

fn default_tls_verify() -> bool {
    true
}

impl ServerConfig {
    /// Create a new server configuration
    pub fn new(address: String, invite_code: String) -> Self {
        Self {
            address,
            invite_code,
            verify_tls: true,
            node_key: None,
        }
    }

    /// Load server configuration from file
    pub fn load(data_dir: &Path) -> io::Result<Self> {
        let config_path = data_dir.join("server.json");
        if !config_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Server configuration not found",
            ));
        }

        let content = fs::read_to_string(config_path)?;
        serde_json::from_str(&content).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
        })
    }

    /// Save server configuration to file
    pub fn save(&self, data_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(data_dir)?;
        let config_path = data_dir.join("server.json");
        let content = serde_json::to_string_pretty(&self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        fs::write(config_path, content)?;
        Ok(())
    }

    /// Check if server is configured
    pub fn exists(data_dir: &Path) -> bool {
        data_dir.join("server.json").exists()
    }

    /// Delete server configuration
    pub fn delete(data_dir: &Path) -> io::Result<()> {
        let config_path = data_dir.join("server.json");
        if config_path.exists() {
            fs::remove_file(config_path)?;
        }
        Ok(())
    }

    /// Get the host from server address
    pub fn get_host(&self) -> Result<String, Box<dyn std::error::Error>> {
        let address = &self.address;
        let address = if address.starts_with("https://") {
            &address[8..]
        } else if address.starts_with("http://") {
            &address[7..]
        } else {
            address
        };

        // Split by '/' to remove path component if present
        let host = address.split('/').next().unwrap_or(address);
        
        // Check if it's an IP address with port
        if let Ok(addr) = host.parse::<std::net::SocketAddr>() {
            Ok(addr.ip().to_string())
        } else {
            // It might be a hostname with port, split by ':'
            Ok(host.split(':').next().unwrap_or(host).to_string())
        }
    }

    /// Check if server address uses HTTPS
    pub fn uses_https(&self) -> bool {
        self.address.starts_with("https://")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_server_config_creation() {
        let config = ServerConfig::new(
            "https://example.com:8443".to_string(),
            "invite123".to_string(),
        );
        assert_eq!(config.address, "https://example.com:8443");
        assert_eq!(config.invite_code, "invite123");
        assert!(config.verify_tls);
    }

    #[test]
    fn test_server_config_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let config = ServerConfig::new(
            "https://example.com".to_string(),
            "test-invite".to_string(),
        );

        config.save(temp_dir.path()).unwrap();
        let loaded = ServerConfig::load(temp_dir.path()).unwrap();

        assert_eq!(loaded.address, config.address);
        assert_eq!(loaded.invite_code, config.invite_code);
    }

    #[test]
    fn test_get_host() {
        let config = ServerConfig::new(
            "https://example.com:8443".to_string(),
            "invite".to_string(),
        );
        assert_eq!(config.get_host().unwrap(), "example.com");
    }

    #[test]
    fn test_uses_https() {
        let https_config = ServerConfig::new(
            "https://example.com".to_string(),
            "invite".to_string(),
        );
        assert!(https_config.uses_https());

        let http_config = ServerConfig::new(
            "http://example.com".to_string(),
            "invite".to_string(),
        );
        assert!(!http_config.uses_https());
    }
}
