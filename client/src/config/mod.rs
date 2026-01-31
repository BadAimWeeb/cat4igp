use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use std::ops::Range;

pub mod server;
pub use server::ServerConfig;

/// Configuration for the client daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Path to the daemon socket file to listen on
    pub daemon_socket: PathBuf,
    
    /// Directory for working data storage
    pub data_dir: PathBuf,
    
    /// Usable port range for tunnels
    pub port_range: PortRange,
    
    /// Enabled tunnel protocols
    pub tunnel_protocols: TunnelProtocols,
    
    /// Optional public IPv4 hostname for responding to connection requests
    pub public_hostname_ipv4: Option<String>,
    
    /// Optional public IPv6 hostname for responding to connection requests
    pub public_hostname_ipv6: Option<String>,
}

/// Port range configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRange {
    pub min: u16,
    pub max: u16,
}

impl PortRange {
    pub fn new(min: u16, max: u16) -> Result<Self, String> {
        if min >= max {
            return Err("min port must be less than max port".to_string());
        }
        Ok(PortRange { min, max })
    }

    pub fn as_range(&self) -> Range<u16> {
        self.min..self.max
    }

    pub fn contains(&self, port: u16) -> bool {
        port >= self.min && port < self.max
    }
}

/// Tunnel protocols configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelProtocols {
    pub wireguard: bool,
    // Future tunnel types can be added here
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            daemon_socket: PathBuf::from("/tmp/cat4igp-client.sock"),
            data_dir: PathBuf::from("/var/lib/cat4igp-client"),
            port_range: PortRange { min: 51820, max: 52000 },
            tunnel_protocols: TunnelProtocols {
                wireguard: true,
            },
            public_hostname_ipv4: None,
            public_hostname_ipv6: None,
        }
    }
}

impl ClientConfig {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: ClientConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(&self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Convert configuration to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self)
    }

    /// Load configuration from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_range() {
        let range = PortRange::new(1000, 2000).unwrap();
        assert!(range.contains(1500));
        assert!(!range.contains(500));
        assert!(!range.contains(2000));
    }

    #[test]
    fn test_default_config() {
        let config = ClientConfig::default();
        assert!(config.tunnel_protocols.wireguard);
        assert_eq!(config.public_hostname_ipv4, None);
        assert_eq!(config.public_hostname_ipv6, None);
    }
}
