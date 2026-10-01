use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;
use wireguard_control::Key;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Result<Vec<u8>, io::Error> {
    if !value.len().is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid hex key",
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid hex key"))
        })
        .collect()
}

/// Server configuration stored in the work directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Controller bootstrap multiaddress, including `/p2p/<peer-id>` during enrollment.
    pub address: String,

    /// Invite code for server registration
    pub invite_code: String,

    /// Local WireGuard private key used to create tunnels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg_private_key: Option<String>,

    /// Local WireGuard public key announced to the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg_public_key: Option<String>,

    /// Persistent libp2p identity; separate from the WireGuard key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_private_key: Option<String>,

    /// Persistent X25519 private key for future recipient-private control payloads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_encryption_private_key: Option<String>,

    /// Pinned controller peer identity from the enrollment bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller_peer_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller_signing_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller_encryption_key: Option<String>,

    /// Controller bootstrap multiaddresses from the enrollment bundle.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub control_bootstrap_addresses: Vec<String>,

    /// libp2p PSK key-file content for the private control network.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_private_network_key: Option<String>,

    /// Last accepted complete topology revision.
    #[serde(default)]
    pub topology_revision: i64,

    /// Controller-assigned recipient identifier for topology PubSub.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_node_id: Option<i32>,

    #[serde(default = "default_control_network_id")]
    pub control_network_id: String,
}

impl ServerConfig {
    /// Create a new server configuration
    pub fn new(address: String, invite_code: String) -> Self {
        Self {
            address,
            invite_code,
            wg_private_key: None,
            wg_public_key: None,
            control_private_key: None,
            control_encryption_private_key: None,
            controller_peer_id: None,
            controller_signing_key: None,
            controller_encryption_key: None,
            control_bootstrap_addresses: Vec::new(),
            control_private_network_key: None,
            topology_revision: 0,
            control_node_id: None,
            control_network_id: default_control_network_id(),
        }
    }

    /// Ensure local WireGuard keypair exists and is internally consistent.
    pub fn ensure_wireguard_keypair(&mut self) -> Result<(), io::Error> {
        let private = if let Some(private) = &self.wg_private_key {
            Key::from_base64(private).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid WireGuard private key in config: {}", e),
                )
            })?
        } else {
            let generated = Key::generate_private();
            self.wg_private_key = Some(generated.to_base64());
            generated
        };

        // Always derive and persist public key from private key.
        self.wg_public_key = Some(private.get_public().to_base64());
        Ok(())
    }

    pub fn ensure_control_keypair(&mut self) -> Result<libp2p::identity::Keypair, io::Error> {
        let keypair = match &self.control_private_key {
            Some(encoded) => libp2p::identity::Keypair::from_protobuf_encoding(&hex_decode(
                encoded,
            )?)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid control key"))?,
            None => libp2p::identity::Keypair::generate_ed25519(),
        };
        self.control_private_key =
            Some(hex_encode(&keypair.to_protobuf_encoding().map_err(
                |_| io::Error::other("failed to encode control key"),
            )?));
        Ok(keypair)
    }

    pub fn ensure_control_encryption_key(&mut self) -> Result<String, io::Error> {
        let private = match &self.control_encryption_private_key {
            Some(encoded) => {
                let bytes = hex_decode(encoded)?;
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid encryption key")
                })?;
                x25519_dalek::StaticSecret::from(bytes)
            }
            None => {
                let generated = x25519_dalek::StaticSecret::random_from_rng(rand08::rngs::OsRng);
                self.control_encryption_private_key = Some(hex_encode(&generated.to_bytes()));
                generated
            }
        };
        Ok(hex_encode(
            x25519_dalek::PublicKey::from(&private).as_bytes(),
        ))
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
        serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    /// Save server configuration to file
    pub fn save(&self, data_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(data_dir)?;
        let config_path = data_dir.join("server.json");
        let content = serde_json::to_string_pretty(&self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        fs::write(&config_path, content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
        }
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
}

fn default_control_network_id() -> String {
    "default".to_string()
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
    }

    #[test]
    fn test_server_config_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let config =
            ServerConfig::new("https://example.com".to_string(), "test-invite".to_string());

        config.save(temp_dir.path()).unwrap();
        let loaded = ServerConfig::load(temp_dir.path()).unwrap();

        assert_eq!(loaded.address, config.address);
        assert_eq!(loaded.invite_code, config.invite_code);
    }

    #[test]
    fn control_identity_is_persistent() {
        let mut config = ServerConfig::new("control".to_string(), "invite".to_string());
        let first = config
            .ensure_control_keypair()
            .unwrap()
            .public()
            .to_peer_id();
        let second = config
            .ensure_control_keypair()
            .unwrap()
            .public()
            .to_peer_id();
        assert_eq!(first, second);
    }

    #[test]
    fn control_encryption_identity_is_persistent() {
        let mut config = ServerConfig::new("control".to_string(), "invite".to_string());
        assert_eq!(
            config.ensure_control_encryption_key().unwrap(),
            config.ensure_control_encryption_key().unwrap()
        );
    }
}
