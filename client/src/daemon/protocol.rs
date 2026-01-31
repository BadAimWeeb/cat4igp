use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs;
use std::io;

/// Request sent from CLI to daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonRequest {
    /// Get daemon status
    Status,
    /// Set server configuration
    SetServer {
        address: String,
        invite_code: String,
        verify_tls: bool,
    },
    /// Get current server configuration
    GetServer,
    /// Register with server and store node key
    Register,
    /// Restart the daemon
    Restart,
    /// Shutdown the daemon
    Shutdown,
    /// Get daemon configuration
    GetConfig,
    /// Modify daemon configuration
    ModifyConfig {
        public_hostname_ipv4: Option<String>,
        public_hostname_ipv6: Option<String>,
    },
}

/// Response sent from daemon to CLI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonResponse {
    /// Success with optional message
    Ok(Option<String>),
    /// Error with message
    Error(String),
    /// Status information
    Status {
        running: bool,
        server_configured: bool,
        node_key_present: bool,
        message: Option<String>,
    },
    /// Server configuration details
    ServerConfig {
        address: String,
        invite_code: String,
        verify_tls: bool,
        registered: bool,
    },
    /// Daemon configuration details
    Config(serde_json::Value),
}

/// Shared secret for CLI-daemon authentication
pub struct SharedSecret {
    pub secret: String,
}

impl SharedSecret {
    /// Create a new shared secret
    pub fn generate() -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                  abcdefghijklmnopqrstuvwxyz\
                                  0123456789";
        let mut rng = rand::thread_rng();
        (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Load shared secret from file
    pub fn load(data_dir: &Path) -> io::Result<Self> {
        let secret_path = data_dir.join(".daemon_secret");
        if !secret_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Daemon secret not found",
            ));
        }
        let secret = fs::read_to_string(secret_path)?;
        Ok(SharedSecret {
            secret: secret.trim().to_string(),
        })
    }

    /// Save shared secret to file
    pub fn save(&self, data_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(data_dir)?;
        let secret_path = data_dir.join(".daemon_secret");
        fs::write(&secret_path, &self.secret)?;
        // Ensure restrictive permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&secret_path, permissions)?;
        }
        Ok(())
    }

    /// Verify a secret matches
    pub fn verify(&self, secret: &str) -> bool {
        // Constant-time comparison
        self.secret.as_bytes().len() == secret.as_bytes().len()
            && self
                .secret
                .as_bytes()
                .iter()
                .zip(secret.as_bytes().iter())
                .fold(0, |acc, (a, b)| acc | (a ^ b))
                == 0
    }

    /// Get the secret value
    pub fn value(&self) -> &str {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secret() {
        let secret = SharedSecret::generate();
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn test_verify_secret() {
        let secret = SharedSecret::generate();
        let shared = SharedSecret {
            secret: secret.clone(),
        };
        assert!(shared.verify(&secret));
        assert!(!shared.verify("wrong"));
    }

    #[test]
    fn test_daemon_request_serialization() {
        let req = DaemonRequest::SetServer {
            address: "https://example.com".to_string(),
            invite_code: "abc123".to_string(),
            verify_tls: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: DaemonRequest = serde_json::from_str(&json).unwrap();
        match deserialized {
            DaemonRequest::SetServer {
                address,
                invite_code,
                ..
            } => {
                assert_eq!(address, "https://example.com");
                assert_eq!(invite_code, "abc123");
            }
            _ => panic!("Wrong request type"),
        }
    }
}
