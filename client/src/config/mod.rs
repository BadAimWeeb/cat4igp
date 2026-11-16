use serde::{Deserialize, Serialize};
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

pub mod server;
pub use server::ServerConfig;

/// Configuration for the client daemon
#[derive(Debug, Clone, Serialize)]
pub struct ClientConfig {
    /// Path to the daemon socket file to listen on
    pub daemon_socket: PathBuf,

    /// Directory for working data storage
    pub data_dir: PathBuf,

    /// Usable port range for tunnels
    pub port_range: PortRange,

    /// Enabled tunnel protocols
    pub tunnel_protocols: TunnelProtocols,

    /// Allow unencrypted L2TP links; cookies do not authenticate traffic.
    #[serde(default)]
    pub allow_insecure_l2tp: bool,

    /// Force xl2tpd's userspace L2TPv2 data path instead of kernel acceleration.
    #[serde(default)]
    pub l2tp_v2_userspace: bool,

    /// Optional public IPv4 hostname for responding to connection requests
    #[serde(default, deserialize_with = "optional_hostname")]
    pub public_hostname_ipv4: Option<String>,

    /// Optional public IPv6 hostname for responding to connection requests
    #[serde(default, deserialize_with = "optional_hostname")]
    pub public_hostname_ipv6: Option<String>,

    /// Private control network identifier shared with the controller.
    #[serde(default = "default_control_network_id")]
    pub control_network_id: String,

    /// Optional fixed-destination control traffic relay.
    #[serde(default)]
    pub control_relay: Option<ControlRelay>,
}

#[derive(Deserialize)]
struct ClientConfigInput {
    daemon_socket: PathBuf,
    data_dir: PathBuf,
    port_range: PortRange,
    tunnel_protocols: TunnelProtocols,
    #[serde(default)]
    allow_insecure_l2tp: bool,
    #[serde(default)]
    l2tp_v2_userspace: bool,
    #[serde(default, deserialize_with = "optional_hostname")]
    public_hostname_ipv4: Option<String>,
    #[serde(default, deserialize_with = "optional_hostname")]
    public_hostname_ipv6: Option<String>,
    #[serde(default = "default_control_network_id")]
    control_network_id: String,
    #[serde(default)]
    control_relay: Option<ControlRelay>,
    #[serde(default, rename = "control_bootstrap_addresses", deserialize_with = "reject_legacy_control_config")]
    _control_bootstrap_addresses: (),
    #[serde(default, rename = "control_private_network_key", deserialize_with = "reject_legacy_control_config")]
    _control_private_network_key: (),
}

fn reject_legacy_control_config<'de, D: serde::Deserializer<'de>>(_: D) -> Result<(), D::Error> {
    Err(serde::de::Error::custom(
        "legacy control bootstrap addresses or private network key found in client config; preserve server.json and verify its enrollment state before removing these fields, or enroll with a trusted bundle",
    ))
}

impl<'de> Deserialize<'de> for ClientConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let input = ClientConfigInput::deserialize(deserializer)?;
        Ok(Self {
            daemon_socket: input.daemon_socket,
            data_dir: input.data_dir,
            port_range: input.port_range,
            tunnel_protocols: input.tunnel_protocols,
            allow_insecure_l2tp: input.allow_insecure_l2tp,
            l2tp_v2_userspace: input.l2tp_v2_userspace,
            public_hostname_ipv4: input.public_hostname_ipv4,
            public_hostname_ipv6: input.public_hostname_ipv6,
            control_network_id: input.control_network_id,
            control_relay: input.control_relay,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlRelay {
    pub listen: std::net::SocketAddr,
    pub target: std::net::SocketAddr,
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
    #[serde(default)]
    pub l2tp: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            daemon_socket: PathBuf::from("/run/cat4igp-client.sock"),
            data_dir: PathBuf::from("/var/lib/cat4igp-client"),
            port_range: PortRange {
                min: 51820,
                max: 52000,
            },
            tunnel_protocols: TunnelProtocols {
                wireguard: true,
                l2tp: false,
            },
            allow_insecure_l2tp: false,
            l2tp_v2_userspace: false,
            public_hostname_ipv4: None,
            public_hostname_ipv6: None,
            control_relay: None,
            control_network_id: default_control_network_id(),
        }
    }
}

fn default_control_network_id() -> String {
    "default".to_string()
}


fn optional_hostname<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.filter(|value| !value.is_empty()))
}

impl ClientConfig {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let value: toml::Value = toml::from_str(&content).map_err(|_| "invalid client configuration TOML")?;
        if value.get("control_bootstrap_addresses").is_some() || value.get("control_private_network_key").is_some() {
            return Err("legacy control bootstrap addresses or private network key found in client config; preserve server.json and verify its enrollment state before removing these fields, or enroll with a trusted bundle".into());
        }
        let config: ClientConfig = toml::from_str(&content).map_err(|_| "invalid client configuration TOML or unrecognized identity/registration field; preserve server.json and migrate manually")?;
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
#[path = "config_test.rs"]
mod tests;
