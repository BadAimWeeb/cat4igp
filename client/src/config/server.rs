use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;
use wireguard_control::Key;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Result<Vec<u8>, io::Error> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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

    /// Original registration seeds; verified discovery may replace the dial candidates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enrollment_bootstrap_addresses: Vec<String>,

    /// Original bundle discovery seeds, independent of learned public dial candidates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_discovery_bootstrap_addresses: Option<Vec<String>>,

    /// Stable enrollment fingerprint input, independent of HOSTNAME after restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_node_name: Option<String>,

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

    /// Optional public discovery seeds, trusted out of band; never private PSK endpoints.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovery_bootstrap_addresses: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_proof:
        Option<cat4igp_shared::discovery::Signed<cat4igp_shared::discovery::ControllerAvailable>>,

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
    pub fn accept_discovery_proof(
        &mut self,
        proof: cat4igp_shared::discovery::Signed<cat4igp_shared::discovery::ControllerAvailable>,
        now_ms: i64,
    ) -> Result<(), String> {
        use cat4igp_shared::discovery::{FindControllers, Role, VERSION};
        let pin = libp2p::identity::PublicKey::try_decode_protobuf(
            &hex_decode(
                self.controller_signing_key
                    .as_deref()
                    .ok_or("missing signing pin")?,
            )
            .map_err(|error| error.to_string())?,
        )
        .map_err(|_| "invalid signing pin")?;
        let requester = self
            .ensure_control_keypair()
            .map_err(|error| error.to_string())?
            .public()
            .to_peer_id();
        let query = FindControllers {
            version: VERSION,
            cluster_id: self.control_network_id.clone(),
            role: Role::Client,
            requester,
            nonce: proof.body.nonce,
            issued_at_ms: proof.body.issued_at_ms,
            expires_at_ms: proof.body.expires_at_ms,
        };
        let minimum = self
            .discovery_proof
            .as_ref()
            .map_or(0, |old| old.body.roster.body.revision);
        proof.validate(&pin, &query, proof.body.endpoint.peer_id, minimum, now_ms)?;
        if self.controller_peer_id.as_deref() != Some(&pin.to_peer_id().to_string()) {
            return Err("logical controller identity does not match signing pin".into());
        }
        if let Some(old) = &self.discovery_proof {
            if old.body.roster.body.revision == proof.body.roster.body.revision
                && cat4igp_shared::discovery::encode(&old.body.roster)?
                    != cat4igp_shared::discovery::encode(&proof.body.roster)?
            {
                return Err("roster changed without revision advancement".into());
            }
        }
        // Only a verified logical-controller signature may replace legacy transport seeds.
        self.control_bootstrap_addresses = proof
            .body
            .roster
            .body
            .controllers
            .iter()
            .flat_map(|endpoint| endpoint.addresses.iter().map(ToString::to_string))
            // ponytail: private RPCs accept 16 seeds; widen both bounds for larger rosters.
            .take(16)
            .collect();
        // Drop previously learned seeds when authority withdraws them. Explicit bundle seeds
        // remain fallback hints; only the separately signed PUBLIC field supplies new seeds.
        let old_learned: Vec<String> = self
            .discovery_proof
            .iter()
            .flat_map(|old| &old.body.roster.body.discovery_endpoints)
            .flat_map(|endpoint| endpoint.addresses.iter().map(ToString::to_string))
            .collect();
        let mut seeds = Vec::new();
        for address in proof
            .body
            .roster
            .body
            .discovery_endpoints
            .iter()
            .flat_map(|endpoint| endpoint.addresses.iter().map(ToString::to_string))
            .chain(
                self.discovery_bootstrap_addresses
                    .iter()
                    .filter(|address| !old_learned.contains(address))
                    .cloned(),
            )
        {
            // ponytail: 16 discovery seeds, matching the native dial bound; learned seeds
            // take priority over stale explicit seeds. Add seed scheduling for larger fleets.
            if seeds.len() == 16 {
                break;
            }
            if !seeds.contains(&address) {
                seeds.push(address);
            }
        }
        self.discovery_bootstrap_addresses = seeds;
        self.discovery_proof = Some(proof);
        Ok(())
    }

    pub fn discovery_authorized(&self, now_ms: i64) -> bool {
        self.discovery_bootstrap_addresses.is_empty()
            || self.discovery_proof.as_ref().is_some_and(|proof| {
                proof.body.roster.body.issued_at_ms <= now_ms
                    && now_ms < proof.body.roster.body.expires_at_ms
            })
    }

    pub fn control_peer_authorized(&self, peer: libp2p::PeerId, now_ms: i64) -> bool {
        let Some(encoded) = &self.controller_signing_key else {
            return false;
        };
        let Ok(bytes) = hex_decode(encoded) else {
            return false;
        };
        let Ok(pin) = libp2p::identity::PublicKey::try_decode_protobuf(&bytes) else {
            return false;
        };
        if self.controller_peer_id.as_deref() != Some(&pin.to_peer_id().to_string()) {
            return false;
        }
        match &self.discovery_proof {
            Some(proof) => {
                proof
                    .body
                    .roster
                    .validate(
                        &pin,
                        &self.control_network_id,
                        proof.body.roster.body.revision,
                        now_ms,
                    )
                    .is_ok()
                    && proof
                        .body
                        .roster
                        .body
                        .controllers
                        .iter()
                        .any(|endpoint| endpoint.peer_id == peer)
            }
            None => self.discovery_bootstrap_addresses.is_empty() && peer == pin.to_peer_id(),
        }
    }

    pub fn from_bundle(json: &str) -> Result<Self, String> {
        if json.len() > 16 * 1024 {
            return Err("enrollment bundle exceeds 16 KiB".into());
        }
        let bundle: cat4igp_shared::control::EnrollmentBundle =
            serde_json::from_str(json).map_err(|_| "invalid enrollment bundle")?;
        if bundle.version != cat4igp_shared::control::CONTROL_PROTOCOL_VERSION
            || bundle.invitation_code.is_empty()
            || bundle.invitation_code.len() > 256
            || bundle.bootstrap_addresses.is_empty()
            || bundle.bootstrap_addresses.len() > 16
            || bundle.discovery_bootstrap_addresses.len() > 16
        {
            return Err("invalid enrollment bundle fields".into());
        }
        cat4igp_shared::discovery::topic(
            &bundle.network_id,
            cat4igp_shared::discovery::Role::Client,
        )?;
        let peer: libp2p::PeerId = bundle
            .controller_peer_id
            .parse()
            .map_err(|_| "invalid bundle controller PeerId")?;
        if bundle.controller_signing_key.len() > 256 {
            return Err("invalid bundle signing key".into());
        }
        let pin = libp2p::identity::PublicKey::try_decode_protobuf(
            &hex_decode(&bundle.controller_signing_key)
                .map_err(|_| "invalid bundle signing key")?,
        )
        .map_err(|_| "invalid bundle signing key")?;
        // The bundle PeerId is the stable logical authority, not a replica transport identity.
        if pin.to_peer_id() != peer {
            return Err("bundle signing key does not match controller PeerId".into());
        }
        bundle
            .private_network_key
            .parse::<libp2p::pnet::PreSharedKey>()
            .map_err(|_| "invalid bundle private network key")?;
        for (addresses, singleton) in [
            (&bundle.bootstrap_addresses, true),
            (&bundle.discovery_bootstrap_addresses, false),
        ] {
            for address in addresses {
                if address.len() > 256 {
                    return Err("invalid bundle address".into());
                }
                let address: libp2p::Multiaddr =
                    address.parse().map_err(|_| "invalid bundle address")?;
                let Some(libp2p::multiaddr::Protocol::P2p(endpoint_peer)) = address.iter().last()
                else {
                    return Err("bundle address must end in PeerId".into());
                };
                cat4igp_shared::discovery::ControllerEndpoint {
                    peer_id: endpoint_peer,
                    addresses: vec![address],
                }
                .validate()?;
                if singleton
                    && endpoint_peer != peer
                    && bundle.discovery_bootstrap_addresses.is_empty()
                {
                    return Err(
                        "bundle control addresses must use singleton controller PeerId".into(),
                    );
                }
            }
        }
        let mut config = Self::new(
            bundle.bootstrap_addresses[0].clone(),
            bundle.invitation_code,
        );
        config.controller_peer_id = Some(peer.to_string());
        config.controller_signing_key = Some(bundle.controller_signing_key);
        config.control_network_id = bundle.network_id;
        config.control_private_network_key = Some(bundle.private_network_key);
        config.control_bootstrap_addresses = bundle.bootstrap_addresses;
        config.discovery_bootstrap_addresses = bundle.discovery_bootstrap_addresses;
        Ok(config)
    }

    /// Create a new server configuration
    pub fn new(address: String, invite_code: String) -> Self {
        Self {
            address,
            invite_code,
            enrollment_bootstrap_addresses: Vec::new(),
            enrollment_discovery_bootstrap_addresses: None,
            enrollment_node_name: None,
            wg_private_key: None,
            wg_public_key: None,
            control_private_key: None,
            control_encryption_private_key: None,
            controller_peer_id: None,
            controller_signing_key: None,
            controller_encryption_key: None,
            control_bootstrap_addresses: Vec::new(),
            discovery_bootstrap_addresses: Vec::new(),
            discovery_proof: None,
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
        self.save_inner(
            data_dir,
            #[cfg(test)]
            |_| Ok(()),
        )
    }

    fn save_inner(
        &self,
        data_dir: &Path,
        #[cfg(test)] mut fault: impl FnMut(&str) -> io::Result<()>,
    ) -> io::Result<()> {
        fs::create_dir_all(data_dir)?;
        // Fail before publication if the directory cannot be opened for its durability barrier.
        let directory = fs::File::open(data_dir)?;
        let config_path = data_dir.join("server.json");
        let content = serde_json::to_string_pretty(&self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        use std::io::Write;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let temporary = data_dir.join(format!(".server-{:032x}.tmp", rand::random::<u128>()));
        // Cleanup only a temporary file this call actually created.
        let mut file = options.open(&temporary)?;
        let result = (|| -> io::Result<()> {
            #[cfg(test)]
            {
                file.write_all(&content.as_bytes()[..content.len() / 2])?;
                fault("partial_write")?;
                file.write_all(&content.as_bytes()[content.len() / 2..])?;
            }
            #[cfg(not(test))]
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
            #[cfg(test)]
            fault("publish")?;
            fs::rename(&temporary, &config_path)?;
            #[cfg(test)]
            fault("parent_sync")?;
            // A failure here is an uncertain durability outcome, not grounds to roll back
            // a complete published identity or report success.
            directory.sync_all()?;
            #[cfg(test)]
            fault("durable")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result?;
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
#[path = "server_test.rs"]
mod tests;
