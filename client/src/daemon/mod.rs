use futures_util::StreamExt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, mpsc};

use crate::config::ClientConfig;
use crate::config::ServerConfig;
use cat4igp_shared::{
    control::{ControlRequest, ControlResponse, MessageMeta, TopologySnapshot, TunnelAnswer},
    custom_type::WireguardAnswered,
};

pub mod client;
pub mod control;
mod daemon_memory;
pub mod protocol;

use protocol::{DaemonRequest, DaemonResponse, SharedSecret};

/// Daemon state and management
pub struct Daemon {
    config: Arc<ClientConfig>,
    server_config: Arc<Mutex<Option<ServerConfig>>>,
    secret: SharedSecret,
    memory: Arc<daemon_memory::DaemonMemory>,
    control_sync: Arc<Mutex<()>>,
    control_plane: Arc<std::sync::Mutex<Option<control::ControlPlane>>>,
    tasks: Arc<std::sync::Mutex<tokio::task::JoinSet<()>>>,
    stopping: Arc<tokio::sync::Notify>,
    stopped: Arc<std::sync::atomic::AtomicBool>,
}

// ponytail: advisory lock coordinates shipped daemons; the socket directory must be trusted.
struct RunGuard<'a> {
    daemon: &'a Daemon,
    _lock: std::fs::File,
    socket: Option<(u64, u64)>,
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        let mut tasks = self.daemon.tasks.lock().unwrap();
        self.daemon
            .stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        tasks.abort_all();
        if let Some(plane) = self.daemon.control_plane.lock().unwrap().take() {
            plane.stop();
        }
        if let Some(identity) = self.socket {
            if std::fs::symlink_metadata(self.daemon.get_socket_path())
                .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == identity)
            {
                let _ = std::fs::remove_file(self.daemon.get_socket_path());
            }
        }
    }
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
                let secret = SharedSecret { secret: new_secret };
                secret.save(&config.data_dir)?;
                secret
            }
        };

        // Load server configuration if it exists and ensure local WireGuard keypair is persisted.
        let mut server_config = match ServerConfig::load(&config.data_dir) {
            Ok(config) => Some(config),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if let Some(cfg) = server_config.as_mut() {
            cfg.ensure_wireguard_keypair()?;
            cfg.ensure_control_keypair()?;
            cfg.save(&config.data_dir)?;
        }

        let cfg_clone = config.clone();

        Ok(Daemon {
            config: Arc::new(config),
            server_config: Arc::new(Mutex::new(server_config)),
            secret,
            memory: Arc::new(daemon_memory::DaemonMemory::new(cfg_clone)),
            control_sync: Arc::new(Mutex::new(())),
            control_plane: Arc::new(std::sync::Mutex::new(None)),
            tasks: Arc::new(std::sync::Mutex::new(tokio::task::JoinSet::new())),
            stopping: Arc::new(tokio::sync::Notify::new()),
            stopped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
            } => self.handle_set_server(address, invite_code).await,
            DaemonRequest::Register {
                address,
                invite_code,
            } => self.handle_register(address, invite_code).await,
            DaemonRequest::RegisterBundle { bundle } => match ServerConfig::from_bundle(&bundle) {
                Ok(config) => self.register_config(config).await,
                Err(error) => DaemonResponse::Error(error),
            },
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
                .is_some_and(|s| s.controller_peer_id.is_some());
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

    async fn handle_set_server(&self, address: String, invite_code: String) -> DaemonResponse {
        let mut server_config = self.server_config.lock().await;
        let mut config = ServerConfig {
            address: address.clone(),
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
            control_private_network_key: self.config.control_private_network_key.clone(),
            topology_revision: 0,
            control_node_id: None,
            control_network_id: self.config.control_network_id.clone(),
        };

        if let Err(e) = config.ensure_wireguard_keypair() {
            return DaemonResponse::Error(format!("Failed to generate WireGuard keypair: {}", e));
        }
        if let Err(e) = config.ensure_control_keypair() {
            return DaemonResponse::Error(format!("Failed to generate control identity: {}", e));
        }
        if let Err(e) = config.ensure_control_encryption_key() {
            return DaemonResponse::Error(format!(
                "Failed to generate control encryption identity: {}",
                e
            ));
        }

        if let Err(e) = config.save(&self.config.data_dir) {
            return DaemonResponse::Error(format!("Failed to save server config: {}", e));
        }

        *server_config = Some(config);
        DaemonResponse::Ok(Some("Server configuration set".to_string()))
    }

    async fn handle_register(&self, address: String, invite_code: String) -> DaemonResponse {
        let mut config = ServerConfig {
            address: address.clone(),
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
            control_private_network_key: self.config.control_private_network_key.clone(),
            topology_revision: 0,
            control_node_id: None,
            control_network_id: self.config.control_network_id.clone(),
        };

        config.control_bootstrap_addresses = self.config.control_bootstrap_addresses.clone();
        if !config.control_bootstrap_addresses.contains(&address) {
            config.control_bootstrap_addresses.insert(0, address);
        }
        self.register_config(config).await
    }

    async fn register_config(&self, mut config: ServerConfig) -> DaemonResponse {
        let _registration = self.control_sync.lock().await;
        if self
            .server_config
            .lock()
            .await
            .as_ref()
            .is_some_and(|config| config.control_node_id.is_some())
        {
            return DaemonResponse::Error(
                "Server already configured; refusing to overwrite enrollment".into(),
            );
        }
        if let Some(pending) = self.server_config.lock().await.as_ref() {
            let original_seeds = if pending.enrollment_bootstrap_addresses.is_empty() {
                &pending.control_bootstrap_addresses
            } else {
                &pending.enrollment_bootstrap_addresses
            };
            if pending.invite_code == config.invite_code
                && original_seeds == &config.control_bootstrap_addresses
                && pending.controller_signing_key == config.controller_signing_key
                && pending.control_network_id == config.control_network_id
                && pending.control_private_network_key == config.control_private_network_key
                && pending
                    .enrollment_discovery_bootstrap_addresses
                    .as_ref()
                    .unwrap_or(&pending.discovery_bootstrap_addresses)
                    == &config.discovery_bootstrap_addresses
            {
                config = pending.clone();
            } else {
                return DaemonResponse::Error(
                    "Pending registration differs; refusing to overwrite identity".into(),
                );
            }
        }

        if let Err(e) = config.ensure_wireguard_keypair() {
            return DaemonResponse::Error(format!("Failed to generate WireGuard keypair: {}", e));
        }
        if let Err(e) = config.ensure_control_keypair() {
            return DaemonResponse::Error(format!("Failed to generate control identity: {}", e));
        }
        if let Err(e) = config.ensure_control_encryption_key() {
            return DaemonResponse::Error(format!(
                "Failed to generate control encryption identity: {}",
                e
            ));
        }

        if config.enrollment_bootstrap_addresses.is_empty() {
            config.enrollment_bootstrap_addresses = config.control_bootstrap_addresses.clone();
        }
        // ponytail: legacy pending files cannot reconstruct pre-discovery seeds; fail closed on mismatch.
        config
            .enrollment_discovery_bootstrap_addresses
            .get_or_insert_with(|| config.discovery_bootstrap_addresses.clone());
        let node_name = config
            .enrollment_node_name
            .get_or_insert_with(|| {
                // ponytail: old pending files lack the original name; preserve it from this upgrade onward.
                std::env::var("HOSTNAME").unwrap_or_else(|_| "cat4igp-client".to_string())
            })
            .clone();
        // Keep the identity even if discovery fails before any enrollment is sent.
        if let Err(error) = config.save(&self.config.data_dir) {
            return DaemonResponse::Error(format!("Failed to save pending registration: {error}"));
        }
        *self.server_config.lock().await = Some(config.clone());
        if let Err(error) = control::refresh_discovery(&mut config).await {
            return DaemonResponse::Error(format!("Registration discovery failed: {error}"));
        }
        // Persist verified roster and stable enrollment identity before releasing the invite.
        if let Err(error) = config.save(&self.config.data_dir) {
            return DaemonResponse::Error(format!("Failed to save pending registration: {error}"));
        }
        *self.server_config.lock().await = Some(config.clone());
        let bootstrap_addresses = config.control_bootstrap_addresses.clone();
        let registration = match control::enroll(&mut config, &bootstrap_addresses, node_name).await
        {
            Ok(response) => response,
            Err(e) => {
                return DaemonResponse::Error(format!("Registration failed: {}", e));
            }
        };
        if !matches!(
            registration,
            cat4igp_shared::control::ControlResponse::Enrolled(_)
        ) {
            return DaemonResponse::Error("Registration rejected by controller".to_string());
        }

        config.invite_code.clear();
        if let Err(e) = config.save(&self.config.data_dir) {
            return DaemonResponse::Error(format!("Failed to save server config: {}", e));
        }

        let mut server_config = self.server_config.lock().await;
        *server_config = Some(config);
        drop(server_config);
        if let Err(error) = self.start_control_plane().await {
            eprintln!("[daemon] control plane start failed: {error}");
            self.memory.set_last_poll_error(Some(error)).await;
        }

        DaemonResponse::Ok(Some("Registration successful".to_string()))
    }

    async fn handle_restart(&self) -> DaemonResponse {
        // In a real implementation, this would restart the daemon process
        DaemonResponse::Ok(Some("Restart signal sent".to_string()))
    }

    async fn handle_shutdown(&self) -> DaemonResponse {
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
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
        // Create parent directory if it doesn't exist
        if let Some(parent) = self.config.daemon_socket.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.config.daemon_socket.with_extension("sock.lock"))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut guard = RunGuard {
            daemon: self,
            _lock: lock,
            socket: None,
        };
        match std::fs::symlink_metadata(&self.config.daemon_socket) {
            Ok(metadata) => {
                if !metadata.file_type().is_socket() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "socket path is not a socket",
                    ));
                }
                match UnixStream::connect(&self.config.daemon_socket).await {
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::AddrInUse,
                            "daemon socket is active",
                        ));
                    }
                    Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                        std::fs::remove_file(&self.config.daemon_socket)?;
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(&self.config.daemon_socket)?;
        let metadata = std::fs::symlink_metadata(&self.config.daemon_socket)?;
        guard.socket = Some((metadata.dev(), metadata.ino()));
        self.stopped
            .store(false, std::sync::atomic::Ordering::SeqCst);
        println!("✓ Listening on socket: {:?}", self.config.daemon_socket);

        if let Err(error) = self.start_control_plane().await {
            eprintln!("[daemon] control plane start failed: {error}");
            self.memory.set_last_poll_error(Some(error)).await;
        }
        let daemon_for_control = self.clone_for_handler();
        self.tasks.lock().unwrap().spawn(async move {
            daemon_for_control.run_control_update_loop().await;
        });
        #[cfg(target_os = "linux")]
        {
            let daemon_for_network = self.clone_for_handler();
            self.tasks.lock().unwrap().spawn(async move {
                daemon_for_network.run_network_change_loop().await;
            });
        }

        loop {
            let accepted = tokio::select! {
                _ = self.stopping.notified() => break,
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((stream, _)) => {
                    let daemon = self.clone_for_handler();
                    let mut tasks = self.tasks.lock().unwrap();
                    while tasks.try_join_next().is_some() {}
                    tasks.spawn(async move {
                        if let Err(e) = handle_client(stream, daemon).await {
                            eprintln!("Error handling client: {}", e);
                        }
                    });
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        let mut tasks = {
            let mut tasks = self.tasks.lock().unwrap();
            self.stopped
                .store(true, std::sync::atomic::Ordering::SeqCst);
            std::mem::take(&mut *tasks)
        };
        tasks.shutdown().await;
        if let Some(plane) = self.control_plane.lock().unwrap().take() {
            plane.stop();
        }
        Ok(())
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
            control_sync: Arc::clone(&self.control_sync),
            control_plane: Arc::clone(&self.control_plane),
            tasks: Arc::clone(&self.tasks),
            stopping: Arc::clone(&self.stopping),
            stopped: Arc::clone(&self.stopped),
        })
    }

    async fn start_control_plane(&self) -> Result<(), String> {
        if self.control_plane.lock().unwrap().is_some() {
            return Ok(());
        }
        let mut config = self
            .server_config
            .lock()
            .await
            .clone()
            .ok_or_else(|| "control plane is not enrolled".to_string())?;
        // Pending enrollment must not discover/save concurrently with RegisterBundle.
        if config.control_node_id.is_none() {
            return Err("control plane is not enrolled".to_string());
        }
        let (updates, mut received) = mpsc::channel(8);
        control::refresh_discovery(&mut config).await?;
        config
            .save(&self.config.data_dir)
            .map_err(|error| error.to_string())?;
        *self.server_config.lock().await = Some(config.clone());
        let mut tasks = self.tasks.lock().unwrap();
        if self.stopped.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("daemon stopped".into());
        }
        if self.control_plane.lock().unwrap().is_some() {
            return Ok(());
        }
        let plane = control::start(config, updates, Arc::clone(&self.server_config))?;
        *self.control_plane.lock().unwrap() = Some(plane);
        let daemon = self.clone_for_handler();
        tasks.spawn(async move {
            while let Some(snapshot) = received.recv().await {
                if let Err(error) = daemon.apply_pushed_snapshot(snapshot).await {
                    eprintln!("[daemon] pushed topology apply failed: {error}");
                    daemon.memory.set_last_poll_error(Some(error)).await;
                }
            }
        });
        Ok(())
    }

    async fn run_control_update_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Err(error) = self.sync_control_snapshot().await {
                if error != "control plane is not enrolled" {
                    eprintln!("[daemon] control snapshot sync failed: {error}");
                    self.memory.set_last_poll_error(Some(error)).await;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn run_network_change_loop(self: Arc<Self>) {
        let (connection, _, mut messages) = match rtnetlink::new_multicast_connection(&[
            rtnetlink::MulticastGroup::Link,
            rtnetlink::MulticastGroup::Ipv4Ifaddr,
            rtnetlink::MulticastGroup::Ipv6Ifaddr,
        ]) {
            Ok(connection) => connection,
            Err(error) => {
                eprintln!("[daemon] network change watcher unavailable: {error}");
                return;
            }
        };
        tokio::pin!(connection);
        while tokio::select! {
            _ = &mut connection => false,
            message = messages.next() => message.is_some(),
        } {
            // ponytail: track interface indexes to skip CAT interfaces if event volume becomes material.
            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Err(error) = self.sync_control_snapshot().await {
                if error != "control plane is not enrolled" {
                    eprintln!("[daemon] network-change endpoint refresh failed: {error}");
                }
            }
        }
    }

    async fn apply_pushed_snapshot(&self, snapshot: TopologySnapshot) -> Result<(), String> {
        let _sync = self.control_sync.lock().await;
        let mut config = self
            .server_config
            .lock()
            .await
            .clone()
            .ok_or_else(|| "control plane is not enrolled".to_string())?;
        if snapshot.node_id != config.control_node_id.unwrap_or_default()
            || snapshot.revision <= config.topology_revision
        {
            return Ok(());
        }
        let private_key = config
            .wg_private_key
            .as_deref()
            .filter(|key| !key.is_empty())
            .ok_or_else(|| "wireguard private key missing from server configuration".to_string())?
            .to_owned();
        self.answer_pending_tunnels(&mut config, &snapshot).await?;
        self.memory
            .apply_topology_snapshot(snapshot.clone(), &private_key)
            .await?;
        self.report_connectivity().await;
        config.topology_revision = snapshot.revision;
        config
            .save(&self.config.data_dir)
            .map_err(|error| error.to_string())?;
        *self.server_config.lock().await = Some(config);
        if self.memory.disconnected_tunnel_ids().await.is_empty() {
            self.memory.set_last_poll_error(None).await;
        }
        Ok(())
    }

    async fn sync_control_snapshot(&self) -> Result<(), String> {
        self.start_control_plane().await?;
        let _sync = self.control_sync.lock().await;
        let mut config = self
            .server_config
            .lock()
            .await
            .clone()
            .ok_or_else(|| "control plane is not enrolled".to_string())?;
        if config.controller_peer_id.is_none() || config.control_bootstrap_addresses.is_empty() {
            return Err("control plane is not enrolled".to_string());
        }

        control::refresh_discovery(&mut config).await?;
        config
            .save(&self.config.data_dir)
            .map_err(|error| error.to_string())?;
        *self.server_config.lock().await = Some(config.clone());

        let plane = self
            .control_plane
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "control plane is not enrolled".to_string())?;
        let response = plane
            .request(cat4igp_shared::control::ControlRequest::Snapshot)
            .await?;
        config
            .save(&self.config.data_dir)
            .map_err(|error| error.to_string())?;
        *self.server_config.lock().await = Some(config.clone());

        match response {
            ControlResponse::SnapshotEnvelope(envelope) => {
                let signing_key = config
                    .controller_signing_key
                    .as_deref()
                    .ok_or_else(|| "controller signing key is not enrolled".to_string())?;
                let encryption_key = config
                    .control_encryption_private_key
                    .as_deref()
                    .ok_or_else(|| "control encryption identity is not enrolled".to_string())?;
                let node_id = config
                    .control_node_id
                    .ok_or_else(|| "control node id is not enrolled".to_string())?;
                let snapshot = cat4igp_shared::control::open_topology_snapshot(
                    signing_key,
                    encryption_key,
                    &config.control_network_id,
                    node_id,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| "system clock is before Unix epoch".to_string())?
                        .as_millis()
                        .try_into()
                        .map_err(|_| "system clock is out of range".to_string())?,
                    &envelope,
                )
                .map_err(str::to_string)?;
                if snapshot.revision < config.topology_revision {
                    return Err("controller returned a stale topology snapshot".to_string());
                }
                let private_key = config
                    .wg_private_key
                    .as_deref()
                    .filter(|key| !key.is_empty())
                    .ok_or_else(|| {
                        "wireguard private key missing from server configuration".to_string()
                    })?
                    .to_owned();
                self.answer_pending_tunnels(&mut config, &snapshot).await?;
                self.memory
                    .apply_topology_snapshot(snapshot.clone(), &private_key)
                    .await?;
                self.report_connectivity().await;
                config.topology_revision = snapshot.revision;
                config
                    .save(&self.config.data_dir)
                    .map_err(|error| error.to_string())?;
                *self.server_config.lock().await = Some(config);
                if self.memory.disconnected_tunnel_ids().await.is_empty() {
                    self.memory.set_last_poll_error(None).await;
                }
                Ok(())
            }
            ControlResponse::Rejected(error) => Err(error),
            _ => Err("unexpected control response".to_string()),
        }
    }

    async fn answer_pending_tunnels(
        &self,
        config: &mut ServerConfig,
        snapshot: &TopologySnapshot,
    ) -> Result<(), String> {
        for tunnel in snapshot.tunnels.iter().filter(|tunnel| {
            matches!(
                tunnel.local_answered,
                WireguardAnswered::Unanswered | WireguardAnswered::Answered
            )
        }) {
            let node_id = config
                .control_node_id
                .ok_or_else(|| "control node id is not enrolled".to_string())?;
            let signing_key = config
                .ensure_control_keypair()
                .map_err(|error| error.to_string())?;
            let controller_key = config
                .controller_encryption_key
                .as_deref()
                .ok_or_else(|| "controller encryption key is not enrolled".to_string())?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "system clock is before Unix epoch".to_string())?
                .as_millis()
                .try_into()
                .map_err(|_| "system clock is out of range".to_string())?;
            let (endpoint, decline_type) = if tunnel.faketcp {
                if matches!(tunnel.local_answered, WireguardAnswered::Unanswered) {
                    (None, Some(4))
                } else {
                    continue;
                }
            } else {
                match self.local_endpoint(tunnel).await {
                    Ok(endpoint) => {
                        let endpoint = endpoint.to_string();
                        if matches!(tunnel.local_answered, WireguardAnswered::Answered)
                            && !self
                                .memory
                                .endpoint_changed(tunnel.tunnel_id, &endpoint)
                                .await
                        {
                            continue;
                        }
                        (Some(endpoint), None)
                    }
                    Err(error) => {
                        eprintln!(
                            "[daemon] tunnel {} cannot advertise endpoint: {error}",
                            tunnel.tunnel_id
                        );
                        if matches!(tunnel.local_answered, WireguardAnswered::Unanswered) {
                            self.memory.release_tunnel_port(tunnel.tunnel_id).await;
                            (None, Some(3))
                        } else {
                            continue;
                        }
                    }
                }
            };
            let answer = TunnelAnswer {
                tunnel_id: tunnel.tunnel_id,
                endpoint,
                decline_type,
            };
            let plane = self
                .control_plane
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| "control plane is not enrolled".to_string())?;
            let response = plane
                .request(ControlRequest::TunnelAnswerEnvelope(
                    cat4igp_shared::control::seal_tunnel_answer(
                        &signing_key,
                        controller_key,
                        MessageMeta {
                            message_id: format!("{:032x}", rand08::random::<u128>()),
                            network_id: config.control_network_id.clone(),
                            recipient_node_id: node_id,
                            issued_at_ms: now,
                            expires_at_ms: now + 60_000,
                            topology_revision: config.topology_revision,
                        },
                        &answer,
                    )
                    .map_err(str::to_string)?,
                ))
                .await?;
            match response {
                ControlResponse::Accepted => {
                    if let Some(endpoint) = answer.endpoint {
                        self.memory
                            .remember_endpoint(tunnel.tunnel_id, endpoint)
                            .await;
                    }
                }
                ControlResponse::Rejected(error) => {
                    return Err(format!(
                        "tunnel {} answer rejected: {error}",
                        tunnel.tunnel_id
                    ));
                }
                _ => {
                    return Err(format!(
                        "unexpected answer response for tunnel {}",
                        tunnel.tunnel_id
                    ));
                }
            }
        }
        Ok(())
    }

    async fn report_connectivity(&self) {
        let disconnected = self.memory.disconnected_tunnel_ids().await;
        if disconnected.is_empty() {
            return;
        }
        self.memory
            .set_last_poll_error(Some(format!(
                "direct UDP handshake pending for tunnels: {}",
                disconnected
                    .into_iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
            .await;
    }

    async fn local_endpoint(
        &self,
        tunnel: &cat4igp_shared::control::WireguardTunnelInfo,
    ) -> Result<SocketAddr, String> {
        let port = self.memory.reserve_tunnel_port(tunnel.tunnel_id).await?;
        let hostname = if tunnel.endpoint_ipv6 {
            self.config.public_hostname_ipv6.as_deref()
        } else {
            self.config.public_hostname_ipv4.as_deref()
        };
        if let Some(hostname) = hostname {
            let address = format!("{hostname}:{port}")
                .to_socket_addrs()
                .map_err(|error| format!("failed to resolve {hostname}: {error}"))?
                .find(|address| address.is_ipv6() == tunnel.endpoint_ipv6)
                .ok_or_else(|| format!("{hostname} has no requested address family"))?;
            if address.ip().is_unspecified() || address.ip().is_multicast() {
                return Err("configured endpoint is unspecified or multicast".to_string());
            }
            return Ok(address);
        }
        let mut detector = crate::network::PublicIpDetector::new();
        detector.init().await?;
        detector
            .mapped_addr_from_port(port, tunnel.endpoint_ipv6)
            .await
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

    let message: IpcMessage = serde_json::from_slice(&buffer)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid JSON: {}", e)))?;

    // Stop only after replying, and only for an authenticated Shutdown.
    let shutdown =
        matches!(message.request, DaemonRequest::Shutdown) && daemon.secret.verify(&message.secret);
    // Handle the request
    let response = daemon
        .handle_request(message.request, &message.secret)
        .await;

    // Send the response
    let response_bytes = serde_json::to_vec(&response).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to serialize response: {}", e),
        )
    })?;

    let response_len = (response_bytes.len() as u32).to_be_bytes();
    let sent = async {
        stream.write_all(&response_len).await?;
        stream.write_all(&response_bytes).await?;
        stream.flush().await
    }
    .await;
    if shutdown {
        daemon.stopping.notify_one();
    }
    sent
}

#[cfg(test)]
#[path = "daemon_test.rs"]
mod tests;
