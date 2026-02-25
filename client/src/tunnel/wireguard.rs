use std::io;
use std::{net::SocketAddr, str::FromStr};
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, PeerConfigBuilder};

use crate::{
    interface::{IPV4_DEFAULT, IPV6_DEFAULT},
    tunnel::{TunnelType, shared::Tunnel},
};

#[cfg(target_os = "linux")]
const BACKEND: Backend = Backend::Kernel;
#[cfg(target_os = "openbsd")]
const BACKEND: Backend = Backend::OpenBSD;
#[cfg(not(any(target_os = "linux", target_os = "openbsd")))]
const BACKEND: Backend = Backend::Userspace;

pub struct WireGuardTunnel {
    interface: String,
    local_private_key: String,
    peer_public_key: String,
    peer_endpoint: Option<SocketAddr>,
    listen_port: Option<u16>,
    force_userspace: bool
}

impl WireGuardTunnel {
    pub fn new(
        interface: String,
        local_private_key: String,
        peer_public_key: String,
        peer_endpoint: Option<SocketAddr>,
        listen_port: Option<u16>,
    ) -> Self {
        Self {
            interface,
            local_private_key,
            peer_public_key,
            peer_endpoint,
            listen_port,
            force_userspace: false
        }
    }

    pub fn new_userspace(
        interface: String,
        local_private_key: String,
        peer_public_key: String,
        peer_endpoint: Option<SocketAddr>,
        listen_port: Option<u16>,
    ) -> Self {
        Self {
            interface,
            local_private_key,
            peer_public_key,
            peer_endpoint,
            listen_port,
            force_userspace: true
        }
    }

    pub fn set_peer_endpoint(&mut self, endpoint: SocketAddr) {
        self.peer_endpoint = Some(endpoint);
    }

    pub fn set_listen_port(&mut self, port: u16) {
        self.listen_port = Some(port);
    }

    pub fn get_peer_endpoint(&self) -> Option<SocketAddr> {
        self.peer_endpoint
    }

    pub fn get_listen_port(&self) -> Option<u16> {
        self.listen_port
    }

    pub fn get_local_private_key(&self) -> &str {
        &self.local_private_key
    }
}

impl Tunnel for WireGuardTunnel {
    fn is_connected(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if let Ok(device) = Device::get(
            &InterfaceName::from_str(self.interface.as_str()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "failed to parse interface name",
                )
            })?,
            if self.force_userspace {
                Backend::Userspace
            } else {
                BACKEND
            },
        ) {
            // check connected status by comparing last handshake time of the peer with current time. it should be 3 minutes (180 seconds) or less if the tunnel is active
            if let Some(peer) = device
                .peers
                .iter()
                .find(|p| p.config.public_key.to_base64() == self.peer_public_key)
            {
                if let Some(last_handshake) = peer.stats.last_handshake_time {
                    return Ok(last_handshake.elapsed().unwrap_or_default().as_secs() <= 180);
                }
            }
        }
        Ok(false)
    }

    async fn get_mtu(&self) -> Result<u32, Box<dyn std::error::Error>> {
        crate::interface::get_mtu(self.interface.clone()).await
    }

    async fn setup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let ifname = InterfaceName::from_str(self.interface.as_str()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "failed to parse interface name",
            )
        })?;

        self.interface = ifname.as_str_lossy().to_string();

        let mut device = DeviceUpdate::new();

        let mut peer_config = PeerConfigBuilder::new(
            &wireguard_control::Key::from_base64(self.peer_public_key.as_str()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "failed to parse peer base64 public key",
                )
            })?,
        )
        .add_allowed_ip(IPV4_DEFAULT, 0)
        .add_allowed_ip(IPV6_DEFAULT, 0)
        .set_persistent_keepalive_interval(25);

        if let Some(endpoint) = &self.peer_endpoint {
            peer_config = peer_config.set_endpoint(endpoint.clone());
        }

        device = device.add_peer(peer_config);

        if let Some(listen_port) = self.listen_port {
            device = device.set_listen_port(listen_port);
        }

        device
            .set_private_key(
                wireguard_control::Key::from_base64(self.local_private_key.as_str()).map_err(
                    |_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "failed to parse local base64 private key",
                        )
                    },
                )?,
            )
            .apply(
                &ifname,
                if self.force_userspace {
                    Backend::Userspace
                } else {
                    BACKEND
                },
            )?;

        Ok(())
    }

    async fn destroy(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        Device::get(
            &InterfaceName::from_str(self.interface.as_str()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "failed to parse interface name",
                )
            })?,
            if self.force_userspace {
                Backend::Userspace
            } else {
                BACKEND
            },
        )?
        .delete()?;

        Ok(())
    }

    fn is_ift_created(&self) -> bool {
        let name = &InterfaceName::from_str(self.interface.as_str());
        if let Ok(ifname) = name {
            Device::get(ifname, if self.force_userspace { Backend::Userspace } else { BACKEND }).is_ok()
        } else {
            false
        }
    }

    fn get_type(&self) -> TunnelType {
        TunnelType::WireGuard
    }

    fn get_interface_name(&self) -> &str {
        self.interface.as_str()
    }
}
