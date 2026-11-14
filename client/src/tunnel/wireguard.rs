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
    applied_endpoint: Option<Option<SocketAddr>>,
    local_bridge: bool,
    listen_port: Option<u16>,
    force_userspace: bool,
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
            applied_endpoint: None,
            local_bridge: false,
            listen_port,
            force_userspace: false,
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
            applied_endpoint: None,
            local_bridge: false,
            listen_port,
            force_userspace: true,
        }
    }

    pub fn set_peer_endpoint(&mut self, endpoint: SocketAddr) {
        self.peer_endpoint = Some(endpoint);
    }

    pub fn set_local_bridge_endpoint(&mut self, endpoint: SocketAddr) {
        self.peer_endpoint = Some(endpoint);
        self.local_bridge = true;
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

    pub fn matches_public_key(&self, expected: &str) -> io::Result<Option<bool>> {
        let name = InterfaceName::from_str(&self.interface).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
        let backend = if self.force_userspace { Backend::Userspace } else { BACKEND };
        match Device::get(&name, backend) {
            Ok(device) => Ok(Some(device.public_key.is_some_and(|key| key.to_base64() == expected))),
            Err(e) if e.kind() == io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ENODEV) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn destroy_with_public_key(&mut self, expected: &str) -> Result<(), Box<dyn std::error::Error>> {
        match self.matches_public_key(expected)? {
            None => return Ok(()),
            Some(false) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, "WireGuard interface belongs to another key").into()),
            Some(true) => {}
        }
        let name = InterfaceName::from_str(&self.interface).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
        let backend = if self.force_userspace { Backend::Userspace } else { BACKEND };
        cleanup_result(Device::get(&name, backend).and_then(Device::delete))?;
        Ok(())
    }

}


fn should_update_endpoint(peer_exists: bool, applied: Option<Option<SocketAddr>>, desired: Option<SocketAddr>, recent: bool, local_bridge: bool, actual: Option<SocketAddr>) -> bool {
    desired.is_some() && ((!peer_exists || (applied.is_some_and(|previous| previous != desired) && !recent)) || (local_bridge && actual != desired))
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

        let backend = if self.force_userspace { Backend::Userspace } else { BACKEND };
        let peer = match Device::get(&ifname, backend) {
            Ok(device) => {
                let local = wireguard_control::Key::from_base64(&self.local_private_key).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid local WireGuard private key"))?;
                if device.public_key != Some(local.get_public()) || device.peers.iter().any(|peer| peer.config.public_key.to_base64() != self.peer_public_key) {
                    return Err(io::Error::new(io::ErrorKind::AlreadyExists, "WireGuard interface has a different identity or peer").into());
                }
                device.peers.into_iter().find(|peer| peer.config.public_key.to_base64() == self.peer_public_key)
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ENODEV) => None,
            Err(error) => return Err(error.into()),
        };
        let recent = peer.as_ref().and_then(|peer| peer.stats.last_handshake_time)
            .is_some_and(|time| time.elapsed().map_or(true, |age| age.as_secs() <= 180));
        let update_endpoint = should_update_endpoint(peer.is_some(), self.applied_endpoint, self.peer_endpoint, recent, self.local_bridge, peer.as_ref().and_then(|peer| peer.config.endpoint));
        if update_endpoint {
            if let Some(endpoint) = self.peer_endpoint { peer_config = peer_config.set_endpoint(endpoint); }
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
        if update_endpoint || self.applied_endpoint.is_none() {
            self.applied_endpoint = Some(self.peer_endpoint);
        }

        Ok(())
    }

    async fn destroy(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let ifname = InterfaceName::from_str(self.interface.as_str()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "failed to parse interface name",
            )
        })?;
        #[cfg(target_os = "linux")]
        if !self.force_userspace {
            let name = std::ffi::CString::new(self.interface.as_str())?;
            // Kernel WireGuard may report ENODEV instead of ErrorKind::NotFound.
            if unsafe { libc::if_nametoindex(name.as_ptr()) } == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENODEV) {
                    return Ok(());
                }
                return Err(error.into());
            }
        }
        let expected = wireguard_control::Key::from_base64(&self.local_private_key)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid local WireGuard private key"))?
            .get_public().to_base64();
        self.destroy_with_public_key(&expected).await
    }

    fn is_ift_created(&self) -> bool {
        let name = &InterfaceName::from_str(self.interface.as_str());
        if let Ok(ifname) = name {
            Device::get(
                ifname,
                if self.force_userspace {
                    Backend::Userspace
                } else {
                    BACKEND
                },
            )
            .is_ok()
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

fn cleanup_result(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changed_endpoint_waits_for_stale_handshake() {
        let old = Some("192.0.2.1:51820".parse().unwrap());
        let new = Some("198.51.100.2:51820".parse().unwrap());
        assert!(should_update_endpoint(false, None, old, false, false, None));
        assert!(!should_update_endpoint(true, None, old, false, false, new));
        assert!(!should_update_endpoint(true, Some(old), old, false, false, old));
        assert!(!should_update_endpoint(true, Some(old), new, true, false, old));
        assert!(should_update_endpoint(true, Some(old), new, false, false, old));
        assert!(should_update_endpoint(true, None, new, true, true, old));
        assert!(!should_update_endpoint(true, None, new, true, true, new));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires an isolated network namespace and CAP_NET_ADMIN"]
    async fn reconciliation_preserves_kernel_roaming() {
        let private = wireguard_control::Key::generate_private();
        let peer = wireguard_control::Key::generate_private().get_public();
        let name = format!("roam{:x}", std::process::id());
        let mut tunnel = WireGuardTunnel::new(name.clone(), private.to_base64(), peer.to_base64(), Some("192.0.2.1:51820".parse().unwrap()), Some(0));
        tunnel.setup().await.unwrap();
        let ifname = InterfaceName::from_str(&name).unwrap();
        let roamed = "198.51.100.2:51820".parse().unwrap();
        DeviceUpdate::new().add_peer(PeerConfigBuilder::new(&peer).set_endpoint(roamed)).apply(&ifname, Backend::Kernel).unwrap();
        tunnel.setup().await.unwrap();
        assert_eq!(Device::get(&ifname, Backend::Kernel).unwrap().peers[0].config.endpoint, Some(roamed));
        let changed = "203.0.113.3:51820".parse().unwrap();
        tunnel.set_peer_endpoint(changed);
        tunnel.setup().await.unwrap();
        assert_eq!(Device::get(&ifname, Backend::Kernel).unwrap().peers[0].config.endpoint, Some(changed));
        tunnel.destroy().await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires an isolated network namespace and CAP_NET_ADMIN"]
    async fn conflicting_interface_is_not_modified_or_destroyed() {
        let private = wireguard_control::Key::generate_private();
        let peer = wireguard_control::Key::generate_private().get_public();
        let name = format!("own{:x}", std::process::id());
        let mut owner = WireGuardTunnel::new(name.clone(), private.to_base64(), peer.to_base64(), None, None);
        owner.setup().await.unwrap();
        let mut other = WireGuardTunnel::new(name.clone(), wireguard_control::Key::generate_private().to_base64(), peer.to_base64(), None, None);
        assert!(other.setup().await.is_err());
        assert!(other.destroy().await.is_err());
        assert_eq!(Device::get(&InterfaceName::from_str(&name).unwrap(), Backend::Kernel).unwrap().public_key, Some(private.get_public()));
        owner.destroy().await.unwrap();
    }


    #[tokio::test]
    async fn teardown_absent_and_preserve_errors() {
        assert!(cleanup_result(Ok(())).is_ok());
        assert!(cleanup_result(Err(io::ErrorKind::NotFound.into())).is_ok());
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::Other,
        ] {
            assert_eq!(cleanup_result(Err(kind.into())).unwrap_err().kind(), kind);
        }
        let mut tunnel = WireGuardTunnel::new_userspace(
            format!("t{:x}", std::process::id()),
            wireguard_control::Key::generate_private().to_base64(),
            String::new(),
            None,
            None,
        );
        tunnel.destroy().await.unwrap();
        tunnel.destroy().await.unwrap();
        #[cfg(target_os = "linux")]
        {
            tunnel.force_userspace = false;
            tunnel.destroy().await.unwrap();
            tunnel.destroy().await.unwrap();
        }
    }
}
