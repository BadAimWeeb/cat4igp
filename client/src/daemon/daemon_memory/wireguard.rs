use base32::Alphabet::Crockford;
use cat4igp_libfec as FEC;
use cat4igp_shared::control::WireguardTunnelInfo;
use std::net::SocketAddr;
use std::{error::Error, sync::Arc};

use crate::daemon::daemon_memory::DaemonMemory;
use crate::tunnel::shared::Tunnel as _;

pub struct WireguardTunnelC {
    tunnel_id: i32,
    peer_node_id: i32,
    ipv6: bool,
    os_tun: crate::tunnel::wireguard::WireGuardTunnel,
    mtu: i32,
    fec: Option<Arc<FEC::PeerEngine>>,
}

impl WireguardTunnelC {
    /// DO NOT USE THIS DIRECTLY UNLESS YOU KNOW WHAT YOU ARE DOING. This is only for testing purposes. Use new_from_rest instead.
    pub fn new(
        tunnel_id: i32,
        peer_node_id: i32,
        ipv6: bool,
        mtu: i32,
        os_tun: crate::tunnel::wireguard::WireGuardTunnel,
        fec: Option<Arc<FEC::PeerEngine>>,
    ) -> Self {
        Self {
            tunnel_id,
            peer_node_id,
            ipv6,
            mtu,
            os_tun,
            fec,
        }
    }

    pub async fn new_from_rest(
        rest_info: Arc<WireguardTunnelInfo>,
        local_private_key: String,
        daemon_memory: Arc<DaemonMemory>,
    ) -> Result<(Self, u16), Box<dyn Error>> {
        let port = daemon_memory
            .reserve_tunnel_port(rest_info.tunnel_id)
            .await
            .map_err(std::io::Error::other)?;
        if let Some(peer) = rest_info
            .remote_endpoint
            .as_deref()
            .and_then(|endpoint| endpoint.parse().ok())
        {
            // ponytail: use the active WireGuard/FEC socket for retries when socket handoff is supported.
            let _ = crate::network::ports::punch_udp(port, peer).await;
        }
        let fec_res = Self::gen_new_fec(rest_info.clone(), port, &local_private_key).await?;

        let (fec, os_tun) = if let Some((fec, fec_listen_port, wg_port)) = fec_res {
            let fec1 = fec.clone();
            (
                Some(fec),
                Self::gen_new_wg_tunnel(
                    rest_info.clone(),
                    local_private_key,
                    Some(fec1),
                    wg_port,
                    fec_listen_port,
                ),
            )
        } else {
            (
                None,
                Self::gen_new_wg_tunnel(rest_info.clone(), local_private_key, None, port, 0),
            )
        };

        Ok((
            Self {
                tunnel_id: rest_info.tunnel_id,
                peer_node_id: rest_info.peer_node_id,
                ipv6: rest_info.endpoint_ipv6,
                mtu: rest_info.mtu,
                fec,
                os_tun,
            },
            port,
        ))
    }

    async fn gen_new_fec(
        rest_info: Arc<WireguardTunnelInfo>,
        port: u16,
        local_private_key: &str,
    ) -> Result<Option<(Arc<FEC::PeerEngine>, u16, u16)>, Box<dyn Error>> {
        if rest_info.fec {
            let local = wireguard_control::Key::from_base64(local_private_key)
                .map_err(|_| "invalid local WireGuard private key for FEC handshake")?;
            let remote = wireguard_control::Key::from_base64(&rest_info.public_key)
                .map_err(|_| "invalid peer WireGuard public key for FEC handshake")?;
            let psk = FEC::tunnel_psk(local.0, remote.0, rest_info.tunnel_id)
                .ok_or("invalid peer WireGuard public key for FEC handshake")?;
            let local_bind_port = crate::network::ports::get_random_udp_port()?;
            let local_app_port = crate::network::ports::get_random_udp_port()?;

            let mut cfg = FEC::Config::new(
                SocketAddr::new(
                    if rest_info.endpoint_ipv6 {
                        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                    } else {
                        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                    },
                    port,
                ),
                SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    local_bind_port,
                ),
                SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    local_app_port,
                ),
            );
            cfg.initial_peer_addr = rest_info
                .remote_endpoint
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(|_| "invalid remote endpoint")?;
            cfg.handshake_psk = Some(psk);
            Ok(Some((
                Arc::new(FEC::PeerEngine::start(cfg).await?),
                local_bind_port,
                local_app_port,
            )))
        } else {
            Ok(None)
        }
    }

    fn gen_new_wg_tunnel(
        rest_info: Arc<WireguardTunnelInfo>,
        local_private_key: String,
        fec: Option<Arc<FEC::PeerEngine>>,
        port: u16,
        fec_peerport: u16,
    ) -> crate::tunnel::wireguard::WireGuardTunnel {
        let mut bit_slice = [0u8; 8]; // 56 bits are required out of 64 bits.

        // Protocol: 11100 (WireGuard)
        bit_slice[0] |= 0b11100 << 3;

        // Peer node ID: 15 bits
        let peer_node_id = rest_info.peer_node_id;
        // take the 15 LSBs of the peer node ID
        // byte 0 has 3 bits left, take the 3 MSBs of the peer node ID
        bit_slice[0] |= ((peer_node_id >> 12) as u8) & 0b00000111;
        // byte 1 takes the next 8 bits of the peer node ID
        bit_slice[1] = (peer_node_id >> 4) as u8;
        // byte 2 takes the last 4 bits of the peer node ID
        bit_slice[2] = ((peer_node_id & 0b1111) as u8) << 4;

        // Start of protocol-specific data.
        // First 3 bits indicates if tunnel uses IPv6, has FEC, and FakeTCP enabled.
        if rest_info.endpoint_ipv6 {
            bit_slice[2] |= 0b1000;
        }
        if rest_info.fec {
            bit_slice[2] |= 0b0100;
        }
        if rest_info.faketcp {
            bit_slice[2] |= 0b0010;
        }
        // Bit 4 is reserved for future use.

        // Bit 5 to bit 20 are tunnel ID
        let tunnel_id = rest_info.tunnel_id;
        // take the 16 LSBs of the tunnel ID
        // byte 3 takes the first 8 bits of the tunnel ID
        bit_slice[3] = (tunnel_id >> 8) as u8;
        // byte 4 takes the last 8 bits of the tunnel ID
        bit_slice[4] = tunnel_id as u8;

        // Preserve existing names for 16-bit IDs; encode the remaining bits for global IDs.
        bit_slice[5] = (tunnel_id >> 24) as u8;
        bit_slice[6] = (tunnel_id >> 16) as u8;

        let pend = if fec.is_some() {
            Some(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                fec_peerport,
            ))
        } else if let Some(endpoint) = &rest_info.remote_endpoint {
            endpoint.parse::<std::net::SocketAddr>().ok()
        } else {
            None
        };

        crate::tunnel::wireguard::WireGuardTunnel::new(
            format!(
                "cat{}",
                base32::encode(Crockford, bit_slice.as_slice())[..12].to_owned()
            ),
            local_private_key,
            rest_info.public_key.clone(),
            pend,
            if port == 0 { None } else { Some(port) },
        )
    }

    pub async fn update_from_rest(
        &mut self,
        rest_info: Arc<WireguardTunnelInfo>,
        daemon_memory: Arc<DaemonMemory>,
    ) -> Result<(), Box<dyn Error>> {
        // Guard for tunnel ID and peer node ID consistency.
        if self.tunnel_id != rest_info.tunnel_id || self.peer_node_id != rest_info.peer_node_id {
            return Err("Tunnel ID or peer node ID mismatch".into());
        }

        self.mtu = rest_info.mtu;
        if self.ipv6 != rest_info.endpoint_ipv6 || self.fec.is_some() != rest_info.fec {
            // Completely destroy and recreate the tunnel because of name
            let local_private_key = self.os_tun.get_local_private_key().to_string();

            let ifcreated = self.os_tun.is_ift_created();
            self.os_tun.destroy().await?;
            if let Some(fec) = self.fec.take() {
                Arc::try_unwrap(fec)
                    .map_err(|_| "FEC engine still in use")?
                    .shutdown()
                    .await;
            }

            let port = daemon_memory
                .reserve_tunnel_port(rest_info.tunnel_id)
                .await
                .map_err(std::io::Error::other)?;
            let fec_res = Self::gen_new_fec(rest_info.clone(), port, &local_private_key).await?;

            let (fec, os_tun) = if let Some((fec, fec_listen_port, wg_port)) = fec_res {
                let fec1 = fec.clone();
                (
                    Some(fec),
                    Self::gen_new_wg_tunnel(
                        rest_info.clone(),
                        local_private_key,
                        Some(fec1),
                        wg_port,
                        fec_listen_port,
                    ),
                )
            } else {
                (
                    None,
                    Self::gen_new_wg_tunnel(rest_info.clone(), local_private_key, None, port, 0),
                )
            };

            self.fec = fec;
            self.os_tun = os_tun;
            self.ipv6 = rest_info.endpoint_ipv6;

            if ifcreated {
                self.os_tun.setup().await?;
                self.ensure_up().await?;
            }

            return Ok(());
        }

        let endpoint = rest_info
            .remote_endpoint
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|_| "invalid remote endpoint")?;
        if let Some(fec) = &self.fec {
            if let Some(endpoint) = endpoint {
                fec.handle().set_peer_addr(endpoint).await;
            } else {
                fec.handle().unpin_peer_addr().await;
            }
        } else {
            if endpoint != self.os_tun.get_peer_endpoint() {
                if let Some(endpoint) = endpoint {
                    self.os_tun.set_peer_endpoint(endpoint);
                }
            }
        }

        // ponytail: recreate when FakeTCP, public key, or listen mode changes.

        Ok(())
    }

    pub async fn activate(&mut self) -> Result<(), Box<dyn Error>> {
        self.os_tun.setup().await?;
        self.ensure_up().await
    }

    pub async fn teardown(&mut self) -> Result<(), Box<dyn Error>> {
        self.os_tun.destroy().await
    }

    pub fn is_connected(&self) -> bool {
        self.os_tun.is_connected().unwrap_or(false)
    }

    async fn ensure_up(&mut self) -> Result<(), Box<dyn Error>> {
        let ifname = self.os_tun.get_interface_name().to_string();

        let llipv6 = crate::interface::generate_ipv6_lla_from_seed(ifname.as_bytes().to_vec());
        let current_addrs = crate::interface::get_addr(ifname.clone()).await?;
        let contain_current_addr = current_addrs.iter().find(|a| a.addr() == llipv6).is_some();

        if !contain_current_addr {
            crate::interface::add_addr(ifname.clone(), llipv6.into()).await?;
        }

        if self.os_tun.get_mtu().await.is_ok_and(|mtu| mtu != self.mtu as u32) {
            crate::interface::link_down(ifname.clone()).await?;
        }
        crate::interface::link_up_with_mtu(ifname, self.mtu as u32).await?;

        Ok(())
    }

    pub fn get_tunnel_id(&self) -> i32 {
        self.tunnel_id
    }

    pub fn get_peer_node_id(&self) -> i32 {
        self.peer_node_id
    }

    pub fn is_ipv6(&self) -> bool {
        self.ipv6
    }

    pub fn get_os_tun(&self) -> &crate::tunnel::wireguard::WireGuardTunnel {
        &self.os_tun
    }

    pub fn get_os_tun_mut(&mut self) -> &mut crate::tunnel::wireguard::WireGuardTunnel {
        &mut self.os_tun
    }

    pub fn get_listen_port(&self) -> Option<u16> {
        self.os_tun.get_listen_port()
    }
}

#[cfg(all(test, target_os = "linux"))]
#[tokio::test]
#[ignore = "requires an isolated network namespace and CAP_NET_ADMIN"]
async fn matching_mtu_still_brings_wireguard_up() {
    let output = std::process::Command::new("ip").args(["link", "add", "wgactivate", "type", "wireguard"]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(std::process::Command::new("ip").args(["link", "set", "wgactivate", "mtu", "1420"]).status().unwrap().success());
    let os = crate::tunnel::wireguard::WireGuardTunnel::new("wgactivate".into(), String::new(), String::new(), None, None);
    let mut tunnel = WireguardTunnelC::new(1, 2, false, 1420, os, None);
    tunnel.ensure_up().await.unwrap();
    let output = std::process::Command::new("ip").args(["-o", "link", "show", "wgactivate"]).output().unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).contains("UP"));
    assert!(std::process::Command::new("ip").args(["link", "del", "wgactivate"]).status().unwrap().success());
}

#[cfg(all(test, target_os = "linux"))]
#[tokio::test]
async fn fec_toggle_releases_socket_and_updates_peer() {
    let memory = Arc::new(DaemonMemory::new(crate::config::ClientConfig::default()));
    let private = wireguard_control::Key::generate_private();
    let local_public = private.get_public();
    let remote_private = wireguard_control::Key::generate_private();
    let remote_public = remote_private.get_public();
    assert_eq!(
        FEC::tunnel_psk(private.0, remote_public.0, 1),
        FEC::tunnel_psk(remote_private.0, local_public.0, 1)
    );
    let mut info: WireguardTunnelInfo = serde_json::from_value(serde_json::json!({
        "tunnel_id": 1, "peer_node_id": 2, "public_key": remote_public.to_base64(), "preferred_port": 0,
        "remote_endpoint": "127.0.0.1:12345", "local_answered": "Unanswered", "remote_response": "Unanswered",
        "mtu": 1420, "endpoint_ipv6": false, "fec": true, "faketcp": false,
        "created_at": 0, "updated_at": 0
    })).unwrap();
    let (mut tunnel, port) = WireguardTunnelC::new_from_rest(
        Arc::new(info.clone()),
        private.to_base64(),
        memory.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        tunnel.fec.as_ref().unwrap().handle().get_peer_addr().await,
        Some("127.0.0.1:12345".parse().unwrap())
    );
    info.remote_endpoint = Some("127.0.0.1:12346".into());
    tunnel
        .update_from_rest(Arc::new(info.clone()), memory.clone())
        .await
        .unwrap();
    assert_eq!(
        tunnel.fec.as_ref().unwrap().handle().get_peer_addr().await,
        Some("127.0.0.1:12346".parse().unwrap())
    );
    info.remote_endpoint = None;
    tunnel
        .update_from_rest(Arc::new(info.clone()), memory.clone())
        .await
        .unwrap();
    assert_eq!(
        tunnel.fec.as_ref().unwrap().handle().get_peer_addr().await,
        None
    );
    info.remote_endpoint = Some("127.0.0.1:12346".into());
    info.fec = false;
    tunnel
        .update_from_rest(Arc::new(info.clone()), memory.clone())
        .await
        .unwrap();
    assert!(tunnel.fec.is_none());
    assert_eq!(tunnel.get_listen_port(), Some(port));
    drop(
        tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
            .await
            .unwrap(),
    );
    info.fec = true;
    tunnel
        .update_from_rest(Arc::new(info), memory)
        .await
        .unwrap();
    let engine = Arc::try_unwrap(tunnel.fec.take().unwrap()).ok().unwrap();
    assert_eq!(engine.handle().fec_bind_addr().port(), port);
    engine.shutdown().await;
    tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
        .await
        .unwrap();
}

#[test]
fn wireguard_interface_names_include_full_tunnel_id() {
    use crate::tunnel::shared::Tunnel;
    let mut info = WireguardTunnelInfo {
        tunnel_id: 1, peer_node_id: 2, public_key: String::new(), preferred_port: 0,
        remote_endpoint: None, local_answered: cat4igp_shared::custom_type::WireguardAnswered::Unanswered,
        remote_response: cat4igp_shared::custom_type::WireguardAnswered::Unanswered,
        mtu: 1420, endpoint_ipv6: false, fec: false, faketcp: false, created_at: 0, updated_at: 0,
    };
    let first = WireguardTunnelC::gen_new_wg_tunnel(Arc::new(info.clone()), String::new(), None, 0, 0);
    info.tunnel_id = 65537;
    let second = WireguardTunnelC::gen_new_wg_tunnel(Arc::new(info), String::new(), None, 0, 0);
    assert_ne!(first.get_interface_name(), second.get_interface_name());
}
