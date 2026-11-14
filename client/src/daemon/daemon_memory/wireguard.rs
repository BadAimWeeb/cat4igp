use base32::Alphabet::Crockford;
use cat4igp_libfec as FEC;
use cat4igp_shared::{control::{TopologySnapshot, WireguardTunnelInfo}, custom_type::WireguardAnswered};
use std::{collections::HashSet, error::Error, net::SocketAddr, sync::Arc};

use crate::daemon::daemon_memory::DaemonMemory;
use crate::tunnel::shared::Tunnel as _;

#[cfg(target_os = "linux")]
fn faketcp_mtu(requested: i32, path_mtu: u32, ipv6: bool, fec: bool) -> Result<i32, Box<dyn Error>> {
    // WireGuard adds 32 bytes and pads its inner packet to a 16-byte boundary.
    // FEC adds an 8-byte envelope, 10-byte frame header and 2-byte shard length.
    let overhead = (if ipv6 { 40 } else { 20 }) + 60 + (if fec { 20 } else { 0 }) + 32;
    let available = path_mtu.min(65_535).checked_sub(overhead).ok_or("FakeTCP path MTU is too small")?;
    let ceiling = (available & !15) as i32;
    if requested < 1280 || ceiling < 1280 { return Err("FakeTCP requires an effective WireGuard MTU of at least 1280".into()); }
    if ceiling < requested { eprintln!("FakeTCP reduced WireGuard MTU from {requested} to {ceiling} for path MTU {path_mtu}"); }
    Ok(requested.min(ceiling))
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn fake_tcp_mtu_accounts_for_outer_headers_and_fec() {
    assert_eq!(faketcp_mtu(1420, 1500, false, false).unwrap(), 1376);
    assert_eq!(faketcp_mtu(1420, 1500, true, false).unwrap(), 1360);
    assert_eq!(faketcp_mtu(1420, 1500, false, true).unwrap(), 1360);
    assert_eq!(faketcp_mtu(1420, 1500, true, true).unwrap(), 1344);
    assert_eq!(faketcp_mtu(1300, 1500, true, true).unwrap(), 1300);
    assert!(faketcp_mtu(1420, 1400, true, true).is_err());
    assert!(faketcp_mtu(1279, 1500, false, false).is_err());
}

pub struct WireguardTunnelC {
    tunnel_id: i32,
    peer_node_id: i32,
    ipv6: bool,
    os_tun: crate::tunnel::wireguard::WireGuardTunnel,
    mtu: i32,
    fec: Option<Arc<FEC::PeerEngine>>,
    proxy: Option<crate::network::udp_proxy::UdpProxy>,
    #[cfg(target_os = "linux")]
    faketcp: Option<crate::network::faketcp::FakeTcp>,
    fake_peer: Option<SocketAddr>,
    replacement_pending: bool,
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
            proxy: None,
            #[cfg(target_os = "linux")]
            faketcp: None,
            fake_peer: None,
            replacement_pending: false,
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
        let alternate = rest_info.refresh.active_slot != 0;
        Self::new_with_port(rest_info, local_private_key, port, alternate).await
    }

    pub(super) async fn new_with_port(
        rest_info: Arc<WireguardTunnelInfo>,
        local_private_key: String,
        port: u16,
        alternate: bool,
    ) -> Result<(Self, u16), Box<dyn Error>> {
        if rest_info.faketcp && matches!(rest_info.refresh_mode, cat4igp_shared::control::RefreshMode::Proxy) {
            return Err("UDP proxy refresh cannot be combined with FakeTCP; use current or dual_link".into());
        }
        let peer = rest_info.remote_endpoint.as_deref().map(str::parse::<SocketAddr>).transpose()?;
        #[cfg(target_os = "linux")]
        let mut faketcp = None;
        let mut transport_info = (*rest_info).clone();
        let mut transport_port = port;
        let mut tunnel_mtu = rest_info.mtu;
        let mut proxy = None;
        if rest_info.faketcp {
            #[cfg(target_os = "linux")]
            {
                let peer = peer.ok_or("FakeTCP requires a remote endpoint")?;
                let local = wireguard_control::Key::from_base64(&local_private_key)?;
                let remote = wireguard_control::Key::from_base64(&rest_info.public_key)?;
                let key = FEC::tunnel_psk(local.0, remote.0, rest_info.tunnel_id).ok_or("invalid FakeTCP peer key")?;
                transport_port = crate::network::ports::get_random_udp_port()?;
                let bridge = crate::network::faketcp::FakeTcp::start(port, peer, ([127, 0, 0, 1], transport_port).into(), key).await?;
                tunnel_mtu = faketcp_mtu(rest_info.mtu, bridge.path_mtu(), peer.is_ipv6(), rest_info.fec)?;
                transport_info.remote_endpoint = Some(bridge.local_addr().to_string());
                transport_info.endpoint_ipv6 = false;
                faketcp = Some(bridge);
            }
            #[cfg(not(target_os = "linux"))]
            return Err("FakeTCP requires Linux".into());
        } else if !rest_info.fec && matches!(rest_info.refresh_mode, cat4igp_shared::control::RefreshMode::Proxy) {
            transport_port = crate::network::ports::get_random_udp_port()?;
            let bridge = crate::network::udp_proxy::UdpProxy::start(port, rest_info.endpoint_ipv6, peer, ([127, 0, 0, 1], transport_port).into()).await?;
            transport_info.remote_endpoint = Some(bridge.local_addr().to_string());
            transport_info.endpoint_ipv6 = false;
            proxy = Some(bridge);
        } else if let Some(peer) = peer {
            let _ = crate::network::ports::punch_udp(port, peer).await;
        }
        let fec_res = Self::gen_new_fec(Arc::new(transport_info.clone()), transport_port, &local_private_key).await?;

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
                    alternate,
                ),
            )
        } else {
            (
                None,
                Self::gen_new_wg_tunnel(rest_info.clone(), local_private_key, None, transport_port, 0, alternate),
            )
        };
        let mut os_tun = os_tun;
        if (rest_info.faketcp || proxy.is_some()) && fec.is_none() {
            os_tun.set_local_bridge_endpoint(transport_info.remote_endpoint.as_deref().ok_or("missing local transport bridge")?.parse()?);
        }

        Ok((
            Self {
                tunnel_id: rest_info.tunnel_id,
                peer_node_id: rest_info.peer_node_id,
                ipv6: rest_info.endpoint_ipv6,
                mtu: tunnel_mtu,
                fec,
                proxy,
                #[cfg(target_os = "linux")]
                faketcp,
                fake_peer: if rest_info.faketcp { peer } else { None },
                replacement_pending: false,
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

    pub(super) fn gen_new_wg_tunnel(
        rest_info: Arc<WireguardTunnelInfo>,
        local_private_key: String,
        fec: Option<Arc<FEC::PeerEngine>>,
        port: u16,
        fec_peerport: u16,
        alternate: bool,
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
        if alternate { bit_slice[2] |= 0b0001; }

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

        let mut tunnel = crate::tunnel::wireguard::WireGuardTunnel::new(
            format!(
                "cat{}",
                base32::encode(Crockford, bit_slice.as_slice())[..12].to_owned()
            ),
            local_private_key,
            rest_info.public_key.clone(),
            pend,
            if port == 0 { None } else { Some(port) },
        );
        if fec.is_some() {
            tunnel.set_local_bridge_endpoint(pend.expect("FEC endpoint is present"));
        }
        tunnel
    }

    pub async fn update_from_rest(
        &mut self,
        rest_info: Arc<WireguardTunnelInfo>,
        daemon_memory: Arc<DaemonMemory>,
    ) -> Result<(), Box<dyn Error>> {
        if rest_info.faketcp && matches!(rest_info.refresh_mode, cat4igp_shared::control::RefreshMode::Proxy) {
            return Err("UDP proxy refresh cannot be combined with FakeTCP; use current or dual_link".into());
        }
        // Guard for tunnel ID and peer node ID consistency.
        if self.tunnel_id != rest_info.tunnel_id || self.peer_node_id != rest_info.peer_node_id {
            return Err("Tunnel ID or peer node ID mismatch".into());
        }
        #[cfg(target_os = "linux")]
        let transport_failed = self.faketcp.as_ref().is_some_and(|bridge| !bridge.is_running());
        #[cfg(not(target_os = "linux"))]
        let transport_failed = false;
        let transport_failed = transport_failed || self.proxy.as_ref().is_some_and(|bridge| !bridge.is_running());
        let new_peer = rest_info.remote_endpoint.as_deref().map(str::parse::<SocketAddr>).transpose()?;
        if self.replacement_pending || transport_failed || self.fake_peer.is_some() != rest_info.faketcp || (rest_info.faketcp && (self.fake_peer != new_peer || self.fec.is_some() != rest_info.fec || self.ipv6 != rest_info.endpoint_ipv6)) || (self.proxy.is_some() && (rest_info.fec || self.ipv6 != rest_info.endpoint_ipv6)) || (!rest_info.fec && !rest_info.faketcp && self.proxy.is_some() != matches!(rest_info.refresh_mode, cat4igp_shared::control::RefreshMode::Proxy)) {
            self.replacement_pending = true;
            let private_key = self.os_tun.get_local_private_key().to_owned();
            self.teardown().await?;
            let (replacement, _) = Self::new_from_rest(rest_info, private_key, daemon_memory).await?;
            *self = replacement;
            return Ok(());
        }
        if rest_info.faketcp {
            #[cfg(target_os = "linux")]
            { self.mtu = faketcp_mtu(rest_info.mtu, self.faketcp.as_ref().ok_or("missing FakeTCP bridge")?.path_mtu(), new_peer.ok_or("FakeTCP requires a remote endpoint")?.is_ipv6(), rest_info.fec)?; }
            return Ok(());
        }

        if let Some(proxy) = &self.proxy {
            proxy.set_peer(new_peer).await?;
            self.mtu = rest_info.mtu;
            return Ok(());
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
                        rest_info.refresh.active_slot != 0,
                    ),
                )
            } else {
                (
                    None,
                    Self::gen_new_wg_tunnel(rest_info.clone(), local_private_key, None, port, 0, rest_info.refresh.active_slot != 0),
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
        self.os_tun.destroy().await?;
        if let Some(proxy) = &mut self.proxy { proxy.stop().await?; }
        self.proxy = None;
        #[cfg(target_os = "linux")]
        if let Some(bridge) = &mut self.faketcp { bridge.stop().await?; }
        #[cfg(target_os = "linux")]
        { self.faketcp = None; }
        if let Some(fec) = self.fec.take() {
            Arc::try_unwrap(fec).map_err(|_| "FEC engine still in use")?.shutdown().await;
        }
        Ok(())
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

    pub(super) fn transport_flags(&self) -> (bool, bool, bool) {
        (self.ipv6, self.fec.is_some(), self.fake_peer.is_some())
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

impl DaemonMemory {
    pub async fn wireguard_mapped_addr(&self, tunnel_id: i32, server: SocketAddr, timeout: std::time::Duration) -> Result<SocketAddr, String> {
        let tunnels = self.wireguard.lock().await;
        let tunnel = tunnels.get(&tunnel_id).ok_or_else(|| format!("unknown WireGuard tunnel {tunnel_id}"))?;
        if tunnel.fake_peer.is_some() {
            return Err("STUN mapping is unsupported for FakeTCP".into());
        }
        if let Some(proxy) = &tunnel.proxy {
            return proxy.mapped_addr(server, timeout).await;
        }
        let fec = tunnel.fec.as_ref().ok_or("STUN mapping is unsupported for kernel WireGuard")?;
        fec.mapped_addr(server, timeout).await
    }

    pub async fn reconcile_wireguard_tunnels(
        &self,
        snapshot: &TopologySnapshot,
        local_private_key: &str,
    ) -> Result<(), String> {
        let mut switched = self.refresh_switched.lock().await;
        let mut preserved = self.refresh_preserved.lock().await;
        let mut active = self.wireguard.lock().await;
        let desired_ids: HashSet<i32> = snapshot
            .tunnels
            .iter()
            .filter(|t| {
                self.wireguard_enabled && (!t.faketcp || cfg!(target_os = "linux"))
                    && matches!(t.local_answered, WireguardAnswered::Answered)
                    && matches!(t.remote_response, WireguardAnswered::Answered)
            })
            .map(|t| t.tunnel_id)
            .collect();
        let memory_arc = Arc::new(self.clone());

        // Removals run before fallible creations; failed teardown stays tracked for the next poll.
        let stale_ids: Vec<i32> = active
            .keys()
            .copied()
            .filter(|id| !desired_ids.contains(id))
            .collect();
        let mut removal_error = None;
        for id in stale_ids {
            let mut candidates = self.refresh_wireguard.lock().await;
            if let Some(candidate) = candidates.get_mut(&id) {
                if let Err(error) = candidate.teardown().await {
                    removal_error = Some(format!("failed to teardown refresh tunnel {id}: {error}"));
                    continue;
                }
            }
            candidates.remove(&id);
            if let Some(port) = self.refresh_ports.lock().await.remove(&id) { self.port_mgmt.release(port); }
            switched.remove(&id);
            preserved.remove(&id);
            drop(candidates);
            if let Some(stale) = active.get_mut(&id) {
                let teardown = stale.teardown().await.map_err(|error| error.to_string());
                match teardown {
                    Ok(()) => {
                        active.remove(&id);
                        self.release_tunnel_port(id).await;
                        self.advertised_endpoints.lock().await.remove(&id);
                    }
                    Err(error) => {
                        removal_error = Some(format!("failed to teardown tunnel {id}: {error}"))
                    }
                }
            }
        }
        let snapshot_ids: HashSet<i32> = snapshot.tunnels.iter().map(|t| t.tunnel_id).collect();
        let unused: Vec<i32> = self
            .reserved_ports
            .lock()
            .await
            .keys()
            .copied()
            .filter(|id| !snapshot_ids.contains(id) && !active.contains_key(id))
            .collect();
        for id in unused {
            self.release_tunnel_port(id).await;
            self.advertised_endpoints.lock().await.remove(&id);
        }

        for tunnel in &snapshot.tunnels {
            let is_ready = self.wireguard_enabled && (!tunnel.faketcp || cfg!(target_os = "linux"))
                && matches!(tunnel.local_answered, WireguardAnswered::Answered)
                && matches!(tunnel.remote_response, WireguardAnswered::Answered);
            if !is_ready {
                continue;
            }

            let tunnel_arc = Arc::new(tunnel.clone());
            if let Some(existing) = active.get_mut(&tunnel.tunnel_id) {
                if switched.contains(&tunnel.tunnel_id) || preserved.contains(&tunnel.tunnel_id) {
                    continue;
                }
                existing
                    .update_from_rest(tunnel_arc, memory_arc.clone())
                    .await
                    .map_err(|e| format!("failed to update tunnel {}: {}", tunnel.tunnel_id, e))?;
                existing.activate().await.map_err(|e| {
                    format!("failed to activate tunnel {}: {}", tunnel.tunnel_id, e)
                })?;
                continue;
            }

            let new_tunnel_result = WireguardTunnelC::new_from_rest(
                tunnel_arc,
                local_private_key.to_string(),
                memory_arc.clone(),
            )
            .await
            .map(|(tunnel, _)| tunnel)
            .map_err(|error| error.to_string());
            let mut new_tunnel = match new_tunnel_result {
                Ok(tunnel) => tunnel,
                Err(error) => {
                    self.release_tunnel_port(tunnel.tunnel_id).await;
                    return Err(format!(
                        "failed to create tunnel {}: {error}",
                        tunnel.tunnel_id
                    ));
                }
            };

            let activation_result = new_tunnel
                .activate()
                .await
                .map_err(|error| error.to_string());
            if let Err(error) = activation_result {
                // A partially created interface must remain tracked if cleanup fails.
                if new_tunnel.teardown().await.is_err() {
                    active.insert(tunnel.tunnel_id, new_tunnel);
                } else {
                    self.release_tunnel_port(tunnel.tunnel_id).await;
                    self.advertised_endpoints
                        .lock()
                        .await
                        .remove(&tunnel.tunnel_id);
                }
                return Err(format!(
                    "failed to setup tunnel {}: {error}",
                    tunnel.tunnel_id
                ));
            }
            active.insert(tunnel.tunnel_id, new_tunnel);
        }

        removal_error.map_or(Ok(()), Err)
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
async fn failed_fake_tcp_replacement_is_retried() {
    let memory = Arc::new(DaemonMemory::new(crate::config::ClientConfig::default()));
    let private = wireguard_control::Key::generate_private();
    let mut info: WireguardTunnelInfo = serde_json::from_value(serde_json::json!({
        "tunnel_id": 71, "peer_node_id": 72, "public_key": "invalid", "preferred_port": 0,
        "remote_endpoint": null, "local_answered": "Unanswered", "remote_response": "Unanswered",
        "mtu": 1420, "endpoint_ipv6": false, "fec": false, "faketcp": false,
        "created_at": 0, "updated_at": 0
    })).unwrap();
    let (mut tunnel, _) = WireguardTunnelC::new_from_rest(Arc::new(info.clone()), private.to_base64(), memory.clone()).await.unwrap();
    tunnel.fake_peer = Some("127.0.0.1:12345".parse().unwrap());
    info.faketcp = true;
    info.remote_endpoint = Some("127.0.0.1:12346".into());
    assert!(tunnel.update_from_rest(Arc::new(info.clone()), memory.clone()).await.is_err());
    assert!(tunnel.replacement_pending);
    info.remote_endpoint = Some("127.0.0.1:12345".into());
    assert!(tunnel.update_from_rest(Arc::new(info), memory).await.is_err());
    assert!(tunnel.replacement_pending);
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
        refresh_mode: Default::default(), refresh: Default::default(),
    };
    let first = WireguardTunnelC::gen_new_wg_tunnel(Arc::new(info.clone()), String::new(), None, 0, 0, false);
    let alternate = WireguardTunnelC::gen_new_wg_tunnel(Arc::new(info.clone()), String::new(), None, 0, 0, true);
    assert_ne!(first.get_interface_name(), alternate.get_interface_name());
    info.tunnel_id = 65537;
    let second = WireguardTunnelC::gen_new_wg_tunnel(Arc::new(info), String::new(), None, 0, 0, false);
    assert_ne!(first.get_interface_name(), second.get_interface_name());
}

#[tokio::test]
async fn active_kernel_mapping_refresh_does_not_rebind_or_disturb_socket() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = crate::config::ClientConfig { data_dir: dir.path().to_owned(), ..Default::default() };
    let daemon = crate::daemon::Daemon::new(config).await.unwrap();
    let socket = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = socket.local_addr().unwrap().port();
    daemon.memory.reserved_ports.lock().await.insert(1, port);
    let os = crate::tunnel::wireguard::WireGuardTunnel::new("unused".into(), String::new(), String::new(), None, Some(port));
    daemon.memory.wireguard.lock().await.insert(1, WireguardTunnelC::new(1, 2, false, 1420, os, None));
    let info: WireguardTunnelInfo = serde_json::from_value(serde_json::json!({
        "tunnel_id": 1, "peer_node_id": 2, "public_key": "", "preferred_port": 0,
        "remote_endpoint": null, "local_answered": "Answered", "remote_response": "Answered",
        "mtu": 1420, "endpoint_ipv6": false, "fec": false, "faketcp": false,
        "created_at": 0, "updated_at": 0
    })).unwrap();
    let error = daemon.local_endpoint(&info).await.unwrap_err();
    assert!(error.contains("active kernel WireGuard mapping"), "{error}");
    let detector = crate::network::PublicIpDetector::new();
    assert!(daemon.memory.inactive_wireguard_mapped_addr(1, &detector, port, false).await.is_err());
    assert!(daemon.memory.wireguard_mapped_addr(1, "127.0.0.1:9".parse().unwrap(), std::time::Duration::from_millis(10)).await.is_err());
    assert_eq!(daemon.memory.reserve_tunnel_port(1).await.unwrap(), port);
    socket.send_to(b"still alive", socket.local_addr().unwrap()).await.unwrap();
    let mut buf = [0; 32];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(1), socket.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"still alive");
}
