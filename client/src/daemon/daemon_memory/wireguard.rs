use std::error::Error;
use base32::Alphabet::Crockford;
use cat4igp_shared::rest::client as REST;

use crate::tunnel::shared::Tunnel as _;

pub struct WireguardTunnelC {
    tunnel_id: i32,
    peer_node_id: i32,
    ipv6: bool,
    os_tun: crate::tunnel::wireguard::WireGuardTunnel,
    mtu: i32
}

impl WireguardTunnelC {
    pub fn new(
        tunnel_id: i32,
        peer_node_id: i32,
        ipv6: bool,
        mtu: i32,
        os_tun: crate::tunnel::wireguard::WireGuardTunnel,
    ) -> Self {
        Self {
            tunnel_id,
            peer_node_id,
            ipv6,
            mtu,
            os_tun,
        }
    }

    pub fn new_from_rest(
        rest_info: REST::WireguardTunnelInfo,
        local_private_key: String,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            tunnel_id: rest_info.tunnel_id,
            peer_node_id: rest_info.peer_node_id,
            ipv6: rest_info.endpoint_ipv6,
            mtu: rest_info.mtu,
            os_tun: Self::gen_new_wg_tunnel(rest_info, local_private_key),
        })
    }

    fn gen_new_wg_tunnel(
        rest_info: REST::WireguardTunnelInfo,
        local_private_key: String,
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

        // Bit 21 to bit 36 are reserved for future use. Leave 0 for now.

        let pend = if let Some(endpoint) = rest_info.remote_endpoint {
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
            rest_info.public_key,
            pend,
            if rest_info.preferred_port == 0 {
                None
            } else {
                Some(rest_info.preferred_port)
            },
        )
    }

    pub async fn update_from_rest(
        &mut self,
        rest_info: REST::WireguardTunnelInfo,
    ) -> Result<(), Box<dyn Error>> {
        // Guard for tunnel ID and peer node ID consistency.
        if self.tunnel_id != rest_info.tunnel_id || self.peer_node_id != rest_info.peer_node_id {
            return Err("Tunnel ID or peer node ID mismatch".into());
        }

        let old_mtu = self.os_tun.get_mtu().await;
        if self.ipv6 != rest_info.endpoint_ipv6 {
            // Completely destroy and recreate the tunnel because of name
            let local_private_key = self.os_tun.get_local_private_key().to_string();

            let ifcreated = self.os_tun.is_ift_created();
            let _ = self.os_tun.destroy();
            self.ipv6 = rest_info.endpoint_ipv6;
            self.mtu = rest_info.mtu;
            self.os_tun = Self::gen_new_wg_tunnel(rest_info, local_private_key);
        
            if ifcreated {
                self.os_tun.setup().await?;
                self.ensure_up().await?;
            }

            return Ok(());
        }


        // TODO: check for FEC, FakeTCP, and other WireGuard parameters.

        Ok(())
    }

    async fn ensure_up(&mut self) -> Result<(), Box<dyn Error>> {
        let ifname = self.os_tun.get_interface_name().to_string();
        
        let llipv6 = crate::interface::generate_ipv6_lla_from_seed(ifname.as_bytes().to_vec());
        let current_addrs = crate::interface::get_addr(ifname.clone()).await?;
        let contain_current_addr = current_addrs.iter().find(|a| a.addr() == llipv6).is_some();
        let filter_addrs: Vec<_> = current_addrs.into_iter().filter(|a| a.addr() != llipv6).collect();

        if !contain_current_addr {
            crate::interface::add_addr(ifname.clone(), llipv6.into()).await?;
        }

        for addr in filter_addrs {
            crate::interface::del_addr(ifname.clone(), addr).await?;
        }

        let current_mtu = self.os_tun.get_mtu().await.ok();
        if let Some(current_mtu) = current_mtu {
            let current_mtu_i32 = current_mtu as i32;

            if current_mtu_i32 != self.mtu {
                // bring link down, then link up with new MTU
                crate::interface::link_down(ifname.clone()).await?;
                crate::interface::link_up_with_mtu(ifname.clone(), self.mtu as u32).await?;
            }
        } else {
            // if we fail to get MTU, just try to bring link up with new MTU.
            crate::interface::link_up_with_mtu(ifname.clone(), self.mtu as u32).await?;
        }

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
}