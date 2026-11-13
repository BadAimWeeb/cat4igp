use super::DaemonMemory;
use crate::tunnel::{l2tp::L2tpTunnel, shared::Tunnel};
use cat4igp_shared::control::{L2tpTunnelInfo, TopologySnapshot};
use std::{collections::HashSet, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, num::NonZeroU32};
use futures_util::TryStreamExt;
use rtnetlink::{new_connection, RouteMessageBuilder, packet_route::route::{RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol}};
struct ConnectionTask(tokio::task::JoinHandle<()>);
impl Drop for ConnectionTask { fn drop(&mut self) { self.0.abort(); } }

fn host_route(ip: IpAddr, index: u32) -> RouteMessage {
    match ip {
        IpAddr::V4(ip) => RouteMessageBuilder::<Ipv4Addr>::new().destination_prefix(ip, 32).output_interface(index).protocol(RouteProtocol::Other(253)).build(),
        IpAddr::V6(ip) => RouteMessageBuilder::<Ipv6Addr>::new().destination_prefix(ip, 128).output_interface(index).protocol(RouteProtocol::Other(253)).build(),
    }
}

async fn route_context(interface: &str, ip: IpAddr) -> Result<(ConnectionTask, rtnetlink::Handle, u32, Vec<RouteMessage>), String> {
    let (connection, handle, _) = new_connection().map_err(|e| e.to_string())?;
    let task = ConnectionTask(tokio::spawn(connection));
    let index = handle.link().get().match_name(interface.to_owned()).execute().try_next().await.map_err(|e| e.to_string())?.ok_or("WireGuard interface missing")?.header.index;
    let query = match ip { IpAddr::V4(_) => RouteMessageBuilder::<Ipv4Addr>::new().build(), IpAddr::V6(_) => RouteMessageBuilder::<Ipv6Addr>::new().build() };
    let mut stream = handle.route().get(query).execute();
    let mut routes = Vec::new();
    while let Some(route) = stream.try_next().await.map_err(|e| e.to_string())? {
        if route.header.table == RouteHeader::RT_TABLE_MAIN && route.header.destination_prefix_length == if ip.is_ipv4() { 32 } else { 128 }
            && route.attributes.iter().any(|a| matches!(a, RouteAttribute::Destination(dest) if *dest == RouteAddress::from(ip))) {
            routes.push(route);
        }
    }
    Ok((task, handle, index, routes))
}

pub(super) async fn add_host_route(interface: &str, ip: IpAddr) -> Result<bool, String> {
    let (_task, handle, index, routes) = route_context(interface, ip).await?;
    if !routes.is_empty() {
        if routes.iter().all(|route| route.attributes.iter().any(|a| matches!(a, RouteAttribute::Oif(i) if *i == index)) && !route.attributes.iter().any(|a| matches!(a, RouteAttribute::Gateway(_) | RouteAttribute::Via(_) | RouteAttribute::MultiPath(_)))) { return Ok(false); }
        return Err(format!("conflicting route to {ip}"));
    }
    handle.route().add(host_route(ip, index)).execute().await.map_err(|e| e.to_string())?;
    Ok(true)
}

pub(super) async fn delete_host_route(interface: &str, ip: IpAddr) -> Result<(), String> {
    let (_task, handle, index, routes) = route_context(interface, ip).await?;
    if let Some(route) = routes.into_iter().find(|r| r.header.protocol == RouteProtocol::Other(253) && r.attributes.iter().any(|a| matches!(a, RouteAttribute::Oif(i) if *i == index)) && !r.attributes.iter().any(|a| matches!(a, RouteAttribute::Gateway(_) | RouteAttribute::Via(_) | RouteAttribute::MultiPath(_)))) {
        handle.route().del(route).execute().await.map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub(super) async fn reject_address_conflict(interface: &str, ip: IpAddr) -> Result<(), String> {
    use rtnetlink::packet_route::address::AddressAttribute;
    let (connection, handle, _) = new_connection().map_err(|e| e.to_string())?;
    let task = tokio::spawn(connection);
    let result = async {
        let index = handle.link().get().match_name(interface.to_owned()).execute().try_next().await.map_err(|e| e.to_string())?.ok_or("WireGuard interface missing")?.header.index;
        let mut addresses = handle.address().get().execute();
        while let Some(address) = addresses.try_next().await.map_err(|e| e.to_string())? {
            if address.header.index != index && address.attributes.iter().any(|a| matches!(a, AddressAttribute::Address(value) | AddressAttribute::Local(value) if *value == ip)) {
                return Err(format!("L2TP local address {ip} belongs to another interface"));
            }
        }
        Ok(())
    }.await;
    task.abort();
    result
}
pub(super) async fn add_host_address(interface: &str, ip: IpAddr) -> Result<(), String> {
    use rtnetlink::packet_route::address::{AddressAttribute, AddressHeaderFlags, AddressProtocol};
    let (connection, handle, _) = new_connection().map_err(|e| e.to_string())?;
    let _task = ConnectionTask(tokio::spawn(connection));
    let index = handle.link().get().match_name(interface.to_owned()).execute().try_next().await.map_err(|e| e.to_string())?.ok_or("WireGuard interface missing")?.header.index;
    let mut request = handle.address().add(index, ip, if ip.is_ipv4() { 32 } else { 128 });
    if ip.is_ipv6() { request.message_mut().header.flags |= AddressHeaderFlags::Nodad; }
    request.message_mut().attributes.push(AddressAttribute::Protocol(AddressProtocol::Other(253)));
    request.execute().await.map_err(|e| e.to_string())
}
pub(super) async fn delete_host_address(interface: &str, ip: IpAddr) -> Result<(), String> {
    use rtnetlink::packet_route::address::{AddressAttribute, AddressProtocol};
    let (connection, handle, _) = new_connection().map_err(|e| e.to_string())?;
    let _task = ConnectionTask(tokio::spawn(connection));
    let index = handle.link().get().match_name(interface.to_owned()).execute().try_next().await.map_err(|e| e.to_string())?.ok_or("WireGuard interface missing")?.header.index;
    let mut stream = handle.address().get().set_link_index_filter(index).execute();
    while let Some(address) = stream.try_next().await.map_err(|e| e.to_string())? {
        if address.header.prefix_len == if ip.is_ipv4() { 32 } else { 128 } && address.attributes.iter().any(|a| matches!(a, AddressAttribute::Address(value) | AddressAttribute::Local(value) if *value == ip)) {
            if !address.attributes.iter().any(|a| matches!(a, AddressAttribute::Protocol(AddressProtocol::Other(253)))) {
                return Err(format!("L2TP address {ip} was replaced; refusing to delete it"));
            }
            handle.address().del(address).execute().await.map_err(|e| e.to_string())?;
            break;
        }
    }
    Ok(())
}




pub(super) struct ActiveL2tp {
    info: L2tpTunnelInfo,
    tunnel: L2tpTunnel,
    underlay: Option<String>,
    wg_flags: Option<(bool, bool)>,
    owned_route: bool,
    owned_address: bool,
    cleanup_pending: bool,
}

fn cookie(value: &str) -> Result<[u8; 8], String> {
    if value.len() != 16 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("invalid L2TP cookie".into());
    }
    let mut result = [0; 8];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| "invalid L2TP cookie")?;
    }
    Ok(result)
}

impl DaemonMemory {
    pub(super) async fn remove_stale_l2tp(&self, snapshot: &TopologySnapshot) -> Result<(), String> {
        let mut active = self.l2tp.lock().await;
        let desired: HashSet<_> = snapshot.l2tp_tunnels.iter().map(|t| t.tunnel_id).collect();
        let stale: Vec<_> = active.iter().filter_map(|(id, existing)| {
            let new = snapshot.l2tp_tunnels.iter().find(|t| t.tunnel_id == *id);
            let dependency_changed = existing.info.wireguard_tunnel_id.is_some_and(|wg| {
                !snapshot.tunnels.iter().any(|t| t.tunnel_id == wg && t.peer_node_id == existing.info.peer_node_id
                    && matches!(t.local_answered, cat4igp_shared::custom_type::WireguardAnswered::Answered)
                    && matches!(t.remote_response, cat4igp_shared::custom_type::WireguardAnswered::Answered)
                    && existing.wg_flags == Some((t.endpoint_ipv6, t.fec)))
            });
            let outer_conflict = existing.underlay.is_some() && existing.info.remote_endpoint.parse::<IpAddr>().ok().is_some_and(|ip| snapshot.tunnels.iter().filter_map(|t| t.remote_endpoint.as_deref()).filter_map(|s| s.parse::<SocketAddr>().ok()).any(|endpoint| endpoint.ip() == ip));
            (!desired.contains(id) || new != Some(&existing.info) || dependency_changed || outer_conflict || existing.cleanup_pending).then_some(*id)
        }).collect();
        for id in stale {
            active.get_mut(&id).unwrap().tunnel.destroy().await.map_err(|e| format!("failed to destroy L2TP {id}: {e}"))?;
            let existing = active.get(&id).unwrap();
            if let Some(interface) = existing.underlay.clone() {
                let local: IpAddr = existing.info.local_endpoint.parse().map_err(|_| "invalid L2TP local address")?;
                let remote: IpAddr = existing.info.remote_endpoint.parse().map_err(|_| "invalid L2TP remote address")?;
                let owned_route = existing.owned_route;
                let owned_address = existing.owned_address;
                let route_sharer = active.iter().find_map(|(other, t)| (*other != id && t.underlay.as_ref() == Some(&interface) && t.info.remote_endpoint.parse::<IpAddr>().ok() == Some(remote)).then_some(*other));
                let address_sharer = active.iter().find_map(|(other, t)| (*other != id && t.underlay.as_ref() == Some(&interface) && t.info.local_endpoint.parse::<IpAddr>().ok() == Some(local)).then_some(*other));
                if owned_route {
                    if let Some(other) = route_sharer { active.get_mut(&other).unwrap().owned_route = true; }
                    else { delete_host_route(&interface, remote).await?; }
                    active.get_mut(&id).unwrap().owned_route = false;
                }
                if owned_address {
                    if let Some(other) = address_sharer { active.get_mut(&other).unwrap().owned_address = true; }
                    else { delete_host_address(&interface, local).await?; }
                    active.get_mut(&id).unwrap().owned_address = false;
                }
            }
            active.remove(&id);
        }
        Ok(())
    }

    pub(super) async fn reconcile_l2tp(&self, snapshot: &TopologySnapshot) -> Result<(), String> {
        let mut active = self.l2tp.lock().await;
        for info in &snapshot.l2tp_tunnels {
            if !self.l2tp_enabled { return Err("L2TP disabled in client configuration".into()); }
            if info.security_mode == "pure" && !self.allow_insecure_l2tp { return Err("unencrypted L2TP requires allow_insecure_l2tp = true".into()); }
            if (self.l2tp_excluded_ports.0..self.l2tp_excluded_ports.1).contains(&info.local_port) {
                return Err(format!("L2TP {} port {} conflicts with WireGuard port_range", info.tunnel_id, info.local_port));
            }
            let local_ip: IpAddr = info.local_endpoint.parse().map_err(|_| "invalid L2TP local address")?;
            let remote_ip: IpAddr = info.remote_endpoint.parse().map_err(|_| "invalid L2TP remote address")?;
            if local_ip.is_ipv4() != remote_ip.is_ipv4() || info.local_port == 0 || info.remote_port == 0 {
                return Err("invalid L2TP endpoint pair".into());
            }
            let underlay = match (info.security_mode.as_str(), info.wireguard_tunnel_id) {
                ("pure", None) => None,
                ("wireguard", Some(id)) => {
                    if snapshot.tunnels.iter().filter_map(|t| t.remote_endpoint.as_deref()).filter_map(|s| s.parse::<SocketAddr>().ok()).any(|endpoint| endpoint.ip() == remote_ip) {
                        return Err("L2TP remote address conflicts with a WireGuard outer endpoint".into());
                    }
                    if !snapshot.tunnels.iter().any(|t| t.tunnel_id == id && t.peer_node_id == info.peer_node_id && matches!(t.local_answered, cat4igp_shared::custom_type::WireguardAnswered::Answered) && matches!(t.remote_response, cat4igp_shared::custom_type::WireguardAnswered::Answered)) {
                        return Err(format!("L2TP {} requires a ready WireGuard tunnel {id}", info.tunnel_id));
                    }
                    let wg = self.wireguard.lock().await;
                    let dependency = wg.get(&id).ok_or_else(|| format!("L2TP {} requires active WireGuard {id}", info.tunnel_id))?;
                    if dependency.get_peer_node_id() != info.peer_node_id { return Err("L2TP WireGuard peer mismatch".into()); }
                    Some(dependency.get_os_tun().get_interface_name().to_owned())
                }
                _ => return Err("invalid L2TP security mode or dependency".into()),
            };
            if let Some(existing) = active.get_mut(&info.tunnel_id) {
                if existing.underlay != underlay { return Err("L2TP underlay changed before cleanup".into()); }
                if !existing.tunnel.is_ift_created() { existing.tunnel.setup().await.map_err(|e| e.to_string())?; }
                continue;
            }
            let bind_ip = if underlay.is_some() { local_ip } else if local_ip.is_ipv4() { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V6(Ipv6Addr::UNSPECIFIED) };
            let mut tunnel = L2tpTunnel::new(
                format!("catl{:x}", info.tunnel_id), snapshot.node_id, SocketAddr::new(bind_ip, info.local_port), SocketAddr::new(remote_ip, info.remote_port),
                NonZeroU32::new(info.local_session_id).ok_or("invalid L2TP local session")?, NonZeroU32::new(info.remote_session_id).ok_or("invalid L2TP peer session")?,
                cookie(&info.local_cookie)?, cookie(&info.remote_cookie)?, u32::try_from(info.mtu).map_err(|_| "invalid L2TP MTU")?, underlay.clone(),
            );
            let mut owned_address = false;
            let mut owned_route = false;
            if let Some(interface) = &underlay {
                reject_address_conflict(interface, local_ip).await?;
                let addresses = crate::interface::get_addr(interface.clone()).await.map_err(|e| e.to_string())?;
                if !addresses.iter().any(|a| a.addr() == local_ip) {
                    add_host_address(interface, local_ip).await?;
                    owned_address = true;
                }
                match add_host_route(interface, remote_ip).await {
                    Ok(owned) => owned_route = owned,
                    Err(e) => {
                        if owned_address {
                            if let Err(rollback) = delete_host_address(interface, local_ip).await {
                                let wg_flags = info.wireguard_tunnel_id.and_then(|id| snapshot.tunnels.iter().find(|t| t.tunnel_id == id)).map(|t| (t.endpoint_ipv6, t.fec));
                                active.insert(info.tunnel_id, ActiveL2tp { info: info.clone(), tunnel, underlay: underlay.clone(), wg_flags, owned_route: false, owned_address: true, cleanup_pending: true });
                                return Err(format!("{e}; address rollback: {rollback}"));
                            }
                        }
                        return Err(e);
                    }
                }
            }
            if let Err(e) = tunnel.setup().await.map_err(|e| e.to_string()) {
                let mut rollback_error = None;
                if let Some(interface) = &underlay {
                    if owned_route { match delete_host_route(interface, remote_ip).await { Ok(()) => owned_route = false, Err(err) => rollback_error = Some(err) } }
                    if owned_address { match delete_host_address(interface, local_ip).await { Ok(()) => owned_address = false, Err(err) => rollback_error = Some(err) } }
                }
                if owned_route || owned_address {
                    let wg_flags = info.wireguard_tunnel_id.and_then(|id| snapshot.tunnels.iter().find(|t| t.tunnel_id == id)).map(|t| (t.endpoint_ipv6, t.fec));
                    active.insert(info.tunnel_id, ActiveL2tp { info: info.clone(), tunnel, underlay, wg_flags, owned_route, owned_address, cleanup_pending: true });
                }
                return Err(format!("failed to set up L2TP {}: {e}; rollback: {:?}", info.tunnel_id, rollback_error));
            }
            let wg_flags = info.wireguard_tunnel_id.and_then(|id| snapshot.tunnels.iter().find(|t| t.tunnel_id == id)).map(|t| (t.endpoint_ipv6, t.fec));
            active.insert(info.tunnel_id, ActiveL2tp { info: info.clone(), tunnel, underlay, wg_flags, owned_route, owned_address, cleanup_pending: false });
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "l2tp_integration_test.rs"]
mod integration_test;
