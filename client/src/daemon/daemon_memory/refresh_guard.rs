use futures_util::TryStreamExt;
use rtnetlink::{new_connection, RouteMessageBuilder, packet_route::{address::{AddressAttribute, AddressProtocol}, route::{RouteAttribute, RouteProtocol}}};
use std::net::{Ipv4Addr, Ipv6Addr};

pub(super) async fn ensure_removable(interface: &str) -> Result<(), String> {
    let (connection, handle, _) = new_connection().map_err(|e| e.to_string())?;
    let task = tokio::spawn(connection);
    let result = async {
        let index = handle.link().get().match_name(interface.to_owned()).execute().try_next().await.map_err(|e| e.to_string())?.ok_or("WireGuard interface missing")?.header.index;
        let expected = crate::interface::generate_ipv6_lla_from_seed(interface.as_bytes().to_vec());
        let mut addresses = handle.address().get().set_link_index_filter(index).execute();
        while let Some(address) = addresses.try_next().await.map_err(|e| e.to_string())? {
            let owned = address.attributes.iter().any(|a| matches!(a, AddressAttribute::Protocol(AddressProtocol::Other(253))));
            let ips = address.attributes.iter().filter_map(|a| match a { AddressAttribute::Address(ip) | AddressAttribute::Local(ip) => Some(*ip), _ => None });
            if !owned && ips.into_iter().any(|ip| ip != expected) {
                return Err(format!("cannot retire {interface}: externally managed address present"));
            }
        }
        for ipv6 in [false, true] {
            let query = if ipv6 { RouteMessageBuilder::<Ipv6Addr>::new().build() } else { RouteMessageBuilder::<Ipv4Addr>::new().build() };
            let mut routes = handle.route().get(query).execute();
            while let Some(route) = routes.try_next().await.map_err(|e| e.to_string())? {
                let uses_interface = route.attributes.iter().any(|a| match a {
                    RouteAttribute::Oif(i) => *i == index,
                    RouteAttribute::MultiPath(hops) => hops.iter().any(|hop| hop.interface_index == index),
                    _ => false,
                });
                if uses_interface && !matches!(route.header.protocol, RouteProtocol::Kernel | RouteProtocol::Other(253) | RouteProtocol::Gated | RouteProtocol::Zebra | RouteProtocol::Bird | RouteProtocol::Babel | RouteProtocol::Bgp | RouteProtocol::Isis | RouteProtocol::Ospf | RouteProtocol::Rip | RouteProtocol::Eigrp) {
                    return Err(format!("cannot retire {interface}: externally managed route present ({:?})", route.header.protocol));
                }
            }
        }
        Ok(())
    }.await;
    task.abort();
    result
}
