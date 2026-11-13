use std::net::{IpAddr, Ipv4Addr};

use futures_util::TryStreamExt;
use rtnetlink::{
    new_connection, Handle, IpVersion, RouteMessageBuilder,
    packet_route::{
        address::AddressAttribute,
        route::{RouteAttribute, RouteMessage, RouteProtocol, RouteType},
        rule::{RuleAction, RuleAttribute, RuleMessage},
    },
};

// This priority precedes the standard main table rule. A different rule at or
// before it must not be allowed to divert packets before confinement.
const PRIORITY: u32 = 1000;
const PROTOCOL: RouteProtocol = RouteProtocol::Other(253);
const TABLE_BASE: u32 = 0x4000_0000;

struct ConnectionTask(tokio::task::JoinHandle<()>);
impl Drop for ConnectionTask {
    fn drop(&mut self) { self.0.abort(); }
}

fn table_of_route(route: &RouteMessage) -> u32 {
    route.attributes.iter().find_map(|a| match a {
        RouteAttribute::Table(table) => Some(*table), _ => None,
    }).unwrap_or(route.header.table as u32)
}

fn table_of_rule(rule: &RuleMessage) -> u32 {
    rule.attributes.iter().find_map(|a| match a {
        RuleAttribute::Table(table) => Some(*table), _ => None,
    }).unwrap_or(rule.header.table as u32)
}

fn priority(rule: &RuleMessage) -> u32 {
    rule.attributes.iter().find_map(|a| match a {
        RuleAttribute::Priority(value) => Some(*value), _ => None,
    }).unwrap_or(0)
}

fn owned_rule(rule: &RuleMessage, source: Ipv4Addr, table: u32) -> bool {
    priority(rule) == PRIORITY && table_of_rule(rule) == table
        && rule.header.src_len == 32 && rule.header.dst_len == 0
        && rule.header.tos == 0 && rule.header.flags.is_empty()
        && rule.header.action == RuleAction::ToTable
        && rule.attributes.iter().any(|a| matches!(a, RuleAttribute::Source(IpAddr::V4(ip)) if *ip == source))
        && rule.attributes.iter().any(|a| matches!(a, RuleAttribute::Protocol(p) if *p == PROTOCOL))
        && rule.attributes.iter().all(|a| matches!(a, RuleAttribute::Source(_) | RuleAttribute::Priority(_) | RuleAttribute::Table(_) | RuleAttribute::Protocol(_) | RuleAttribute::SuppressPrefixLen(u32::MAX)))
}

fn other_owned_rule(rule: &RuleMessage, source: Ipv4Addr) -> bool {
    let other = rule.attributes.iter().find_map(|a| match a {
        RuleAttribute::Source(IpAddr::V4(ip)) => Some(*ip), _ => None,
    });
    other.is_some_and(|ip| ip != source && table_of_rule(rule) >= TABLE_BASE
        && owned_rule(rule, ip, table_of_rule(rule)))
}

async fn rules(handle: &Handle) -> Result<Vec<RuleMessage>, String> {
    handle.rule().get(IpVersion::V4).execute().try_collect().await.map_err(|e| e.to_string())
}

async fn routes(handle: &Handle, table: u32) -> Result<Vec<RouteMessage>, String> {
    let all: Vec<RouteMessage> = handle.route().get(RouteMessageBuilder::<Ipv4Addr>::new().build())
        .execute().try_collect().await.map_err(|e| e.to_string())?;
    Ok(all.into_iter().filter(|r| table_of_route(r) == table).collect())
}

/// Owns one private RPDB rule and table. Call destroy only after the UDP socket
/// is closed and the source address has been removed. Privileged external route
/// or rule changes cannot be protected against by this policy.
pub(crate) struct Policy {
    source: Ipv4Addr,
    table: u32,
    index: u32,
    remote: Ipv4Addr,
    rule_installed: bool,
    host_installed: bool,
    reject_installed: bool,
}

impl Policy {
    pub(crate) async fn setup(interface: &str, local: Ipv4Addr, remote: Ipv4Addr, id: i32) -> Result<Self, (String, Option<Self>)> {
        let mut retained = None;
        Self::setup_inner(interface, local, remote, id, &mut retained).await.map_err(|e| (e, retained))
    }

    async fn setup_inner(interface: &str, local: Ipv4Addr, remote: Ipv4Addr, id: i32, retained: &mut Option<Self>) -> Result<Self, String> {
        let id = u32::try_from(id).map_err(|_| "invalid L2TPv2 tunnel id")?;
        let table = TABLE_BASE.checked_add(id).ok_or("invalid L2TPv2 tunnel id")?;
        if local == remote || local.is_unspecified() || remote.is_unspecified() || local.is_multicast() || remote.is_multicast() || local.is_broadcast() || remote.is_broadcast() {
            return Err("invalid L2TPv2 underlay addresses".into());
        }
        let (connection, handle, _) = new_connection().map_err(|e| e.to_string())?;
        let _task = ConnectionTask(tokio::spawn(connection));
        let index = handle.link().get().match_name(interface.to_owned()).execute().try_next().await
            .map_err(|e| e.to_string())?.ok_or("WireGuard interface missing")?.header.index;
        let mut addresses = handle.address().get().execute();
        while let Some(address) = addresses.try_next().await.map_err(|e| e.to_string())? {
            if address.attributes.iter().any(|a| matches!(a, AddressAttribute::Address(ip) | AddressAttribute::Local(ip) if *ip == IpAddr::V4(local) || *ip == IpAddr::V4(remote))) {
                return Err(format!("L2TPv2 underlay address already assigned: {local} or {remote}"));
            }
        }
        if !routes(&handle, table).await?.is_empty() { return Err(format!("routing table {table} already in use")); }
        for rule in rules(&handle).await? {
            let p = priority(&rule);
            // The kernel's unmodified local rule is the sole permitted earlier rule.
            let local_rule = p == 0 && table_of_rule(&rule) == 255 && rule.header.action == RuleAction::ToTable
                && rule.header.src_len == 0 && rule.header.dst_len == 0 && rule.header.tos == 0 && rule.header.flags.is_empty()
                && rule.attributes.iter().all(|a| matches!(a, RuleAttribute::Table(_) | RuleAttribute::Priority(_) | RuleAttribute::Protocol(_) | RuleAttribute::SuppressPrefixLen(u32::MAX)));
            if table_of_rule(&rule) == table || (p <= PRIORITY && !local_rule && !other_owned_rule(&rule, local)) {
                return Err(format!("conflicting IPv4 policy rule at priority {p}: {rule:?}"));
            }
        }
        let mut policy = Self { source: local, table, index, remote, rule_installed: false, host_installed: false, reject_installed: false };
        let result: Result<(), String> = async {
            handle.route().add(policy.reject_route()).execute().await.map_err(|e| e.to_string())?;
            policy.reject_installed = true;
            handle.route().add(policy.host_route()).execute().await.map_err(|e| e.to_string())?;
            policy.host_installed = true;
            let mut request = handle.rule().add().v4().source_prefix(local, 32).table_id(table).priority(PRIORITY).action(RuleAction::ToTable);
            request.message_mut().attributes.push(RuleAttribute::Protocol(PROTOCOL));
            request.execute().await.map_err(|e| e.to_string())?;
            policy.rule_installed = true;
            Ok(())
        }.await;
        if let Err(error) = result {
            return match policy.cleanup(&handle).await {
                Ok(()) => Err(error),
                Err(cleanup) => {
                    *retained = Some(policy);
                    Err(format!("{error}; rollback incomplete: {cleanup}; retained table {table}, source {local}"))
                }
            };
        }
        Ok(policy)
    }

    fn reject_route(&self) -> RouteMessage {
        RouteMessageBuilder::<Ipv4Addr>::new().table_id(self.table).protocol(PROTOCOL).kind(RouteType::Unreachable).build()
    }

    fn host_route(&self) -> RouteMessage {
        RouteMessageBuilder::<Ipv4Addr>::new().table_id(self.table).protocol(PROTOCOL)
            .destination_prefix(self.remote, 32).output_interface(self.index).build()
    }

    pub(crate) async fn destroy(&mut self) -> Result<(), String> {
        let (connection, handle, _) = new_connection().map_err(|e| e.to_string())?;
        let _task = ConnectionTask(tokio::spawn(connection));
        self.cleanup(&handle).await
    }

    async fn cleanup(&mut self, handle: &Handle) -> Result<(), String> {
        if self.rule_installed {
            let matching: Vec<_> = rules(handle).await?.into_iter().filter(|r| priority(r) == PRIORITY && table_of_rule(r) == self.table).collect();
            if matching.len() != 1 || !owned_rule(&matching[0], self.source, self.table) {
                return Err("L2TPv2 policy rule missing or replaced; refusing cleanup".into());
            }
            handle.rule().del(matching[0].clone()).execute().await.map_err(|e| e.to_string())?;
            self.rule_installed = false;
        }
        let current = routes(handle, self.table).await?;
        for route in current {
            let is_host = route.header.destination_prefix_length == 32 && route.header.kind == RouteType::Unicast
                && route.attributes.iter().any(|a| matches!(a, RouteAttribute::Destination(ip) if *ip == self.remote.into()))
                && route.attributes.iter().any(|a| matches!(a, RouteAttribute::Oif(i) if *i == self.index))
                && !route.attributes.iter().any(|a| matches!(a, RouteAttribute::Gateway(_) | RouteAttribute::Via(_) | RouteAttribute::MultiPath(_)));
            let is_reject = route.header.destination_prefix_length == 0 && route.header.kind == RouteType::Unreachable;
            if route.header.protocol != PROTOCOL || !(is_host && self.host_installed || is_reject && self.reject_installed) {
                return Err(format!("routing table {} contains a foreign route; refusing cleanup", self.table));
            }
            handle.route().del(route).execute().await.map_err(|e| e.to_string())?;
            if is_host { self.host_installed = false; } else { self.reject_installed = false; }
        }
        // Deleting an interface removes its host route automatically.
        self.host_installed = false;
        self.reject_installed = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ownership_requires_exact_source_and_protocol() {
        let source = Ipv4Addr::new(192, 0, 2, 1);
        let mut rule = RuleMessage::default();
        rule.header.src_len = 32;
        rule.header.action = RuleAction::ToTable;
        rule.attributes = vec![RuleAttribute::Source(source.into()), RuleAttribute::Table(TABLE_BASE),
            RuleAttribute::Priority(PRIORITY), RuleAttribute::Protocol(PROTOCOL)];
        assert!(owned_rule(&rule, source, TABLE_BASE));
        assert!(!owned_rule(&rule, Ipv4Addr::new(192, 0, 2, 2), TABLE_BASE));
        rule.attributes.push(RuleAttribute::FwMark(1));
        assert!(!owned_rule(&rule, source, TABLE_BASE));
    }

    #[tokio::test]
    #[ignore = "requires an isolated Linux network namespace and CAP_NET_ADMIN"]
    async fn policy_routes_to_wireguard_and_drops_when_it_disappears() {
        fn ip(args: &[&str]) -> std::process::Output { std::process::Command::new("ip").args(args).output().unwrap() }
        assert!(ip(&["link", "add", "wgpolicy", "type", "wireguard"]).status.success());
        assert!(ip(&["link", "set", "wgpolicy", "up"]).status.success());
        let local = Ipv4Addr::new(198, 18, 0, 1);
        let remote = Ipv4Addr::new(198, 18, 0, 2);
        let mut policy = Policy::setup("wgpolicy", local, remote, 100).await.map_err(|(e, _)| e).unwrap();
        assert!(ip(&["addr", "add", "198.18.0.1/32", "dev", "wgpolicy"]).status.success());
        let route = ip(&["route", "get", "198.18.0.2", "from", "198.18.0.1"]);
        assert!(route.status.success() && String::from_utf8_lossy(&route.stdout).contains("dev wgpolicy"));
        assert!(ip(&["link", "del", "wgpolicy"]).status.success());
        let route = ip(&["route", "get", "198.18.0.2", "from", "198.18.0.1"]);
        assert!(!route.status.success(), "missing WireGuard route must not fall through");
        policy.destroy().await.unwrap();
    }
}
