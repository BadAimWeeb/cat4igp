//! Native WireGuard configuration only. Interface addresses and all routing
//! policy remain outside this module.

use cat4igp_protocol::DesiredState;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

#[cfg(target_os = "linux")]
const BACKEND: Backend = Backend::Kernel;
#[cfg(target_os = "openbsd")]
const BACKEND: Backend = Backend::OpenBSD;
#[cfg(not(any(target_os = "linux", target_os = "openbsd")))]
const BACKEND: Backend = Backend::Userspace;

/// Reconciles server-managed point-to-point interfaces without creating routes.
pub(crate) fn apply(
    prefix: &str,
    private_key: &[u8; 32],
    state: &DesiredState,
) -> anyhow::Result<()> {
    validate_prefix(prefix)?;
    validate_interfaces(state.wireguard.iter().map(|peer| peer.interface.as_str()))?;
    let wanted: HashSet<_> = state
        .wireguard
        .iter()
        .map(|peer| peer.interface.as_str())
        .collect();
    for peer in &state.wireguard {
        let interface = managed_interface(prefix, &peer.interface)?;
        DeviceUpdate::new()
            .set_private_key(Key::from_base64(&base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                private_key,
            ))?)
            .replace_peers()
            .add_peer(peer_config(&peer.public_key, &peer.endpoint)?)
            .apply(&interface, BACKEND)?;
    }
    for interface in Device::list(BACKEND)? {
        let name = interface.as_str_lossy();
        if name.starts_with(prefix) && !wanted.contains(name.as_ref()) {
            Device::get(&interface, BACKEND)?.delete()?;
        }
    }
    Ok(())
}

fn validate_interfaces<'a>(mut interfaces: impl Iterator<Item = &'a str>) -> anyhow::Result<()> {
    let mut seen = std::collections::HashSet::new();
    if interfaces.any(|interface| !seen.insert(interface)) {
        anyhow::bail!("WireGuard interface is configured more than once");
    }
    Ok(())
}

fn managed_interface(prefix: &str, interface: &str) -> anyhow::Result<InterfaceName> {
    if !interface.starts_with(prefix)
        || interface.len() != 15
        || !interface.starts_with("catW")
        || !interface
            .bytes()
            .all(|byte| b"0123456789ABCDEFGHJKMNPQRSTVWXYZcat".contains(&byte))
    {
        anyhow::bail!("controller interface does not use the WireGuard naming convention");
    }
    Ok(InterfaceName::from_str(interface)?)
}

fn validate_prefix(prefix: &str) -> anyhow::Result<()> {
    if !prefix.starts_with("catW")
        || prefix.len() > 15
        || !prefix
            .bytes()
            .all(|byte| b"0123456789ABCDEFGHJKMNPQRSTVWXYZcat".contains(&byte))
    {
        anyhow::bail!("WireGuard interface prefix must be a catW naming-convention prefix");
    }
    Ok(())
}

fn peer_config(public_key: &str, endpoint: &str) -> anyhow::Result<PeerConfigBuilder> {
    Ok(PeerConfigBuilder::new(&Key::from_base64(public_key)?)
        .set_endpoint(SocketAddr::from_str(endpoint)?)
        .replace_allowed_ips()
        .add_allowed_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        .add_allowed_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
}

#[cfg(test)]
mod tests {
    #[test]
    fn peer_config_accepts_default_selectors() {
        assert!(
            super::peer_config(
                &base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0; 32]),
                "127.0.0.1:51820",
            )
            .is_ok()
        );
    }

    #[test]
    fn interfaces_are_unique_per_point_to_point_link() {
        assert!(super::validate_interfaces(["cat-a", "cat-b"].into_iter()).is_ok());
        assert!(super::validate_interfaces(["cat-a", "cat-a"].into_iter()).is_err());
    }

    #[test]
    fn naming_requires_wireguard_convention() {
        assert!(super::managed_interface("catW", "catW00000000000").is_ok());
        assert!(super::managed_interface("catW", "catX00000000000").is_err());
    }
}
