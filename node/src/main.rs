//! CAT4IGP node.
//!
//! Applies only verified server state. WireGuard peers use default IPv4/IPv6
//! AllowedIPs as cryptokey-routing selectors; this program never manages routes.

pub mod command;
pub mod enrollment;
pub mod keys;
pub mod p2p;
pub mod state_store;
pub mod wireguard;

#[derive(serde::Deserialize)]
struct Config {
    data_dir: std::path::PathBuf,
    network: String,
    controller: libp2p::Multiaddr,
    enrollment_token: String,
    server_ed25519_base64: String,
    wireguard_interface_prefix: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config: Config = serde_json::from_slice(&read_config(config_path()?)?)?;
    let data_dir = config.data_dir;
    let network = cat4igp_protocol::NetworkId::new(config.network)?;
    let controller = config.controller;
    let controller_id = controller
        .iter()
        .last()
        .and_then(|protocol| match protocol {
            libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("CONTROLLER_MULTIADDR requires a /p2p peer ID"))?;
    let server_key = ed25519_dalek::VerifyingKey::from_bytes(
        &base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            config.server_ed25519_base64,
        )?
        .try_into()
        .map_err(|_| anyhow::anyhow!("SERVER_ED25519_BASE64 must decode to 32 bytes"))?,
    )?;
    let identity = keys::load_or_create_libp2p(data_dir.join("libp2p.key"))?;
    let command_key = keys::load_or_create_command_key(data_dir.join("command.key"))?;
    let wireguard_key = keys::load_or_create_wireguard_key(data_dir.join("wireguard.key"))?;
    let state_store = state_store::StateStore::new(data_dir.join("desired-state.json"));
    if let Some(state) = state_store.desired_state(cat4igp_protocol::unix_now())? {
        wireguard::apply(&config.wireguard_interface_prefix, &wireguard_key, &state)?;
    }
    let request = enrollment::build_request(
        config.enrollment_token,
        data_dir.join("libp2p.key"),
        data_dir.join("command.key"),
        data_dir.join("wireguard.key"),
    )?;
    let mut swarm = p2p::swarm(identity)?;
    let controller = p2p::BootstrapPeer {
        peer_id: controller_id,
        address: controller,
    };
    p2p::dial_bootstrap(&mut swarm, controller.clone())?;
    p2p::request_enrollment(&mut swarm, controller_id, request);
    p2p::run_control(
        &mut swarm,
        &controller,
        &network,
        &command_key,
        &server_key,
        &state_store,
        |state| wireguard::apply(&config.wireguard_interface_prefix, &wireguard_key, &state),
    )
    .await
}

fn config_path() -> anyhow::Result<std::path::PathBuf> {
    std::env::args_os()
        .nth(1)
        .map(Into::into)
        .ok_or_else(|| anyhow::anyhow!("usage: cat4igp-node CONFIG.json"))
}

fn read_config(path: std::path::PathBuf) -> anyhow::Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(&path)?.permissions().mode() & 0o077 != 0 {
            anyhow::bail!(
                "node config containing enrollment authorization must not be group/world accessible"
            );
        }
    }
    Ok(std::fs::read(path)?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_requires_a_config_path() {
        assert!("usage: cat4igp-node CONFIG.json".contains("CONFIG.json"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_readable_config() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("cat4igp-config-{}", std::process::id()));
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(super::read_config(path.clone()).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
