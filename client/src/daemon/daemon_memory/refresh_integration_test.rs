use super::{DaemonMemory, wireguard::WireguardTunnelC};
use crate::{config::ClientConfig, tunnel::shared::Tunnel};
use cat4igp_shared::{control::{RefreshMode, RefreshOffer, TopologySnapshot, WireguardTunnelInfo}, custom_type::WireguardAnswered};
use std::{process::Stdio, sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use wireguard_control::{Backend, Device, InterfaceName, Key};

const ID: i32 = 0x12345;
const TEST: &str = "daemon::daemon_memory::refresh_integration_test::kernel_dual_link_refresh";

fn ip(args: &[&str]) {
    let output = std::process::Command::new("ip").args(args).output().unwrap();
    assert!(output.status.success(), "ip {args:?}: {}", String::from_utf8_lossy(&output.stderr));
}

fn info(peer_id: i32, peer: &Key, endpoint: &str) -> WireguardTunnelInfo {
    WireguardTunnelInfo {
        tunnel_id: ID, peer_node_id: peer_id, public_key: peer.get_public().to_base64(),
        preferred_port: 51820, remote_endpoint: Some(endpoint.into()),
        local_answered: WireguardAnswered::Answered, remote_response: WireguardAnswered::Answered,
        mtu: 1420, endpoint_ipv6: false, fec: false, faketcp: false,
        created_at: 0, updated_at: 0, refresh_mode: RefreshMode::DualLink, refresh: Default::default(),
    }
}

fn snapshot(info: Option<WireguardTunnelInfo>) -> TopologySnapshot {
    TopologySnapshot { node_id: 1, revision: 1, tunnels: info.into_iter().collect(), l2tp_tunnels: vec![], l2tp_v2_tunnels: vec![], l2tp_availability: None }
}

fn name(info: &WireguardTunnelInfo, alternate: bool) -> String {
    WireguardTunnelC::gen_new_wg_tunnel(Arc::new(info.clone()), String::new(), None, 0, 0, alternate).get_interface_name().to_owned()
}

fn device(name: &str) -> Device {
    Device::get(&name.parse::<InterfaceName>().unwrap(), Backend::Kernel).unwrap()
}

fn exists(name: &str) -> bool {
    let name = std::ffi::CString::new(name).unwrap();
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index != 0 { return true; }
    let error = std::io::Error::last_os_error();
    assert_eq!(error.raw_os_error(), Some(libc::ENODEV), "interface lookup failed: {error}");
    false
}

fn handshaken(name: &str, local: &Key, peer: &Key) -> bool {
    let device = device(name);
    assert_eq!(device.public_key, Some(local.get_public()));
    let peer = device.peers.iter().find(|p| p.config.public_key == peer.get_public()).unwrap();
    peer.stats.last_handshake_time.is_some()
}

async fn signal(input: &mut tokio::process::ChildStdin, value: &str) {
    input.write_all(format!("{value}\n").as_bytes()).await.unwrap();
}

async fn receive<R: tokio::io::AsyncBufRead + Unpin>(input: &mut R, expected: &str) {
    let mut line = String::new();
    loop {
        line.clear();
        let n = tokio::time::timeout(Duration::from_secs(45), input.read_line(&mut line)).await.unwrap().unwrap();
        assert!(n != 0, "peer exited before {expected}");
        if line.contains(expected) { return; }
    }
}

async fn ping(local: &str, remote: &str) {
    let address = crate::interface::generate_ipv6_lla_from_seed(remote.as_bytes().to_vec());
    for _ in 0..10 {
        let result = tokio::process::Command::new("ping").args(["-6", "-I", local, "-c", "1", "-W", "2", &address.to_string()]).output().await.unwrap();
        if result.status.success() { return; }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("no traffic over {local} to {remote}");
}

#[tokio::test]
#[ignore = "requires Linux kernel WireGuard, ip, ping, unshare and CAP_NET_ADMIN in an isolated network namespace"]
async fn kernel_dual_link_refresh() {
    let child_side = std::env::var_os("CAT4IGP_REFRESH_TEST_CHILD").is_some();
    let keys: Vec<Key> = (0..4).map(|i| if child_side {
        Key::from_base64(&std::env::var(format!("CAT4IGP_REFRESH_KEY_{i}")).unwrap()).unwrap()
    } else { Key::generate_private() }).collect();
    let (old, old_peer, new, new_peer, peer_id, endpoint, new_endpoint) = if child_side {
        (&keys[1], &keys[0], &keys[3], &keys[2], 1, "192.0.2.1:51820", "192.0.2.1:51821")
    } else {
        (&keys[0], &keys[1], &keys[2], &keys[3], 2, "192.0.2.2:51820", "192.0.2.2:51821")
    };
    let info = info(peer_id, old_peer, endpoint);
    let old_name = name(&info, false);
    let new_name = name(&info, true);
    let old_bits = base32::decode(base32::Alphabet::Crockford, &old_name[3..]).unwrap();
    let new_bits = base32::decode(base32::Alphabet::Crockford, &new_name[3..]).unwrap();
    assert_eq!(old_bits.len(), new_bits.len());
    assert_eq!(old_bits[2] ^ new_bits[2], 1);
    assert!(old_bits.iter().zip(&new_bits).enumerate().all(|(i, (a, b))| i == 2 || a == b));
    let memory = DaemonMemory::new(ClientConfig::default());
    let snap = snapshot(Some(info.clone()));
    let mut stdin = BufReader::new(tokio::io::stdin());

    if child_side {
        println!("REFRESH_WAITING");
        receive(&mut stdin, "START").await;
        ip(&["link", "set", "lo", "up"]);
        ip(&["link", "set", "vethpeer", "up"]);
        ip(&["address", "add", "192.0.2.2/24", "dev", "vethpeer"]);
    } else {
        ip(&["link", "set", "lo", "up"]);
        ip(&["link", "add", "vethhost", "type", "veth", "peer", "name", "vethpeer"]);
        ip(&["link", "set", "vethhost", "up"]);
        ip(&["address", "add", "192.0.2.1/24", "dev", "vethhost"]);
    }

    let mut child = if !child_side {
        let mut command = tokio::process::Command::new("unshare");
        command.arg("-n").arg(std::env::current_exe().unwrap()).args(["--exact", TEST, "--ignored", "--nocapture"])
            .env("CAT4IGP_REFRESH_TEST_CHILD", "1").stdin(Stdio::piped()).stdout(Stdio::piped()).kill_on_drop(true);
        for (i, key) in keys.iter().enumerate() { command.env(format!("CAT4IGP_REFRESH_KEY_{i}"), key.to_base64()); }
        let mut child = command.spawn().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut input = child.stdin.take().unwrap();
        receive(&mut output, "REFRESH_WAITING").await;
        ip(&["link", "set", "vethpeer", "netns", &child.id().unwrap().to_string()]);
        signal(&mut input, "START").await;
        Some((child, input, output))
    } else { None };

    memory.restore_active_wireguard(&info, &old.to_base64(), 51820, false).await.unwrap();
    memory.reserve_refresh_port(ID, Some(51821)).await.unwrap();
    memory.prepare_refresh(&info, &new.to_base64(), &RefreshOffer { public_key: new_peer.get_public().to_base64(), endpoint: new_endpoint.into() }, true).await.unwrap();
    let mut remote_info = info.clone();
    remote_info.peer_node_id = if child_side { 2 } else { 1 };
    for (local, remote) in [(&old_name, name(&remote_info, false)), (&new_name, name(&remote_info, true))] {
        let address = crate::interface::generate_ipv6_lla_from_seed(remote.as_bytes().to_vec());
        ip(&["-6", "route", "add", &format!("{address}/128"), "dev", local, "proto", "253"]);
    }
    assert!(exists(&old_name) && exists(&new_name));
    assert!(memory.active_matches(ID, &old.get_public().to_base64()).await.unwrap());

    if child_side {
        println!("REFRESH_READY");
        receive(&mut stdin, "SWITCH").await;
        assert!(handshaken(&old_name, old, old_peer));
        assert!(handshaken(&new_name, new, new_peer));
        assert!(memory.refresh_connected(ID).await);
    } else {
        let (_, input, output) = child.as_mut().unwrap();
        receive(output, "REFRESH_READY").await;
        let remote_info = info_for_remote(old, "192.0.2.1:51820");
        ping(&old_name, &name(&remote_info, false)).await;
        ping(&new_name, &name(&remote_info, true)).await;
        assert!(handshaken(&old_name, old, old_peer));
        assert!(handshaken(&new_name, new, new_peer));
        assert!(memory.refresh_connected(ID).await);
        signal(input, "SWITCH").await;
    }
    memory.switch_refresh(ID, &snap).await.unwrap();
    assert!(memory.refresh_is_switched(ID).await);
    assert!(memory.active_matches(ID, &new.get_public().to_base64()).await.unwrap());
    assert!(exists(&old_name) && exists(&new_name));
    memory.finish_refresh(ID).await.unwrap();
    assert!(!memory.refresh_is_switched(ID).await);
    assert!(!exists(&old_name) && exists(&new_name));
    if child_side {
        println!("REFRESH_SWITCHED");
        receive(&mut stdin, "CLEANUP").await;
    } else {
        let (_, input, output) = child.as_mut().unwrap();
        receive(output, "REFRESH_SWITCHED").await;
        ping(&new_name, &name(&info_for_remote(old, "192.0.2.1:51820"), true)).await;
        signal(input, "CLEANUP").await;
    }
    memory.reconcile_wireguard_tunnels(&snapshot(None), &new.to_base64()).await.unwrap();
    assert!(!exists(&old_name) && !exists(&new_name));
    assert_eq!(memory.wireguard_len().await, 0);
    if let Some((mut child, _, _)) = child { assert!(child.wait().await.unwrap().success()); }
}

fn info_for_remote(peer: &Key, endpoint: &str) -> WireguardTunnelInfo { info(1, peer, endpoint) }
