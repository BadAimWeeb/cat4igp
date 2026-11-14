use super::*;
use std::{process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use wireguard_control::{Backend, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

#[tokio::test]
async fn direct_policy_and_port_collision_fail_closed() {
    let mut config = crate::config::ClientConfig::default();
    config.tunnel_protocols.l2tp = true;
    let mut snapshot = TopologySnapshot { node_id: 1, revision: 1, tunnels: vec![], l2tp_v2_tunnels: vec![], l2tp_availability: None, l2tp_tunnels: vec![cat4igp_shared::control::L2tpTunnelInfo {
        tunnel_id: 1, peer_node_id: 2, local_endpoint: "192.0.2.1".into(), remote_endpoint: "192.0.2.2".into(), local_port: 51820, remote_port: 1701,
        local_session_id: 1, remote_session_id: 2, local_cookie: "0101010101010101".into(), remote_cookie: "0202020202020202".into(), security_mode: "pure".into(), wireguard_tunnel_id: None, mtu: 1500,
    }] };
    let memory = DaemonMemory::new(config.clone());
    assert!(memory.reconcile_l2tp(&snapshot).await.unwrap_err().contains("allow_insecure_l2tp"));
    config.allow_insecure_l2tp = true;
    let memory = DaemonMemory::new(config);
    assert!(memory.reconcile_l2tp(&snapshot).await.unwrap_err().contains("conflicts"));
    snapshot.l2tp_tunnels[0].local_port = 0;
    assert!(memory.reconcile_l2tp(&snapshot).await.is_err());
}

#[tokio::test]
#[ignore = "requires an isolated user/network namespace with CAP_NET_ADMIN"]
async fn reconcile_wireguard_resources_are_shared_and_cleaned() {
    use cat4igp_shared::{control::{L2tpTunnelInfo, WireguardTunnelInfo}, custom_type::WireguardAnswered};
    command(&["link", "set", "lo", "up"]);
    command(&["link", "add", "wgtest", "type", "wireguard"]);
    command(&["link", "set", "wgtest", "up"]);
    let private = Key::generate_private();
    let peer_key = Key::generate_private().get_public();
    DeviceUpdate::new().set_private_key(private).add_peer(PeerConfigBuilder::new(&peer_key).add_allowed_ip("0.0.0.0".parse().unwrap(), 0).add_allowed_ip("::".parse().unwrap(), 0).set_endpoint("127.0.0.1:41000".parse().unwrap())).apply(&"wgtest".parse::<InterfaceName>().unwrap(), Backend::Kernel).unwrap();
    let mut config = crate::config::ClientConfig::default();
    config.tunnel_protocols.l2tp = true;
    let memory = DaemonMemory::new(config);
    let os = crate::tunnel::wireguard::WireGuardTunnel::new("wgtest".into(), String::new(), String::new(), None, None);
    let wg = super::super::wireguard::WireguardTunnelC::new(10, 2, false, 1420, os, None);
    memory.wireguard.lock().await.insert(10, wg);
    for (local, remote) in [("10.253.2.1", "10.253.2.2"), ("fd00:253:2::1", "fd00:253:2::2")] {
    let info = L2tpTunnelInfo { tunnel_id: 20, peer_node_id: 2, local_endpoint: local.into(), remote_endpoint: remote.into(), local_port: 42001, remote_port: 42002, local_session_id: 1, remote_session_id: 2, local_cookie: "0101010101010101".into(), remote_cookie: "0202020202020202".into(), security_mode: "wireguard".into(), wireguard_tunnel_id: Some(10), mtu: 1500 };
    let mut second = info.clone();
    second.tunnel_id = 21;
    second.local_port = 42003;
    second.remote_port = 42004;
    let wg_info = WireguardTunnelInfo { tunnel_id: 10, peer_node_id: 2, public_key: String::new(), preferred_port: 41000, remote_endpoint: Some("192.0.2.2:41000".into()), local_answered: WireguardAnswered::Answered, remote_response: WireguardAnswered::Answered, mtu: 1420, endpoint_ipv6: false, fec: false, faketcp: false, created_at: 0, updated_at: 0, refresh_mode: Default::default(), refresh: Default::default() };
    let mut snapshot = TopologySnapshot { node_id: 1, revision: 1, tunnels: vec![wg_info], l2tp_tunnels: vec![info, second], l2tp_v2_tunnels: vec![], l2tp_availability: None };
    memory.reconcile_l2tp(&snapshot).await.unwrap();
    memory.reconcile_l2tp(&snapshot).await.unwrap();
    assert!(memory.l2tp.lock().await.get(&20).unwrap().tunnel.is_ift_created());
    assert!(memory.l2tp.lock().await.get(&21).unwrap().tunnel.is_ift_created());
    let ip: std::net::IpAddr = local.parse().unwrap();
    let peer: std::net::IpAddr = remote.parse().unwrap();
    assert!(crate::interface::get_addr("wgtest".into()).await.unwrap().iter().any(|a| a.addr() == ip));
    assert!(!add_host_route("wgtest", peer).await.unwrap());
    snapshot.l2tp_tunnels.remove(0);
    memory.remove_stale_l2tp(&snapshot).await.unwrap();
    assert!(crate::interface::get_addr("wgtest".into()).await.unwrap().iter().any(|a| a.addr() == ip));
    assert!(!add_host_route("wgtest", peer).await.unwrap());
    assert!(memory.l2tp.lock().await.get(&21).unwrap().tunnel.is_ift_created());
    snapshot.l2tp_tunnels.clear();
    memory.remove_stale_l2tp(&snapshot).await.unwrap();
    assert!(memory.l2tp.lock().await.is_empty());
    assert!(!crate::interface::get_addr("wgtest".into()).await.unwrap().iter().any(|a| a.addr() == ip));
    assert!(add_host_route("wgtest", peer).await.unwrap());
    delete_host_route("wgtest", peer).await.unwrap();
    assert!(std::ffi::CString::new("catl14").map(|n| unsafe { libc::if_nametoindex(n.as_ptr()) } == 0).unwrap());
    assert!(std::ffi::CString::new("catl15").map(|n| unsafe { libc::if_nametoindex(n.as_ptr()) } == 0).unwrap());
    }
}

#[tokio::test]
#[ignore = "requires an isolated user/network namespace with CAP_NET_ADMIN"]
async fn unmanaged_address_is_not_removed() {
    command(&["link", "add", "wgtest", "type", "wireguard"]);
    command(&["address", "add", "10.254.1.1/32", "dev", "wgtest"]);
    let ip = "10.254.1.1".parse().unwrap();
    assert!(delete_host_address("wgtest", ip).await.unwrap_err().contains("refusing"));
    assert!(crate::interface::get_addr("wgtest".into()).await.unwrap().iter().any(|address| address.addr() == ip));
}

fn command(args: &[&str]) {
    let output = std::process::Command::new("ip").args(args).output().unwrap();
    assert!(output.status.success(), "ip {args:?}: {}", String::from_utf8_lossy(&output.stderr));
}

async fn wireguard(own: &Key, peer: &Key, port: u16, other: u16, endpoint: &str, address: &str) {
    let endpoint = format!("{endpoint}:{other}").parse().unwrap();
    DeviceUpdate::new().set_private_key(own.clone()).set_listen_port(port)
        .add_peer(PeerConfigBuilder::new(&peer.get_public()).add_allowed_ip("0.0.0.0".parse().unwrap(), 0).add_allowed_ip("::".parse().unwrap(), 0).set_endpoint(endpoint))
        .apply(&"wgtest".parse::<InterfaceName>().unwrap(), Backend::Kernel).unwrap();
    command(&["address", "add", address, "dev", "wgtest"]);
    command(&["link", "set", "wgtest", "up"]);
    let (remote, local6, remote6) = if address.starts_with("10.253.1.1") { ("10.253.1.2", "fd00:253::1/128", "fd00:253::2") } else { ("10.253.1.1", "fd00:253::2/128", "fd00:253::1") };
    let remote = remote.parse().unwrap();
    command(&["route", "add", &format!("{remote}/32"), "dev", "lo"]);
    assert!(add_host_route("wgtest", remote).await.is_err());
    command(&["route", "del", &format!("{remote}/32"), "dev", "lo"]);
    assert!(add_host_route("wgtest", remote).await.unwrap());
    assert!(!add_host_route("wgtest", remote).await.unwrap());
    delete_host_route("wgtest", remote).await.unwrap();
    assert!(add_host_route("wgtest", remote).await.unwrap());
    command(&["-6", "address", "add", local6, "dev", "wgtest", "nodad"]);
    let remote6 = remote6.parse().unwrap();
    assert!(add_host_route("wgtest", remote6).await.unwrap());
    assert!(!add_host_route("wgtest", remote6).await.unwrap());
    delete_host_route("wgtest", remote6).await.unwrap();
    assert!(add_host_route("wgtest", remote6).await.unwrap());
    command(&["link", "set", "wgtest", "mtu", "1420"]);
}

async fn marker(reader: &mut BufReader<tokio::process::ChildStdout>, marker: &str) {
    let mut line = String::new();
    loop {
        line.clear();
        let count = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line)).await.unwrap().unwrap();
        assert!(count != 0, "peer exited before {marker}");
        if line.contains(marker) { break; }
    }
}

#[tokio::test]
#[ignore = "requires an isolated user/network namespace with CAP_NET_ADMIN"]
async fn l2tp_direct_and_wireguard_exchange_jumbo_packets() {
    if std::env::var_os("CAT4IGP_L2TP_TEST_CHILD").is_some() {
        let mut input = BufReader::new(tokio::io::stdin());
        let mut line = String::new();
        println!("L2TP_CHILD_WAITING");
        input.read_line(&mut line).await.unwrap();
        command(&["link", "set", "lo", "up"]);
        command(&["link", "set", "vethpeer", "up"]);
        command(&["address", "add", "192.0.2.2/24", "dev", "vethpeer"]);
        command(&["-6", "address", "add", "fd00:192::2/64", "dev", "vethpeer", "nodad"]);
        let own = Key::from_base64(&std::env::var("CAT4IGP_L2TP_KEY_B").unwrap()).unwrap();
        let peer = Key::from_base64(&std::env::var("CAT4IGP_L2TP_KEY_A").unwrap()).unwrap();
        wireguard(&own, &peer, 41002, 41001, "192.0.2.1", "10.253.1.2/32").await;
        for mode in ["pure", "pure6", "wireguard", "wireguard6"] {
            let (local, remote, underlay) = if mode == "pure" {
                ("192.0.2.2:42002", "192.0.2.1:42001", None)
            } else if mode == "pure6" {
                ("[fd00:192::2]:42002", "[fd00:192::1]:42001", None)
            } else if mode == "wireguard" {
                ("10.253.1.2:42002", "10.253.1.1:42001", Some("wgtest".to_string()))
            } else {
                ("[fd00:253::2]:42002", "[fd00:253::1]:42001", Some("wgtest".to_string()))
            };
            let mut tunnel = L2tpTunnel::new("catright".into(), 2, local.parse().unwrap(), remote.parse().unwrap(), NonZeroU32::new(102).unwrap(), NonZeroU32::new(101).unwrap(), [2; 8], [1; 8], 9000, underlay);
            tunnel.setup().await.unwrap();
            tunnel.setup().await.unwrap();
            command(&["address", "add", "10.254.0.2/30", "dev", "catright"]);
            println!("L2TP_CHILD_READY_{mode}");
            line.clear();
            input.read_line(&mut line).await.unwrap();
            assert!(tunnel.is_connected().unwrap());
            tunnel.destroy().await.unwrap();
            tunnel.destroy().await.unwrap();
        }
        return;
    }

    command(&["link", "set", "lo", "up"]);
    command(&["link", "add", "vethhost", "type", "veth", "peer", "name", "vethpeer"]);
    command(&["link", "set", "vethhost", "up"]);
    command(&["address", "add", "192.0.2.1/24", "dev", "vethhost"]);
    command(&["-6", "address", "add", "fd00:192::1/64", "dev", "vethhost", "nodad"]);
    let key_a = Key::generate_private();
    let key_b = Key::generate_private();
    let mut child = tokio::process::Command::new("unshare")
        .arg("-n").arg(std::env::current_exe().unwrap())
        .args(["--exact", "daemon::daemon_memory::l2tp::integration_test::l2tp_direct_and_wireguard_exchange_jumbo_packets", "--ignored", "--nocapture"])
        .env("CAT4IGP_L2TP_TEST_CHILD", "1")
        .env("CAT4IGP_L2TP_KEY_A", key_a.to_base64())
        .env("CAT4IGP_L2TP_KEY_B", key_b.to_base64())
        .stdin(Stdio::piped()).stdout(Stdio::piped()).kill_on_drop(true).spawn().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut input = child.stdin.take().unwrap();
    marker(&mut output, "L2TP_CHILD_WAITING").await;
    command(&["link", "set", "vethpeer", "netns", &child.id().unwrap().to_string()]);
    input.write_all(b"go\n").await.unwrap();
    wireguard(&key_a, &key_b, 41001, 41002, "192.0.2.2", "10.253.1.1/32").await;
    for mode in ["pure", "pure6", "wireguard", "wireguard6"] {
        let (local, remote, underlay) = if mode == "pure" {
            ("192.0.2.1:42001", "192.0.2.2:42002", None)
        } else if mode == "pure6" {
            ("[fd00:192::1]:42001", "[fd00:192::2]:42002", None)
        } else if mode == "wireguard" {
            ("10.253.1.1:42001", "10.253.1.2:42002", Some("wgtest".to_string()))
        } else {
            ("[fd00:253::1]:42001", "[fd00:253::2]:42002", Some("wgtest".to_string()))
        };
        let mut tunnel = L2tpTunnel::new("catleft".into(), 1, local.parse().unwrap(), remote.parse().unwrap(), NonZeroU32::new(101).unwrap(), NonZeroU32::new(102).unwrap(), [1; 8], [2; 8], 9000, underlay);
        tunnel.setup().await.unwrap();
        tunnel.setup().await.unwrap();
        command(&["address", "add", "10.254.0.1/30", "dev", "catleft"]);
        marker(&mut output, &format!("L2TP_CHILD_READY_{mode}")).await;
        let result = tokio::process::Command::new("ping").args(["-I", "catleft", "-c", "2", "-W", "3", "-s", "8000", "10.254.0.2"]).output().await.unwrap();
        assert!(result.status.success(), "{mode}: {} {}", String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
        assert!(tunnel.is_connected().unwrap());
        input.write_all(b"next\n").await.unwrap();
        tunnel.destroy().await.unwrap();
        tunnel.destroy().await.unwrap();
    }
    assert!(child.wait().await.unwrap().success());
}
