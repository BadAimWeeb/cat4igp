use super::{DaemonMemory, wireguard::WireguardTunnelC};
use crate::{config::ClientConfig, tunnel::shared::Tunnel};
use cat4igp_shared::{control::{L2tpTunnelInfo, TopologySnapshot, WireguardTunnelInfo}, custom_type::WireguardAnswered};
use std::{process::Stdio, sync::Arc, time::{Duration, Instant}};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use wireguard_control::Key;

const FILTER: &str = "daemon::daemon_memory::l2tp_recovery_test::paired_snapshot_dependency_recovery";

fn ip(args: &[&str]) {
    let output = std::process::Command::new("ip").args(args).output().unwrap();
    assert!(output.status.success(), "ip {args:?}: {}", String::from_utf8_lossy(&output.stderr));
}
fn exists(name: &str) -> bool {
    let name = std::ffi::CString::new(name).unwrap();
    unsafe { libc::if_nametoindex(name.as_ptr()) != 0 }
}
async fn marker<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R, expected: &str) {
    let mut line = String::new();
    loop {
        line.clear();
        let count = tokio::time::timeout(Duration::from_secs(15), reader.read_line(&mut line)).await.unwrap().unwrap();
        assert_ne!(count, 0, "peer exited before {expected}");
        if line.split_whitespace().last() == Some(expected) { return; }
    }
}
async fn ping(interface: &str, target: &str) {
    let mut last_output = String::new();
    for _ in 0..5 {
        let output = tokio::process::Command::new("ping").args(["-n", "-I", interface, "-c", "1", "-W", "1", target]).output().await.unwrap();
        if output.status.success() { return; }
        last_output = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("L2TP traffic did not recover on {interface}: {last_output}");
}

#[tokio::test]
#[ignore = "disposable isolated network namespace: CAP_NET_ADMIN, kernel WireGuard, /dev/net/tun, ip, ping, unshare"]
async fn paired_snapshot_dependency_recovery() {
    let child_side = std::env::var_os("CAT4IGP_L2TP_RECOVERY_CHILD").is_some();
    let keys: Vec<Key> = (0..2).map(|index| if child_side {
        Key::from_base64(&std::env::var(format!("CAT4IGP_L2TP_RECOVERY_KEY_{index}")).unwrap()).unwrap()
    } else { Key::generate_private() }).collect();
    let index = usize::from(child_side);
    let mut input = BufReader::new(tokio::io::stdin());
    ip(&["link", "set", "lo", "up"]);
    if child_side {
        println!("RECOVERY_WAITING");
        marker(&mut input, "START").await;
    } else {
        ip(&["link", "add", "recoverhost", "type", "veth", "peer", "name", "recoverpeer"]);
    }
    let mut child = if !child_side {
        let mut command = tokio::process::Command::new("unshare");
        command.arg("-n").arg(std::env::current_exe().unwrap()).args(["--exact", FILTER, "--ignored", "--nocapture"])
            .env("CAT4IGP_L2TP_RECOVERY_CHILD", "1").stdin(Stdio::piped()).stdout(Stdio::piped()).kill_on_drop(true);
        for (index, key) in keys.iter().enumerate() { command.env(format!("CAT4IGP_L2TP_RECOVERY_KEY_{index}"), key.to_base64()); }
        let mut process = command.spawn().unwrap();
        let mut output = BufReader::new(process.stdout.take().unwrap());
        let mut commands = process.stdin.take().unwrap();
        marker(&mut output, "RECOVERY_WAITING").await;
        ip(&["link", "set", "recoverpeer", "netns", &process.id().unwrap().to_string()]);
        commands.write_all(b"START\n").await.unwrap();
        Some((process, commands, output))
    } else { None };
    let device = if child_side { "recoverpeer" } else { "recoverhost" };
    ip(&["addr", "add", &format!("192.0.2.{}/24", index+1), "dev", device]);
    ip(&["link", "set", device, "up"]);
    ip(&["link", "add", "sentinel50", "type", "dummy"]);
    ip(&["addr", "add", "198.19.50.1/32", "dev", "sentinel50"]);
    ip(&["link", "set", "sentinel50", "up"]);
    let wg = WireguardTunnelInfo {
        tunnel_id: 50, peer_node_id: (2-index) as i32, public_key: keys[1-index].get_public().to_base64(),
        preferred_port: 41500, remote_endpoint: Some(format!("192.0.2.{}:41500", 2-index)),
        local_answered: WireguardAnswered::Answered, remote_response: WireguardAnswered::Answered,
        mtu: 1420, endpoint_ipv6: false, fec: false, faketcp: false, created_at: 0, updated_at: 0,
        refresh_mode: Default::default(), refresh: Default::default(),
    };
    let wg_name = WireguardTunnelC::gen_new_wg_tunnel(Arc::new(wg.clone()), String::new(), None, 0, 0, false).get_interface_name().to_owned();
    let l2tp = L2tpTunnelInfo {
        tunnel_id: 50, peer_node_id: (2-index) as i32,
        local_endpoint: format!("10.253.50.{}", index+1), remote_endpoint: format!("10.253.50.{}", 2-index),
        local_port: 42500, remote_port: 42500, local_session_id: 101+index as u32, remote_session_id: 102-index as u32,
        local_cookie: if child_side { "0202020202020202" } else { "0101010101010101" }.into(),
        remote_cookie: if child_side { "0101010101010101" } else { "0202020202020202" }.into(),
        security_mode: "wireguard".into(), wireguard_tunnel_id: Some(50), mtu: 1500,
    };
    let mut snapshot = TopologySnapshot { node_id: index as i32+1, revision: 1, tunnels: vec![wg], l2tp_tunnels: vec![l2tp], l2tp_v2_tunnels: vec![], l2tp_availability: None };
    let mut config = ClientConfig::default();
    config.tunnel_protocols.l2tp = true;
    // The actuator allocates from the configured range, not preferred_port.
    // Keep the real listener aligned with the endpoint advertised to the peer.
    config.port_range.min = 41500;
    config.port_range.max = 41501;
    let memory = DaemonMemory::new(config);
    memory.apply_topology_snapshot(snapshot.clone(), &keys[index].to_base64()).await.unwrap();
    ip(&["addr", "add", &format!("198.18.50.{}/30", index+1), "dev", "catl32"]);
    if let Some((_, commands, output)) = child.as_mut() {
        marker(output, "INITIAL_READY").await;
        ping("catl32", "198.18.50.2").await;
        commands.write_all(b"INITIAL_TRAFFIC\n").await.unwrap();
        marker(output, "INITIAL_DONE").await;
    } else {
        println!("INITIAL_READY");
        marker(&mut input, "INITIAL_TRAFFIC").await;
        ping("catl32", "198.18.50.1").await;
        println!("INITIAL_DONE");
    }
    let started = Instant::now();
    let empty = TopologySnapshot { node_id: snapshot.node_id, revision: 2, tunnels: vec![], l2tp_tunnels: vec![], l2tp_v2_tunnels: vec![], l2tp_availability: None };
    memory.apply_topology_snapshot(empty.clone(), &keys[index].to_base64()).await.unwrap();
    assert!(!exists("catl32") && !exists(&wg_name));
    assert!(exists("sentinel50"));
    assert!(crate::interface::get_addr("sentinel50".into()).await.unwrap().iter().any(|address| address.addr() == "198.19.50.1".parse::<std::net::IpAddr>().unwrap()));
    if let Some((_, commands, output)) = child.as_mut() {
        marker(output, "REMOVED").await;
        commands.write_all(b"RESTORE\n").await.unwrap();
    } else {
        println!("REMOVED");
        marker(&mut input, "RESTORE").await;
    }
    snapshot.revision = 3;
    memory.apply_topology_snapshot(snapshot, &keys[index].to_base64()).await.unwrap();
    ip(&["addr", "add", &format!("198.18.50.{}/30", index+1), "dev", "catl32"]);
    if let Some((_, commands, output)) = child.as_mut() {
        marker(output, "RESTORED").await;
        ping("catl32", "198.18.50.2").await;
        commands.write_all(b"RESTORED_TRAFFIC\n").await.unwrap();
        marker(output, "RECOVERED").await;
    } else {
        println!("RESTORED");
        marker(&mut input, "RESTORED_TRAFFIC").await;
        ping("catl32", "198.18.50.1").await;
        println!("RECOVERED");
    }
    assert!(started.elapsed() < Duration::from_secs(10), "reference snapshot recovery exceeded ten seconds");
    println!("reference_l2tp_snapshot_recovery_ms={}", started.elapsed().as_millis());
    memory.apply_topology_snapshot(empty, &keys[index].to_base64()).await.unwrap();
    assert!(!exists("catl32") && !exists(&wg_name) && exists("sentinel50"));
    ip(&["link", "del", "sentinel50"]);
    if let Some((mut process, _, _)) = child {
        assert!(tokio::time::timeout(Duration::from_secs(10), process.wait()).await.unwrap().unwrap().success());
        ip(&["link", "del", "recoverhost"]);
    }
}
