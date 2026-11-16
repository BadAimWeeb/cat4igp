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
    peer.stats.last_handshake_time.is_some_and(|time|
        time.duration_since(std::time::UNIX_EPOCH).is_ok_and(|elapsed| !elapsed.is_zero())
            && time.elapsed().is_ok_and(|age| age.as_secs() <= 180))
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
    // Opt in with CAT4IGP_REFRESH_BLOCK_CANDIDATE=1; the child inherits it.
    // Run in an outer disposable network namespace because this installs nft rules.
    let blocked_candidate = std::env::var_os("CAT4IGP_REFRESH_BLOCK_CANDIDATE").is_some();
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

    if blocked_candidate && !child_side {
        nft("add table inet refresh_candidate_test\nadd chain inet refresh_candidate_test input { type filter hook input priority 0; policy accept; }\nadd chain inet refresh_candidate_test output { type filter hook output priority 0; policy accept; }\nadd rule inet refresh_candidate_test input udp dport 51821 counter drop\nadd rule inet refresh_candidate_test output udp dport 51821 counter drop\n");
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
        if blocked_candidate {
            receive(&mut stdin, "CHECK_BLOCKED").await;
            assert!(handshaken(&old_name, old, old_peer));
            assert!(!handshaken(&new_name, new, new_peer));
            assert!(!memory.refresh_connected(ID).await);
            assert!(!memory.refresh_is_switched(ID).await);
            assert!(memory.active_matches(ID, &old.get_public().to_base64()).await.unwrap());
            assert!(exists(&old_name) && exists(&new_name));
            println!("REFRESH_BLOCKED_VERIFIED");
        }
        receive(&mut stdin, "SWITCH").await;
        assert!(handshaken(&old_name, old, old_peer));
        assert!(handshaken(&new_name, new, new_peer));
        assert!(memory.refresh_connected(ID).await);
    } else {
        let (_, input, output) = child.as_mut().unwrap();
        receive(output, "REFRESH_READY").await;
        let remote_info = info_for_remote(old, "192.0.2.1:51820");
        ping(&old_name, &name(&remote_info, false)).await;
        if blocked_candidate {
            assert_no_ping(&new_name, &name(&remote_info, true)).await;
            assert!(handshaken(&old_name, old, old_peer));
            assert!(!handshaken(&new_name, new, new_peer));
            assert!(!memory.refresh_connected(ID).await);
            assert!(!memory.refresh_is_switched(ID).await);
            assert!(memory.active_matches(ID, &old.get_public().to_base64()).await.unwrap());
            assert!(exists(&old_name) && exists(&new_name));
            ping(&old_name, &name(&remote_info, false)).await;
            signal(input, "CHECK_BLOCKED").await;
            receive(output, "REFRESH_BLOCKED_VERIFIED").await;
            let counters = nft("list table inet refresh_candidate_test\n");
            assert!(counters.lines().any(|line| line.contains("drop") && line.split("counter packets ").nth(1).and_then(|tail| tail.split_whitespace().next()).and_then(|value| value.parse::<u64>().ok()).is_some_and(|packets| packets > 0)), "candidate transport was not exercised");
            nft("delete table inet refresh_candidate_test\n");
        }
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

async fn assert_no_ping(local: &str, remote: &str) {
    let address = crate::interface::generate_ipv6_lla_from_seed(remote.as_bytes().to_vec());
    let result = tokio::process::Command::new("ping")
        .args(["-6", "-I", local, "-c", "1", "-W", "1", "-w", "3", &address.to_string()])
        .output().await.unwrap();
    assert_eq!(result.status.code(), Some(1), "ping must time out, not fail to run: {}", String::from_utf8_lossy(&result.stderr));
}

fn nft(script: &str) -> String {
    use std::io::Write;
    let mut child = std::process::Command::new("nft").args(["-f", "-"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(script.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "nft: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

#[tokio::test]
#[ignore = "requires Linux kernel WireGuard, ip, ping, nft, unshare and CAP_NET_ADMIN in an isolated network namespace"]
async fn offline_revocation_requires_independent_containment() {
    const TEST: &str = "daemon::daemon_memory::refresh_integration_test::offline_revocation_requires_independent_containment";
    let child_side = std::env::var_os("CAT4IGP_REVOCATION_TEST_CHILD").is_some();
    let keys = [Key([0x11; 32]), Key([0x22; 32])];
    let (local, remote, peer_id, endpoint) = if child_side {
        (&keys[1], &keys[0], 1, "192.0.2.1:51820")
    } else {
        (&keys[0], &keys[1], 2, "192.0.2.2:51820")
    };
    let mut info = info(peer_id, remote, endpoint);
    info.refresh_mode = RefreshMode::Current;
    let local_name = name(&info, false);
    let mut remote_info = info.clone();
    remote_info.peer_node_id = if child_side { 2 } else { 1 };
    let remote_name = name(&remote_info, false);
    let mut config = ClientConfig::default();
    config.tunnel_protocols.wireguard = true;
    let memory = DaemonMemory::new(config);
    let mut stdin = BufReader::new(tokio::io::stdin());

    let mut child = if child_side {
        println!("REVOCATION_WAITING");
        receive(&mut stdin, "START").await;
        ip(&["link", "set", "lo", "up"]);
        ip(&["link", "set", "vethpeer", "up"]);
        ip(&["address", "add", "192.0.2.2/24", "dev", "vethpeer"]);
        None
    } else {
        ip(&["link", "set", "lo", "up"]);
        ip(&["link", "add", "vethhost", "type", "veth", "peer", "name", "vethpeer"]);
        ip(&["link", "set", "vethhost", "up"]);
        ip(&["address", "add", "192.0.2.1/24", "dev", "vethhost"]);
        let mut child = tokio::process::Command::new("unshare")
            .arg("-n").arg(std::env::current_exe().unwrap()).args(["--exact", TEST, "--ignored", "--nocapture"])
            .env("CAT4IGP_REVOCATION_TEST_CHILD", "1")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).kill_on_drop(true).spawn().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut input = child.stdin.take().unwrap();
        receive(&mut output, "REVOCATION_WAITING").await;
        ip(&["link", "set", "vethpeer", "netns", &child.id().unwrap().to_string()]);
        signal(&mut input, "START").await;
        Some((child, input, output))
    };

    memory.restore_active_wireguard(&info, &local.to_base64(), 51820, false).await.unwrap();
    let address = crate::interface::generate_ipv6_lla_from_seed(remote_name.as_bytes().to_vec());
    ip(&["-6", "route", "add", &format!("{address}/128"), "dev", &local_name, "proto", "253"]);

    if child_side {
        // The isolated peer receives no controller update throughout containment.
        println!("REVOCATION_READY");
        receive(&mut stdin, "CONVERGED").await;
        assert!(exists(&local_name));
        assert_eq!(memory.wireguard_len().await, 1);
        assert!(handshaken(&local_name, local, remote));
        assert_no_ping(&local_name, &remote_name).await;
        memory.apply_topology_snapshot(snapshot(None), &local.to_base64()).await.unwrap();
        assert!(!exists(&local_name));
        println!("REVOCATION_FINISHED");
    } else {
        let (_, input, output) = child.as_mut().unwrap();
        receive(output, "REVOCATION_READY").await;
        ping(&local_name, &remote_name).await;
        assert!(handshaken(&local_name, local, remote));

        // Control-plane isolation does not expire a previously authorized data path.
        // Independent outer-transport filtering must work before peers converge.
        nft("add table inet revocation_test\nadd counter inet revocation_test blocked\nadd chain inet revocation_test input { type filter hook input priority -300; policy accept; }\nadd rule inet revocation_test input ip saddr 192.0.2.2 udp dport 51820 counter name blocked drop\n");
        assert_no_ping(&local_name, &remote_name).await;
        let counter = nft("list counter inet revocation_test blocked\n");
        let packets = counter.split_whitespace().skip_while(|word| *word != "packets").nth(1).unwrap().parse::<u64>().unwrap();
        assert!(packets > 0, "containment must drop actual WireGuard traffic: {counter}");
        assert!(exists(&local_name));
        assert_eq!(memory.wireguard_len().await, 1);

        // Prove the failed probe was the firewall, not a broken tunnel.
        nft("delete table inet revocation_test\n");
        ping(&local_name, &remote_name).await;
        nft("add table inet revocation_test\nadd chain inet revocation_test input { type filter hook input priority -300; policy accept; }\nadd rule inet revocation_test input ip saddr 192.0.2.2 udp dport 51820 drop\n");

        // A surviving peer applies the post-deletion topology while containment holds.
        let mut revoked = snapshot(None);
        revoked.revision = 2;
        memory.apply_topology_snapshot(revoked, &local.to_base64()).await.unwrap();
        assert!(!exists(&local_name));
        assert_eq!(memory.wireguard_len().await, 0);
        assert!(memory.cached_ports().await.is_empty());
        nft("delete table inet revocation_test\n");
        signal(input, "CONVERGED").await;
        receive(output, "REVOCATION_FINISHED").await;
    }
    if let Some((mut child, _, _)) = child {
        assert!(tokio::time::timeout(Duration::from_secs(45), child.wait()).await.unwrap().unwrap().success());
    }
}
