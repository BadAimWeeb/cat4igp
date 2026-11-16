use super::{DaemonMemory, wireguard::WireguardTunnelC};
use crate::{config::ClientConfig, tunnel::shared::Tunnel};
use cat4igp_shared::{control::{RefreshMode, WireguardTunnelInfo}, custom_type::WireguardAnswered};
use std::{io::{BufRead, BufReader, Write}, process::{Child, Command, Stdio}, sync::Arc, time::Duration};
use wireguard_control::{Backend, Device, InterfaceName, Key};

const FILTER: &str = "daemon::daemon_memory::nat_integration_test::kernel_wireguard_static_udp_forward";

fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(output.status.success(), "{program} {args:?}: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

struct Namespaces(Vec<String>);
impl Drop for Namespaces {
    fn drop(&mut self) {
        for name in self.0.iter().rev() { let _ = Command::new("ip").args(["netns", "del", name]).output(); }
    }
}
struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}

fn signal(peer: &mut Peer, command: &str) {
    writeln!(peer.0.stdin.as_mut().unwrap(), "{command}").unwrap();
}

fn receive(peer: &mut Peer) {
    let mut output = BufReader::new(peer.0.stdout.take().unwrap());
    let (send, recv) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            if output.read_line(&mut line).unwrap() == 0 { panic!("NAT peer exited before acknowledgement"); }
            // libtest may print its test-name prefix without a newline before
            // the first marker when the child runs with --nocapture.
            if line.split_whitespace().last() == Some("NAT_READY") { break; }
        }
        send.send(output.into_inner()).unwrap();
    });
    peer.0.stdout = Some(recv.recv_timeout(Duration::from_secs(45)).expect("NAT peer acknowledgement timeout"));
    thread.join().unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "disposable root VM: kernel WireGuard, ip, nft, conntrack, ping and network namespace privileges"]
async fn kernel_wireguard_static_udp_forward() {
    if let Ok(side) = std::env::var("CAT4IGP_NAT_SIDE") {
        let a = side == "a";
        let private = Key::from_base64(&std::env::var("CAT4IGP_NAT_PRIVATE").unwrap()).unwrap();
        let public = std::env::var("CAT4IGP_NAT_REMOTE_PUBLIC").unwrap();
        let info = WireguardTunnelInfo {
            tunnel_id: 0x4344, peer_node_id: if a { 2 } else { 1 }, public_key: public.clone(),
            preferred_port: 51820, remote_endpoint: Some(if a { "192.0.2.2:51820" } else { "192.0.2.1:51820" }.into()),
            local_answered: WireguardAnswered::Answered, remote_response: WireguardAnswered::Answered,
            mtu: 1420, endpoint_ipv6: false, fec: false, faketcp: false, created_at: 0, updated_at: 0,
            refresh_mode: RefreshMode::Current, refresh: Default::default(),
        };
        let name = WireguardTunnelC::gen_new_wg_tunnel(Arc::new(info.clone()), String::new(), None, 0, 0, false).get_interface_name().to_owned();
        let memory = DaemonMemory::new(ClientConfig::default());
        memory.restore_active_wireguard(&info, &private.to_base64(), 51820, false).await.unwrap();
        run("ip", &["addr", "add", if a { "198.18.0.1/30" } else { "198.18.0.2/30" }, "dev", &name]);
        println!("NAT_READY");
        for line in std::io::stdin().lock().lines() {
            let command = line.unwrap();
            if command == "STOP" { break; }
            let output = Command::new("ping").args(["-n", "-c", "3", "-W", "1", "-I", &name, if a { "198.18.0.2" } else { "198.18.0.1" }]).output().unwrap();
            if command == "BLOCKED" { assert_eq!(output.status.code(), Some(1), "forwarding removal did not block encrypted traffic"); }
            else {
                assert!(output.status.success(), "encrypted traffic failed");
                let device = Device::get(&name.parse::<InterfaceName>().unwrap(), Backend::Kernel).unwrap();
                assert_eq!(device.public_key, Some(private.get_public()));
                let peer = device.peers.iter().find(|peer| peer.config.public_key.to_base64() == public).unwrap();
                assert!(peer.stats.last_handshake_time.is_some());
                assert_eq!(peer.config.endpoint.unwrap().ip().to_string(), if a { "192.0.2.2" } else { "192.0.2.1" });
            }
            println!("NAT_READY");
        }
        memory.reconcile_wireguard_tunnels(&cat4igp_shared::control::TopologySnapshot {
            node_id: if a { 1 } else { 2 }, revision: 2, tunnels: vec![],
            l2tp_tunnels: vec![], l2tp_v2_tunnels: vec![], l2tp_availability: None,
        }, &private.to_base64()).await.unwrap();
        return;
    }

    assert_eq!(unsafe { libc::geteuid() }, 0, "requires disposable root VM");
    let prefix = format!("c4nat{}", std::process::id());
    let names = Namespaces(["a", "r", "b"].map(|side| format!("{prefix}{side}")).to_vec());
    let [a, router, b] = names.0.as_slice() else { unreachable!() };
    for name in &names.0 { run("ip", &["netns", "add", name]); run("ip", &["-n", name, "link", "set", "lo", "up"]); }
    for (peer, edge, gateway, address) in [(a, "private", "10.42.0.1/24", "10.42.0.2/24"), (b, "public", "192.0.2.1/24", "192.0.2.2/24")] {
        run("ip", &["link", "add", "natpeer", "type", "veth", "peer", "name", "natedge"]);
        run("ip", &["link", "set", "natpeer", "netns", peer]);
        run("ip", &["link", "set", "natedge", "netns", router]);
        run("ip", &["-n", router, "link", "set", "natedge", "name", edge]);
        for (namespace, interface, ip) in [(peer, "natpeer", address), (router, edge, gateway)] {
            run("ip", &["-n", namespace, "addr", "add", ip, "dev", interface]);
            run("ip", &["-n", namespace, "link", "set", interface, "up"]);
        }
    }
    run("ip", &["-n", a, "route", "add", "default", "via", "10.42.0.1"]);
    run("ip", &["netns", "exec", router, "sysctl", "-w", "net.ipv4.ip_forward=1"]);
    let rules = "table ip static_forward {
        chain pre {
            type nat hook prerouting priority dstnat;
            ip daddr 192.0.2.1 udp dport 51820 counter dnat to 10.42.0.2:51820;
        }
        chain post {
            type nat hook postrouting priority srcnat;
            ip saddr 10.42.0.2 ip daddr 192.0.2.2 udp sport 51820 counter snat to 192.0.2.1:51820;
        }
        chain forward {
            type filter hook forward priority filter; policy accept;
        }
    }
";
    let install = || {
        let mut nft = Command::new("ip").args(["netns", "exec", router, "nft", "-f", "-"]).stdin(Stdio::piped()).spawn().unwrap();
        nft.stdin.take().unwrap().write_all(rules.as_bytes()).unwrap();
        assert!(nft.wait().unwrap().success());
    };
    install();
    let keys = [Key::generate_private(), Key::generate_private()];
    let mut peers = Vec::new();
    for (index, namespace) in [a, b].into_iter().enumerate() {
        let child = Command::new("ip").args(["netns", "exec", namespace]).arg(std::env::current_exe().unwrap())
            .args(["--exact", FILTER, "--ignored", "--nocapture"])
            .env("CAT4IGP_NAT_SIDE", if index == 0 { "a" } else { "b" })
            .env("CAT4IGP_NAT_PRIVATE", keys[index].to_base64())
            .env("CAT4IGP_NAT_REMOTE_PUBLIC", keys[1-index].get_public().to_base64())
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        peers.push(Peer(child));
    }
    for peer in &mut peers { receive(peer); }
    // B initiates first: successful entry requires the explicit DNAT rule.
    signal(&mut peers[1], "TRAFFIC"); receive(&mut peers[1]);
    // A new conntrack flow initiated privately must traverse SNAT rather than
    // merely reuse the reverse translation of B's earlier DNAT connection.
    run("ip", &["netns", "exec", router, "conntrack", "-F"]);
    signal(&mut peers[0], "TRAFFIC"); receive(&mut peers[0]);
    let counters = run("ip", &["netns", "exec", router, "nft", "list", "table", "ip", "static_forward"]);
    for rule in ["dnat to", "snat to"] {
        let line = counters.lines().find(|line| line.contains(rule)).unwrap();
        let fields: Vec<_> = line.split_whitespace().collect();
        let packets = fields.iter().position(|field| *field == "packets").unwrap();
        assert!(fields[packets + 1].parse::<u64>().unwrap() > 0, "NAT rule did not carry traffic");
    }
    run("ip", &["netns", "exec", router, "nft", "delete", "table", "ip", "static_forward"]);
    run("ip", &["netns", "exec", router, "conntrack", "-F"]);
    for peer in &mut peers { signal(peer, "BLOCKED"); receive(peer); }
    install();
    for index in [1, 0] { signal(&mut peers[index], "TRAFFIC"); receive(&mut peers[index]); }
    for peer in &mut peers {
        signal(peer, "STOP");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = peer.0.try_wait().unwrap() { assert!(status.success()); break; }
            assert!(std::time::Instant::now() < deadline, "NAT peer cleanup timeout");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
