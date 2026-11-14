//! A datagram bridge over raw TCP-shaped packets. This is not a TCP stack and is
//! not wire-compatible with udp2raw; peers must both use this implementation.

use std::{
    io::{self, Write},
    mem,
    net::{IpAddr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    process::{Command, Stdio},
};
use tokio::{io::unix::AsyncFd, net::UdpSocket, sync::oneshot, task::JoinHandle};
use blake2::{Blake2sMac, Blake2sMac256, digest::{consts::U16, KeyInit, Mac}};

// Fits in an unfragmented maximum-size IPv4 packet (before path MTU limits).
const MAX_PAYLOAD: usize = 65_451;
const TCP_HEADER: usize = 20;

pub struct FakeTcp {
    local_addr: SocketAddr,
    path_mtu: u32,
    table: Option<(String, &'static str)>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl FakeTcp {
    pub async fn start(local_port: u16, peer: SocketAddr, local_udp: SocketAddr, key: [u8; 32]) -> io::Result<Self> {
        if local_port == 0 || peer.port() == 0 || peer.ip().is_unspecified()
            || !local_udp.ip().is_loopback() || local_udp.port() == 0
            || matches!(peer, SocketAddr::V6(v) if v.scope_id() != 0 || v.ip().is_unicast_link_local())
        {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid FakeTCP endpoint"));
        }

        // Ask the kernel which address its route to the peer uses.
        let probe = std::net::UdpSocket::bind(match peer {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        })?;
        probe.connect(peer)?;
        let source = probe.local_addr()?.ip();
        let mut path_mtu: libc::c_int = 0;
        let mut len = mem::size_of_val(&path_mtu) as libc::socklen_t;
        let (level, option) = if peer.is_ipv4() { (libc::IPPROTO_IP, libc::IP_MTU) } else { (libc::IPPROTO_IPV6, libc::IPV6_MTU) };
        if unsafe { libc::getsockopt(probe.as_raw_fd(), level, option, (&mut path_mtu as *mut libc::c_int).cast(), &mut len) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if path_mtu <= 0 { return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid FakeTCP path MTU")); }
        let raw = raw_socket(source, peer)?;
        let udp = UdpSocket::bind(SocketAddr::new(local_udp.ip(), 0)).await?;
        udp.connect(local_udp).await?;
        let local_addr = udp.local_addr()?;

        // An individual table per bridge makes cleanup independent of unrelated rules.
        let family = if peer.is_ipv4() { "ip" } else { "ip6" };
        let table = format!("cat4igp_ft_{:016x}", rand08::random::<u64>());
        let script = format!(
            "add table {family} {table}\nadd chain {family} {table} output {{ type filter hook output priority 0; policy accept; }}\nadd rule {family} {table} output {family} saddr {source} {family} daddr {} tcp sport {local_port} tcp dport {} tcp flags & rst == rst drop\n",
            peer.ip(), peer.port()
        );
        nft(&["-f", "-"], Some(&script))?;
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(run(raw, udp, source, local_port, peer, key, stopped));
        Ok(Self { local_addr, path_mtu: path_mtu as u32, table: Some((table, family)), shutdown: Some(shutdown), task: Some(task) })
    }

    pub fn local_addr(&self) -> SocketAddr { self.local_addr }
    pub fn path_mtu(&self) -> u32 { self.path_mtu }

    pub fn is_running(&self) -> bool { self.task.as_ref().is_some_and(|task| !task.is_finished()) }

    pub async fn stop(&mut self) -> io::Result<()> {
        if let Some(shutdown) = self.shutdown.take() { let _ = shutdown.send(()); }
        let result = match self.task.take() {
            Some(task) => { task.abort(); match task.await { Err(e) if e.is_cancelled() => Ok(()), Err(e) => Err(io::Error::other(e)), Ok(result) => result } },
            None => Ok(()),
        };
        // Retain ownership if deletion fails, so a subsequent stop or Drop can retry.
        let cleanup = self.cleanup();
        result.and(cleanup)
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if let Some((table, family)) = &self.table {
            nft(&["delete", "table", family, table], None)?;
            self.table = None;
        }
        Ok(())
    }
}

impl Drop for FakeTcp {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() { task.abort(); }
        if let Err(error) = self.cleanup() {
            eprintln!("FakeTCP nftables cleanup failed: {error}");
        }
    }
}

fn nft(args: &[&str], input: Option<&str>) -> io::Result<()> {
    let mut child = Command::new("nft").args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::null()).stderr(Stdio::piped()).spawn()?;
    if let Some(input) = input {
        let write_result = child.stdin.take().unwrap().write_all(input.as_bytes());
        if let Err(error) = write_result {
            let _ = child.wait();
            return Err(error);
        }
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!("nft failed: {}", String::from_utf8_lossy(&output.stderr).trim())));
    }
    Ok(())
}

fn sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // sockaddr_storage is large and aligned enough for both socket address types.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            let value = libc::sockaddr_in { sin_family: libc::AF_INET as _, sin_port: 0,
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(a.ip().octets()) }, sin_zero: [0; 8] };
            unsafe { (std::ptr::addr_of_mut!(storage) as *mut libc::sockaddr_in).write(value); }
            mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            let value = libc::sockaddr_in6 { sin6_family: libc::AF_INET6 as _, sin6_port: 0,
                sin6_flowinfo: 0, sin6_addr: libc::in6_addr { s6_addr: a.ip().octets() }, sin6_scope_id: a.scope_id() };
            unsafe { (std::ptr::addr_of_mut!(storage) as *mut libc::sockaddr_in6).write(value); }
            mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, len as libc::socklen_t)
}

fn raw_socket(source: IpAddr, peer: SocketAddr) -> io::Result<AsyncFd<OwnedFd>> {
    let domain = if peer.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let fd = unsafe { libc::socket(domain, libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, libc::IPPROTO_TCP) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    for (addr, connect) in [(SocketAddr::new(source, 0), false), (peer, true)] {
        let (storage, len) = sockaddr(addr);
        let ptr = &storage as *const _ as *const libc::sockaddr;
        let result = unsafe { if connect { libc::connect(fd.as_raw_fd(), ptr, len) } else { libc::bind(fd.as_raw_fd(), ptr, len) } };
        if result < 0 { return Err(io::Error::last_os_error()); }
    }
    AsyncFd::new(fd)
}

fn syscall(fd: RawFd, buf: &mut [u8], send: bool) -> io::Result<usize> {
    let n = unsafe {
        if send { libc::send(fd, buf.as_ptr().cast(), buf.len(), 0) }
        else { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) }
    };
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
}

async fn send_packet(raw: &AsyncFd<OwnedFd>, source: IpAddr, peer: SocketAddr, port: u16,
    seq: u32, ack: u32, flags: u8, nonce: &[u8; 16], counter: u32, payload: &[u8], key: &[u8; 32]) -> io::Result<()> {
    let mut packet = make_packet(source, peer.ip(), port, peer.port(), seq, ack, flags, nonce, counter, payload, key);
    loop {
        let mut ready = raw.writable().await?;
        match ready.try_io(|fd| syscall(fd.as_raw_fd(), &mut packet, true)) {
            Ok(Ok(sent)) if sent == packet.len() => return Ok(()),
            Ok(Ok(_)) => return Err(io::Error::new(io::ErrorKind::WriteZero, "short raw TCP send")),
            Ok(Err(e)) => return Err(e), Err(_) => continue,
        }
    }
}

fn session_key(key: &[u8; 32], local: &[u8; 16], remote: &[u8; 16]) -> [u8; 32] {
    let mut mac = <Blake2sMac256 as KeyInit>::new_from_slice(key).expect("valid key");
    Mac::update(&mut mac, b"cat4igp-faketcp-session-v2");
    // NAT may rewrite ports, so order the shared nonces rather than endpoint ports.
    let (first, second) = if local < remote { (local, remote) } else { (remote, local) };
    Mac::update(&mut mac, first);
    Mac::update(&mut mac, second);
    mac.finalize().into_bytes().into()
}

// A bounded replay window accepts reordered datagrams without accepting duplicates.
fn accept_counter(high: &mut u32, bitmap: &mut u128, counter: u32) -> bool {
    if counter == 0 { return false; }
    if counter > *high {
        let shift = counter - *high;
        *bitmap = if shift >= 128 { 1 } else { (*bitmap << shift) | 1 };
        *high = counter;
        true
    } else {
        let delta = *high - counter;
        if delta >= 128 || (*bitmap & (1u128 << delta)) != 0 { return false; }
        *bitmap |= 1u128 << delta;
        true
    }
}

fn datagram_send_result(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {
            eprintln!("FakeTCP dropped a datagram exceeding the path MTU: {error}");
            Ok(())
        }
        other => other,
    }
}

async fn run(raw: AsyncFd<OwnedFd>, udp: UdpSocket, source: IpAddr, port: u16, peer: SocketAddr, key: [u8; 32], mut shutdown: oneshot::Receiver<()>) -> io::Result<()> {
    let mut incoming = vec![0u8; 65_536];
    let mut outgoing = vec![0u8; MAX_PAYLOAD + 1];
    let mut initial = rand08::random::<u32>();
    let mut local_nonce = rand08::random::<[u8; 16]>();
    let mut seq = initial.wrapping_add(1);
    let mut remote: Option<([u8; 16], u32)> = None;
    let mut remote_next = 0u32;
    let mut established = false;
    let mut counter = 0u32;
    let mut high = 0u32;
    let mut bitmap = 0u128;
    let mut last_seen = tokio::time::Instant::now();
    let mut retry = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = retry.tick() => {
                if last_seen.elapsed() >= std::time::Duration::from_secs(15) || counter >= u32::MAX - 1 {
                    initial = rand08::random(); local_nonce = rand08::random(); seq = initial.wrapping_add(1);
                    remote = None; established = false; counter = 0; high = 0; bitmap = 0;
                    last_seen = tokio::time::Instant::now();
                }
                if let Some((remote_nonce, _)) = remote {
                    if established {
                        counter += 1;
                        let sk = session_key(&key, &local_nonce, &remote_nonce);
                        send_packet(&raw, source, peer, port, seq, remote_next, 0x10, &local_nonce, counter, &[], &sk).await?;
                    } else {
                        send_packet(&raw, source, peer, port, initial, remote_next, 0x12, &local_nonce, 0, &[], &key).await?;
                    }
                } else {
                    send_packet(&raw, source, peer, port, initial, 0, 0x02, &local_nonce, 0, &[], &key).await?;
                }
            }
            result = udp.recv(&mut outgoing) => {
                let n = result?;
                if n > MAX_PAYLOAD {
                    eprintln!("FakeTCP dropped a datagram exceeding its maximum payload of {MAX_PAYLOAD} bytes");
                    continue;
                }
                if n == 0 || !established || counter >= u32::MAX - 1 { continue; }
                let Some((remote_nonce, _)) = remote else { continue };
                counter += 1;
                let sk = session_key(&key, &local_nonce, &remote_nonce);
                datagram_send_result(send_packet(&raw, source, peer, port, seq, remote_next, 0x18, &local_nonce, counter, &outgoing[..n], &sk).await)?;
                seq = seq.wrapping_add(n as u32);
            }
            result = raw.readable() => {
                let mut ready = result?;
                let n = match ready.try_io(|fd| syscall(fd.as_raw_fd(), &mut incoming, false)) { Ok(result) => result?, Err(_) => continue };
                let bytes = &incoming[..n];
                if let Some((flags, remote_seq, ack, nonce, count, payload)) = parse_packet(bytes, peer.ip(), source, peer.port(), port, &key) {
                    if !payload.is_empty() || count != 0 { continue; }
                    if flags == 0x02 && !established {
                        remote = Some((nonce, remote_seq)); remote_next = remote_seq.wrapping_add(1);
                        send_packet(&raw, source, peer, port, initial, remote_next, 0x12, &local_nonce, 0, &[], &key).await?;
                    } else if flags == 0x12 && ack == initial.wrapping_add(1) && (!established || remote == Some((nonce, remote_seq))) {
                        if !established { remote = Some((nonce, remote_seq)); remote_next = remote_seq.wrapping_add(1); }
                        counter += 1;
                        let sk = session_key(&key, &local_nonce, &nonce);
                        send_packet(&raw, source, peer, port, seq, remote_next, 0x10, &local_nonce, counter, &[], &sk).await?;
                    }
                    continue;
                }
                let Some((remote_nonce, _)) = remote else { continue };
                let sk = session_key(&key, &local_nonce, &remote_nonce);
                let Some((flags, remote_seq, _ack, nonce, count, payload)) = parse_packet(bytes, peer.ip(), source, peer.port(), port, &sk) else { continue };
                if nonce != remote_nonce || !matches!(flags, 0x10 | 0x18) || (flags == 0x10 && !payload.is_empty()) || (flags == 0x18 && payload.is_empty()) { continue; }
                if !accept_counter(&mut high, &mut bitmap, count) { continue; }
                established = true;
                last_seen = tokio::time::Instant::now();
                if flags == 0x18 {
                    let end = remote_seq.wrapping_add(payload.len() as u32);
                    if (end.wrapping_sub(remote_next) as i32) > 0 { remote_next = end; }
                    udp.send(payload).await?;
                }
            }
        }
    }
}

fn checksum(src: IpAddr, dst: IpAddr, tcp: &[u8]) -> u16 {
    let mut sum = 0u64;
    let mut add = |bytes: &[u8]| {
        for chunk in bytes.chunks(2) {
            sum += u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u64;
        }
    };
    match (src, dst) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            add(&a.octets()); add(&b.octets());
            add(&[0, libc::IPPROTO_TCP as u8]); add(&(tcp.len() as u16).to_be_bytes());
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            add(&a.octets()); add(&b.octets());
            add(&(tcp.len() as u32).to_be_bytes()); add(&[0, 0, 0, libc::IPPROTO_TCP as u8]);
        }
        _ => return u16::MAX,
    }
    add(tcp);
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

fn make_packet(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, nonce: &[u8; 16], counter: u32, payload: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut packet = vec![0; TCP_HEADER + 40 + payload.len()];
    packet[0..2].copy_from_slice(&sport.to_be_bytes());
    packet[2..4].copy_from_slice(&dport.to_be_bytes());
    packet[4..8].copy_from_slice(&seq.to_be_bytes());
    packet[8..12].copy_from_slice(&ack.to_be_bytes());
    packet[12] = 15 << 4;
    packet[13] = flags;
    packet[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    packet[20] = 254;
    packet[21] = 38;
    packet[22..38].copy_from_slice(nonce);
    packet[38..42].copy_from_slice(&counter.to_be_bytes());
    packet[58] = 1;
    packet[59] = 1;
    packet[60..].copy_from_slice(payload);
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(key).expect("valid key");
    Mac::update(&mut mac, b"cat4igp-faketcp-v2");
    Mac::update(&mut mac, &packet[4..16]);
    Mac::update(&mut mac, &packet[22..42]);
    Mac::update(&mut mac, payload);
    packet[42..58].copy_from_slice(&mac.finalize().into_bytes());
    let sum = checksum(src, dst, &packet);
    packet[16..18].copy_from_slice(&sum.to_be_bytes());
    packet
}

fn parse_packet<'a>(packet: &'a [u8], src: IpAddr, dst: IpAddr, sport: u16, dport: u16, key: &[u8; 32]) -> Option<(u8, u32, u32, [u8; 16], u32, &'a [u8])> {
    let tcp = match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            if packet.len() < 20 || packet[0] >> 4 != 4 { return None; }
            let header = (packet[0] as usize & 15) * 4;
            let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if header < 20 || total < header || total > packet.len() || packet[9] != libc::IPPROTO_TCP as u8
                || packet[6] & 0x3f != 0 || packet[7] != 0
                || packet[12..16] != src.octets() || packet[16..20] != dst.octets() { return None; }
            &packet[header..total]
        }
        // Linux IPv6 raw sockets return the transport header, not the IPv6 header.
        (IpAddr::V6(_), IpAddr::V6(_)) => packet,
        _ => return None,
    };
    if tcp.len() < 60 || tcp.len() > 60 + MAX_PAYLOAD
        || u16::from_be_bytes([tcp[0], tcp[1]]) != sport || u16::from_be_bytes([tcp[2], tcp[3]]) != dport
        || tcp[12] != 15 << 4 || !matches!(tcp[13], 0x02 | 0x12 | 0x10 | 0x18)
        || tcp[20] != 254 || tcp[21] != 38 || tcp[58..60] != [1, 1] || checksum(src, dst, tcp) != 0 { return None; }
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(key).expect("valid key");
    Mac::update(&mut mac, b"cat4igp-faketcp-v2");
    Mac::update(&mut mac, &tcp[4..16]);
    Mac::update(&mut mac, &tcp[22..42]);
    Mac::update(&mut mac, &tcp[60..]);
    mac.verify_slice(&tcp[42..58]).ok()?;
    Some((tcp[13], u32::from_be_bytes(tcp[4..8].try_into().ok()?), u32::from_be_bytes(tcp[8..12].try_into().ok()?), tcp[22..38].try_into().ok()?, u32::from_be_bytes(tcp[38..42].try_into().ok()?), &tcp[60..]))
}

#[cfg(test)]
mod tests {
    #[test]
    fn replay_window_accepts_reordering_once() {
        let (mut high, mut bitmap) = (0, 0);
        assert!(accept_counter(&mut high, &mut bitmap, 10));
        assert!(accept_counter(&mut high, &mut bitmap, 8));
        assert!(!accept_counter(&mut high, &mut bitmap, 8));
        assert!(accept_counter(&mut high, &mut bitmap, 140));
        assert!(!accept_counter(&mut high, &mut bitmap, 10));
        assert!(!accept_counter(&mut high, &mut bitmap, 0));
        assert!(accept_counter(&mut high, &mut bitmap, 139));
    }

    use super::*;

    #[tokio::test]
    #[ignore = "requires root, network namespaces, iproute2, nftables, conntrack-tools and kernel conntrack NAT"]
    async fn routed_conntrack_nat_outage_and_recovery() {
        use std::time::Duration;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        const TEST: &str = "network::faketcp::tests::routed_conntrack_nat_outage_and_recovery";
        fn ip(args: &[&str]) {
            let result = Command::new("ip").args(args).output().unwrap();
            assert!(result.status.success(), "ip {args:?}: {}", String::from_utf8_lossy(&result.stderr));
        }
        fn spawn(role: &str) -> tokio::process::Child {
            tokio::process::Command::new("unshare")
                .arg("--net").arg(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--ignored", "--nocapture"])
                .env("CAT4IGP_FAKETCP_NS_TEST", role)
                .stdin(Stdio::piped()).stdout(if role == "router" { Stdio::inherit() } else { Stdio::piped() }).kill_on_drop(true)
                .spawn().unwrap()
        }
        async fn marker(reader: &mut BufReader<tokio::process::ChildStdout>, expected: &str) {
            let mut line = String::new();
            loop {
                line.clear();
                let n = tokio::time::timeout(Duration::from_secs(30), reader.read_line(&mut line)).await.expect(expected).unwrap();
                assert_ne!(n, 0, "child exited before {expected}");
                if line.trim().ends_with(expected) { return; }
            }
        }
        async fn translated_flow() -> String {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
            loop {
                let result = Command::new("conntrack").args([
                    "-L", "-p", "tcp", "--orig-src", "192.0.2.2", "--orig-dst", "198.51.100.1",
                    "--sport", "41001", "--dport", "42002", "-o", "id",
                ]).output().unwrap();
                let output = String::from_utf8_lossy(&result.stdout);
                if result.status.success()
                    && output.contains("src=192.0.2.2 dst=198.51.100.1 sport=41001 dport=42002")
                    && output.contains("src=198.51.100.2 dst=198.51.100.1 sport=41002 dport=42001") {
                    return output.split("id=").nth(1).expect("conntrack entry has no ID")
                        .split(|c: char| !c.is_ascii_digit()).next().unwrap().to_owned();
                }
                assert!(tokio::time::Instant::now() < deadline, "translated conntrack flow not found: {output} {}", String::from_utf8_lossy(&result.stderr));
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }


        let role = std::env::var("CAT4IGP_FAKETCP_NS_TEST").unwrap_or_default();
        if role.is_empty() {
            let status = spawn("router").wait().await.unwrap();
            assert!(status.success(), "isolated router process failed");
            return;
        }
        if role == "a" || role == "b" {
            println!("WAITING");
            let mut input = BufReader::new(tokio::io::stdin());
            let mut line = String::new();
            assert_ne!(input.read_line(&mut line).await.unwrap(), 0);
            let (address, gateway, local_port, peer) = if role == "a" {
                ("192.0.2.2/24", "192.0.2.1", 41001, "198.51.100.1:42002")
            } else {
                ("198.51.100.2/24", "198.51.100.1", 41002, "198.51.100.1:42001")
            };
            ip(&["link", "set", "lo", "up"]);
            ip(&["link", "set", "endpoint", "up"]);
            ip(&["address", "add", address, "dev", "endpoint"]);
            ip(&["route", "add", "default", "via", gateway]);
            println!("LINK_READY");
            line.clear();
            assert_ne!(input.read_line(&mut line).await.unwrap(), 0);
            let udp = std::sync::Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let mut bridge = FakeTcp::start(local_port, peer.parse().unwrap(), udp.local_addr().unwrap(), [7; 32]).await.unwrap();
            let table = bridge.table.clone().unwrap();
            let bridge_addr = bridge.local_addr();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let receiver = udp.clone();
            let task = tokio::spawn(async move {
                let mut buf = [0u8; 128];
                loop {
                    let (n, from) = receiver.recv_from(&mut buf).await.unwrap();
                    if from != bridge_addr { continue; }
                    if &buf[..n] == b"request" {
                        receiver.send_to(b"response", bridge_addr).await.unwrap();
                    } else if &buf[..n] == b"response" {
                        tx.send(()).unwrap();
                    }
                }
            });
            println!("READY");
            loop {
                line.clear();
                assert_ne!(input.read_line(&mut line).await.unwrap(), 0);
                match line.trim() {
                    "probe" | "quiet" => {
                        while rx.try_recv().is_ok() {}
                        let quiet = line.trim() == "quiet";
                        let deadline = tokio::time::Instant::now() + Duration::from_secs(if quiet { 3 } else { 12 });
                        let mut delivered = false;
                        while tokio::time::Instant::now() < deadline {
                            udp.send_to(b"request", bridge_addr).await.unwrap();
                            if tokio::time::timeout(Duration::from_millis(200), rx.recv()).await.is_ok() {
                                delivered = true;
                                break;
                            }
                        }
                        assert_eq!(delivered, !quiet, "unexpected delivery state in {role}");
                        assert!(bridge.is_running(), "bridge stopped in {role}");
                        println!("DONE");
                    }
                    "stop" => break,
                    other => panic!("unknown command: {other}"),
                }
            }
            task.abort();
            bridge.stop().await.unwrap();
            assert!(!Command::new("nft").args(["list", "table", table.1, &table.0]).output().unwrap().status.success());
            println!("STOPPED");
            return;
        }
        assert_eq!(role, "router");
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
        ip(&["link", "set", "lo", "up"]);
        let mut a = spawn("a");
        let mut b = spawn("b");
        let mut a_out = BufReader::new(a.stdout.take().unwrap());
        let mut b_out = BufReader::new(b.stdout.take().unwrap());
        let mut a_in = a.stdin.take().unwrap();
        let mut b_in = b.stdin.take().unwrap();
        marker(&mut a_out, "WAITING").await;
        marker(&mut b_out, "WAITING").await;
        for (router, child, address, pid) in [
            ("left", "endpoint", "192.0.2.1/24", a.id().unwrap()),
            ("right", "endpoint", "198.51.100.1/24", b.id().unwrap()),
        ] {
            ip(&["link", "add", router, "type", "veth", "peer", "name", child]);
            ip(&["link", "set", child, "netns", &pid.to_string()]);
            ip(&["address", "add", address, "dev", router]);
            ip(&["link", "set", router, "up"]);
        }
        nft(&["-f", "-"], Some(concat!(
            "add table ip ft_test\n",
            "add chain ip ft_test gate { type filter hook prerouting priority raw; policy accept; }\n",
            "add rule ip ft_test gate iifname \"right\" meta l4proto tcp drop\n",
            "add chain ip ft_test prerouting { type nat hook prerouting priority dstnat; policy accept; }\n",
            "add chain ip ft_test postrouting { type nat hook postrouting priority srcnat; policy accept; }\n",
            "add rule ip ft_test prerouting ip saddr 192.0.2.2 ip daddr 198.51.100.1 tcp sport 41001 tcp dport 42002 counter dnat to 198.51.100.2:41002\n",
            "add rule ip ft_test postrouting ip saddr 192.0.2.2 ip daddr 198.51.100.2 tcp sport 41001 tcp dport 41002 counter snat to 198.51.100.1:42001\n",
        ))).unwrap();
        a_in.write_all(b"go\n").await.unwrap();
        b_in.write_all(b"go\n").await.unwrap();
        marker(&mut a_out, "LINK_READY").await;
        marker(&mut b_out, "LINK_READY").await;
        a_in.write_all(b"start\n").await.unwrap();
        b_in.write_all(b"start\n").await.unwrap();
        marker(&mut a_out, "READY").await;
        marker(&mut b_out, "READY").await;
        // Seed the one NAT mapping from A before permitting B's simultaneous-open SYN.
        let original_flow = translated_flow().await;
        println!("Initial translated conntrack flow ID: {original_flow}");
        nft(&["flush", "chain", "ip", "ft_test", "gate"], None).unwrap();
        for (input, output) in [(&mut a_in, &mut a_out), (&mut b_in, &mut b_out)] {
            input.write_all(b"probe\n").await.unwrap();
            marker(output, "DONE").await;
        }
        // A short outage must recover on the same conntrack mapping.
        nft(&["add", "rule", "ip", "ft_test", "gate", "meta", "l4proto", "tcp", "drop"], None).unwrap();
        a_in.write_all(b"quiet\n").await.unwrap();
        b_in.write_all(b"quiet\n").await.unwrap();
        marker(&mut a_out, "DONE").await;
        marker(&mut b_out, "DONE").await;
        nft(&["flush", "chain", "ip", "ft_test", "gate"], None).unwrap();
        for (input, output) in [(&mut a_in, &mut a_out), (&mut b_in, &mut b_out)] {
            input.write_all(b"probe\n").await.unwrap();
            marker(output, "DONE").await;
        }
        assert_eq!(translated_flow().await, original_flow, "short outage replaced the conntrack flow");
        println!("Short outage recovered on conntrack flow ID: {original_flow}");
        nft(&["add", "rule", "ip", "ft_test", "gate", "meta", "l4proto", "tcp", "drop"], None).unwrap();
        a_in.write_all(b"quiet\n").await.unwrap();
        b_in.write_all(b"quiet\n").await.unwrap();
        marker(&mut a_out, "DONE").await;
        marker(&mut b_out, "DONE").await;
        // Exercise re-handshake after the 15-second session timeout without
        // flushing conntrack: ordinary network recovery must not need operator action.
        tokio::time::sleep(Duration::from_secs(16)).await;
        nft(&["flush", "chain", "ip", "ft_test", "gate"], None).unwrap();
        println!("Long outage ended; probing without clearing conntrack");
        for (input, output) in [(&mut a_in, &mut a_out), (&mut b_in, &mut b_out)] {
            input.write_all(b"probe\n").await.unwrap();
            marker(output, "DONE").await;
        }
        println!("Long outage recovered on conntrack flow ID: {}", translated_flow().await);
        a_in.write_all(b"stop\n").await.unwrap();
        b_in.write_all(b"stop\n").await.unwrap();
        marker(&mut a_out, "STOPPED").await;
        marker(&mut b_out, "STOPPED").await;
        assert!(a.wait().await.unwrap().success());
        assert!(b.wait().await.unwrap().success());
        nft(&["delete", "table", "ip", "ft_test"], None).unwrap();
    }

    #[test]
    fn translated_addresses_and_ports_keep_authentication_valid() {
        let source: IpAddr = "192.0.2.2".parse().unwrap();
        let public: IpAddr = "198.51.100.1".parse().unwrap();
        let destination: IpAddr = "198.51.100.2".parse().unwrap();
        let session = session_key(&[7; 32], &[1; 16], &[2; 16]);
        let mut tcp = make_packet(source, public, 41001, 42002, 1, 2, 0x18, &[1; 16], 1, b"data", &session);
        tcp[0..2].copy_from_slice(&42001u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&41002u16.to_be_bytes());
        tcp[16..18].fill(0);
        let sum = checksum(public, destination, &tcp);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        packet[9] = libc::IPPROTO_TCP as u8;
        let IpAddr::V4(src) = public else { unreachable!() };
        let IpAddr::V4(dst) = destination else { unreachable!() };
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet.extend_from_slice(&tcp);
        assert!(parse_packet(&packet, public, destination, 42001, 41002, &session).is_some());
        assert!(parse_packet(&packet, source, destination, 42001, 41002, &session).is_none());
        assert!(parse_packet(&packet, public, destination, 41001, 41002, &session).is_none());
        packet[80] ^= 1;
        packet[36..38].fill(0);
        let sum = checksum(public, destination, &packet[20..]);
        packet[36..38].copy_from_slice(&sum.to_be_bytes());
        assert!(parse_packet(&packet, public, destination, 42001, 41002, &session).is_none());
    }

    #[test]
    fn translated_ports_keep_authentication_valid() {
        let src: IpAddr = "2001:db8::1".parse().unwrap();
        let dst: IpAddr = "2001:db8::2".parse().unwrap();
        let key = [7; 32];
        let session = session_key(&key, &[1; 16], &[2; 16]);
        assert_eq!(session, session_key(&key, &[2; 16], &[1; 16]));
        let mut packet = make_packet(src, dst, 1000, 2000, 1, 2, 0x18, &[1; 16], 1, b"data", &session);
        packet[0..2].copy_from_slice(&3000u16.to_be_bytes());
        packet[2..4].copy_from_slice(&4000u16.to_be_bytes());
        packet[16..18].fill(0);
        let sum = checksum(src, dst, &packet);
        packet[16..18].copy_from_slice(&sum.to_be_bytes());
        assert!(parse_packet(&packet, src, dst, 3000, 4000, &session).is_some());
        assert!(parse_packet(&packet, src, dst, 1000, 4000, &session).is_none());
        packet[60] ^= 1;
        packet[16..18].fill(0);
        let sum = checksum(src, dst, &packet);
        packet[16..18].copy_from_slice(&sum.to_be_bytes());
        assert!(parse_packet(&packet, src, dst, 3000, 4000, &session).is_none());
    }

    #[test]
    fn mtu_errors_drop_only_the_affected_datagram() {
        assert!(datagram_send_result(Err(io::Error::from_raw_os_error(libc::EMSGSIZE))).is_ok());
        assert!(datagram_send_result(Ok(())).is_ok());
        assert_eq!(datagram_send_result(Err(io::Error::from_raw_os_error(libc::EACCES))).unwrap_err().raw_os_error(), Some(libc::EACCES));
    }


    #[test]
    fn ipv4_packet_validation() {
        let src: IpAddr = "192.0.2.1".parse().unwrap();
        let dst: IpAddr = "192.0.2.2".parse().unwrap();
        let key = [7; 32];
        let tcp = make_packet(src, dst, 1000, 2000, 42, 99, 0x18, &[3; 16], 1, b"hello", &key);
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        packet[9] = libc::IPPROTO_TCP as u8;
        if let (IpAddr::V4(a), IpAddr::V4(b)) = (src, dst) {
            packet[12..16].copy_from_slice(&a.octets()); packet[16..20].copy_from_slice(&b.octets());
        }
        packet.extend_from_slice(&tcp);
        assert_eq!(parse_packet(&packet, src, dst, 1000, 2000, &key), Some((0x18, 42, 99, [3; 16], 1, &b"hello"[..])));
        assert_eq!(parse_packet(&packet, src, dst, 1001, 2000, &key), None);
        assert_eq!(parse_packet(&packet, src, dst, 1000, 2000, &[8; 32]), None);
        packet[20 + 60] ^= 1;
        assert_eq!(parse_packet(&packet, src, dst, 1000, 2000, &key), None);
        packet[6] = 0x20;
        assert_eq!(parse_packet(&packet, src, dst, 1000, 2000, &key), None);
    }

    #[test]
    fn ipv6_packet_validation() {
        let src: IpAddr = "::1".parse().unwrap();
        let dst: IpAddr = "2001:db8::1".parse().unwrap();
        let key = [7; 32];
        let mut packet = make_packet(src, dst, 123, 456, 1, 2, 0x18, &[3; 16], 1, b"odd", &key);
        assert_eq!(parse_packet(&packet, src, dst, 123, 456, &key), Some((0x18, 1, 2, [3; 16], 1, &b"odd"[..])));
        assert_eq!(parse_packet(&packet[..19], src, dst, 123, 456, &key), None);
        packet[12] = 0xe0;
        assert_eq!(parse_packet(&packet, src, dst, 123, 456, &key), None);
    }
}
