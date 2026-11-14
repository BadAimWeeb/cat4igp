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
        Ok(Self { local_addr, table: Some((table, family)), shutdown: Some(shutdown), task: Some(task) })
    }

    pub fn local_addr(&self) -> SocketAddr { self.local_addr }

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

fn session_key(key: &[u8; 32], local: &[u8; 16], remote: &[u8; 16], port: u16, peer_port: u16) -> [u8; 32] {
    let mut mac = <Blake2sMac256 as KeyInit>::new_from_slice(key).expect("valid key");
    Mac::update(&mut mac, b"cat4igp-faketcp-session-v1");
    // A deterministic ordering gives both ends the same key, including equal ports.
    let (first, second) = if (port, local) < (peer_port, remote) { (local, remote) } else { (remote, local) };
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
                        let sk = session_key(&key, &local_nonce, &remote_nonce, port, peer.port());
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
                if n == 0 || n > MAX_PAYLOAD || !established || counter >= u32::MAX - 1 { continue; }
                let Some((remote_nonce, _)) = remote else { continue };
                counter += 1;
                let sk = session_key(&key, &local_nonce, &remote_nonce, port, peer.port());
                send_packet(&raw, source, peer, port, seq, remote_next, 0x18, &local_nonce, counter, &outgoing[..n], &sk).await?;
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
                        let sk = session_key(&key, &local_nonce, &nonce, port, peer.port());
                        send_packet(&raw, source, peer, port, seq, remote_next, 0x10, &local_nonce, counter, &[], &sk).await?;
                    }
                    continue;
                }
                let Some((remote_nonce, _)) = remote else { continue };
                let sk = session_key(&key, &local_nonce, &remote_nonce, port, peer.port());
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
    Mac::update(&mut mac, b"cat4igp-faketcp-v1");
    Mac::update(&mut mac, &packet[0..16]);
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
    Mac::update(&mut mac, b"cat4igp-faketcp-v1");
    Mac::update(&mut mac, &tcp[0..16]);
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
