//! UDP bridge for WireGuard with STUN on the live public-facing socket.
//!
//! The bridge cannot authenticate WireGuard packets itself. Only the exact
//! control-plane-selected peer is forwarded; roaming requires a trusted update.
use std::{io, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, time::Duration};
use rand08::{rngs::OsRng, RngCore};
use tokio::{net::UdpSocket, sync::{mpsc, oneshot, Mutex}, task::JoinHandle};

enum Command {
    Peer(Option<SocketAddr>),
    Stun(SocketAddr, [u8; 20], oneshot::Sender<Result<SocketAddr, String>>),
}

pub struct UdpProxy {
    local_addr: SocketAddr,
    ipv6: bool,
    commands: mpsc::Sender<Command>,
    serial: Mutex<()>,
    task: Option<JoinHandle<io::Result<()>>>,
}

fn valid_peer(addr: SocketAddr, ipv6: bool) -> bool {
    addr.is_ipv6() == ipv6 && addr.port() != 0 && !addr.ip().is_unspecified() && !addr.ip().is_multicast()
}

impl UdpProxy {
    pub async fn start(local_port: u16, ipv6: bool, peer: Option<SocketAddr>, local_udp: SocketAddr) -> io::Result<Self> {
        if local_port == 0 || !local_udp.ip().is_loopback() || local_udp.port() == 0 || peer.is_some_and(|p| !valid_peer(p, ipv6)) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid UDP proxy endpoint"));
        }
        let public = UdpSocket::bind(if ipv6 { SocketAddr::from(([0u16; 8], local_port)) } else { SocketAddr::from(([0u8; 4], local_port)) }).await?;
        let local = UdpSocket::bind(SocketAddr::new(local_udp.ip(), 0)).await?;
        local.connect(local_udp).await?;
        let local_addr = local.local_addr()?;
        let (commands, rx) = mpsc::channel(8);
        let task = tokio::spawn(run(public, local, peer, rx));
        Ok(Self { local_addr, ipv6, commands, serial: Mutex::new(()), task: Some(task) })
    }

    pub fn local_addr(&self) -> SocketAddr { self.local_addr }
    pub fn is_running(&self) -> bool { self.task.as_ref().is_some_and(|t| !t.is_finished()) }

    pub async fn set_peer(&self, peer: Option<SocketAddr>) -> io::Result<()> {
        if peer.is_some_and(|p| !valid_peer(p, self.ipv6)) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid UDP proxy peer"));
        }
        self.commands.send(Command::Peer(peer)).await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "UDP proxy stopped"))
    }

    pub async fn mapped_addr(&self, server: SocketAddr, timeout: Duration) -> Result<SocketAddr, String> {
        if !valid_peer(server, self.ipv6) { return Err("invalid STUN server address".into()); }
        let _guard = self.serial.lock().await;
        let mut request = [0u8; 20];
        request[..2].copy_from_slice(&[0, 1]);
        request[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        OsRng.fill_bytes(&mut request[8..]);
        let (tx, rx) = oneshot::channel();
        self.commands.send(Command::Stun(server, request, tx)).await.map_err(|_| "UDP proxy stopped".to_string())?;
        tokio::time::timeout(timeout, rx).await.map_err(|_| "STUN request timed out".to_string())?
            .map_err(|_| "UDP proxy stopped during STUN request".to_string())?
    }

    pub async fn stop(&mut self) -> io::Result<()> {
        if let Some(task) = self.task.take() {
            task.abort();
            match task.await { Ok(result) => result, Err(e) if e.is_cancelled() => Ok(()), Err(e) => Err(io::Error::other(e)) }
        } else { Ok(()) }
    }
}
impl Drop for UdpProxy { fn drop(&mut self) { if let Some(task) = self.task.take() { task.abort(); } } }

fn datagram_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EMSGSIZE)
        || matches!(error.kind(), io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset)
}

fn discard_datagram_error<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if datagram_error(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

async fn run(public: UdpSocket, local: UdpSocket, mut peer: Option<SocketAddr>, mut commands: mpsc::Receiver<Command>) -> io::Result<()> {
    let mut pending: Option<(SocketAddr, [u8; 12], oneshot::Sender<Result<SocketAddr, String>>)> = None;
    let mut remote_buf = [0u8; 65536];
    let mut local_buf = [0u8; 65536];
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Peer(next)) => peer = next,
                Some(Command::Stun(server, request, reply)) => {
                    match public.send_to(&request, server).await {
                        Ok(_) => pending = Some((server, request[8..].try_into().unwrap(), reply)),
                        Err(e) => {
                            let fatal = !datagram_error(&e);
                            let _ = reply.send(Err(format!("STUN send failed: {e}")));
                            if fatal { return Err(e); }
                        }
                    }
                }
                None => return Ok(()),
            },
            packet = public.recv_from(&mut remote_buf) => {
                let Some((len, source)) = discard_datagram_error(packet)? else { continue };
                let packet = &remote_buf[..len];
                if let Some((server, transaction, _)) = &pending {
                    if source == *server && packet.len() >= 20 && packet[8..20] == *transaction {
                        if let Some(mapped) = parse_stun(packet).filter(|a| valid_peer(*a, source.is_ipv6())) {
                            let (_, _, reply) = pending.take().unwrap();
                            let _ = reply.send(Ok(mapped));
                        }
                        continue;
                    }
                }
                if Some(source) == peer { discard_datagram_error(local.send(packet).await)?; }
            },
            packet = local.recv(&mut local_buf) => {
                let Some(len) = discard_datagram_error(packet)? else { continue };
                if let Some(peer) = peer { discard_datagram_error(public.send_to(&local_buf[..len], peer).await)?; }
            }
        }
    }
}

fn parse_stun(packet: &[u8]) -> Option<SocketAddr> {
    if packet.len() < 20 || packet[..2] != [1, 1] || packet[4..8] != [0x21, 0x12, 0xa4, 0x42] { return None; }
    let len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if len % 4 != 0 || packet.len() != 20 + len { return None; }
    let mut offset = 20;
    while offset + 4 <= packet.len() {
        let kind = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let len = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
        let start = offset + 4;
        let end = start.checked_add((len + 3) & !3)?;
        if end > packet.len() { return None; }
        if matches!(kind, 1 | 0x20) {
            let data = &packet[start..start + len];
            if !matches!((data.get(1), data.len()), (Some(1), 8) | (Some(2), 20)) { return None; }
            let mut port = u16::from_be_bytes([data[2], data[3]]);
            let mut bytes = [0; 16];
            bytes[..len - 4].copy_from_slice(&data[4..]);
            if kind == 0x20 {
                port ^= 0x2112;
                for (byte, mask) in bytes[..len - 4].iter_mut().zip(&packet[4..20]) { *byte ^= mask; }
            }
            let ip = if data[1] == 1 { IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])) } else { IpAddr::V6(Ipv6Addr::from(bytes)) };
            return Some(SocketAddr::new(ip, port));
        }
        offset = end;
    }
    None
}

#[cfg(test)]
#[path = "udp_proxy_test.rs"]
mod tests;
