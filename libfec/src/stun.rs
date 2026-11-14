use rand::{rngs::OsRng, RngCore};
use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, sync::{Arc, Mutex}, time::Duration};
use tokio::{net::UdpSocket, sync::{oneshot, Mutex as AsyncMutex}};

struct Pending {
    server: SocketAddr,
    transaction: [u8; 12],
    reply: oneshot::Sender<SocketAddr>,
}

#[derive(Default)]
pub(crate) struct Stun {
    pending: Mutex<Option<Pending>>,
    serial: AsyncMutex<()>,
}

struct Cleanup<'a>(&'a Stun);
impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        self.0.pending.lock().unwrap().take();
    }
}

impl Stun {
    pub(crate) async fn mapped_addr(self: &Arc<Self>, socket: &UdpSocket, server: SocketAddr, timeout: Duration) -> Result<SocketAddr, String> {
        let _serial = self.serial.lock().await;
        let mut request = [0u8; 20];
        request[..2].copy_from_slice(&[0, 1]);
        request[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        OsRng.fill_bytes(&mut request[8..]);
        let transaction = request[8..20].try_into().unwrap();
        let (reply, received) = oneshot::channel();
        *self.pending.lock().unwrap() = Some(Pending { server, transaction, reply });
        let _cleanup = Cleanup(self);
        socket.send_to(&request, server).await.map_err(|e| format!("STUN send failed: {e}"))?;
        tokio::time::timeout(timeout, received).await
            .map_err(|_| "STUN request timed out".to_string())?
            .map_err(|_| "FEC receive loop stopped during STUN request".to_string())
    }

    pub(crate) fn receive(&self, source: SocketAddr, packet: &[u8]) -> bool {
        let mut pending = self.pending.lock().unwrap();
        let Some(probe) = pending.as_ref() else { return false };
        if source != probe.server || packet.len() < 20 || packet[8..20] != probe.transaction {
            return false;
        }
        let Some(mapped) = parse(packet) else { return true };
        if mapped.is_ipv6() != source.is_ipv6() || mapped.port() == 0 || mapped.ip().is_unspecified() || mapped.ip().is_multicast() {
            return true;
        }
        let probe = pending.take().unwrap();
        let _ = probe.reply.send(mapped);
        true
    }
}

fn parse(packet: &[u8]) -> Option<SocketAddr> {
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
mod tests {
    use super::*;

    #[test]
    fn parses_ipv6_xor_mapping_and_rejects_truncation() {
        let expected: SocketAddr = "[2001:db8:1234:5678:90ab:cdef:1020:3040]:4660".parse().unwrap();
        let mut packet = vec![1, 1, 0, 24, 0x21, 0x12, 0xa4, 0x42];
        packet.extend_from_slice(&[7; 12]);
        packet.extend_from_slice(&[0, 0x20, 0, 20, 0, 2]);
        packet.extend_from_slice(&(expected.port() ^ 0x2112).to_be_bytes());
        let ip = match expected.ip() { IpAddr::V6(ip) => ip.octets(), _ => unreachable!() };
        for (byte, mask) in ip.into_iter().zip(packet[4..20].to_vec()) { packet.push(byte ^ mask); }
        assert_eq!(parse(&packet), Some(expected));
        for n in 0..packet.len() { assert_eq!(parse(&packet[..n]), None); }
    }
}
