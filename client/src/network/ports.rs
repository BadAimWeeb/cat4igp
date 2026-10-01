use std::collections::HashSet;
use std::net::{TcpListener, UdpSocket};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket as AsyncUdpSocket;

/// Get a random unused ephemeral port for TCP
pub fn get_random_tcp_port() -> std::io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Get a random unused ephemeral port for UDP
pub fn get_random_udp_port() -> std::io::Result<u16> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    Ok(socket.local_addr()?.port())
}

/// Send bounded delayed NAT-punch bursts before WireGuard/FEC claims the port.
pub async fn punch_udp(port: u16, peer: std::net::SocketAddr) -> std::io::Result<()> {
    let socket = AsyncUdpSocket::bind(if peer.is_ipv6() {
        format!("[::]:{port}")
    } else {
        format!("0.0.0.0:{port}")
    })
    .await?;
    for retry in 0..3 {
        for _ in 0..3 {
            socket.send_to(&[0], peer).await?;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if retry < 2 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    Ok(())
}

/// Manages port allocation within a specified range
#[derive(Clone)]
pub struct PortRange {
    start: u16,
    end: u16,
    allocated: Arc<Mutex<HashSet<u16>>>,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Self {
        Self {
            start,
            end,
            allocated: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Request a specific port, or allocate an unused port in range if unavailable
    pub fn allocate(&self, requested: Option<u16>) -> std::io::Result<u16> {
        let mut allocated = self.allocated.lock().unwrap();

        if let Some(port) = requested {
            if port >= self.start && port < self.end && !allocated.contains(&port) {
                allocated.insert(port);
                return Ok(port);
            }
        }

        // Find an unused port in range
        for port in self.start..self.end {
            if !allocated.contains(&port) {
                allocated.insert(port);
                return Ok(port);
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "No available ports in range",
        ))
    }

    /// Release an allocated port
    pub fn release(&self, port: u16) {
        self.allocated.lock().unwrap().remove(&port);
    }
}

#[cfg(test)]
mod tests {
    use super::PortRange;

    #[test]
    fn max_port_is_exclusive() {
        let ports = PortRange::new(10, 12);
        assert_eq!(ports.allocate(Some(12)).unwrap(), 10);
        assert_eq!(ports.allocate(Some(11)).unwrap(), 11);
    }
}
