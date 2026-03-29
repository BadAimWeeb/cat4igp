use std::net::{TcpListener, UdpSocket};
use std::sync::{Arc, Mutex};
use std::collections::HashSet;

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
            if port >= self.start && port <= self.end && !allocated.contains(&port) {
                allocated.insert(port);
                return Ok(port);
            }
        }

        // Find an unused port in range
        for port in self.start..=self.end {
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