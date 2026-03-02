use async_trait::async_trait;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::UdpSocket;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[async_trait]
pub trait UdpPipe: Send + Sync {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), TransportError>;
    async fn send_to(&self, data: &[u8], target: SocketAddr) -> Result<usize, TransportError>;
    fn local_addr(&self) -> Result<SocketAddr, TransportError>;
}

pub struct TokioUdpPipe {
    socket: UdpSocket,
}

impl TokioUdpPipe {
    pub async fn bind(addr: SocketAddr) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self { socket })
    }

    pub fn from_socket(socket: UdpSocket) -> Self {
        Self { socket }
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

#[async_trait]
impl UdpPipe for TokioUdpPipe {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), TransportError> {
        Ok(self.socket.recv_from(buf).await?)
    }

    async fn send_to(&self, data: &[u8], target: SocketAddr) -> Result<usize, TransportError> {
        Ok(self.socket.send_to(data, target).await?)
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.socket.local_addr()?)
    }
}
