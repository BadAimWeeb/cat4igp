use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct PeerState {
    current: Arc<RwLock<Option<SocketAddr>>>,
}

impl PeerState {
    pub fn new(initial: Option<SocketAddr>) -> Self {
        Self {
            current: Arc::new(RwLock::new(initial)),
        }
    }

    pub async fn set_peer_addr(&self, addr: SocketAddr) {
        let mut lock = self.current.write().await;
        *lock = Some(addr);
    }

    pub async fn clear_peer_addr(&self) {
        let mut lock = self.current.write().await;
        *lock = None;
    }

    pub async fn get_peer_addr(&self) -> Option<SocketAddr> {
        *self.current.read().await
    }
}
