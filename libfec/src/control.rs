use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct PeerState {
    current: Arc<RwLock<(bool, Option<SocketAddr>)>>,
}

impl PeerState {
    pub fn new(initial: Option<SocketAddr>) -> Self {
        Self {
            current: Arc::new(RwLock::new((true, initial))),
        }
    }

    pub async fn set_peer_addr(&self, addr: SocketAddr) {
        let mut lock = self.current.write().await;
        *lock = (true, Some(addr));
    }

    pub async fn clear_peer_addr(&self) {
        let mut lock = self.current.write().await;
        *lock = (false, None);
    }

    pub async fn unpin_peer_addr(&self) {
        let mut lock = self.current.write().await;
        *lock = (true, None);
    }

    pub async fn get_peer_addr(&self) -> Option<SocketAddr> {
        self.current.read().await.1
    }

    pub async fn snapshot(&self) -> (bool, Option<SocketAddr>) {
        *self.current.read().await
    }
}
