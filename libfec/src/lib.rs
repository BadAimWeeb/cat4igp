mod config;
mod control;
mod engine;
mod fec;
mod handshake;
mod proto;
mod stats;
mod transport;

pub use config::{Config, ConfigError};
pub use fec::{FecConfig, FecDecoder, FecEncoder, FecError, FecMode};
pub use stats::Snapshot;
pub use transport::{TokioUdpPipe, TransportError, UdpPipe};

pub use proto::{decode_packet, encode_packet, Header, Packet, ProtoError, MAGIC, VERSION};
pub use handshake::{ControlMessage, HandshakeError, Role};

use crate::control::PeerState;
use crate::engine::Runtime;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Fec(#[from] FecError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct EngineHandle {
    peer_state: PeerState,
    counters: Arc<stats::Counters>,
    fec_bind_addr: SocketAddr,
    local_bind_addr: SocketAddr,
}

impl EngineHandle {
    pub async fn set_peer_addr(&self, addr: SocketAddr) {
        self.peer_state.set_peer_addr(addr).await;
    }

    pub async fn clear_peer_addr(&self) {
        self.peer_state.clear_peer_addr().await;
    }

    pub async fn get_peer_addr(&self) -> Option<SocketAddr> {
        self.peer_state.get_peer_addr().await
    }

    pub fn stats(&self) -> Snapshot {
        self.counters.snapshot()
    }

    pub fn fec_bind_addr(&self) -> SocketAddr {
        self.fec_bind_addr
    }

    pub fn local_bind_addr(&self) -> SocketAddr {
        self.local_bind_addr
    }
}

pub struct PeerEngine {
    _runtime: Runtime,
    handle: EngineHandle,
}

impl PeerEngine {
    pub async fn start(config: Config) -> Result<Self, Error> {
        config.validate()?;

        let peer_state = PeerState::new(config.initial_peer_addr);
        let counters = Arc::new(stats::Counters::default());
        let (runtime, bound) = engine::spawn(config, peer_state.clone(), Arc::clone(&counters)).await?;

        let handle = EngineHandle {
            peer_state,
            counters,
            fec_bind_addr: bound.fec_addr,
            local_bind_addr: bound.local_addr,
        };

        Ok(Self {
            _runtime: runtime,
            handle,
        })
    }

    pub fn handle(&self) -> &EngineHandle {
        &self.handle
    }
}
