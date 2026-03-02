use std::net::SocketAddr;

use crate::FecMode;

#[derive(Debug, Clone)]
pub struct Config {
    pub fec_bind: SocketAddr,
    pub local_bind: SocketAddr,
    pub local_app_endpoint: SocketAddr,
    pub max_payload_size: usize,
    pub fec_mode: FecMode,
    pub fec_data_shards: u8,
    pub fec_parity_shards: u8,
    pub fec_flush_timeout_ms: u64,
    pub encode_fast_send: bool,
    pub decode_fast_send: bool,
    pub replay_window_blocks: usize,
    pub initial_peer_addr: Option<SocketAddr>,
    pub enforce_local_source: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            fec_bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            local_bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            local_app_endpoint: SocketAddr::from(([127, 0, 0, 1], 0)),
            max_payload_size: 1400,
            fec_mode: FecMode::Mode0,
            fec_data_shards: 4,
            fec_parity_shards: 2,
            fec_flush_timeout_ms: 50,
            encode_fast_send: true,
            decode_fast_send: true,
            replay_window_blocks: 1024,
            initial_peer_addr: None,
            enforce_local_source: true,
        }
    }
}

impl Config {
    pub fn new(fec_bind: SocketAddr, local_bind: SocketAddr, local_app_endpoint: SocketAddr) -> Self {
        Self {
            fec_bind,
            local_bind,
            local_app_endpoint,
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_payload_size == 0 || self.max_payload_size > u16::MAX as usize {
            return Err(ConfigError::InvalidMaxPayload(self.max_payload_size));
        }
        if self.fec_data_shards == 0 {
            return Err(ConfigError::InvalidFecDataShards);
        }
        if self.fec_flush_timeout_ms == 0 {
            return Err(ConfigError::InvalidFecFlushTimeout);
        }
        if self.replay_window_blocks == 0 {
            return Err(ConfigError::InvalidReplayWindow);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid max payload size: {0}")]
    InvalidMaxPayload(usize),
    #[error("fec_data_shards must be greater than 0")]
    InvalidFecDataShards,
    #[error("fec_flush_timeout_ms must be greater than 0")]
    InvalidFecFlushTimeout,
    #[error("replay_window_blocks must be greater than 0")]
    InvalidReplayWindow,
}
