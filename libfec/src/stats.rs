use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Counters {
    pub local_rx_packets: AtomicU64,
    pub fec_tx_packets: AtomicU64,
    pub fec_rx_packets: AtomicU64,
    pub local_tx_packets: AtomicU64,
    pub dropped_no_peer: AtomicU64,
    pub dropped_local_source: AtomicU64,
    pub dropped_decode: AtomicU64,
    pub dropped_unestablished: AtomicU64,
    pub handshake_tx_packets: AtomicU64,
    pub handshake_rx_packets: AtomicU64,
    pub handshake_established: AtomicU64,
    pub resume_success: AtomicU64,
    pub dropped_invalid_control: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub local_rx_packets: u64,
    pub fec_tx_packets: u64,
    pub fec_rx_packets: u64,
    pub local_tx_packets: u64,
    pub dropped_no_peer: u64,
    pub dropped_local_source: u64,
    pub dropped_decode: u64,
    pub dropped_unestablished: u64,
    pub handshake_tx_packets: u64,
    pub handshake_rx_packets: u64,
    pub handshake_established: u64,
    pub resume_success: u64,
    pub dropped_invalid_control: u64,
}

impl Counters {
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            local_rx_packets: self.local_rx_packets.load(Ordering::Relaxed),
            fec_tx_packets: self.fec_tx_packets.load(Ordering::Relaxed),
            fec_rx_packets: self.fec_rx_packets.load(Ordering::Relaxed),
            local_tx_packets: self.local_tx_packets.load(Ordering::Relaxed),
            dropped_no_peer: self.dropped_no_peer.load(Ordering::Relaxed),
            dropped_local_source: self.dropped_local_source.load(Ordering::Relaxed),
            dropped_decode: self.dropped_decode.load(Ordering::Relaxed),
            dropped_unestablished: self.dropped_unestablished.load(Ordering::Relaxed),
            handshake_tx_packets: self.handshake_tx_packets.load(Ordering::Relaxed),
            handshake_rx_packets: self.handshake_rx_packets.load(Ordering::Relaxed),
            handshake_established: self.handshake_established.load(Ordering::Relaxed),
            resume_success: self.resume_success.load(Ordering::Relaxed),
            dropped_invalid_control: self.dropped_invalid_control.load(Ordering::Relaxed),
        }
    }
}
