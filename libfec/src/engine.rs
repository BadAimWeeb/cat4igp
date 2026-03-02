use crate::config::Config;
use crate::control::PeerState;
use crate::fec::{FecConfig, FecDecoder, FecEncoder};
use crate::handshake::{
    choose_server_role, decode_control_message, decode_resume_plaintext, derive_shared_key, encode_control_message,
    encode_resume_plaintext, encrypt_with_key, random_nonce, random_u64, ControlMessage, Hello, HelloAck, Resume,
    ResumeAck,
};
use crate::proto::{decode_packet, encode_packet, FLAG_CONTROL};
use crate::stats::Counters;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};

pub struct Runtime {
    local_task: JoinHandle<()>,
    fec_task: JoinHandle<()>,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.local_task.abort();
        self.fec_task.abort();
    }
}

pub struct BoundAddrs {
    pub fec_addr: SocketAddr,
    pub local_addr: SocketAddr,
}

struct SessionRuntime {
    local_session_id: u64,
    local_timestamp_ms: u64,
    local_secret: [u8; 32],
    local_public: [u8; 32],
    configured_peer: Option<SocketAddr>,
    active_peer: Option<SocketAddr>,
    remote_session_id: Option<u64>,
    remote_timestamp_ms: Option<u64>,
    remote_public: Option<[u8; 32]>,
    shared_key: Option<[u8; 32]>,
    established: bool,
    last_handshake_tx_ms: u64,
}

impl SessionRuntime {
    fn new(config: &Config) -> Self {
        let local_timestamp_ms = crate::handshake::now_ms();
        let (local_secret, local_public) = crate::handshake::generate_local_keypair();
        Self {
            local_session_id: random_u64(),
            local_timestamp_ms,
            local_secret,
            local_public,
            configured_peer: config.initial_peer_addr,
            active_peer: None,
            remote_session_id: None,
            remote_timestamp_ms: None,
            remote_public: None,
            shared_key: None,
            established: false,
            last_handshake_tx_ms: 0,
        }
    }

    fn target_for_handshake(&self) -> Option<SocketAddr> {
        self.configured_peer.or(self.active_peer)
    }

    fn sync_configured_peer(&mut self, configured: Option<SocketAddr>) {
        if self.configured_peer == configured {
            return;
        }

        self.configured_peer = configured;
        if configured.is_none() {
            self.active_peer = None;
            self.established = false;
            self.shared_key = None;
            self.remote_session_id = None;
            self.remote_timestamp_ms = None;
            self.remote_public = None;
        }
    }

    fn can_send_data(&self) -> Option<SocketAddr> {
        if self.established {
            self.active_peer
        } else {
            None
        }
    }

    fn maybe_establish_from_remote(
        &mut self,
        src: SocketAddr,
        remote_session_id: u64,
        remote_timestamp_ms: u64,
        remote_public: [u8; 32],
    ) {
        let key = derive_shared_key(
            self.local_secret,
            remote_public,
            self.local_session_id,
            remote_session_id,
        );
        self.remote_session_id = Some(remote_session_id);
        self.remote_timestamp_ms = Some(remote_timestamp_ms);
        self.remote_public = Some(remote_public);
        self.shared_key = Some(key);
        self.active_peer = Some(src);
        self.established = true;
    }

    fn should_send_hello(&self, now_ms: u64) -> Option<SocketAddr> {
        let target = if self.established {
            let configured = self.configured_peer?;
            if Some(configured) == self.active_peer {
                return None;
            }
            configured
        } else {
            self.target_for_handshake()?
        };

        if now_ms.saturating_sub(self.last_handshake_tx_ms) >= 100 {
            Some(target)
        } else {
            None
        }
    }

    fn should_send_resume(&self, now_ms: u64) -> Option<SocketAddr> {
        if !self.established {
            return None;
        }
        let configured = self.configured_peer?;
        if Some(configured) == self.active_peer {
            return None;
        }
        if now_ms.saturating_sub(self.last_handshake_tx_ms) >= 100 {
            Some(configured)
        } else {
            None
        }
    }
}

async fn send_control_packet(
    fec_socket: &UdpSocket,
    peer: SocketAddr,
    msg: ControlMessage,
) -> Result<(), std::io::Error> {
    let payload = encode_control_message(&msg);
    let encoded = encode_packet(FLAG_CONTROL, &payload)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    fec_socket.send_to(&encoded, peer).await?;
    Ok(())
}

pub async fn spawn(config: Config, peer_state: PeerState, counters: Arc<Counters>) -> Result<(Runtime, BoundAddrs), std::io::Error> {
    let fec_socket = Arc::new(UdpSocket::bind(config.fec_bind).await?);
    let local_socket = Arc::new(UdpSocket::bind(config.local_bind).await?);

    let bound = BoundAddrs {
        fec_addr: fec_socket.local_addr()?,
        local_addr: local_socket.local_addr()?,
    };

    let session = Arc::new(RwLock::new(SessionRuntime::new(&config)));

    let local_task = {
        let cfg = config.clone();
        let peer_state = peer_state.clone();
        let counters = Arc::clone(&counters);
        let fec_socket = Arc::clone(&fec_socket);
        let local_socket = Arc::clone(&local_socket);
        let session = Arc::clone(&session);
        tokio::spawn(async move {
            let mut fec_encoder = match FecEncoder::new(FecConfig {
                mode: cfg.fec_mode,
                data_shards: cfg.fec_data_shards,
                parity_shards: cfg.fec_parity_shards,
                max_payload_size: cfg.max_payload_size,
                encode_fast_send: cfg.encode_fast_send,
                decode_fast_send: cfg.decode_fast_send,
                replay_window_blocks: cfg.replay_window_blocks,
            }) {
                Ok(encoder) => encoder,
                Err(_) => return,
            };

            let flush_timeout = Duration::from_millis(cfg.fec_flush_timeout_ms);
            let mut flush_tick = time::interval(flush_timeout);
            flush_tick.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
            let mut handshake_tick = time::interval(Duration::from_millis(50));
            handshake_tick.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

            let mut buf = vec![0u8; cfg.max_payload_size];
            loop {
                tokio::select! {
                    recv = local_socket.recv_from(&mut buf) => {
                        let Ok((n, src)) = recv else {
                            break;
                        };

                        counters.local_rx_packets.fetch_add(1, Ordering::Relaxed);

                        if cfg.enforce_local_source && src != cfg.local_app_endpoint {
                            counters.dropped_local_source.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }

                        let peer_addr = {
                            let lock = session.read().await;
                            lock.can_send_data()
                        };

                        let Some(peer_addr) = peer_addr else {
                            counters.dropped_no_peer.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };

                        let fec_frames = match fec_encoder.push(&buf[..n]) {
                            Ok(frames) => frames,
                            Err(_) => {
                                counters.dropped_decode.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        };

                        for frame in fec_frames {
                            if let Ok(encoded) = encode_packet(0, &frame) {
                                if fec_socket.send_to(&encoded, peer_addr).await.is_ok() {
                                    counters.fec_tx_packets.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                    _ = flush_tick.tick() => {
                        let peer_addr = {
                            let lock = session.read().await;
                            lock.can_send_data()
                        };

                        let Some(peer_addr) = peer_addr else {
                            continue;
                        };

                        let fec_frames = match fec_encoder.flush_if_timed_out(flush_timeout) {
                            Ok(frames) => frames,
                            Err(_) => {
                                counters.dropped_decode.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        };

                        for frame in fec_frames {
                            if let Ok(encoded) = encode_packet(0, &frame) {
                                if fec_socket.send_to(&encoded, peer_addr).await.is_ok() {
                                    counters.fec_tx_packets.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                    _ = handshake_tick.tick() => {
                        let configured = peer_state.get_peer_addr().await;
                        let now_ms = crate::handshake::now_ms();

                        let (hello_target, hello, resume_target, resume) = {
                            let mut lock = session.write().await;
                            lock.sync_configured_peer(configured);

                            let hello_target = lock.should_send_hello(now_ms);
                            let hello = hello_target.map(|_| ControlMessage::Hello(Hello {
                                session_id: lock.local_session_id,
                                timestamp_ms: lock.local_timestamp_ms,
                                public_key: lock.local_public,
                            }));

                            let resume_target = lock.should_send_resume(now_ms);
                            let resume = if let Some(_peer) = resume_target {
                                if let (Some(key), Some(remote_session_id)) = (lock.shared_key, lock.remote_session_id) {
                                    let nonce = random_nonce();
                                    let plain = encode_resume_plaintext(lock.local_session_id, remote_session_id, now_ms);
                                    encrypt_with_key(key, nonce, &plain).ok().map(|ciphertext| {
                                        ControlMessage::Resume(Resume {
                                            session_id: lock.local_session_id,
                                            nonce,
                                            ciphertext,
                                        })
                                    })
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                            if hello_target.is_some() || resume_target.is_some() {
                                lock.last_handshake_tx_ms = now_ms;
                            }
                            (hello_target, hello, resume_target, resume)
                        };

                        if let (Some(target), Some(msg)) = (hello_target, hello) {
                            if send_control_packet(&fec_socket, target, msg).await.is_ok() {
                                counters.handshake_tx_packets.fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        if let (Some(target), Some(msg)) = (resume_target, resume) {
                            if send_control_packet(&fec_socket, target, msg).await.is_ok() {
                                counters.handshake_tx_packets.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        })
    };

    let fec_task = {
        let cfg = config;
        let counters = Arc::clone(&counters);
        let local_socket = Arc::clone(&local_socket);
        let fec_socket = Arc::clone(&fec_socket);
        let session = Arc::clone(&session);
        tokio::spawn(async move {
            let mut fec_decoder = FecDecoder::new(cfg.decode_fast_send, cfg.replay_window_blocks);
            let mut buf = vec![0u8; 65535];
            while let Ok((n, src)) = fec_socket.recv_from(&mut buf).await {
                counters.fec_rx_packets.fetch_add(1, Ordering::Relaxed);

                let packet = match decode_packet(&buf[..n]) {
                    Ok(packet) => packet,
                    Err(_) => {
                        counters.dropped_decode.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                if (packet.header.flags & FLAG_CONTROL) != 0 {
                    counters.handshake_rx_packets.fetch_add(1, Ordering::Relaxed);
                    let control = match decode_control_message(&packet.payload) {
                        Ok(msg) => msg,
                        Err(_) => {
                            counters.dropped_invalid_control.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };

                    let response = {
                        let mut lock = session.write().await;
                        if lock.configured_peer.is_none() {
                            lock.configured_peer = Some(src);
                        }

                        match control {
                            ControlMessage::Hello(msg) => {
                                let role = choose_server_role(
                                    lock.local_timestamp_ms,
                                    msg.timestamp_ms,
                                    lock.local_session_id,
                                    msg.session_id,
                                );

                                lock.maybe_establish_from_remote(src, msg.session_id, msg.timestamp_ms, msg.public_key);
                                counters.handshake_established.fetch_add(1, Ordering::Relaxed);

                                Some(ControlMessage::HelloAck(HelloAck {
                                    session_id: lock.local_session_id,
                                    timestamp_ms: lock.local_timestamp_ms,
                                    public_key: lock.local_public,
                                    role,
                                }))
                            }
                            ControlMessage::HelloAck(msg) => {
                                lock.maybe_establish_from_remote(src, msg.session_id, msg.timestamp_ms, msg.public_key);
                                counters.handshake_established.fetch_add(1, Ordering::Relaxed);
                                None
                            }
                            ControlMessage::Resume(msg) => {
                                let accepted = if let (Some(key), Some(remote_session_id)) = (lock.shared_key, lock.remote_session_id) {
                                    let decrypted = crate::handshake::decrypt_with_key(key, msg.nonce, &msg.ciphertext);
                                    if let Ok(plain) = decrypted {
                                        if let Ok((sender_local, sender_remote, _ts)) = decode_resume_plaintext(&plain) {
                                            if sender_local == remote_session_id && sender_remote == lock.local_session_id {
                                                lock.active_peer = Some(src);
                                                lock.configured_peer = Some(src);
                                                lock.established = true;
                                                counters.resume_success.fetch_add(1, Ordering::Relaxed);
                                                true
                                            } else {
                                                false
                                            }
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                };

                                Some(ControlMessage::ResumeAck(ResumeAck {
                                    session_id: lock.local_session_id,
                                    accepted,
                                }))
                            }
                            ControlMessage::ResumeAck(msg) => {
                                if msg.accepted {
                                    lock.active_peer = Some(src);
                                    lock.configured_peer = Some(src);
                                    lock.established = true;
                                    counters.resume_success.fetch_add(1, Ordering::Relaxed);
                                }
                                None
                            }
                        }
                    };

                    if let Some(msg) = response {
                        if send_control_packet(&fec_socket, src, msg).await.is_ok() {
                            counters.handshake_tx_packets.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    continue;
                }

                let established_peer = {
                    let lock = session.read().await;
                    lock.can_send_data()
                };

                let Some(peer_addr) = established_peer else {
                    counters.dropped_unestablished.fetch_add(1, Ordering::Relaxed);
                    continue;
                };

                if src != peer_addr {
                    counters.dropped_unestablished.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                let recovered = match fec_decoder.ingest(&packet.payload) {
                    Ok(items) => items,
                    Err(_) => {
                        counters.dropped_decode.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                for payload in recovered {
                    if local_socket.send_to(&payload, cfg.local_app_endpoint).await.is_ok() {
                        counters.local_tx_packets.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        })
    };

    Ok((Runtime { local_task, fec_task }, bound))
}
