use cat4igp_libfec::{encode_packet, Config, FecMode, PeerEngine};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha256;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use x25519_dalek::{PublicKey, StaticSecret};

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

#[tokio::test]
async fn peer_address_can_change_on_the_fly() {
    let sender = UdpSocket::bind(localhost(0)).await.expect("bind sender");
    let app_peer1 = UdpSocket::bind(localhost(0)).await.expect("bind app peer1");
    let app_peer2 = UdpSocket::bind(localhost(0)).await.expect("bind app peer2");

    let sender_addr = sender.local_addr().expect("sender addr");
    let app_peer1_addr = app_peer1.local_addr().expect("app peer1 addr");
    let app_peer2_addr = app_peer2.local_addr().expect("app peer2 addr");

    let mut peer1_cfg = Config::new(localhost(0), localhost(0), app_peer1_addr);
    peer1_cfg.fec_mode = FecMode::Mode0;
    peer1_cfg.fec_data_shards = 1;
    peer1_cfg.fec_parity_shards = 0;
    peer1_cfg.fec_flush_timeout_ms = 20;
    peer1_cfg.encode_fast_send = false;
    peer1_cfg.decode_fast_send = false;

    let peer1 = PeerEngine::start(peer1_cfg).await.expect("start peer1");

    let mut peer2_cfg = Config::new(localhost(0), localhost(0), app_peer2_addr);
    peer2_cfg.fec_mode = FecMode::Mode0;
    peer2_cfg.fec_data_shards = 1;
    peer2_cfg.fec_parity_shards = 0;
    peer2_cfg.fec_flush_timeout_ms = 20;
    peer2_cfg.encode_fast_send = false;
    peer2_cfg.decode_fast_send = false;

    let peer2 = PeerEngine::start(peer2_cfg).await.expect("start peer2");

    let mut cfg = Config::new(localhost(0), localhost(0), sender_addr);
    cfg.fec_mode = FecMode::Mode0;
    cfg.fec_data_shards = 1;
    cfg.fec_parity_shards = 0;
    cfg.fec_flush_timeout_ms = 20;
    cfg.encode_fast_send = false;
    cfg.decode_fast_send = false;
    cfg.initial_peer_addr = Some(peer1.handle().fec_bind_addr());

    let engine = PeerEngine::start(cfg).await.expect("start engine");
    let handle = engine.handle();
    peer1.handle().set_peer_addr(handle.fec_bind_addr()).await;
    peer2.handle().set_peer_addr(handle.fec_bind_addr()).await;

    for _ in 0..100 {
        if handle.stats().handshake_established > 0
            && peer1.handle().stats().handshake_established > 0
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    sender
        .send_to(b"first", handle.local_bind_addr())
        .await
        .expect("send first");

    let mut buf = [0u8; 2048];
    let (n1, _) = timeout(Duration::from_secs(2), app_peer1.recv_from(&mut buf))
        .await
        .expect("wait first timeout")
        .expect("wait first recv");
    assert_eq!(&buf[..n1], b"first");

    handle.set_peer_addr(peer2.handle().fec_bind_addr()).await;

    for _ in 0..100 {
        if handle.stats().handshake_established > 1
            && peer2.handle().stats().handshake_established > 0
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    sender
        .send_to(b"second", handle.local_bind_addr())
        .await
        .expect("send second");

    let (n2, _) = timeout(Duration::from_secs(2), app_peer2.recv_from(&mut buf))
        .await
        .expect("wait second timeout")
        .expect("wait second recv");
    assert_eq!(&buf[..n2], b"second");

    let stats = handle.stats();
    assert!(stats.fec_tx_packets >= 2);
    assert!(stats.handshake_established >= 2);
}

#[tokio::test]
async fn unsolicited_control_cannot_establish_or_redirect_peer() {
    let app = UdpSocket::bind(localhost(0)).await.unwrap();
    let peer = UdpSocket::bind(localhost(0)).await.unwrap();
    let intruder = UdpSocket::bind(localhost(0)).await.unwrap();
    let mut cfg = Config::new(localhost(0), localhost(0), app.local_addr().unwrap());
    cfg.fec_data_shards = 1;
    cfg.fec_parity_shards = 0;
    cfg.handshake_psk = Some([42; 32]);
    let engine = PeerEngine::start(cfg).await.unwrap();
    let handle = engine.handle();
    let mut hello = vec![1]; // Hello, session ID 7, timestamp 8, public key.
    hello.extend_from_slice(&7u64.to_be_bytes());
    hello.extend_from_slice(&8u64.to_be_bytes());
    hello.extend_from_slice(&[9; 32]);
    let mut hello_ack = hello.clone();
    hello_ack[0] = 2;
    hello_ack[17] = 10; // The known session ID must not change public keys.
    hello_ack.push(1);
    let mut resume_ack = vec![4];
    resume_ack.extend_from_slice(&7u64.to_be_bytes());
    resume_ack.push(1);
    let mut resume = vec![3];
    resume.extend_from_slice(&7u64.to_be_bytes());
    resume.extend_from_slice(&[0; 12]);
    resume.extend_from_slice(&0u16.to_be_bytes());

    async fn inject(socket: &UdpSocket, handle: &cat4igp_libfec::EngineHandle, payload: &[u8]) {
        inject_with_key(socket, handle, payload, None).await;
    }

    async fn inject_with_key(
        socket: &UdpSocket,
        handle: &cat4igp_libfec::EngineHandle,
        payload: &[u8],
        key: Option<[u8; 32]>,
    ) {
        let mut payload = payload.to_vec();
        if let Some(key) = key {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
            mac.update(b"cat4igp-fec-control-v1");
            mac.update(&payload);
            payload.extend_from_slice(&mac.finalize().into_bytes());
        }
        let received = handle.stats().fec_rx_packets;
        socket
            .send_to(&encode_packet(1, &payload).unwrap(), handle.fec_bind_addr())
            .await
            .unwrap();
        // Receiving a second frame proves the control packet finished processing.
        socket
            .send_to(&encode_packet(0, &[]).unwrap(), handle.fec_bind_addr())
            .await
            .unwrap();
        timeout(Duration::from_secs(2), async {
            while handle.stats().fec_rx_packets < received + 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    for payload in [&hello_ack, &resume_ack, &hello, &resume] {
        inject(&intruder, handle, payload).await;
        assert_eq!(handle.stats().handshake_established, 0);
        assert_eq!(handle.stats().resume_success, 0);
    }
    handle.set_peer_addr(peer.local_addr().unwrap()).await;
    let mut buf = [0; 2048];
    timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    inject_with_key(&peer, handle, &hello, Some([42; 32])).await;
    assert_eq!(handle.stats().handshake_established, 0);

    for payload in [&hello, &hello_ack, &resume, &resume_ack] {
        inject(&intruder, handle, payload).await;
        assert_eq!(handle.stats().handshake_established, 0);
        assert_eq!(handle.stats().resume_success, 0);
    }
    // Even the configured peer cannot acknowledge an exchange that is not pending.
    for payload in [&hello_ack, &resume_ack] {
        inject_with_key(&peer, handle, payload, Some([42; 32])).await;
        assert_eq!(handle.stats().handshake_established, 0);
        assert_eq!(handle.stats().resume_success, 0);
    }
    app.send_to(b"unconfirmed", handle.local_bind_addr())
        .await
        .unwrap();
    timeout(Duration::from_secs(2), async {
        while handle.stats().dropped_no_peer == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    handle.clear_peer_addr().await;
    let dropped = handle.stats().dropped_no_peer;
    app.send_to(b"cleared", handle.local_bind_addr())
        .await
        .unwrap();
    timeout(Duration::from_secs(2), async {
        while handle.stats().dropped_no_peer == dropped {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for payload in [&hello, &hello_ack, &resume, &resume_ack] {
        inject_with_key(&peer, handle, payload, Some([42; 32])).await;
        assert_eq!(handle.stats().handshake_established, 0);
        assert_eq!(handle.stats().resume_success, 0);
    }
    assert_eq!(handle.get_peer_addr().await, None);
}

#[tokio::test]
async fn one_known_endpoint_learns_only_matching_psk() {
    for key in [None, Some([93; 32])] {
        let app_a = UdpSocket::bind(localhost(0)).await.unwrap();
        let app_b = UdpSocket::bind(localhost(0)).await.unwrap();
        let mut b = Config::new(localhost(0), localhost(0), app_b.local_addr().unwrap());
        b.fec_data_shards = 1;
        b.fec_parity_shards = 0;
        b.handshake_psk = key;
        let b = PeerEngine::start(b).await.unwrap();
        let mut a = Config::new(localhost(0), localhost(0), app_a.local_addr().unwrap());
        a.initial_peer_addr = Some(b.handle().fec_bind_addr());
        a.fec_data_shards = 1;
        a.fec_parity_shards = 0;
        a.handshake_psk = key;
        let a = PeerEngine::start(a).await.unwrap();

        timeout(Duration::from_secs(3), async {
            while a.handle().stats().handshake_established == 0
                || b.handle().stats().handshake_established == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(b.handle().get_peer_addr().await, None);
        app_b
            .send_to(b"learned", b.handle().local_bind_addr())
            .await
            .unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = timeout(Duration::from_secs(2), app_a.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"learned");
        app_a
            .send_to(b"response", a.handle().local_bind_addr())
            .await
            .unwrap();
        let (n, _) = timeout(Duration::from_secs(2), app_b.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"response");
    }
}

#[tokio::test]
async fn different_psk_cannot_learn_unknown_endpoint() {
    let app = UdpSocket::bind(localhost(0)).await.unwrap();
    let sender = UdpSocket::bind(localhost(0)).await.unwrap();
    let mut b = Config::new(localhost(0), localhost(0), app.local_addr().unwrap());
    b.handshake_psk = Some([93; 32]);
    let b = PeerEngine::start(b).await.unwrap();
    let mut a = Config::new(localhost(0), localhost(0), sender.local_addr().unwrap());
    a.handshake_psk = Some([92; 32]);
    a.initial_peer_addr = Some(b.handle().fec_bind_addr());
    let a = PeerEngine::start(a).await.unwrap();
    timeout(Duration::from_secs(2), async {
        while b.handle().stats().dropped_invalid_control == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(b.handle().stats().handshake_established, 0);
    assert_eq!(a.handle().stats().handshake_established, 0);
    assert_eq!(b.handle().get_peer_addr().await, None);
}

#[tokio::test]
async fn simultaneous_psk_hello_completes() {
    let app = UdpSocket::bind(localhost(0)).await.unwrap();
    let mut a = Config::new(localhost(0), localhost(0), app.local_addr().unwrap());
    a.handshake_psk = Some([61; 32]);
    let a = PeerEngine::start(a).await.unwrap();
    let mut b = Config::new(localhost(0), localhost(0), app.local_addr().unwrap());
    b.handshake_psk = Some([61; 32]);
    let b = PeerEngine::start(b).await.unwrap();
    a.handle().set_peer_addr(b.handle().fec_bind_addr()).await;
    b.handle().set_peer_addr(a.handle().fec_bind_addr()).await;
    timeout(Duration::from_secs(3), async {
        while a.handle().stats().handshake_established == 0
            || b.handle().stats().handshake_established == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn lost_confirmation_ack_retries_proof() {
    let app = UdpSocket::bind(localhost(0)).await.unwrap();
    let relay = UdpSocket::bind(localhost(0)).await.unwrap();
    let mut b = Config::new(localhost(0), localhost(0), app.local_addr().unwrap());
    b.handshake_psk = Some([17; 32]);
    let b = PeerEngine::start(b).await.unwrap();
    let mut a = Config::new(localhost(0), localhost(0), app.local_addr().unwrap());
    a.initial_peer_addr = Some(relay.local_addr().unwrap());
    a.handshake_psk = Some([17; 32]);
    let a = PeerEngine::start(a).await.unwrap();

    let a_addr = a.handle().fec_bind_addr();
    let b_addr = b.handle().fec_bind_addr();
    let relay_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut dropped = false;
        loop {
            let (n, src) = relay.recv_from(&mut buf).await.unwrap();
            let packet = cat4igp_libfec::decode_packet(&buf[..n]).unwrap();
            if src == b_addr && !dropped && packet.payload.first() == Some(&4) {
                dropped = true;
                continue;
            }
            relay
                .send_to(&buf[..n], if src == a_addr { b_addr } else { a_addr })
                .await
                .unwrap();
        }
    });

    timeout(Duration::from_secs(3), async {
        while a.handle().stats().handshake_established == 0
            || b.handle().stats().resume_success == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    relay_task.abort();
}

#[tokio::test]
async fn authenticated_roaming_rejects_replayed_resume() {
    let app = UdpSocket::bind(localhost(0)).await.unwrap();
    let initial = UdpSocket::bind(localhost(0)).await.unwrap();
    let replacement = UdpSocket::bind(localhost(0)).await.unwrap();
    let mut cfg = Config::new(localhost(0), localhost(0), app.local_addr().unwrap());
    cfg.handshake_psk = Some([87; 32]);
    let engine = PeerEngine::start(cfg).await.unwrap();
    let target = engine.handle().fec_bind_addr();
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let session_id = 41u64;
    let mut hello = vec![1];
    hello.extend_from_slice(&session_id.to_be_bytes());
    hello.extend_from_slice(&1u64.to_be_bytes());
    hello.extend_from_slice(public.as_bytes());

    async fn send_signed(socket: &UdpSocket, target: SocketAddr, payload: &[u8]) {
        let mut packet = payload.to_vec();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&[87; 32]).unwrap();
        mac.update(b"cat4igp-fec-control-v1");
        mac.update(&packet);
        packet.extend_from_slice(&mac.finalize().into_bytes());
        socket
            .send_to(&encode_packet(1, &packet).unwrap(), target)
            .await
            .unwrap();
    }

    send_signed(&initial, target, &hello).await;
    let mut buffer = [0u8; 2048];
    let (length, _) = timeout(Duration::from_secs(2), initial.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let ack = cat4igp_libfec::decode_packet(&buffer[..length])
        .unwrap()
        .payload;
    assert_eq!(ack[0], 2);
    let remote_id = u64::from_be_bytes(ack[1..9].try_into().unwrap());
    let remote_public: [u8; 32] = ack[17..49].try_into().unwrap();
    let shared = secret.diffie_hellman(&PublicKey::from(remote_public));
    let mut hash = Sha256::new();
    use sha2::Digest;
    hash.update(shared.as_bytes());
    hash.update(session_id.min(remote_id).to_be_bytes());
    hash.update(session_id.max(remote_id).to_be_bytes());
    let key: [u8; 32] = hash.finalize().into();
    let cipher = ChaCha20Poly1305::new((&key).into());
    async fn resume(
        socket: &UdpSocket,
        target: SocketAddr,
        session_id: u64,
        remote_id: u64,
        timestamp: u64,
        cipher: &ChaCha20Poly1305,
    ) -> Vec<u8> {
        let nonce = [timestamp as u8; 12];
        let mut plain = Vec::new();
        plain.extend_from_slice(&session_id.to_be_bytes());
        plain.extend_from_slice(&remote_id.to_be_bytes());
        plain.extend_from_slice(&timestamp.to_be_bytes());
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
            .unwrap();
        let mut packet = vec![3];
        packet.extend_from_slice(&session_id.to_be_bytes());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        packet.extend_from_slice(&ciphertext);
        send_signed(socket, target, &packet).await;
        packet
    }
    let first = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let old = resume(&initial, target, session_id, remote_id, first, &cipher).await;
    timeout(Duration::from_secs(2), async {
        while engine.handle().stats().handshake_established == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let newer = first + 1;
    resume(&replacement, target, session_id, remote_id, newer, &cipher).await;
    timeout(Duration::from_secs(2), async {
        while engine.handle().stats().resume_success == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    send_signed(&initial, target, &old).await;
    app.send_to(b"after roaming", engine.handle().local_bind_addr())
        .await
        .unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            let (n, _) = replacement.recv_from(&mut buffer).await.unwrap();
            let frame = cat4igp_libfec::decode_packet(&buffer[..n]).unwrap();
            if frame.header.flags == 0 {
                break;
            }
        }
    })
    .await
    .unwrap();
    // A negative ResumeAck is allowed; application data must not return to the old source.
    assert!(timeout(Duration::from_millis(50), async {
        loop {
            let (n, _) = initial.recv_from(&mut buffer).await.unwrap();
            if cat4igp_libfec::decode_packet(&buffer[..n])
                .unwrap()
                .header
                .flags
                == 0
            {
                break;
            }
        }
    })
    .await
    .is_err());
}
