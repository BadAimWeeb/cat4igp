use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use cat4igp_libfec::{Config, FecMode, PeerEngine};

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

    let peer1 = PeerEngine::start(peer1_cfg)
    .await
    .expect("start peer1");

    let mut peer2_cfg = Config::new(localhost(0), localhost(0), app_peer2_addr);
    peer2_cfg.fec_mode = FecMode::Mode0;
    peer2_cfg.fec_data_shards = 1;
    peer2_cfg.fec_parity_shards = 0;
    peer2_cfg.fec_flush_timeout_ms = 20;
    peer2_cfg.encode_fast_send = false;
    peer2_cfg.decode_fast_send = false;

    let peer2 = PeerEngine::start(peer2_cfg)
    .await
    .expect("start peer2");

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

    for _ in 0..100 {
        if handle.stats().handshake_established > 0 && peer1.handle().stats().handshake_established > 0 {
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
        if handle.stats().handshake_established > 1 && peer2.handle().stats().handshake_established > 0 {
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
