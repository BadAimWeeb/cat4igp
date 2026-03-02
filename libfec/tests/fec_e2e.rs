use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout, Duration};
use cat4igp_libfec::{Config, FecMode, PeerEngine};

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn lcg(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    *seed
}

fn random_payload(seed: &mut u64, seq: u32, max_len: usize) -> Vec<u8> {
    let body_len = (lcg(seed) as usize % max_len).max(1);
    let mut out = Vec::with_capacity(4 + body_len);
    out.extend_from_slice(&seq.to_be_bytes());
    for _ in 0..body_len {
        out.push((lcg(seed) & 0xff) as u8);
    }
    out
}

async fn wait_for_handshake_established(engine: &PeerEngine) {
    for _ in 0..100 {
        if engine.handle().stats().handshake_established > 0 {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("handshake did not establish in time");
}

async fn recv_n(socket: &UdpSocket, n: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(n);
    let mut buf = [0u8; 2048];
    for _ in 0..n {
        let (len, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
            .await
            .expect("recv timeout")
            .expect("recv failure");
        out.push(buf[..len].to_vec());
    }
    out
}

async fn run_e2e_udp_passthrough(mode: FecMode, data_shards: u8, parity_shards: u8, count: u32) {
    let app_a = UdpSocket::bind(localhost(0)).await.expect("bind app A");
    let app_b = UdpSocket::bind(localhost(0)).await.expect("bind app B");
    let app_a_addr = app_a.local_addr().expect("app A addr");
    let app_b_addr = app_b.local_addr().expect("app B addr");

    let mut cfg_a = Config::new(localhost(0), localhost(0), app_a_addr);
    cfg_a.max_payload_size = 1200;
    cfg_a.fec_mode = mode;
    cfg_a.fec_data_shards = data_shards;
    cfg_a.fec_parity_shards = parity_shards;
    cfg_a.fec_flush_timeout_ms = 25;
    cfg_a.encode_fast_send = mode == FecMode::Mode1;
    cfg_a.decode_fast_send = mode == FecMode::Mode1;

    let mut cfg_b = Config::new(localhost(0), localhost(0), app_b_addr);
    cfg_b.max_payload_size = 1200;
    cfg_b.fec_mode = mode;
    cfg_b.fec_data_shards = data_shards;
    cfg_b.fec_parity_shards = parity_shards;
    cfg_b.fec_flush_timeout_ms = 25;
    cfg_b.encode_fast_send = mode == FecMode::Mode1;
    cfg_b.decode_fast_send = mode == FecMode::Mode1;

    let peer_a = PeerEngine::start(cfg_a).await.expect("start peer A");
    let peer_b = PeerEngine::start(cfg_b).await.expect("start peer B");

    peer_a
        .handle()
        .set_peer_addr(peer_b.handle().fec_bind_addr())
        .await;
    peer_b
        .handle()
        .set_peer_addr(peer_a.handle().fec_bind_addr())
        .await;

    wait_for_handshake_established(&peer_a).await;
    wait_for_handshake_established(&peer_b).await;

    let local_a = peer_a.handle().local_bind_addr();
    let local_b = peer_b.handle().local_bind_addr();

    let mut seed_a = 0xA11CEu64;
    let mut seed_b = 0xB0Bu64;

    let mut expected_at_b = Vec::with_capacity(count as usize);
    let mut expected_at_a = Vec::with_capacity(count as usize);

    for i in 0..count {
        let payload_a = random_payload(&mut seed_a, i, 700);
        expected_at_b.push(payload_a.clone());
        app_a
            .send_to(&payload_a, local_a)
            .await
            .expect("send A->local");

        let payload_b = random_payload(&mut seed_b, i, 700);
        expected_at_a.push(payload_b.clone());
        app_b
            .send_to(&payload_b, local_b)
            .await
            .expect("send B->local");

        if i % 16 == 0 {
            sleep(Duration::from_millis(2)).await;
        }
    }

    sleep(Duration::from_millis(120)).await;

    let mut got_at_b = recv_n(&app_b, count as usize).await;
    let mut got_at_a = recv_n(&app_a, count as usize).await;

    expected_at_b.sort();
    expected_at_a.sort();
    got_at_b.sort();
    got_at_a.sort();

    assert_eq!(got_at_b, expected_at_b, "A->B UDP stack passthrough mismatch");
    assert_eq!(got_at_a, expected_at_a, "B->A UDP stack passthrough mismatch");
}

#[tokio::test]
async fn e2e_udp_stack_mode0_random_passthrough() {
    run_e2e_udp_passthrough(FecMode::Mode0, 4, 2, 80).await;
}

#[tokio::test]
async fn e2e_udp_stack_mode1_random_passthrough() {
    run_e2e_udp_passthrough(FecMode::Mode1, 4, 2, 80).await;
}
