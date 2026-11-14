use cat4igp_libfec::{Config, PeerEngine};
use std::{net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::{sleep, timeout}};

async fn socket() -> UdpSocket { UdpSocket::bind("127.0.0.1:0").await.unwrap() }

fn response(request: &[u8], mapped: SocketAddr) -> Vec<u8> {
    let mut response = request[..20].to_vec();
    response[0..2].copy_from_slice(&[1, 1]);
    response[2..4].copy_from_slice(&12u16.to_be_bytes());
    response.extend_from_slice(&[0, 0x20, 0, 8, 0, 1]);
    response.extend_from_slice(&(mapped.port() ^ 0x2112).to_be_bytes());
    let ip = match mapped.ip() { std::net::IpAddr::V4(ip) => ip.octets(), _ => unreachable!() };
    for (byte, mask) in ip.into_iter().zip([0x21, 0x12, 0xa4, 0x42]) { response.push(byte ^ mask); }
    response
}

#[tokio::test]
async fn refresh_uses_live_socket_validates_response_and_preserves_traffic() {
    let app_a = socket().await;
    let app_b = socket().await;
    let stun = socket().await;
    let attacker = socket().await;
    let a = PeerEngine::start(Config::new("127.0.0.1:0".parse().unwrap(), "127.0.0.1:0".parse().unwrap(), app_a.local_addr().unwrap())).await.unwrap();
    let b = PeerEngine::start(Config::new("127.0.0.1:0".parse().unwrap(), "127.0.0.1:0".parse().unwrap(), app_b.local_addr().unwrap())).await.unwrap();
    a.handle().set_peer_addr(b.handle().fec_bind_addr()).await;
    b.handle().set_peer_addr(a.handle().fec_bind_addr()).await;
    for _ in 0..100 {
        if a.handle().stats().handshake_established > 0 && b.handle().stats().handshake_established > 0 { break; }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(a.handle().stats().handshake_established > 0 && b.handle().stats().handshake_established > 0);
    let server = stun.local_addr().unwrap();
    let expected: SocketAddr = "203.0.113.4:43210".parse().unwrap();
    let probe = a.mapped_addr(server, Duration::from_secs(2));
    let server_task = async {
        let mut request = [0; 128];
        let (n, src) = stun.recv_from(&mut request).await.unwrap();
        assert_eq!(src, a.handle().fec_bind_addr());
        let forged = response(&request[..n], "203.0.113.99:12345".parse().unwrap());
        attacker.send_to(&forged, src).await.unwrap();
        let good = response(&request[..n], expected);
        let mut wrong = forged;
        wrong[8] ^= 1;
        stun.send_to(&wrong, src).await.unwrap();
        app_a.send_to(b"while probing", a.handle().local_bind_addr()).await.unwrap();
        let mut payload = [0; 128];
        let (n, _) = timeout(Duration::from_secs(1), app_b.recv_from(&mut payload)).await.unwrap().unwrap();
        assert_eq!(&payload[..n], b"while probing");
        stun.send_to(&good, src).await.unwrap();
    };
    let (mapped, ()) = tokio::join!(probe, server_task);
    assert_eq!(mapped.unwrap(), expected);
    assert!(a.mapped_addr(server, Duration::from_millis(20)).await.is_err());
}
