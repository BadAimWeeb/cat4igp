use super::*;
use tokio::time::timeout;

#[tokio::test]
async fn forwards_only_pinned_peer_and_stun_uses_transport_socket() {
    let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let reserve = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = reserve.local_addr().unwrap().port();
    drop(reserve);
    let mut proxy = UdpProxy::start(port, false, Some(peer.local_addr().unwrap()), wg.local_addr().unwrap()).await.unwrap();
    let public = SocketAddr::from(([127, 0, 0, 1], port));
    wg.send_to(b"out", proxy.local_addr()).await.unwrap();
    let mut buf = [0u8; 1024];
    let (n, source) = peer.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"out");
    assert_eq!(source, public);
    attacker.send_to(b"bad", public).await.unwrap();
    peer.send_to(b"in", public).await.unwrap();
    let (n, _) = timeout(Duration::from_secs(1), wg.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"in");
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let reply = tokio::spawn(async move {
        let mut req = [0u8; 128];
        let (n, source) = server.recv_from(&mut req).await.unwrap();
        assert_eq!(n, 20);
        assert_eq!(source, public);
        let mut response = Vec::from(&req[..20]);
        response[..2].copy_from_slice(&[1, 1]);
        response[2..4].copy_from_slice(&12u16.to_be_bytes());
        response.extend_from_slice(&[0, 1, 0, 8, 0, 1, 0x12, 0x34, 192, 0, 2, 1]);
        server.send_to(&response, source).await.unwrap();
    });
    assert_eq!(proxy.mapped_addr(server_addr, Duration::from_secs(1)).await.unwrap(), "192.0.2.1:4660".parse().unwrap());
    reply.await.unwrap();
    proxy.set_peer(None).await.unwrap();
    proxy.stop().await.unwrap();
    assert!(!proxy.is_running());
}

#[test]
fn parses_ipv6_xor_mapping_and_rejects_malformed() {
    let mut packet = vec![1, 1, 0, 24, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    packet.extend_from_slice(&[0, 0x20, 0, 20, 0, 2, 0x21, 0x62]);
    let address: Ipv6Addr = "2001:db8::1".parse().unwrap();
    for (b, mask) in address.octets().iter().zip(packet[4..20].to_vec()) { packet.push(b ^ mask); }
    assert_eq!(parse_stun(&packet), Some(SocketAddr::new(IpAddr::V6(address), 112)));
    packet.pop();
    assert_eq!(parse_stun(&packet), None);
}

#[test]
fn datagram_errors_are_discarded_but_fatal_errors_propagate() {
    for code in [libc::EMSGSIZE, libc::ECONNREFUSED, libc::ECONNRESET] {
        assert!(discard_datagram_error::<()>(Err(io::Error::from_raw_os_error(code))).unwrap().is_none());
    }
    assert_eq!(discard_datagram_error::<()>(Err(io::Error::from_raw_os_error(libc::EBADF))).unwrap_err().raw_os_error(), Some(libc::EBADF));
}

#[tokio::test]
async fn unreachable_peer_does_not_stop_proxy() {
    let wg = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let reserve = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = reserve.local_addr().unwrap().port();
    drop(reserve);
    let mut proxy = UdpProxy::start(port, false, Some(peer.local_addr().unwrap()), wg.local_addr().unwrap()).await.unwrap();
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    proxy.set_peer(Some(dead_addr)).await.unwrap();
    wg.send_to(b"unreachable", proxy.local_addr()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    proxy.set_peer(Some(peer.local_addr().unwrap())).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    wg.send_to(b"still alive", proxy.local_addr()).await.unwrap();
    let mut buf = [0; 64];
    let (len, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..len], b"still alive");
    assert!(proxy.is_running());
    proxy.stop().await.unwrap();
}
