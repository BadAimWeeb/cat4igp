use std::num::NonZeroU32;
use std::{io, net::SocketAddr};
use tokio::net::UdpSocket;

const HEADER_LEN: usize = 16;
const ETHERNET_HEADER_LEN: usize = 14;
const UDP_RECEIVE_LEN: usize = u16::MAX as usize;
const MAX_FRAME_LEN: usize = 65_507 - HEADER_LEN;

#[cfg(test)]
fn frame_limit(ip_mtu: usize, ipv6: bool) -> Option<usize> {
    let overhead = if ipv6 { 40 } else { 20 } + 8 + HEADER_LEN;
    let limit = ip_mtu.checked_sub(overhead)?.min(MAX_FRAME_LEN);
    (limit >= ETHERNET_HEADER_LEN).then_some(limit)
}

/// Encapsulates an Ethernet frame without preamble or FCS using the peer's ID and cookie.
#[cfg(test)]
fn encapsulate(peer_session: NonZeroU32, peer_cookie: [u8; 8], frame: &[u8]) -> Option<Vec<u8>> {
    if !(ETHERNET_HEADER_LEN..=MAX_FRAME_LEN).contains(&frame.len()) {
        return None;
    }
    let mut packet = Vec::with_capacity(HEADER_LEN.checked_add(frame.len())?);
    packet.extend_from_slice(&[0, 3, 0, 0]);
    packet.extend_from_slice(&peer_session.get().to_be_bytes());
    packet.extend_from_slice(&peer_cookie);
    packet.extend_from_slice(frame);
    Some(packet)
}

/// Checks the local session and cookie; neither is cryptographic authentication.
fn decapsulate(local_session: NonZeroU32, local_cookie: [u8; 8], packet: &[u8]) -> Option<&[u8]> {
    if !(HEADER_LEN + ETHERNET_HEADER_LEN..=HEADER_LEN + MAX_FRAME_LEN).contains(&packet.len())
        || packet[0] & 0x80 != 0
        || packet[1] & 0x0f != 3
        || packet[4..8] != local_session.get().to_be_bytes()
        || packet[8..16] != local_cookie
    {
        return None;
    }
    Some(&packet[HEADER_LEN..])
}
// Ethernet VLAN tags extend the frame but do not count against the interface MTU.
fn valid_frame(frame: &[u8], mtu: usize) -> bool {
    if !(ETHERNET_HEADER_LEN..=MAX_FRAME_LEN).contains(&frame.len()) { return false; }
    let mut header = ETHERNET_HEADER_LEN;
    let mut protocol = u16::from_be_bytes([frame[12], frame[13]]);
    while protocol == 0x8100 || protocol == 0x88a8 || protocol == 0x9100 {
        if frame.len() < header + 4 { return false; }
        protocol = u16::from_be_bytes([frame[header + 2], frame[header + 3]]);
        header += 4;
    }
    frame.len() - header <= mtu
}

#[cfg(test)]
async fn bind(local: SocketAddr, peer: SocketAddr) -> io::Result<UdpSocket> {
    if peer.port() == 0 || peer.ip().is_unspecified() || peer.ip().is_multicast()
        || matches!(peer.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
        || local.is_ipv4() != peer.is_ipv4()
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid L2TP peer endpoint"));
    }
    let socket = UdpSocket::bind(local).await?;
    socket.connect(peer).await?;
    Ok(socket)
}

#[cfg(test)]
async fn send(
    socket: &UdpSocket,
    peer_session: NonZeroU32,
    peer_cookie: [u8; 8],
    frame: &[u8],
    max_frame_len: usize,
) -> io::Result<()> {
    if !(ETHERNET_HEADER_LEN..=MAX_FRAME_LEN).contains(&max_frame_len)
        || frame.len() > max_frame_len
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Ethernet frame size or limit",
        ));
    }
    let packet = encapsulate(peer_session, peer_cookie, frame).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid Ethernet frame size")
    })?;
    if socket.send(&packet).await? != packet.len() {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "short UDP send"));
    }
    Ok(())
}

#[cfg(test)]
async fn receive<'a>(
    socket: &UdpSocket,
    local_session: NonZeroU32,
    local_cookie: [u8; 8],
    buffer: &'a mut [u8],
    max_frame_len: usize,
) -> io::Result<&'a [u8]> {
    if buffer.len() < UDP_RECEIVE_LEN
        || !(ETHERNET_HEADER_LEN..=MAX_FRAME_LEN).contains(&max_frame_len)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid UDP receive buffer or frame limit",
        ));
    }
    let len = socket.recv(buffer).await?;
    decapsulate(local_session, local_cookie, &buffer[..len])
        .filter(|frame| frame.len() <= max_frame_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid L2TPv3 data packet"))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::tunnel::{shared::Tunnel, TunnelType};
    use std::{ffi::CString, fs::OpenOptions, os::fd::{AsRawFd, FromRawFd, OwnedFd}, os::unix::fs::OpenOptionsExt, sync::{Arc, Mutex}};
    use tokio::{io::unix::AsyncFd, task::JoinHandle};

    /// Ethernet L2TPv3 over UDP. A WireGuard underlay must already exist and own
    /// the local address; SO_BINDTODEVICE prevents fallback to a physical route.
    pub struct L2tpTunnel {
        interface: String,
        local_node_id: i32,
        local: SocketAddr,
        peer: SocketAddr,
        local_session: NonZeroU32,
        peer_session: NonZeroU32,
        local_cookie: [u8; 8],
        peer_cookie: [u8; 8],
        mtu: u32,
        underlay: Option<String>,
        task: Option<JoinHandle<()>>,
        failure: Arc<Mutex<Option<String>>>,
    }

    impl L2tpTunnel {
        pub fn new(interface: String, local_node_id: i32, local: SocketAddr, peer: SocketAddr, local_session: NonZeroU32, peer_session: NonZeroU32, local_cookie: [u8; 8], peer_cookie: [u8; 8], mtu: u32, underlay: Option<String>) -> Self {
            Self { interface, local_node_id, local, peer, local_session, peer_session, local_cookie, peer_cookie, mtu, underlay, task: None, failure: Arc::new(Mutex::new(None)) }
        }
    }

    fn invalid(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidInput, message) }

    fn name(name: &str) -> io::Result<CString> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.contains('/') || name == "." || name == ".." {
            return Err(invalid("invalid interface name"));
        }
        CString::new(name).map_err(|_| invalid("invalid interface name"))
    }

    fn assigned(interface: &str, ip: std::net::IpAddr) -> io::Result<bool> {
        let mut addrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut addrs) } != 0 { return Err(io::Error::last_os_error()); }
        let mut cursor = addrs;
        let mut found = false;
        while !cursor.is_null() {
            let entry = unsafe { &*cursor };
            if !entry.ifa_addr.is_null() && !entry.ifa_name.is_null()
                && unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }.to_bytes() == interface.as_bytes() {
                let addr = unsafe { &*entry.ifa_addr };
                let candidate = match addr.sa_family as i32 {
                    libc::AF_INET => {
                        let a = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes())))
                    }
                    libc::AF_INET6 => {
                        let a = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
                        Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(a.sin6_addr.s6_addr)))
                    }
                    _ => None,
                };
                if candidate == Some(ip) { found = true; break; }
            }
            cursor = entry.ifa_next;
        }
        unsafe { libc::freeifaddrs(addrs) };
        Ok(found)
    }

    fn option(fd: i32, level: i32, key: i32, value: &[u8]) -> io::Result<()> {
        if unsafe { libc::setsockopt(fd, level, key, value.as_ptr().cast(), value.len() as libc::socklen_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    async fn socket(local: SocketAddr, peer: SocketAddr, underlay: Option<&str>) -> io::Result<UdpSocket> {
        if local.is_ipv4() != peer.is_ipv4() || local.port() == 0 || peer.port() == 0 || peer.ip().is_unspecified() || peer.ip().is_multicast()
            || matches!(peer.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast()) {
            return Err(invalid("invalid L2TP endpoint"));
        }
        let (mut local, mut peer) = (local, peer);
        let device = if let Some(interface) = underlay {
            let device = name(interface)?;
            let index = unsafe { libc::if_nametoindex(device.as_ptr()) };
            if index == 0 { return Err(io::Error::last_os_error()); }
            if local.ip().is_unspecified() || !assigned(interface, local.ip())? { return Err(invalid("L2TP source address is not assigned to WireGuard interface")); }
            for endpoint in [&mut local, &mut peer] {
                if let SocketAddr::V6(addr) = endpoint {
                    if addr.ip().is_unicast_link_local() {
                        if addr.scope_id() != 0 && addr.scope_id() != index { return Err(invalid("incorrect IPv6 scope")); }
                        addr.set_scope_id(index);
                    }
                }
            }
            Some(device)
        } else { None };
        let fd = unsafe { libc::socket(if local.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 }, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        if let Some(device) = device { option(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_BINDTODEVICE, device.as_bytes_with_nul())?; }
        // Permit IP fragmentation, including for jumbo Ethernet frames over WireGuard.
        let (level, key) = if local.is_ipv4() { (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER) } else { (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER) };
        option(fd.as_raw_fd(), level, key, &0i32.to_ne_bytes())?;
        let std_socket = std::net::UdpSocket::from(fd);
        // bind through a temporary sockaddr because std has no bind-on-existing-fd API.
        let result = match local {
            SocketAddr::V4(a) => {
                let addr = libc::sockaddr_in { sin_family: libc::AF_INET as _, sin_port: a.port().to_be(), sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(a.ip().octets()) }, sin_zero: [0; 8] };
                unsafe { libc::bind(std_socket.as_raw_fd(), (&addr as *const libc::sockaddr_in).cast(), std::mem::size_of_val(&addr) as _) }
            }
            SocketAddr::V6(a) => {
                let addr = libc::sockaddr_in6 { sin6_family: libc::AF_INET6 as _, sin6_port: a.port().to_be(), sin6_flowinfo: a.flowinfo(), sin6_addr: libc::in6_addr { s6_addr: a.ip().octets() }, sin6_scope_id: a.scope_id() };
                unsafe { libc::bind(std_socket.as_raw_fd(), (&addr as *const libc::sockaddr_in6).cast(), std::mem::size_of_val(&addr) as _) }
            }
        };
        if result != 0 { return Err(io::Error::last_os_error()); }
        let socket = UdpSocket::from_std(std_socket)?;
        socket.connect(peer).await?;
        Ok(socket)
    }

    fn tap(interface: &str) -> io::Result<AsyncFd<std::fs::File>> {
        let name = name(interface)?;
        let file = OpenOptions::new().read(true).write(true).custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC).open("/dev/net/tun")?;
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in request.ifr_name.iter_mut().zip(name.as_bytes()) { *dst = *src as _; }
        request.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as _;
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF as _, &mut request) } < 0 { return Err(io::Error::last_os_error()); }
        AsyncFd::new(file)
    }

    async fn read_tap(tap: &AsyncFd<std::fs::File>, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = tap.readable().await?;
            match ready.try_io(|fd| {
                let n = unsafe { libc::read(fd.get_ref().as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
                if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
            }) { Ok(result) => return result, Err(_) => continue }
        }
    }

    async fn write_tap(tap: &AsyncFd<std::fs::File>, frame: &[u8]) -> io::Result<()> {
        loop {
            let mut ready = tap.writable().await?;
            match ready.try_io(|fd| {
                let n = unsafe { libc::write(fd.get_ref().as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
                if n < 0 { Err(io::Error::last_os_error()) } else if n as usize != frame.len() { Err(io::Error::new(io::ErrorKind::WriteZero, "short TAP write")) } else { Ok(()) }
            }) { Ok(result) => return result, Err(_) => continue }
        }
    }

    async fn forward(tap: AsyncFd<std::fs::File>, socket: UdpSocket, local_session: NonZeroU32, peer_session: NonZeroU32, local_cookie: [u8; 8], peer_cookie: [u8; 8], mtu: usize) -> io::Result<()> {
        let mut outbound = vec![0u8; HEADER_LEN + MAX_FRAME_LEN + 1];
        outbound[..4].copy_from_slice(&[0, 3, 0, 0]);
        outbound[4..8].copy_from_slice(&peer_session.get().to_be_bytes());
        outbound[8..16].copy_from_slice(&peer_cookie);
        let mut inbound = vec![0u8; UDP_RECEIVE_LEN];
        loop {
            tokio::select! {
                n = read_tap(&tap, &mut outbound[HEADER_LEN..]) => {
                    let n = n?;
                    if n == 0 { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TAP closed")); }
                    if !valid_frame(&outbound[HEADER_LEN..HEADER_LEN + n], mtu) { continue; }
                    match socket.send(&outbound[..HEADER_LEN + n]).await {
                        Ok(sent) if sent == HEADER_LEN + n => {},
                        Ok(_) => return Err(io::Error::new(io::ErrorKind::WriteZero, "short UDP send")),
                        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => continue,
                        Err(error) => return Err(error),
                    }
                }
                n = socket.recv(&mut inbound) => {
                    let n = match n {
                        Ok(n) => n,
                        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => continue,
                        Err(error) => return Err(error),
                    };
                    if let Some(frame) = decapsulate(local_session, local_cookie, &inbound[..n]).filter(|f| valid_frame(f, mtu)) { write_tap(&tap, frame).await?; }
                }
            }
        }
    }

    impl Tunnel for L2tpTunnel {
        async fn setup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            if self.task.as_ref().is_some_and(|task| !task.is_finished()) { return Ok(()); }
            if let Some(task) = self.task.take() { let _ = task.await; }
            *self.failure.lock().unwrap() = None;
            if self.mtu < 68 || self.mtu as usize + ETHERNET_HEADER_LEN > MAX_FRAME_LEN { return Err(invalid("invalid L2TP MTU").into()); }
            let socket = socket(self.local, self.peer, self.underlay.as_deref()).await?;
            let tap = tap(&self.interface)?;
            let mut seed = self.interface.as_bytes().to_vec();
            seed.extend_from_slice(&self.local_node_id.to_be_bytes());
            let address = crate::interface::generate_ipv6_lla_from_seed(seed);
            crate::interface::add_addr(self.interface.clone(), address.into()).await?;
            crate::interface::link_up_with_mtu(self.interface.clone(), self.mtu).await?;
            *self.failure.lock().unwrap() = None;
            let failure = self.failure.clone();
            let (local_session, peer_session, local_cookie, peer_cookie, mtu) = (self.local_session, self.peer_session, self.local_cookie, self.peer_cookie, self.mtu as usize);
            self.task = Some(tokio::spawn(async move {
                if let Err(error) = forward(tap, socket, local_session, peer_session, local_cookie, peer_cookie, mtu).await { *failure.lock().unwrap() = Some(error.to_string()); }
            }));
            Ok(())
        }
        async fn destroy(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            if let Some(task) = self.task.take() { task.abort(); let _ = task.await; }
            *self.failure.lock().unwrap() = None;
            Ok(())
        }
        fn get_interface_name(&self) -> &str { &self.interface }
        fn get_type(&self) -> TunnelType { TunnelType::L2tp }
        async fn get_mtu(&self) -> Result<u32, Box<dyn std::error::Error>> { crate::interface::get_mtu(self.interface.clone()).await }
        fn is_ift_created(&self) -> bool { self.task.as_ref().is_some_and(|task| !task.is_finished()) }
        fn is_connected(&self) -> Result<bool, Box<dyn std::error::Error>> {
            if let Some(error) = self.failure.lock().unwrap().as_ref() { return Err(io::Error::other(error.clone()).into()); }
            Ok(self.is_ift_created())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn underlay_requires_assigned_source_and_existing_device() {
            let peer = "127.0.0.1:1701".parse().unwrap();
            let wildcard = "0.0.0.0:1701".parse().unwrap();
            assert_eq!(socket(wildcard, peer, Some("lo")).await.unwrap_err().kind(), io::ErrorKind::InvalidInput);
            let unassigned = "192.0.2.1:1701".parse().unwrap();
            assert_eq!(socket(unassigned, peer, Some("lo")).await.unwrap_err().kind(), io::ErrorKind::InvalidInput);
            assert!(socket(unassigned, peer, Some("no-such-device")).await.is_err());
        }
    }

    impl Drop for L2tpTunnel {
        fn drop(&mut self) { if let Some(task) = self.task.take() { task.abort(); } }
    }
}

#[cfg(target_os = "linux")]
pub use linux::L2tpTunnel;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_mtu_excludes_vlan_tags() {
        let mtu = 1500;
        let mut frame = vec![0; ETHERNET_HEADER_LEN + mtu];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        assert!(valid_frame(&frame, mtu));
        frame.push(0);
        assert!(!valid_frame(&frame, mtu));
        frame.pop();
        frame.splice(12..12, [0x88, 0xa8, 0, 1, 0x81, 0x00, 0, 2]);
        assert!(valid_frame(&frame, mtu));
        frame.push(0);
        assert!(!valid_frame(&frame, mtu));
        assert!(!valid_frame(&[0; ETHERNET_HEADER_LEN - 1], mtu));
        let mut truncated_tag = [0; ETHERNET_HEADER_LEN];
        truncated_tag[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        assert!(!valid_frame(&truncated_tag, mtu));
        assert!(!valid_frame(&vec![0; MAX_FRAME_LEN + 1], usize::MAX));
    }

    #[tokio::test]
    async fn rejects_invalid_peer_endpoints() {
        let local = "127.0.0.1:0".parse().unwrap();
        for peer in ["0.0.0.0:1701", "127.0.0.1:0", "224.0.0.1:1701", "255.255.255.255:1701", "[::1]:1701"] {
            assert_eq!(bind(local, peer.parse().unwrap()).await.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
        let local = "[::1]:0".parse().unwrap();
        for peer in ["[::]:1701", "[ff02::1]:1701", "[::1]:0"] {
            assert_eq!(bind(local, peer.parse().unwrap()).await.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn frame_limit_accounts_for_outer_headers() {
        assert_eq!(frame_limit(1500, false), Some(1456));
        assert_eq!(frame_limit(1500, true), Some(1436));
        for (ipv6, overhead) in [(false, 44), (true, 64)] {
            assert_eq!(frame_limit(overhead + ETHERNET_HEADER_LEN - 1, ipv6), None);
            assert_eq!(frame_limit(overhead + ETHERNET_HEADER_LEN, ipv6), Some(ETHERNET_HEADER_LEN));
            assert_eq!(frame_limit(usize::MAX, ipv6), Some(MAX_FRAME_LEN));
            assert_eq!(frame_limit(0, ipv6), None);
        }
    }

    #[test]
    fn udp_ethernet_packet_profile() {
        let session = NonZeroU32::new(0x12345678).unwrap();
        let cookie = [1, 2, 3, 4, 5, 6, 7, 8];
        let frame = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x81, 0, 0, 1, 8, 0];
        let packet = encapsulate(session, cookie, &frame).unwrap();
        assert_eq!(
            packet,
            [
                0, 3, 0, 0, 0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 2, 3, 4, 5, 6, 7,
                8, 9, 10, 11, 0x81, 0, 0, 1, 8, 0,
            ]
        );
        assert_eq!(
            decapsulate(session, cookie, &packet),
            Some(frame.as_slice())
        );
        for length in 0..HEADER_LEN + ETHERNET_HEADER_LEN {
            assert_eq!(decapsulate(session, cookie, &packet[..length]), None);
        }
        assert!(encapsulate(session, cookie, &frame[..13]).is_none());
        assert!(encapsulate(session, cookie, &vec![0; MAX_FRAME_LEN + 1]).is_none());
        let largest = encapsulate(session, cookie, &vec![0; MAX_FRAME_LEN]).unwrap();
        assert_eq!(decapsulate(session, cookie, &largest).unwrap().len(), MAX_FRAME_LEN);
        let mut oversized = largest;
        oversized.push(0);
        assert!(decapsulate(session, cookie, &oversized).is_none());
        assert!(decapsulate(NonZeroU32::new(1).unwrap(), cookie, &packet).is_none());
        assert!(decapsulate(session, [0; 8], &packet).is_none());
        let mut altered = packet.clone();
        altered[0] = 0x80;
        assert!(decapsulate(session, cookie, &altered).is_none());
        altered[0] = 0x7f;
        altered[1] = 0xf3;
        altered[2..4].copy_from_slice(&[0xff, 0xff]);
        assert_eq!(
            decapsulate(session, cookie, &altered),
            Some(frame.as_slice())
        );
        altered[1] = 2;
        assert!(decapsulate(session, cookie, &altered).is_none());
    }

    #[tokio::test]
    async fn udp_exchange_rejects_invalid_packets_and_releases_sockets() {
        let local = "127.0.0.1:0".parse().unwrap();
        let a = UdpSocket::bind(local).await.unwrap();
        let b = bind(local, a.local_addr().unwrap()).await.unwrap();
        a.connect(b.local_addr().unwrap()).await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();
        let a_id = NonZeroU32::new(1).unwrap();
        let b_id = NonZeroU32::new(2).unwrap();
        let a_cookie = [1; 8];
        let b_cookie = [2; 8];
        let frame = [0x42; ETHERNET_HEADER_LEN];
        let mut buffer = vec![0; UDP_RECEIVE_LEN];

        send(&a, b_id, b_cookie, &frame, frame.len()).await.unwrap();
        assert_eq!(
            receive(&b, b_id, b_cookie, &mut buffer, frame.len())
                .await
                .unwrap(),
            frame
        );
        send(&b, a_id, a_cookie, &frame, frame.len()).await.unwrap();
        assert_eq!(
            receive(&a, a_id, a_cookie, &mut buffer, frame.len())
                .await
                .unwrap(),
            frame
        );
        send(&a, a_id, a_cookie, &frame, frame.len()).await.unwrap();
        assert_eq!(
            receive(&b, b_id, b_cookie, &mut buffer, frame.len())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            send(&a, b_id, b_cookie, &frame[..13], frame.len())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            receive(&a, a_id, a_cookie, &mut buffer[..100], frame.len())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let oversized = [0; ETHERNET_HEADER_LEN + 1];
        assert_eq!(
            send(&a, b_id, b_cookie, &oversized, frame.len())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        send(&a, b_id, b_cookie, &oversized, oversized.len())
            .await
            .unwrap();
        assert_eq!(
            receive(&b, b_id, b_cookie, &mut buffer, frame.len())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        for limit in [ETHERNET_HEADER_LEN - 1, MAX_FRAME_LEN + 1] {
            assert_eq!(
                send(&a, b_id, b_cookie, &frame, limit)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                receive(&b, b_id, b_cookie, &mut buffer, limit)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }

        drop((a, b));
        UdpSocket::bind(a_addr).await.unwrap();
        UdpSocket::bind(b_addr).await.unwrap();
    }
}
