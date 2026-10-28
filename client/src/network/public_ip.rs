use rand::prelude::*;
use rand::seq::SliceRandom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::os::unix::io::AsRawFd;
use std::time::Duration;
use tokio::net::UdpSocket;

const IPV4_STUN_LIST_URL: &str =
    "https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_ipv4s.txt";
const IPV6_STUN_LIST_URL: &str =
    "https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_ipv6s.txt";
const IPV4_NAT_TESTING_LIST_URL: &str = "https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_nat_testing_ipv4s.txt";
const IPV6_NAT_TESTING_LIST_URL: &str = "https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_nat_testing_ipv6s.txt";

/// NAT type as determined by RFC 5780 STUN NAT Behavior Discovery
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatType {
    /// Open Internet - no NAT detected
    OpenInternet,

    /// Endpoint-Independent Mapping + Endpoint-Independent Filtering (Full Cone NAT)
    EndpointIndependentNoFiltering,

    /// Endpoint-Independent Mapping + Address-Dependent Filtering (Restricted Cone NAT)
    EndpointIndependentAddressFiltering,

    /// Endpoint-Independent Mapping + Address and Port-Dependent Filtering (Port Restricted Cone NAT)
    EndpointIndependentAddressPortFiltering,

    /// Address-Dependent Mapping
    AddressDependentMapping,

    /// Address and Port-Dependent Mapping (Symmetric NAT)
    AddressPortDependentMapping,

    /// No UDP connectivity
    NoUdpConnectivity,

    /// NAT type could not be determined
    Unknown,
}

/// A STUN server with separate IPv4 and IPv6 addresses
#[derive(Debug, Clone)]
struct StunServer {
    port: u16,
    ipv4_addrs: Vec<Ipv4Addr>,
    ipv6_addrs: Vec<Ipv6Addr>,
}

/// Public IP detection
pub struct PublicIpDetector {
    /// IPv4 STUN servers
    ipv4_servers: Vec<StunServer>,
    /// IPv6 STUN servers
    ipv6_servers: Vec<StunServer>,
    /// IPv4 NAT testing STUN servers (RFC 5780 capable)
    ipv4_nat_servers: Vec<StunServer>,
    /// IPv6 NAT testing STUN servers (RFC 5780 capable)
    ipv6_nat_servers: Vec<StunServer>,
    /// Timeout for STUN queries
    timeout: Duration,
}

impl Default for PublicIpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PublicIpDetector {
    /// Create a new public IP detector with STUN servers from remote URLs
    pub fn new() -> Self {
        Self {
            ipv4_servers: Vec::new(),
            ipv6_servers: Vec::new(),
            ipv4_nat_servers: Vec::new(),
            ipv6_nat_servers: Vec::new(),
            timeout: Duration::from_secs(5),
        }
    }

    /// Initialize the detector by fetching STUN server lists (should be called before use)
    pub async fn init(&mut self) -> Result<(), String> {
        self.ipv4_servers = Self::fetch_ipv4_servers().await?;
        self.ipv6_servers = Self::fetch_ipv6_servers().await?;
        self.ipv4_nat_servers = Self::fetch_ipv4_nat_servers().await?;
        self.ipv6_nat_servers = Self::fetch_ipv6_nat_servers().await?;
        Ok(())
    }

    /// Set the timeout for STUN queries
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Fetch IPv4 STUN servers from the remote list
    async fn fetch_ipv4_servers() -> Result<Vec<StunServer>, String> {
        Self::fetch_servers_from_list(IPV4_STUN_LIST_URL, true).await
    }

    /// Fetch IPv6 STUN servers from the remote list
    async fn fetch_ipv6_servers() -> Result<Vec<StunServer>, String> {
        Self::fetch_servers_from_list(IPV6_STUN_LIST_URL, false).await
    }

    /// Fetch IPv4 NAT testing STUN servers from the remote list
    async fn fetch_ipv4_nat_servers() -> Result<Vec<StunServer>, String> {
        Self::fetch_servers_from_list(IPV4_NAT_TESTING_LIST_URL, true).await
    }

    /// Fetch IPv6 NAT testing STUN servers from the remote list
    async fn fetch_ipv6_nat_servers() -> Result<Vec<StunServer>, String> {
        Self::fetch_servers_from_list(IPV6_NAT_TESTING_LIST_URL, false).await
    }

    /// Fetch STUN servers from a list URL
    async fn fetch_servers_from_list(url: &str, is_ipv4: bool) -> Result<Vec<StunServer>, String> {
        let client = reqwest::Client::new();
        let response = client
            .get(url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("Failed to fetch STUN list: {}", e))?;

        let text = response
            .text()
            .await
            .map_err(|e| format!("Failed to read STUN list: {}", e))?;

        let mut servers = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse "hostname:port" or "[ipv6]:port" format
            let (hostname, port) = Self::parse_stun_server_line(line)?;

            // Resolve hostname to addresses
            let (ipv4_addrs, ipv6_addrs) = Self::resolve_hostname(&hostname).await;

            if is_ipv4 && !ipv4_addrs.is_empty() {
                servers.push(StunServer {
                    port,
                    ipv4_addrs,
                    ipv6_addrs: Vec::new(),
                });
            } else if !is_ipv4 && !ipv6_addrs.is_empty() {
                servers.push(StunServer {
                    port,
                    ipv4_addrs: Vec::new(),
                    ipv6_addrs,
                });
            }
        }

        Ok(servers)
    }

    /// Parse a STUN server line in format "hostname:port" or "[ipv6]:port"
    fn parse_stun_server_line(line: &str) -> Result<(String, u16), String> {
        if line.starts_with('[') {
            // IPv6 format: [address]:port
            if let Some(bracket_end) = line.rfind(']') {
                let address = &line[1..bracket_end];
                if line.len() > bracket_end + 1 && line.chars().nth(bracket_end + 1) == Some(':') {
                    if let Ok(port) = line[bracket_end + 2..].parse::<u16>() {
                        return Ok((address.to_string(), port));
                    }
                }
            }
            Err("Invalid IPv6 format".to_string())
        } else {
            // IPv4 format: hostname:port
            if let Some(colon_pos) = line.rfind(':') {
                let hostname = &line[..colon_pos];
                if let Ok(port) = line[colon_pos + 1..].parse::<u16>() {
                    return Ok((hostname.to_string(), port));
                }
            }
            Err("Invalid hostname format".to_string())
        }
    }

    /// Resolve a hostname to IPv4 and IPv6 addresses
    async fn resolve_hostname(hostname: &str) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
        let mut ipv4_addrs = Vec::new();
        let mut ipv6_addrs = Vec::new();

        let addr_str = format!("{}:3478", hostname);
        match addr_str.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    match addr.ip() {
                        IpAddr::V4(ip) => {
                            if !ipv4_addrs.contains(&ip) {
                                ipv4_addrs.push(ip);
                            }
                        }
                        IpAddr::V6(ip) => {
                            if !ipv6_addrs.contains(&ip) {
                                ipv6_addrs.push(ip);
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // Hostname resolution failed, skip this server
            }
        }

        (ipv4_addrs, ipv6_addrs)
    }

    /// Detect public IPv4 address using STUN
    pub async fn detect_public_ipv4(&self) -> Result<IpAddr, String> {
        if self.ipv4_servers.is_empty() {
            return Err("No IPv4 STUN servers available - call init() first".to_string());
        }

        // Randomize server order
        let mut rng = rand::rng();
        let mut servers = self.ipv4_servers.clone();
        servers.shuffle(&mut rng);

        for server in &servers {
            for ip in &server.ipv4_addrs {
                let addr = format!("{}:{}", ip, server.port);
                match self.query_stun_ipv4(&addr).await {
                    Ok(public_ip) => return Ok(public_ip),
                    Err(_) => continue,
                }
            }
        }

        Err("Failed to detect public IPv4 address from any STUN server".to_string())
    }

    /// Detect public IPv6 address using STUN
    pub async fn detect_public_ipv6(&self) -> Result<IpAddr, String> {
        if self.ipv6_servers.is_empty() {
            return Err("No IPv6 STUN servers available - call init() first".to_string());
        }

        // Randomize server order
        let mut rng = rand::rng();
        let mut servers = self.ipv6_servers.clone();
        servers.shuffle(&mut rng);

        for server in &servers {
            for ip in &server.ipv6_addrs {
                let addr = format!("[{}]:{}", ip, server.port);
                match self.query_stun_ipv6(&addr).await {
                    Ok(public_ip) => return Ok(public_ip),
                    Err(_) => continue,
                }
            }
        }

        Err("Failed to detect public IPv6 address from any STUN server".to_string())
    }

    /// Discover the mapped address from the UDP port intended for the tunnel.
    pub async fn mapped_addr_from_port(
        &self,
        port: u16,
        ipv6: bool,
    ) -> Result<std::net::SocketAddr, String> {
        let socket = UdpSocket::bind(if ipv6 {
            format!("[::]:{port}")
        } else {
            format!("0.0.0.0:{port}")
        })
        .await
        .map_err(|error| format!("failed to bind UDP port {port}: {error}"))?;
        let mut servers = if ipv6 {
            self.ipv6_servers.clone()
        } else {
            self.ipv4_servers.clone()
        };
        servers.shuffle(&mut rand::rng());
        for server in servers {
            let addresses: Vec<IpAddr> = if ipv6 {
                server.ipv6_addrs.into_iter().map(IpAddr::V6).collect()
            } else {
                server.ipv4_addrs.into_iter().map(IpAddr::V4).collect()
            };
            for ip in addresses {
                let server = std::net::SocketAddr::new(ip, server.port);
                socket
                    .send_to(&self.create_stun_binding_request(), server)
                    .await
                    .map_err(|error| format!("failed to send STUN request: {error}"))?;
                let mut response = [0; 512];
                if let Ok(Ok((length, _))) =
                    tokio::time::timeout(self.timeout, socket.recv_from(&mut response)).await
                {
                    if let Ok(mapped) = self.parse_mapped_socket_addr(&response[..length]) {
                        if mapped.is_ipv6() == ipv6 {
                            return Ok(mapped);
                        }
                    }
                }
            }
        }
        Err("no STUN server returned a mapped address".to_string())
    }

    /// Detect NAT type for IPv4 using 2 STUN servers
    /// Detect NAT type for IPv4 using RFC 5780
    pub async fn detect_nat_type_ipv4(&self) -> Result<NatType, String> {
        if self.ipv4_nat_servers.is_empty() {
            return Err("No IPv4 NAT testing servers available - call init() first".to_string());
        }

        // Pick a random NAT testing server
        let mut rng = rand::rng();
        let server = self
            .ipv4_nat_servers
            .choose(&mut rng)
            .ok_or("No NAT testing servers available")?;

        let server_ip = server
            .ipv4_addrs
            .first()
            .ok_or("NAT testing server has no IPv4 addresses")?;
        let server_addr = format!("{}:{}", server_ip, server.port);

        self.detect_nat_type_rfc5780(&server_addr, true).await
    }

    /// Detect NAT type for IPv6 using RFC 5780
    pub async fn detect_nat_type_ipv6(&self) -> Result<NatType, String> {
        if self.ipv6_nat_servers.is_empty() {
            return Err("No IPv6 NAT testing servers available - call init() first".to_string());
        }

        // Pick a random NAT testing server
        let mut rng = rand::rng();
        let server = self
            .ipv6_nat_servers
            .choose(&mut rng)
            .ok_or("No NAT testing servers available")?;

        let server_ip = server
            .ipv6_addrs
            .first()
            .ok_or("NAT testing server has no IPv6 addresses")?;
        let server_addr = format!("[{}]:{}", server_ip, server.port);

        self.detect_nat_type_rfc5780(&server_addr, false).await
    }

    /// Detect NAT type using RFC 5780 section 4 algorithm
    async fn detect_nat_type_rfc5780(
        &self,
        server_addr: &str,
        is_ipv4: bool,
    ) -> Result<NatType, String> {
        // RFC 5780 Section 4: NAT Behavior Discovery
        // IMPORTANT: All tests must share the same socket to preserve source port

        // Create shared socket for all tests
        let bind_addr = if is_ipv4 { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind socket: {}", e))?;

        // Enable IP_PKTINFO/IPV6_RECVPKTINFO for recv_sas to work
        let raw_fd = socket.as_raw_fd();
        udp_sas::set_pktinfo(raw_fd).map_err(|e| format!("Failed to enable pktinfo: {}", e))?;

        // Test I: Basic binding request to get mapped address and actual interface IP
        let test1_result = self.stun_test_basic(&socket, server_addr).await;

        let (test1_mapped_addr, local_interface_ip) = match test1_result {
            Ok((mapped, iface_ip)) => (mapped, iface_ip),
            Err(e) => {
                // No UDP connectivity or recv_sas failed
                eprintln!("Test I failed: {}", e);
                return Ok(NatType::NoUdpConnectivity);
            }
        };

        // Check if we're behind NAT by comparing with actual interface IP
        if test1_mapped_addr.ip() == local_interface_ip {
            // No NAT - Open Internet
            return Ok(NatType::OpenInternet);
        }

        // Test II: Request with CHANGE-REQUEST to test filtering
        // Try to get response from alternate IP and port
        let test2_response = self
            .stun_test_change_request(&socket, server_addr, true, true)
            .await;

        // Test III: Request from same server but different port (if Test II failed)
        let test3_response = if test2_response.is_err() {
            self.stun_test_change_request(&socket, server_addr, false, true)
                .await
        } else {
            Ok(()) // Test II passed, skip Test III
        };

        // Test IV: Binding request to alternate server to check mapping behavior
        // We need another server for this - use regular STUN servers as fallback
        let mapping_behavior = if !self.ipv4_servers.is_empty() && is_ipv4 {
            let mut rng = rand::rng();
            let alt_server = self.ipv4_servers.choose(&mut rng).unwrap();
            let alt_ip = alt_server.ipv4_addrs.first().unwrap();
            let alt_addr = format!("{}:{}", alt_ip, alt_server.port);

            match self.stun_test_basic(&socket, &alt_addr).await {
                Ok((alt_mapped, _)) => {
                    // Compare mapped addresses
                    if alt_mapped == test1_mapped_addr {
                        "endpoint-independent"
                    } else if alt_mapped.ip() == test1_mapped_addr.ip() {
                        "address-dependent"
                    } else {
                        "address-port-dependent"
                    }
                }
                Err(s) => {
                    eprintln!("Failed Test IV on alternate server {}: {}", alt_addr, s);
                    "unknown"
                }
            }
        } else if !self.ipv6_servers.is_empty() && !is_ipv4 {
            let mut rng = rand::rng();
            let alt_server = self.ipv6_servers.choose(&mut rng).unwrap();
            let alt_ip = alt_server.ipv6_addrs.first().unwrap();
            let alt_addr = format!("[{}]:{}", alt_ip, alt_server.port);

            match self.stun_test_basic(&socket, &alt_addr).await {
                Ok((alt_mapped, _)) => {
                    // Compare mapped addresses
                    if alt_mapped == test1_mapped_addr {
                        "endpoint-independent"
                    } else if alt_mapped.ip() == test1_mapped_addr.ip() {
                        "address-dependent"
                    } else {
                        "address-port-dependent"
                    }
                }
                Err(_) => "unknown",
            }
        } else {
            "unknown"
        };

        // Determine NAT type based on test results
        match mapping_behavior {
            "endpoint-independent" => {
                // Endpoint-Independent Mapping
                if test2_response.is_ok() {
                    // No filtering
                    Ok(NatType::EndpointIndependentNoFiltering)
                } else if test3_response.is_ok() {
                    // Address-dependent filtering
                    Ok(NatType::EndpointIndependentAddressFiltering)
                } else {
                    // Address and port-dependent filtering
                    Ok(NatType::EndpointIndependentAddressPortFiltering)
                }
            }
            "address-dependent" => Ok(NatType::AddressDependentMapping),
            "address-port-dependent" => Ok(NatType::AddressPortDependentMapping),
            _ => Ok(NatType::Unknown),
        }
    }

    /// Test I: Basic STUN binding request (using shared socket)
    async fn stun_test_basic(
        &self,
        socket: &UdpSocket,
        server_addr: &str,
    ) -> Result<(std::net::SocketAddr, IpAddr), String> {
        use std::os::unix::io::AsRawFd;

        // Send basic STUN binding request
        let request = self.create_stun_binding_request();
        socket
            .send_to(&request, server_addr)
            .await
            .map_err(|e| format!("Failed to send STUN request: {}", e))?;

        // Receive response with actual interface IP using recv_sas
        let raw_fd = socket.as_raw_fd();
        let timeout = self.timeout;

        // Use recv_sas in a blocking task with proper fd handling
        let (n, _peer_addr, local_interface_ip, response) =
            tokio::task::spawn_blocking(move || {
                // Create a temporary socket wrapper just for mode setting
                // We won't use from_raw_fd to avoid ownership issues

                // Set non-blocking to false using fcntl directly
                let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL) };
                if flags < 0 {
                    return Err("Failed to get socket flags".to_string());
                }

                let new_flags = flags & !libc::O_NONBLOCK;
                if unsafe { libc::fcntl(raw_fd, libc::F_SETFL, new_flags) } < 0 {
                    return Err("Failed to set socket to blocking mode".to_string());
                }

                // Set read timeout
                let tv = libc::timeval {
                    tv_sec: timeout.as_secs() as libc::time_t,
                    tv_usec: timeout.subsec_micros() as libc::suseconds_t,
                };

                if unsafe {
                    libc::setsockopt(
                        raw_fd,
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        &tv as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                    )
                } < 0
                {
                    return Err("Failed to set socket timeout".to_string());
                }

                let mut buf = vec![0; 512];
                let result = udp_sas::recv_sas(raw_fd, &mut buf)
                    .map_err(|e| format!("recv_sas error: {}", e))?;

                // Set back to non-blocking
                let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL) };
                if flags >= 0 {
                    unsafe { libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
                }

                Ok::<_, String>((result.0, result.1, result.2, buf))
            })
            .await
            .map_err(|e| format!("Task error: {}", e))??;

        // Extract the local interface IP
        let local_ip = local_interface_ip.ok_or("Local interface IP not available".to_string())?;

        // Extract mapped address from STUN response
        let mapped_addr = self.parse_mapped_socket_addr(&response[..n])?;

        Ok((mapped_addr, local_ip))
    }

    /// Test with CHANGE-REQUEST attribute (RFC 5780) using shared socket
    async fn stun_test_change_request(
        &self,
        socket: &UdpSocket,
        server_addr: &str,
        change_ip: bool,
        change_port: bool,
    ) -> Result<(), String> {
        // Create STUN binding request with CHANGE-REQUEST attribute
        let request = self.create_stun_change_request(change_ip, change_port);
        socket
            .send_to(&request, server_addr)
            .await
            .map_err(|e| format!("Failed to send STUN change request: {}", e))?;

        // Try to receive response - if we get one, the test passed
        let mut response = vec![0; 512];
        tokio::time::timeout(self.timeout, socket.recv_from(&mut response))
            .await
            .map_err(|_| "STUN change request timeout (expected for filtered NAT)".to_string())?
            .map_err(|e| format!("Failed to receive response: {}", e))?;

        Ok(())
    }

    /// Create STUN binding request with CHANGE-REQUEST attribute
    fn create_stun_change_request(&self, change_ip: bool, change_port: bool) -> Vec<u8> {
        let mut request = vec![0x00, 0x01]; // Message type: Binding Request

        // Message length will be updated after adding attributes
        request.extend_from_slice(&[0x00, 0x08]); // Length: 8 bytes (one attribute)
        request.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]); // Magic cookie
        request.extend_from_slice(&[0x00; 12]); // Transaction ID

        // CHANGE-REQUEST attribute (0x0003)
        request.extend_from_slice(&[0x00, 0x03]); // Attribute type
        request.extend_from_slice(&[0x00, 0x04]); // Attribute length: 4 bytes

        // Flag bits: bit 1 = change IP, bit 2 = change port
        let flags: u32 = ((change_ip as u32) << 1) | ((change_port as u32) << 2);
        request.extend_from_slice(&flags.to_be_bytes());

        request
    }

    /// Parse mapped socket address from STUN response
    fn parse_mapped_socket_addr(&self, response: &[u8]) -> Result<std::net::SocketAddr, String> {
        if response.len() < 20 {
            return Err("STUN response too short".to_string());
        }

        if response[..2] != [0x01, 0x01] || response[4..8] != [0x21, 0x12, 0xa4, 0x42] {
            return Err("Invalid STUN binding response header".to_string());
        }

        let response_len = u16::from_be_bytes([response[2], response[3]]) as usize;
        if response_len % 4 != 0 || response.len() != 20 + response_len {
            return Err("Invalid STUN response length".to_string());
        }

        // ponytail: wire-format validation only; correlate replies with requests at receive sites.
        // Parse attributes
        let mut offset = 20;
        while offset + 4 <= response.len() {
            let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let attr_len =
                u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
            let attr_data_offset = offset + 4;
            let padded_end = attr_data_offset + attr_len.next_multiple_of(4);
            if padded_end > response.len() {
                return Err("STUN attribute exceeds message length".to_string());
            }

            // XOR-MAPPED-ADDRESS (0x0020), with MAPPED-ADDRESS (0x0001) fallback.
            if matches!(attr_type, 0x0020 | 0x0001) {
                let data = &response[attr_data_offset..attr_data_offset + attr_len];
                if !matches!((data.get(1), data.len()), (Some(1), 8) | (Some(2), 20)) {
                    return Err("Invalid STUN mapped address family or length".to_string());
                }
                let mut port = u16::from_be_bytes([data[2], data[3]]);
                let mut bytes = [0u8; 16];
                bytes[..data.len() - 4].copy_from_slice(&data[4..]);
                if attr_type == 0x0020 {
                    port ^= 0x2112;
                    // RFC 8489: IPv6 uses the cookie followed by the transaction ID.
                    for (byte, mask) in bytes[..data.len() - 4].iter_mut().zip(&response[4..20]) {
                        *byte ^= mask;
                    }
                }
                let ip = if data[1] == 1 {
                    IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
                } else {
                    IpAddr::V6(Ipv6Addr::from(bytes))
                };
                return Ok(std::net::SocketAddr::new(ip, port));
            }

            offset = padded_end;
        }

        Err("No mapped address found in STUN response".to_string())
    }

    /// Create a STUN binding request message
    fn create_stun_binding_request(&self) -> Vec<u8> {
        let mut request = vec![0x00, 0x01]; // Message type: Binding Request
        request.extend_from_slice(&[0x00, 0x00]); // Message length: 0
        request.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]); // Magic cookie
        request.extend_from_slice(&[0x00; 12]); // Transaction ID
        request
    }

    /// Query a STUN server for IPv4 address
    async fn query_stun_ipv4(&self, server: &str) -> Result<IpAddr, String> {
        let mut request = vec![0x00, 0x01]; // Message type: Binding Request
        request.extend_from_slice(&[0x00, 0x00]); // Message length: 0
        request.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]); // Magic cookie
        request.extend_from_slice(&[0x00; 12]); // Transaction ID

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("Failed to bind IPv4 socket: {}", e))?;

        socket
            .send_to(&request, server)
            .await
            .map_err(|e| format!("Failed to send STUN request: {}", e))?;

        let mut response = vec![0; 512];
        match tokio::time::timeout(self.timeout, socket.recv_from(&mut response)).await {
            Ok(Ok((n, _))) => self.parse_stun_response(&response[..n], true),
            Ok(Err(e)) => Err(format!("Failed to receive STUN response: {}", e)),
            Err(_) => Err("STUN query timeout".to_string()),
        }
    }

    /// Query a STUN server for IPv6 address
    async fn query_stun_ipv6(&self, server: &str) -> Result<IpAddr, String> {
        let mut request = vec![0x00, 0x01]; // Message type: Binding Request
        request.extend_from_slice(&[0x00, 0x00]); // Message length: 0
        request.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]); // Magic cookie
        request.extend_from_slice(&[0x00; 12]); // Transaction ID

        let socket = UdpSocket::bind("[::]:0")
            .await
            .map_err(|e| format!("Failed to bind IPv6 socket: {}", e))?;

        socket
            .send_to(&request, server)
            .await
            .map_err(|e| format!("Failed to send STUN request: {}", e))?;

        let mut response = vec![0; 512];
        match tokio::time::timeout(self.timeout, socket.recv_from(&mut response)).await {
            Ok(Ok((n, _))) => self.parse_stun_response(&response[..n], false),
            Ok(Err(e)) => Err(format!("Failed to receive STUN response: {}", e)),
            Err(_) => Err("STUN query timeout".to_string()),
        }
    }

    /// Parse STUN response to extract IP address
    fn parse_stun_response(&self, response: &[u8], is_ipv4: bool) -> Result<IpAddr, String> {
        let mapped = self.parse_mapped_socket_addr(response)?;
        if mapped.is_ipv4() == is_ipv4 {
            Ok(mapped.ip())
        } else {
            Err("Unexpected STUN mapped address family".to_string())
        }
    }
}

#[cfg(test)]
#[path = "public_ip_test.rs"]
mod tests;
