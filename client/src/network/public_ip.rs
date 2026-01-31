use std::net::{IpAddr, ToSocketAddrs, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use std::os::unix::io::AsRawFd;
use tokio::net::UdpSocket;
use rand::seq::SliceRandom;

const IPV4_STUN_LIST_URL: &str = "https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_ipv4s.txt";
const IPV6_STUN_LIST_URL: &str = "https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_ipv6s.txt";
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
        let mut rng = rand::thread_rng();
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
        let mut rng = rand::thread_rng();
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

    /// Detect NAT type for IPv4 using 2 STUN servers
    /// Detect NAT type for IPv4 using RFC 5780
    pub async fn detect_nat_type_ipv4(&self) -> Result<NatType, String> {
        if self.ipv4_nat_servers.is_empty() {
            return Err("No IPv4 NAT testing servers available - call init() first".to_string());
        }

        // Pick a random NAT testing server
        let mut rng = rand::thread_rng();
        let server = self.ipv4_nat_servers.choose(&mut rng)
            .ok_or("No NAT testing servers available")?;

        let server_ip = server.ipv4_addrs.first()
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
        let mut rng = rand::thread_rng();
        let server = self.ipv6_nat_servers.choose(&mut rng)
            .ok_or("No NAT testing servers available")?;

        let server_ip = server.ipv6_addrs.first()
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
        udp_sas::set_pktinfo(raw_fd)
            .map_err(|e| format!("Failed to enable pktinfo: {}", e))?;
        
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
        let test2_response = self.stun_test_change_request(&socket, server_addr, true, true).await;
        
        // Test III: Request from same server but different port (if Test II failed)
        let test3_response = if test2_response.is_err() {
            self.stun_test_change_request(&socket, server_addr, false, true).await
        } else {
            Ok(()) // Test II passed, skip Test III
        };

        // Test IV: Binding request to alternate server to check mapping behavior
        // We need another server for this - use regular STUN servers as fallback
        let mapping_behavior = if !self.ipv4_servers.is_empty() && is_ipv4 {
            let mut rng = rand::thread_rng();
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
            let mut rng = rand::thread_rng();
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
                Err(_) => "unknown"
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
            "address-dependent" => {
                Ok(NatType::AddressDependentMapping)
            }
            "address-port-dependent" => {
                Ok(NatType::AddressPortDependentMapping)
            }
            _ => Ok(NatType::Unknown)
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
        socket.send_to(&request, server_addr).await
            .map_err(|e| format!("Failed to send STUN request: {}", e))?;

        // Receive response with actual interface IP using recv_sas
        let raw_fd = socket.as_raw_fd();
        let timeout = self.timeout;
        
        // Use recv_sas in a blocking task with proper fd handling
        let (n, _peer_addr, local_interface_ip, response) = tokio::task::spawn_blocking(move || {
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
            
            if unsafe { libc::setsockopt(raw_fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, 
                                        &tv as *const _ as *const libc::c_void, 
                                        std::mem::size_of::<libc::timeval>() as libc::socklen_t) } < 0 {
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
        let local_ip = local_interface_ip
            .ok_or("Local interface IP not available".to_string())?;

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
        socket.send_to(&request, server_addr).await
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

        let response_len = u16::from_be_bytes([response[2], response[3]]) as usize;
        if response.len() < 20 + response_len {
            return Err("STUN response incomplete".to_string());
        }

        // Parse attributes
        let mut offset = 20;
        while offset + 4 <= 20 + response_len {
            let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let attr_len = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
            let attr_data_offset = offset + 4;

            // XOR-MAPPED-ADDRESS (0x0020)
            if attr_type == 0x0020 && attr_data_offset + attr_len <= response.len() {
                let data = &response[attr_data_offset..attr_data_offset + attr_len];
                let family = data[1];
                
                if family == 0x01 {
                    // IPv4
                    let magic = [0x21, 0x12, 0xa4, 0x42];
                    let port = u16::from_be_bytes([data[2] ^ magic[0], data[3] ^ magic[1]]);
                    let ip = Ipv4Addr::new(
                        data[4] ^ magic[0],
                        data[5] ^ magic[1],
                        data[6] ^ magic[2],
                        data[7] ^ magic[3],
                    );
                    return Ok(std::net::SocketAddr::new(IpAddr::V4(ip), port));
                } else if family == 0x02 {
                    // IPv6
                    let magic = [0x21, 0x12, 0xa4, 0x42];
                    let port = u16::from_be_bytes([data[2] ^ magic[0], data[3] ^ magic[1]]);
                    let mut bytes = [0u8; 16];
                    for i in 0..4 {
                        bytes[i] = data[4 + i] ^ magic[i];
                    }
                    for i in 4..16 {
                        bytes[i] = data[4 + i];
                    }
                    let ip = Ipv6Addr::from(bytes);
                    return Ok(std::net::SocketAddr::new(IpAddr::V6(ip), port));
                }
            }

            let padded_len = ((attr_len + 3) / 4) * 4;
            offset = attr_data_offset + padded_len;
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
        if response.len() < 20 {
            return Err("STUN response too short".to_string());
        }

        // Check if it's a STUN response (0x0101)
        if response[0] != 0x01 || response[1] != 0x01 {
            return Err("Invalid STUN response type".to_string());
        }

        let response_len = u16::from_be_bytes([response[2], response[3]]) as usize;
        if response.len() < 20 + response_len {
            return Err("STUN response incomplete".to_string());
        }

        // Parse attributes (starting at offset 20)
        let mut offset = 20;
        while offset + 4 <= 20 + response_len {
            let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let attr_len = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
            let attr_data_offset = offset + 4;

            // XOR-MAPPED-ADDRESS (0x0020)
            if attr_type == 0x0020 && attr_data_offset + attr_len <= response.len() {
                return self.parse_xor_mapped_address(&response[attr_data_offset..attr_data_offset + attr_len], is_ipv4);
            }

            // MAPPED-ADDRESS (0x0001) - fallback
            if attr_type == 0x0001 && attr_data_offset + attr_len <= response.len() {
                return self.parse_mapped_address(&response[attr_data_offset..attr_data_offset + attr_len], is_ipv4);
            }

            // Move to next attribute (with padding to 4-byte boundary)
            let padded_len = ((attr_len + 3) / 4) * 4;
            offset = attr_data_offset + padded_len;
        }

        Err("No mapped address found in STUN response".to_string())
    }

    /// Parse MAPPED-ADDRESS attribute
    fn parse_mapped_address(&self, data: &[u8], is_ipv4: bool) -> Result<IpAddr, String> {
        if data.len() < 2 {
            return Err("Invalid MAPPED-ADDRESS".to_string());
        }

        let family = data[1];
        if is_ipv4 {
            if family != 0x01 {
                return Err("Expected IPv4 address but got different family".to_string());
            }
            if data.len() < 8 {
                return Err("Invalid IPv4 address in MAPPED-ADDRESS".to_string());
            }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(IpAddr::V4(ip))
        } else {
            if family != 0x02 {
                return Err("Expected IPv6 address but got different family".to_string());
            }
            if data.len() < 20 {
                return Err("Invalid IPv6 address in MAPPED-ADDRESS".to_string());
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[4..20]);
            let ip = Ipv6Addr::from(bytes);
            Ok(IpAddr::V6(ip))
        }
    }

    /// Parse XOR-MAPPED-ADDRESS attribute
    fn parse_xor_mapped_address(&self, data: &[u8], is_ipv4: bool) -> Result<IpAddr, String> {
        if data.len() < 2 {
            return Err("Invalid XOR-MAPPED-ADDRESS".to_string());
        }

        let family = data[1];
        if is_ipv4 {
            if family != 0x01 {
                return Err("Expected IPv4 address but got different family".to_string());
            }
            if data.len() < 8 {
                return Err("Invalid IPv4 address in XOR-MAPPED-ADDRESS".to_string());
            }
            // XOR with magic cookie
            let magic = [0x21, 0x12, 0xa4, 0x42];
            let ip = Ipv4Addr::new(
                data[4] ^ magic[0],
                data[5] ^ magic[1],
                data[6] ^ magic[2],
                data[7] ^ magic[3],
            );
            Ok(IpAddr::V4(ip))
        } else {
            if family != 0x02 {
                return Err("Expected IPv6 address but got different family".to_string());
            }
            if data.len() < 20 {
                return Err("Invalid IPv6 address in XOR-MAPPED-ADDRESS".to_string());
            }
            let mut bytes = [0u8; 16];
            let magic = [0x21, 0x12, 0xa4, 0x42];
            // XOR first 4 bytes with magic cookie
            for i in 0..4 {
                bytes[i] = data[4 + i] ^ magic[i];
            }
            // Remaining bytes are not XORed in XOR-MAPPED-ADDRESS for IPv6
            for i in 4..16 {
                bytes[i] = data[4 + i];
            }
            let ip = Ipv6Addr::from(bytes);
            Ok(IpAddr::V6(ip))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let detector = PublicIpDetector::new();
        assert_eq!(detector.ipv4_servers.len(), 0);
        assert_eq!(detector.ipv6_servers.len(), 0);
    }

    #[test]
    fn test_detector_with_timeout() {
        let detector = PublicIpDetector::new().with_timeout(Duration::from_secs(10));
        assert_eq!(detector.timeout, Duration::from_secs(10));
    }
}
