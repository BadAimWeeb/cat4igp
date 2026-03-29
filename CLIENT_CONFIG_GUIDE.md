# cat4igp Client Configuration and Usage Guide

## Overview

The cat4igp client has been enhanced with:

1. **Configuration Management**: Load/save configuration from TOML or JSON files
2. **CLI Interface**: Command-line options for managing the daemon
3. **Public IP Detection**: STUN-based detection of public IPv4 and IPv6 addresses
4. **WireGuard Response Handler**: Smart IP address selection for connection responses
5. **TLS Support**: Configuration for HTTPS server connections

## Configuration File Format

Configuration can be stored in TOML or JSON format. The configuration file should include:

### TOML Format (Recommended)

```toml
daemon_socket = "/tmp/cat4igp-client.sock"
data_dir = "/var/lib/cat4igp-client"

# Port range for tunnel endpoints
[port_range]
min = 51820
max = 52000

# Enabled tunnel protocols
[tunnel_protocols]
wireguard = true

# Optional public hostname for connection responses
public_hostname = "example.com"

# Server connection settings
[server]
address = "https://example.com:8443"
verify_tls = true
```

### JSON Format

```json
{
  "daemon_socket": "/tmp/cat4igp-client.sock",
  "data_dir": "/var/lib/cat4igp-client",
  "port_range": {
    "min": 51820,
    "max": 52000
  },
  "tunnel_protocols": {
    "wireguard": true
  },
  "public_hostname": "example.com",
  "server": {
    "address": "https://example.com:8443",
    "verify_tls": true
  }
}
```

## CLI Commands

### Start the Daemon

```bash
# Start with default configuration
./target/debug/client start

# Start with custom configuration file
./target/debug/client start --config /path/to/config.toml

# Or using the --config global option
./target/debug/client --config /path/to/config.toml start
```

### Generate Configuration File

```bash
# Generate TOML configuration
./target/debug/client gen-config --output config.toml

# Generate JSON configuration
./target/debug/client gen-config --output config.json --json
```

### Show Current Configuration

```bash
# Display configuration as TOML (default)
./target/debug/client show-config

# Display configuration as JSON
./target/debug/client show-config --json

# Display specific config file
./target/debug/client show-config --config /path/to/config.toml
```

### Detect Public IP Address

```bash
# Detect both IPv4 and IPv6
./target/debug/client public-ip

# Detect only IPv4
./target/debug/client public-ip ipv4

# Detect only IPv6
./target/debug/client public-ip ipv6
```

## Configuration Features

### Port Range Validation

The port range configuration ensures tunnel endpoints are allocated within a valid range:

```rust
let range = PortRange::new(51820, 52000)?;
assert!(range.contains(51900)); // true
assert!(range.contains(52100)); // false
```

### Public IP Detection

The `PublicIpDetector` uses STUN (Session Traversal Utilities for NAT) to detect public IP addresses:

- Multiple STUN servers for redundancy
- Configurable timeout (default 5 seconds)
- Support for both IPv4 and IPv6
- Automatic fallback between servers

### WireGuard Response Handler

When a client connects via WireGuard, the handler can respond with the appropriate IP address:

```rust
let handler = WireGuardResponseHandler::new(config);

// Handle IPv4 request
let response = handler.handle_request(AddressFamily::IPv4).await?;
match response {
    WireGuardResponse::Address(ip) => println!("Responding with: {}", ip),
    WireGuardResponse::Empty => println!("No suitable address found"),
}
```

The response logic:
1. Detects public IP using STUN
2. Validates the IP matches either:
   - A local network interface address, OR
   - The configured public hostname (DNS lookup)
3. Returns the IP if valid, empty if unsuitable, or error if address family unavailable

### Server Configuration

The server address configuration supports:

- **HTTPS**: `https://example.com:8443` - TLS verification enabled by default
- **HTTP**: `http://example.com:8080` - No TLS verification
- **Hostname or IP**: Both are supported
- **Ports**: Custom ports can be specified

TLS verification can be disabled per-connection or globally in configuration:

```toml
[server]
address = "https://internal.example.com"
verify_tls = false  # Disable certificate verification
```

## Programmatic Configuration

Create and save configurations programmatically:

```rust
use std::path::PathBuf;
use client::config::ClientConfig;

// Create default configuration
let mut config = ClientConfig::default();

// Customize
config.daemon_socket = PathBuf::from("/tmp/my-client.sock");
config.public_hostname = Some("my-server.example.com".to_string());

// Save to file
config.save_to_file("my-config.toml")?;

// Convert to JSON string
let json = config.to_json()?;

// Load from file
let loaded = ClientConfig::from_file("my-config.toml")?;

// Parse from JSON
let from_json = ClientConfig::from_json(&json)?;
```

## Default Configuration

If no configuration file is specified, the client uses defaults:

```toml
daemon_socket = "/tmp/cat4igp-client.sock"
data_dir = "/var/lib/cat4igp-client"
port_range = { min = 51820, max = 52000 }
tunnel_protocols = { wireguard = true }
server = { address = "https://localhost:8443", verify_tls = true }
```

## Module Structure

- **`config.rs`**: Configuration parsing, serialization, and defaults
- **`public_ip.rs`**: STUN-based public IP detection
- **`wireguard_response.rs`**: Handler for WireGuard connection responses
- **`tls_verifier.rs`**: TLS configuration and verification
- **`main.rs`**: CLI interface and daemon startup

## Error Handling

All operations return proper error types:

- **Configuration errors**: Invalid port ranges, missing files, parse errors
- **Network errors**: STUN server timeouts, DNS lookup failures
- **Address family errors**: Specific errors when IPv4/IPv6 not available

## Testing

Run tests for configuration management:

```bash
cargo test --package client config::tests
cargo test --package client public_ip::tests
cargo test --package client wireguard_response::tests
```

## Future Enhancements

- Full TLS certificate verification with rustls
- Caching of detected public IPs
- Multiple tunnel protocol support
- Configuration hot-reload
- Metrics and logging integration
