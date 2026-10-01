# cat4igp Client Configuration and Usage Guide

## Overview

The cat4igp client has been enhanced with:

1. **Configuration Management**: Load/save configuration from TOML or JSON files
2. **CLI Interface**: Command-line options for managing the daemon
3. **Public IP Detection**: STUN-based detection of public IPv4 and IPv6 addresses
4. **WireGuard Response Handler**: Smart IP address selection for connection responses
5. **Private libp2p control plane**: PSK-protected, encrypted controller communication

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

# Optional reachable addresses. The matching family is advertised with the
# allocated tunnel UDP port; IPv6 uses the IPv6 value.
public_hostname_ipv4 = "example.com"
public_hostname_ipv6 = "vpn6.example.com"

# Additional controller multiaddresses for bootstrap/failover. Each must include
# the same `/p2p/<controller-peer-id>` as the address passed to `register`.
control_bootstrap_addresses = [
  "/dns4/controller-backup.example.com/tcp/9000/p2p/12D3KooW..."
]

# Required libp2p private-network key file, issued out of band with the invite.
control_private_network_key = """/key/swarm/psk/1.0.0/
/base16/
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"""
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
  "public_hostname_ipv4": "example.com",
  "public_hostname_ipv6": "vpn6.example.com",
  "control_bootstrap_addresses": [
    "/dns4/controller.example.com/tcp/9000/p2p/12D3KooW..."
  ]
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

### Direct WireGuard connectivity

For each controller-requested link, a node advertises an endpoint in this order:

1. Resolve `public_hostname_ipv4` or `public_hostname_ipv6` and combine it with the allocated tunnel port.
2. If the relevant hostname is unset, issue STUN from that requested UDP port and advertise STUN's mapped address and **actual mapped port**.
3. If neither yields a valid endpoint for the requested family, reject that link with `RejectedNoIpStack`.

Nodes exchange endpoints through the controller, send a short UDP punch burst, then use WireGuard persistent keepalive. They re-advertise a changed endpoint after control polling or Linux link/address events.

This is best effort. Permit and, when necessary, forward the configured UDP range at the host and edge firewall. Do not use a private, unspecified, multicast, split-horizon, or controller-only hostname. Symmetric NAT and restrictive endpoint-dependent firewalls can still prevent direct connectivity; CAT4IGP does not relay traffic.

### Controller bootstrap servers

`register --server` takes a controller libp2p multiaddress containing
`/p2p/<controller-peer-id>`. Configure `control_bootstrap_addresses` for
additional reachable addresses. The client tries each address in order and
requires every configured address to identify the same controller peer.
`control_private_network_key` is required and must match the controller's
`CONTROL_PRIVATE_NETWORK_KEY` environment variable.

The controller stores its libp2p signing and encryption identities in its
database. On enrollment, the client pins the controller peer ID, signing key,
encryption key, recipient node ID, and control-network ID in
`<data_dir>/server.json` (mode `0600`). Topology snapshots are signed and
recipient-encrypted for both PubSub delivery and recovery requests.

## Programmatic Configuration

Create and save configurations programmatically:

```rust
use std::path::PathBuf;
use client::config::ClientConfig;

// Create default configuration
let mut config = ClientConfig::default();

// Customize
config.daemon_socket = PathBuf::from("/tmp/my-client.sock");
config.public_hostname_ipv4 = Some("my-server.example.com".to_string());

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
control_bootstrap_addresses = ["/dns4/controller.example.com/tcp/9000/p2p/12D3KooW..."]
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
- **Direct-link errors**: Pending WireGuard handshake when NAT or firewall policy blocks direct UDP

## Testing

Run tests for configuration management:

```bash
cargo test --package client config::tests
cargo test --package client public_ip::tests
```

## Future Enhancements

- Full TLS certificate verification with rustls
- Caching of detected public IPs
- Multiple tunnel protocol support
- Configuration hot-reload
- Metrics and logging integration
