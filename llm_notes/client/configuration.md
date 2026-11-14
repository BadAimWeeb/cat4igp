# Trusted enrollment bundle

Use `cat4igp-client register-bundle --bundle /secure/enrollment.json` with the daemon running.
Receive this JSON file from a trusted operator channel; protect it like a password and delete it after registration.
It uses the existing `EnrollmentBundle` fields: `version` (1), `bootstrap_addresses`,
`controller_peer_id`, `controller_signing_key` (hex-encoded protobuf public key),
`network_id`, `private_network_key` (libp2p PSK key-file contents), and `invitation_code`.
The bundle names one trusted server and its private control address.

Import is limited to 16 KiB and 16 addresses per list. Addresses must be IP/TCP/p2p;
all private addresses must name the pinned singleton controller. The supplied full public key
is the out-of-band trust anchor (not TOFU); a separate fingerprint-only exchange is not implemented.
Unknown fields, invalid keys/PSKs, identity mismatches and returned network/key substitutions fail closed.
Pins and discovery proof are automatically saved to mode-0600 `server.json` using atomic replacement.
The pending client identity is saved before sending enrollment, reused when the same bundle is retried,
and the invite is removed from the completed config. Completed enrollment cannot be overwritten by registration.
Legacy `register --server ... --invite ...` and existing configs remain supported.

This is singleton trusted enrollment against one standalone server. The client uses
the configured server and pinned identity for control traffic.

The daemon retains the last accepted topology and local UDP port assignments in
its private state directory and attempts to restore tunnels at startup even if
the controller is unreachable. It retries restoration while offline. This is
best effort: changed peer endpoints, NAT mappings, local interfaces, policy,
or unavailable tunnel dependencies can prevent connectivity. Deletions,
revocations and new configuration cannot reach an isolated client until it
reconnects; protect the cache and remove access through network controls when
immediate revocation is required. The cache contains tunnel secrets and must be
included in protected backups of the client state directory.


## Fixed-target client control relay

An operator can configure a reachable client as a TCP relay to one fixed
controller address. On the relay client, add this top-level TOML table and
restart its daemon:

```toml
[control_relay]
listen = "192.0.2.10:19001"
target = "192.0.2.20:19000"
```

Give the remote client an enrollment bundle whose `bootstrap_addresses`
includes `/ip4/192.0.2.10/tcp/19001/p2p/<controller-peer-id>`; keep the real
controller signing key and peer ID in the bundle. The address is the relay,
but the peer ID is the controller: the private-network and Noise handshakes
remain end-to-end and the relay cannot impersonate the pinned controller.
Use the same address for subsequent control traffic. Direct and relay
addresses may both be listed; firewall access to the relay as appropriate.

The relay accepts at most 128 concurrent streams, forwards only to its fixed
target, and drops idle streams after five minutes. It forwards control bytes,
not mesh data. It is raw TCP, not HTTPS or DPI camouflage: filtering can block
the relay too. A reachable route to the relay and from relay to controller is
required even for first enrollment; avoid relying exclusively on a mesh link
that must itself be provisioned through this control connection.


# Packaged installations

For distro packages, use `/etc/cat4igp/client.toml` and the packaged service.
See [packaging setup](../packaging/packages.md) for current CLI commands, enrollment
and persistent OpenWrt state. The older standalone examples below are not the
package installation contract; configuration files accepted by the daemon are TOML.

# cat4igp Client Configuration and Usage Guide

## Overview

The cat4igp client has been enhanced with:

1. **Configuration Management**: Load/save TOML configuration files
2. **CLI Interface**: Command-line options for managing the daemon
3. **Public IP Detection**: STUN-based detection of public IPv4 and IPv6 addresses
4. **WireGuard Response Handler**: Smart IP address selection for connection responses
5. **Private libp2p control plane**: PSK-protected, encrypted controller communication

Linux clients can enable L2TPv3 Ethernet and L2TPv2/PPP with
`tunnel_protocols.l2tp = true`. Direct L2TP is unencrypted and additionally
requires `allow_insecure_l2tp = true` on each endpoint. WireGuard-backed modes
do not require that opt-in. See [L2TP configuration](l2tp.md) for prerequisites,
policy routing and security limitations.

## Configuration File Format

The daemon loads TOML configuration files:

```toml
daemon_socket = "/tmp/cat4igp-client.sock"
data_dir = "/var/lib/cat4igp-client"
# Required only for direct, unencrypted L2TP.
allow_insecure_l2tp = false

# Optional reachable addresses, placed at the top level.
public_hostname_ipv4 = "example.com"
public_hostname_ipv6 = "vpn6.example.com"

# Port range for tunnel endpoints
[port_range]
min = 51820
max = 52000

# Enabled tunnel protocols
[tunnel_protocols]
wireguard = true
l2tp = false
```

Controller addresses and the private-network key are normally supplied in the
trusted enrollment bundle. Protect any manually configured keys as secrets.

## CLI Commands

### Start the Daemon

```bash
# Start with default configuration
cat4igp-client daemon

# Start with custom configuration file
cat4igp-client daemon --config /path/to/config.toml

# Or using the --config global option
cat4igp-client --config /path/to/config.toml daemon
```

### Generate Configuration File

```bash
# Generate TOML configuration
cat4igp-client gen-config --output config.toml

# JSON output is for inspection, not a loadable daemon configuration.
cat4igp-client gen-config --output config.json --json
```

### Show Current Configuration

```bash
# Display configuration as TOML (default)
cat4igp-client show-config

# Display configuration as JSON
cat4igp-client show-config --json

# Display specific config file
cat4igp-client show-config --config /path/to/config.toml
```

### Detect Public IP Address

```bash
# Detect both IPv4 and IPv6
cat4igp-client public-ip

# Detect only IPv4
cat4igp-client public-ip ipv4

# Detect only IPv6
cat4igp-client public-ip ipv6
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

Nodes exchange endpoints through the controller, send a short UDP punch burst, then use WireGuard persistent keepalive. FEC tunnels refresh STUN through their active socket. The kernel WireGuard socket cannot be probed by the daemon after activation: without a configured hostname, refresh reports an error and retains the last advertised endpoint. Configure a stable hostname and port forwarding for automatic address refresh on kernel WireGuard. STUN cannot guarantee the same mapping toward different destinations behind endpoint-dependent NAT.
For an existing WireGuard peer, reconciliation preserves a kernel-learned
endpoint while its handshake is recent. A changed controller endpoint is
applied after the handshake becomes stale, allowing reconnection without
repeatedly overwriting authenticated roaming.

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

The daemon tries `/etc/cat4igp/client.toml` unless `--config` is supplied; if
the selected file does not exist, it uses defaults including:

```toml
daemon_socket = "/tmp/cat4igp-client.sock"
data_dir = "/var/lib/cat4igp-client"
port_range = { min = 51820, max = 52000 }
tunnel_protocols = { wireguard = true, l2tp = false }
```


## Error Handling

All operations return proper error types:

- **Configuration errors**: Invalid port ranges, missing files, parse errors
- **Network errors**: STUN server timeouts, DNS lookup failures
- **Address family errors**: Specific errors when IPv4/IPv6 not available
- **Direct-link errors**: Pending WireGuard handshake when NAT or firewall policy blocks direct UDP

## Testing

Run tests for configuration management:

```bash
cargo test -p cat4igp-client config::tests
cargo test -p cat4igp-client public_ip::tests
```

## Future Enhancements

Registration persists the pending client identity before sending. A lost completion
can retry that identity against the configured server. Private control addresses
remain explicitly configured and authenticated; the client does not fall back to an
untrusted endpoint.

- Full TLS certificate verification with rustls
- Caching of detected public IPs
- Multiple tunnel protocol support
- Configuration hot-reload
- Metrics and logging integration
