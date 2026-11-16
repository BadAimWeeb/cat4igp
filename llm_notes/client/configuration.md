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
The daemon saves pins, bootstrap addresses and the private-network key to its private
`<data_dir>/server.json` (mode `0600`, atomic replacement), not to user TOML or JSON
configuration. Protect and back up the entire state directory. The pending client
identity is saved before sending enrollment and reused when the same bundle is retried;
the invite is removed from completed state. Completed enrollment cannot be overwritten
by registration. Preserve existing enrolled state during upgrades; do not delete or
recreate `server.json` to migrate configuration. Address/invite-only registration is
no longer supported.

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

An operator must plan containment outside the controller: block the isolated host
or its tunnel endpoints at host and edge firewalls, disable its network access,
and remove or rotate affected peer credentials on reachable systems as appropriate.
Verify that traffic is blocked; a controller-side deletion alone is not immediate
revocation. After reconnection, verify the deleted identity is rejected and the
remaining peers converge before lifting containment. Preserve corrupt state for
diagnosis; do not replace a cache based only on the configuration revision, which
can lag the cached topology. Protect client backups with encryption and separately
managed recoverable keys: the enrollment state and topology cache contain secrets.

### Damaged cache recovery boundary

On Unix, a client with a valid revision journal can repair a cache that cannot be
decoded when an authenticated controller snapshot matches the journal's exact
revision and topology hash. The daemon retains a private diagnostic copy before
replacing the cache. This requires the controller to be reachable and does not
repair a missing or damaged journal, unsafe file permissions, or a parseable but
conflicting cache. For other failures, stop and fence the client and retain an
encrypted, access-restricted copy of its entire state directory for diagnosis. Do
not remove the cache, edit `server.json`, lower
its revision, or re-enroll the existing identity as a recovery shortcut. A cache
write can reach stable storage before the configuration revision is saved, so even
an intact `server.json` does not establish the highest accepted revision. A valid
older backup has the same limitation. Deleting the cache also loses the check that
rejects different topology at an already accepted revision.
New enrollments also retain an identity-bound revision journal with a hash of the
accepted topology. Journal publication precedes cache publication and fails closed
if the journal is missing or damaged. Existing enrollments are not automatically
migrated. The journal is in the same state directory, so a coordinated restore or
rollback of that directory can roll it back too; it is not an independent trust anchor.
Control synchronization preserves and reserves surviving cached tunnel ports before
publishing another cache, even if offline restoration has not completed. A completed
dual-link refresh may replace a reservation only when the previous cache matches
its required version 2 journal and the new port matches an identity-bound, persisted
active refresh generation and slot. Other in-memory conflicts fail closed, including
journal-only recovery; updating the cache never frees an in-use reservation.
Refresh records without an enrollment identity binding are rejected rather than
adopted during recovery; preserve such state for diagnosis.
Rejected refresh candidates retain a durable cleanup intent and reserve their
port on restart until verified interface cleanup and state publication succeed.



Version 2 journals also retain validated local port reservations before cache
publication. Exact-hash repair restores those reservations and rejects conflicts.
Version 1 journals contain no reservations; damaged caches using them cannot
recover lost mappings, and allocation alone may not reconstruct advertised ports.

Recovery after a coordinated state-directory rollback would require an independently
protected and current record,
bound to this client and controller identity, of every accepted revision and the
topology accepted at its high-water mark, including writes immediately before the
failure. It would also require a verified, authorized replacement topology and a
crash-safe, exclusive installation procedure that preserves both the revision floor
and same-revision content check. This software does not maintain that independent
record or provide that procedure. A controller signature, the controller's current
revision, an operator estimate, or a backup comparison alone cannot supply it.
Keep affected data paths contained using independent network controls while the
incident is investigated; do not claim rollback-safe recovery without this evidence.

## Backend privilege verification

The zero-capability regression can be reproduced with
`cargo test --locked -p cat4igp-client network::privilege_test::backends_fail_closed_without_capabilities -- --exact`.
It runs denial checks in an isolated child with `no_new_privs` and empty capability
sets, covering FakeTCP raw sockets, WireGuard, L2TPv3 and both L2TPv2 modes. It
checks failed-setup resource release and retry, not the minimum sufficient positive
capability profile; a packaged root service is not evidence of least privilege.
When wrapping this test in a fresh `unshare --net` namespace, bring loopback up
before launching the executable; otherwise FakeTCP can fail route discovery with
ENETUNREACH before exercising the intended raw-socket EPERM boundary.

In a disposable root VM, run the compiled test binary with
`--exact network::privilege_test::l2tpv3_setup_with_net_admin_only --ignored --nocapture`
to verify backend setup/recreation with only CAP_NET_ADMIN, or
`--exact network::privilege_test::l2tpv2_denied_without_sys_admin --ignored --nocapture`
to verify mount-namespace denial while retaining filesystem access. The harness
creates its isolated network namespace before dropping capabilities; this does
not establish the capabilities needed to create that namespace or run PPP.

The same harness supports
`--exact network::privilege_test::wireguard_setup_with_net_admin_only --ignored --nocapture`.
It verifies configured kernel identity, peer/listener and destroy/recreate with
CAP_NET_ADMIN only; it does not provision a live peer or establish traffic.
`daemon::daemon_memory::l2tp_recovery_test::paired_snapshot_dependency_recovery`
under `sudo unshare --net --mount` with `--exact --ignored --nocapture` instead
verifies paired WireGuard/L2TP packet recovery after empty-snapshot teardown,
including unmanaged-resource preservation and a ten-second reference bound.

For a controlled PPP helper profile, run `.github/workflows/ppp-test.sh` with the
compiled test executable inside a disposable transient systemd unit using
`CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID`
and `NoNewPrivileges=yes`, under `unshare --net --mount`. This bounds the complete
driver, including namespace setup and ping; it is a candidate sufficient profile,
not a minimum-helper or production-daemon profile. Pin pppd/xl2tpd versions in
results, and require kernel, userspace and WireGuard modes to finish successfully.

The real two-client native WireGuard restore driver also passed in Debian 13
with `CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_RAW` and
`NoNewPrivileges=yes`. This includes its namespace/ping orchestration and excludes
PPP/FakeTCP; it is a sufficient reference profile, not a production service change
or proof that all three capabilities are needed by the long-running daemon.
The same three-capability bounding set passed the complete PPP driver with
pppd 2.5.2/xl2tpd 1.3.18 and the routed FakeTCP conntrack outage/recovery scenario.
These root-owned fixtures needed neither DAC override nor UID/GID-changing caps;
they do not establish non-root operation or helper-version-independent minimums.

In a disposable VM with nftables, run the compiled test executable under
`sudo env CAT4IGP_REFRESH_BLOCK_CANDIDATE=1 unshare -n` with
`--exact daemon::daemon_memory::refresh_integration_test::kernel_dual_link_refresh --ignored --nocapture`.
This blocks candidate UDP transport, verifies old-link traffic and absent candidate
readiness, checks drop counters, then unblocks and verifies switch/cleanup/traffic.
It does not establish deployment-specific proxy or restrictive-NAT compatibility.

The ignored `daemon::daemon_memory::nat_integration_test::kernel_wireguard_static_udp_forward`
scenario requires a disposable root VM with kernel WireGuard, iproute2, nftables,
conntrack and ping. Run the compiled test executable with `--exact` for that name
and `--ignored --nocapture` under `sudo unshare --net --mount`. It verifies explicit
UDP DNAT/SNAT, removal-induced traffic failure and recovery after reinstating rules.
It does not establish automatic NAT traversal or compatibility with an operator's
restrictive firewall topology.


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
daemon_socket = "/run/cat4igp-client.sock"
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

Controller bootstrap addresses and the private-network key come from the trusted
enrollment bundle and are managed only in daemon-owned `server.json`; do not put
them in client TOML or JSON configuration.

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

### Register and control the daemon

```bash
cat4igp-client --config /path/to/config.toml register-bundle --bundle /secure/enrollment.json
cat4igp-client --config /path/to/config.toml status
cat4igp-client --config /path/to/config.toml stop
```

Use the same configuration path as the daemon so the CLI finds its socket and
authentication state. Protect the bundle and delete it after successful registration.

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

Put reachable controller IP/TCP/p2p multiaddresses in the bundle's
`bootstrap_addresses`, each ending in `/p2p/<controller-peer-id>`. The client
tries them in order and requires each to identify the pinned controller. The
bundle's `private_network_key` must match the controller's
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
daemon_socket = "/run/cat4igp-client.sock"
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
