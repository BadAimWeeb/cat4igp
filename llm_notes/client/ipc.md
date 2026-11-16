# IPC Unix Socket Communication

## Overview

The cat4igp client uses Unix domain sockets for secure inter-process communication (IPC) between the daemon and CLI.

## Architecture

```
┌─────────────┐                      ┌──────────────┐
│     CLI     │                      │    Daemon    │
│             │                      │              │
│  • Connects │──────Socket─────────▶│  • Listens   │
│  • Sends    │   (Unix Domain)      │  • Receives  │
│  • Receives │◀─────Response────────│  • Processes │
└─────────────┘                      └──────────────┘
```

## Socket Location

- **Path**: Configured in `daemon_socket` field (default: `/run/cat4igp-client.sock`); custom parent directories must be trusted.
- **Type**: Unix domain socket (SOCK_STREAM)
- **Protocol**: Length-prefixed JSON messages

## Authentication

**Shared Secret**:
- Generated on daemon first startup
- Stored in: `<data_dir>/.daemon_secret`
- Permissions: `0600` (owner read/write only)
- Length: 32 random alphanumeric characters
- Sent with every request for authentication
- Before sending any request, the CLI checks the connected peer's kernel credentials and accepts only root or its own effective UID. Processes running as that same UID are trusted.

## Message Protocol

### Request Format

```
┌──────────────┬────────────────────┐
│ Length (4B)  │  JSON Payload      │
│ Big-Endian   │  IpcMessage        │
└──────────────┴────────────────────┘
```

**IpcMessage Structure**:
```json
{
  "secret": "32-character-shared-secret",
  "request": {
    // DaemonRequest variant
  }
}
```

### Response Format

```
┌──────────────┬────────────────────┐
│ Length (4B)  │  JSON Payload      │
│ Big-Endian   │  DaemonResponse    │
└──────────────┴────────────────────┘
```

## Request Types

### Status
```rust
DaemonRequest::Status
```
Returns daemon running status, server configuration state, node key presence, the age of the last verified, non-rollback controller snapshot pull, and any reconciliation error. The age uses a monotonic clock and is unknown until the first successful verified pull after each daemon start. Cached topology and unsolicited pushes do not reset it; a fresh pull does not imply successful tunnel reconciliation.

### RegisterBundle
```rust
DaemonRequest::RegisterBundle { bundle: bundle_json }
```
Imports the trusted enrollment JSON and registers with its pinned controller.
The bundle contains secrets: never log it. The daemon saves pending and completed
enrollment in private `<data_dir>/server.json`; retry the same bundle to resume a
pending enrollment. Completed enrollment cannot be replaced by registration.
Address/invite-only registration is not supported.

### GetConfig
```rust
DaemonRequest::GetConfig
```
Returns the running daemon configuration as JSON.

### ModifyConfig
```rust
DaemonRequest::ModifyConfig {
    public_hostname_ipv4: Some("client4.example.com"),
    public_hostname_ipv6: Some("client6.example.com"),
}
```
Updates the supplied hostnames in the loaded TOML file and the running daemon;
omitted fields are unchanged; an empty string clears a hostname and restores
STUN detection. Nonempty values must be DNS hostnames or IP addresses of the
matching family. Updating requires an existing regular TOML file on Linux;
symlink paths and files with ACLs or extended attributes are rejected. Comments,
owner, and mode are preserved. Do not edit the file concurrently with an IPC
update; changes to hostnames made on disk require a restart. Endpoint changes
are advertised on the next control poll or network event.

## Response Types

### Ok
```rust
DaemonResponse::Ok(Some("Operation successful"))
```

### Error
```rust
DaemonResponse::Error("Error message")
```

### Status
```rust
DaemonResponse::Status {
    running: true,
    server_configured: true,
    node_key_present: false,
    controller_snapshot_age_seconds: None,
    message: None,
}
```

### Config
```rust
DaemonResponse::Config(serde_json::Value)
```

## Usage Examples

### Start Daemon

```bash
# Terminal 1: Start daemon
cat4igp-client daemon --config config.toml
```

### Check Status

```bash
# Terminal 2: Check daemon status
cat4igp-client --config config.toml status

# Output:
# Daemon Status:
#   Running: Yes
#   Server Configured: No
#   Node Key Present: No
#   Controller Snapshot Age Seconds: Unknown
```

### Register with Server

Obtain the bundle from a trusted operator channel and protect it like a password.
With the daemon running, use the same configuration file to locate its socket:

```bash
cat4igp-client --config config.toml register-bundle --bundle /secure/enrollment.json
```

Delete the bundle after successful registration. Preserve the private daemon
state directory during upgrades and protect backups because `server.json` contains
the private control-network key and enrollment identity.

## Implementation Details

### Daemon Side (`daemon.rs`)

```rust
pub async fn run(&self) -> io::Result<()> {
    let listener = UnixListener::bind(&self.config.daemon_socket)?;
    
    loop {
        let (stream, _) = listener.accept().await?;
        // Spawn handler for each connection
        tokio::spawn(async move {
            handle_client(stream, daemon).await
        });
    }
}
```

**Handler**:
1. Read length prefix (4 bytes, big-endian)
2. Read JSON message
3. Deserialize `IpcMessage`
4. Verify shared secret
5. Process request
6. Send response with length prefix

### Client Side (`daemon_client.rs`)

```rust
pub async fn send_request(&self, request: DaemonRequest) -> io::Result<DaemonResponse> {
    let stream = UnixStream::connect(&self.socket_path).await?;
    
    // Send request with length prefix
    let message = IpcMessage { secret, request };
    let bytes = serde_json::to_vec(&message)?;
    stream.write_all(&len_prefix).await?;
    stream.write_all(&bytes).await?;
    
    // Read response
    let response_len = read_u32(&stream).await?;
    let response_bytes = read_bytes(&stream, response_len).await?;
    serde_json::from_slice(&response_bytes)
}
```

## Security Features

1. **Shared Secret Authentication**: Every request must include the correct secret
2. **File Permissions**: Socket and secret file have restricted permissions
3. **Constant-Time Comparison**: Secret verification uses constant-time comparison
4. **Message Size Limits**: Maximum 1MB per message to prevent DoS
5. **Local Only**: Unix sockets are only accessible locally

## Error Handling

**Connection Errors**:
- Socket file doesn't exist → Daemon not running
- Permission denied → Check file permissions
- Connection refused → Daemon not listening

**Authentication Errors**:
- Secret file not found → Run daemon first to generate
- Wrong secret → Secret mismatch (daemon was restarted)

**Protocol Errors**:
- Invalid JSON → Malformed request/response
- Message too large → Exceeded 1MB limit

## File Locations

```
<data_dir>/
├── .daemon_secret          # Shared secret (0600)
└── server.json             # Private daemon-owned enrollment state (0600)
```

```
<daemon_socket>             # Unix socket (usually /run/cat4igp-client.sock, mode 0600)
```

## Testing

```bash
# Generate config
cat4igp-client gen-config --output test-config.toml

# Start daemon (Terminal 1)
cat4igp-client daemon --config test-config.toml

# Inspect status and enroll (Terminal 2)
cat4igp-client --config test-config.toml status
cat4igp-client --config test-config.toml register-bundle --bundle /secure/enrollment.json
cat4igp-client public-ip both
```

## Performance

- **Latency**: < 1ms for local socket communication
- **Throughput**: Limited by JSON serialization, ~10K requests/sec
- **Concurrency**: One handler task per connection (tokio async)
- **Memory**: ~1KB per active connection

## Future Enhancements

- [ ] Message framing optimization (binary protocol)
- [ ] Request/response correlation IDs
- [ ] Streaming responses for long operations
- [ ] Connection pooling for CLI
- [ ] Request timeout handling
- [ ] Daemon restart without losing connections
