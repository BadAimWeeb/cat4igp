# cat4igp libfec

Accelerated FEC-based UDP transport library for cat4igp client tunnels. Inspired by [UDPspeeder](https://github.com/wangyu-/UDPspeeder).

## Design goals

- Peer-to-peer symmetric topology (no fixed client/server role).
- Two UDP planes:
  - FEC transport plane: one listen/send UDP port for encoded packets.
  - Local application plane: one listen/send UDP port for plain application packets.
- Runtime API to update peer address without restart.
- Portable Unix-like behavior with Tokio networking.

## Library layout

Single crate: `udpspeeder`

- `src/proto.rs`: packet/header encode/decode.
- `src/transport.rs`: portable UDP pipe abstractions.
- `src/engine.rs`: runtime forwarding loops.
- `src/lib.rs`: public API, config, control, stats exports.

## Minimal usage

```rust
use std::net::SocketAddr;
use udpspeeder::{Config, FecMode, PeerEngine};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let mut config = Config::new(
    "0.0.0.0:4000".parse::<SocketAddr>()?,
    "127.0.0.1:5000".parse::<SocketAddr>()?,
    "127.0.0.1:6000".parse::<SocketAddr>()?,
);
config.fec_mode = FecMode::Mode0;
config.initial_peer_addr = Some("198.51.100.10:4000".parse::<SocketAddr>()?);
config.enforce_local_source = false;

let engine = PeerEngine::start(config).await?;
engine.handle().set_peer_addr("198.51.100.11:4000".parse()?).await;
let _stats = engine.handle().stats();
# Ok(()) }
```

## Config defaults

`Config::new(fec_bind, local_bind, local_app_endpoint)` sets:

| Field | Default |
| --- | --- |
| `max_payload_size` | `1400` |
| `fec_mode` | `FecMode::Mode0` |
| `fec_data_shards` | `4` |
| `fec_parity_shards` | `2` |
| `fec_flush_timeout_ms` | `50` |
| `encode_fast_send` | `true` |
| `decode_fast_send` | `true` |
| `replay_window_blocks` | `1024` |
| `initial_peer_addr` | `None` |
| `enforce_local_source` | `true` |

## Status

Initial implementation is a single library crate with protocol framing, runtime peer-address control, and block-based Reed-Solomon FEC encode/decode.

- `FecMode::Mode0`: batched block FEC transmission.
- `FecMode::Mode1`: immediate data-frame send plus grouped parity FEC frames.
