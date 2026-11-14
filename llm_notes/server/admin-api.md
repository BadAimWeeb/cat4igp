# Standalone administrator API

This note documents the browser administrator API for one standalone cat4igp server: authentication, inventory, invites, and management actions. The `/operator/*` automation API remains separate. Browser APIs require `ADMIN_JWT_CONFIG_FILE`; invalid configuration fails startup.

## Provisioning

Run `cat4igp-server migrate` against the standalone database before starting the server, or use the supported automatic migration setting. Do not copy a database, identity, or authority configuration between servers. Historical migration directories remain part of the repository and must not be rewritten or removed.

Set `ADMIN_JWT_CONFIG_FILE` to an owner-only JSON file containing the exact public HTTPS origin, issuer, audience, active key ID, and independently generated HS256 keys. For first bootstrap, set `ADMIN_BOOTSTRAP_FILE` to an owner-only file containing the administrator username and password, then remove it after successful bootstrap. Passwords are hashed with Argon2id and are never returned or logged.

Use a same-origin HTTPS reverse proxy. Every JSON POST requires the configured Origin and `Content-Type: application/json`; bodies are limited to 4096 bytes. Do not expose the server HTTP listener directly to an untrusted network and do not enable credentialed CORS.

For per-client login throttling behind the proxy, set `ADMIN_TRUSTED_PROXY_IP` to the proxy's exact IP address as seen by the server. Configure that proxy to **overwrite** `X-Real-IP` with the verified connecting client's IP, not append to or pass through an incoming header; restrict access to the proxy and server listener accordingly. Requests from that peer without exactly one valid IP in `X-Real-IP` are rejected. Headers from other peers are ignored. Without this setting, the TCP peer is the client, so all users behind a proxy share its limit. Invalid configuration fails startup.

Login allows 10 attempts per client per 60 seconds; IPv6 clients share a /64 bucket. State is in memory and resets on restart. At most 16,384 client buckets are retained; when full, the oldest is evicted, so distributed attackers can weaken this limit. Argon2 verification remains capped at two concurrent jobs. Deploy additional network-level abuse controls as appropriate.

## Browser contract

| Endpoint | Request | Successful response |
|---|---|---|
| `POST /admin/login` | username and password JSON | success, administrator subject, and Secure HttpOnly cookie |
| `GET /admin/me` | none | `{"subject":"administrator:1"}` |
| `POST /admin/logout` | `{}` | successful logout and cleared cookie |
| `GET /admin/inventory` | none | nodes, meshes, memberships, invites, and tunnels |
| `POST /admin/actions` | one typed action plus `Idempotency-Key` | committed action result |
| `POST /admin/invites` | invite parameters plus `Idempotency-Key` | generated invite code |

All endpoints except login require the cookie session. Inventory omits authentication keys, control keys, invite codes, and other authority secrets. `last_seen` is an observation, not a reachability guarantee.

`Idempotency-Key` is 1 to 100 printable ASCII bytes. After a timeout or 503, retry the same key and identical body. A changed body with the same key is rejected. A definite 4xx is not automatically retried. A 503 or unreadable response means the outcome is unknown and must be inspected before submitting a new key.

## Actions

`/admin/actions` supports node and mesh rename, mesh creation, FEC and MTU updates, membership add/remove, mesh/node deletion, invite invalidation, and removal of explicit `legacy` or `manual` tunnel intents. Each action validates referenced IDs before committing. Topology responses acknowledge the server commit and affected nodes; they do not prove that every client has already reconciled.

WireGuard, L2TPv2 and L2TPv3 share one monotonically increasing tunnel ID
sequence. Parent relationships are stored as tunnel dependencies and orphaned
descendants are removed on topology changes. The currently supported underlay
for L2TP is WireGuard between the same peers; other combinations are rejected.
After upgrading an existing database, refresh inventory because colliding legacy
L2TP IDs can change. Historical idempotency receipts are retained.

`/admin/invites` accepts an expiry, maximum use count, and optional mesh ID. Invite codes are returned only in the successful creation response. Invalidation removes the invite and prevents cached creation retries from returning the deleted code; already enrolled nodes are unaffected.

## Operational boundary

The server is a local authority backed by its configured SQLite database and control worker. Availability, backups, TLS termination, process supervision, and database recovery are deployment concerns outside this browser API.
