# Server container

CI builds native `linux/amd64` and `linux/arm64` (aarch64) images and publishes
a combined image to `ghcr.io/<owner>/<repository>-server`. The runtime is
Alpine 3.23 with system SQLite; Rust 1.94.0 builds only the server.

Default-branch commits and untagged manual builds use the first **seven
characters of the Git commit SHA** as their SNAPSHOT tag, for example
`ghcr.io/badaimweeb/cat4igp-server:4ab12cd`. Release tags use `vX.Y.Z`, matching
`server/Cargo.toml`. No rolling `latest` tag is published. Manual runs on a
release tag publish that version. The combined tag is published only after
both architectures build and pass runtime payload checks. GHCR visibility
and access are managed through the repository's GitHub Packages settings.

## Runtime configuration

The image runs as UID/GID **10001:10001** without root privileges. Mount
persistent storage at `/data`, writable by that UID; its default database is
`/data/cat4igp.db`. Database settings include persistent controller identities,
so keep backups and never discard the volume on an ordinary upgrade.

Set these environment variables through your deployment's secret/configuration
mechanism (do not bake credentials into the image):

- `DATABASE_URL`: optional override of `/data/cat4igp.db`.
- `BIND_HOST_PORT`: operator HTTP listener, e.g. `0.0.0.0:8080`.
- `CONTROL_BIND_MULTIADDR`: control listener, e.g. `/ip4/0.0.0.0/tcp/4001`.
- `CONTROL_PRIVATE_NETWORK_KEY`: complete libp2p PSK key-file **contents**, not a path.
- `OPERATOR_AUTH_KEY`: operator API authentication secret.

Publish the chosen HTTP/control TCP ports explicitly. The operator endpoint
uses plain HTTP: restrict access or put it behind authenticated TLS termination.
WireGuard privileges/devices are not required for the server.

## Database migrations

Migrations are included at `/usr/share/cat4igp/migrations`, but the server does
**not** automatically apply them. Before first startup, initialize the database
with the existing Diesel migrations using an administrator-managed migration
tool. Apply pending migrations before upgrades with the server stopped and a
backup taken; retain the migration ledger. Never replay all `up.sql` files on
an existing database. The SQLite CLI/Diesel CLI is intentionally not installed
in the runtime image.

Local builds use `server/Dockerfile` with the repository root as build context.
The `.dockerignore` excludes Git data, build outputs, environment files and
SQLite databases. Neither registry publication nor arm64 testing is performed
by a local amd64 build.