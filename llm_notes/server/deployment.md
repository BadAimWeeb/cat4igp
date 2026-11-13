# Standalone server deployment

cat4igp-server is deployed as one process with one local database and one local control identity. Put an HTTPS reverse proxy in front of the server when using the administrator browser API; keep the server's private HTTP listener and database inaccessible to untrusted users.

## First setup

1. Create an owner-only server configuration, database directory, control identity, and private-network key.
2. Run `cat4igp-server migrate` for a fresh or supported standalone database.
3. Configure the control worker and listener addresses.
4. Configure `ADMIN_JWT_CONFIG_FILE` with the public HTTPS origin and high-entropy signing key.
5. Set `ADMIN_BOOTSTRAP_FILE` for the one-time administrator, start the server, and remove the bootstrap file after successful creation.
6. Serve the built frontend through the same HTTPS origin and proxy `/admin` to the server.

Use separate credentials and database paths for separate environments. Do not clone a live database or control identity as a replacement for another installation. Protect database backups because they contain administrator password hashes and network metadata.

## Upgrades and recovery

Stop the process before replacing its binary, configuration, or database. Back up the database and configuration as a matched set, record checksums, and verify restore procedures against a disposable copy. Apply repository migrations through the server's migration workflow; do not edit migration SQL after it has been published. Historical migrations, including older migration directories, are retained for reproducible setup and rollback analysis.

The global tunnel-ID migration preserves WireGuard IDs but renumbers L2TP rows
whose IDs collide with another tunnel type. It increments affected nodes' topology
revisions; their L2TP interfaces are recreated on reconciliation. Before upgrading,
stop the server, drain administrator requests, back up the database, and refresh
inventory after migration rather than reusing saved L2TP IDs. Coordinate writers
and clients; older binaries must not write the migrated database. Downgrade of this
migration is refused while any L2TP records or dependencies remain.

A database restore can recover only the state present in that backup. It does not prove that recent writes were present, that a previously running process is stopped, or that clients have reconciled. Fence the old process and ingress before restoring, then verify administrator login, inventory, client enrollment, and tunnel reconciliation.

## Security checklist

Use HTTPS with certificate and hostname verification, Secure HttpOnly SameSite=Strict host-only cookies, exact Origin validation, restrictive CSP, and request rate/body/time limits. Keep `ADMIN_JWT_CONFIG_FILE`, `ADMIN_BOOTSTRAP_FILE`, private-network keys, control identities, and database backups owner-only. Do not log passwords, cookies, invite codes, private keys, or full enrollment bundles.

The administrator API is local to this server. Do not infer client reconciliation or durable recovery from process health alone or from a successful database restore.
