# Standalone server deployment

cat4igp-server is deployed as one process with one local database and one local control identity. Put an HTTPS reverse proxy in front of the server when using the administrator browser API; keep the server's private HTTP listener and database inaccessible to untrusted users.

For per-client login throttling behind a reverse proxy, set
`ADMIN_TRUSTED_PROXY_IP` to the proxy's exact source IP as seen by the server.
Configure that proxy to overwrite `X-Real-IP` with the verified client address;
never forward a client-supplied value. Without this setting proxied users share
one rate limit. The bounded throttle denies new addresses when its 16,384 active
buckets are full until a bucket expires; upstream rate limiting is recommended.

## First setup

The following Linux example uses Docker, Python 3 and a local image built from the repository. The control port must be reachable by clients; HTTP is bound to loopback on the host and must be served through an HTTPS reverse proxy. Commands that modify `/var/lib/cat4igp` require root. Choose a unique HTTPS origin with no trailing slash and an administrator password of at least 12 characters.

```sh
docker build -f server/Dockerfile -t cat4igp-server .
sudo install -d -m 700 -o 10001 -g 10001 /var/lib/cat4igp
sudo python3 - <<'PY'
import getpass, json, os, secrets
from pathlib import Path

root = Path('/var/lib/cat4igp')
os.umask(0o077)
with open('/dev/tty', 'r+') as tty:
    tty.write('Public HTTPS origin (e.g. https://controller.example): '); tty.flush()
    origin = tty.readline().strip()
    tty.write('Administrator username: '); tty.flush()
    username = tty.readline().strip()
    password = getpass.getpass('Administrator password: ', stream=tty)
if not username.strip() or len(password) < 12:
    raise SystemExit('A username and password of at least 12 characters are required')
files = {
    'control.psk': '/key/swarm/psk/1.0.0/\n/base16/\n' + secrets.token_hex(32),
    'jwt.json': json.dumps({'origin': origin, 'issuer': 'cat4igp', 'audience': 'cat4igp-admin',
                            'active': 'primary', 'keys': {'primary': secrets.token_hex(32)}}),
    'bootstrap.json': json.dumps({'username': username, 'password': password}),
}
for name, content in files.items():
    path = root / name
    with path.open('x') as f:
        f.write(content)
    os.chown(path, 10001, 10001)
PY
docker run -d --name cat4igp \
  -p 127.0.0.1:8080:8080 -p 9000:9000 \
  --mount type=bind,src=/var/lib/cat4igp,dst=/data \
  -e CONTROL_PRIVATE_NETWORK_KEY_FILE=/data/control.psk \
  -e ADMIN_JWT_CONFIG_FILE=/data/jwt.json \
  -e ADMIN_BOOTSTRAP_FILE=/data/bootstrap.json cat4igp-server
docker logs cat4igp
curl --fail http://127.0.0.1:8080/
```

The logs should show the control listener and the request should return the controller banner. This only checks that the process and HTTP listener started, not client connectivity. If startup fails, inspect the logs; do not remove the bootstrap file until administrator creation has succeeded. Once startup succeeds, remove the one-time bootstrap setting and credentials before restarting; otherwise the next start fails because the account already exists:

```sh
docker stop cat4igp && docker rm cat4igp
sudo rm /var/lib/cat4igp/bootstrap.json
docker run -d --name cat4igp --restart unless-stopped \
  -p 127.0.0.1:8080:8080 -p 9000:9000 \
  --mount type=bind,src=/var/lib/cat4igp,dst=/data \
  -e CONTROL_PRIVATE_NETWORK_KEY_FILE=/data/control.psk \
  -e ADMIN_JWT_CONFIG_FILE=/data/jwt.json cat4igp-server
```

Build the frontend with `cd frontend && npm ci && npm run build`; serve `frontend/dist` at the configured HTTPS origin and proxy `/admin` to `http://127.0.0.1:8080/admin`, preserving the request path and Origin. Verify login and inventory through that HTTPS origin. Restrict the control port to intended clients where possible. The PSK must be shared securely with enrolling clients; it is not a substitute for protecting the database and administrator credentials.

The image runs as UID/GID 10001 and stores SQLite and its automatically generated control identity under `/data`. `CONTROL_PRIVATE_NETWORK_KEY_FILE` is an image entrypoint convenience; native binary deployments use `CONTROL_PRIVATE_NETWORK_KEY` with the file's contents, and must also set `DATABASE_URL`, `BIND_HOST_PORT`, and `CONTROL_BIND_MULTIADDR`. Automatic migrations are enabled by default; set `AUTO_MIGRATE=false` to require an explicit `cat4igp-server migrate` before startup. In Docker, run that command against the same stopped database with `docker run --rm` and the same `/data` mount, passing `migrate` after the image name.

Use separate credentials and database paths for separate environments. Do not clone a live database or control identity as a replacement for another installation. Protect database backups: they contain administrator password hashes, network metadata, and enrollment receipts with invitation codes. L2TPv2 secrets are also stored in plaintext.
Clients report enabled WireGuard, L2TPv2, L2TPv3, FEC and FakeTCP support over
their authenticated control connection. Administrator inventory exposes
`server_features` and each node's last reported `features`; `null` means the
node has not reported, not that it supports every feature. New L2TP tunnels
require both nodes to report the required version (and WireGuard for an
underlay). WireGuard answers require both peers' reported flags. Feature reports
are last observed, not live health checks; deploy updated clients alongside the
server, since older clients cannot perform the feature exchange. Cached topology
remains available for best-effort offline recovery.


## Upgrades and recovery

Stop the process before replacing its binary, configuration, or database. Back up the database and configuration as a matched set, record checksums, and verify restore procedures against a disposable copy. Apply repository migrations through the server's migration workflow; do not edit migration SQL after it has been published. Historical migrations, including older migration directories, are retained for reproducible setup and rollback analysis.

The global tunnel-ID migration preserves WireGuard IDs but renumbers L2TP rows
whose IDs collide with another tunnel type. It increments affected nodes' topology
revisions; their L2TP interfaces are recreated on reconciliation. Before upgrading,
stop the server, drain administrator requests, back up the database, and refresh
inventory after migration rather than reusing saved L2TP IDs. Coordinate writers
and clients; older binaries must not write the migrated database. Downgrade of this
migration is refused while any L2TP records or dependencies remain.

Enrollment request IDs are scoped to the authenticated peer after the
`2026-11-17` migration. Downgrade to global uniqueness fails if two peers have
used the same request ID; do not delete successful enrollment receipts to force
the downgrade, because they preserve safe retry semantics.

A database restore can recover only the state present in that backup. It does not prove that recent writes were present, that a previously running process is stopped, or that clients have reconciled. Fence the old process and ingress before restoring, then verify administrator login, inventory, client enrollment, and tunnel reconciliation.

### Offline backup and restore

This example uses the Docker setup above, Python 3's SQLite module, and root on the host. First block administrator and control ingress, drain requests, stop `cat4igp`, and fence every other process, scheduled job, host, and restart mechanism that could access the database or serve the same control identity. Confirm the container is stopped (`docker inspect -f '{{.State.Running}}' cat4igp` must print `false`). Keep the fence in place through the backup; for recovery, keep it until the replacement is ready and the old instance cannot return. `docker stop cat4igp` alone does not fence another host. Adapt paths and service controls for native deployments.

For the example container, after blocking ingress and draining requests, disable its restart policy and stop it:

```sh
docker update --restart=no cat4igp
docker stop cat4igp
test "$(docker inspect -f '{{.State.Running}}' cat4igp)" = false
```

Also disable any external service manager or automation that recreates it. Re-enable the intended restart policy only after recovery is accepted.

Run the following as root after fencing. Record the printed backup directory and the server image version, deployment settings, proxy configuration, and matching external secrets in the same protected backup set. The database contains the controller signing and encryption identities. This takes a SQLite online-backup snapshot, which includes committed WAL transactions; never copy only `cat4igp.db` from a live or uncheckpointed WAL database. Missing source files or a failed integrity check abort the procedure.

```sh
set -eu
umask 077
backup=$(mktemp -d /var/lib/cat4igp-backup.XXXXXXXX)
python3 - "$backup" <<'PY'
import pathlib, sqlite3, sys
dest = pathlib.Path(sys.argv[1]) / 'cat4igp.db'
src = sqlite3.connect('file:/var/lib/cat4igp/cat4igp.db?mode=rw', uri=True)
with sqlite3.connect(dest) as dst:
    src.backup(dst)
    if dst.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
        raise SystemExit('backup integrity check failed')
src.close()
PY
install -m 600 /var/lib/cat4igp/control.psk /var/lib/cat4igp/jwt.json "$backup/"
(cd "$backup" && sha256sum cat4igp.db control.psk jwt.json > SHA256SUMS)
printf 'Backup: %s\n' "$backup"
```

Store the set encrypted with restricted access, protect its checksum manifest against tampering separately, and test recovery periodically. Include any other deployment-specific configuration and secrets securely; do not retain the one-time bootstrap password unnecessarily. Checksums detect accidental corruption, not malicious replacement of both data and manifest.

To restore, first fence ingress and **all** old writers and prevent automatic restarts, as above. Select the verified backup directory explicitly; the commands below move the current database and its WAL/SHM sidecars into an owner-only quarantine rather than mixing them with the restored snapshot. Preserve that quarantine until recovery is accepted. Run as root, with enough free disk space:

```sh
set -eu
umask 077
backup=/var/lib/cat4igp-backup.REPLACE_WITH_SELECTED_BACKUP
(cd "$backup" && sha256sum -c SHA256SUMS)
python3 - "$backup/cat4igp.db" <<'PY'
import pathlib, sqlite3, sys
uri = pathlib.Path(sys.argv[1]).resolve().as_uri() + '?mode=ro'
with sqlite3.connect(uri, uri=True) as db:
    if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
        raise SystemExit('restore integrity check failed')
PY
quarantine=$(mktemp -d /var/lib/cat4igp-before-restore.XXXXXXXX)
for name in cat4igp.db cat4igp.db-wal cat4igp.db-shm control.psk jwt.json; do
  if [ -e "/var/lib/cat4igp/$name" ]; then
    mv -- "/var/lib/cat4igp/$name" "$quarantine/"
  fi
done
install -o 10001 -g 10001 -m 600 "$backup/cat4igp.db" /var/lib/cat4igp/cat4igp.db
install -o 10001 -g 10001 -m 600 "$backup/control.psk" "$backup/jwt.json" /var/lib/cat4igp/
printf 'Previous files: %s\n' "$quarantine"
```

If any step fails, leave the service fenced and recover the previous files from quarantine or repeat the restore; do not start with a partial set. Restore other matching configuration and secrets before starting exactly one compatible server. Check logs and SQLite integrity, then lift ingress deliberately and verify HTTPS administrator login and inventory, client enrollment, and tunnel reconciliation. Restoring older state can lose later writes and resurrect revoked credentials or invitations; review and revoke or rotate them as appropriate. Never connect a disposable restore to production clients or ingress.

The following isolated, runnable scenario exercises a committed transaction still in WAL, the same SQLite backup API, and integrity and content verification without touching production files:

```sh
python3 - <<'PY'
import pathlib, sqlite3, tempfile
with tempfile.TemporaryDirectory() as tmp:
    live, snapshot = (pathlib.Path(tmp) / name for name in ('live.db', 'snapshot.db'))
    src = sqlite3.connect(live)
    src.execute('PRAGMA journal_mode=WAL')
    src.execute('PRAGMA wal_autocheckpoint=0')
    src.execute('CREATE TABLE example (value TEXT)')
    src.execute("INSERT INTO example VALUES ('committed in WAL')")
    src.commit()
    assert pathlib.Path(str(live) + '-wal').stat().st_size > 0
    with sqlite3.connect(snapshot) as dst:
        src.backup(dst)
        assert dst.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        assert dst.execute('SELECT value FROM example').fetchall() == [('committed in WAL',)]
    src.close()
print('WAL backup and restore verification passed')
PY
```

## Security checklist

Use HTTPS with certificate and hostname verification, Secure HttpOnly SameSite=Strict host-only cookies, exact Origin validation, restrictive CSP, and request rate/body/time limits. Keep `ADMIN_JWT_CONFIG_FILE`, `ADMIN_BOOTSTRAP_FILE`, private-network keys, control identities, and database backups owner-only. Do not log passwords, cookies, invite codes, private keys, or full enrollment bundles.

The administrator API is local to this server. Do not infer client reconciliation or durable recovery from process health alone or from a successful database restore.
