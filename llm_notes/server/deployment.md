# Standalone server deployment

cat4igp-server is deployed as one process with one local database and one local control identity. Put an HTTPS reverse proxy in front of the server when using the administrator browser API; keep the server's private HTTP listener and database inaccessible to untrusted users.

For per-client login throttling behind a reverse proxy, set
`ADMIN_TRUSTED_PROXY_IP` to the proxy's exact source IP as seen by the server.
Configure that proxy to overwrite `X-Real-IP` with the verified client address;
never forward a client-supplied value. Without this setting proxied users share
one rate limit. The bounded throttle denies new addresses when its 16,384 active
buckets are full until a bucket expires; upstream rate limiting is recommended.

## Client artifact provenance

For a tagged GitHub release, download the appropriate client package or binary
and verify each file before installation with GitHub CLI, using the expected
repository rather than a value supplied by the download source:

```sh
gh attestation verify <artifact> --repo <owner>/<repo>
```

Inspect the verified workflow identity and release revision against the expected
repository and tag; verify the appropriate dependency manifest and `SHA256SUMS`
separately if using them. Matrix build jobs attest each client artifact and its
dependency manifest; the publishing job verifies those attestations, then attests
the assembled files and `SHA256SUMS`. It re-downloads the draft and verifies
checksums and attestations for the expected workflow, source revision and tag
before publishing. This updated tagged release path has not yet been verified on
an actual tagged run; verify published artifacts independently rather than assuming it ran.
Availability depends on repository and plan settings. The dependency manifest
records installed build-container packages, not every transitive input. Workflow
provenance does not prove that mutable build-time distribution repositories or
unsigned feeds are trustworthy; secure and verify those sources independently.
A checksum alone is not provenance. See the [package guide](../packaging/packages.md)
for manifest scope and package-specific trust limits.

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

For each client, provide a version 1 enrollment bundle over a trusted channel with
the controller's IP/TCP/p2p bootstrap addresses, peer ID, hex-encoded protobuf
signing public key, network ID, private-network PSK contents, and invitation code.
The [client enrollment guide](../client/configuration.md#trusted-enrollment-bundle)
lists the exact JSON field names and import command. Treat the bundle as a secret;
do not log it or put its key or addresses in client TOML/JSON configuration. The
client daemon stores its enrollment in private `server.json`; preserve that state
when upgrading clients.

The image runs as UID/GID 10001 and stores SQLite and its automatically generated control identity under `/data`. `CONTROL_PRIVATE_NETWORK_KEY_FILE` is an image entrypoint convenience; native binary deployments use `CONTROL_PRIVATE_NETWORK_KEY` with the file's contents, and must also set `DATABASE_URL`, `BIND_HOST_PORT`, and `CONTROL_BIND_MULTIADDR`. Automatic migrations are enabled by default; set `AUTO_MIGRATE=false` to require an explicit `cat4igp-server migrate` before startup. In Docker, run that command against the same stopped database with `docker run --rm` and the same `/data` mount, passing `migrate` after the image name.

Use separate credentials and database paths for separate environments. Do not clone a live database or control identity as a replacement for another installation. Protect database backups: they contain administrator password hashes, network metadata, and enrollment receipts with invitation codes. L2TPv2 secrets are also stored in plaintext.

The container entrypoint sets `umask 077` before starting the server, so newly
created database and SQLite sidecar files are private to its UID. This does not
repair existing files or secure an exposed parent directory or backups. Before
starting an existing deployment, fence all writers and restrict the database,
its `-wal` and `-shm` sidecars, and the containing directory to the service
account; verify ownership, ACLs and permissions without deleting sidecars. Native
deployments must set a restrictive umask (for example, systemd `UMask=0077`)
and protect the directory and existing files themselves. These permissions do not
encrypt the database or defend against the service account, root, storage theft,
or an attacker with access to unencrypted backups; use encrypted storage and the
independently managed backup encryption and key custody described below.
Clients report enabled WireGuard, L2TPv2, L2TPv3, FEC and FakeTCP support over
their authenticated control connection. Administrator inventory exposes
`server_features` and each node's last reported `features`; `null` means the
node has not reported, not that it supports every feature. New L2TP tunnels
require both nodes to report the required version (and WireGuard for an
underlay). WireGuard answers require both peers' reported flags. Feature reports
are last observed, not live health checks; deploy updated clients alongside the
server, since older clients cannot perform the feature exchange. Cached topology
remains available for best-effort offline recovery.


## Deployment workload and acceptance scope

The user-reported target is 80+ nodes carrying mixed traffic. Available test
resources limit the reference deployment to five nodes; this is a resource-limited
reference test, not a reduced production target. Traffic rates, traffic mix
proportions and production performance guarantees have not been specified.

The requested acceptance posture is best effort. Availability requirements and
RPO/RTO remain undecided; best effort does not select those policies or imply a
numerical service guarantee. Record measured reference results and their workload
and environment without inventing throughput, latency, loss or recovery promises.
A successful five-node reference test establishes only the behavior exercised in
that test: it does not establish capacity for 80+ nodes, production acceptance or
closure of the availability and recovery decisions below. Existing two-client
reference modes retain their narrower scope.

## Availability and backup policy

This is a single-controller deployment, not an automatic highly available cluster.
The operator owns supervision, alert delivery and recovery: choose an on-call owner,
alert destinations and response times, and monitor the host, disk capacity, container
or service process, HTTPS proxy and certificate expiry. The Docker restart policy
above restarts an exited container; it does not repair a hung process, failed proxy,
unreachable clients, lost disk or a broken data path. Use independent external
checks of administrator HTTPS and control reachability as well as the client and
path checks below. Alert on missing checks as well as failures, and verify alerts
reach the responsible operator. Do not start a second writer against the database
or serve the same control identity concurrently as a failover shortcut.

Before production, the operator must choose and record a recovery point objective
(RPO: maximum acceptable lost committed changes) and recovery time objective
(RTO: maximum acceptable elapsed time from disruption to restored service). Select
the backup schedule and off-host transfer frequency to meet the RPO, accounting for
backup failures and transfer delay; alert on stale or failed backups. Select staffing,
replacement capacity, credentials and restore procedures to meet the RTO. The offline
backup below requires downtime, so its frequency must also fit the availability
budget. Measure actual lost changes and time through an isolated end-to-end restore
drill; neither a backup interval nor a process restart establishes an achieved RPO
or RTO.

Encrypt each complete backup set before off-host transfer and at rest with an
operator-managed encryption system; the snapshot commands below create plaintext
files and do not encrypt them. Restrict access to backups and keys separately, keep
recoverable key copies outside the failed host, and test decryption during restore
drills. Retain protected copies in a separate failure domain according to an
operator-chosen retention policy. Protect temporary plaintext snapshots and restore
quarantine with owner-only permissions, then securely dispose of them according to
the site's storage policy once no longer needed. Include controller database, matching
configuration and secrets, and protected client state; they contain control keys,
invitation receipts and plaintext L2TPv2 CHAP secrets. Record backup ownership,
encryption/key recovery, retention, schedule and the last successful restore drill.

The deployment owner must decide the RPO, RTO, maintenance windows, alert thresholds,
on-call coverage, backup destination and retention, encryption and key custody,
replacement host and fencing mechanism, and acceptable client/data-path outage. None
can be inferred from the software or the example commands.

Record a deployment-specific decision before accepting service, and review it after
topology, workload or staffing changes. The record must identify the service owner
and approver, the time zone and measurement period, and these values with evidence:

| Decision | Deployment value and evidence required |
| --- | --- |
| Availability | Required service hours, permitted planned and unplanned outage, alert destinations and response coverage. |
| RPO | Maximum age of recoverable committed state and which enrollment, revocation and topology changes may be lost. Include backup runtime, off-host transfer, detection and missed-backup response in the budget. |
| RTO | Maximum elapsed time from disruption to verified service, including detection, notification, fencing, key access, restore, reconciliation and data-path verification. |
| Recovery resources | Backup frequency and retention, independent encrypted destination and key custodian, replacement host, fencing authority and responsible operator. |
| Acceptance limits | Per-path throughput, packet loss, latency, convergence and outage limits at the intended node/tunnel counts and load, including peak and failure conditions. |
| Evidence | Dated staging results, workload and environment, observed loss and recovery times, remaining exceptions, owner approval and next drill date. |

An unset value or missing, failed or stale evidence is not acceptance. A backup
interval alone cannot establish RPO: establish the age of the latest recoverable,
off-host verified snapshot at incident time, and compare actual lost committed
changes to the permitted loss. HTTP probe recovery is not full-service RTO; stop
the clock only after the required clients and data paths work. If the offline backup
downtime or the measured recovery exceeds the selected objectives, change the
deployment or objectives with explicit owner approval before production.

### Reproducible reference-staging recovery

The reference drill uses two disposable enrolled Linux clients and one standalone
controller, dual-stack directly reachable WireGuard endpoints, and no external NAT.
It is not a production workload or availability-policy selection. Run in a
disposable VM with the prerequisites listed in the driver:

```sh
cargo build --locked -p cat4igp-server -p cat4igp-client
# Transfer both actual executables and server/tests/{restore_enrolled,https_management}.py
# to the VM, preserving the server/tests directory structure.
sudo python3 server/tests/restore_enrolled.py --confirm-disposable \
  --server /tmp/cat4igp-server --client /tmp/cat4igp-client
```

For the resource-limited five-node full-mesh reference, add `--nodes 5`.
Add `--reference-traffic-seconds 300` for eight concurrent hash-checked TCP/UDP
echo streams spanning all five nodes and both underlay families before restore.
Five-node mode verifies twenty links and eight interfaces per client; specialized
two-node modes are rejected. Debian 13 passed the five-minute traffic run and
subsequent restore. Restore verification includes sequential per-link probes and
must not be reported as packet-outage duration. Results are synthetic reference
measurements, not extrapolated 80+ node capacity or production SLO acceptance.
With at least 30 traffic seconds, add `--reference-controller-outage` to stop the
controller for five seconds during all eight active streams, restart the same
database, and verify fresh authenticated snapshots before streams finish.
The five-node 60-second run passed; stop-to-reconnection verification was 26.434 s.
Echo hashes/byte counts prove completed transfer, not zero packet-outage duration.

The driver uses ephemeral test encryption keys and reports omitted off-host,
detection, notification and key-retrieval intervals explicitly. A successful
reference result cannot approve production key custody, RPO/RTO, older-backup
reconciliation or deployment-specific NAT connectivity.

Add `--reference-soak` for a 60-second reference run: four 300-probe streams at
0.2-second intervals, controller stopped at 20 seconds and restarted at 30 seconds.
Acceptance is at most 1% loss per stream, at most two seconds of consecutive missing
probe intervals and authenticated reconciliation within 15 seconds after restart.
The report distinguishes sampling resolution from actual outage duration. These
small-topology thresholds are reproducible staging checks, not production SLOs.
Validate packet accounting with `python3 server/tests/test_restore_enrolled.py`.

Add `--offline-client-restart` to stop the controller and restart both enrolled
clients from retained state. The driver requires reconstructed links, fresh
handshakes and traffic while controller freshness remains Unknown, then requires
authenticated freshness after controller restart. This is cached-connectivity
evidence, not offline revocation enforcement or restrictive-NAT coverage.

Add `--damaged-cache-repair` to damage only the disposable clients' topology caches
while retaining valid version-2 revision journals. The driver requires matching
authenticated snapshot repair, exact cache/journal/port preservation and fresh
traffic. It does not repair lost journals or authorize coordinated state rollback.
With `--nodes 5`, only client0's cache is damaged and restarted while the other
four daemons stay running. The reference passed authenticated repair with all
eight bindings/identities retained and bidirectional traffic on all twenty links.

Add `--offline-revocation` (requires nftables) to isolate one client's controller
TCP path while keeping its cached data path, delete its node through the real
administrator API, and verify reachable-peer tunnel removal, traffic denial and
identity rejection after control reconnects. The isolated cache remains: this
demonstrates containment against a reachable peer, not erasure or enforcement on
every disconnected peer, and does not exercise NAT traversal.
With `--nodes 5`, this mode verifies all four reachable peers remove the eight
revoked links while all twelve survivor links retain identities and pass traffic.
The reference run passed; isolated cached intent persists and requires independent
edge containment when other peers are also disconnected from the controller.
The deployment owner accepts continued cached connectivity when both peers lose
controller access. When one peer is reachable, only tunnels still returned as
valid by its authenticated controller may remain; authenticated deletion overrides
cached intent on that peer. This policy accepts delayed revocation between two
disconnected peers; it does not make an unseen revocation enforceable offline.
Required paths also include both-peers CGNAT without forwarding and TCP-only
egress. Direct UDP/static forwarding and TCP-shaped FakeTCP do not establish those
paths: they need verified rendezvous/relay or a genuine TCP-stream transport.
The owner explicitly deferred data-plane relay implementation. Consequently
both-peers CGNAT without forwarding and TCP-only egress remain unsupported;
do not deploy assuming those required paths work or mark connectivity acceptance complete.

Add `--endpoint-roaming` to change one client's advertised IPv4/IPv6 addresses
through authenticated daemon IPC and remove its old addresses. Peer kernel endpoints,
authenticated topology cache and traffic must converge without changing enrolled
identities or restarting clients. This direct-underlay case does not cover NAT.
This mode also supports `--nodes 5`: all eight links affected by one node's
address change must converge, and all twenty mesh links must pass traffic.
The reference run passed with unchanged identities and fresh snapshots; complete
verification time includes sequential probes and is not a packet-outage measure.

For an actual Debian package transaction against enrolled clients, run the driver
with `--client /usr/bin/cat4igp-client --client-reinstall-deb /path/to/installed-version.deb`.
This two-node mode requires matching installed package name/version/architecture,
performs `dpkg --force-confold -i`, checks enrollment/cache/journal bytes across
the transaction, then verifies identities, ports, authenticated freshness and traffic.
The November Debian artifact passed in a disposable VM. It is explicitly a
same-version reinstall, not a version upgrade, reboot or systemd lifecycle drill.
On Arch, use `--client-reinstall-arch /path/to/installed-version.pkg.tar.zst`
instead; this validates package metadata and runs actual `pacman -U --noconfirm`.
The d4ded0e231d9 artifact passed enrolled reinstall, packaged service and real
reboot phases on x86-64. The older 34af artifact lacks authenticated freshness
tracking and cannot satisfy this driver's acceptance checks; do not bypass them.
Add `--packaged-service` to run enrolled clients through runtime copies of the
installed systemd unit and actual systemctl lifecycle. Scoped overrides supply
drill namespaces, configuration, state/runtime directories and logging; packaged
stop/cgroup settings remain in force. Debian 13 passed this mode through reinstall
and authenticated traffic recovery. Generated units are cleaned up; default-path
boot ordering, reboot persistence and cross-architecture upgrades remain unverified.
Add `--packaged-crash-recovery` to signal the owned unit's main process with
SIGKILL and require automatic on-failure restart, a changed MainPID and increased
restart counter before authenticated traffic recovery. The Debian native WireGuard
reference passed without manual tunnel deletion; PPP and machine reboot are excluded.

For actual reboot verification, add `--prepare-reboot /opt/readiness/reboot-fixture`
to the packaged-service command. Preparation reports PREPARED, not PASS, and
installs uniquely owned persistent boot units plus protected controller/client state.
Reboot the disposable VM, observe console readiness, then run the driver with
`--confirm-disposable --verify-reboot /opt/readiness/reboot-fixture`.
Verification requires a changed boot ID and automatically active units before
checking retained identities/ports/revision floors, freshness and real traffic.
Debian amd64 passed this scoped fixture; verification time is not boot-time RTO.
Finally run `--confirm-disposable --cleanup-reboot /opt/readiness/reboot-fixture`;
cleanup validates unit ownership, removes fixture units/topology and retains secret
state for explicit secure disposal. Never run these phases on production systems.

Add `--client-crash-recovery` to SIGKILL and restart an actual enrolled daemon
without deleting surviving kernel WireGuard devices; identities, ports, interface
indices, authenticated freshness and sampled traffic must survive. PPP is excluded.
For a compatible prior executable, `--client-upgrade-from /path/to/old/client`
enrolls and verifies traffic with that artifact, then replaces it with `--client`
using the same state and records both SHA256 hashes. Unsupported historical
enrollment CLIs fail explicitly; this is not a package-manager or reboot drill.
For combined restart/cache-repair and `--endpoint-roaming` drills, freshness is
observed per client: each must report a verified snapshot newer than the roaming
request while its age is at most five seconds. Independent 30-second pollers need
not satisfy that five-second window simultaneously. All clients must still pass
the driver's current-age bound, endpoint/cache convergence, identity preservation
and bidirectional traffic checks. A reference pass does not establish intended
restrictive-NAT paths or a production interruption budget.
The driver enables ICMP datagram probes for group 0 only inside its newly owned
client network namespaces (`net.ipv4.ping_group_range=0 0`). This avoids giving
native WireGuard fixtures CAP_NET_RAW solely for ping; it does not alter host
policy or prove minimum daemon/helper privileges. The Arch reference passed with
CAP_NET_ADMIN/CAP_SYS_ADMIN and NoNewPrivileges; namespace orchestration still
uses CAP_SYS_ADMIN, and other backend/non-root profiles require separate proof.


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

When an independently protected, trusted reference backup is available, compare it
with a candidate restore before reopening ingress:

```sh
python3 tools/compare_controller_backups.py REFERENCE CANDIDATE
```

Both arguments are protected, self-contained offline SQLite backup copies, not live
databases; use the snapshot procedure below and do not discard SQLite sidecars from
a live database. The tool rejects sidecars and mismatched or unsupported schemas.
It reports identity and revision changes, allocation high-water regressions,
selected topology and key differences, and revocation and enrollment receipt
differences. Topology comparisons report counts rather than secret values. Exit 0
means no selected differences, 2 means differences, and 1 means inspection failed.
Investigate differences against independently protected incident and change records;
the tool does not repair state. No result proves either backup is current,
complete, authentic or safe to restore, or that no events were lost.

### Older controller recovery boundary

There is currently no supported rollback-safe procedure for bringing an older
controller backup back into service for existing enrollments. Fence all controller
writers and ingress, preserve the backup and incident evidence, and independently
contain affected clients and tunnel endpoints. A restored controller retains its
signing identity but may have forgotten later enrollments, revocations, consumed
invitations, allocated IDs, topology changes and revisions. It can consequently
authenticate an identity that was revoked, reuse an ID, or sign different topology
at a previously accepted revision. Clients that retain a newer revision reject
older snapshots; this does not reconstruct the lost controller state or revoke an
offline client. Never lower client revision floors or discard caches to make the
restored controller appear current.

To authorize recovery of existing identities, an operator would need independent,
authenticated and complete records through the last possible acknowledged write,
including all enrollment and revocation decisions, identity and ID allocation,
invitation consumption, topology mutations, and each client's accepted revision and
same-revision topology. The operator would also need to reconcile those records
without reusing identities or revisions, verify every affected client and revocation,
and fence the old controller permanently. Neither the database backup nor the
comparison tool establishes completeness or currentness, and the software has no
validated transaction or recovery procedure that performs this reconciliation.
If that evidence or procedure is unavailable, keep ingress and affected data paths
contained; an operator assertion or a clean comparison is not proof of safe recovery.

#### Owner-selected alternative: new-network enrollment

When current trust history is unavailable, the owner selects a new network rather
than restoring old enrolled identities. This is a destructive trust cutover, not
older-backup reconciliation or journal repair. Keep the old network contained
throughout; production backup/key policy remains undecided.

1. Inventory all clients, administrators, old controller endpoints and data paths.
   Permanently fence the old controller identity, its hosts, replicas and restart
   automation. Independently block old peer traffic: two disconnected clients may
   continue cached links despite a controller fence.
2. Preserve protected forensic copies of old databases, enrollment state, revision
   journals and configuration. Do not import them into the replacement network or
   lower their revision floors. Do not delete unmanaged host networking resources.
3. Provision a separate empty controller database and fresh controller signing,
   encryption and private-network keys, network identity, administrator credentials
   and invitations. Verify the new controller identities differ from the old ones
   before issuing bundles. Do not copy old revocation/enrollment receipts as proof
   that an identity belongs in the new network.
4. Independently authorize each member again. On each contained client, stop the
   old daemon and preserve its complete state; provision a separate protected state
   directory with fresh client/WireGuard keys and enroll using a verified new
   trusted bundle. Do not reuse the old enrollment or bypass its rollback checks.
5. Verify fresh authenticated snapshots and peer identities, intended links,
   negative access for excluded members, ownership-safe cleanup and reboot recovery.
   Release containment only for accepted new-network paths; keep old credentials
   and endpoints permanently fenced, including clients not yet migrated.

This procedure design has not been executed as an old-to-new cutover drill.
Closure requires a disposable regression proving old credentials are rejected by
the new controller, excluded members cannot rejoin, old cached paths stay fenced,
and only explicitly reenrolled members pass traffic. Off-host key custody and
deployment fencing authority still require operator decisions and evidence.

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

If any step fails, leave the service fenced and recover the previous files from quarantine or repeat the restore; do not start with a partial set. Restore other matching configuration and secrets before starting exactly one compatible server. Check logs and SQLite integrity, then verify HTTPS administrator login and inventory, client enrollment, and tunnel reconciliation in isolation. Do not reopen production ingress or affected data paths for an older backup: the recovery boundary above applies even if these checks succeed. Never connect a disposable restore to production clients or ingress.

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

## Operational acceptance and recovery drills

Before production and after upgrades, record the deployed versions, intended topology,
client identities, tunnel IDs and expected reachability. Use dedicated test nodes and
non-production traffic; define the acceptable outage and recovery time for the deployment.
Record observations and elapsed times rather than treating a running process as success.

1. Verify HTTPS administrator login and inventory, and confirm that each enrolled node
   reports the expected features. Create a permitted tunnel between two test nodes; verify
   that both ends reconcile, `wg show` reports a recent handshake for WireGuard, and
   traffic traverses the intended link in both directions. Repeat for each tunnel type,
   address family and firewall/NAT path required in production. Verify an unauthorized
   administrator login is rejected and an allowed topology change reaches both clients.
2. Disconnect a test client's control path while retaining its data path, restart its
   daemon, and check whether its cached tunnels and traffic recover. Restore control
   connectivity, change or remove the test tunnel, and confirm both endpoints converge.
   Offline recovery is best effort, not a guarantee of reachability or current policy.
3. Exercise the backup and restore procedure below in an isolated environment containing
   a controller and at least two **already-enrolled** disposable clients with a working
   tunnel. Back up the stopped controller and preserve each client's protected state.
   Record the baseline inventory, peer identities, handshake and traffic. Make a deliberate
   post-backup change, fence the old controller and all writers, restore the matched backup,
   and start exactly one compatible controller. Reconnect the same clients without a new
   enrollment bundle or resetting their state. Confirm administrator login, the backed-up
   inventory and identities, client reconnection, tunnel reconciliation, a fresh handshake
   and bidirectional traffic. Confirm the post-backup change is absent, and measure the
   lost-write window and time to recovery against the deployment's targets. Record the
   snapshot's last committed change, successful off-host verification, simulated disruption,
   last acknowledged post-backup change, and verified service restoration times using a
   common clock; compare the lost changes as well as their age with the selected RPO.
   Include detection, notification, fencing and key retrieval in the measured RTO, or
   explicitly record any omitted interval and do not claim the objective was met. Investigate
   any mismatch before accepting the drill. Keep it isolated from production clients, ingress
   and routes: a copied identity must never serve alongside the original. Successful drill
   results do not authorize older-backup recovery of production identities; the recovery
   boundary above still applies. The SQLite-only example above tests snapshot mechanics,
   not this end-to-end recovery.

For controller capacity and recovery measurements, use an isolated staging
controller and inspect the available options with:

```sh
python3 tools/controller_benchmark.py load --help
python3 tools/controller_benchmark.py recovery --help
```

Both modes require `--url` and `--confirm-staging`; admin paths require a
short-lived `CAT4IGP_BENCH_COOKIE` session cookie. The default load pass requires
at most 1% failures, successful-request p95 at most 1000 ms, and at least 90%
of offered requests completed. Set thresholds and load to deployment targets.
Recovery requires a successful baseline, an operator-induced failure and restoration,
and by default three consecutive HTTP 200 responses with observed outage at most
30 seconds; the tool does not inject failure. Both modes output JSON and exit 0
on pass or 1 on failed thresholds. Protect the cookie and do not run against
production. These measure the selected HTTP endpoint, not client reconciliation
or representative tunnel/data-plane capacity: separately exercise live traffic
over the intended topology and measure its throughput, loss and recovery.

Before running, record hardware, versions, topology, client and tunnel counts,
NAT/firewall paths, background load, test duration and deployment-selected limits.
Run both peak-load and extended soak scenarios, collecting controller and client
CPU, memory, disk and network use as well as HTTP errors and latency. For each
required tunnel type and path, generate bidirectional traffic with independent
endpoints and record offered and achieved throughput, loss, latency, convergence
and interruptions. Repeat with representative churn and failure scenarios, including
unreachable peers, controller restart and a fenced restore with already-enrolled
clients. Record failure injection and recovery timestamps independently; polling
intervals and consecutive HTTP successes make the benchmark's observed outage an
approximation, not the time to restored data service. Compare every result with the
preselected limits and retain dated results, failures and operator sign-off in a
protected location. A passing HTTP result alone is not capacity or recovery acceptance.

For ongoing monitoring, run the health check on each client with one probe per
required path (repeat `--probe` for additional paths):

```sh
python3 tools/healthcheck.py --client /usr/bin/cat4igp-client --config /etc/cat4igp/client.toml --probe INTERFACE=PEER
```

Replace `INTERFACE` and `PEER` with the local interface and reachable peer address.
The check requires a verified, non-rollback controller snapshot pull within the
last 120 seconds by default; set `--max-controller-age SECONDS` to an appropriate
threshold for the deployment. The age resets on daemon restart and remains unknown
until the first verified pull; cached snapshots and unsolicited pushes do not count.
No pull yet, an expired age, reconciliation errors, and failed probes are critical.
Exit 0 means healthy, 2 critical, and 3 unknown; without a probe or with an older
client that does not report snapshot age, the result is unknown. Alert on both
critical and unknown. Fresh controller contact does not prove successful reconciliation,
reachability, or immediate revocation: use real per-path probes and independent checks.

### Revocation and network limits

Deleting a node revokes its control identity on the controller, but an isolated client
cannot receive a topology deletion or revocation and may continue using cached tunnels.
During an incident, do not wait for controller reconciliation: block the affected host or
its tunnel endpoints at independent host/edge firewalls, disable its network access, and
remove or rotate affected peer credentials on reachable systems as appropriate. Verify
traffic is actually blocked. When connectivity returns, verify the deleted identity is
rejected and surviving peers converge; review any stale clients before lifting containment.
Restoring an older database can undo revocations and revive invitations, so reconcile
against an independently protected incident/change record and reapply required revocations
before reopening ingress.

Direct mesh traffic has no data relay. STUN and UDP hole punching are best effort and can
fail under symmetric NAT, endpoint-dependent filtering or restrictive firewalls. Test the
actual paths; permit and, where needed, forward the configured tunnel ports or provide a
routable endpoint. FakeTCP requires a public hostname and TCP forwarding and is not a
guaranteed workaround. The optional fixed-target TCP control relay forwards control
traffic only, requires reachability on both legs, and cannot rescue a blocked data path;
see the [client guide](../client/configuration.md#fixed-target-client-control-relay).
If the required direct path cannot be established, the topology is not accepted; use an
independently provisioned routable path or change the network policy.

## Security checklist

Use HTTPS with certificate and hostname verification, Secure HttpOnly SameSite=Strict host-only cookies, exact Origin validation, restrictive CSP, and request rate/body/time limits. Keep `ADMIN_JWT_CONFIG_FILE`, `ADMIN_BOOTSTRAP_FILE`, private-network keys, control identities, and database backups owner-only. Do not log passwords, cookies, invite codes, private keys, or full enrollment bundles.

Plain L2TPv2 CHAP secrets are readable by privileged users on both endpoint hosts
and in controller state and backups; L2TPv2 alone is not an encrypted data path.
For untrusted networks, carry it inside a separately authenticated, encrypted
underlay such as WireGuard and verify that routing and firewall rules prevent
plaintext fallback. Restrict controller and client state, runtime secret directories,
backup staging and diagnostic output to the service owner or root; do not include
secrets in tickets, logs, shell history or benchmark results. Encrypt backups before
transfer and at rest, keep decryption keys in a separate failure domain, restrict
access and audit it, and exercise key recovery. Rotate affected credentials after a
suspected exposure and verify both endpoints have applied the replacement. Encryption
at rest does not protect secrets from a compromised running endpoint.

The administrator API is local to this server. Do not infer client reconciliation or durable recovery from process health alone or from a successful database restore.
