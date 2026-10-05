# Application schema/protocol compatibility

The HA application epoch is fixed at **1**, persisted in `raft_meta.application_version`
and required in Raft RPCs, replica join requests and snapshots. Missing/future epochs
reject before application replacement or admission; startup also requires the exact
embedded migration set. Only a standalone database with no Raft metadata/logs may
acquire its first epoch after explicit migrations. Existing unversioned HA databases
and snapshots are **not** auto-stamped: retain protected originals and use a reviewed
offline conversion; there is no bypass or rolling mixed-version upgrade. Coordinate
stop-all upgrades before deploying incompatible application schemas/protocols.

# Offline disaster-recovery verification (no force bootstrap)

Run the shipped `cat4igp-server verify-recovery` before manual recovery, with
`CLUSTER_MAINTENANCE_STOPPED=true`, `RECOVERY_FILE` (existing SQLite backup or
raw version-1 Raft JSON snapshot), `RECOVERY_KIND=database` or `snapshot`,
`DISCOVERY_CLUSTER_ID`, `DISCOVERY_SIGNING_KEY` (trusted protobuf public key hex),
and `RECOVERY_ENCRYPTION_KEY` (trusted X25519 public key hex). Pins must come from
the operator's independent trusted record, not be copied from the suspect backup.

The command starts no transport/Raft core and writes no source application data:
SQLite opens read-only in a consistent read transaction, runs `integrity_check`,
requires the exact embedded migration set, then validates application rows in an
in-memory current-schema DB. It checks logical identity, historical signed roster,
typed enrollment/invite/answer dedup, applied membership, local binding/vote/log
decoding and log bounds, and stored snapshot format/identity. Same-applied snapshot
and application must agree. Raw snapshots are capped at 16 MiB and exclude local
settings. Output contains only classification, flags, index, voter count and row
counts; errors intentionally redact SQL/JSON/keys. A local pristine replica DB is
not accepted as a legacy backup. Old/future schemas fail closed; this command does
not migrate historical files. Keep SQLite WAL with the DB or use an offline native
SQLite backup, never copy a live main file alone. SQLite may access/create read-only
WAL coordination sidecars; the maintenance flag is an attestation, not a process detector.

The runnable `offline_recovery_verifies_and_restores_fresh_application_without_local_identity`
test installs a verified snapshot into a fresh state-machine DB, preserves the
entire application image/client pins/consumed invite and exact enrollment/operator
retries, without transplanting vote/log/transport binding. This is not an admitted
live learner or a public restore command: normal learner admission/catch-up still
requires the existing quorum. `initialize` remains explicit pristine initialization
(or bounded standalone legacy import); `recover` retains same-replica local identity
and never reinitializes a lost quorum. No bypass/reset/automatic revival is added.

**Manual disaster recovery ceiling:** fence/stop all old replicas, retain protected
original backups and independent pins, select a recovery point and explicitly accept
loss of all later committed changes. Verification cannot prove freshness, RPO=0,
missing WAL detection, absence of an old live quorum, power-loss durability, or a
safe replacement membership. Lost-quorum membership reconstruction remains a separate
reviewed maintenance procedure, not something this command authorizes. Snapshots,
logs and backups contain private identities/dedup credentials; protect them like keys.

# Bounded committed-joint recovery rehearsal

`follower_retry_failover_and_minority` retains its 90-second bound and exercises
actual native promotion and roster-first removal of voter 9. A connection-local
SQLite TEMP trigger aborts the uniform membership log append only after joint
membership is durably applied. All four databases agree on the committed joint
configuration; the writer fails stop. Removal retains an incomplete tombstone,
withdraws both serving roster roles exactly once, and keeps the target's local
consensus transport binding alive before safe membership removal.

Recovery uses the same writer DB, identity and pinned configuration, then an
authorized follower explicitly retries removal through native OpenRaft. Remaining
replicas converge to uniform voters `{1,2,3}` and durable completed revocation;
exact join retry returns `Rejected` (no bootstrap credentials), activation,
promotion and serving grants remain denied, and duplicate revoke does not bump
the roster again. Existing static-bootstrap revocation regressions remain required.

`joint_removal_surviving_leader_authority` reuses that fault block but leaves the
failed writer stopped. Native election retries on one original survivor elect a
new leader with both original survivors and voter 9 alive: the joint configuration
requires 3/4 old voters and 2/3 new voters, so the two originals alone cannot elect.
All three survivors report the exact persisted joint membership and new leader;
quorum `Ready` and authoritative reads preserve logical keys, withdrawn roster
revision and incomplete revocation. This test stops there, without reintegration
or removal completion under the new leader.

ponytail: native SQL statement abort and in-process same-writer recovery only;
elections are disabled at the fault boundary, not quorum verification. No joint-stage
SIGKILL, power-loss/fsync interruption, old-writer reintegration under a competing
leader or automatic
completion is proved. Add those separate fault rehearsals when required; no
production gate lift or consensus/security changes.

# Coordinated transport credential maintenance

`POST /operator/transport_rotation` uses the existing authenticated operator middleware
and any-replica forwarding. Supply only `{ "cluster_id": "...", "generation": 1,
"fingerprint": "..." }`: fingerprint is lowercase SHA-256 of the canonical libp2p
`PreSharedKey::to_key_file()` bytes (including its trailing newline). Initial generation
is 0. Choose an independent random next key offline; never send it in this request.
The applied Raft record contains fingerprints only. Identical prepare retries succeed;
conflicting/stale generations, wrong cluster and unchanged key reject. Success requires
a quorum. Preparation does NOT replace the captured running pnet key.

While preparation is pending **all replica join credential release fails closed**,
including exact admission retries. Existing client PSK and logical signing/encryption
pins are untouched. Raw next keys never enter pubsub, Raft commands or responses.

Maintenance procedure (operator-attested stop-all, not an automatic rolling rotation):

1. Prepare while the old-key quorum is healthy; wait for every intended replica to
	apply the record. Stop **all** replicas and keep client/operator traffic closed.
2. On each replica run `cat4igp-server apply-transport-rotation`, setting
	`CLUSTER_MAINTENANCE_STOPPED=true`, `DATABASE_URL` to its existing local database,
	`CLUSTER_CONFIG_FILE` to its recover-mode config (remove legacy_import),
	`CLUSTER_NEXT_PSK_FILE` to the next canonical pnet key file, and
	`CLUSTER_ROTATED_CONFIG_FILE` to a new generation-specific output filename.
	Input config/key files must be regular owner-only files; output is create-new,
	mode 0600, fsynced and no-clobber. The command opens SQLite read-only, validates
	locally applied next fingerprint/cluster/generation and local replica binding,
	and leaves DB and old config unchanged. A lagging DB without preparation rejects.
3. Start every replica using the new config, then authenticate
	`POST /operator/transport_rotation/complete` (no body) through any replica.
	Only a runtime using the prepared key can complete, through a new-key quorum.
	Completion commits the new active generation and reenables matching join release.
	Verify every replica and readiness before reopening traffic; learners also need
	their applied record and new protected config before restart.

Versioned configs contain the raw local secret and `transport_generation`; protect
configs, backup volumes and previous keys. Join bootstrap carries the active generation
with its matching key. New-generation startup requires protected config permissions.
Startup pins local fingerprint/generation transactionally with replica bindings;
after new-key startup it refuses local rollback, and after applied completion old-key
startup rejects everywhere that has applied completion. An untouched stale database
can still start on its old key but cannot form a new-key quorum: do not reopen it.

ponytail: coordinated maintenance ceiling; no hot switch, key auto-distribution,
all-replica online readiness proof, automatic rollback or crash recovery. The stop-all
environment value is an explicit operator assertion, not a remote process detector.
Do not start a partial new-key group while old processes are alive. If interrupted,
inspect applied record/config/local generation and finish the same maintenance; never
erase local pins or overwrite consensus state to force rollback. OS kill/power-loss
and mixed stale-backup recovery remain TODO.

The bounded `three_node_offline_transport_rotation_rehearsal` uses three real
in-process Raft/SQLite/private swarms, restarts a prepared leader, stops all replicas,
publishes protected configs, and completes through a new-key quorum. After every
replica applies completion, a fresh authenticated replica uses the shipped pinned
public Noise discovery/join path through a follower: bootstrap and exact retry
deliver generation 1 and the exact new PSK, and protected `save_join` persists them.
Credential delivery does not activate membership. The fourth replica starts from
that protected config/current PSK, stops before activation or any applied authority,
then recovers the same DB/identity before explicit operator activation and catchup.
Wrong lower/higher generation and wrong PSK recoveries reject without changing its
durable credential or creating authority. A second restart retains applied state,
logical pins and transport generation.
It remains a learner (only voters 1–3), absent from both serving rosters. Only a
fresh learner may initially pin a nonzero generation before its rotation record
arrives; pre-catchup recovery requires the exact durable local credential.
existing replicas still require matching applied rotation/local credential state.
Old-config startup and a live old-PSK private transport remain denied.
After completion, the same test serves an actual follower `private_control_at`
listener with the unchanged independent client PSK (`0x12`, not the rotated cluster
PSK). The shipped client enrolls and reloads its saved pending identity for an
exact-response retry using the original logical signing pin and a signed roster
authorizing that private endpoint. Its keys, PSK, pin and proof stay unchanged;
the one-use client invite is consumed once and the original invite remains unused.
The whole test retains its 90-second ceiling; discovery and join retain their
native 10-second deadlines, and learner catchup uses the existing 10-second bound.
This is not learner promotion/serving, postrotation daemon restart or enrollment reply loss,
committed-joint interruption, privileged dataplane, process kill/power-loss, publication-fault coverage,
or a production gate lift; add those separate rehearsals when required.

# Offline legacy HA cutover

Stop the standalone server and upgrade clients before cutover. Keep its original
database and configuration untouched and protected; do not reopen it for writes
after the cluster accepts writes. Use the existing server launch command with
`CLUSTER_CONFIG_FILE` pointing to an explicit single-voter `mode: "initialize"`
config and `DATABASE_URL` pointing to a **nonexistent** destination. Add
`"legacy_import": {"source": "/absolute/legacy.sqlite", "backup": "/absolute/legacy-backup.sqlite"}`
to that config. The backup path must not exist. The cluster ID must equal the
legacy `control_network_id`; provision a distinct replica transport identity
and an independent private cluster PSK through the existing configuration.

Native SQLite `VACUUM INTO` creates a consistent mode-0600 backup, including WAL
contents. Only the backup is schema-migrated and read; the source is opened
read-only. The fresh destination is mode 0600. A bounded committed import
preserves logical signing/encryption keys, network, nodes, revisions, invites,
meshes, tunnels and durable retry results. Replica-local settings, votes, logs,
membership and transport keys are never imported. Any consensus/cluster authority
in the source rejects cutover; invalid identity, wrong network and imports above
512 KiB reject without source writes. Failed backups are retained, never silently
overwritten. Keep an additional archival copy if an unmigrated backup is needed.

After success remove `legacy_import` and switch to `mode: "recover"`. Initialize
is never automatically retried against an existing destination. An interrupted
destination needs explicit recovery/inspection: it may have committed only part
of initialization; do not serve it until logical identity and imported rows are
verified. Exact committed import replay is a no-op only on identical application
state; conflicts reject and malformed rows roll back. Configure the signed serving
roster/listeners explicitly, then join and catch up two learners, explicitly
promote them, and verify a three-voter quorum before reopening traffic.

ponytail: coordinated offline single-voter cutover only, maximum 512 KiB import
command; use staged snapshot seeding for larger databases. This is not disaster
recovery or a multi-voter import. Transport PSK generation/rotation remains pending:
do not change one live voter's PSK, which partitions consensus. No automatic
logical controller pin rotation, mixed-version upgrade or crash-safety claim.

# Explicit serving grants (bounded HA gate)

Signed rosters may carry optional `discovery_endpoints` (existing endpoint type,
at most 16 peers/four addresses each), explicitly identifying **public Noise
discovery listeners** of authorized serving peers. Never copy private PSK control
addresses into this field. `grant_serving` records only its validated
`public_address` here and rejects identical public/control listener addresses.
Authenticated operator roster updates must attest the listener role; an address
or PeerId alone cannot prove which transport it serves. Omission preserves old
roster signatures and provides no automatic public seed learning. Older binaries
with strict unknown-field decoding require coordinated upgrade before enabling it.
Upgraded clients persist/deduplicate these verified public addresses (16 total,
new signed seeds first), remove superseded learned seeds on refresh, and retain
remaining explicit bundle seeds as fallback. Expired cached seeds are reachability
hints only: fresh signed discovery still must pass the pinned key/revision checks.
This repairs bootstrap loss only after a valid public roster was learned; it
cannot recover a client whose only initial seed died before any trusted discovery.

`POST /operator/grant_serving` uses the existing operator authentication on any
replica and forwards the typed operation to the serialized leader. JSON fields:
`node_id`, `public_address` (public discovery), `control_address` (private client
control). Both addresses must be distinct bounded IP/TCP `/p2p/<PeerId>` addresses
bound to the same committed admitted replica identity. No credentials appear in
this request or in the signed roster; control addresses themselves are public metadata.

Only a stable committed voter caught up to the leader's applied log is eligible;
learners, unknown/revoked identities and lagging voters are refused. Admission and
promotion never grant serving rights. An initial roster must already exist.
Success (204) follows signed `Command::Roster` quorum commit and application;
invalid/conflicting grants return 409, unavailable quorum/leader returns 503.
Retry the identical endpoints: roster revision/lease do not change. Changing an
existing grant through this endpoint is refused; explicit roster administration
remains available and new/changed endpoints receive the same eligibility checks.
New grants advance revision and expiry; existing committed renewal and verifier
refresh apply without static fallback revival.

These are operator-attested listener addresses, not authenticated reachability
probes or listener provisioning. Configure the corresponding listeners separately.
Limits remain 16 serving peers, four IP/TCP addresses per peer, 16 KiB public
messages, synchronized leader UTC and count-bounded queues. Credential rotation,
crash/joint-transition injection and migration/recovery rehearsal remain required;
this does not establish production readiness.

# Live committed verifier refresh

Cluster transport reconciliation now refreshes topology verification and the private
control listener from applied authority using the existing store-change/watch path.
Renewed signed rosters take effect without restarting listeners, including replicas
without a control listener. Expired, missing or malformed authority disables serving
and relaying; serving withdrawal excludes the authenticated publishing source while
retaining consensus transport until the existing safe removal completes. Logical key
and network pins remain stable, with monotonic revision and same-revision proof checks.
Discovery hints cannot update these pins. Client pin semantics are unchanged.

Reconciliation is asynchronous after application, not an instantaneous cross-replica
revocation barrier. Explicit dynamic serving grants, signing-key/PSK rotation, crash
injection and maintenance migration/recovery rehearsal remain separate gates.

# Automatic committed roster renewal

The leader's existing one-second credential scheduler also renews an existing
committed serving roster when at most one minute remains, issuing a four-minute
lease with a strictly higher revision and expiry. It copies the committed
endpoints unchanged; it never discovers, admits or grants service to an endpoint.
There is no roster issuance until an operator has installed the first roster.
Renewal requires the shared allocation lock, a fresh quorum barrier and successful
Raft application. Ordered application rechecks admitted peers and pending/complete
revocations. Contention skips a tick; quorum loss cannot issue a fresh lease.
Restart or a new leader uses the committed deadline, including overdue renewal.
Synchronized leader UTC is trusted: time before issuance fails closed, forward
jumps can expire leases, and backwards movement within a lease is not detected.

This is an authority-renewal slice only. Static listener/transport verification
pins still need live committed-authority refresh; renewal does not extend their
cached proofs. Existing client discovery refresh can fetch the new committed
proof, but automatic serving grants for learners/voters, listenerless verifier
refresh, signing-key/PSK rotation and legacy migration remain separate gates.

# Durable replica revocation

Authenticated `POST /operator/revoke_replica` accepts a JSON NodeId through any
bootstrap operator endpoint. `204` means completed, `409` rejects unknown identities,
self-removal or unsafe last-voter/last-serving removal; `503` requires retry of the
same NodeId after quorum/leader recovery. Existing operator middleware applies.

The serialized leader first commits a permanent NodeId/PeerId tombstone and removes
the peer from the signed serving roster atomically. This immediately refuses old
join retries/credential retrieval and activation/promotion, while retaining Raft
transport. Native OpenRaft safe voter and learner removal commits next; only then
does a final committed stage withdraw transport authorization and disconnect peers.
Snapshot/reopen reconciliation filters tombstones even from static bootstrap config.
A replica with the final tombstone cannot start from that database/config. A removed
replica with stale state may start in isolation, but current replicas deny its transport;
it cannot obtain fresh credentials or rejoin under either revoked identity.

ponytail: interrupted stages require explicit operator retry, not automatic membership
changes. Tombstones are permanent, bounded to 64 lifetime identities; expand storage
before supporting unbounded replacement churn. No PSK rotation: a removed trusted
replica already knows historical PSKs/logs/keys, and revocation cannot erase them.
Previously signed rosters expire normally; no immediate offline-client invalidation.
No dynamic serving grant, live authority/endpoint refresh, legacy migration/recovery
rehearsal or production HA gate is supplied here. Coordinated binary upgrades are
required for the new command and protected snapshot setting.

# Explicit learner promotion (bounded HA stage)

Authenticated `POST /operator/promote_learner` accepts a JSON NodeId, forwards
from an original operator-enabled replica to the leader, and returns 204 on
committed success, 409 for unknown/unactivated/lagging learners, or 503 when
quorum/leadership is unavailable (retry the same NodeId; outcome may be unknown).
The shared leader allocation lock serializes activation/promotion and writes.
Promotion requires committed admission, existing learner membership and leader
replication matched through the quorum-barrier applied index. OpenRaft's native
`change_membership(AddVoterIds, true)` commits joint then uniform membership;
explicit retries resume a persisted joint transition after leadership/restart.
A completed retry is read-only but still requires quorum. No discovery, join
code or scheduler promotes nodes. Pending/unknown peers cannot forward operator
RPCs. Promotion persists through Raft logs and logical snapshots.

`follower_retry_failover_and_minority` now interrupts actual native promotion:
a connection-local SQLite TEMP trigger rejects the uniform membership log append
only after the joint membership is durably applied. All four replicas retain the
joint voter sets `{1,2,3}` / `{1,2,3,9}`; the writer fails closed, then recovers
the same database, identity and pinned transport. An explicit follower retry
completes uniform four-voter membership on all four, without a serving grant.
Native election toggles keep the interruption deterministic; no quorum or
consensus override is used. This is a live SQLite statement fault and in-process
writer restart, not joint removal, leader failover, SIGKILL, powerloss or fsync
interruption. The existing 90-second whole-test ceiling is unchanged.

Promotion grants voting only: the operational learner config still exposes no
client/operator listener, and does not enter the signed serving roster. Four
voters require three votes, not two; plan quorum before explicitly promoting.
No production demotion/removal/revocation API is shipped in this slice. In
particular, static bootstrap authority and exact join retries still retain
credentials: **do not treat an in-memory transport removal as revocation**.
Durable revocation must first remove serving authorization, safely remove voter
membership while retaining transport, then commit authorization disconnection
and deny credential retries/static fallback resurrection. PSK/endpoint refresh,
roster expiry refresh, coordinated upgrades, legacy migration and verified
backup/disaster-recovery rehearsal remain production gates.

# Operational learner bootstrap

`join-replica` now returns transport bootstrap material only through the pinned
Noise direct response after exact NodeId/PeerId/request/address/code admission
has committed. The response is never printed or published. It contains only the
replica cluster PSK and pinned transport endpoints, not logical controller keys,
client-network credentials, snapshots, serving permission or voting permission.

Provision a distinct existing `REPLICA_IDENTITY_FILE` first. In addition to the
existing discovery pin/bootstrap/cluster/minimum-revision and stable join inputs,
set `CLUSTER_CONFIG_FILE` to a new local file and `REPLICA_LISTEN_ADDRESS` to the
committed advertised IP/TCP address without its `/p2p` suffix. The command writes
an atomic, fsynced, no-clobber mode-0600 JSON file. Identical retries are safe;
different existing configuration is never overwritten. Protect its directory,
database, key and backups; no encryption-at-rest is added.

Start the normal server with that config and a migrated empty `DATABASE_URL`.
The saved PSK replaces the need for a cluster-PSK environment variable. This
stage runs private replica transport and consensus only: no public/client or
operator listener, initialization, serving grant or automatic promotion. An
authenticated existing operator must explicitly activate this learner using
the existing learner endpoint. Restart with the same file/database/key resumes
catch-up; never create a fresh identity or initialize on failure.

Admission retry policy retains the exact original request (including its old
code) after expiry; a valid current code is not required for that exact committed
retry. It still requires pinned live discovery and quorum. Changed requests,
identity substitution, missing quorum or invalid bootstrap fail closed. Replies
are capped at 64 KiB. Revocation, promotion, endpoint/PSK refresh, automatic
activation and legacy database import remain separate future operations. Existing
pending rows retain secrets and must be protected, not casually pruned.

# Bounded replica pre-admission (pending only)

`cat4igp-server join-replica` uses the public Noise/Gossipsub discovery listener
(`DISCOVERY_LISTEN_ADDRESS`) and a separate direct Noise request-response protocol
`/cat4igp/replica-join/1`; it needs no cluster PSK. Supply trusted
`DISCOVERY_BOOTSTRAP` (IP/TCP/p2p), `DISCOVERY_SIGNING_KEY` (logical protobuf public
key in hex), `DISCOVERY_CLUSTER_ID`, and `DISCOVERY_MINIMUM_REVISION`. The authority
must have a current committed serving roster containing that public endpoint.
Clients and joining controllers share public metadata discovery; neither publishes
invitations, join codes or cluster credentials.

Joining controllers additionally require `REPLICA_IDENTITY_FILE` (persistent private
Noise key, created mode 0600), `REPLICA_JOIN_REQUEST_ID` (stable 1..128 ASCII
alphanumeric/hyphen characters), `REPLICA_NODE_ID` (nonzero), `REPLICA_ADDRESS`
(proposed private-cluster IP/TCP/p2p endpoint ending in that identity's PeerId), and
`REPLICA_JOIN_CODE` (operator's 256-bit hex rolling code). Keep identity, request ID,
address and code unchanged for uncertain-result retries. Do not put codes in shell
history, logs or public configuration. Discovery verifies the authority pin before
the direct request discloses the code; there is no TOFU/fallback.

Authenticated public Noise source is captured by the serving replica and forwarded
over admitted private RPC. The leader uses a quorum barrier and commits code
verification, unique NodeId/PeerId/socket binding, and lifetime retry identity in
one application transaction with the Raft applied index. Exact committed retries
survive code expiry, restart and snapshots; changed payload/source, admitted
NodeId/PeerId collisions and invalid/expired codes reject. Client invites cannot
authorize this protocol. Capacity is 64 total static plus pending identities,
4 KiB request/response, 16 native concurrent streams, eight accepted joins/second,
one/source/second, 256-entry source cache, ten-second direct deadline. Serial
dispatch may delay public discovery during a quorum outage; higher-volume concurrent
completion scheduling is pending. Quorum loss cannot return successful admission.

**A `Pending` response is not membership.** It returns only request ID, NodeId and
authenticated PeerId. No cluster PSK, snapshot, serving authorization or voting
rights are released, and `add_learner` is deliberately not called: current private
transport authorization maps remain static. Pending records do not mutate
`controller_admitted` or the serving roster. Do not edit static bindings to activate
a pending record; startup continues checking the committed static authority.
Next prerequisite is restart-safe reconciliation of committed pending authorization
into both inbound/outbound network maps before learner catch-up, then explicit
promotion/serving authorization and protected credential release. No automatic voter
promotion or lost-quorum replacement is supported.

Pending records are protected replicated settings (including exact retry code);
logs/snapshots/backups/volumes remain secret-bearing. No SQL migration is needed:
the existing unique settings key and atomic Raft application transaction are reused.
This new command/protocol/snapshot setting requires coordinated binary upgrades;
mixed-version Raft replay is unsupported. Pending recovery/cancellation, transport
key refresh/revocation, legacy identity-preserving maintenance migration, and tested
backup/disaster recovery remain production gates.

# Rolling replica enrollment code (HA prerequisite)

Cluster mode now commits one shared 256-bit random hexadecimal replica code in
protected application settings. Only the leader reconciles rotation, once per
second, using the committed 15-minute deadline; retrieval also reconciles overdue
state. Rotation retains only the immediately previous code for two minutes after
the earlier of its original expiry and rotation. A delayed rotation does not
resurrect an already-expired grace window. Manual rotation does not disconnect
existing replicas. Client invitations remain independent.

Authenticated operator endpoints on **any replica**, using the existing operator
authentication/leader forwarding:

- `GET /operator/replica_enrollment_code`: current generation, raw code, explicit
	UTC activation/expiry and previous code/grace deadline; response is `no-store`.
- `PUT /operator/replica_enrollment_code`: JSON integer containing the expected
	generation from GET. Repeat the same generation after a lost reply: the next
	generation is returned without a second rotation. Older/conflicting generations
	return 409; quorum/authority unavailable returns 503, never a local fallback.

The deterministic Raft command contains the selected random code and explicit
times, with generation compare-and-swap. Application performs no random generation
or clock reads. Snapshots include these settings; protect volumes, Raft logs,
snapshots and backups as secrets, just like controller private keys. Codes never
enter discovery/pubsub, diagnostic Debug output or errors. Use a protected HTTP
operator connection; existing HTTP authentication is not transport encryption.

Clock policy: trusted synchronized UTC on leaders; activation is inclusive and
expiry/grace exclusive. A clock before committed activation fails closed, forward
jumps expire immediately, and no grace is added for skew/quorum outage. Backward
jumps within a validity interval cannot be detected by this bounded wall-clock
policy: maintain synchronized clocks; a durable external time authority is not
implemented. Failover/restart reads deadlines from committed state, not new timers.

Internal verification uses a quorum-backed read and fixed-width constant-time
comparisons against both generations. It is admitted-replica-only and **does not
grant membership**. Static transport bindings, serving roster and push authority
remain unchanged. Next: bounded Noise pre-admission join, identity-bound committed
learner admission, membership transitions and secure key delivery/refresh. Fixed
15-minute/two-minute policy and one-second scheduler are the current ceiling;
committed configurable policy can be added with admission. Coordinated schema/
protocol upgrades remain required (new command/settings, no SQL migration).

# Bounded private topology relay

The existing admitted private Raft swarm also carries strict signed Gossipsub
on a cluster-scoped topology topic. Raft and forwarded operations remain direct
RPCs. After an accepted committed answer, the ingress obtains a fresh quorum
read of the authorized committed answer result, enumerates both tunnel recipients,
seals each recipient-specific snapshot, and queues the unchanged
ciphertext for other replicas and their local client listeners. Receivers check
both authenticated pubsub author and propagation peer against static admission,
topic, logical controller signature, network, expiry, metadata and 64 KiB bound.
No receiving replica reads SQL or manufactures fresh authoritative state.

Native queues hold 32 bounded envelopes; 256 recipient revision watermarks
suppress duplicates/out-of-order delivery. Publish failure, startup mesh delay,
queue overflow and disconnected listeners lose pushes without undoing writes;
existing linearizable snapshot polling repairs loss. The wire regression uses
two real listeners and the shipped client decryptor on separate replicas.

The internal typed read revalidates the original signed answer, committed accepted
result/fingerprint and tunnel ownership; no public client principal is forged.
Rejected/failed answers and quorum loss produce no fresh envelopes.
Verification authority is configured when the private client listener starts
using a quorum read; replicas without that listener fail closed on notifications.
Configure listeners on relay replicas; no live authority-key rotation or dynamic
admission is supplied here. Static admission, coordinated migration and rolling
replica-code work remain separate prerequisites for production HA.

### Committed client control slice (2026-10-03)

Cluster mode now forwards typed enrollment, encrypted tunnel answers and snapshot
requests through the authenticated admitted-replica RPC transport. The forwarding
replica binds the principal to the client's Noise PeerId; the receiving replica
also binds the claimed serving PeerId to the forwarding Noise peer. The leader
requires a quorum read barrier and a fresh committed serving roster before
preparing any operation. Enrollment checks the client's signing/encryption keys,
selects explicit allocation under the shared leader submission lock and returns
only the committed durable enrollment result. Answers verify the client's signed,
encrypted envelope and apply ownership checks through Raft. Snapshots are signed
with the committed logical identity and encrypted for the enrolled client, not
manufactured from a follower's potentially stale state. No local SQL fallback is
used on quorum loss.

`CONTROL_BIND_MULTIADDR` explicitly enables a separate private client listener
using the replica's persisted transport identity; `CONTROL_PRIVATE_NETWORK_KEY`
is required and must be distinct from the replica-only cluster PSK. Without the
listen setting there is no cluster private listener. Dispatch is asynchronous,
bounded to 32 requests, with a 64 KiB post-decode request check and the existing
ten-second submission/five-second cluster RPC deadlines. The native JSON codec's
receive limit still applies before decoding; the 64 KiB check is not a pre-decode
allocation limit. Unknown outcomes must retry the original enrollment request ID
or answer message ID. Enrollment dedup is lifetime; answer dedup is 24 hours.

This remains bounded control functionality, **not production-ready client HA**.
The shipped client supports pinned-roster-authorized replica routing. After an
accepted answer, the ingress asynchronously obtains a new quorum-backed encrypted,
logical-key-signed snapshot for each affected client and publishes those immutable
envelopes through admitted-cluster Gossipsub and local client topics. No follower
SQL snapshot generation or pubsub consensus is used; snapshot pulls repair loss.
There are at most 32 concurrent postcommit reads, 256 recipient revision watermarks
and 64 KiB per envelope. Duplicate/nonincreasing revisions are suppressed locally;
watermarks reset on restart/overflow and are not an authoritative store. Failed
publication never rolls back a write; there is no delivery acknowledgement/retry.
Static admission, operator-renewed serving
rosters, no legacy import and count-not-byte concurrency bounds remain unchanged.
Tests exercise real three-node Raft/Noise follower enrollment/retry/failover,
snapshot decryption, snapshot-restored dedup, successful wire answers and local
push decryption by the shipped client, duplicate push suppression, invalid answer
signature/ownership and minority refusal without revision mutation.

# Committed client ingress slice (2026-10-03)

Cluster mode now optionally starts `CONTROL_BIND_MULTIADDR` on a separate
client-pnet/Noise swarm using the persisted **replica transport key**, not the
logical controller signing key. `CONTROL_PRIVATE_NETWORK_KEY` is required when
enabled; never reuse the cluster admission PSK. Unset bind keeps this listener off.
The committed, unexpired serving roster must authorize the ingress replica.

Enrollment, encrypted tunnel answers and snapshot requests forward only over
admitted replica RPCs. Forwarded serving PeerId must equal the cluster Noise
sender; original client principal comes from private ingress Noise. The leader
checks enrollment key/principal binding and answer signatures/ownership, obtains
a quorum read barrier, serializes allocation and waits for committed application.
Enrollment requires a nonempty stable request ID; lost replies retry unchanged.
Existing transactional dedup/revisions apply, and topology envelopes are sealed
with the stable logical authority from leader/quorum-backed state, never follower
SQL. No local fallback exists on quorum failure.

**Ceiling:** listener remains opt-in; admitted-cluster push fanout, other-recipient
pushes, dynamic admission/shared rolling-code rotation, legacy import/migration
and production recovery rehearsal remain pending. Local push delivery is best
effort; clients use existing periodic snapshot polling after loss or queue overflow.
Tests model orderly leader shutdown, not OS process kill or dropped packets.

# Quorum-backed public discovery (bounded activation)

In cluster mode, optionally set `DISCOVERY_LISTEN_ADDRESS` to a separate public
IP/TCP listener. It uses the persisted **replica** transport identity, not the
logical controller PeerId; include that public address/PeerId in the committed
operator-managed roster and trusted client discovery seeds. No cluster PSK is
used on this public Noise/Gossipsub transport. Only public signed metadata is
published; it exposes no enrollment or Raft RPC.

Each accepted query resolves current committed authority through the leader's
quorum read barrier (followers forward). The leader signs a query/source-bound
response for the authorized serving replica with the stable logical key.
Missing/expired roster, removed serving peer, invalid query or unavailable quorum
produces no response. Roster updates take effect without restarting discovery.
Clients can verify/persist distinct replica discovery proofs, but private control
remains singleton-gated and cluster private client listeners remain disabled.

`ponytail:` static admission/endpoints, operator roster renewal and one bounded
lookup at a time; add concurrent dispatch and replicated enrollment/answer plus
quorum topology routing before claiming any-replica client HA. Earlier disabled
discovery limits below describe prior slices; this section supersedes them only
for public discovery. No full end-to-end client failover is implemented.

# Committed cluster controller authority

Cluster initialization now commits one logical Ed25519 signing key, X25519 encryption
key, network ID (= cluster ID), and static NodeId/transport-PeerId admission map.
Only the explicit initializer generates initial keys; join/recover replicas replay
settings and never generate independent logical identities. Replica identity files
remain distinct and are not overwritten by application snapshots.

With the existing `Authorization: OPERATOR_AUTH_KEY` authentication, any replica
accepts `/operator/controller_authority`:

- `POST` initializes missing authority on an existing operator-only cluster through
	its elected leader and quorum. Already initialized authority is preserved.
- `GET` performs a quorum-backed read and returns public signing/encryption keys,
	network ID and the last committed signed roster (possibly absent or expired).
	This is an operator read, not a client trust/bootstrap endpoint.
- `PUT` accepts the existing unsigned `ControllerRoster` JSON (maximum 16 KiB).
	Leader signs with the committed logical key; Raft application rechecks signature,
	version, network, endpoint PeerId/address consistency and committed admitted peers.
	Successful response is 204 only after committed application. Invalid state is
	409; no leader/quorum is 503. No private key or credential is forwarded from HTTP.

Roster revision starts at >=1; updates must increase revision and expiry and must
not decrease issue time. Exact retry of a still-fresh roster is harmless;
equal-revision substitutions and rollback reject. Existing discovery lifetime cap
is five minutes; operators must renew before expiry and consumers must validate
expiry before use. Removed serving peers can be omitted in later revisions without
changing static Raft membership. Public serving addresses need not be private Raft
addresses, but must contain the admitted transport PeerId. Static binding changes
on recovery or authority service fail closed against committed bindings.

Authority settings are replicated and snapshot-restored; signing/encryption secrets
remain protected replicated data. Existing operator-only deployments can recover
then POST; legacy standalone import remains unsupported. Coordinated upgrades are
required because new Raft command variants are not mixed-version compatible.

**Scope ceiling:** no public cluster discovery, client control listener, automatic
renewal, dynamic admission or any-replica client routing is enabled. A roster is
serving authorization, not evidence a disabled client listener is available. Next
enable transport-separated client service and committed roster refresh, never
multiple swarms sharing the logical signing PeerId as their transport identity.

# Opt-in static Raft runtime (operator invites only)

Set `CLUSTER_CONFIG_FILE` to a bounded (64 KiB) JSON file with fields:
`cluster_id` (1..64 ASCII alphanumeric/`-`/`_` bytes), `node_id` (nonzero u64), `mode`
(`initialize`, `join`, or `recover`), `identity_file`, `listen` (TCP multiaddr),
and `replicas` (map of node IDs to `{ "peer_id": "...", "address": "..." }`).
Every replica must use the same admitted map and independent database/key files.
Set `CLUSTER_PRIVATE_NETWORK_KEY` to a separate replica-only libp2p PSK key-file
contents; never reuse the client PSK. Existing `DATABASE_URL`, `AUTO_MIGRATE`,
`BIND_HOST_PORT` and `OPERATOR_AUTH_KEY` still apply.

Pre-provision each private protobuf replica key and its matching PeerId before
starting. `initialize` is an explicit one-time action on exactly one node;
the other configured voters start in `join` mode and wait for replication.
This is static out-of-band admission, not dynamic learner admission.
Initialize/join require pristine consensus and application databases; importing
an existing standalone database is deliberately unsupported in this slice.
After any startup attempt that persists the binding, use `recover`, retaining
the same cluster ID/node ID/key. Recovery never calls initialize; missing keys,
identity mismatches, corrupt state, and join/quorum failures never bootstrap.
A database bearing Raft state cannot be opened in standalone mode even if the
cluster environment variable is accidentally removed.

Clustered mode starts only the private Raft transport and authenticated operator
HTTP invite route. Invites use quorum barrier, serial ID selection and actual
`client_write`, returning only applied results. Preserve `Idempotency-Key` on
unknown-outcome retries. Any replica authenticates operator HTTP ingress locally
and forwards only typed invite settings/request ID over the existing private
PSK/Noise transport; Authorization headers/credentials are never forwarded.
Redirects are bounded to two and the whole submission to ten seconds (individual
RPCs to five). A minority/unavailable replica returns 503 without local writes
or terminating the healthy process. Raft fatal/storage failures still fail stop.
One shared leader allocation slot rejects concurrent work with retryable 503;
accepted operations retain that slot until OpenRaft resolves them, even after
the caller deadline/disconnect. Retry with the same Idempotency-Key, not a new ID.
`GET /cluster/ready` returns 204 only after an actual quorum-backed leader read
barrier (forwarded from followers), otherwise 503. The root banner is not readiness.

Client control and public discovery listeners are **disabled** in cluster mode:
enrollment, answers and topology reads cannot bypass consensus. Logical controller
keys/rosters are committed as described above; persisted replica transport keys
are distinct. No singleton controller PeerId is run concurrently on voters.
Legacy standalone configuration remains unchanged for standalone databases.
There is no any-replica client HA, client request forwarding, automatic admission, logical
identity import or topology publication yet. Three statically
configured voters provide consensus fault tolerance, not full client-service HA.

# Enrollment/answer storage prerequisite

The dormant OpenRaft adapter now accepts enrollment and tunnel-answer commands as well as
initialization/invites. Enrollment captures node/auth/time and explicit membership/tunnel IDs
before application; apply validates current mesh peers, invite capacity/expiry and allocation
availability. Stale allocations are deterministic rejections, not replica-local reallocations.
Commands carry the authenticated client PeerId; enrollment checks its signing-key binding,
and answers recheck that principal's node ownership. Only authenticated ingress may construct
these commands (answer signature/envelope validation remains at existing ingress).

Business state, revisions, durable semantic dedup and applied-log metadata share one SQLite
transaction. Storage errors roll back and return OpenRaft storage failure; business rejection
advances the applied index. Snapshots restore enrollment/answer retry results. Enrollment dedup
is lifetime; answers retain the existing 24-hour committed-time retry window.

This does not activate consensus or HA. The singleton API/config is unchanged; its worker and
the dormant adapter remain separate until live committed submission replaces direct writes.
Leader preparation must serialize allocations or handle committed stale-allocation rejection;
no authenticated cluster RPC, quorum reads, roster authority or replica admission is wired yet.

### Deterministic invite and controller initialization prerequisites

The existing authenticated `POST /operator/create_invite` accepts an optional
`Idempotency-Key` header (1–128 ASCII bytes). Reuse the same key and payload after
an unknown outcome: the original invite code is returned, including after restart
or later invite consumption/expiry. Different expiry/capacity/mesh with that key
returns 409 without another invite. Without the header, legacy requests remain
independent attempts. Authentication still runs before submission; only one shared
operator principal exists today, so keys are global to that principal and survive
credential rotation. Do not use credentials as request IDs.

Invite capacity must be positive, supplied expiry must be later than the selected
application timestamp, and a supplied mesh must exist. These business rejections
are durable outcomes too (409); malformed timestamps/headers return 400. Queue
overload, SQL failure or lost worker reply returns 503; retry with the same key.
Invite mutation and the exact canonical payload/result row commit together.
Results are retained for the database lifetime; protect them and backups as secrets.

The serial worker selects invite ID/code/time before deterministic application.
Startup selects a serializable signing/encryption/network initialization command;
all missing settings are inserted atomically with explicit timestamps. Existing
settings, including partially initialized legacy databases, are never replaced.
No randomness or clock reads occur inside either application transaction.

These are singleton prerequisites, not replicated writes. OpenRaft log/vote storage,
applied metadata, snapshots, authenticated replica transport and a committed
submission service are still required before any replica can serve authoritative
writes. No homemade consensus or additional mesh routes are introduced.
# Bounded database submission (singleton prerequisite)

Control requests and the authenticated `/operator/create_invite` route share one
serial `spawn_blocking` SQLite worker. Submission never waits for queue capacity:
32 queued jobs, one active job and up to 32 completed control results are retained.
SQL, request cryptography and topology serialization run off the swarm task;
only the swarm task sends control responses and publishes topology updates.
Overload rejects control requests with a same-request retry hint and returns HTTP
503 for operator submissions. Worker failure stops the server rather than
silently restarting an uncertain application; committed enrollment results remain
in SQLite and replay after restart. Lost publications recover through snapshot
polling. Accepted work is not cancelled when its caller disconnects.

This is not Raft or replicated HA. Bounds count jobs, not total topology bytes.
Invite creation still uses local randomness and has no durable request ID/result:
a lost operator reply is an unknown outcome, not permission to blindly retry.
Next: deterministic, idempotent invite/settings commands, then OpenRaft
commit/apply and storage integration. Unregistered mesh/list routes remain disabled.

# Public metadata discovery (optional, not HA)

`DISCOVERY_ROSTER_FILE` enables a **separate** TCP/Noise/Gossipsub listener at
`DISCOVERY_LISTEN_ADDRESS` (for example `/ip4/0.0.0.0/tcp/9001`). Open that TCP
port separately from private control. The file is a bounded JSON
`Signed<ControllerRoster>` signed by the existing logical controller identity;
it must authorize this server's PeerId and contain reachable public discovery
addresses ending in `/p2p/<PeerId>`. Its maximum lifetime is five minutes.
An expired/invalid proof never authorizes responses; replacement currently
requires restart. No roster generation or membership administration is provided.
Leave the variable unset to preserve legacy singleton operation.

`cat4igp-server discover-replica` queries the public topic without opening the
database or starting control. Supply `DISCOVERY_BOOTSTRAP` (trusted IP/TCP/p2p
address), `DISCOVERY_CLUSTER_ID`, `DISCOVERY_SIGNING_KEY` (out-of-band pinned
protobuf public key in hex), `DISCOVERY_PRIVATE_KEY` (persistent joining Noise
identity in protobuf hex), and `DISCOVERY_MINIMUM_REVISION`. Output is a verified
public signed proof, **not** admission, a PSK, or consensus state. Persist its
roster revision before a later query. The command fails after ten seconds if no
valid response arrives; it never substitutes an untrusted seed or key.

Enrolled clients may configure `discovery_bootstrap_addresses` in `server.json`;
startup then requires public discovery using their existing signing-key pin and
network ID before private control requests. `discovery_proof` holds the enrollment
proof/revision floor. Enrollment's discovery path also requires an out-of-band
pin, but the current registration CLI does not yet import such a trust bundle.
Discovery addresses are not private control addresses: current singleton control
routing remains explicitly configured and rejects a different discovered PeerId.

Topics contain only public queries and signed endpoint/roster responses, never
invites, join codes, PSKs, topology or private keys. Both roles use the same
bounded requester and role-scoped topics. The public swarm has no enrollment or
cluster RPCs. Private control remains unchanged; private admitted cluster/Raft
transport, committed roster authority, live roster refresh, bundle import and
any-replica routing are still pending. Tests exercise live Noise/pubsub for both
roles and fail-closed wrong-pin/bootstrap-outage paths, not HA or consensus.

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
- `AUTO_MIGRATE`: `true` (default) applies pending migrations before startup;
	`false` requires an already up-to-date database. Other values are rejected.
- `BIND_HOST_PORT`: operator HTTP listener, e.g. `0.0.0.0:8080`.
- `CONTROL_BIND_MULTIADDR`: control listener, e.g. `/ip4/0.0.0.0/tcp/4001`.
- `CONTROL_PRIVATE_NETWORK_KEY`: complete libp2p PSK key-file **contents**, not a path.
- `OPERATOR_AUTH_KEY`: operator API authentication secret.

Publish the chosen HTTP/control TCP ports explicitly. The operator endpoint
uses plain HTTP: restrict access or put it behind authenticated TLS termination.
WireGuard privileges/devices are not required for the server.

## Database migrations

Migrations are embedded in the server executable and automatically applied
before HTTP/control listeners start. With `AUTO_MIGRATE=false`, pending
migrations prevent startup instead. Migration errors also prevent startup.

For manual migration, run `DATABASE_URL=/path/to/database.db cat4igp-server migrate`.
This applies pending migrations and exits without starting listeners or needing
HTTP/control/auth configuration; it ignores `AUTO_MIGRATE`. Unknown arguments
are rejected. No separate Diesel CLI or runtime SQL directory is needed.

For the container, use the same image, database volume, and database override
as the server deployment, for example:

```sh
docker run --rm -v /srv/cat4igp:/data ghcr.io/badaimweeb/cat4igp-server:<tag> migrate
```

The volume must be writable by UID/GID 10001:10001. Before upgrades, stop all
server instances sharing the database and take a backup. Run only one migration
writer at a time, including automatic startup migration.

Each migration and its Diesel ledger entry commit in one transaction, not the
whole pending batch. A failed migration rolls back while earlier successful
migrations remain committed. After correcting the cause, rerun to apply only
pending versions. Retain `__diesel_schema_migrations`; never replay all `up.sql`
files or silently baseline an existing untracked database. There is no automatic
rollback or destructive rollback command.

The state-prerequisite migration rejects duplicate `settings.key` or
`(mesh_group_id, node_id)` memberships without deleting records. On a
`repair_duplicate_*` error, inspect those groups in a stopped, backed-up
database and explicitly resolve them before retrying; conflicting controller
secrets must not be arbitrarily selected. Existing rows and revisions are preserved.

Connections use SQLite WAL, a 5-second busy timeout and `synchronous=FULL`.
Back up with SQLite's backup API (or stop the server and preserve the database
and WAL together), not by copying only a live `.db` file.
Authenticated tunnel answers retain semantic retry results for 24 hours from
first application, keyed by node and message ID. Identical retries do not
increment revisions; conflicting reuse is rejected. Envelope expiry/signature
checks still apply before retry lookup. Expired records are pruned on answer
application; clients must not retry an ID beyond this window.

Enrollment stores its original semantic response durably in the same immediate
transaction as invite consumption, node/control identity, WireGuard key,
mesh membership/tunnels and affected topology revisions. A lost reply or restart
replays that response without consuming another invite or advancing revisions.
Explicit request IDs are bound to one authenticated PeerId and exact request;
conflicting request content or principal is rejected. Legacy empty request IDs
remain PeerId-scoped. Rejected state-dependent requests are also retained, so a
changed invite cannot turn a retry into a new enrollment. Results have no expiry:
one result per enrollment identity, with retention deferred until identity recovery
exists. These rows include invitations and must be protected like controller keys.

Commands supply node/auth IDs and time; ordered SQLite allocation supplies tunnel
and membership IDs. This is deterministic for identical application state, not a
replicated allocator. Database processing still runs on the control swarm thread;
a bounded blocking submission worker is the next slice before consensus wiring.

This is a singleton prerequisite, not HA: OpenRaft storage/transport, replicated
enrollment/invites/settings, asynchronous database submission, roster-based
client failover and membership admission remain unimplemented. Never deploy
multiple independent controllers against one shared SQLite file.

Local builds use `server/Dockerfile` with the repository root as build context.
The `.dockerignore` excludes Git data, build outputs, environment files and
SQLite databases. Neither registry publication nor arm64 testing is performed
by a local amd64 build.

### Durable OpenRaft adapter (not live HA)

`server/src/raft_storage.rs` implements pinned OpenRaft 0.9.25 storage-v2 log
reader/storage, state machine and snapshot builder contracts. The additive
`2026-10-02-000002-0000_raft_storage` migration creates local metadata/log tables.
One 32-job blocking worker serializes each adapter's SQLite IO with WAL/FULL.
Vote returns and log flush callbacks follow durable SQL commits. Purge metadata
and deletion commit together. Initialization/invite mutations, durable retries
and applied ID/membership commit together using nested command savepoints.

Versioned logical snapshots include application rows, all three dedup tables,
applied ID and membership. Settings are allowlisted to the three logical
controller identity/network keys. Install atomically replaces application state
and the persisted current snapshot, never local vote/log/commit/purge or other
settings such as transport keys. No live SQLite/WAL file is copied. Build/install
do not compact logs themselves. Metadata mismatch, local-setting injection and
oversized payloads fail closed. Protect snapshots/logs/volumes as private keys.

Ceilings: 16 MiB in-memory JSON payload, schema version 1, coordinated upgrades;
build loads each table before checking encoded size. Upgrade to streaming files
before state reaches that ceiling. Only initialization/invite commands are
enabled; enrollment/answer validation and explicit allocation remain pending.
The adapter reuses the existing bounded worker pattern, not the live singleton
worker itself. Only one adapter writer per replica database is supported.
No Raft startup, cluster RPCs, snapshot transport/integrity protocol, leader
forwarding, quorum reads or committed write routing exists. Singleton endpoints
still write locally. Tests cover native storage conformance, reopen durability,
SQL-fault rollback and snapshots, not process-kill/power-loss or live consensus.

### Private Raft RPC adapter (not production HA)

`src/raft_network.rs` implements the pinned OpenRaft network factory/client contracts
using a separate TCP/pnet/Noise/Yamux request-response swarm. No consensus message
uses pubsub. Supply a **replica-only** cluster PSK, a distinct persistent mode-0600
protobuf transport key, cluster ID and an explicit unique NodeId/PeerId/address map;
the existing client PSK and logical controller key must not be reused. Key corruption
or unsafe permissions fail closed; incomplete first creation is not regenerated.

The authenticated Noise peer must match the claimed NodeId and RPC vote leader,
recipient and cluster ID. Unknown peers are disconnected and cannot dispatch Raft
work even if they know the PSK. Native request IDs correlate responses with the
expected peer. Dispatch calls actual `Raft::vote`, `append_entries` and
`install_snapshot` asynchronously, allowing the swarm to keep serving consensus.
Errors preserve typed remote Raft failures; deadlines use native RPC timeout errors.

Ceilings: 64 static bindings, 1 MiB encoded RPC, 32 queued outbound calls,
32 pending outbound streams, 32 inbound dispatch tasks, one concurrent snapshot
dispatch, five-second transport/dispatch deadline (shorter caller deadlines apply).
Canceled callers retain stream slots until completion/native deadline. Oversized
append batches return OpenRaft splitting hints; a single oversized entry fails closed.
Configure small batches and 64 KiB snapshot chunks when constructing Raft; default
snapshot chunks can exceed the JSON wire limit. Snapshot byte length/offset bounds
and atomic installation also remain enforced by the existing 16 MiB storage adapter.
Noise authenticates/encrypts streams; no separate snapshot digest protocol or packet
capture verification is implemented. Static admission, coordinated protocol upgrades,
per-connection native stream limits and count-bounded queues are not dynamic membership,
a byte-budget scheduler or global pre-handshake connection/rate protection.

Two runnable module tests cover genuine three-voter election/committed SQLite invite
replication, explicit vote RPC, snapshot installation into a fourth genuine fresh node,
live wrong-cluster/unknown-peer/wrong-PSK rejection, persisted distinct identities,
binding validation, oversized payload, caller timeout and queue overload. They do not
claim production startup, crash/failover, partition or plaintext packet-capture coverage.
The fourth node is only transport-allowlisted, not promoted to Raft membership.

The adapter remains **unconnected to production startup and API submission**. Next:
explicit initialize/join/recover, supervise transport and one DB writer, supply committed
admission bindings, route all writes through committed application and follower forwarding,
add quorum-backed read barriers and publish only committed roster/topology notifications.
Existing singleton endpoints still bypass Raft; this is not end-to-end HA.