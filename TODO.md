# Production readiness

- [x] Secure the default daemon socket and authenticate its server peer before sending secrets or enrollment bundles.
- [ ] Establish safe, tested recovery of enrolled clients after restoring an older controller backup; reconcile lost enrollments and revocations and preserve rollback protection. Current-backup database restore passed `cargo test --locked -p cat4igp-server db::migration_tests::enrolled_client_current_backup_restore_retains_enrollment_and_revocation -- --exact` (1 passed), preserving enrollment receipts, authentication, topology, invitation consumption and revocation enforcement. Older-backup recovery still requires independently complete acknowledged-write/revocation history and a validated reconciliation procedure; neither the comparator nor a current-backup drill supplies that history.
- [ ] Recover safely from damaged topology state across all cases: 22 cache regressions passed; attempt 38 additionally verified actual two-client authenticated repair with unchanged version-2 journals, ports, identities and fresh traffic in Debian 13. Missing/damaged journals, legacy lost reservations and coordinated rollback cannot reconstruct a trustworthy high-water mark. Closure requires an independent current trust anchor and validated legacy recovery procedure, not deleting state or lowering revision floors.
- [x] Prevent one failed tunnel from indefinitely blocking reconciliation of unrelated tunnels.
- [x] Bound control-plane convergence delays when bootstrap addresses are unreachable.
- [ ] Recover or clean up owned L2TP resources after unclean exits without removing unmanaged resources. Attempt 35 fixes unexpected xl2tpd leader-exit descendant cleanup while retaining unreaped PID ownership; 11 supervisor tests passed locally and in Debian 13, plus all six real kernel/userspace/WireGuard PPP endpoint packet-transfer/cleanup checks. Attempt 37 verifies packaged systemd cgroup termination of escaped-session descendants. Abrupt client death outside that service, escaped helpers on other supervisors and durable netlink/secret-directory ownership remain unresolved.
  - Debian 13 VM ownership checks passed: `daemon::daemon_memory::l2tp::integration_test::reconcile_wireguard_resources_are_shared_and_cleaned` and `unmanaged_address_is_not_removed`. A native PID-namespace containment investigation found that an owned namespace-init launcher and explicit stop/parent-death protocol are required; adding `CLONE_NEWPID` to the current `pre_exec` would not contain xl2tpd itself. Closure needs abrupt-death/escaped-helper regressions and durable netlink/secret ownership, not PID/name-based stale cleanup.
- [ ] Validate offline revocation containment and connectivity across intended NAT paths. Attempt 39 passed real two-client controller-path isolation, cached traffic before deletion, reachable-peer resource removal/traffic denial and authenticated rejection after reconnect in Debian 13. An isolated cache remains usable against other disconnected peers; intended restrictive NAT paths and independent edge containment still require deployment-specific verification.
- [x] Gate client releases on privileged networking and actual L2TPv2 PPP packet-transfer tests.
- [x] Gate releases on real HTTPS management and browser integration tests.
- [ ] Complete artifact authenticity and supply-chain controls: `bash packaging/build.sh --check`, `bash packaging/check-release-tag.sh --check` and `bash packaging/image-tag.sh --check` all passed. Source staging is commit-bound, but mutable feeds and RISE self-hosted runner identity remain trust dependencies. Closure requires an authorized real tagged-publication/attestation drill and approved runner/feed provenance policy; publishing releases is outside this goal's scope.
- [x] Provide actionable service and tunnel health monitoring, including verified controller-snapshot freshness and reconciliation failures.
- [x] Run resource-limited five-node best-effort load, soak, failure and recovery benchmarks per operator clarification. Attempts 67–70 verified twenty dual-stack links, eight concurrent hash-checked TCP/UDP streams, a five-minute synthetic soak, controller outage/reconnection during traffic, and subsequent enrolled restore. Per-stream goodput, process RSS and recovery-verification times are recorded below. This closes the authorized five-node reference benchmark scope only, not 80+ node capacity, production traffic representativeness or an availability SLO.
- [ ] Document production acceptance criteria and drill backup/restore with already-enrolled clients; `llm_notes/server/deployment.md` defines acceptance and fencing requirements. Attempt 31 passed the real isolated two-client dual-stack WireGuard restore drill with preserved enrollment, encrypted/decrypted snapshot, lost-write accounting, fresh authenticated controller snapshots, unchanged public identities and bidirectional traffic after restart (15.123 s measured recovery; 0.526 s lost-write window, one unrelated invitation). Reference-staging scope was selected explicitly. Production acceptance remains blocked on intended workload/path targets, off-host backup verification, detection/notification/key-retrieval timing and owner-approved RPO/RTO; this local drill omits those intervals.
- [ ] Define the standalone controller availability, supervision, off-host backup, RPO and RTO requirements; `llm_notes/server/deployment.md` specifies a single writer, external checks, fencing, encrypted off-host backup/key custody and a deployment decision table. Closure requires the deployment owner's explicit service hours, loss/outage budgets, on-call/key custodians and measured restore acceptance; these policy values cannot safely be inferred from the repository.
- [ ] Protect plaintext L2TPv2 secrets and sensitive controller/client backups; owner-only package/config/state permissions passed VM checks, and untrusted-network WireGuard guidance exists. Attempt 31 passed real CMS encryption/decryption and checksum verification with approved ephemeral test keys. Production encryption at rest, independent recoverable key custody and existing-deployment permissions remain operator-managed and unapproved; test keys do not establish those policies.
- [ ] Validate minimum Linux privileges for every enabled backend. Attempts 53–60 verified CAP_NET_ADMIN-only WireGuard/L2TPv3 lifecycle, selective PPP namespace denial, three-capability bounded native daemon recovery, all PPP modes, and routed FakeTCP packet recovery in Debian 13. CAP_NET_ADMIN/CAP_SYS_ADMIN/CAP_NET_RAW suffices for these root-owned reference fixtures with NoNewPrivileges; removing CAP_NET_RAW fails the PPP driver's raw ping probe, not necessarily its helpers. Closure still requires separating driver-only privileges from daemon/helper minima, non-root filesystem/device access, and intended enabled-backend/version profiles. Packaged production services remain unchanged.
- [ ] Validate proxy endpoint roaming and dual-link refresh behavior, port capacity and dependent-tunnel interruptions in deployment scenarios. Existing VM checks cover kernel refresh/roaming, FakeTCP NAT outage recovery, isolated proxy updates, shared L2TP ownership and underlay-loss containment. Attempt 41 adds real daemon exhaustion/release convergence with active WireGuard resources. Attempt 34 measured uninterrupted reference traffic through controller outage/restart. Intended NAT/roaming topology and dependent-tunnel outage measurements remain unverified; isolated and reference checks are not deployment proof.
- [ ] Validate package installation, upgrades and reboot recovery on supported architectures and OpenWrt sysupgrade. Debian 13 amd64 VM: installed baseline `0.1.0~20261001093604.g7a9f3bc6e2b2-1`, built candidate with `bash packaging/build.sh debian x86_64`, upgraded to `0.1.0~20261114222031.gd4ded0e231d9-1` using `dpkg --force-confold -i`, verified conffile/state checksums and 0600/0700 permissions, explicitly restarted, rebooted, and verified enabled/active daemon plus retained config/state. Package intentionally does not auto-start; maintenance/restart procedure documented. No enrolled identity was used; remaining distro/architecture upgrades, enrolled traffic and OpenWrt sysupgrade retention still require their own drills.
  - Alpine 3.24 x86-64 VM: `apk add --allow-untrusted /tmp/baseline.apk` then `/tmp/upgrade.apk` upgraded October to November artifacts, preserved modified configuration/state checksums and 0600/0700 permissions, and OpenRC daemon status passed after reboot. Unsigned local artifacts were explicitly trusted only inside the disposable VM; this is not release-authenticity proof.
  - OpenWrt 25.12.5 x86-64 VM: installed November APK; `sysupgrade -l` and `sysupgrade -b /tmp/cat4igp-backup.tar.gz` included both `/etc/cat4igp/client.toml` and a state-directory marker; packaged daemon, retained marker and private permissions passed after reboot. This verifies backup selection, not flashing a replacement firmware image or restoring an enrolled identity.
  - Arch Linux x86-64 VM: `pacman -U --noconfirm` upgraded October to November package artifacts; modified config/state checksums and 0600/0700 permissions survived, and enabled/active daemon status passed after reboot. A `.pacnew` retained the distributor's new configuration for deliberate merging.
- [x] Verify CI status and published releases independently: remote main `34af248e356d` passed native, package-build and server-image workflows; no releases or tags were published. These results do not validate local changes.

## Autonomous verification pass (30-attempt cap)

No broad readiness item was marked complete from partial checks. All disposable
VMs created for this pass were removed; golden images and releases were untouched.

| Attempt | Fix or validation scenario | Result |
| --- | --- | --- |
| 1 | Added current-backup enrolled-identity/revocation restore test in `server/src/db_test.rs`; exact test command recorded above | 1 passed |
| 2 | Native crash-containment investigation | Blocked on owned PID-namespace init/stop/reaping design; no unsafe patch |
| 3 | Debian amd64 build, baseline install, upgrade, explicit restart and reboot | Passed config/state preservation; unenrolled daemon only |
| 4 | `cargo test --locked -p cat4igp-client daemon::topology_cache::` | 22 passed |
| 5 | Exact `network::privilege_test::backends_fail_closed_without_capabilities` | 1 passed locally |
| 6 | `packaging/build.sh --check`, `check-release-tag.sh --check`, `image-tag.sh --check` | All exit 0 |
| 7 | Alpine x86-64 baseline/upgrade/reboot | Passed config/state checksums and OpenRC status |
| 8 | OpenWrt x86-64 install, sysupgrade backup selection and reboot | Passed retention selection and daemon status; no firmware flash |
| 9 | Arch x86-64 baseline/upgrade/reboot | Passed config/state checksums and systemd status |
| 10 | `python3 -W error::ResourceWarning -m unittest discover -s tools -p test_compare_controller_backups.py` | 31 passed |
| 11 | `cargo test --locked -p cat4igp-client network::ports::tests::` | 3 passed |
| 12 | VM exact `reconcile_wireguard_resources_are_shared_and_cleaned` | Passed |
| 13 | VM exact `unmanaged_address_is_not_removed` | Passed |
| 14 | VM exact `policy_routes_to_wireguard_and_drops_when_it_disappears` | Passed |
| 15 | VM exact `l2tp_direct_and_wireguard_exchange_jumbo_packets` | Passed (4.29 s) |
| 16 | VM exact `backends_fail_closed_without_capabilities` | Passed |
| 17 | VM `network::udp_proxy::tests::` including trusted roaming | 6 passed |
| 18 | Underlay-loss fail-closed routing/resource-ownership scenario review | Evidence limited to isolated scenarios; deployment outage measurements still missing |
| 19 | `cargo test --locked -p cat4igp-client config::server::tests::` | 6 passed |
| 20 | `python3 -m unittest discover -s tools -p test_controller_benchmark.py` | 6 passed; tooling, not capacity proof |
| 21 | `python3 -m unittest discover -s tools -p test_healthcheck.py` | 5 passed |
| 22 | `cargo test --locked -p cat4igp-client config::tests::` | 5 passed |
| 23 | Exact server `offline_node_deletion_revokes_identity_and_updates_only_surviving_peers` | 1 passed |
| 24 | `cargo test --locked -p cat4igp-client daemon::refresh::` | 9 passed |
| 25 | Exact server `enrollment_retry_restart_conflict_and_rollback` | 1 passed |
| 26 | Exact server `invite_settings_retry_restart_conflict_rollback_and_determinism` | 1 passed |
| 27 | Exact server `management_rejection_invite_invalidation_and_implicit_id_nonreuse` | 1 passed |
| 28 | Exact server `deterministic_answer_retry_and_atomic_rollback` | 1 passed |
| 29 | Exact client `direct_policy_and_port_collision_fail_closed` | 1 passed |
| 30 | Exact client `reconciliation_reports_each_independent_failure` | 1 passed |

Server exact filters above use `cargo test --locked -p cat4igp-server
db::migration_tests::NAME -- --exact`; client exact filters use `cargo test
--locked -p cat4igp-client FULL_TEST_PATH -- --exact`. VM checks used the actual
transferred test binary with `--exact FULL_TEST_PATH --ignored --nocapture` under
`sudo unshare --net`; the unignored capability/proxy checks omitted `--ignored`.
Remaining blockers and closure evidence are recorded individually above. This
pass reached its attempt cap; it did not establish production readiness.

## Additional authorized pass (attempts 31–130)

The user authorized 100 additional fix-or-validation attempts after the original
30-attempt pass. Scope, ownership safeguards and full-item verification requirements
are unchanged. Attempts 31–84 completed their scoped fixes/validation, including
actual enrolled Debian reboot recovery; cross-architecture/version-upgrade gaps remain.
The operator-authorized five-node benchmark item is complete; other items retain their blockers.

### Attempt 32 — expanded zero-capability backend denial

Extended `client/src/network/privilege_test.rs` to exercise L2TPv3 setup denial,
UDP-port release, absent interfaces, retry and cleanup, plus kernel/userspace
L2TPv2 pre-exec denial without leaked configuration, interfaces or children.
`cargo test --locked -p cat4igp-client network::privilege_test::backends_fail_closed_without_capabilities -- --exact`
exited 0 (1 passed). Transferred its freshly compiled executable to Debian 13
VM `readiness-restore-31` after observing the login console; running
`sudo /tmp/client-tests-32 --exact network::privilege_test::backends_fail_closed_without_capabilities --nocapture`
exited 0 (1 passed, 0.02 s). This adds negative coverage; minimum positive
capability profiles and selective namespace/mount/policy-routing denial remain
unverified, so the broad privilege item remains unchecked.

The user selected reference-staging acceptance rather than unspecified production
targets, and approved ephemeral OpenSSL test keys for the isolated backup drill.
Production workload, RPO/RTO and key-custody approval remain separate requirements.

### Attempt 33 — selective backend capabilities

Added ignored, isolated-process capability profiles to the same regression file.
`cargo test --locked -p cat4igp-client network::privilege_test:: --no-run` exited 0.
Transferred that executable as `/tmp/client-tests-33` to the Debian 13 VM; both
commands exited 0 (one passed each):

```sh
sudo /tmp/client-tests-33 --exact network::privilege_test::l2tpv2_denied_without_sys_admin --ignored --nocapture
sudo /tmp/client-tests-33 --exact network::privilege_test::l2tpv3_setup_with_net_admin_only --ignored --nocapture
```

The first retains only CAP_DAC_OVERRIDE, proves configuration-directory access,
then verifies L2TPv2 mount-namespace denial and cleanup in both modes. The second
retains only CAP_NET_ADMIN after creating its isolated namespace and verifies
real L2TPv3 setup, MTU, socket ownership, destroy and recreation. Exact effective,
permitted, inheritable and bounding sets and no_new_privs are asserted. These are
backend profiles, not proof of minimum privileges for the entire daemon or PPP.

### Attempt 31 — real enrolled-client encrypted restore

Added `server/tests/restore_enrolled.py` and reused the HTTPS certificate fixture.
Built actual binaries with `cargo build --locked -p cat4igp-server -p cat4igp-client`
(exit 0), transferred both binaries and Python drivers to disposable Debian 13,
then ran:

```sh
sudo python3 /opt/readiness/server/tests/restore_enrolled.py --confirm-disposable --server /tmp/cat4igp-server --client /tmp/cat4igp-client
```

Final run exited 0, result PASS. Two enrolled clients and two WireGuard links
passed baseline and restored bidirectional ping and fresh handshakes; public keys
and enrollment identity fields were unchanged. Both restarted daemons reported
authenticated controller snapshot age 8 s. Stopped SQLite backup was CMS-encrypted
and decrypted with ephemeral test keys; SHA256 matched, integrity checks passed,
and exactly one post-backup unrelated invitation was lost. Measured restoration
was 15.123 s; recorded lost-write window 0.526 s. Report explicitly excludes
off-host transfer/verification, detection, notification and key retrieval, and
does not claim production RPO/RTO or older-backup safety. Initial fixture runs
exposed dual-stack endpoint configuration, unclosed SQLite connections and an
unmaintained legacy last_seen field; corrected without bypassing restoration or
rollback checks. `python3 server/tests/https_management.py` also exited 0 after
certificate-fixture extraction (HTTPS/authentication assertions passed).

### Attempt 34 — reference two-client soak and outage

Ran the attempt-31 command with `--reference-soak` using the transferred actual
binaries in Debian 13; exit 0, PASS. Four streams each sent/received 300 probes
at 0.2 s intervals over two links in both directions (1,200/1,200 total, zero
loss and zero missing-probe intervals). Controller stopped at 20 s and restarted
at 30 s; authenticated reconciliation after restart took 12.765 s (threshold 15 s),
while existing clients/interfaces remained alive. Reference duration 61.029 s;
restoration afterward also passed (15.113 s). This is a tiny reference topology,
not production capacity or a long-duration soak. Initial accounting incorrectly
included non-reply icmp_seq diagnostics; fixed reply-only parsing and added
`python3 server/tests/test_restore_enrolled.py` (exit 0, four tests) covering
missing notices, ICMP errors, duplicates and invalid sequences. Production load,
topology and long-soak targets remain unspecified.

### Attempt 35 — unexpected PPP leader exit cleanup

Changed the L2TPv2 supervisor to observe leader exit with waitid(WNOWAIT), keep
the unreaped leader pinning ownership, kill remaining owned group members, then
reap. Ownership mismatch fails closed; escaped groups and abrupt client death
remain outside this containment. Added a descendant regression.
`cargo test --locked -p cat4igp-client tunnel::l2tp_v2::tests:: -- --skip ppp_session_transfers_packets_and_cleans_up`
exited 0 (11 passed); transferred executable `/tmp/client-tests-35` passed the
same 11 checks in Debian 13. Existing PPP driver also exited 0:
`sudo unshare --net --mount bash /tmp/ppp-test.sh /tmp/client-tests-35`.
All six endpoints passed packet transfer and interface cleanup across kernel,
userspace and WireGuard-underlay modes, including jumbo WireGuard packets.
Full crash-safe cleanup still requires escaped-helper containment and durable
ownership of netlink resources and secret directories.

### Attempt 36 — live offline client restart

The attempt-31 driver with `--offline-client-restart` exited 0 in Debian 13.
Both same enrolled clients reconstructed both WireGuard links from retained state
while the controller listener was unreachable; fresh handshakes and bidirectional
traffic passed, public keys matched, and controller snapshot age remained Unknown.
After controller restart both ages became 0 s, proving authenticated reconnection.
The subsequent restore phase also passed (15.136 s). This verifies offline cache
recovery on direct reference paths, not immediate revocation or restrictive NAT.

### Attempt 37 — packaged systemd process containment

Made KillMode=control-group, SendSIGKILL=yes and TimeoutStopSec=15s explicit in
`packaging/cat4igp-client.service`. Debian 13 transient-unit proof with these
properties terminated a forked, session-escaping, TERM-resistant Python descendant
on systemctl stop (exit 0); initial proof helpers were corrected for systemd's
dollar expansion and session-leader setsid restrictions. This codifies systemd
containment, not portable backend containment: OpenRC/procd behavior, abrupt
daemon death and leftover `/run/cat4igp-l2tpv2-*` secret directories still need
separate ownership-safe recovery. No broad cleanup item is complete.

Attempt 37 permanent proof artifact: transferred the actual service unit alongside
`packaging/check-service-containment.py`; running
`sudo python3 /tmp/containment/check-service-containment.py --confirm-disposable`
exited 0: packaged properties terminated a session-escaped TERM-resistant descendant.
The proof reads property values from the supplied unit rather than duplicating them.

### Attempt 38 — live authenticated damaged-cache repair

The attempt-31 command with `--damaged-cache-repair` exited 0 in Debian 13.
Both enrolled clients restarted with deliberately undecodable cache files and
intact version-2 journals. Exact cache content, journal bytes, revision/hash
commitments, listening ports and identities were preserved; authenticated snapshot
age became 0 s, fresh handshakes and bidirectional traffic passed on both links.
The subsequent restore passed (15.118 s). Missing/damaged journals, legacy lost
reservations and coordinated rollback remain unresolved and explicitly fail closed.

### Attempt 40 — source identity replacement-ref protection

Fixed `packaging/build.sh` to set GIT_NO_REPLACE_OBJECTS=1 before host source
inspection/staging and container committed-script selection. Without it, local
Git replacement refs could substitute source while recording the original SHA.
Extended the existing source-staging fixture with an actual replacement ref;
`bash packaging/build.sh --check` exited 0 (Version/input checks passed).
Mutable feeds, runner provenance and an authorized real release-attestation drill
remain independent release-assurance blockers; no releases were published.

### Attempt 39 — end-to-end offline revocation containment

The attempt-31 command with `--offline-revocation` exited 0 in Debian 13.
nftables isolated only one client's controller TCP path; its preserved cache
reconstructed working traffic before deletion. Real administrator deletion then
removed the reachable peer's WireGuard resources and blocked traffic from the
isolated cached peer. On restoring control access, the deleted identity received
the actual unknown-control-identity rejection and freshness remained Unknown.
The isolated cache remained present: no global offline erasure claim. Intended
restrictive NAT paths and independent edge containment remain separate evidence.

### Attempt 41 — real daemon port exhaustion convergence

Added an ignored kernel-backed daemon-memory regression, not only allocator checks.
Compiled with `cargo test --locked -p cat4igp-client daemon::daemon_memory::two_port_exhaustion_preserves_active_tunnels_and_converges_after_removal --no-run`
(exit 0), transferred executable, then ran:
`sudo unshare --net /tmp/client-tests-41 --exact daemon::daemon_memory::two_port_exhaustion_preserves_active_tunnels_and_converges_after_removal --ignored --nocapture`
(exit 0, one passed, 0.28 s). Two active tunnels retained reservations through
repeated third-tunnel exhaustion; stale-tunnel removal allowed the waiting tunnel
to converge on the released port; empty topology released all resources.

### Attempt 42 — real authenticated endpoint roaming

The attempt-31 command with `--endpoint-roaming` exited 0 in Debian 13.
Authenticated daemon ModifyConfig changed one client's IPv4/IPv6 endpoints;
old underlay addresses were removed. Peer WireGuard endpoints and authenticated
topology cache converged, bidirectional traffic passed, and client processes and
WireGuard identities were unchanged. Subsequent restore passed (15.111 s).
This exercises direct dual-stack paths, not restrictive NAT or proxy refresh.

### Attempt 43 — managed runtime secret containment

Systemd unit now creates a private RuntimeDirectory=cat4igp-client (0700).
L2TPv2 honors only its exact managed path, requiring nonsymlink directory,
effective-UID ownership and exact private mode; invalid environment/metadata fail
closed, unset retains native unmanaged /run behavior.
`cargo test --locked -p cat4igp-client runtime_directory_rejects_unsafe_paths_and_metadata`
exited 0 (one passed). Updated actual-unit containment proof exited 0 in Debian 13,
including service-created runtime sentinel and directory removal after cgroup stop.
Native/OpenRC/procd crash recovery and escaped-cgroup helpers remain outside this
guarantee; no ownership-blind startup scavenger was added.

### Attempt 45 — actual PPP under managed runtime

Transferred freshly compiled `/tmp/client-tests-45`; ran existing PPP driver in
a transient systemd unit with RuntimeDirectory=cat4igp-client, mode0700,
KillMode=control-group, SendSIGKILL=yes and TimeoutStopSec=15s:
`unshare --net --mount bash /tmp/ppp-test.sh /tmp/client-tests-45`.
Unit ExecMainStatus=0; all six kernel/userspace/WireGuard endpoints passed
packet-transfer and cleanup assertions. Managed runtime directory was absent
after unit completion. This verifies actual helper configuration under the new
managed path, not just a sentinel lifecycle.

### Attempt 46 — main-process crash containment

`sudo python3 /tmp/containment/check-service-containment.py --confirm-disposable --main-crash`
exited 0 using the transferred matching packaged unit and proof. Systemd SIGKILL
of its owned main process terminated the session-escaped TERM-resistant descendant
and removed managed runtime secrets. Test uses Restart=no to observe cleanup;
automatic production restart and non-systemd cleanup remain unverified.

### Attempt 47 — automatic systemd restart after crash

`sudo python3 /tmp/containment/check-service-containment.py --confirm-disposable --restart-crash`
exited 0 (retained-output run). The proof reads actual Restart/RestartSec values,
kills only systemd's owned main process, verifies the old escaped descendant is
dead and a new main PID/generation receives fresh runtime state, then verifies
runtime removal on stop. This validates packaged lifecycle properties with a
controlled helper, not enrolled daemon restart traffic or non-systemd supervisors.

### Attempt 44 — static UDP forwarding failure/recovery

Added `nat_integration_test.rs` using actual daemon-memory WireGuard backends
in private-peer/router/public-peer namespaces. Compiled and transferred executable;
`sudo unshare --net --mount /tmp/client-tests-44c --exact daemon::daemon_memory::nat_integration_test::kernel_wireguard_static_udp_forward --ignored --nocapture`
exited 0 (one passed, 17.48 s). Bidirectional encrypted traffic, identities,
handshakes, router-public learned endpoint and positive DNAT/SNAT counters passed.
Removing NAT rules and conntrack blocked traffic; reinstalling rules recovered it.
Initial fixture syntax/marker failures were repaired without weakening assertions.
This is explicit static UDP forwarding, not automatic traversal or arbitrary
restrictive-NAT compatibility.

### Attempt 48 — dependent resource ordering/timing

Transferred compiled executable and ran
`sudo unshare --net /tmp/client-tests-48 --exact daemon::daemon_memory::l2tp::integration_test::reconcile_wireguard_resources_are_shared_and_cleaned --ignored --nocapture`.
Exit 0, one passed; dependent teardown/recreation measured 26 ms for each family.
Assertions require dependent TAP removal while the WireGuard underlay still exists,
and preserve unmanaged-resource checks. This resource-only test has no remote peer;
combined packet recovery is attempt 50, not inferred from these timings.

### Attempt 49 — native enrolled daemon SIGKILL recovery

The attempt-31 command with `--client-crash-recovery` exited 0 in Debian 13.
SIGKILL/restart of the actual same enrolled client preserved kernel interface
indices, identities and ports without manual deletion, then accepted an authenticated
snapshot and passed bidirectional traffic. Four probe streams each delivered 52/52
packets with no missing intervals at 0.2-second resolution; verification interval
9.469 s. Subsequent controller restore also passed (15.089 s). This covers native
kernel WireGuard, not PPP crash cleanup or production outage acceptance.

### Attempt 51 — October enrolled binary upgrade boundary

Added optional `--client-upgrade-from PATH` to the real-client driver. Extracted
actual October Debian package `0.1.0~20261001093604.g7a9f3bc6e2b2-1` in the VM;
baseline enrollment failed with exit 2 at register-bundle because that historical
CLI lacks the trusted-bundle command. No protocol shim, enrollment reset or weakened
trust was introduced. Driver now probes support and reports incompatibility safely.
This artifact cannot supply a current-protocol enrolled upgrade drill; migration
from the old enrollment contract needs an explicit secure migration procedure.
Attempt 52 uses the actual November package as a compatible prior baseline instead.

### Attempt 50 — paired dependent snapshot packet recovery

Compiled and transferred the actual test executable, then ran
`sudo unshare --net --mount /tmp/client-tests-50b --exact daemon::daemon_memory::l2tp_recovery_test::paired_snapshot_dependency_recovery --ignored --nocapture`.
Exit 0, one passed (6.16 s); measured reference reconstruction and packet recovery
3.055 s against a ten-second limit. Two namespace-local daemon memories applied
real WireGuard+L2TP snapshots, exchanged traffic, removed owned resources through
empty snapshots while preserving unmanaged sentinels, then rebuilt and exchanged
traffic again. Initial fixture listener-port mismatch was corrected by constraining
the actual allocation range, not bypassing network assertions. This does not prove
arbitrary production underlay refresh or abrupt-crash ownership recovery.

### Attempt 52 — compatible November enrolled binary upgrade

The driver with `--client-upgrade-from /opt/readiness/baseline52/usr/bin/cat4igp-client`
exited 0 using the extracted real November Debian package and current compiled
candidate. Both prior-binary clients enrolled and passed traffic before replacement;
same protected state then passed authenticated snapshots, unchanged identities and
ports, and bidirectional traffic after upgrade (8.695 s verification interval).
Prior SHA256 `4c39b8af5e75b116d0ab26c813a1d7a919a91ebb65018b327bea39785f3a3e4a`;
candidate SHA256 `7a398a9f795226583d434cfc4451107782dca3e383c8c8114152988173863ac3`.
Subsequent restore passed (15.216 s). This is binary/state compatibility, not a
package-manager transaction, reboot, downgrade or non-x86 validation.

### Attempt 53 — kernel WireGuard CAP_NET_ADMIN-only lifecycle

Transferred compiled test executable and ran
`sudo unshare --net --mount /tmp/client-tests-53c --exact network::privilege_test::wireguard_setup_with_net_admin_only --ignored --nocapture`.
Exit 0, one passed (0.18 s). Selective child retains only CAP_NET_ADMIN;
kernel identity, peer and listener configuration, destruction and recreation pass.
No live-peer handshake or packet-transfer claim. Initial assertions incorrectly
equated setup state with handshake state and assumed exclusive kernel UDP binding;
removed those unsupported assumptions, retaining actual netlink configuration checks.
This is a backend lifecycle profile, not complete daemon/helper minimum privileges.

### Attempt 54 — controlled PPP capability profile

Debian 13 has ppp 2.5.2-1+1 and xl2tpd 1.3.18-1+b1. Ran transferred
`.github/workflows/ppp-test.sh` and compiled `/tmp/client-tests-53c` under
`unshare --net --mount` in transient `readiness-ppp54b`, with `NoNewPrivileges=yes`
and `CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID`.
This is a controlled candidate sufficient profile, not a proven minimum. The first
run's older guest script passed kernel/userspace transfer+cleanup but failed its
WireGuard key fixture; current repository driver was transferred for the complete
run. Whole-driver exit 0: kernel, userspace and WireGuard modes all passed actual
packet-transfer and cleanup assertions on both endpoints. Minimum helper capabilities,
other helper versions and full-daemon profiles remain unverified.

### Attempt 55 — bounded-capability native daemon recovery

Ran the real enrolled restore driver in transient `readiness-daemon55` with
`NoNewPrivileges=yes` and the same six-capability bounding set as attempt 54.
Command: `python3 /opt/readiness/server/tests/restore_enrolled.py --confirm-disposable --server /tmp/cat4igp-server --client /tmp/cat4igp-client`.
Exit 0; both enrolled native WireGuard clients passed dual-link bidirectional
traffic before and after controller restore, unchanged identities and fresh
authenticated snapshots. Measured restore 15.132 s. This demonstrates a sufficient
bounded profile for this native daemon scenario, not minimum privileges or all backends.

### Attempt 56 — negative capability comparison

Transferred executable selective PPP denial filter
`network::privilege_test::l2tpv2_denied_without_sys_admin` passed (exit 0).
Zero-capability backend filter initially encountered ENETUNREACH in the fresh
namespace before reaching raw-socket creation. With loopback explicitly up,
`sudo unshare --net --mount sh -ec 'ip link set lo up; /tmp/client-tests-53c --exact network::privilege_test::backends_fail_closed_without_capabilities --nocapture'`
passed (exit 0), exercising the intended denial boundary rather than network absence.

### Attempt 57 — three-capability native daemon profile

Repeated attempt 55 in `readiness-daemon57` with only CAP_NET_ADMIN,
CAP_SYS_ADMIN and CAP_NET_RAW in CapabilityBoundingSet, retaining NoNewPrivileges.
Driver exit 0, PASS; measured restore 15.179 s. This removes DAC override and
UID/GID-changing capabilities from the sufficient native reference profile without
changing production service defaults. Namespace/driver privileges are included;
this does not establish a minimal long-running daemon profile.

### Attempt 60 — selective L2TPv3 positive comparison

`sudo unshare --net --mount /tmp/client-tests-53c --exact network::privilege_test::l2tpv3_setup_with_net_admin_only --ignored --nocapture`
exited 0, one passed (0.03 s), retaining CAP_NET_ADMIN only inside the verified
selective child. Complements the current executable's negative profiles; this
setup/recreation scenario does not establish paired traffic or namespace-creation minimums.

### Attempt 59 — bounded FakeTCP NAT outage recovery

Ran `sudo unshare --net --mount /tmp/client-tests-53c --exact network::faketcp::tests::routed_conntrack_nat_outage_and_recovery --ignored --nocapture`
inside `readiness-faketcp59` with NoNewPrivileges and only CAP_NET_ADMIN,
CAP_SYS_ADMIN and CAP_NET_RAW in the capability bounding set. Exit 0;
both scenario processes passed (24.11 s), including recovery after the long outage
without clearing conntrack. This is a sufficient profile for the tested routed
fixture, not compatibility with arbitrary deployment NAT or proof of minimum caps.

### Attempt 58 — three-capability PPP profile

Repeated the complete current PPP driver in `readiness-ppp58` with only
CAP_NET_ADMIN, CAP_SYS_ADMIN and CAP_NET_RAW, plus NoNewPrivileges.
Whole-driver exit 0; kernel, userspace and WireGuard endpoint scenarios passed
packet transfer and cleanup with ppp 2.5.2/xl2tpd 1.3.18. Thus DAC override and
UID/GID-changing capabilities are unnecessary for these root-owned fixtures.
This is not a non-root profile, a helper-version-independent minimum, or proof
that namespace/ping orchestration capabilities are needed by every helper.

### Attempt 63 — two-capability PPP reconciliation ownership

In transient `readiness-reconcile63`, ran the exact ignored
`daemon::daemon_memory::l2tp_v2::tests::wireguard_ppp_reconciler_creates_and_removes_resources`
filter using `/tmp/client-tests-53c` under `unshare --net --mount`, with only
CAP_NET_ADMIN/CAP_SYS_ADMIN and NoNewPrivileges. Exit 0, one passed (0.02 s):
unmanaged-source rejection, managed host-address provisioning and dependent removal.
No live PPP peer was provisioned; transfer is covered separately, not inferred here.

### Attempt 64 — namespace creation negative boundary

`systemd-run --wait --pipe` with only CAP_NET_ADMIN/CAP_NET_RAW and
NoNewPrivileges ran `unshare --net --mount true`; observed EPERM and explicit
`namespace-denied-without-sys-admin`, wrapper exit 0. This checks namespace
creation separately from backend operations after namespace setup.

### Attempt 61 — PPP driver without CAP_NET_RAW

Repeated complete PPP driver with only CAP_NET_ADMIN/CAP_SYS_ADMIN and
NoNewPrivileges. Exit 1: PPP reached established call, but ping reported
`socktype: SOCK_RAW` and `socket: Operation not permitted`; packet assertion failed.
This establishes the tested driver's ping requirement, not a PPP-helper raw-socket
requirement. Do not infer failed PPP negotiation from an unavailable traffic probe.

### Attempt 65 — offline backup comparison safeguards

`python3 -m unittest discover -s tools -p test_compare_controller_backups.py`
exited 0, 31 passed. Comparator remains read-only and explicitly does not establish
backup completeness/currentness or reconcile lost acknowledged writes. Older-backup
recovery remains blocked on independently complete history and an authorized
reconciliation contract; no rollback floors or revocation checks were weakened.

### Attempt 62 — native reference driver without CAP_NET_RAW

Repeated native enrolled restore driver in `readiness-daemon62` with only
CAP_NET_ADMIN/CAP_SYS_ADMIN and NoNewPrivileges. Exit 1 at baseline handshake/
traffic timeout. The driver captures ping output rather than exposing it, so this
result does not isolate daemon failure from probe privilege failure. The three-cap
positive remains the supported reference evidence; no minimum claim is made.

### Attempt 66 — damaged-cache trust boundary regressions

`cargo test --locked -p cat4igp-client daemon::topology_cache::tests -- --nocapture`
exited 0, 22 passed. Existing recovery remains journal-bound; no independent
trust anchor can be manufactured from coordinated damaged/rolled-back local state.
Missing/damaged journal recovery therefore remains blocked rather than resetting
identity, reservations or revision protection.

### Operator workload clarification

User specifies intended deployment of 80+ nodes with mixed traffic, but requests
only five nodes in testing to limit resources. Acceptance is best effort;
availability policy is undecided. Five-node reference measurements are authorized,
not extrapolated 80-node capacity or invented production RPO/RTO guarantees.

### Attempt 67 — five-node reference full-mesh restore

Added `--nodes {2,5}` to `server/tests/restore_enrolled.py`; five-node mode
rejects specialized two-node modes and maps actual kernel interfaces through
authenticated cached tunnel-ID/port/peer bindings.
Command in Debian 13: `sudo python3 /opt/readiness/server/tests/restore_enrolled.py --confirm-disposable --nodes 5 --server /tmp/cat4igp-server --client /tmp/cat4igp-client`.
Exit 0, PASS: five enrolled daemons, twenty dual-stack links, eight interfaces per
client; all twenty links delivered 3/3 probes in each direction before and after
restore, preserving identities and authenticated snapshot freshness.
Measured disruption-to-complete-verification interval 109.924 s includes sequential
full-mesh probing; it is not measured packet outage. Lost-write window 0.524 s,
one unrelated unused invitation. Baseline controller RSS 46,720 KiB; client RSS
27,024–27,516 KiB, excluding kernel WireGuard memory. No mixed-traffic throughput,
long soak, 80-node capacity, off-host recovery or availability guarantee is claimed.
Initial launch from /tmp failed helper-relative import; rerun used staged repository layout.

### Attempt 68 — five-node concurrent synthetic TCP/UDP

Ran the attempt-67 command with `--reference-traffic-seconds 30`; exit 0, PASS.
Eight concurrent echo streams across four actual mesh edges span all five nodes
and both underlay families. Payload hashes and sender/receiver byte counts matched.
TCP sender goodput 94.45–95.68 Mbit/s per stream; UDP 11.67–11.91 Mbit/s per stream.
All daemons survived with authenticated snapshot ages 6–8 s after traffic;
controller sampled RSS 46,844 KiB, clients 27,268–27,596 KiB, excluding kernel memory.
Subsequent complete twenty-link restore verification passed (110.036 s including
sequential probes). This 30-second synthetic echo workload is not a long soak,
production traffic mix, saturation benchmark or extrapolated 80-node capacity.

### Attempt 69 — five-minute five-node synthetic soak

Repeated attempt 68 with `--reference-traffic-seconds 300`; exit 0, PASS.
Eight overlapping TCP/UDP streams passed payload hashes and byte accounting;
measured orchestration wall time 314.598 s. TCP sender goodput 95.31–95.74 Mbit/s
per stream, UDP 11.78–11.83 Mbit/s per stream. All five authenticated snapshot
ages were 16–18 s after traffic. Subsequent twenty-link restore verification
passed (109.882 s including sequential probes). This supplies bounded five-node
best-effort soak evidence, not 80-node capacity, saturation or a production SLO.

### Attempt 70 — five-node controller outage during mixed traffic

Ran attempt 68 with `--reference-traffic-seconds 60 --reference-controller-outage`;
exit 0, PASS. All eight stream processes stayed active at controller stop and
reconnection; payload hashes and byte accounting passed. Controller was stopped
5.008 s before restart request; all five fresh authenticated snapshots verified
26.434 s after stop (21.426 s restart/reconciliation), ages 0–2 s. Subsequent
separate twenty-link restore verification passed (110.049 s including probes).
No zero-packet-outage claim follows from echo completion; this tests cached
data-path continuity and bounded reconnection in the five-node reference only.

### Attempt 71 — five-node dual-stack endpoint roaming

Ran `sudo python3 /opt/readiness/server/tests/restore_enrolled.py --confirm-disposable --nodes 5 --endpoint-roaming --server /tmp/cat4igp-server --client /tmp/cat4igp-client`.
Exit 0, PASS. Client0 changed both advertised address families; old addresses
were removed, all eight affected kernel endpoints/controller records/authenticated
caches converged, and all twenty links passed bidirectional traffic without
restarting clients or changing WireGuard identities. Snapshot ages 0–1 s;
complete roaming verification 108.155 s including sequential probes, not packet
outage. Subsequent restore verification passed (110.056 s). Restrictive NAT,
proxy roaming and dependent dual-link refresh remain separate requirements.

### Attempt 72 — five-node offline revocation containment

Ran attempt 71 command with `--offline-revocation` instead of roaming; exit 0,
PASS. Client0's controller path alone was isolated and cached traffic verified.
All four reachable peers removed the eight revoked tunnel resources/intents and
blocked traffic from the revoked peer. Twelve survivor links retained identities
and passed bidirectional traffic before/after the revoked client's reconnection.
Reconnected identity was explicitly rejected and freshness became Unknown;
isolated cached intent remained unchanged, demonstrating the offline enforcement
limit rather than erasing it. No global offline revocation or NAT claim is made.

### Operator connectivity and cache policy

User requires public UDP, static forwarding, both-peers CGNAT without forwarding,
and restrictive/TCP-only egress paths. Cached connectivity is explicitly accepted
when both peers lack controller access; with a reachable peer, the controller must
still return that tunnel as valid. Authenticated removal therefore overrides that
peer's cache; disconnected peers cannot learn an unseen revocation. Existing
five-node revocation proof enforces the reachable-peer rule. CGNAT rendezvous/relay
and genuine TCP-only transport remain required evidence/capability gaps; FakeTCP
packet shaping is not a TCP stream and cannot be represented as TCP-only support.

### Restrictive-path decision

User explicitly defers data-plane relay support. Both-peers CGNAT without
forwarding and genuine TCP-only egress remain unsupported required paths and
readiness blockers. Do not reinterpret FakeTCP or the controller-only relay as
data-plane coverage; public UDP/static forwarding remain the verified scope.

### Attempt 73 — five-node authenticated damaged-cache repair

Ran attempt 71 command with `--damaged-cache-repair`; exit 0, PASS.
Only client0's cache was corrupted, retaining its revision journal/enrollment;
four other daemons remained running. Authenticated repair preserved all eight
port bindings and tunnel identities, fresh repaired-link handshakes, and traffic
across all twenty links. Subsequent restore verification passed (110.274 s including
probes). Missing/damaged journals and coordinated rollback remain outside this
trustworthy repair path; no revision floor was lowered.

### Owner-selected recovery alternative

When trustworthy current history is unavailable, user selects explicit fresh-network
enrollment rather than preserving old enrollment through an unverifiable restore.
Documented a fenced cutover design in deployment.md: independent old-peer traffic
containment, protected forensic state, fresh controller/network/client identities,
individually reauthorized trusted bundles, exclusion checks and permanent old-network
fencing. This is not implemented/tested cutover automation and does not close
older-backup reconciliation or missing-journal recovery. Backup/key policy remains
explicitly undecided; no production keys or state were changed.

### Attempt 74 — recovery probe accounting

`python3 server/tests/test_restore_enrolled.py` exited 0, four passed. This validates
probe accounting only; actual five-node repair proof is attempt 73.

### Attempt 75 — durable revocation survivor regression

`cargo test --locked -p cat4igp-server offline_node_deletion_revokes_identity_and_updates_only_surviving_peers -- --nocapture`
exited 0, one passed. Confirms existing deletion/revocation and survivor-update
contract; does not substitute for an old-to-new network cutover drill.

### Attempt 76 — fresh-network rejects old credentials

Added `submission_tests::fresh_network_rejects_old_control_peer_and_unused_invitation`
in server/src/main_test.rs. Exact command:
`cargo test --locked -p cat4igp-server fresh_network_rejects_old_control_peer_and_unused_invitation -- --exact submission_tests::fresh_network_rejects_old_control_peer_and_unused_invitation`.
Exit 0, one passed. Independently initialized fresh database/control handler rejects
the old enrolled peer as unknown and rejects an unused old invitation; fresh state
remains unenrolled and old identity revision/invitation usage remain unchanged.
This verifies a cutover trust boundary, not live fencing, reenrollment traffic or
complete recovery. A full cutover drill remains missing; no unsafe driver refactor
or rollback-floor reset was substituted for it.

### Attempt 77 — blocked refresh candidate preserves active traffic

Compiled/transferred actual test executable and ran
`sudo env CAT4IGP_REFRESH_BLOCK_CANDIDATE=1 unshare -n /tmp/client-tests-77b --exact daemon::daemon_memory::refresh_integration_test::kernel_dual_link_refresh --ignored --nocapture`.
Exit 0, one passed (11.63 s). nft candidate-port drops prevented handshake and
readiness while the old link remained active and passed traffic on both peers;
drop counters proved the blocked transport was exercised. Removing the drops
allowed handshake, switch, old-interface cleanup and new-link traffic.
Initial fixture treated Some(UNIX_EPOCH) as a handshake; corrected the predicate
to require a nonzero recent nonfuture timestamp, retaining all failure assertions.
This is a reference refresh failure, not arbitrary proxy/NAT deployment coverage.

### Attempt 78 — unblocked refresh compatibility

`sudo unshare -n /tmp/client-tests-77b --exact daemon::daemon_memory::refresh_integration_test::kernel_dual_link_refresh --ignored --nocapture`
exited 0, one passed (6.09 s). The corrected handshake predicate retains the
original successful dual-link switch/cleanup scenario as well as attempt 77's denial path.

### Attempt 79 — release source guard self-checks

`bash packaging/build.sh --check && bash packaging/check-release-tag.sh --check && bash packaging/image-tag.sh --check`
exited 0 (`Version/input checks passed`). These local checks do not authenticate
mutable feeds, the release runner or published artifacts. Real tagged publication
and attestation remain outside authorized scope; no release was published.

### Attempt 80 — supervisor leader-exit containment regression

`cargo test --locked -p cat4igp-client tunnel::l2tp_v2::tests::unexpected_leader_exit_terminates_remaining_group_members -- --exact`
exited 0, one passed. Owned-group cleanup after helper leader exit remains verified;
this does not establish escaped-session containment after unmanaged daemon SIGKILL
or durable ownership of stale netlink resources. Those require a real ownership/
launcher design, not name-based deletion or signals to potentially reused PIDs.

### Attempt 81 — enrolled Debian package reinstall recovery

Added explicit `--client-reinstall-deb PATH`, distinct from binary upgrade.
Installed actual November package, then ran
`sudo python3 /opt/readiness/server/tests/restore_enrolled.py --confirm-disposable --nodes 2 --server /tmp/cat4igp-server --client /usr/bin/cat4igp-client --client-reinstall-deb /tmp/baseline52.deb`.
Exit 0, PASS. Actual `dpkg --force-confold -i` transaction preserved enrollment,
cache and journal bytes, followed by unchanged identities/ports, fresh authenticated
snapshots (ages 0 s) and bidirectional traffic; verification 8.842 s.
Package version `0.1.0~20261114222031.gd4ded0e231d9-1`, SHA256
`a91a94158194414dba9ce59e5295fc49687568c65b8ac5f9cc11cf5bd6e9a148`.
This is same-version/same-artifact reinstall, not a version upgrade, reboot or
service-manager lifecycle proof. Cross-architecture and enrolled reboot remain open.

### Attempt 82 — enrolled packaged systemd lifecycle

Ran attempt 81 command with `--packaged-service`; exit 0, PASS. Driver uses
unique runtime copies of the installed package unit, overriding only drill paths,
namespace/state/runtime directories and logging. Actual systemctl start/stop,
same-version dpkg reinstall, unit reload and enrolled reconnection passed with
identities/ports/traffic preserved; subsequent restore verification 15.329 s.
Cleanup removes only generated units/directories. This verifies installed unit
lifecycle under scoped overrides, not default-path boot ordering, reboot persistence,
version upgrade or other architectures.

### Attempt 83 — automatic packaged restart after enrolled SIGKILL

Ran attempt 82 with `--packaged-crash-recovery`; exit 0, PASS. systemctl signals
the owned unit's main process, not a guessed numeric PID. Requires increased
restart count and changed MainPID under installed Restart=on-failure behavior,
then fresh authenticated snapshots, unchanged enrolled identities/ports and
bidirectional traffic without manual tunnel deletion. Subsequent actual reinstall
and restore also passed (15.304 s restore verification). This native WireGuard
service scenario does not prove PPP crash ownership or machine reboot recovery.

### Attempt 84 — actual enrolled Debian reboot recovery

Added persistent `--prepare-reboot DIR`, `--verify-reboot DIR` and manifest-owned
`--cleanup-reboot DIR` phases. Prepared two enrolled package-derived units with
persistent controller/state/topology, performed actual `systemctl reboot`, waited
180 seconds and observed the console login prompt before guest commands.
Verification exited 0, PASS: changed boot ID, automatically active topology,
controller and both client units, unchanged artifacts/identities/ports, nondecreasing
revision floors, fresh authenticated snapshots and bidirectional traffic on both
links. Verification took 8.499 s after invocation, not boot-time availability.
Initial reboot exposed multiline private-network key corruption through systemd
EnvironmentFile serialization; fixed using owner-only JSON and os.execve launcher,
cleaned the failed fixture and repeated a real reboot without weakening checks.
Owned unit/topology cleanup exited 0; protected fixture secrets remain in the
disposable VM at /opt/readiness/reboot84 and reboot84b pending explicit disposal.
This establishes scoped Debian amd64 enrolled reboot recovery, not default-path
production boot policy, version upgrade or other architectures.

### Attempt 85 — historical Arch enrolled package boundary

Created disposable readiness-arch85, waited 180 s and observed login console,
transferred actual server/package/driver and installed Python/wireguard harness
dependencies. Actual November Arch 34af package enrolled and passed baseline
traffic, but driver exited 1 requiring authenticated snapshot freshness.
Historical status CLI and IPC lack the age field and daemon tracking, so no CLI
shim can prove this acceptance requirement. Freshness assertions remain intact.
Building a commit-bound newer Arch artifact for the next scenario; no fake package
version or unsupported freshness inference. User retains all advertised architecture
scope, so non-x86 verification remains an explicit blocker.

### Attempt 86 — freshness-capable Arch packaged recovery

`bash packaging/build.sh arch x86_64` exited 0 and produced commit-bound
`0.1.0alpha20261114222031.gd4ded0e231d9-1`; transferred and installed it in
readiness-arch85. Ran the real enrolled driver with `--client /usr/bin/cat4igp-client
--client-reinstall-arch /tmp/arch86.pkg.tar.zst --packaged-service`.
Exit 0, PASS: actual pacman reinstall and package-derived systemd lifecycle retained
enrollment/cache/journal, identities/ports, authenticated freshness and traffic.
Subsequent controller restore verification passed (15.162 s). This is current
same-version reinstall recovery, not an enrolled old-version upgrade or reboot.

### Attempt 87 — actual enrolled Arch reboot recovery

Prepared the two-node package-derived persistent fixture using
`--client-reinstall-arch /tmp/arch86.pkg.tar.zst --packaged-service --prepare-reboot /opt/readiness/reboot87`,
performed actual systemctl reboot, waited 180 s and observed login console.
`--verify-reboot /opt/readiness/reboot87` exited 0, PASS: changed boot ID,
automatically active controller/topology/client units, retained identities/ports/
revision floors and fresh bidirectional traffic on both links. Verification
8.588 s after invocation, not boot-time RTO. Manifest-owned cleanup exited 0;
protected fixture state remains in the disposable VM. This closes this Arch
x86-64 reference reboot scenario only, not all supported architectures or sysupgrade.

### Attempt 88 — Arch packaged automatic SIGKILL recovery

Ran actual two-node enrolled `--client-reinstall-arch` driver with
`--packaged-service --packaged-crash-recovery` in readiness-arch85: exit 0.
The scenario requires automatic restart after owned MainPID SIGKILL, changed PID
and increased restart count, retained enrollment/identities/ports, authenticated
freshness and bidirectional traffic without manual tunnel deletion. Subsequent
controller restore passed (15.160 s verification). Initial invocation failed
before enrollment because reboot cleared /tmp server/package prerequisites;
retransferred actual artifacts and reran without weakening checks. Native
WireGuard reference only; PPP, other supervisors and architectures remain open.

### Attempts 89–90 — Arch roaming recovery interaction

Attempt 89 combined `--damaged-cache-repair --client-crash-recovery
--endpoint-roaming` against the actual installed Arch client. It exited 1 at
post-roaming authenticated freshness, after endpoint convergence; this is an
unresolved combined-scenario regression, not a passing roaming result.
Attempt 90 isolated `--endpoint-roaming` with otherwise identical server/client:
exit 0, fresh authenticated snapshots, endpoint/cache convergence and traffic;
subsequent restore verification 15.002 s. Do not infer combined recovery safety
from the isolated pass. Logs retained at /opt/readiness/state89.log and roam90.log
in readiness-arch85. No freshness assertion or rollback floor was weakened.

### Attempt 91 — isolated post-crash roaming regression

Removed damaged-cache repair from attempt 89, retaining native client SIGKILL/
restart followed by endpoint roaming. Exit 1 at the same post-roaming fresh
authenticated snapshot assertion, after endpoint/cache convergence. Together with
attempt 90's isolated roaming pass, this narrows the observed failure to the
crash-then-roaming path; the root cause is not yet established. Driver log:
/opt/readiness/interaction91.log in readiness-arch85. No production readiness
claim, assertion relaxation or automatic state deletion is justified.

### Attempt 92 — safe post-roaming freshness diagnostics

Added age-only diagnostics on changes while preserving all original acceptance
assertions. Transferred the driver and ran the attempt-91 command again: exit 0,
post-roaming ages [1, 4] seconds and restore verification 14.998 s. This shows
the failure is intermittent, not a proven deterministic daemon defect or a fix.
Both clients poll on independent 30-second schedules while the existing check
requires simultaneous ages <=5 seconds; schedule skew is a candidate cause,
not yet proven. Keep failed attempts 89/91 as unresolved evidence. Diagnostic
output contains only snapshot ages, not configuration, identities or secrets.

### Attempts 93–94 — independent post-roaming freshness observations

Attempt 93 exited 1 with diagnostics proving both authenticated snapshot ages
reset independently: [0,18], then [12,0], repeating at 30-second cadence.
Neither daemon stopped receiving snapshots; simultaneous <=5-second ages were
an invalid synchronization requirement for independent pollers.
Fixed the driver to require each client individually observed at <=5 seconds
with a snapshot newer than the roaming request, retaining authenticated_ages'
90-second current-age bound and all endpoint/cache/identity/traffic assertions.
Attempt 94 ran `python3 /opt/readiness/server/tests/restore_enrolled.py
--confirm-disposable --nodes 2 --server /tmp/cat4igp-server
--client /usr/bin/cat4igp-client --damaged-cache-repair --endpoint-roaming
--client-crash-recovery` with the transferred driver: exit 0. Observations
[0,18] and [11,0] exercise the formerly failing skew; full combined recovery
and subsequent restore passed (14.977 s verification). This resolves the
reference driver synchronization failure, not intended deployment NAT proof.

### Attempt 95 — Arch offline-client revocation containment

Ran `python3 /opt/readiness/server/tests/restore_enrolled.py
--confirm-disposable --nodes 2 --server /tmp/cat4igp-server
--client /usr/bin/cat4igp-client --offline-revocation` in readiness-arch85:
exit 0. Existing assertions exercise isolated control connectivity, cached
traffic, reachable-peer revocation and rejection after reconnect. Subsequent
restore verification 14.979 s. This does not revoke disconnected-to-disconnected
cached traffic or establish restrictive NAT connectivity; independent deployment
edge containment remains required. Local driver parser regression command
`python3 server/tests/test_restore_enrolled.py` also exited 0 (4 tests).

### Attempt 96 — Arch offline cached restart

Ran attempt 95's exact server/client command replacing `--offline-revocation`
with `--offline-client-restart`: exit 0. Existing assertions require cached
tunnel reconstruction with controller offline and retained identity/traffic;
subsequent authenticated restore verification passed (14.939 s). Cache
availability is not offline revocation or recovery from a lost revision journal.

### Attempt 97 — release input safety and owner scope decision

`bash packaging/build.sh --check && bash packaging/check-release-tag.sh --check
&& bash packaging/image-tag.sh --check` exited 0 (`Version/input checks passed`).
This verifies local input/tag guards, not publisher identity or attestations.
The owner explicitly selected reference-staging scope again and supplied no
production requirements. Production acceptance, availability/RPO/RTO, backup/key
custody and deployment network-policy items therefore remain blocked on those
owner decisions; do not invent values or mark them complete. Tagged publication
remains outside scope, and no supported non-x86 guest image is available in the
current Terrarium inventory. Those require authorized infrastructure/access,
not a weaker x86-only acceptance claim.

### Attempts 98–99 — recovery safety boundaries

98: `python3 -W error::ResourceWarning -m unittest discover -s tools
-p test_compare_controller_backups.py` exited 0, 31 tests passed. Comparator
checks do not supply independently complete acknowledged enrollment/revocation
history; older-backup reconciliation remains blocked on that trust anchor.
99: `cargo test --locked -p cat4igp-client daemon::topology_cache::` exited 0,
22 passed. Together with attempt 94's actual VM cache repair, this verifies
the covered fail-closed repair paths, not reconstruction of missing/damaged
journal high-water marks. Independent current state and a validated legacy
recovery procedure remain necessary; deleting journals is not a workaround.

### Attempt 100 — local PPP supervisor ownership regressions

`cargo test --locked -p cat4igp-client tunnel::l2tp_v2::tests::` exited 0,
12 passed, 1 privileged packet-transfer test ignored. This proves only local
supervisor regressions; it does not replace VM packet-transfer proof. Remaining
unclean-exit closure requires namespace-init/parent-death containment outside
systemd and durable netlink/secret-directory ownership that cannot mistake
unmanaged resources for stale owned ones. No PID/name-only cleanup was added.

### Attempts 101–103 — native two-capability boundary

101: Arch real enrolled baseline driver under systemd NoNewPrivileges=yes and
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN exited 1 at baseline
handshake/traffic timeout. Command otherwise matches attempt 95 without its
specialized flag. No daemon minimum-privilege conclusion follows from this
whole-driver failure. Log: /opt/readiness/caps101.log in readiness-arch85.
102–103: Under the same bounding set, `ping -n -c 1 -W 1 127.0.0.1` and
`ping -n -c 1 -W 1 -I lo 127.0.0.1` each exited 0, one reply. Thus the failure
cannot simply be attributed to all ICMP probes requiring CAP_NET_RAW; actual
tunnel/helper diagnostics and separation of orchestration privileges are still
needed. Production capability defaults remain unchanged.

### Attempt 104 — three-capability Arch native comparison

Repeated attempt 101 with CAP_NET_RAW added to CapabilityBoundingSet, keeping
NoNewPrivileges=yes and the same actual server/client/driver. Exit 0: enrolled
dual-link traffic, authenticated freshness and restore passed (14.997 s).
This establishes a sufficient whole-fixture three-capability profile, not a
minimal daemon profile or proof that raw sockets caused attempt 101's failure.
Do not remove capabilities from production based on this comparison alone.

### Attempts 105–106 — isolated namespace probe privilege boundary

In a fresh `unshare --net` namespace under systemd NoNewPrivileges and
CAP_NET_ADMIN/CAP_SYS_ADMIN, created a private veth pair, assigned
198.18.250.1/30 and .2/30, raised both links, then ran
`ping -n -c 1 -W 1 -I probe0 198.18.250.2`. Attempt 105 exited 2 with
`ping: socktype: SOCK_RAW` / `ping: socket: Operation not permitted`.
Attempt 106 added CAP_NET_RAW: raw socket creation succeeded, but the same-
namespace veth topology returned no echo (exit 1); no packet-transfer claim.
Unlike host loopback tests 102–103, the fresh network namespace exposes the
probe's raw-socket requirement. This identifies a driver privilege dependency,
not a demonstrated daemon/helper minimum. All resources disappear with the
private namespace; no host interfaces or production services were modified.

### Attempts 107–108 — namespace-local ICMP policy cause

107: Under the same two-capability profile, fresh `unshare --net` reported
`/proc/sys/net/ipv4/ping_group_range` as `1 0`; loopback ping exited 2 with
SOCK_RAW/Operation not permitted. 108: In another disposable private namespace,
`echo 0 0 >/proc/sys/net/ipv4/ping_group_range; ip link set lo up;
ping -n -c 1 -W 1 127.0.0.1` exited 0 (one reply), without CAP_NET_RAW.
This proves namespace ICMP datagram policy can remove the probe-only raw-socket
requirement. Host policy and production service capabilities were not changed.
Full enrolled traffic with separated probe/daemon privileges is still missing.

### Attempt 109 — enrolled native recovery without CAP_NET_RAW

The driver now sets `net.ipv4.ping_group_range=0 0` only inside each newly
created owned client network namespace, enabling root-group ICMP datagram probes.
Transferred driver; repeated attempt 101's exact two-capability systemd profile
with NoNewPrivileges=yes: exit 0. Actual enrolled dual-link packet transfer,
authenticated freshness and controller restore passed (14.992 s verification).
This resolves the fixture's probe-only CAP_NET_RAW dependency for native
WireGuard; no host sysctl or production service setting changed. CAP_SYS_ADMIN
still covers orchestration, and non-root/PPP/FakeTCP helper minima remain open.

## Current continuation stop boundary

The active objective specifies at most 30 fix-or-validation attempts. Historical
authorization above allowed 31–130, but does not override the current narrower
cap. Attempts 80–109 alone comprise 30 counted scenarios; no additional scenario
is authorized by assuming the counter restarted on a continuation. Stop further
validation here pending explicit renewed authorization. No broad unchecked item
is promoted from partial reference evidence.

Remaining closure requirements:

| Open item | Missing evidence or decision |
| --- | --- |
| Older controller backup | Independently complete acknowledged enrollment/revocation history and a verified reconciliation procedure retaining rollback protection |
| Corrupt topology cache | Independent current trust anchor for missing/damaged journals and validated legacy reservation recovery |
| Unclean L2TP exits | Abrupt-death containment outside systemd, escaped-helper regressions and durable netlink/secret ownership without touching unmanaged resources |
| Offline revocation/NAT | Intended restrictive-NAT path tests and independently enforced edge containment for disconnected peers |
| Artifact integrity | Authorized tagged publication/attestation drill and approved runner/feed provenance policy; publication is outside current scope |
| Production acceptance | Owner-approved intended workload/path targets, off-host verification and complete detection/notification/key-retrieval measurements |
| Standalone availability | Owner-approved service hours, RPO/RTO, on-call/key custodians and measured acceptance against those budgets |
| Secrets/backups | Approved production encryption-at-rest/key custody and existing-deployment permission verification |
| Privilege boundaries | Daemon/helper versus orchestration minima, non-root device/filesystem access and intended backend/version profiles; attempt 109 covers only native root-owned reference traffic |
| Roaming/dual-link refresh | Intended NAT/roaming topology and dependent-tunnel interruption measurements; reference driver synchronization is fixed, not deployment acceptance |
| Packages | Enrolled version upgrades on all supported architectures and actual OpenWrt replacement-firmware sysupgrade; x86 reference reinstall/reboot is insufficient |

The owner retained reference-staging scope and supplied no production policy
values. Golden images, releases, remote branches and production systems remain
outside these verification changes. Protected reboot fixture state remains at
/opt/readiness/reboot87 in disposable readiness-arch85 for explicit disposal.
