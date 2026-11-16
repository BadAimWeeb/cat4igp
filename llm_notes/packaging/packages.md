# Client packages

The client package includes the CLI, a root-run service and
`/etc/cat4igp/client.toml`. Services are installed **without enabling or
starting them**. Linux kernel WireGuard support is required; OpenWrt declares
`kmod-wireguard`. No server or firewall configuration is installed.

| Build environment | Architectures | Service |
| --- | --- | --- |
| Alpine 3.24 | x86_64, aarch64, riscv64 | OpenRC |
| Debian 13 (trixie) | amd64, arm64, riscv64 | systemd |
| Arch Linux | x86_64 | systemd |
| OpenWrt 25.12.5 | x86/64, armsr/armv8 | procd |
| Static musl binary | x86_64, aarch64 | Administrator-managed |

Build images, OpenWrt SDK checksums and the packages feed are specified
in `packaging/build.sh` and the workflow (paths are repository-root relative).
The workflow pins GitHub Actions to commit SHAs. Package repositories inside the
images remain mutable: these are ABI-appropriate builds, not bit-for-bit
reproducible builds, and pinned images do not authenticate later feed contents.

## Builds and downloads

Default-branch commits and manual runs produce SNAPSHOT packages retained as
Actions artifacts for 14 days. Versions include the commit time and hash
(Alpine and OpenWrt encode the hash as a number) and sort before the corresponding final
release. Release tags must be `vX.Y.Z` matching `client/Cargo.toml`; matrix build
jobs attest their own package and dependency manifest. All eleven builds must
succeed before the release job verifies those attestations and assembles a draft
containing each package or binary, dependency manifest, build-provenance bundle,
and `SHA256SUMS` (34 files). The publisher also attests the assembled files,
re-downloads the draft, checks checksums and verifies attestations before publishing.
A failed check leaves the draft unpublished.
The workflow checks that the release tag resolves to the source commit immediately
before creating and publishing the draft, but these checks are not atomic with
publication. Restrict tag creation and updates with repository rules; independently
verify the released artifact's attested source revision.

RISC-V matrix builds currently trust RISE self-hosted runners; the attestation
does not independently establish that a runner is RISE-operated. Other matrix
builds and the publisher require GitHub-hosted runners. Replace this exception
when a trusted GitHub-hosted RISC-V build path is available.

Manual runs never publish releases. Release filenames identify the distro
and architecture to avoid collisions. This updated tagged release path has not
yet been verified on an actual tagged run; do not treat its configuration as
evidence that a published release passed.

For local builds, invoke `bash packaging/build.sh DISTRO ARCH` on a matching
architecture Linux machine with Docker, using `alpine`, `debian`, `arch` or
`openwrt` or `static` and `x86_64` or `aarch64` (Arch supports x86_64 only).
Debian and Alpine additionally support `riscv64`, built natively on
`ubuntu-24.04-riscv` RISE runners. Debian uses Rust 1.94.0's
`riscv64gc-unknown-linux-gnu` host; Alpine uses its native Rust/Cargo
1.96.1-r0 packages because upstream 1.94.0 has no prebuilt RISC-V musl host.
Alpine's native Cargo does not apply the rustup toolchain file. RISC-V builds
use the toolchain's default RV64GC baseline, not runner-specific CPU tuning.
Both OpenWrt builds require an x86_64 host.
Outputs go to `dist/DISTRO-ARCH/`. Builds package the committed `GITHUB_SHA`
(or local `HEAD`), not working-tree changes or untracked files; commit changes
before building. The checked-out client version must match that commit. The
build script itself is run from the checkout and should also be trusted.
Source inspection, archive staging and container committed-script selection disable
Git replacement refs; local `refs/replace` cannot substitute another tree under the
recorded source SHA. This does not authenticate the checkout, upstream feeds or runner.
The workflow builds only `cat4igp-client` with locked dependencies. Rust and native
crypto compilation need substantial
memory, disk space and network access. OpenWrt uses the checksummed prebuilt
release SDK for its C compiler/sysroot and upstream Rust 1.94.0 binaries plus
the matching musl standard library; it does not rebuild rustc or LLVM.
The pinned feed still supplies Cargo/linker integration. This prebuilt Rust
path supports only the listed x86_64 and aarch64 targets; custom targets may
require the feed's source-built `rust/host` toolchain.

Each target also produces `BUILD-DEPENDENCIES.txt`, recording its target, source
revision and sorted installed system package versions in the build container.
OpenWrt's list describes the Debian SDK host container, not a complete OpenWrt
target dependency bill of materials. The manifest is inventory, not proof of
feed integrity, complete transitive inputs or reproducibility. Review it alongside
the independently verified release artifact and attestation; assess and verify
mutable upstream feeds independently.

Standalone packages are not published through signed distribution
repositories. Alpine packages use a disposable build signing key: installation
requires explicitly allowing an untrusted package after independently verifying
its provenance and checksum. Do not disable signature verification globally.
OpenWrt packages similarly require an appropriate trust decision for local APKs.
OpenWrt and Alpine APKs are **not interchangeable**; the OpenWrt kernel package
ABI must match the supported firmware release.

## Configure and activate

### Portable binaries

`static` artifacts are standalone executable `cat4igp-client` binaries for
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`. They statically
link libc and native dependencies and need no glibc or dynamic loader. Builds
use baseline x86-64 / ARMv8-A rather than runner-specific CPU tuning; optimized
crypto implementations may select faster instructions at runtime. Each build
checks ELF architecture, absence of an interpreter and shared dependencies,
and successful `--help` execution on its native runner.

After downloading, verify provenance and checksum as described in the
[deployment guide](../server/deployment.md#client-artifact-provenance), set executable permission
(`chmod +x`), and install the binary wherever appropriate. These artifacts do
not install configuration, services or licenses separately; the project is
MIT-licensed (see the repository `LICENSE`). Linux kernel support for the Rust
target remains necessary (normally Linux 3.2+ on x86_64 and 4.1+ on aarch64),
and actual tunnel operation requires kernel WireGuard, root/network
privileges, DNS/network access and suitable configuration. Static linking
does not make this a Windows/macOS binary or remove kernel requirements.

### Distribution packages

Install the matching package with the native package manager. As root, edit
`/etc/cat4igp/client.toml` for local settings. The port range upper bound is
exclusive. Keep configuration mode `0600`; bootstrap addresses and the private
control-network key belong in a trusted enrollment bundle, not this file.
Debian upgrades can prompt when both the shipped and locally modified conffile
change. For an unattended upgrade that preserves local configuration, use
`apt-get -o Dpkg::Options::="--force-confold" install cat4igp-client`, then
review any `.dpkg-dist` file and merge required changes deliberately.
Schedule a maintenance window and stop the daemon before a Debian upgrade. The
package deliberately does not start services; an upgrade from an older package
can leave a previously running daemon stopped. After reviewing configuration,
run `systemctl daemon-reload` and `systemctl start cat4igp-client`, then verify
`cat4igp-client --config /etc/cat4igp/client.toml status` and enrolled tunnel traffic.
An enabled service starts after reboot; this is not a zero-downtime upgrade.

Start the service explicitly with `systemctl start cat4igp-client`,
`rc-service cat4igp-client start`, or `/etc/init.d/cat4igp-client start`.
Then enroll with `cat4igp-client --config /etc/cat4igp/client.toml
register-bundle --bundle /secure/enrollment.json`. Obtain the bundle via a trusted
operator channel, protect it as a secret, and delete it after registration. This
connects to the running daemon; it does not automatically enable boot startup.
Check with `cat4igp-client --config /etc/cat4igp/client.toml status`.

Once configured, enable boot startup using `systemctl enable cat4igp-client`,
`rc-update add cat4igp-client default`, or `/etc/init.d/cat4igp-client enable`.
Private identity, bootstrap addresses, private-network key and daemon authentication
state live in `/var/lib/cat4igp-client`, or `/etc/cat4igp/state` on OpenWrt;
enrollment is daemon-owned `server.json`, not user configuration. State directories
are `0700`; generated credentials are not package payloads. OpenWrt registers
only `/etc/cat4igp/client.toml` and the default `/etc/cat4igp/state/` for sysupgrade
retention when keeping configuration. If `data_dir` is customized, add its path to
the device's sysupgrade retention list and verify the backup includes it before
upgrading. Backups contain secrets and must be protected. Preserve existing state
during upgrades; do not purge it unless intentionally discarding the enrolled identity.

## Client privilege boundary

The shipped services run as root without a capability bounding set. This is a
compatibility default, **not** a least-privilege or sandbox guarantee. A trusted
controller can request every backend enabled locally; the controller, client
binary, service configuration and helper executables are privileged trust inputs.
Keep `PATH` and its directories administrator-owned (no writable or relative
entries); FakeTCP invokes `nft`, and L2TPv2 invokes `xl2tpd` and `pppd` through it.
Keep the state directory private and writable by the service identity, and the
socket directory protected against replacement by other users.

The following are source-derived Linux requirements, not a verified exact
minimum-capability profile for every kernel, distribution or external helper:

| Enabled path | Required operations and deployment boundary |
| --- | --- |
| Control plane, UDP STUN, fixed TCP relay | Ordinary TCP/UDP sockets, DNS, private state and Unix socket access; a configured port below the namespace's unprivileged-port threshold can additionally require `CAP_NET_BIND_SERVICE`. No tunnel capability is needed when both tunnel protocols are disabled. |
| Kernel WireGuard (including FEC, proxy and dual-link) | `CAP_NET_ADMIN` in the target network namespace for WireGuard and route-netlink interface/address/MTU changes; kernel WireGuard must already be available. FEC and UDP proxy add ordinary UDP sockets, not raw sockets. |
| WireGuard FakeTCP | WireGuard requirements plus `CAP_NET_RAW` for raw TCP sockets and `CAP_NET_ADMIN` for nftables. The external `nft` process must inherit sufficient privileges; giving only the parent file capabilities does not establish that. |
| L2TPv3 Ethernet | Network administration for L2TP generic netlink, interface, address and routing changes, plus supported kernel L2TP modules. Do not assume an unprivileged UDP socket alone enables this backend. |
| L2TPv2/PPP | Root-run `xl2tpd`/`pppd`, PPP device access and networking privileges; the client explicitly creates a mount namespace and bind-mounts private PPP configuration, requiring `CAP_SYS_ADMIN`. Helper versions, kernel acceleration and device policy can impose further requirements. `l2tp_v2_userspace` does not remove the mount-namespace or PPP privilege requirement. |

For a reduced-privilege deployment, start with `tunnel_protocols.l2tp = false`
and a dedicated network namespace/VM. A WireGuard-only capability ceiling is a
candidate for local validation, not a shipped supported non-root service profile.
Do not grant `CAP_SYS_MODULE` to load missing modules: arrange kernel support
outside the daemon. `CAP_NET_ADMIN` can change the namespace's entire network and
firewall configuration; these capabilities are not restricted to CAT4IGP links.
Prefer a dedicated network namespace or VM over granting them in a shared host
namespace. Namespace creation/setup may itself require additional launcher
privileges; those are not daemon runtime requirements. Dropping capabilities,
using `NoNewPrivileges`, restricting `/dev/ppp`, or prohibiting mount namespaces
can break external helpers even when the parent starts successfully.

Backend setup propagates privileged syscall/netlink failures; there is no fallback
to an unencrypted tunnel or less privileged backend. Capability advertisement
checks local policy/platform/helper availability, not effective capabilities or
kernel module readiness. A running daemon or advertised feature is therefore not
evidence of a functioning data path. Validate each enabled backend end to end on
the deployment kernel before enabling it in production.

### Negative-capability regression

Run the ordinary regression on Linux (also suitable for Linux CI):

```sh
cargo test --locked -p cat4igp-client network::privilege_test::backends_fail_closed_without_capabilities -- --exact --nocapture
```

It executes a child with effective, permitted and inheritable capabilities
cleared and privilege acquisition disabled, verifies those sets, then requires
FakeTCP's raw-socket `EPERM` to propagate and WireGuard setup to fail without
leaving an interface. It neither needs root nor changes the runner's capabilities.
A blocked `capset`/`prctl` is a test failure, not a silent skip. The WireGuard
negative check alone does not prove that kernel WireGuard is installed; pair it
with positive isolated-namespace coverage on a representative host:

```sh
sudo unshare --net -- cargo test --locked -p cat4igp-client tunnel::wireguard::tests::conflicting_interface_is_not_modified_or_destroyed -- --exact --ignored --nocapture
```

That positive test requires kernel WireGuard and namespace/network administration
privileges. It verifies setup, identity-conflict rejection and owned cleanup; it
does not certify a minimum-capability service profile or L2TP helper confinement.

## Checks

`bash packaging/build.sh --check` validates version inputs. Existing Rust tests
also parse both packaged TOML samples. Native recipes execute `--help` and
check staged permissions; OpenWrt checks its init script and installer suppression.
Disposable x86_64 VMs exercised installation, upgrade configuration preservation,
enabled-service reboot and crash recovery on Debian 13, Alpine 3.24, Arch Linux,
and OpenWrt 25.12.5. This does not verify other architectures, enrolled tunnel
recovery or OpenWrt sysupgrade; validate those on representative systems.