# Client packages

The client package includes the CLI, a root-run service and
`/etc/cat4igp/client.toml`. Services are installed **without enabling or
starting them**. Linux kernel WireGuard support is required; OpenWrt declares
`kmod-wireguard`. No server or firewall configuration is installed.

| Build environment | Architectures | Service |
| --- | --- | --- |
| Alpine 3.24 | x86_64, aarch64 | OpenRC |
| Debian 13 (trixie) | amd64, arm64 | systemd |
| Arch Linux | x86_64 | systemd |
| OpenWrt 25.12.5 | x86/64, armsr/armv8 | procd |
| Static musl binary | x86_64, aarch64 | Administrator-managed |

Build images, actions, OpenWrt SDK checksums and the packages feed are pinned
in `build.sh` and the workflow. Package repositories
inside the images remain live: these are ABI-appropriate builds, not
bit-for-bit reproducible builds.

## Builds and downloads

Default-branch commits and manual runs produce SNAPSHOT packages retained as
Actions artifacts for 14 days. Versions include the commit time and hash
(Alpine and OpenWrt encode the hash as a number) and sort before the corresponding final
release. Release tags must be `vX.Y.Z` matching `client/Cargo.toml`; all nine
builds must succeed before GitHub Releases receives packages and SHA256SUMS.
Manual runs never publish releases. Release filenames identify the distro
and architecture to avoid collisions.

For local builds, invoke `bash packaging/build.sh DISTRO ARCH` on a matching
architecture Linux machine with Docker, using `alpine`, `debian`, `arch` or
`openwrt` or `static` and `x86_64` or `aarch64` (Arch supports x86_64 only).
Both OpenWrt builds require an x86_64 host.
Outputs go to `dist/DISTRO-ARCH/`. The workflow builds only `cat4igp-client`
with locked dependencies. Rust and native crypto compilation need substantial
memory, disk space and network access; OpenWrt also builds its Rust host toolchain.

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

After downloading, verify the release checksum, set executable permission
(`chmod +x`), and install the binary wherever appropriate. These artifacts do
not install configuration, services or licenses separately; the project is
MIT-licensed (see the repository `LICENSE`). Linux kernel support for the Rust
target remains necessary (normally Linux 3.2+ on x86_64 and 4.1+ on aarch64),
and actual tunnel operation requires kernel WireGuard, root/network
privileges, DNS/network access and suitable configuration. Static linking
does not make this a Windows/macOS binary or remove kernel requirements.

### Distribution packages

Install the matching package with the native package manager. As root, edit
`/etc/cat4igp/client.toml`, including private-control-network settings if needed.
The port range upper bound is exclusive. Keep configuration mode `0600`.

Start the service explicitly with `systemctl start cat4igp-client`,
`rc-service cat4igp-client start`, or `/etc/init.d/cat4igp-client start`.
Then enroll with `cat4igp-client --config /etc/cat4igp/client.toml register
--server MULTIADDR --invite CODE`. This connects to the running daemon; it does
not automatically enable boot startup. Check with `cat4igp-client --config
/etc/cat4igp/client.toml status`.

Once configured, enable boot startup using `systemctl enable cat4igp-client`,
`rc-update add cat4igp-client default`, or `/etc/init.d/cat4igp-client enable`.
Private identity and daemon authentication state live in
`/var/lib/cat4igp-client`, or `/etc/cat4igp/state` on OpenWrt. State directories
are `0700`; generated credentials are not package payloads. OpenWrt registers
configuration and state for sysupgrade retention when keeping configuration.
Backups therefore contain secrets and must be protected. Do not purge state
unless intentionally discarding the enrolled identity.

## Checks

`bash packaging/build.sh --check` validates version inputs. Existing Rust tests
also parse both packaged TOML samples. Native recipes execute `--help` and
check staged permissions; OpenWrt checks its init script and installer suppression.
Real service activation, upgrade preservation, sysupgrade and WireGuard
enrollment/reboot still require disposable systems or supported devices.