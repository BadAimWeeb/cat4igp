## CAT4IGP - Controllable Array of Tunnels for Interior Gateway Protocol

This is inspired by [RAIT](https://gitlab.com/NickCao/RAIT), which is a piece of software that if given a registry, will create a bunch of "inexpensive" WireGuard tunnels. You can abuse those as a bunch of point-to-point link and run IGP like Babel to figure out best routes.

While it is great, it has some drawbacks:

- It does not have a daemon and therefore cannot do tricks like UDP hole-punching.
- It also requires a cron job to automatically update new link, or you have to manually go to each node and refresh it.
- You cannot easily control which links are created, only a full-mesh networks can be formed. The amount of tunnels will be ridiculously high if you have a large amount of nodes, and you may not be able to handle it.
- The binary size of it is large due to usage of Golang (although I don't know if I can optimize Rust to be more efficient...)
- You can only use WireGuard. I'd like to add more types of tunnel, and the capability to do tunnel over tunnel (e.g. L2TP over WireGuard, with IP fragmentation inside WireGuard to get a very high MTU capable of transmitting jumbo frames)

This will attempt to address those drawbacks.

**WORK-IN-PROGRESS**

**This is not available in Windows.**

### Install the client

Install `cat4igp-client` from the signed feed for your distribution. Verify the
repository signing key with your operator before trusting it; keep signature
checks enabled.

| Distribution | Feed | Install |
| --- | --- | --- |
| Debian 13 | `https://c4i-repo.badaimweeb.me/debian` (`trixie main`) | `apt-get update && apt-get install cat4igp-client` |
| Alpine 3.24 | `https://c4i-repo.badaimweeb.me/alpine/v3.24` | `apk update && apk add cat4igp-client` |
| Arch Linux | `https://c4i-repo.badaimweeb.me/arch/$arch` (`[cat4igp]`, `SigLevel = Required`) | `pacman -Syu cat4igp/cat4igp-client` |
| OpenWrt 25.12.5 | `https://c4i-repo.badaimweeb.me/openwrt/25.12.5/<arch>/packages.adb` (`x86_64` or `aarch64_generic`, matching firmware) | `apk update && apk add cat4igp-client` |

Portable x86-64 and ARM64 Linux binaries are available in the [signed download
directory](https://c4i-repo.badaimweeb.me/portable/v0.1.0/SHA256SUMS) and on
[GitHub Releases](https://github.com/BadAimWeeb/cat4igp/releases).

Packages do not start the service automatically. Review `/etc/cat4igp/client.toml`,
then start `cat4igp-client` with `systemctl`, `rc-service`, or
`/etc/init.d/cat4igp-client start` on OpenWrt. With the service running, enroll
using `cat4igp-client register-bundle --bundle /secure/enrollment.json` and a
trusted bundle from your operator.

### Controller

The server container image is published to [GitHub Packages](https://github.com/BadAimWeeb/cat4igp/pkgs/container/cat4igp-server).
