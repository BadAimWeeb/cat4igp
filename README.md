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

Client packages for Alpine, Debian, Arch Linux and OpenWrt, plus portable static binaries, are
built by GitHub Actions. The server is published as a multiarchitecture Alpine image in GitHub Packages.

For a standalone server, see the [deployment guide](llm_notes/server/deployment.md) for Docker setup, administrator bootstrap, HTTPS, backups, and verification.

### WireGuard mesh FakeTCP

Administrators can enable FakeTCP when creating an Auto WireGuard mesh or toggle it later in the mesh actions. It applies to current and future mesh-owned WireGuard tunnels; changing it causes clients to converge on the new configuration. A tunnel shared by multiple meshes uses FakeTCP if any owning mesh enables it, or if its explicit per-tunnel flag is set. Other tunnel protocols are unaffected.

FakeTCP is disabled by default for existing meshes and requests that omit the setting. It requires Linux clients with raw-socket privileges and nftables; enable it only when both ends support it. FakeTCP disguises packet framing as TCP, not as a reliable TCP connection, and does not replace WireGuard encryption.

The administrator `create_mesh` action accepts optional boolean `faketcp` (default `false`); enabling it requires `auto_wireguard: true`. Use `{"action":"set_mesh_faketcp","id":1,"faketcp":true}` to change an existing mesh. Inventory mesh entries report the boolean as `faketcp`. Disabling a mesh policy does not override another owning mesh or an explicit tunnel setting.
