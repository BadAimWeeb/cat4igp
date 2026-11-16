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
Non-release server images use the full source commit SHA as their tag; release images use the matching `vX.Y.Z` tag. Prefer the image digest when an immutable deployment reference is required.

For a standalone server, see the [deployment guide](llm_notes/server/deployment.md) for Docker setup, administrator bootstrap, HTTPS, backups, and verification.

Enroll clients using a trusted, sensitive registration bundle, not client TOML or JSON settings. Start the daemon and run `cat4igp-client register-bundle --bundle /secure/enrollment.json`; see the [client guide](llm_notes/client/configuration.md#trusted-enrollment-bundle) for bundle contents, secret handling, retries, and protected daemon state. Preserve the existing client state directory when upgrading.

### WireGuard mesh FakeTCP

Administrators can enable FakeTCP when creating an Auto WireGuard mesh or toggle it later in the mesh actions. It applies to current and future mesh-owned WireGuard tunnels; changing it causes clients to converge on the new configuration. A tunnel shared by multiple meshes uses FakeTCP if any owning mesh enables it, or if its explicit per-tunnel flag is set. Other tunnel protocols are unaffected.

FakeTCP is disabled by default for existing meshes and requests that omit the setting. It requires Linux clients with raw-socket privileges and nftables; enable it only when both ends support it. FakeTCP disguises packet framing as TCP, not as a reliable TCP connection, and does not replace WireGuard encryption.

The administrator `create_mesh` action accepts optional boolean `faketcp` (default `false`); enabling it requires `auto_wireguard: true`. Use `{"action":"set_mesh_faketcp","id":1,"faketcp":true}` to change an existing mesh. Inventory mesh entries report the boolean as `faketcp`. Disabling a mesh policy does not override another owning mesh or an explicit tunnel setting.

### WireGuard endpoint refresh modes

Each WireGuard tunnel has a controller-selected refresh mode. `current` preserves the original behavior: active kernel WireGuard sockets cannot be queried for a STUN mapping, so refresh requires a configured public hostname and forwarding, or an FEC transport whose socket can be queried. `proxy` keeps a userspace UDP bridge in front of kernel WireGuard so STUN can use the live public socket. The bridge forwards only packets from the exact controller-selected peer address and port; unlike direct WireGuard it cannot authenticate or follow endpoint roaming by itself. A trusted controller update is required when the peer address changes. FEC already owns its public socket and does not need the UDP bridge. FakeTCP requires a public hostname and TCP port forwarding.

`dual_link` creates a second WireGuard interface with a new key and UDP port. Both peers exchange offers and wait for an authenticated handshake before switching; the old interface remains until both have switched. A reserved interface-name bit distinguishes the two slots, giving them distinct link-local addresses for IGP convergence. Direct UDP mapping discovery closes and rebinds the candidate port, so the discovered NAT mapping is best effort; an unsuccessful handshake must not cause a cutover. The port range must have room for both links. Dependent L2TP sessions are recreated on the new underlay during cutover and may experience a brief interruption.

The client stores active and pending generation keys and ports in its protected daemon data directory. Do not delete or reset this state during a transition or after a key rotation: the controller and peer may still depend on those keys, and a reset can interrupt connectivity until the tunnel is reprovisioned. Back up the client state securely along with the controller state.

Dual-link retirement refuses to remove an interface with externally managed addresses or static routes; migrate those settings yourself before retrying. Recognized dynamic routing-protocol routes can reconverge over the new interface; routes using an unrecognized protocol are treated conservatively as external. Changing between `current` and `proxy` rebinds the public port and can briefly interrupt traffic. `proxy` cannot be combined with FakeTCP: select `current` or `dual_link` instead.
