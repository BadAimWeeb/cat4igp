# L2TPv3 Ethernet

The client keeps separate active maps for WireGuard, L2TPv3 and L2TPv2,
with reconciliation next to each backend in `client/src/daemon/daemon_memory/`.
All three consume the same verified or cached topology snapshot. The common
actuator removes stale L2TP dependents before changing WireGuard, then creates
or updates WireGuard before creating its L2TP dependents. Failed cleanup stays
tracked for retry; cached topology permits best-effort offline restoration.


Linux clients support static L2TPv3 Ethernet over UDP in userspace, using a TAP
interface, either directly or over a controller-managed WireGuard tunnel. Both
endpoints must enable `[tunnel_protocols] l2tp = true` and have `/dev/net/tun`
and `CAP_NET_ADMIN`. No kernel L2TPv3 module is required.
Enable `allow_insecure_l2tp = true` at the top level on **both** clients only
when direct, unencrypted and unauthenticated traffic is acceptable. A cookie is
not cryptographic authentication. WireGuard mode requires no insecure opt-in.

Create a tunnel in the administrator Tunnels page: select the two nodes, mode,
UDP ports, nonzero receiving session IDs, eight-byte lowercase hexadecimal
receiving cookies, and MTU (576–65477). Each node sends the other node's session
ID and cookie. Use distinct, unpredictable cookies and protect controller access.
The profile uses UDP L2TPv3, an eight-byte cookie, no L2-specific sublayer, and
Ethernet frames without preamble or FCS.

Direct endpoints are public unicast IP addresses; UDP ports must be reachable,
with static port forwarding where NAT is present. Choose L2TP UDP ports outside
each client's WireGuard `port_range` and other services' ports. WireGuard mode
requires an existing WireGuard edge connecting the same nodes and two distinct
dedicated IP addresses; the clients assign the local address to the selected WireGuard
interface, install a host route to the remote address, and confine the UDP socket
to that interface. Ensure these addresses do not conflict with local addresses,
existing routes, or either WireGuard public endpoint. Jumbo frames require a suitable path;
IP fragmentation is enabled for the UDP transport. Both clients must be running
and receive the updated topology. Deleting a tunnel removes the TAP interface;
deleting a WireGuard edge also deletes dependent L2TP records.
After an unclean daemon exit, inspect the WireGuard interface for stale L2TP
host addresses and routes; their ownership is not persisted across restarts.

## L2TPv2 / PPP

Linux clients can establish L2TPv2/PPP directly or over a controller-managed
WireGuard tunnel using the Tunnels page. Both clients must enable
`tunnel_protocols.l2tp` and install `xl2tpd` and `pppd`. Direct mode also
requires `allow_insecure_l2tp` on both clients. The client needs root,
`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `/etc/ppp`, mount namespaces and `/dev/ppp`.
Each endpoint uses a dedicated UDP port outside the WireGuard port range and
other services, an IPv4 transport address, and a distinct PPP IPv4 address.
Peer 1 initiates; peer 2 listens. Direct mode permits PPP MTU 1280–1500;
WireGuard mode permits 1280–65000, using IP fragmentation over WireGuard.

To force the xl2tpd userspace data path, set `l2tp_v2_userspace = true` at the
top level on each client. The default `false` retains xl2tpd's kernel/auto
selection. Userspace mode requires an xl2tpd build supporting `force userspace`
and limits PPP MTU to 4000 bytes because of its packet buffer; it still needs
`pppd`, `/dev/ppp`, and the privileges above. Peers may select different modes.
Userspace does not add encryption.


In WireGuard mode select an existing edge connecting the same peers and supply
two dedicated, unused IPv4 underlay addresses. Each client installs its local
address and a source-specific policy route through that edge with an unreachable
fallback. Conflicting policy rules, addresses or routing tables prevent setup.
After an unclean exit, stale policy rules and tables may require administrative
cleanup; inspect them before restarting the tunnel. Privileged external routing
changes can bypass confinement. Permit WireGuard UDP traffic in both directions.
WireGuard links are brought up even when their existing MTU already matches the
desired MTU; matching MTU alone does not imply an active interface.

Provide a strong unique CHAP secret; the UI accepts 32–128 lowercase hex
digits. CHAP authenticates PPP peers but does not encrypt or protect traffic.
Use direct L2TPv2 only on trusted networks. The controller stores the secret
in plaintext in its database and mutation receipts and replicates it to other
controllers; protect their storage and backups. The secret is omitted from
administrator inventory. Each client creates private temporary PPP files and
isolates them with a mount namespace; they are removed on normal shutdown.
