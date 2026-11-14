import { useState, type FormEvent } from "react";
import {
  Alert,
  Button,
  FormControlLabel,
  Checkbox,
  MenuItem,
  TextField,
  Chip,
  Table,
  TableContainer,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
} from "@mui/material";
import type { Inventory } from "../api/inventory";

export function Tunnels({
  tunnels,
  disabled,
  confirmed,
  meshName,
  nodeName,
}: {
  tunnels: Inventory["tunnels"];
  disabled: boolean;
  confirmed: (payload: object, label: string, warning: string) => void;
  meshName: (id: number | null) => string;
  nodeName: (id: number) => string;
}) {
  return (
    <>
      <h3>WireGuard</h3>
      <div>
        <TableContainer>
          <Table>
            <caption className="sr-only">
              Tunnels and intent removal actions
            </caption>
            <TableHead>
              <TableRow>
                <TableCell scope="col">Tunnel</TableCell>
                <TableCell scope="col">Peers</TableCell>
                <TableCell scope="col">Endpoints</TableCell>
                <TableCell scope="col">MTU</TableCell>
                <TableCell scope="col">Refresh mode</TableCell>
                <TableCell scope="col">Intents / actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {tunnels.map((t) => (
                <TableRow key={t.id}>
                  <TableCell component="th" scope="row">
                    #{t.id}
                  </TableCell>
                  <TableCell>
                    {nodeName(t.node_id_peer1)}
                    <br />
                    {nodeName(t.node_id_peer2)}
                  </TableCell>
                  <TableCell>
                    <div>{t.ipv6 ? "IPv6" : "IPv4"}</div>
                    <div>
                      {nodeName(t.node_id_peer1)}:{" "}
                      {t.endpoint_peer1 || "Not available"}
                    </div>
                    <div>
                      {nodeName(t.node_id_peer2)}:{" "}
                      {t.endpoint_peer2 || "Not available"}
                    </div>
                  </TableCell>
                  <TableCell>{t.mtu}</TableCell>
                  <TableCell>
                    <TextField select size="small" label={`Refresh mode for tunnel #${t.id}`} value={t.refresh_mode || "current"} disabled={disabled}
                      onChange={e => confirmed({ action: "set_tunnel_refresh_mode", tunnel_id: t.id, mode: e.target.value }, `Change refresh mode for tunnel #${t.id}`, "Both peers must support this mode. Mode cannot change during a dual-link transition. Switching between current and proxy rebinds the public UDP port and may briefly interrupt traffic. Proxy pins the peer IP and port and disables authenticated WireGuard endpoint roaming; it cannot be combined with FakeTCP. FEC uses its own socket.")}>
                      <MenuItem value="current">Current</MenuItem>
                      <MenuItem value="proxy">Userspace proxy</MenuItem>
                      <MenuItem value="dual_link">New tunnel link</MenuItem>
                    </TextField>
                  </TableCell>
                  <TableCell>
                    {t.intents.length
                      ? t.intents.map((intent, i) => (
                          <div
                            className="intent"
                            key={`${intent.kind}-${intent.mesh_id}-${i}`}
                          >
                            {intent.kind === "mesh" ? (
                              <Chip
                                label={`Mesh: ${meshName(intent.mesh_id)}`}
                                size="small"
                              />
                            ) : (
                              <Chip
                                label={intent.kind}
                                size="small"
                                aria-label={`Remove ${intent.kind} intent from tunnel #${t.id}`}
                                disabled={disabled}
                                onDelete={() =>
                                  confirmed(
                                    {
                                      action: "remove_tunnel_intent",
                                      tunnel_id: t.id,
                                      kind: intent.kind,
                                    },
                                    `Remove ${intent.kind} intent from tunnel #${t.id}`,
                                    "Removes the selected intent. If it is the last intent, deletes the tunnel.",
                                  )
                                }
                              />
                            )}
                          </div>
                        ))
                      : "No tracked intents (legacy ownership may be retained by the controller)"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        {!tunnels.length && <p className="empty">No tunnels recorded.</p>}
      </div>
    </>
  );
}

export function L2tpTunnels({ data, disabled, confirmed, nodeName }: {
  data: Inventory; disabled: boolean;
  confirmed: (payload: object, label: string, warning: string) => void;
  nodeName: (id: number) => string;
}) {
  const [mode, setMode] = useState<"pure" | "wireguard">("pure");
  const [error, setError] = useState("");
  function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const number = (name: string, max: number, min = 1) => {
      const value = Number(form.get(name));
      if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`Invalid ${name.replaceAll("_", " ")}.`);
      return value;
    };
    try {
      const peer1 = number("node_id_peer1", 2147483647), peer2 = number("node_id_peer2", 2147483647);
      if (peer1 === peer2 || !data.nodes.some(n => n.id === peer1) || !data.nodes.some(n => n.id === peer2)) throw new Error("Select two different existing nodes.");
      const endpoint1 = String(form.get("endpoint_peer1") || "").trim(), endpoint2 = String(form.get("endpoint_peer2") || "").trim();
      if (!endpoint1 || !endpoint2 || endpoint1.length > 45 || endpoint2.length > 45) throw new Error("Enter both IP endpoints (up to 45 characters). ");
      const cookie1 = String(form.get("cookie_peer1") || ""), cookie2 = String(form.get("cookie_peer2") || "");
      if (!/^[0-9a-f]{16}$/.test(cookie1) || !/^[0-9a-f]{16}$/.test(cookie2)) throw new Error("Each cookie must contain exactly 16 lowercase hexadecimal characters.");
      const wireguard = mode === "wireguard" ? number("wireguard_tunnel_id", 2147483647) : null;
      if (wireguard !== null && !data.tunnels.some(t => t.id === wireguard && ((t.node_id_peer1 === peer1 && t.node_id_peer2 === peer2) || (t.node_id_peer1 === peer2 && t.node_id_peer2 === peer1)))) throw new Error("Select a WireGuard tunnel connecting the selected nodes.");
      if (mode === "pure" && form.get("accept_unencrypted") !== "on") throw new Error("Acknowledge the risks of direct L2TP.");
      const payload = { action: "create_l2tp_tunnel", node_id_peer1: peer1, node_id_peer2: peer2, endpoint_peer1: endpoint1, endpoint_peer2: endpoint2, udp_port_peer1: number("udp_port_peer1", 65535), udp_port_peer2: number("udp_port_peer2", 65535), session_id_peer1: number("session_id_peer1", 4294967295), session_id_peer2: number("session_id_peer2", 4294967295), cookie_peer1: cookie1, cookie_peer2: cookie2, security_mode: mode, wireguard_tunnel_id: wireguard, mtu: number("mtu", 65477, 576) };
      setError("");
      confirmed(payload, "Create L2TP tunnel", mode === "pure" ? "Direct L2TP has no encryption or cryptographic authentication. Create this tunnel?" : "Create L2TP over the selected WireGuard tunnel?");
    } catch (e) { setError(e instanceof Error ? e.message : "Invalid tunnel settings."); }
  }
  return <section aria-labelledby="l2tp-title">
    <h3 id="l2tp-title">L2TPv3 Ethernet</h3>
    <Alert severity="warning">Direct L2TP is not encrypted or cryptographically authenticated. Use WireGuard for confidential or untrusted networks.</Alert>
    <TableContainer><Table><TableHead><TableRow><TableCell>ID</TableCell><TableCell>Peers and endpoints</TableCell><TableCell>Security</TableCell><TableCell>MTU</TableCell><TableCell>Actions</TableCell></TableRow></TableHead><TableBody>
      {data.l2tp_tunnels.map(t => <TableRow key={t.id}><TableCell>#{t.id}</TableCell><TableCell>{nodeName(t.node_id_peer1)}: {t.endpoint_peer1}:{t.udp_port_peer1}<br />{nodeName(t.node_id_peer2)}: {t.endpoint_peer2}:{t.udp_port_peer2}</TableCell><TableCell>{t.security_mode === "pure" ? "Direct (unencrypted)" : `WireGuard #${t.wireguard_tunnel_id}`}</TableCell><TableCell>{t.mtu}</TableCell><TableCell><Button disabled={disabled} onClick={() => confirmed({ action: "delete_l2tp_tunnel", id: t.id }, `Delete L2TP tunnel #${t.id}`, "This removes the L2TP tunnel from both peers.")}>Delete…</Button></TableCell></TableRow>)}
    </TableBody></Table></TableContainer>
    {!data.l2tp_tunnels.length && <p className="empty">No L2TP tunnels recorded.</p>}
    <h4>Create L2TP tunnel</h4>
    <form onSubmit={create} className="form-grid" style={{ display: "flex", flexDirection: "column", gap: "1rem", width: "100%" }}>
      {error && <Alert severity="error">{error}</Alert>}
      <TextField select label="Security mode" value={mode} onChange={e => setMode(e.target.value as "pure" | "wireguard")} disabled={disabled}><MenuItem value="pure">Direct L2TP (unencrypted)</MenuItem><MenuItem value="wireguard">L2TP over WireGuard</MenuItem></TextField>
      {[1, 2].map(i => <TextField key={i} select required name={`node_id_peer${i}`} label={`Peer ${i}`} defaultValue="" disabled={disabled}>{data.nodes.map(n => <MenuItem key={n.id} value={n.id}>{nodeName(n.id)}</MenuItem>)}</TextField>)}
      {mode === "wireguard" && <TextField select required name="wireguard_tunnel_id" label="Underlying WireGuard tunnel" defaultValue="" disabled={disabled}>{data.tunnels.map(t => <MenuItem key={t.id} value={t.id}>#{t.id}: {nodeName(t.node_id_peer1)} / {nodeName(t.node_id_peer2)}</MenuItem>)}</TextField>}
      {[1, 2].map(i => <div key={i} style={{ display: "flex", flexDirection: "column", gap: "1rem", width: "100%" }}><h5>Peer {i} parameters</h5><TextField required name={`endpoint_peer${i}`} label={`Peer ${i} IP address`} disabled={disabled} /><TextField required type="number" name={`udp_port_peer${i}`} label={`Peer ${i} UDP port`} defaultValue="1701" slotProps={{ htmlInput: { min: 1, max: 65535, step: 1 } }} disabled={disabled} /><TextField required type="number" name={`session_id_peer${i}`} label={`Peer ${i} session ID`} slotProps={{ htmlInput: { min: 1, max: 4294967295, step: 1 } }} disabled={disabled} /><TextField required name={`cookie_peer${i}`} label={`Peer ${i} cookie (16 lowercase hex digits)`} slotProps={{ htmlInput: { pattern: "[0-9a-f]{16}", maxLength: 16 } }} disabled={disabled} /></div>)}
      <TextField required type="number" name="mtu" label="MTU" defaultValue="1500" slotProps={{ htmlInput: { min: 576, max: 65477, step: 1 } }} disabled={disabled} />
      {mode === "pure" && <FormControlLabel control={<Checkbox required name="accept_unencrypted" disabled={disabled} />} label="I understand direct L2TP is unencrypted and unauthenticated" />}
      <Button type="submit" variant="contained" disabled={disabled || data.nodes.length < 2}>Create L2TP tunnel…</Button>
    </form>
  </section>;
}

export function L2tpV2Tunnels({ data, disabled, confirmed, nodeName }: {
  data: Inventory; disabled: boolean;
  confirmed: (payload: object, label: string, warning: string) => void;
  nodeName: (id: number) => string;
}) {
  const [mode, setMode] = useState<"pure" | "wireguard">("pure");
  const [error, setError] = useState("");
  function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const f = new FormData(event.currentTarget);
    const number = (name: string) => Number(f.get(name));
    try {
      const peer1 = number("node_id_peer1"), peer2 = number("node_id_peer2");
      if (peer1 === peer2 || !data.nodes.some(n => n.id === peer1) || !data.nodes.some(n => n.id === peer2)) throw new Error("Select two different existing nodes.");
      const secret = String(f.get("secret") || "");
      if (!/^[a-f0-9]{32,128}$/.test(secret)) throw new Error("CHAP secret must contain 32–128 lowercase hexadecimal characters.");
      const wireguard = mode === "wireguard" ? number("wireguard_tunnel_id") : null;
      if (wireguard !== null && !data.tunnels.some(t => t.id === wireguard && ((t.node_id_peer1 === peer1 && t.node_id_peer2 === peer2) || (t.node_id_peer1 === peer2 && t.node_id_peer2 === peer1)))) throw new Error("Select a WireGuard tunnel connecting the selected nodes.");
      const mtu = number("mtu");
      if (!Number.isSafeInteger(mtu) || mtu < 1280 || mtu > (wireguard === null ? 1500 : 65000)) throw new Error("Invalid PPP MTU for the selected underlay.");
      if (wireguard === null && f.get("accept_unencrypted") !== "on") throw new Error("Acknowledge the risks of direct L2TPv2.");
      const payload = { action: "create_l2tp_v2_tunnel", node_id_peer1: peer1, node_id_peer2: peer2,
        endpoint_peer1: String(f.get("endpoint_peer1") || "").trim(), endpoint_peer2: String(f.get("endpoint_peer2") || "").trim(),
        udp_port_peer1: number("udp_port_peer1"), udp_port_peer2: number("udp_port_peer2"),
        address_peer1: String(f.get("address_peer1") || "").trim(), address_peer2: String(f.get("address_peer2") || "").trim(), secret, mtu, wireguard_tunnel_id: wireguard };
      setError("");
      confirmed(payload, "Create L2TPv2/PPP tunnel", wireguard === null ? "L2TPv2 and PPP CHAP do not encrypt traffic. Create this tunnel?" : "Create L2TPv2/PPP over the selected WireGuard tunnel?");
    } catch (e) { setError(e instanceof Error ? e.message : "Invalid tunnel settings."); }
  }
  return <section aria-labelledby="l2tp-v2-title">
    <h3 id="l2tp-v2-title">L2TPv2 / PPP</h3>
    <Alert severity="warning">Direct L2TPv2 is unencrypted. CHAP authenticates peers but does not protect traffic. Use only on trusted networks.</Alert>
    <TableContainer><Table><TableHead><TableRow><TableCell>ID</TableCell><TableCell>Peers and endpoints</TableCell><TableCell>PPP addresses</TableCell><TableCell>Security</TableCell><TableCell>MTU</TableCell><TableCell>Actions</TableCell></TableRow></TableHead><TableBody>
      {data.l2tp_v2_tunnels.map(t => <TableRow key={t.id}><TableCell>#{t.id}</TableCell><TableCell>{nodeName(t.node_id_peer1)}: {t.endpoint_peer1}:{t.udp_port_peer1}<br />{nodeName(t.node_id_peer2)}: {t.endpoint_peer2}:{t.udp_port_peer2}</TableCell><TableCell>{t.address_peer1} / {t.address_peer2}</TableCell><TableCell>{t.wireguard_tunnel_id == null ? "Direct (unencrypted)" : `WireGuard #${t.wireguard_tunnel_id}`}</TableCell><TableCell>{t.mtu}</TableCell><TableCell><Button disabled={disabled} onClick={() => confirmed({ action: "delete_l2tp_v2_tunnel", id: t.id }, `Delete L2TPv2 tunnel #${t.id}`, "This removes the PPP tunnel from both peers.")}>Delete…</Button></TableCell></TableRow>)}
    </TableBody></Table></TableContainer>
    {!data.l2tp_v2_tunnels.length && <p className="empty">No L2TPv2 tunnels recorded.</p>}
    <h4>Create L2TPv2 tunnel</h4>
    <form onSubmit={create} className="form-grid" style={{ display: "flex", flexDirection: "column", gap: "1rem", width: "100%" }}>
      {error && <Alert severity="error">{error}</Alert>}
      <TextField select label="L2TPv2 security mode" value={mode} onChange={e => setMode(e.target.value as "pure" | "wireguard")} disabled={disabled}><MenuItem value="pure">Direct L2TPv2 (unencrypted)</MenuItem><MenuItem value="wireguard">L2TPv2 over WireGuard</MenuItem></TextField>
      {mode === "wireguard" && <><TextField select required name="wireguard_tunnel_id" label="Underlying WireGuard tunnel" defaultValue="" disabled={disabled}>{data.tunnels.map(t => <MenuItem key={t.id} value={t.id}>#{t.id}: {nodeName(t.node_id_peer1)} / {nodeName(t.node_id_peer2)}</MenuItem>)}</TextField><Alert severity="info">Use dedicated IPv4 host addresses on the selected WireGuard tunnel as the outer endpoints. Large PPP MTUs require fragmentation over WireGuard.</Alert></>}
      {[1, 2].map(i => <div key={i} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}><TextField select required name={`node_id_peer${i}`} label={`Peer ${i}`} defaultValue="" disabled={disabled}>{data.nodes.map(n => <MenuItem key={n.id} value={n.id}>{nodeName(n.id)}</MenuItem>)}</TextField><TextField required name={`endpoint_peer${i}`} label={`Peer ${i} outer IPv4 address`} disabled={disabled} /><TextField required type="number" name={`udp_port_peer${i}`} label={`Peer ${i} UDP port`} defaultValue="1701" slotProps={{ htmlInput: { min: 1, max: 65535, step: 1 } }} disabled={disabled} /><TextField required name={`address_peer${i}`} label={`Peer ${i} PPP IPv4 address`} disabled={disabled} /></div>)}
      <TextField required type="password" name="secret" label="CHAP secret (32–128 lowercase hex digits)" slotProps={{ htmlInput: { pattern: "[0-9a-f]{32,128}", minLength: 32, maxLength: 128, autoComplete: "new-password" } }} disabled={disabled} />
      <TextField required type="number" name="mtu" label="PPP MTU" defaultValue="1400" slotProps={{ htmlInput: { min: 1280, max: mode === "wireguard" ? 65000 : 1500, step: 1 } }} disabled={disabled} />
      {mode === "pure" && <FormControlLabel control={<Checkbox required name="accept_unencrypted" disabled={disabled} />} label="I understand this tunnel is unencrypted" />}
      <Button type="submit" variant="contained" disabled={disabled || data.nodes.length < 2}>Create L2TPv2 tunnel…</Button>
    </form>
  </section>;
}
