import {
  Chip,
  Tab,
  Tabs,
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
      <Tabs value="wireguard" aria-label="Tunnel types">
        <Tab
          value="wireguard"
          label="WireGuard"
          id="wireguard-tab"
          aria-controls="wireguard-panel"
        />
      </Tabs>
      <div
        role="tabpanel"
        id="wireguard-panel"
        aria-labelledby="wireguard-tab"
        tabIndex={0}
      >
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
