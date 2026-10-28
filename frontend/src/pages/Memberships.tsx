import type { FormEvent } from "react";
import {
  Button,
  Table,
  TableContainer,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  TextField,
} from "@mui/material";
import { ActionMenu } from "../components/Controls";
import type { Inventory } from "../api/inventory";

export type MembershipScope = { kind: "node" | "mesh"; id: number };

export function Memberships({
  scope,
  data,
  disabled,
  confirmed,
  addMembership,
  meshName,
  nodeName,
  back,
}: {
  scope: MembershipScope;
  data: Inventory;
  disabled: boolean;
  confirmed: (payload: object, label: string, warning: string) => void;
  addMembership: (event: FormEvent<HTMLFormElement>) => void;
  meshName: (id: number | null) => string;
  nodeName: (id: number) => string;
  back: () => void;
}) {
  const node = scope.kind === "node";
  const exists = (node ? data.nodes : data.meshes).some(
    (item) => item.id === scope.id,
  );
  const memberships = data.memberships.filter(
    (m) => (node ? m.node_id : m.mesh_id) === scope.id,
  );
  const remaining = (node ? data.meshes : data.nodes).filter(
    (item) =>
      !memberships.some((m) => (node ? m.mesh_id : m.node_id) === item.id),
  );
  return (
    <>
      <Button variant="text" onClick={back}>
        Back to {node ? "Nodes" : "Meshes"}
      </Button>
      {!exists ? (
        <p role="status">This {scope.kind} is no longer available.</p>
      ) : (
        <>
          <TableContainer>
            <Table>
              <caption className="sr-only">
                {node ? "Joined meshes" : "Mesh members"}
              </caption>
              <TableHead>
                <TableRow>
                  <TableCell scope="col">{node ? "Mesh" : "Node"}</TableCell>
                  <TableCell scope="col">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {memberships.map((m) => (
                  <TableRow key={`${m.mesh_id}-${m.node_id}`}>
                    <TableCell component="th" scope="row">
                      {node ? meshName(m.mesh_id) : nodeName(m.node_id)}
                    </TableCell>
                    <TableCell>
                      <ActionMenu
                        label={`Actions for node #${m.node_id} in mesh #${m.mesh_id}`}
                        disabled={disabled}
                        items={[
                          {
                            label: `Remove node #${m.node_id} from mesh #${m.mesh_id}`,
                            icon: "delete",
                            onClick: () =>
                              confirmed(
                                {
                                  action: "remove_membership",
                                  mesh_id: m.mesh_id,
                                  node_id: m.node_id,
                                },
                                `Remove node #${m.node_id} from mesh #${m.mesh_id}`,
                                "Removes this membership and its mesh-owned intents.",
                              ),
                          },
                        ]}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          {!memberships.length && (
            <p className="empty">No memberships recorded.</p>
          )}
          <h2>Add membership</h2>
          <form className="form-grid" onSubmit={addMembership}>
            <fieldset disabled={disabled || !remaining.length}>
              <input
                type="hidden"
                name={node ? "node" : "mesh"}
                value={scope.id}
              />
              <TextField
                label={node ? "Mesh" : "Node"}
                name={node ? "mesh" : "node"}
                select
                required
                defaultValue=""
                disabled={disabled || !remaining.length}
                slotProps={{
                  select: { native: true },
                  inputLabel: { shrink: true },
                }}
              >
                <option value="" disabled>
                  Select {node ? "mesh" : "node"}
                </option>
                {remaining.map((item) => (
                  <option key={item.id} value={item.id}>
                    {node ? meshName(item.id) : nodeName(item.id)}
                  </option>
                ))}
              </TextField>
              <Button
                variant="contained"
                type="submit"
                disabled={disabled || !remaining.length}
              >
                Add membership
              </Button>
            </fieldset>
          </form>
          {!remaining.length && (
            <p className="muted">
              No more {node ? "meshes" : "nodes"} available.
            </p>
          )}
        </>
      )}
    </>
  );
}
