import type { FormEvent } from "react";
import {
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
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

export function Nodes({
  nodes,
  disabled,
  edit,
  manage,
  confirmed,
  nodeName,
}: {
  nodes: Inventory["nodes"];
  disabled: boolean;
  edit: (node: Inventory["nodes"][number]) => void;
  manage: (id: number) => void;
  confirmed: (payload: object, label: string, warning: string) => void;
  nodeName: (id: number) => string;
}) {
  return (
    <>
      <p className="muted">Last seen ≠ online.</p>
      <TableContainer>
        <Table>
          <caption className="sr-only">Nodes and rename actions</caption>
          <TableHead>
            <TableRow>
              <TableCell scope="col">Node</TableCell>
              <TableCell scope="col">Created (SQLite time)</TableCell>
              <TableCell scope="col">Last seen (SQLite time)</TableCell>
              <TableCell scope="col">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {nodes.map((n) => (
              <TableRow key={n.id}>
                <TableCell component="th" scope="row">
                  {n.name}
                  <small>#{n.id}</small>
                </TableCell>
                <TableCell>{n.created_at}</TableCell>
                <TableCell>{n.last_seen ?? "Not observed"}</TableCell>
                <TableCell>
                  <ActionMenu
                    label={`Actions for node #${n.id}`}
                    disabled={disabled}
                    items={[
                      {
                        label: "Manage memberships",
                        onClick: () => manage(n.id),
                      },
                      {
                        label: `Rename node #${n.id}`,
                        icon: "edit",
                        onClick: () => edit(n),
                      },
                      {
                        label: `Delete / revoke node #${n.id}…`,
                        icon: "delete",
                        onClick: () =>
                          confirmed(
                            { action: "delete_node", id: n.id },
                            `Permanently delete and revoke ${nodeName(n.id)}`,
                            "The enrolled identity cannot re-enroll. Its memberships, keys and tunnels are deleted. This cannot be undone.",
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
      {!nodes.length && <p className="empty">No nodes enrolled yet.</p>}
    </>
  );
}

export function RenameNode({
  editing,
  kind = "node",
  signedIn,
  disabled,
  close,
  rename,
}: {
  editing?: { id: number; name: string };
  kind?: "node" | "mesh";
  signedIn: boolean;
  disabled: boolean;
  close: () => void;
  rename: (event: FormEvent<HTMLFormElement>, id: number) => void;
}) {
  return (
    <Dialog
      open={!!editing && signedIn}
      onClose={close}
      aria-labelledby="rename-title"
    >
      <DialogTitle id="rename-title">
        Rename {kind} #{editing?.id}
      </DialogTitle>
      <DialogContent>
        {editing && (
          <form id="rename-form" onSubmit={(e) => rename(e, editing.id)}>
            <TextField
              fullWidth
              margin="dense"
              autoFocus
              label={`New name for ${kind} #${editing.id}`}
              name="name"
              defaultValue={editing.name}
              required
              disabled={disabled}
              slotProps={{ htmlInput: { maxLength: 256 } }}
            />
          </form>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={close}>Cancel</Button>
        <Button
          variant="contained"
          type="submit"
          form="rename-form"
          disabled={disabled}
        >
          Save
        </Button>
      </DialogActions>
    </Dialog>
  );
}
