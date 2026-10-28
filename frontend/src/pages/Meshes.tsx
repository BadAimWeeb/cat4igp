import { useState, type FormEvent } from "react";
import {
  Button,
  Switch,
  FormControlLabel,
  Paper,
  Table,
  TableContainer,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  TextField,
  Box,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
} from "@mui/material";
import { ActionMenu } from "../components/Controls";
import { NumberField } from "../components/NumberField";
import { integer, type Inventory } from "../api/inventory";

export function Meshes({
  meshes,
  disabled,
  confirmed,
  meshName,
  manage,
  edit,
  setMtu,
}: {
  meshes: Inventory["meshes"];
  disabled: boolean;
  confirmed: (payload: object, label: string, warning: string) => void;
  meshName: (id: number | null) => string;
  manage: (id: number) => void;
  edit: (mesh: Inventory["meshes"][number]) => void;
  setMtu: (id: number, mtu: number) => void;
}) {
  const [editingMtu, setEditingMtu] = useState<Inventory["meshes"][number]>();
  const [mtuError, setMtuError] = useState("");
  return (
    <>
      <TableContainer>
        <Table>
          <caption className="sr-only">Meshes</caption>
          <TableHead>
            <TableRow>
              <TableCell scope="col">Mesh</TableCell>
              <TableCell scope="col">Auto WireGuard</TableCell>
              <TableCell scope="col">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {meshes.map((m) => (
              <TableRow key={m.id}>
                <TableCell component="th" scope="row">
                  {m.name}
                  <small>#{m.id}</small>
                </TableCell>
                <TableCell>
                  {m.auto_wireguard
                    ? `MTU ${m.mtu}${m.fec ? " · FEC enabled" : ""}`
                    : "Disabled"}
                </TableCell>
                <TableCell>
                  <ActionMenu
                    label={`Actions for mesh #${m.id}`}
                    disabled={disabled}
                    items={[
                      {
                        label: "Manage members",
                        onClick: () => manage(m.id),
                      },
                      {
                        label: `Rename mesh #${m.id}`,
                        icon: "edit",
                        onClick: () => edit(m),
                      },
                      ...(m.auto_wireguard ? [{
                        label: "Update WireGuard MTU…",
                        onClick: () => { setMtuError(""); setEditingMtu(m); },
                      }, {
                        label: `${m.fec ? "Disable" : "Enable"} FEC for all WireGuard tunnels…`,
                        onClick: () => confirmed(
                          { action: "set_mesh_fec", id: m.id, fec: !m.fec },
                          `${m.fec ? "Disable" : "Enable"} WireGuard FEC for ${meshName(m.id)}`,
                          "Applies only to current and future IPv4 and IPv6 WireGuard tunnels in this mesh. Other protocols use their own FEC settings. Existing WireGuard tunnels restart as clients converge. Shared tunnels keep FEC if another mesh or their explicit setting requires it.",
                        ),
                      }] : []),
                      {
                        label: `Delete ${meshName(m.id)}…`,
                        icon: "delete",
                        onClick: () =>
                          confirmed(
                            { action: "delete_mesh", id: m.id },
                            `Permanently delete ${meshName(m.id)}`,
                            "Deletes the mesh, memberships and mesh-owned intents; invalidates mesh-scoped invites. This cannot be undone.",
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
      {!meshes.length && <p className="empty">No meshes created yet.</p>}
      <Dialog
        open={!!editingMtu}
        onClose={() => setEditingMtu(undefined)}
        aria-labelledby="mesh-mtu-title"
        aria-describedby="mesh-mtu-description"
      >
        <DialogTitle id="mesh-mtu-title">WireGuard MTU · {editingMtu?.name}</DialogTitle>
        <DialogContent>
          <DialogContentText id="mesh-mtu-description" sx={{ mb: 2 }}>
            Updates current and future IPv4 and IPv6 WireGuard tunnels in this mesh as clients converge.
            Shared tunnels also change, even if another mesh or a manual intent uses them.
            The latest explicit mesh MTU update wins.
          </DialogContentText>
          {mtuError && <Alert severity="error">{mtuError}</Alert>}
          {editingMtu && (
            <form id="mesh-mtu-form" onSubmit={(event) => {
              event.preventDefault();
              if (disabled) return;
              const mtu = Number(new FormData(event.currentTarget).get("mtu"));
              if (!integer(mtu) || mtu < 1280 || mtu > 9000) {
                setMtuError("MTU must be an integer between 1280 and 9000.");
                return;
              }
              setMtu(editingMtu.id, mtu);
              setEditingMtu(undefined);
            }}>
              <NumberField
                key={editingMtu.id}
                label="WireGuard MTU"
                name="mtu"
                min={1280}
                max={9000}
                defaultValue={editingMtu.mtu}
                disabled={disabled}
                required
              />
            </form>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditingMtu(undefined)}>Cancel</Button>
          <Button variant="contained" type="submit" form="mesh-mtu-form" disabled={disabled}>Save MTU</Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

export function CreateMesh({
  disabled,
  createMesh,
}: {
  disabled: boolean;
  createMesh: (event: FormEvent<HTMLFormElement>) => void;
}) {
  const [auto, setAuto] = useState(true);
  return (
    <Paper component="section" className="panel">
      <h2>Create mesh</h2>
      <form className="form-grid" onSubmit={createMesh} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
        <TextField
          label="Mesh name"
          disabled={disabled}
          name="name"
          required
          slotProps={{ htmlInput: { maxLength: 256 } }}
          placeholder="e.g. Production"
        />
        <fieldset disabled={disabled} style={{ display: "flex", flexDirection: "column", gap: "0.5rem", alignItems: "flex-start", border: "none", padding: 0, margin: 0 }}>
          <FormControlLabel
            control={
              <Switch
                name="auto"
                checked={auto}
                onChange={(event) => setAuto(event.target.checked)}
                disabled={disabled}
              />
            }
            label="Auto WireGuard"
          />
          <Box sx={{ marginLeft: 3, marginTop: 1, display: "flex", alignItems: "flex-start", flexDirection: "column", gap: 1 }}>
            <FormControlLabel
              control={<Switch name="fec" disabled={disabled || !auto} />}
              label="Enable FEC for WireGuard only"
            />
            <small className="muted">Other protocols use their own FEC settings.</small>
            <NumberField
              size="small"
              label="MTU"
              disabled={disabled || !auto}
              name="mtu"
              min={1280}
              max={9000}
              defaultValue={1420}
              required={auto}
            />
          </Box>
        </fieldset>
        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <Button variant="contained" type="submit" disabled={disabled}>
            Create mesh
          </Button>
        </div>
      </form>
    </Paper>
  );
}
