import type { FormEvent } from "react";
import {
  Button,
  Paper,
  Table,
  TableContainer,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  TextField,
} from "@mui/material";
import type { Inventory } from "../api/inventory";
import { ActionMenu, IconAction } from "../components/Controls";
import { NumberField } from "../components/NumberField";

export function Invites({
  invites,
  meshName,
  disabled,
  confirmed,
}: {
  invites: Inventory["invites"];
  meshName: (id: number | null) => string;
  disabled: boolean;
  confirmed: (payload: object, label: string, warning: string) => void;
}) {
  return (
    <>
      <TableContainer>
        <Table>
          <caption className="sr-only">Invite metadata</caption>
          <TableHead>
            <TableRow>
              <TableCell scope="col">Invite</TableCell>
              <TableCell scope="col">Mesh</TableCell>
              <TableCell scope="col">Uses / limit</TableCell>
              <TableCell scope="col">Created</TableCell>
              <TableCell scope="col">Expires</TableCell>
              <TableCell scope="col">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {invites.map((i) => (
              <TableRow key={i.id}>
                <TableCell component="th" scope="row">
                  #{i.id}
                </TableCell>
                <TableCell>{meshName(i.mesh_id)}</TableCell>
                <TableCell>
                  {i.used_count} / {i.max_uses || "Unlimited"}
                </TableCell>
                <TableCell>{i.created_at}</TableCell>
                <TableCell>{i.expires_at ?? "No expiry"}</TableCell>
                <TableCell>
                  <ActionMenu
                    label={`Actions for invite #${i.id}`}
                    disabled={disabled}
                    items={[
                      {
                        label: `Invalidate invite #${i.id}…`,
                        icon: "delete",
                        onClick: () =>
                          confirmed(
                            { action: "invalidate_invite", id: i.id },
                            `Permanently invalidate invite #${i.id}`,
                            "Prevents future enrollment with this invite and removes its recoverable code. Existing nodes are not revoked. This cannot be undone.",
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
      {!invites.length && <p className="empty">No invites created yet.</p>}
    </>
  );
}

export function CreateInvite({
  meshes,
  disabled,
  createInvite,
}: {
  meshes: Inventory["meshes"];
  disabled: boolean;
  createInvite: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <Paper component="section" className="panel">
      <h2>Create invite</h2>
      <p className="muted">
        Share privately. Code stays in this tab’s memory only.
      </p>
      <form className="form-grid" onSubmit={createInvite}>
        <fieldset disabled={disabled}>
          <TextField
            label="Override initial mesh join"
            disabled={disabled}
            select
            defaultValue=""
            slotProps={{
              select: { native: true },
              inputLabel: { shrink: true },
            }}
            name="mesh"
          >
            <option value="">Use global default</option>
            {meshes.map((m) => (
              <option key={m.id} value={m.id}>
                {m.name} · #{m.id}
              </option>
            ))}
          </TextField>
          <NumberField
            size="small"
            label="Maximum uses (0 = unlimited)"
            disabled={disabled}
            name="max"
            min={0}
            max={Number.MAX_SAFE_INTEGER}
            defaultValue={0}
          />
          <TextField
            label="Expires at (local time; blank = never)"
            disabled={disabled}
            name="expiry"
            type="datetime-local"
            slotProps={{ inputLabel: { shrink: true } }}
          />
          <Button variant="contained" type="submit">
            Create invite
          </Button>
        </fieldset>
      </form>
    </Paper>
  );
}

export function InviteCode({
  code,
  failed,
  dismiss,
}: {
  code: string;
  failed: (error: unknown) => void;
  dismiss: () => void;
}) {
  return (
    <Paper
      component="section"
      className="panel secret"
      aria-labelledby="code-title"
    >
      <h2 id="code-title">Your new node invite code</h2>
      <p>
        Do not share this code publicly. Only send this code to secure channels
        as it can be used to join your mesh.
      </p>
      <TextField
        label="Invite code"
        slotProps={{
          htmlInput: {
            readOnly: true,
            onFocus: (e: React.FocusEvent<HTMLInputElement>) =>
              e.currentTarget.select(),
          },
        }}
        value={code}
        autoComplete="off"
        spellCheck={false}
      />
      <IconAction
        label="Copy invite code"
        icon="copy"
        onClick={() => {
          void navigator.clipboard.writeText(code).catch(failed);
        }}
      />
      <Button variant="outlined" onClick={dismiss}>
        Dismiss code
      </Button>
    </Paper>
  );
}
