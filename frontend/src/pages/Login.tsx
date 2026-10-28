import type { FormEvent } from "react";
import { Button, Paper, TextField } from "@mui/material";

export function Login({
  busy,
  login,
}: {
  busy: boolean;
  login: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <Paper component="section" className="panel login">
      <h2>Administrator sign in</h2>
      <form onSubmit={login} aria-busy={busy}>
        <TextField
          label="Username"
          name="username"
          autoComplete="username"
          required
          slotProps={{ htmlInput: { maxLength: 256 } }}
        />
        <TextField
          label="Password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          slotProps={{ htmlInput: { minLength: 12, maxLength: 1024 } }}
        />
        <Button variant="contained" type="submit" loading={busy}>
          {busy ? "Connecting…" : "Sign in securely"}
        </Button>
      </form>
    </Paper>
  );
}
