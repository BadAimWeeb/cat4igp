import { useMemo, useEffect, useRef, useState, type FormEvent } from "react";
import {
  prepare,
  request,
  send,
  RequestError,
  type Pending,
} from "./api/request";
import { inventoryFrom, integer, type Inventory } from "./api/inventory";
import { Replicas } from "./pages/Replicas";
import { type ReplicaAction } from "./api/replicas";
import { IconAction } from "./components/Controls";
import { Login } from "./pages/Login";
import { Nodes, RenameNode } from "./pages/Nodes";
import { Meshes, CreateMesh } from "./pages/Meshes";
import { Memberships, type MembershipScope } from "./pages/Memberships";
import { Tunnels } from "./pages/Tunnels";
import { Invites, CreateInvite, InviteCode } from "./pages/Invites";
import { preferredMode, themeKey, type Mode } from "./theme";
import {
  Alert,
  Button,
  CssBaseline,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  Paper,
  ThemeProvider,
  createTheme,
} from "@mui/material";

// ponytail: MD2 visual tokens with maintained MUI; adopt MD3 tokens only when requested.
const makeTheme = (mode: Mode) =>
  createTheme({
    palette: {
      mode,
      primary: { main: mode === "dark" ? "#a5b4fc" : "#3f51b5" },
      secondary: { main: "#f50057" },
      background: { default: mode === "dark" ? "#121212" : "#fafafa" },
    },
    shape: { borderRadius: 4 },
    typography: {
      fontFamily: 'Roboto, "Helvetica Neue", Arial, system-ui, sans-serif',
      h1: { fontSize: "2.125rem", fontWeight: 400, letterSpacing: "0.00735em" },
      h2: { fontSize: "1.25rem", fontWeight: 500, letterSpacing: "0.0075em" },
    },
    components: {
      MuiButton: { defaultProps: { type: "button" } },
      MuiTextField: { defaultProps: { variant: "outlined", size: "small" } },
      MuiPaper: {
        defaultProps: { elevation: 2 },
        styleOverrides: {
          root: ({ theme }) => ({
            "&.panel": {
              padding: theme.spacing(3),
              marginBottom: theme.spacing(3),
              [theme.breakpoints.down(720)]: { padding: theme.spacing(2) },
            },
            "&.login": { padding: theme.spacing(4) },
          }),
        },
      },
      MuiCssBaseline: {
        styleOverrides: {
          ":root": {
            colorScheme: mode,
            "--surface": mode === "dark" ? "#121212" : "#fff",
            "--muted": mode === "dark" ? "#bbb" : "#616161",
            "--divider": mode === "dark" ? "#ffffff1f" : "#0000001f",
            "--accent": mode === "dark" ? "#a5b4fc" : "#3f51b5",
          },
          h1: { fontSize: "2.125rem", fontWeight: 400 },
          h2: { fontSize: "1.25rem", fontWeight: 500 },
        },
      },
    },
  });

const inventoryTabs = ["Nodes", "Meshes", "Invites", "Tunnels"] as const;
const tabs = [...inventoryTabs, "Replicas"] as const;
type Tab = (typeof tabs)[number];

function checkedName(name: string) {
  if (
    !name.trim() ||
    /[\p{Cc}]/u.test(name) ||
    new TextEncoder().encode(name).length > 256
  )
    throw new Error(
      "Name must be nonblank, without control characters, and at most 256 UTF-8 bytes.",
    );
  return name;
}
const fields = (event: FormEvent<HTMLFormElement>) => {
  event.preventDefault();
  return new FormData(event.currentTarget);
};
const message = (error: unknown) =>
  error instanceof Error ? error.message : "Request failed.";

export function App() {
  const [editing, setEditing] = useState<{
    id: number;
    name: string;
    kind?: "node" | "mesh";
  }>();
  const [session, setSession] = useState<"checking" | "out" | "in">("checking");
  const [tab, setTab] = useState<Tab>("Nodes");
  const [scope, setScope] = useState<MembershipScope>();
  const [data, setData] = useState<Inventory>();
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [confirmation, setConfirmation] = useState<{
    label: string;
    warning: string;
    proceed: () => void;
  }>();
  // ponytail: one memory-only pending action; add secure durable recovery if reload survival is required.
  const [pending, setPending] = useState<Pending>();
  const [replicaUnknown, setReplicaUnknown] = useState<ReplicaAction>();
  const [replicaRefresh, setReplicaRefresh] = useState(0);
  const [code, setCode] = useState("");
  const heading = useRef<HTMLHeadingElement>(null);
  const lock = useRef(false);
  const inventoryGeneration = useRef(0);
  const [mode, setMode] = useState<Mode>(() => {
    const dark = matchMedia("(prefers-color-scheme: dark)").matches;
    try {
      return preferredMode(localStorage, dark);
    } catch {
      return dark ? "dark" : "light";
    }
  });
  useEffect(() => {
    const media = matchMedia("(prefers-color-scheme: dark)");
    const change = () => {
      try {
        setMode(preferredMode(localStorage, media.matches));
      } catch {
        setMode(media.matches ? "dark" : "light");
      }
    };
    media.addEventListener("change", change);
    return () => media.removeEventListener("change", change);
  }, []);
  const theme = useMemo(() => makeTheme(mode), [mode]);
  function toggleTheme() {
    const next = mode === "dark" ? "light" : "dark";
    try {
      localStorage.setItem(themeKey, next);
    } catch {
      /* Preference is optional. */
    }
    setMode(next);
  }

  function failed(e: unknown) {
    setError(message(e));
    if (e instanceof RequestError && e.status === 401) {
      inventoryGeneration.current++;
      setLoading(false);
      setSession("out");
      setData(undefined);
      setCode("");
    }
  }
  async function refresh() {
    const generation = ++inventoryGeneration.current;
    setLoading(true);
    try {
      const inventory = inventoryFrom(await request("/admin/inventory"));
      if (generation === inventoryGeneration.current) setData(inventory);
    } catch (e) {
      if (generation === inventoryGeneration.current) {
        setData(undefined);
        failed(e);
      }
    } finally {
      if (generation === inventoryGeneration.current) setLoading(false);
    }
  }
  async function resume() {
    if (lock.current) return;
    lock.current = true;
    setBusy(true);
    setError("");
    try {
      const me = (await request("/admin/me")) as { subject?: unknown } | null;
      // ponytail: one fixed administrator; add account-scoped state only with a multi-account backend.
      if (me?.subject !== "administrator:1")
        throw new Error("Unsupported administrator identity.");
      setSession("in");
    } catch (e) {
      setSession("out");
      if (!(e instanceof RequestError && e.status === 401)) failed(e);
    } finally {
      lock.current = false;
      setBusy(false);
    }
  }
  useEffect(() => {
    void resume();
    return () => { inventoryGeneration.current++; };
  }, []);
  useEffect(() => {
    if (session === "in") void refresh();
  }, [session]);
  useEffect(() => {
    heading.current?.focus();
  }, [session, tab, scope]);
  useEffect(() => {
    if (!pending && !replicaUnknown) return;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [pending, replicaUnknown]);

  async function login(event: FormEvent<HTMLFormElement>) {
    const form = event.currentTarget;
    const values = fields(event);
    if (lock.current) return;
    const username = String(values.get("username"));
    const password = String(values.get("password"));
    const bytes = new TextEncoder();
    if (
      !username.trim() ||
      /[\p{Cc}]/u.test(username) ||
      bytes.encode(username).length > 256 ||
      bytes.encode(password).length < 12 ||
      bytes.encode(password).length > 1024
    ) {
      setError(
        "Use a valid username (up to 256 bytes) and password (12–1024 UTF-8 bytes).",
      );
      return;
    }
    lock.current = true;
    setBusy(true);
    setError("");
    try {
      const result = (await request(
        "/admin/login",
        JSON.stringify({ username, password }),
      )) as { success?: unknown; subject?: unknown } | null;
      if (result?.success !== true || result.subject !== "administrator:1")
        throw new Error("Unrecognized login response.");
      inventoryGeneration.current++;
      setSession("in");
      setNotice(
        pending
          ? "Signed in. Retry the retained action to confirm its outcome."
          : "Signed in securely.",
      );
    } catch (e) {
      failed(e);
    } finally {
      form.reset();
      lock.current = false;
      setBusy(false);
    }
  }
  async function logout() {
    if (lock.current) return;
    inventoryGeneration.current++;
    setLoading(false);
    lock.current = true;
    setBusy(true);
    setError("");
    setCode("");
    setTab("Nodes");
    setScope(undefined);
    try {
      await request("/admin/logout", "{}");
      setSession("out");
      setData(undefined);
      setNotice(
        "Signed out. Any unresolved action is retained in this tab for the same administrator.",
      );
    } catch (e) {
      failed(e);
    } finally {
      lock.current = false;
      setBusy(false);
    }
  }
  async function attempt(action: Pending) {
    if (lock.current) return;
    lock.current = true;
    setBusy(true);
    setError("");
    setNotice("");
    setCode("");
    try {
      const result = await send(action);
      setPending(undefined);
      if (action.endpoint === "/admin/invites")
        setCode(result.invite_code as string);
      setNotice(
        action.endpoint === "/admin/replicas/reconcile"
          ? `Historical serving receipt: revision ${result.roster_revision} · issued ${result.issued_at_ms} · expires ${result.expires_at_ms} (Unix ms). Not current serving status; replay does not renew the lease.`
          : `${action.label} committed.`,
      );
      if (action.endpoint === "/admin/replicas/reconcile")
        setReplicaRefresh((v) => v + 1);
      await refresh();
    } catch (e) {
      if (e instanceof RequestError && e.outcome === "rejected")
        setPending(undefined);
      failed(
        action.endpoint === "/admin/replicas/reconcile" &&
          e instanceof RequestError &&
          e.status === 409
          ? new Error(
              "Serving grant rejected (409): stale roster revision or binding/gateway/voter prerequisite conflict. Refresh replicas, inspect the binding, then explicitly submit a new intent. No new UUID/revision was allocated automatically.",
            )
          : e,
      );
    } finally {
      lock.current = false;
      setBusy(false);
    }
  }
  function start(
    endpoint: "/admin/actions" | "/admin/invites",
    payload: object,
    label: string,
  ) {
    if (pending || replicaUnknown || lock.current) return;
    try {
      const action = prepare(endpoint, payload, label);
      setPending(action);
      void attempt(action);
    } catch (e) {
      failed(e);
    }
  }
  function grant(action: Pending) {
    if (pending || replicaUnknown || lock.current) return;
    setPending(action);
    void attempt(action);
  }
  function cancel() {
    if (busy) return;
    ask("Forget this retry", "This does NOT undo a committed action. A new submission uses a new UUID/key and could duplicate creation or issue a new serving lease. Refresh inventory first.", () => {
      if (lock.current) return;
      setPending(undefined);
      setNotice("Retry forgotten, not rolled back. Inspect inventory before submitting a new action.");
      setError("");
    });
  }
  function rename(event: FormEvent<HTMLFormElement>, id: number) {
    const values = fields(event);
    if (pending || replicaUnknown || lock.current || loading) return;
    try {
      const name = checkedName(String(values.get("name")));
      start(
        "/admin/actions",
        {
          action: editing?.kind === "mesh" ? "rename_mesh" : "rename_node",
          id,
          name,
        },
        `Rename ${editing?.kind ?? "node"} #${id}`,
      );
      setEditing(undefined);
    } catch (e) {
      failed(e);
    }
  }
  function createMesh(event: FormEvent<HTMLFormElement>) {
    const values = fields(event);
    try {
      const auto = values.get("auto") === "on";
      const mtu = auto ? Number(values.get("mtu")) : 0;
      if (!integer(mtu) || (auto && (mtu < 1280 || mtu > 9000)))
        throw new Error("MTU must be an integer between 1280 and 9000.");
      start(
        "/admin/actions",
        {
          action: "create_mesh",
          name: checkedName(String(values.get("name"))),
          auto_wireguard: auto,
          fec: auto && values.get("fec") === "on",
          mtu,
        },
        "Create mesh",
      );
    } catch (e) {
      failed(e);
    }
  }
  function createInvite(event: FormEvent<HTMLFormElement>) {
    const values = fields(event);
    try {
      const max = String(values.get("max"));
      const mesh = String(values.get("mesh"));
      const expiry = String(values.get("expiry"));
      const max_uses = !max || Number(max) === 0 ? null : Number(max);
      const join_mesh = mesh ? Number(mesh) : null;
      const expires_at = expiry ? new Date(expiry).getTime() : null;
      if (
        max_uses !== null &&
        (!integer(max_uses) || max_uses < 1 || max_uses > 2147483647)
      )
        throw new Error("Maximum uses must be 0 (unlimited), blank, or an integer from 1 to 2147483647.");
      if (
        join_mesh !== null &&
        (!integer(join_mesh) || !data?.meshes.some((m) => m.id === join_mesh))
      )
        throw new Error("Select an existing mesh.");
      if (
        expires_at !== null &&
        (!integer(expires_at) || expires_at <= Date.now())
      )
        throw new Error("Expiry must be in the future (your local time).");
      start(
        "/admin/invites",
        { expires_at, max_uses, join_mesh },
        "Create invite",
      );
    } catch (e) {
      failed(e);
    }
  }
  function addMembership(event: FormEvent<HTMLFormElement>) {
    const values = fields(event);
    const mesh_id = Number(values.get("mesh"));
    const node_id = Number(values.get("node"));
    if (
      !integer(mesh_id) ||
      !integer(node_id) ||
      !data?.meshes.some((m) => m.id === mesh_id) ||
      !data.nodes.some((n) => n.id === node_id)
    ) {
      setError("Select an existing mesh and node.");
      return;
    }
    start(
      "/admin/actions",
      { action: "add_membership", mesh_id, node_id },
      `Add node #${node_id} to mesh #${mesh_id}`,
    );
  }
  function confirmed(payload: object, label: string, warning: string) {
    if (pending || replicaUnknown || lock.current || loading) return;
    ask(label, warning, () => start("/admin/actions", payload, label));
  }
  function ask(label: string, warning: string, proceed: () => void) {
    setConfirmation({ label, warning, proceed });
  }
  const disabled = busy || !!pending || !!replicaUnknown || loading;
  const meshName = (id: number | null) =>
    id === null
      ? "Any mesh"
      : `${data?.meshes.find((m) => m.id === id)?.name ?? "Mesh"} · #${id}`;
  const nodeName = (id: number) =>
    `${data?.nodes.find((n) => n.id === id)?.name ?? "Node"} · #${id}`;

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <a className="skip" href="#main">
        Skip to content
      </a>
      <aside className="sidebar">
        <a className="brand" href="#main">
          <span className="logo" aria-hidden="true">
            c4
          </span>
          cat4igp<span className="edition">CONTROL ROOM</span>
        </a>
        <p className="eyebrow">Administration</p>
        <nav aria-label="Inventory views">
          <List disablePadding className="view-list">
            {tabs.map((t) => (
              <ListItem key={t} disablePadding>
                <ListItemButton
                  component="button"
                  type="button"
                  selected={tab === t}
                  aria-label={t}
                  aria-current={tab === t ? "page" : undefined}
                  onClick={() => {
                    setCode("");
                    setError("");
                    setTab(t);
                    setScope(undefined);
                  }}
                >
                  <ListItemText primary={t} />
                  <span
                    className="view-count"
                    aria-label={
                      t === "Replicas" ? "High availability" : `${t} count`
                    }
                  >
                    {t === "Replicas"
                      ? "HA"
                      : (data?.[t.toLowerCase() as keyof Inventory].length ??
                        "—")}
                  </span>
                </ListItemButton>
              </ListItem>
            ))}
          </List>
        </nav>
      </aside>
      <div className="workspace">
        <header>
          <span>
            Network workspace <span className="separator">/</span> Administrator
          </span>
          <div className="actions">
            <IconAction
              label={`Switch to ${mode === "dark" ? "light" : "dark"} mode`}
              icon={mode === "dark" ? "light" : "dark"}
              onClick={toggleTheme}
            />
            {session === "in" ? (
              <IconAction
                label="Sign out"
                icon="logout"
                disabled={busy}
                onClick={() => void logout()}
              />
            ) : (
              <span className="tag">Secure cookie session</span>
            )}
          </div>
        </header>
        <main
          id="main"
          tabIndex={-1}
          aria-busy={session === "checking" || busy || loading}
        >
          <div className="page-heading">
            <div>
              <p className="eyebrow">cat4igp / management</p>
              <h1 ref={heading} tabIndex={-1}>
                {session === "in"
                  ? scope
                    ? `${scope.kind === "node" ? "Memberships" : "Members"} · ${scope.kind === "node" ? nodeName(scope.id) : meshName(scope.id)}`
                    : tab
                  : session === "checking"
                    ? "Restoring session"
                    : "Welcome back"}
              </h1>
              <p>
                {session === "in"
                  ? "Management inventory"
                  : "Sign in to your controller. Credentials stay out of browser storage."}
              </p>
            </div>
            {session === "in" && (
              <IconAction
                label="Refresh"
                icon="refresh"
                disabled={busy || loading}
                onClick={() => {
                  setError("");
                  void refresh();
                }}
              />
            )}
          </div>
          {error && (
            <Alert severity="error" className="banner" role="alert">
              {error}
            </Alert>
          )}
          {notice && (
            <Alert severity="success" className="banner" role="status">
              {notice}
            </Alert>
          )}
          {pending && (
            <Paper
              component="section"
              className="panel pending"
              aria-labelledby="pending-title"
            >
              <h2 id="pending-title">
                {busy ? "Awaiting confirmation" : "Unresolved action"} ·{" "}
                {pending.label}
              </h2>
              <p>
                The outcome may be unknown.{" "}
                {pending.endpoint === "/admin/replicas/reconcile"
                  ? "Retry sends the frozen JSON body with the same request_id and expected roster revision, without Idempotency-Key. A durable historical receipt never renews the lease or proves current serving."
                  : "Retry sends the identical body and idempotency key; it will not intentionally create a second operation."}{" "}
                Identity: administrator:1.{" "}
                {session !== "in" && "Sign in as the same administrator first."}
              </p>
              <p>
                Cancel only forgets the retry, not the server operation.
                Switching views and signing out retain it; reloading or closing
                this tab loses it. Refresh inventory before starting again.
              </p>
              <div className="actions">
                <Button
                  variant="contained"
                  disabled={busy || session !== "in"}
                  onClick={() => void attempt(pending)}
                >
                  Retry same action
                </Button>
                <Button variant="outlined" disabled={busy} onClick={cancel}>
                  Cancel retry…
                </Button>
              </div>
            </Paper>
          )}
          {replicaUnknown && tab !== "Replicas" && (
            <p role="status">
              An unresolved desired-state operation blocks new writes. Open
              Replicas to inspect and manually resume or dismiss it.
            </p>
          )}
          {session === "checking" ? (
            <p role="status">Checking your session…</p>
          ) : session === "out" ? (
            <Login busy={busy} login={login} />
          ) : (
            <>
              <div className="metrics">
                {inventoryTabs.map((t) => (
                  <Paper className="metric" key={t}>
                    <span>{t}</span>
                    <strong>
                      {data?.[t.toLowerCase() as keyof Inventory].length ?? "—"}
                    </strong>
                  </Paper>
                ))}
              </div>
              {tab === "Replicas" && (
                <Replicas
                  blocked={busy || !!pending}
                  lock={lock}
                  setBusy={setBusy}
                  failed={failed}
                  grant={grant}
                  refreshVersion={replicaRefresh}
                  unknown={replicaUnknown}
                  setUnknown={setReplicaUnknown}
                  ask={ask}
                />
              )}
              {loading && (
                <p role="status">Loading quorum-confirmed inventory…</p>
              )}
              {!loading && !data && (
                <Paper component="section" className="panel">
                  <h2>Inventory unavailable</h2>
                  <p>
                    No cached inventory is shown. Retry using Refresh inventory.
                  </p>
                </Paper>
              )}
              {data && tab !== "Replicas" && (
                <>
                  <Paper
                    component="section"
                    className="panel inventory"
                    aria-label={`${tab} inventory`}
                    aria-busy={loading}
                  >
                    <div className="section-heading">
                      <h2>{tab}</h2>
                    </div>
                    {scope ? (
                      <Memberships
                        key={`${scope.kind}-${scope.id}`}
                        scope={scope}
                        data={data}
                        disabled={disabled}
                        confirmed={confirmed}
                        addMembership={addMembership}
                        meshName={meshName}
                        nodeName={nodeName}
                        back={() => setScope(undefined)}
                      />
                    ) : tab === "Nodes" ? (
                      <Nodes
                        nodes={data.nodes}
                        disabled={disabled}
                        edit={setEditing}
                        manage={(id) => setScope({ kind: "node", id })}
                        confirmed={confirmed}
                        nodeName={nodeName}
                      />
                    ) : tab === "Meshes" ? (
                      <Meshes
                        meshes={data.meshes}
                        disabled={disabled}
                        confirmed={confirmed}
                        meshName={meshName}
                        manage={(id) => setScope({ kind: "mesh", id })}
                        edit={(mesh) => setEditing({ ...mesh, kind: "mesh" })}
                        setMtu={(id, mtu) => start(
                          "/admin/actions",
                          { action: "set_mesh_mtu", id, mtu },
                          `Update WireGuard MTU for ${meshName(id)}`,
                        )}
                      />
                    ) : tab === "Tunnels" ? (
                      <Tunnels
                        tunnels={data.tunnels}
                        disabled={disabled}
                        confirmed={confirmed}
                        meshName={meshName}
                        nodeName={nodeName}
                      />
                    ) : tab === "Invites" ? (
                      <Invites
                        invites={data.invites}
                        meshName={meshName}
                        disabled={disabled}
                        confirmed={confirmed}
                      />
                    ) : null}
                  </Paper>
                  {!scope && tab === "Meshes" && (
                    <CreateMesh disabled={disabled} createMesh={createMesh} />
                  )}
                  {tab === "Invites" && (
                    <CreateInvite
                      meshes={data.meshes}
                      disabled={disabled}
                      createInvite={createInvite}
                    />
                  )}
                </>
              )}
              {code && (
                <InviteCode
                  code={code}
                  failed={failed}
                  dismiss={() => setCode("")}
                />
              )}
              <section className="upcoming">
                <span className="tag">NOT AVAILABLE</span>
                <p>
                  Replica admission submission, transport rotation, observed
                  health, and password management are not available here.
                </p>
              </section>
            </>
          )}
        </main>
        <footer>cat4igp control room</footer>
      </div>
      <RenameNode
        editing={editing}
        kind={editing?.kind}
        signedIn={session === "in"}
        disabled={disabled}
        close={() => setEditing(undefined)}
        rename={rename}
      />
      <Dialog
        open={!!confirmation}
        onClose={() => setConfirmation(undefined)}
        aria-labelledby="confirmation-title"
        aria-describedby="confirmation-warning"
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle id="confirmation-title">{confirmation?.label}?</DialogTitle>
        <DialogContent>
          <DialogContentText id="confirmation-warning" sx={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
            {confirmation?.warning}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button autoFocus onClick={() => setConfirmation(undefined)}>Cancel</Button>
          <Button variant="contained" disabled={busy || loading} onClick={() => {
            const proceed = confirmation?.proceed;
            setConfirmation(undefined);
            proceed?.();
          }}>Confirm</Button>
        </DialogActions>
      </Dialog>
    </ThemeProvider>
  );
}
