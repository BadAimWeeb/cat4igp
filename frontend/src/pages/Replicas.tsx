import {
  useEffect,
  useRef,
  useState,
  type MutableRefObject,
  type FormEvent,
} from "react";
import { request, RequestError, type Pending } from "../api/request";
import {
  Alert,
  Button,
  Checkbox,
  FormControlLabel,
  Paper,
  Table,
  TableContainer,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  TextField,
} from "@mui/material";
import { ActionMenu, IconAction } from "../components/Controls";
import {
  desiredState,
  grantDraft,
  prepareGrant,
  replicasFrom,
  servingEndpoints,
  joinCommand,
  type Replicas as Inventory,
  type ReplicaAction,
  type EnrollmentCode,
  type JoinBundle,
} from "../api/replicas";

export function Replicas({
  blocked,
  lock,
  setBusy,
  failed,
  grant,
  refreshVersion,
  unknown,
  setUnknown,
  ask,
}: {
  blocked: boolean;
  lock: MutableRefObject<boolean>;
  setBusy: (v: boolean) => void;
  failed: (e: unknown) => void;
  grant: (p: Pending) => void;
  refreshVersion: number;
  unknown?: ReplicaAction;
  setUnknown: (p: ReplicaAction | undefined) => void;
  ask: (label: string, warning: string, proceed: () => void) => void;
}) {
  const [data, setData] = useState<Inventory>();
  const [loading, setLoading] = useState(false);
  const [secret, setSecret] = useState<EnrollmentCode>();
  const [bundle, setBundle] = useState<JoinBundle>();
  const [bundleNode, setBundleNode] = useState("");
  const [bundleBootstrap, setBundleBootstrap] = useState("");
  const [notice, setNotice] = useState("");
  const [inspected, setInspected] = useState(false);
  const [grantNode, setGrantNode] = useState("");
  const [publicPrefix, setPublicPrefix] = useState("");
  const [controlPrefix, setControlPrefix] = useState("");
  const [suggestControl, setSuggestControl] = useState("");
  const grantSelect = useRef<HTMLInputElement>(null);
  const alive = useRef(true);
  const sequence = useRef(0);
  async function refresh() {
    const seq = ++sequence.current;
    setLoading(true);
    try {
      const inventory = replicasFrom(await request("/admin/replicas"));
      if (alive.current && seq === sequence.current) {
        setData(inventory);
        setInspected(true);
      }
    } catch (e) {
      if (alive.current && seq === sequence.current) {
        setData(undefined);
        setInspected(false);
        failed(
          e instanceof RequestError && e.status === 409
            ? new Error(
                "Replica inventory is unavailable in standalone mode (409); use an HA controller.",
              )
            : e,
        );
      }
    } finally {
      if (alive.current && seq === sequence.current) setLoading(false);
    }
  }
  useEffect(() => {
    alive.current = true;
    void refresh();
    const clear = () => {
      setSecret(undefined);
    };
    window.addEventListener("pagehide", clear);
    window.addEventListener("hashchange", clear);
    return () => {
      alive.current = false;
      sequence.current++;
      window.removeEventListener("pagehide", clear);
      window.removeEventListener("hashchange", clear);
    };
  }, []);
  useEffect(() => {
    if (refreshVersion) void refresh();
  }, [refreshVersion]);
  async function run(payload: ReplicaAction) {
    if (
      blocked ||
      lock.current ||
      loading ||
      (unknown && payload !== unknown && payload.action !== "enrollment_code")
    )
      return;
    lock.current = true;
    setBusy(true);
    setSecret(undefined);
    setBundle(undefined);
    setNotice("");
    try {
      const result = await desiredState(payload);
      if (payload.action !== "enrollment_code") setUnknown(undefined);
      if (!alive.current) return;
      if (payload.action === "join_bundle") {
        if (result) setBundle(result as JoinBundle);
        else setNotice("Desired state reconciled.");
      } else if (result) setSecret(result as EnrollmentCode);
      else setNotice("Desired state reconciled.");
      if (payload.action !== "enrollment_code") {
        setUnknown(undefined);
        await refresh();
      }
    } catch (e) {
      if (
        e instanceof RequestError &&
        e.outcome === "unknown" &&
        payload.action !== "enrollment_code"
      )
        setUnknown(payload);
      if (alive.current) {
        if (
          e instanceof RequestError &&
          e.outcome === "unknown" &&
          payload.action !== "enrollment_code"
        )
          setInspected(false);
        failed(e);
      } else if (e instanceof RequestError && e.status === 401) failed(e);
    } finally {
      lock.current = false;
      setBusy(false);
    }
  }
  function rotate(initial = false) {
    if ((!initial && !secret) || disabled || unknown) return;
    const expected_generation = initial ? 0 : secret!.generation;
    ask(`Rotate enrollment code with expected generation ${expected_generation}`,
      `${initial ? "Creates the first code only if none exists. " : ""}After an unknown outcome, retrieve the current code/generation before resuming.`,
      () => void run({ action: "rotate_enrollment_code", expected_generation }));
  }
  function operate(action: "activate_learner" | "promote_learner" | "revoke_replica", node_id: number) {
    if (disabled || unknown) return;
    const payload = { action, node_id } as const;
    if (action === "revoke_replica")
      ask(`Permanently revoke replica #${node_id}`,
        "Withdraw serving, remove membership and tombstone the identity. Self/last-voter removal is unsupported. This cannot be undone.",
        () => void run(payload));
    else void run(payload);
  }
  function submitGrant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (disabled || unknown || !data) return;
    const values = new FormData(event.currentTarget);
    try {
      if (values.get("binding") !== "on")
        throw new Error("Confirm the selected admission and address binding.");
      const node_id = Number(grantNode);
      const public_address = String(values.get("public_address"));
      const control_address = String(values.get("control_address"));
      const peer = data ? grantDraft(data, node_id)?.peer : null;
      if (!peer) throw new Error("Select an admitted replica first.");
      const public_full = public_address.endsWith(`/p2p/${peer}`)
        ? public_address
        : `${public_address}/p2p/${peer}`;
      const pending = prepareGrant(data, node_id, public_full, control_address);
      ask(`Grant serving to node #${node_id}, admission peer ${data.admitted[grantNode]}`,
        `Public: ${public_full}\nControl: ${control_address}\nExpected roster revision: ${data.roster?.revision}\n\nExisting bindings cannot be relocated.`,
        () => grant(pending));
    } catch (e) {
      failed(e);
    }
  }
  function suggestGrant(node_id: string) {
    setGrantNode(node_id);
    const draft = data ? grantDraft(data, Number(node_id)) : null;
    setSuggestControl(draft?.control ?? "");
    requestAnimationFrame(() => {
      document
        .querySelector<HTMLInputElement>('input[name="public_address"]')
        ?.focus();
    });
  }
  const disabled = blocked || loading;
  const m = data?.membership_observation;
  const selectedPeer = data?.admitted[grantNode];
  const eligible =
    !!data?.roster && !!selectedPeer && !data?.revocations[grantNode];
  const batchCandidates = data && m && data.roster ? batchTargets(data) : [];
  function batchTargets(data: Inventory) {
    return data.pending
      .filter((p) =>
        data.admitted[String(p.node_id)] &&
        !data.revocations[String(p.node_id)] &&
        data.membership_observation.membership.configs.some((c) =>
          c.includes(p.node_id)))
      .sort((a, b) => a.node_id - b.node_id);
  }
  function submitBatchGrant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (disabled || unknown || !data) return;
    const values = new FormData(event.currentTarget);
    try {
      if (values.get("binding") !== "on")
        throw new Error("Confirm the batch binding attestation.");
      const public_base = String(values.get("public_base")).trim();
      const control_base = String(values.get("control_base")).trim();
      const start = Number(values.get("start_port"));
      if (
        !public_base.startsWith("/") ||
        !control_base.startsWith("/") ||
        !Number.isSafeInteger(start) ||
        start <= 0 ||
        start + batchCandidates.length > 65535
      )
        throw new Error(
          "Enter multiaddress prefixes ending in /tcp/ plus a positive starting port.",
        );
      const batch = batchCandidates.map((candidate, index) => {
        const draft = grantDraft(data, candidate.node_id);
        if (!draft) throw new Error(`No draft for node #${candidate.node_id}.`);
        return {
          pending: prepareGrant(
            data,
            draft.node_id,
            `${public_base}${start + index}${draft.hint}`,
            draft.control,
          ),
          label: `#${draft.node_id} · ${draft.peer}`,
          control: draft.control,
          public: `${public_base}${start + index}${draft.hint}`,
        };
      });
      ask(
        `Grant serving to ${batch.length} admitted non-revoked voters`,
        batch.map((b) => `${b.label}\n  public ${b.public}\n  control ${b.control}`).join("\n") +
          `\n\nExpected roster revision: ${data.roster?.revision}. Each grant bumps the revision; existing bindings cannot be relocated. Definite conflicts end the batch — inspect and resubmit individually.`,
        () => batch.forEach((b, i) => setTimeout(() => grant(b.pending), i * 250)),
      );
    } catch (e) {
      failed(e);
    }
  }
  const ids =
    data && m
      ? [
          ...new Set([
            ...Object.keys(data.admitted),
            ...data.pending.map((p) => String(p.node_id)),
            ...Object.keys(m.membership.nodes),
            ...m.membership.configs.flat().map(String),
            ...Object.keys(data.revocations),
          ]),
        ].sort((a, b) => Number(a) - Number(b))
      : [];
  return (
    <>
      <Paper component="section" className="panel" aria-busy={loading}>
        <div className="section-heading">
          <h2>Replica inventory</h2>
          <IconAction
            label="Refresh replicas"
            icon="refresh"
            disabled={disabled}
            onClick={() => void refresh()}
          />
        </div>
        {loading && <p role="status">Loading replica inventory…</p>}
        {!data && !loading && <p>No cached replica inventory is shown.</p>}
        {data && m && (
          <>
            <p>Leader #{m.leader_id ?? "not observed"}</p>
            <p>
              {m.membership.configs.length > 1
                ? "Joint membership — each voter set matters:"
                : "Voters:"}{" "}
              {m.membership.configs
                .map((c, i) => `set ${i + 1} [${c.join(", ")}]`)
                .join(" / ") || "No voter sets"}
            </p>
            <TableContainer>
              <Table>
                <caption className="sr-only">
                  Admissions, native membership and revocations
                </caption>
                <TableHead>
                  <TableRow>
                    <TableCell scope="col">Node</TableCell>
                    <TableCell scope="col">Role</TableCell>
                    <TableCell scope="col">Address</TableCell>
                    <TableCell scope="col">Status</TableCell>
                    <TableCell scope="col">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {ids.map((id) => {
                    const p = data.pending.find(
                      (p) => String(p.node_id) === id,
                    );
                    const revoked = data.revocations[id];
                    const sets = m.membership.configs.flatMap((c, i) =>
                      c.includes(Number(id)) ? [i + 1] : [],
                    );
                    const role = sets.length
                      ? `Voter (set ${sets.join(", ")})`
                      : m.membership.nodes[id]
                        ? "Learner"
                        : "Not a member";
                    const status = revoked
                      ? revoked.complete
                        ? "Permanently revoked"
                        : "Revocation pending"
                      : data.admitted[id]
                        ? p
                          ? "Admitted · pending"
                          : "Admitted"
                        : "Not admitted";
                    const serving = servingEndpoints(data, Number(id));
                    const grantEligible =
                      !!data.roster && sets.length > 0 && !revoked && !serving;
                    return (
                      <TableRow key={id} data-testid={`replica-row-${id}`}>
                        <TableCell component="th" scope="row">
                          #{id}
                        </TableCell>
                        <TableCell>{role}</TableCell>
                        <TableCell>
                          {p?.address ?? m.membership.nodes[id]?.addr ?? "—"}
                          {serving && (
                            <small>
                              public ({serving.public || "—"})
                              <br />
                              control ({serving.control || "—"})
                            </small>
                          )}
                        </TableCell>
                        <TableCell>{status}</TableCell>
                        <TableCell>
                          <ActionMenu
                            label={`Actions for replica #${id}`}
                            disabled={disabled || !!unknown}
                            items={[
                              {
                                label: "Activate learner…",
                                onClick: () => operate("activate_learner", Number(id)),
                              },
                              {
                                label: "Promote learner…",
                                onClick: () => operate("promote_learner", Number(id)),
                              },
                              {
                                label: "Revoke replica permanently…",
                                onClick: () => operate("revoke_replica", Number(id)),
                              },
                            ]}
                          />
                          {grantEligible && (
                            <Button
                              size="small"
                              variant="outlined"
                              disabled={disabled || !!unknown}
                              onClick={() => {
                                setGrantNode(id);
                                grantSelect.current?.focus();
                              }}
                            >
                              Grant serving
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
            {!ids.length && <p>No replica records.</p>}
            {!data.roster && (
              <p className="muted">
                No committed serving roster: grants and bundle joins are
                unavailable until HA is up.
              </p>
            )}
          </>
        )}
      </Paper>
      <Paper component="section" className="panel">
        <h2>Grant serving</h2>
        {!data?.roster && !loading && (
          <p>Fetch a committed roster before submitting a grant.</p>
        )}
        <form className="form-grid" onSubmit={submitGrant}>
          <fieldset disabled={disabled || !!unknown || !data?.roster}>
            <TextField
              label="Admitted replica"
              disabled={disabled || !!unknown || !data?.roster}
              inputRef={grantSelect}
              select
              slotProps={{
                select: { native: true },
                inputLabel: { shrink: true },
              }}
              required
              value={grantNode}
              onChange={(e) => suggestGrant(e.target.value)}
            >
              <option value="">Select admission</option>
              {Object.entries(data?.admitted ?? {}).map(([id, peer]) => (
                <option key={id} value={id}>
                  #{id} · {peer}
                </option>
              ))}
            </TextField>
            <TextField
              label="Public address"
              disabled={disabled || !!unknown || !data?.roster}
              name="public_address"
              required
              spellCheck={false}
              autoComplete="off"
              value={publicPrefix}
              onChange={(e) => setPublicPrefix(e.target.value)}
              placeholder="/ip4/203.0.113.9/tcp/9000"
              helperText={
                selectedPeer
                  ? `Append /p2p/${selectedPeer} if not included`
                  : "Suffix /p2p/ with the selected peer ID"
              }
            />
            <TextField
              label="Private address"
              disabled={disabled || !!unknown || !data?.roster}
              name="control_address"
              required
              spellCheck={false}
              autoComplete="off"
              value={controlPrefix || suggestControl}
              onChange={(e) => setControlPrefix(e.target.value)}
              placeholder="/ip4/10.0.0.9/tcp/9001"
              helperText={
                suggestControl
                  ? "Prefilled from the committed admission"
                  : undefined
              }
            />
            <FormControlLabel
              className="confirmation"
              key={grantNode}
              control={
                <Checkbox
                  name="binding"
                  required
                  disabled={disabled || !!unknown || !data?.roster}
                />
              }
              label="I confirm both addresses name the selected admission peer."
            />
            <Button variant="contained" type="submit" disabled={!eligible}>
              Grant serving…
            </Button>
          </fieldset>
        </form>
      </Paper>
      <Paper component="section" className="panel">
        <h2>Batch grant serving</h2>
        {!batchCandidates.length && !loading && (
          <p>
            No pending batch: every admitted voter either already serves or has
            no committed admission. Grant individually instead.
          </p>
        )}
        {!!batchCandidates.length && (
          <>
            <p className="muted">
              {batchCandidates.map((c) => `#${c.node_id}`).join(", ")}
            </p>
            <form className="form-grid" onSubmit={submitBatchGrant}>
              <fieldset disabled={disabled || !!unknown || !data?.roster}>
                <TextField
                  label="Public prefix"
                  disabled={disabled || !!unknown || !data?.roster}
                  name="public_base"
                  required
                  spellCheck={false}
                  autoComplete="off"
                  placeholder="/ip4/203.0.113.9/tcp/9000"
                  slotProps={{ htmlInput: { spellCheck: false } }}
                />
                <TextField
                  label="Starting port"
                  disabled={disabled || !!unknown || !data?.roster}
                  name="start_port"
                  required
                  type="number"
                  slotProps={{
                    htmlInput: {
                      min: 1,
                      max: 65534 - batchCandidates.length,
                      inputMode: "numeric",
                    },
                  }}
                />
                <FormControlLabel
                  className="confirmation"
                  control={
                    <Checkbox
                      name="binding"
                      required
                      disabled={disabled || !!unknown || !data?.roster}
                    />
                  }
                  label="I confirm the prefix, starting port and each node's admission produce distinct valid public addresses; private addresses come from each committed admission."
                />
                <Button variant="outlined" type="submit">
                  Draft batch grants…
                </Button>
              </fieldset>
            </form>
          </>
        )}
      </Paper>
      <Paper component="section" className="panel">
        <h2>Operations</h2>
        {unknown && (
          <Alert severity="error" className="banner" role="alert">
            <p>
              Outcome unknown: {JSON.stringify(unknown)}. Inspect inventory; for
              rotation retrieve current code/generation. Only then manually
              resume this identical desired state. New writes are blocked across
              views; this reminder survives sign-out but not reload.
            </p>
            <Button
              disabled={
                disabled ||
                !inspected ||
                (unknown.action === "rotate_enrollment_code" && !secret)
              }
              onClick={() => {
                ask("Resume desired state",
                  "No new generation or target will be allocated.",
                  () => void run(unknown));
              }}
            >
              Resume…
            </Button>
            <Button
              variant="outlined"
              disabled={disabled || !inspected}
              onClick={() => {
                ask("Dismiss outcome reminder",
                  "This does not undo any commit.",
                  () => setUnknown(undefined));
              }}
            >
              Dismiss…
            </Button>
          </Alert>
        )}
        {notice && (
          <Alert severity="success" role="status">
            {notice}
          </Alert>
        )}
        <div className="actions">
          <Button
            disabled={disabled}
            onClick={() => void run({ action: "enrollment_code" })}
          >
            Enrollment code
          </Button>
          <Button
            variant="outlined"
            disabled={disabled || !secret || !!unknown}
            onClick={() => rotate()}
          >
            Rotate…
          </Button>
          <Button
            variant="outlined"
            disabled={disabled || !!unknown}
            onClick={() => rotate(true)}
          >
            Create first code…
          </Button>
        </div>
        <form
          className="form-grid"
          onSubmit={(e) => {
            e.preventDefault();
            if (disabled || unknown) return;
            const node_id = Number(bundleNode);
            if (!Number.isSafeInteger(node_id) || node_id <= 0) {
              failed(new Error("Enter a safe positive node ID for the bundle."));
              return;
            }
            void run({ action: "join_bundle", bootstrap: bundleBootstrap });
          }}
        >
          <fieldset disabled={disabled || !!unknown}>
            <legend className="muted">Prepare join bundle</legend>
            <TextField
              label="Bootstrap address"
              disabled={disabled || !!unknown}
              value={bundleBootstrap}
              onChange={(e) => setBundleBootstrap(e.target.value)}
              placeholder="/ip4/203.0.113.9/tcp/9000/p2p/PEER_ID"
              slotProps={{ htmlInput: { spellCheck: false } }}
            />
            <TextField
              label="Replica node ID"
              disabled={disabled || !!unknown}
              value={bundleNode}
              onChange={(e) => setBundleNode(e.target.value)}
              placeholder="e.g. 4"
              slotProps={{ htmlInput: { inputMode: "numeric" } }}
            />
            <Button variant="outlined" type="submit">
              Join bundle…
            </Button>
          </fieldset>
        </form>
      </Paper>
      <Paper component="section" className="panel">
        <h2>Replica operations guide</h2>
        <ol>
          <li>
            Read the inventory: every row is one replica with its role (voter,
            learner or not a member), transport address and status. Admission,
            membership and serving are separate concepts — a row can be
            admitted but not yet a member, and being a voter does not prove
            reachability. Use the refresh button above the table to re-read.
          </li>
          <li>
            Grant serving first for a new replica: pick it from "Admitted
            replica" (only committed, non-revoked voters are listed), enter a
            public discovery multiaddress and a distinct private control
            multiaddress, both ending in <code>/p2p/</code> with that
            replica's peer ID, tick the binding confirmation and submit.
            Existing bindings cannot be relocated; a stale roster revision is
            rejected — refresh, inspect the binding, then submit a new intent.
          </li>
          <li>
            Onboard the replica: in "Prepare join bundle" enter the bootstrap
            multiaddress (the controller's public discovery address; the
            optional node ID pre-assigns the replica's number) and copy the
            generated command to the joining machine. The bundle contains a
            live enrollment code — treat it like a password, never log it.
            Run the command there, start the server, wait for it to appear as
            "Admitted" in the inventory.
          </li>
          <li>
            Activate the learner from the row's action menu. This starts
            native replication so the new replica catches up with the
            cluster's log. Wait until it is caught up before continuing.
          </li>
          <li>
            Promote the learner from the row's action menu. It then becomes a
            full voter and counts toward quorum.
          </li>
          <li>
            Decommission a replica with "Revoke replica permanently…" in its
            action menu. This withdraws serving, removes membership and
            tombstones the identity and cannot be undone; removing yourself
            or the last remaining voter is refused. Revoked replicas stay
            visible with their revocation status.
          </li>
          <li>
            Manage enrollment codes in "Operations": retrieve the current
            code to inspect it, rotate the retrieved generation to switch
            codes (the previous one overlaps for a while), or "Create first
            code…" only when none exists yet. Codes are shown once and
            cleared by navigation, sign-out or dismissal.
          </li>
          <li>
            If an operation's outcome is unknown (server error on the way
            back), a reminder appears and blocks further writes. Inspect the
            inventory — and for rotation retrieve the current code/generation
            — before resuming the identical desired state with "Resume…", or
            explicitly dismiss the reminder after inspection. Cancel or
            dismissing cannot undo something already committed.
          </li>
        </ol>
        <p className="muted">
          Order matters: grant serving → join bundle → activate → promote;
          reversal of removal is impossible, and leadership keeps running
          with at least a 2-node quorum.
        </p>
      </Paper>
      {secret && (
        <Paper component="section" className="panel secret">
          <h2>Enrollment code</h2>
          <p>Generation {secret.generation}</p>
          <TextField
            label="Current enrollment code"
            slotProps={{
              htmlInput: {
                readOnly: true,
                onFocus: (e: React.FocusEvent<HTMLInputElement>) =>
                  e.currentTarget.select(),
              },
            }}
            value={secret.code}
            autoComplete="off"
            spellCheck={false}
          />
          <IconAction
            label="Copy current enrollment code"
            icon="copy"
            onClick={() => {
              void navigator.clipboard.writeText(secret.code).catch(failed);
            }}
          />
          {secret.previous && (
            <>
              <TextField
                label="Previous overlapping code"
                slotProps={{
                  htmlInput: {
                    readOnly: true,
                    onFocus: (e: React.FocusEvent<HTMLInputElement>) =>
                      e.currentTarget.select(),
                  },
                }}
                value={secret.previous[0]}
                autoComplete="off"
                spellCheck={false}
              />
              <IconAction
                label="Copy previous enrollment code"
                icon="copy"
                onClick={() => {
                  void navigator.clipboard
                    .writeText(secret.previous![0])
                    .catch(failed);
                }}
              />
              <p>Previous overlap expires {secret.previous[1]} (Unix ms).</p>
            </>
          )}
          <p>
            Transient only: no browser storage/logs. Navigation, session
            rejection, sign out or dismissal clears this reveal.
          </p>
          <Button variant="outlined" onClick={() => setSecret(undefined)}>
            Dismiss enrollment codes
          </Button>
        </Paper>
      )}
      {bundle && (
        <Paper component="section" className="panel secret">
          <h2>Join bundle</h2>
          <p>
            Contains a live enrollment code, treat like the code itself.
          </p>
          <TextField
            label="One-command join (copy for the joining operator)"
            multiline
            minRows={3}
            slotProps={{
              htmlInput: {
                readOnly: true,
                onFocus: (e: React.FocusEvent<HTMLInputElement>) =>
                  e.currentTarget.select(),
              },
            }}
            value={joinCommand(bundle, Number(bundleNode) || 0)}
            autoComplete="off"
            spellCheck={false}
          />
          <IconAction
            label="Copy join command"
            icon="copy"
            onClick={() => {
              void navigator.clipboard
                .writeText(joinCommand(bundle, Number(bundleNode) || 0))
                .catch(failed);
            }}
          />
          <p>
            The joining operator saves the JSON payload as a file and runs the
            command. Explicit learner activation afterwards is still required.
          </p>
          <Button variant="outlined" onClick={() => setBundle(undefined)}>
            Dismiss join bundle
          </Button>
        </Paper>
      )}
    </>
  );
}
