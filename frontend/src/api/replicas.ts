import { request, RequestError, type Pending } from "./request.ts";

export type ReplicaAction =
  | { action: "enrollment_code" }
  | { action: "rotate_enrollment_code"; expected_generation: number }
  | { action: "join_bundle"; bootstrap: string }
  | {
      action: "activate_learner" | "promote_learner" | "revoke_replica";
      node_id: number;
    };
export type EnrollmentCode = {
  generation: number;
  code: string;
  activated_at_ms: number;
  expires_at_ms: number;
  previous: [string, number] | null;
};
export type JoinBundle = {
  application_version: number;
  cluster_id: string;
  signing_key: string;
  bootstrap: string;
  minimum_revision: number;
  code: string;
  node_id?: number;
};
type LogId = { leader_id: { term: number; node_id: number }; index: number };
type Controller = { peer_id: string; addresses: string[] };
export type Replicas = {
  admitted: Record<string, string>;
  pending: {
    node_id: number;
    peer_id: string;
    address: string;
    admitted_at_ms: number;
  }[];
  roster: null | {
    version: number;
    cluster_id: string;
    revision: number;
    issued_at_ms: number;
    expires_at_ms: number;
    controllers: Controller[];
    discovery_endpoints?: Controller[];
  };
  revocations: Record<string, { peer: string; complete: boolean }>;
  observation: string;
  membership_observation: {
    node_id: number;
    leader_id: number | null;
    membership: {
      configs: number[][];
      nodes: Record<string, { addr: string }>;
    };
    last_applied: LogId | null;
    replication: Record<string, LogId | null> | null;
    scope: string;
  };
};
const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
const uint = (v: unknown): v is number =>
  Number.isSafeInteger(v) && (v as number) >= 0;
const id = (v: unknown): v is number => uint(v) && v > 0;
const text = (v: unknown): v is string => typeof v === "string";
const hex = (v: unknown) => text(v) && /^[a-fA-F0-9]{64}$/.test(v);
const map = (v: unknown, check: (v: unknown) => boolean) =>
  object(v) &&
  Object.entries(v).every(
    ([k, value]) => /^[1-9]\d*$/.test(k) && id(Number(k)) && check(value),
  );
const log = (v: unknown): boolean =>
  v === null ||
  (object(v) &&
    object(v.leader_id) &&
    uint(v.leader_id.term) &&
    uint(v.leader_id.node_id) &&
    uint(v.index));
const controllers = (v: unknown) =>
  Array.isArray(v) &&
  v.every(
    (c) =>
      object(c) &&
      text(c.peer_id) &&
      Array.isArray(c.addresses) &&
      c.addresses.every(text),
  );

interface GrantDraft {
  node_id: number;
  peer: string;
  control: string;
  hint: string;
}

// Derives a control-address suggestion from a replica's committed interior
// transport address plus its admission peer. The public discovery address is
// never derived: which IP:port is externally routable is an operator
// attestation, not committed state.
export function grantDraft(
  data: Replicas,
  node_id: number,
): GrantDraft | null {
  const peer = data.admitted[String(node_id)];
  if (!id(node_id) || !peer) return null;
  const recorded =
    data.pending.find((p) => p.node_id === node_id)?.address ??
    data.membership_observation.membership.nodes[String(node_id)]?.addr;
  if (!recorded) return null;
  // Inventory addresses may or may not already carry the /p2p/<peer> suffix;
  // the endpoint interior is everything before it.
  const suffix = `/p2p/${peer}`;
  const interior = recorded.endsWith(suffix)
    ? recorded.slice(0, -suffix.length)
    : recorded.endsWith("/p2p")
      ? recorded.slice(0, -"/p2p".length)
      : recorded;
  return {
    node_id,
    peer,
    control: `${interior}${suffix}`,
    hint: suffix,
  };
}

export function prepareGrant(
  data: Replicas,
  node_id: number,
  public_address: string,
  control_address: string,
): Pending {
  const peer = data.admitted[String(node_id)];
  if (
    !id(node_id) ||
    !peer ||
    data.revocations[String(node_id)] ||
    !data.membership_observation.membership.configs.some((c) =>
      c.includes(node_id),
    ) ||
    !data.roster
  )
    throw new Error(
      "Fetch a committed roster and select an admitted, non-revoked voter first.",
    );
  // ponytail: backend parses multiaddresses and checks public endpoints/catch-up; add a parser only with richer address editing.
  if (
    public_address === control_address ||
    ![public_address, control_address].every(
      (a) =>
        a.startsWith("/") &&
        a.endsWith(`/p2p/${peer}`) &&
        !/[\s\p{Cc}]/u.test(a),
    )
  )
    throw new Error(
      "Use distinct multiaddresses ending in /p2p/ plus the selected admission peer ID, without whitespace/control characters.",
    );
  const body = JSON.stringify({
    action: "grant_serving",
    node_id,
    expected_roster_revision: data.roster.revision,
    public_address,
    control_address,
    request_id: crypto.randomUUID(),
  });
  if (new TextEncoder().encode(body).length > 4096)
    throw new Error("Request exceeds the 4096-byte limit.");
  return Object.freeze({
    endpoint: "/admin/replicas/reconcile",
    body,
    label: `Serving grant for #${node_id}`,
    subject: "administrator:1",
  });
}

// The committed roster reports each serving replica's attested public
// discovery and private control multiaddresses. Controllers may be recorded
// as [public, control]; discovery_endpoints repeats the public address when
// published.
export function servingEndpoints(
  data: Replicas,
  node_id: number | string,
): { public: string; control: string } | null {
  const peer = data.admitted[String(node_id)];
  const roster = data.roster;
  if (!peer || !roster) return null;
  const controller = roster.controllers.find((c) => c.peer_id === peer);
  if (!controller) return null;
  const discovery =
    roster.discovery_endpoints?.find((c) => c.peer_id === peer)?.addresses[0] ??
    "";
  return {
    public: discovery || controller.addresses[0],
    control:
      controller.addresses.find((a) => a !== discovery) ??
      controller.addresses[0],
  };
}

export function replicasFrom(v: unknown): Replicas {  if (
    !object(v) ||
    !map(v.admitted, text) ||
    !Array.isArray(v.pending) ||
    !v.pending.every(
      (p) =>
        object(p) &&
        id(p.node_id) &&
        text(p.peer_id) &&
        text(p.address) &&
        uint(p.admitted_at_ms),
    ) ||
    !map(
      v.revocations,
      (r) => object(r) && text(r.peer) && typeof r.complete === "boolean",
    ) ||
    !text(v.observation)
  )
    throw new Error("Unrecognized replica inventory.");
  const r = v.roster,
    m = v.membership_observation;
  if (
    !(
      r === null ||
      (object(r) &&
        uint(r.version) &&
        text(r.cluster_id) &&
        uint(r.revision) &&
        uint(r.issued_at_ms) &&
        uint(r.expires_at_ms) &&
        controllers(r.controllers) &&
        (r.discovery_endpoints === undefined ||
          controllers(r.discovery_endpoints)))
    ) ||
    !object(m) ||
    !id(m.node_id) ||
    !(m.leader_id === null || id(m.leader_id)) ||
    !object(m.membership) ||
    !Array.isArray(m.membership.configs) ||
    !m.membership.configs.every((c) => Array.isArray(c) && c.every(id)) ||
    !map(m.membership.nodes, (n) => object(n) && text(n.addr)) ||
    !log(m.last_applied) ||
    !(m.replication === null || map(m.replication, log)) ||
    !text(m.scope)
  )
    throw new Error("Unrecognized replica inventory.");
  return v as unknown as Replicas;
}

// One-line command for the joining replica operator; the bundle itself stays
// server-side and the code is embedded in the printed command only.
export function joinCommand(bundle: JoinBundle, node_id: number): string {
  if (!id(node_id)) throw new Error("Use a safe positive node ID.");
  const node = bundle.node_id ?? node_id;
  return [
    "cat4igp-server join-replica",
    "--bundle <(cat <<'EOF'",
    JSON.stringify({ ...bundle, node_id: node }),
    "EOF",
    ")",
    "--address /ip4/<joiner-ip>/tcp/<port>/p2p/<joiner-peer-id>",
    `--node-id ${node}`,
  ].join(" ");
}

// Deliberately separate from durable management writes: one request, no key, no automated replay.
export async function desiredState(
  payload: ReplicaAction,
): Promise<EnrollmentCode | JoinBundle | null> {
  if (
    payload.action === "rotate_enrollment_code"
      ? !uint(payload.expected_generation)
      : payload.action === "join_bundle"
        ? !(
            text(payload.bootstrap) &&
            payload.bootstrap.startsWith("/") &&
            payload.bootstrap.includes("/p2p/") &&
            !/[\s\p{Cc}]/u.test(payload.bootstrap)
          )
        : payload.action !== "enrollment_code" && !id(payload.node_id)
  )
    throw new Error("Use a safe positive node ID or nonnegative generation.");
  let v: unknown;
  try {
    v = await request("/admin/replicas/reconcile", JSON.stringify(payload));
  } catch (e) {
    if (e instanceof RequestError && e.status === 409)
      throw new RequestError(
        "Replica workflow conflict: standalone is unsupported; code and writes require a statically trusted bootstrap gateway. Otherwise inspect admission, generation and membership prerequisites.",
        409,
        "rejected",
      );
    if (e instanceof RequestError && e.outcome === "unknown")
      throw new RequestError(
        "Outcome unknown. Inspect replica inventory and retrieve current code/generation before manually resuming the same desired state. No automatic retry was sent.",
        e.status,
        "unknown",
      );
    throw e;
  }
  if (object(v)) {
    if (
      payload.action === "enrollment_code" ||
      payload.action === "rotate_enrollment_code"
    ) {
      if (
        id(v.generation) &&
        hex(v.code) &&
        uint(v.activated_at_ms) &&
        uint(v.expires_at_ms) &&
        (v.previous === null ||
          (Array.isArray(v.previous) &&
            v.previous.length === 2 &&
            hex(v.previous[0]) &&
            uint(v.previous[1])))
      )
        return v as EnrollmentCode;
    } else if (payload.action === "join_bundle") {
      if (
        uint(v.application_version) &&
        text(v.cluster_id) &&
        hex(v.signing_key) &&
        text(v.bootstrap) &&
        uint(v.minimum_revision) &&
        hex(v.code) &&
        (v.node_id === undefined || id(v.node_id))
      )
        return v as JoinBundle;
    } else if (
      v.reconciled === true &&
      v.semantics === "desired_state; no request receipt"
    )
      return null;
  }
  throw new RequestError(
    "Unrecognized confirmation; outcome unknown. Inspect inventory/code before manually resuming the same desired state.",
    200,
    "unknown",
  );
}
