// ponytail: no installed Node typings; native server imports are runtime-tested.
// Remove these import suppressions when Node typings are otherwise needed.
// @ts-ignore -- native Node API, also supported by Bun
import { randomBytes } from "node:crypto";
// @ts-ignore -- native Node API, also supported by Bun
import type { IncomingMessage, ServerResponse } from "node:http";
// @ts-ignore -- native Node API, also supported by Bun
import { Buffer } from "node:buffer";
import type { Inventory } from "../src/api/inventory.ts";
import type { Replicas, EnrollmentCode } from "../src/api/replicas.ts";

const positive = (v: unknown): v is number =>
  Number.isSafeInteger(v) && (v as number) > 0;
const uint = (v: unknown): v is number =>
  Number.isSafeInteger(v) && (v as number) >= 0;
const name = (v: unknown): v is string =>
  typeof v === "string" &&
  !!v.trim() &&
  !/[\p{Cc}]/u.test(v) &&
  Buffer.byteLength(v) <= 256;
const peer = (id: number) => `demo-peer-${id}`;
const uuid = (v: unknown): v is string =>
  typeof v === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
const stamp = () => new Date().toISOString();
type Reply = { status: number; body: Record<string, unknown> };
type Receipt = Reply & {
  fingerprint: string;
  mesh?: number | null;
  invite?: number;
};
class Rejection extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}
const requireValue = (
  ok: unknown,
  status = 409,
  message = "Mock prerequisite conflict",
) => {
  if (!ok) throw new Rejection(status, message);
};
function fields(body: Record<string, unknown>, keys: string[]) {
  requireValue(
    Object.keys(body).length === keys.length &&
      keys.every((k) => Object.hasOwn(body, k)),
    400,
    "Invalid fields",
  );
}

export function createMockApi() {
  const now = Date.now();
  const inventory: Inventory = {
    nodes: [1, 2, 3].map((id) => ({
      id,
      name: ["edge-london", "edge-tokyo", "lab-offline"][id - 1],
      created_at: stamp(),
      last_seen: id === 3 ? null : stamp(),
    })),
    meshes: [{ id: 1, name: "Demo mesh", auto_wireguard: true, mtu: 1420, fec: false }],
    memberships: [
      { mesh_id: 1, node_id: 1 },
      { mesh_id: 1, node_id: 2 },
    ],
    invites: [
      {
        id: 1,
        created_at: stamp(),
        expires_at: null,
        used_count: 0,
        max_uses: 5,
        mesh_id: 1,
      },
    ],
    tunnels: [
      {
        id: 1,
        node_id_peer1: 1,
        node_id_peer2: 2,
        ipv6: false,
        mtu: 1420,
        intents: [
          { kind: "mesh", mesh_id: 1 },
          { kind: "legacy", mesh_id: null },
          { kind: "manual", mesh_id: null },
        ],
      },
    ],
  };
  const replicas: Replicas = {
    admitted: { "1": peer(1), "2": peer(2), "3": peer(3) },
    pending: [
      {
        node_id: 3,
        peer_id: peer(3),
        address: "/ip4/127.0.0.1/tcp/9003",
        admitted_at_ms: now,
      },
    ],
    roster: {
      version: 1,
      cluster_id: "demo-only",
      revision: 1,
      issued_at_ms: now,
      expires_at_ms: now + 900000,
      controllers: [
        {
          peer_id: peer(1),
          addresses: [`/ip4/127.0.0.1/tcp/9001/p2p/${peer(1)}`],
        },
      ],
      discovery_endpoints: [],
    },
    revocations: {},
    observation:
      "DEV MOCK: desired metadata only; not live convergence or reachability",
    membership_observation: {
      node_id: 1,
      leader_id: 1,
      membership: {
        configs: [[1]],
        nodes: {
          "1": { addr: "/ip4/127.0.0.1/tcp/9001" },
          "2": { addr: "/ip4/127.0.0.1/tcp/9002" },
        },
      },
      last_applied: null,
      replication: null,
      scope: "DEV MOCK: static observations, no Raft or live replication",
    },
  };
  const sessions = new Map<string, number>();
  const receipts = new Map<string, Receipt>();
  const bindings = new Map<number, [string, string]>();
  let meshId = 2,
    inviteId = 2;
  let code: EnrollmentCode = {
    generation: 1,
    code: "d".repeat(64),
    activated_at_ms: now,
    expires_at_ms: now + 900000,
    previous: null,
  };
  const signingKey = "e".repeat(64);
  const state = { inventory, replicas, sessions, receipts };
  const node = (id: unknown) => {
    requireValue(positive(id));
    const n = inventory.nodes.find((n) => n.id === id);
    requireValue(n, 404, "Node not found");
    return n!;
  };
  const mesh = (id: unknown) => {
    requireValue(positive(id));
    const m = inventory.meshes.find((m) => m.id === id);
    requireValue(m, 404, "Mesh not found");
    return m!;
  };
  const prune = () => {
    inventory.tunnels = inventory.tunnels.filter((t) => t.intents.length);
  };

  function mutate(
    path: string,
    b: Record<string, unknown>,
  ): Record<string, unknown> {
    if (path === "/admin/invites") {
      fields(b, ["expires_at", "max_uses", "join_mesh"]);
      requireValue(
        b.expires_at === null ||
          (positive(b.expires_at) && b.expires_at > Date.now()),
      );
      requireValue(b.max_uses === null || positive(b.max_uses));
      if (b.join_mesh !== null) mesh(b.join_mesh);
      inventory.invites.push({
        id: inviteId++,
        created_at: stamp(),
        expires_at:
          b.expires_at === null
            ? null
            : new Date(b.expires_at as number).toISOString(),
        max_uses: b.max_uses as number | null,
        mesh_id: b.join_mesh as number | null,
        used_count: 0,
      });
      return {
        success: true,
        invite_code: `demo-invite-${randomBytes(8).toString("hex")}`,
      };
    }
    const affected = new Set<number>();
    switch (b.action) {
      case "rename_node": {
        fields(b, ["action", "id", "name"]);
        const n = node(b.id);
        requireValue(name(b.name));
        n.name = b.name as string;
        return { committed: true };
      }
      case "rename_mesh": {
        fields(b, ["action", "id", "name"]);
        const m = mesh(b.id);
        requireValue(name(b.name));
        m.name = b.name as string;
        return { committed: true };
      }
      case "invalidate_invite": {
        fields(b, ["action", "id"]);
        requireValue(positive(b.id));
        requireValue(
          inventory.invites.some((i) => i.id === b.id),
          404,
          "Invite not found",
        );
        inventory.invites = inventory.invites.filter((i) => i.id !== b.id);
        for (const r of receipts.values())
          if (r.invite === b.id) {
            r.status = 409;
            r.body = {
              success: false,
              message: "invite invalidated by administrator",
            };
          }
        return { committed: true };
      }
      case "create_mesh": {
        if (!Object.hasOwn(b, "fec")) b.fec = false;
        fields(b, ["action", "name", "auto_wireguard", "mtu", "fec"]);
        requireValue(
          name(b.name) &&
            typeof b.auto_wireguard === "boolean" &&
            typeof b.fec === "boolean" && (b.auto_wireguard || !b.fec) &&
            uint(b.mtu) &&
            ((b.mtu >= 1280 && b.mtu <= 9000) || (!b.auto_wireguard && b.mtu === 0)),
        );
        const id = meshId++;
        inventory.meshes.push({
          id,
          name: b.name as string,
          auto_wireguard: b.auto_wireguard as boolean,
          mtu: b.auto_wireguard ? b.mtu as number : 0,
          fec: b.fec as boolean,
        });
        return { committed: true, mesh_id: id };
      }
      case "set_mesh_mtu": {
        fields(b, ["action", "id", "mtu"]);
        const m = mesh(b.id);
        requireValue(m.auto_wireguard && uint(b.mtu) && b.mtu >= 1280 && b.mtu <= 9000);
        m.mtu = b.mtu as number;
        for (const t of inventory.tunnels)
          if (t.mtu !== m.mtu && t.intents.some((i) => i.kind === "mesh" && i.mesh_id === m.id)) {
            t.mtu = m.mtu;
            affected.add(t.node_id_peer1);
            affected.add(t.node_id_peer2);
          }
        break;
      }
      case "set_mesh_fec": {
        fields(b, ["action", "id", "fec"]);
        const m = mesh(b.id);
        requireValue(typeof b.fec === "boolean" && (m.auto_wireguard || !b.fec));
        m.fec = b.fec as boolean;
        for (const t of inventory.tunnels)
          if (t.intents.some((i) => i.kind === "mesh" && i.mesh_id === m.id)) {
            affected.add(t.node_id_peer1);
            affected.add(t.node_id_peer2);
          }
        break;
      }
      case "add_membership":
      case "remove_membership": {
        fields(b, ["action", "mesh_id", "node_id"]);
        mesh(b.mesh_id);
        node(b.node_id);
        const exists = inventory.memberships.some(
          (m) => m.mesh_id === b.mesh_id && m.node_id === b.node_id,
        );
        if (b.action === "add_membership" && !exists) {
          inventory.memberships.push({
            mesh_id: b.mesh_id as number,
            node_id: b.node_id as number,
          });
          affected.add(b.node_id as number);
        }
        if (b.action === "remove_membership" && exists) {
          inventory.memberships = inventory.memberships.filter(
            (m) => m.mesh_id !== b.mesh_id || m.node_id !== b.node_id,
          );
          affected.add(b.node_id as number);
          for (const t of inventory.tunnels)
            if (
              [t.node_id_peer1, t.node_id_peer2].includes(b.node_id as number)
            ) {
              t.intents = t.intents.filter(
                (i) => i.kind !== "mesh" || i.mesh_id !== b.mesh_id,
              );
            }
        }
        // ponytail: membership metadata/removal only, no simulated auto-tunnel creation; use the real backend for topology convergence.
        break;
      }
      case "delete_node": {
        fields(b, ["action", "id"]);
        node(b.id);
        affected.add(b.id as number);
        inventory.nodes = inventory.nodes.filter((n) => n.id !== b.id);
        inventory.memberships = inventory.memberships.filter(
          (m) => m.node_id !== b.id,
        );
        inventory.tunnels = inventory.tunnels.filter((t) => {
          const remove = t.node_id_peer1 === b.id || t.node_id_peer2 === b.id;
          if (remove) {
            affected.add(t.node_id_peer1);
            affected.add(t.node_id_peer2);
          }
          return !remove;
        });
        break;
      }
      case "delete_mesh": {
        fields(b, ["action", "id"]);
        mesh(b.id);
        for (const m of inventory.memberships)
          if (m.mesh_id === b.id) affected.add(m.node_id);
        inventory.meshes = inventory.meshes.filter((m) => m.id !== b.id);
        inventory.memberships = inventory.memberships.filter(
          (m) => m.mesh_id !== b.id,
        );
        inventory.invites = inventory.invites.filter((i) => i.mesh_id !== b.id);
        for (const t of inventory.tunnels)
          t.intents = t.intents.filter(
            (i) => i.kind !== "mesh" || i.mesh_id !== b.id,
          );
        for (const r of receipts.values())
          if (r.mesh === b.id) {
            r.status = 409;
            r.body = {
              success: false,
              message: "Mock invite invalidated by mesh deletion",
            };
          }
        break;
      }
      case "remove_tunnel_intent": {
        fields(b, ["action", "tunnel_id", "kind"]);
        requireValue(
          positive(b.tunnel_id) &&
            ["legacy", "manual"].includes(b.kind as string),
        );
        const t = inventory.tunnels.find((t) => t.id === b.tunnel_id);
        requireValue(t, 404, "Tunnel not found");
        if (t!.intents.some((i) => i.kind === b.kind)) {
          t!.intents = t!.intents.filter((i) => i.kind !== b.kind);
          affected.add(t!.node_id_peer1);
          affected.add(t!.node_id_peer2);
        }
        break;
      }
      default:
        throw new Rejection(400, "Unknown action");
    }
    prune();
    return {
      committed: true,
      convergence: "polling",
      affected_nodes: [...affected],
    };
  }

  function reconcile(b: Record<string, unknown>): Record<string, unknown> {
    if (b.action === "enrollment_code") {
      fields(b, ["action"]);
      return { ...code };
    }
    if (b.action === "join_bundle") {
      fields(b, ["action", "bootstrap"]);
      requireValue(
        typeof b.bootstrap === "string" &&
          b.bootstrap.startsWith("/") &&
          b.bootstrap.includes("/p2p/") &&
          !/[\s\p{Cc}]/u.test(b.bootstrap),
      );
      return {
        application_version: 4,
        cluster_id: "demo-cluster",
        signing_key: signingKey,
        bootstrap: b.bootstrap,
        minimum_revision: 1,
        code: code.code,
      };
    }
    if (b.action === "rotate_enrollment_code") {
      fields(b, ["action", "expected_generation"]);
      requireValue(uint(b.expected_generation));
      if (b.expected_generation === code.generation - 1) return { ...code };
      requireValue(b.expected_generation === code.generation);
      const now = Date.now();
      code = {
        generation: code.generation + 1,
        code: randomBytes(32).toString("hex"),
        activated_at_ms: now,
        expires_at_ms: now + 900000,
        previous: [code.code, now + 60000],
      };
      return { ...code };
    }
    const id = b.node_id;
    requireValue(positive(id));
    requireValue(replicas.admitted[String(id)], 404, "Replica not found");
    const membership = replicas.membership_observation.membership;
    if (b.action === "grant_serving") {
      fields(b, [
        "action",
        "node_id",
        "expected_roster_revision",
        "public_address",
        "control_address",
        "request_id",
      ]);
      requireValue(uuid(b.request_id), 400, "Invalid request ID");
      const roster = replicas.roster!;
      requireValue(
        uint(b.expected_roster_revision) &&
          b.expected_roster_revision === roster.revision &&
          !replicas.revocations[String(id)] &&
          membership.configs.every((c) => c.includes(id as number)),
      );
      const addresses = [b.public_address, b.control_address];
      requireValue(
        addresses.every(
          (a) =>
            typeof a === "string" &&
            a.startsWith("/") &&
            a.endsWith(`/p2p/${replicas.admitted[String(id)]}`) &&
            !/[\s\p{Cc}]/u.test(a),
        ) && addresses[0] !== addresses[1],
      );
      const binding = bindings.get(id as number);
      requireValue(!binding || binding.every((a, i) => a === addresses[i]));
      bindings.set(id as number, addresses as [string, string]);
      roster.revision++;
      roster.issued_at_ms = Date.now();
      roster.expires_at_ms = roster.issued_at_ms + 900000;
      roster.controllers = roster.controllers.filter(
        (c) => c.peer_id !== replicas.admitted[String(id)],
      );
      roster.controllers.push({
        peer_id: replicas.admitted[String(id)],
        addresses: [b.control_address as string],
      });
      roster.discovery_endpoints = (roster.discovery_endpoints ?? []).filter(
        (c) => c.peer_id !== replicas.admitted[String(id)],
      );
      roster.discovery_endpoints.push({
        peer_id: replicas.admitted[String(id)],
        addresses: [b.public_address as string],
      });
      return {
        committed: true,
        semantics: "durable request receipt; not lease renewal",
        roster_revision: roster.revision,
        issued_at_ms: roster.issued_at_ms,
        expires_at_ms: roster.expires_at_ms,
      };
    }
    fields(b, ["action", "node_id"]);
    if (b.action === "revoke_replica") {
      requireValue(id !== 1);
      if (replicas.revocations[String(id)])
        return {
          reconciled: true,
          semantics: "desired_state; no request receipt",
        };
      replicas.revocations[String(id)] = {
        peer: replicas.admitted[String(id)],
        complete: false,
      };
      replicas.pending = replicas.pending.filter((p) => p.node_id !== id);
      membership.configs = membership.configs.map((c) =>
        c.filter((n) => n !== id),
      );
      delete membership.nodes[String(id)];
      const roster = replicas.roster!;
      roster.controllers = roster.controllers.filter(
        (c) => c.peer_id !== replicas.admitted[String(id)],
      );
      roster.discovery_endpoints = (roster.discovery_endpoints ?? []).filter(
        (c) => c.peer_id !== replicas.admitted[String(id)],
      );
      roster.revision++;
    } else {
      requireValue(!replicas.revocations[String(id)]);
      if (b.action === "activate_learner") {
        membership.nodes[String(id)] ??= {
          addr: `/ip4/127.0.0.1/tcp/${9000 + (id as number)}`,
        };
        replicas.pending = replicas.pending.filter((p) => p.node_id !== id);
      } else if (b.action === "promote_learner") {
        requireValue(membership.nodes[String(id)]);
        for (const c of membership.configs)
          if (!c.includes(id as number)) c.push(id as number);
      } else throw new Rejection(400, "Unknown replica action");
    }
    // ponytail: desired metadata only; no live Raft/catch-up, revocation completion or serving simulation. Use real backend integration checks for those.
    return { reconciled: true, semantics: "desired_state; no request receipt" };
  }

  async function handle(req: IncomingMessage, res: ServerResponse) {
    const send = (
      status: number,
      body: Record<string, unknown> | Inventory | Replicas,
    ) => {
      res.writeHead(status, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(JSON.stringify(body));
    };
    try {
      const path = (req.url ?? "").split("?")[0];
      const routes: Record<string, string> = {
        "/admin/login": "POST",
        "/admin/logout": "POST",
        "/admin/me": "GET",
        "/admin/inventory": "GET",
        "/admin/replicas": "GET",
        "/admin/actions": "POST",
        "/admin/invites": "POST",
        "/admin/replicas/reconcile": "POST",
      };
      requireValue(routes[path], 404, "Unknown mock endpoint");
      requireValue(req.method === routes[path], 405, "Method not allowed");
      const token = req.headers.cookie
        ?.split(";")
        .map((c: string) => c.trim())
        .find((c: string) => c.startsWith("cat4igp_mock_session="))
        ?.slice("cat4igp_mock_session=".length);
      for (const [t, expiry] of sessions)
        if (expiry <= Date.now()) sessions.delete(t);
      if (path !== "/admin/login")
        requireValue(token && sessions.has(token), 401, "Sign in required");
      if (req.method === "GET") {
        send(
          200,
          path === "/admin/me"
            ? { subject: "administrator:1" }
            : path === "/admin/inventory"
              ? inventory
              : replicas,
        );
        return;
      }
      requireValue(
        !req.headers.origin ||
          req.headers.origin === `http://${req.headers.host}` ||
          req.headers.origin === `https://${req.headers.host}`,
        403,
        "Origin rejected",
      );
      requireValue(
        req.headers["content-type"]?.split(";")[0] === "application/json",
        415,
        "JSON required",
      );
      let length = 0;
      const chunks: Uint8Array[] = [];
      for await (const chunk of req) {
        length += Buffer.byteLength(chunk);
        if (length > 4096) {
          send(413, { success: false, message: "Body exceeds 4096 bytes" });
          req.resume();
          return;
        }
        chunks.push(Buffer.from(chunk));
      }
      const raw = Buffer.concat(chunks).toString("utf8");
      let b: Record<string, unknown>;
      try {
        b = JSON.parse(raw);
      } catch {
        throw new Rejection(400, "Invalid JSON");
      }
      requireValue(
        b && typeof b === "object" && !Array.isArray(b),
        400,
        "JSON object required",
      );
      // ponytail: HTTP-only dev mock cookie deliberately lacks Secure; this is NOT production authentication. Real backend auth remains unchanged.
      const cookie = (value: string, age: number) =>
        res.setHeader(
          "Set-Cookie",
          `cat4igp_mock_session=${value}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=${age}`,
        );
      if (path === "/admin/login") {
        fields(b, ["username", "password"]);
        requireValue(
          b.username === "administrator" && b.password === "demo-password",
          401,
          "Invalid demo credentials",
        );
        if (token) sessions.delete(token);
        const next = randomBytes(32).toString("hex");
        sessions.set(next, Date.now() + 900000);
        cookie(next, 900);
        send(200, { success: true, subject: "administrator:1" });
        return;
      }
      if (path === "/admin/logout") {
        fields(b, []);
        sessions.delete(token!);
        cookie("", 0);
        send(200, { success: true });
        return;
      }
      const grant =
        path === "/admin/replicas/reconcile" && b.action === "grant_serving";
      const desired = path === "/admin/replicas/reconcile" && !grant;
      if (path === "/admin/replicas/reconcile")
        requireValue(
          !req.headers["idempotency-key"],
          400,
          "Replica requests do not use Idempotency-Key",
        );
      if (desired) {
        send(200, reconcile(b));
        return;
      }
      const key = grant ? b.request_id : req.headers["idempotency-key"];
      requireValue(
        grant
          ? uuid(key)
          : typeof key === "string" && /^[\x21-\x7e]{1,100}$/.test(key),
        400,
        "Invalid retry key",
      );
      const scope = `${path}:${key}`;
      const old = receipts.get(scope);
      if (old) {
        requireValue(old.fingerprint === raw, 409, "Retry payload conflict");
        send(old.status, old.body);
        return;
      }
      let reply: Reply;
      try {
        reply = { status: 200, body: grant ? reconcile(b) : mutate(path, b) };
      } catch (e) {
        if (!(e instanceof Rejection)) throw e;
        reply = {
          status: e.status,
          body: { success: false, message: e.message },
        };
      }
      receipts.set(scope, {
        ...reply,
        fingerprint: raw,
        ...(path === "/admin/invites" && reply.status === 200
          ? { mesh: b.join_mesh as number | null, invite: inviteId - 1 }
          : {}),
      });
      send(reply.status, reply.body);
    } catch (e) {
      if (!res.headersSent)
        send(e instanceof Rejection ? e.status : 500, {
          success: false,
          message: e instanceof Rejection ? e.message : "Mock request failed",
        });
      else res.destroy(e instanceof Error ? e : undefined);
      if (!(e instanceof Rejection))
        console.error(
          "Mock API internal/transport failure",
          e instanceof Error ? e.name : "unknown",
        );
    }
  }
  return { handle, state };
}
