// ponytail: no installed Node typings; native server imports are runtime-tested.
// Remove these import suppressions when Node typings are otherwise needed.
// @ts-ignore -- native Node API, also supported by Bun
import { randomBytes } from "node:crypto";
// @ts-ignore -- native Node API, also supported by Bun
import type { IncomingMessage, ServerResponse } from "node:http";
// @ts-ignore -- native Node API, also supported by Bun
import { Buffer } from "node:buffer";
import type { Inventory } from "../src/api/inventory.ts";

const positive = (v: unknown): v is number =>
  Number.isSafeInteger(v) && (v as number) > 0;
const uint = (v: unknown): v is number =>
  Number.isSafeInteger(v) && (v as number) >= 0;
const name = (v: unknown): v is string =>
  typeof v === "string" &&
  !!v.trim() &&
  !/[\p{Cc}]/u.test(v) &&
  Buffer.byteLength(v) <= 256;
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
    meshes: [
      { id: 1, name: "Demo mesh", auto_wireguard: true, mtu: 1420, fec: false, faketcp: false },
    ],
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
        refresh_mode: "current",
        intents: [
          { kind: "mesh", mesh_id: 1 },
          { kind: "legacy", mesh_id: null },
          { kind: "manual", mesh_id: null },
        ],
      },
    ],
    l2tp_tunnels: [],
    l2tp_v2_tunnels: [],
  };
  const sessions = new Map<string, number>();
  const receipts = new Map<string, Receipt>();
  let meshId = 2,
    inviteId = 2, tunnelId = 2;
  const state = { inventory, sessions, receipts };
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
      case "create_l2tp_v2_tunnel": {
        fields(b, ["action", "node_id_peer1", "node_id_peer2", "endpoint_peer1", "endpoint_peer2", "udp_port_peer1", "udp_port_peer2", "address_peer1", "address_peer2", "secret", "mtu", ...(Object.hasOwn(b, "wireguard_tunnel_id") ? ["wireguard_tunnel_id"] : [])]);
        node(b.node_id_peer1); node(b.node_id_peer2);
        requireValue(b.node_id_peer1 !== b.node_id_peer2);
        for (const key of ["endpoint_peer1", "endpoint_peer2", "address_peer1", "address_peer2"]) requireValue(typeof b[key] === "string" && (b[key] as string).length > 0);
        for (const key of ["udp_port_peer1", "udp_port_peer2"]) requireValue(positive(b[key]) && (b[key] as number) <= 65535);
        requireValue(typeof b.secret === "string" && /^[0-9a-f]{32,128}$/.test(b.secret));
        const wireguard = b.wireguard_tunnel_id ?? null;
        if (wireguard !== null) requireValue(positive(wireguard) && inventory.tunnels.some(t => t.id === wireguard && ((t.node_id_peer1 === b.node_id_peer1 && t.node_id_peer2 === b.node_id_peer2) || (t.node_id_peer1 === b.node_id_peer2 && t.node_id_peer2 === b.node_id_peer1))));
        requireValue(uint(b.mtu) && b.mtu >= 1280 && b.mtu <= (wireguard === null ? 1500 : 65000));
        const { action: _, secret: _secret, ...values } = b;
        inventory.l2tp_v2_tunnels.push({ ...values, wireguard_tunnel_id: wireguard, id: tunnelId++ } as Inventory["l2tp_v2_tunnels"][number]);
        return { committed: true };
      }
      case "delete_l2tp_v2_tunnel": {
        fields(b, ["action", "id"]);
        requireValue(inventory.l2tp_v2_tunnels.some(t => t.id === b.id), 404, "L2TPv2 tunnel not found");
        inventory.l2tp_v2_tunnels = inventory.l2tp_v2_tunnels.filter(t => t.id !== b.id);
        return { committed: true };
      }
      case "create_l2tp_tunnel": {
        fields(b, ["action", "node_id_peer1", "node_id_peer2", "endpoint_peer1", "endpoint_peer2", "udp_port_peer1", "udp_port_peer2", "session_id_peer1", "session_id_peer2", "cookie_peer1", "cookie_peer2", "security_mode", "wireguard_tunnel_id", "mtu"]);
        node(b.node_id_peer1); node(b.node_id_peer2);
        requireValue(b.node_id_peer1 !== b.node_id_peer2);
        for (const key of ["endpoint_peer1", "endpoint_peer2"]) requireValue(typeof b[key] === "string" && (b[key] as string).length > 0 && (b[key] as string).length <= 45);
        for (const key of ["udp_port_peer1", "udp_port_peer2"]) requireValue(positive(b[key]) && (b[key] as number) <= 65535);
        for (const key of ["session_id_peer1", "session_id_peer2"]) requireValue(positive(b[key]) && (b[key] as number) <= 4294967295);
        for (const key of ["cookie_peer1", "cookie_peer2"]) requireValue(typeof b[key] === "string" && /^[0-9a-f]{16}$/.test(b[key] as string));
        requireValue(uint(b.mtu) && (b.mtu as number) >= 576 && (b.mtu as number) <= 65477);
        requireValue((b.security_mode === "pure" && b.wireguard_tunnel_id === null) || (b.security_mode === "wireguard" && inventory.tunnels.some(t => t.id === b.wireguard_tunnel_id && ((t.node_id_peer1 === b.node_id_peer1 && t.node_id_peer2 === b.node_id_peer2) || (t.node_id_peer1 === b.node_id_peer2 && t.node_id_peer2 === b.node_id_peer1)))));
        const { action: _, ...values } = b;
        inventory.l2tp_tunnels.push({ ...values, id: tunnelId++, construction: "static" } as Inventory["l2tp_tunnels"][number]);
        return { committed: true };
      }
      case "delete_l2tp_tunnel": {
        fields(b, ["action", "id"]);
        requireValue(inventory.l2tp_tunnels.some(t => t.id === b.id), 404, "L2TP tunnel not found");
        inventory.l2tp_tunnels = inventory.l2tp_tunnels.filter(t => t.id !== b.id);
        return { committed: true };
      }
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
        if (!Object.hasOwn(b, "faketcp")) b.faketcp = false;
        fields(b, ["action", "name", "auto_wireguard", "mtu", "fec", "faketcp"]);
        requireValue(
          name(b.name) &&
            typeof b.auto_wireguard === "boolean" &&
            typeof b.fec === "boolean" &&
            typeof b.faketcp === "boolean" &&
            (b.auto_wireguard || (!b.fec && !b.faketcp)) &&
            uint(b.mtu) &&
            ((b.mtu >= 1280 && b.mtu <= 9000) ||
              (!b.auto_wireguard && b.mtu === 0)),
        );
        const id = meshId++;
        inventory.meshes.push({
          id,
          name: b.name as string,
          auto_wireguard: b.auto_wireguard as boolean,
          mtu: b.auto_wireguard ? (b.mtu as number) : 0,
          fec: b.fec as boolean,
          faketcp: b.faketcp as boolean,
        });
        return { committed: true, mesh_id: id };
      }
      case "set_mesh_mtu": {
        fields(b, ["action", "id", "mtu"]);
        const m = mesh(b.id);
        requireValue(
          m.auto_wireguard && uint(b.mtu) && b.mtu >= 1280 && b.mtu <= 9000,
        );
        m.mtu = b.mtu as number;
        for (const t of inventory.tunnels)
          if (
            t.mtu !== m.mtu &&
            t.intents.some((i) => i.kind === "mesh" && i.mesh_id === m.id)
          ) {
            t.mtu = m.mtu;
            affected.add(t.node_id_peer1);
            affected.add(t.node_id_peer2);
          }
        break;
      }
      case "set_mesh_fec": {
        fields(b, ["action", "id", "fec"]);
        const m = mesh(b.id);
        requireValue(
          typeof b.fec === "boolean" && (m.auto_wireguard || !b.fec),
        );
        m.fec = b.fec as boolean;
        for (const t of inventory.tunnels)
          if (t.intents.some((i) => i.kind === "mesh" && i.mesh_id === m.id)) {
            affected.add(t.node_id_peer1);
            affected.add(t.node_id_peer2);
          }
        break;
      }
      case "set_mesh_faketcp": {
        fields(b, ["action", "id", "faketcp"]);
        const m = mesh(b.id);
        requireValue(typeof b.faketcp === "boolean" && (m.auto_wireguard || !b.faketcp));
        if (b.faketcp) requireValue(!inventory.tunnels.some(t => t.refresh_mode === "proxy" && t.intents.some(i => i.kind === "mesh" && i.mesh_id === m.id)), 409, "userspace UDP proxy cannot refresh FakeTCP transport");
        m.faketcp = b.faketcp as boolean;
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
        inventory.l2tp_v2_tunnels = inventory.l2tp_v2_tunnels.filter(t => t.node_id_peer1 !== b.id && t.node_id_peer2 !== b.id);
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
      case "set_tunnel_refresh_mode": {
        fields(b, ["action", "tunnel_id", "mode"]);
        requireValue(typeof b.mode === "string" && ["current", "proxy", "dual_link"].includes(b.mode), 400, "Invalid refresh mode");
        requireValue(Number.isInteger(b.tunnel_id) && (b.tunnel_id as number) >= -2147483648 && (b.tunnel_id as number) <= 2147483647, 400, "Invalid tunnel ID");
        const t = inventory.tunnels.find(t => t.id === b.tunnel_id);
        requireValue(t, 404, "Tunnel not found");
        if (b.mode === "proxy") requireValue(!t!.intents.some(i => i.kind === "mesh" && inventory.meshes.some(m => m.id === i.mesh_id && m.faketcp)), 409, "userspace UDP proxy cannot refresh FakeTCP transport");
        if ((t!.refresh_mode ?? "current") !== b.mode) {
          t!.refresh_mode = b.mode as "current" | "proxy" | "dual_link";
          affected.add(t!.node_id_peer1);
          affected.add(t!.node_id_peer2);
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

  async function handle(req: IncomingMessage, res: ServerResponse) {
    const send = (
      status: number,
      body: Record<string, unknown> | Inventory,
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
        "/admin/actions": "POST",
        "/admin/invites": "POST",
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
          path === "/admin/me" ? { subject: "administrator:1" } : inventory,
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
      const key = req.headers["idempotency-key"];
      requireValue(
        typeof key === "string" && /^[\x21-\x7e]{1,100}$/.test(key),
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
        reply = { status: 200, body: mutate(path, b) };
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
