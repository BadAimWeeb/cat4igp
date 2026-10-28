type Node = {
  id: number;
  name: string;
  created_at: string;
  last_seen: string | null;
};
type Mesh = { id: number; name: string; auto_wireguard: boolean; mtu: number; fec: boolean };
type Membership = { mesh_id: number; node_id: number };
type Invite = {
  id: number;
  created_at: string;
  expires_at: string | null;
  used_count: number;
  max_uses: number | null;
  mesh_id: number | null;
};
type Intent = { kind: "mesh" | "legacy" | "manual"; mesh_id: number | null };
type Tunnel = {
  id: number;
  node_id_peer1: number;
  node_id_peer2: number;
  endpoint_peer1?: string | null;
  endpoint_peer2?: string | null;
  ipv6: boolean;
  mtu: number;
  intents: Intent[];
};
export type Inventory = {
  nodes: Node[];
  meshes: Mesh[];
  memberships: Membership[];
  invites: Invite[];
  tunnels: Tunnel[];
};
export const integer = (x: unknown): x is number =>
  typeof x === "number" && Number.isSafeInteger(x);
const text = (x: unknown): x is string => typeof x === "string";
const nullableText = (x: unknown) => x === null || text(x);
const nullableInteger = (x: unknown) => x === null || integer(x);
const rows = (
  value: unknown,
  check: (row: Record<string, unknown>) => boolean,
) =>
  Array.isArray(value) &&
  value.every(
    (row) =>
      row && typeof row === "object" && !Array.isArray(row) && check(row),
  );

export function inventoryFrom(value: unknown): Inventory {
  if (!value || typeof value !== "object")
    throw new Error("Invalid inventory response.");
  const data = value as Record<string, unknown>;
  if (
    !rows(
      data.nodes,
      (r) =>
        integer(r.id) &&
        text(r.name) &&
        text(r.created_at) &&
        nullableText(r.last_seen),
    ) ||
    !rows(
      data.meshes,
      (r) =>
        integer(r.id) &&
        text(r.name) &&
        typeof r.auto_wireguard === "boolean" &&
        typeof r.fec === "boolean" &&
        integer(r.mtu),
    ) ||
    !rows(data.memberships, (r) => integer(r.mesh_id) && integer(r.node_id)) ||
    !rows(
      data.invites,
      (r) =>
        integer(r.id) &&
        text(r.created_at) &&
        nullableText(r.expires_at) &&
        integer(r.used_count) &&
        nullableInteger(r.max_uses) &&
        nullableInteger(r.mesh_id),
    ) ||
    !rows(
      data.tunnels,
      (r) =>
        integer(r.id) &&
        integer(r.node_id_peer1) &&
        integer(r.node_id_peer2) &&
        (r.endpoint_peer1 === undefined || nullableText(r.endpoint_peer1)) &&
        (r.endpoint_peer2 === undefined || nullableText(r.endpoint_peer2)) &&
        typeof r.ipv6 === "boolean" &&
        integer(r.mtu) &&
        rows(r.intents, (i) =>
          i.kind === "mesh"
            ? integer(i.mesh_id)
            : (i.kind === "legacy" || i.kind === "manual") &&
              i.mesh_id === null,
        ),
    )
  )
    throw new Error("Invalid inventory response.");
  return value as Inventory;
}
