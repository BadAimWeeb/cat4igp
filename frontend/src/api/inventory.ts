type Features = { wireguard: boolean; l2tp_v2: boolean; l2tp_v3: boolean; faketcp: boolean; fec: boolean };
type Node = {
  id: number;
  name: string;
  created_at: string;
  last_seen: string | null;
  features?: Features | null;
};
type Mesh = { id: number; name: string; auto_wireguard: boolean; mtu: number; fec: boolean; faketcp?: boolean };
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
type L2tpTunnel = {
  id: number; construction: "static"; node_id_peer1: number; node_id_peer2: number;
  endpoint_peer1: string; endpoint_peer2: string; udp_port_peer1: number; udp_port_peer2: number;
  session_id_peer1: number; session_id_peer2: number; cookie_peer1: string; cookie_peer2: string;
  security_mode: "pure" | "wireguard"; wireguard_tunnel_id: number | null; mtu: number;
};
type L2tpV2Tunnel = {
  id: number; node_id_peer1: number; node_id_peer2: number;
  endpoint_peer1: string; endpoint_peer2: string; udp_port_peer1: number; udp_port_peer2: number;
  address_peer1: string; address_peer2: string; mtu: number; wireguard_tunnel_id?: number | null;
};
export type Inventory = {
  server_features?: Features;
  nodes: Node[];
  meshes: Mesh[];
  memberships: Membership[];
  invites: Invite[];
  tunnels: Tunnel[];
  l2tp_tunnels: L2tpTunnel[];
  l2tp_v2_tunnels: L2tpV2Tunnel[];
};
export const integer = (x: unknown): x is number =>
  typeof x === "number" && Number.isSafeInteger(x);
const text = (x: unknown): x is string => typeof x === "string";
const nullableText = (x: unknown) => x === null || text(x);
const nullableInteger = (x: unknown) => x === null || integer(x);
const features = (x: unknown): x is Features => !!x && typeof x === "object" &&
  ["wireguard", "l2tp_v2", "l2tp_v3", "faketcp", "fec"].every((k) => typeof (x as Record<string, unknown>)[k] === "boolean");
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
  if (data.server_features !== undefined && !features(data.server_features)) throw new Error("Invalid server feature flags.");
  if (
    !rows(
      data.nodes,
      (r) =>
        integer(r.id) &&
        text(r.name) &&
        text(r.created_at) &&
        nullableText(r.last_seen) && (r.features === undefined || r.features === null || features(r.features)),
    ) ||
    !rows(
      data.meshes,
      (r) =>
        integer(r.id) &&
        text(r.name) &&
        typeof r.auto_wireguard === "boolean" &&
        typeof r.fec === "boolean" &&
        (r.faketcp === undefined || typeof r.faketcp === "boolean") &&
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
    ) ||
    !rows(data.l2tp_tunnels, (r) =>
      integer(r.id) && r.construction === "static" &&
      integer(r.node_id_peer1) && integer(r.node_id_peer2) &&
      text(r.endpoint_peer1) && text(r.endpoint_peer2) &&
      integer(r.udp_port_peer1) && integer(r.udp_port_peer2) &&
      integer(r.session_id_peer1) && integer(r.session_id_peer2) &&
      text(r.cookie_peer1) && text(r.cookie_peer2) &&
      (r.security_mode === "pure" || r.security_mode === "wireguard") &&
      nullableInteger(r.wireguard_tunnel_id) && integer(r.mtu),
    ) ||
    !rows(data.l2tp_v2_tunnels, (r) =>
      integer(r.id) && integer(r.node_id_peer1) && integer(r.node_id_peer2) &&
      text(r.endpoint_peer1) && text(r.endpoint_peer2) &&
      integer(r.udp_port_peer1) && integer(r.udp_port_peer2) &&
      text(r.address_peer1) && text(r.address_peer2) && integer(r.mtu) &&
      (r.wireguard_tunnel_id === undefined || nullableInteger(r.wireguard_tunnel_id)),
    )
  )
    throw new Error("Invalid inventory response.");
  return value as Inventory;
}
