import assert from "node:assert/strict";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { createMockApi } from "../dev/mock-api.ts";
import { inventoryFrom } from "../src/api/inventory.ts";

const api = createMockApi();
const server = createServer(api.handle);
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;
let cookie = "";
async function call(path, body, key, expected = 200, session = cookie) {
  const response = await fetch(base + path, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      ...(session ? { Cookie: session } : {}),
      ...(body === undefined
        ? {}
        : { "Content-Type": "application/json", Origin: base }),
      ...(key ? { "Idempotency-Key": key } : {}),
    },
    body:
      body === undefined
        ? undefined
        : typeof body === "string"
          ? body
          : JSON.stringify(body),
  });
  assert.equal(response.status, expected, path);
  return { response, data: await response.json() };
}
const action = (body, key = randomUUID(), expected = 200) =>
  call("/admin/actions", body, key, expected);
try {
  await call("/admin/me", undefined, undefined, 401);
  await call(
    "/admin/login",
    { username: "administrator", password: "wrong" },
    undefined,
    401,
  );
  const login = await call("/admin/login", {
    username: "administrator",
    password: "demo-password",
  });
  assert.equal(login.data.subject, "administrator:1");
  const header = login.response.headers.get("set-cookie");
  assert.match(header, /HttpOnly/);
  assert.match(header, /SameSite=Strict/);
  assert.match(header, /Max-Age=900/);
  assert.doesNotMatch(header, /Secure|Domain=/);
  cookie = header.split(";")[0];
  await call("/admin/me");
  await call("/admin/me", undefined, undefined, 401, "");
  const inventory = inventoryFrom((await call("/admin/inventory")).data);
  assert.equal(inventory.nodes.length, 3);
  assert.doesNotMatch(JSON.stringify(inventory), /invite_code|demo-password/);
  assert.equal(inventory.tunnels[0].refresh_mode, "current");
  const refresh = { action: "set_tunnel_refresh_mode", tunnel_id: 1, mode: "proxy" };
  const refreshKey = randomUUID();
  const refreshResult = (await action(refresh, refreshKey)).data;
  assert.deepEqual(refreshResult.affected_nodes, [1, 2]);
  assert.deepEqual((await action(refresh, refreshKey)).data, refreshResult);
  assert.equal(inventoryFrom((await call("/admin/inventory")).data).tunnels[0].refresh_mode, "proxy");
  assert.deepEqual((await action(refresh)).data.affected_nodes, []);
  await action({ ...refresh, mode: "dual_link" }, refreshKey, 409);
  await action({ ...refresh, mode: "invalid" }, randomUUID(), 400);
  await action({ ...refresh, mode: null }, randomUUID(), 400);
  await action({ ...refresh, tunnel_id: 999 }, randomUUID(), 404);
  await action({ ...refresh, extra: true }, randomUUID(), 400);
  await action({ action: "set_mesh_faketcp", id: 1, faketcp: true }, randomUUID(), 409);
  await action({ ...refresh, mode: "dual_link" });
  assert.equal(inventoryFrom((await call("/admin/inventory")).data).tunnels[0].refresh_mode, "dual_link");
  await action({ ...refresh, mode: "current" });
  assert.equal(inventoryFrom((await call("/admin/inventory")).data).tunnels[0].refresh_mode, "current");
  const l2tp = { action: "create_l2tp_tunnel", node_id_peer1: 1, node_id_peer2: 2, endpoint_peer1: "192.0.2.1", endpoint_peer2: "192.0.2.2", udp_port_peer1: 1701, udp_port_peer2: 1701, session_id_peer1: 1, session_id_peer2: 2, cookie_peer1: "0123456789abcdef", cookie_peer2: "fedcba9876543210", security_mode: "pure", wireguard_tunnel_id: null, mtu: 1500 };
  await action(l2tp);
  await action({ ...l2tp, security_mode: "wireguard", wireguard_tunnel_id: 1 });
  let l2tpRows = inventoryFrom((await call("/admin/inventory")).data).l2tp_tunnels;
  assert.deepEqual(l2tpRows.map(t => t.security_mode), ["pure", "wireguard"]);
  await action({ action: "delete_l2tp_tunnel", id: l2tpRows[0].id });
  l2tpRows = inventoryFrom((await call("/admin/inventory")).data).l2tp_tunnels;
  assert.equal(l2tpRows.length, 1);
  await action({ ...l2tp, cookie_peer1: "invalid" }, randomUUID(), 409);
  await action({ ...l2tp, mtu: 65478 }, randomUUID(), 409);
  const v2 = { action: "create_l2tp_v2_tunnel", node_id_peer1: 1, node_id_peer2: 2, endpoint_peer1: "192.0.2.1", endpoint_peer2: "192.0.2.2", udp_port_peer1: 1701, udp_port_peer2: 1702, address_peer1: "10.0.0.1", address_peer2: "10.0.0.2", secret: "a".repeat(32), mtu: 1500 };
  await action(v2);
  await action({ ...v2, mtu: 1501 }, randomUUID(), 409);
  await action({ ...v2, wireguard_tunnel_id: 1, mtu: 65000 });
  await action({ ...v2, wireguard_tunnel_id: 1, mtu: 65001 }, randomUUID(), 409);
  await action({ ...v2, wireguard_tunnel_id: 999 }, randomUUID(), 409);
  await action({ ...v2, node_id_peer2: 3, wireguard_tunnel_id: 1 }, randomUUID(), 409);
  const v2Rows = inventoryFrom((await call("/admin/inventory")).data).l2tp_v2_tunnels;
  assert.deepEqual(v2Rows.map(t => t.wireguard_tunnel_id), [null, 1]);
  assert.deepEqual([inventory.tunnels[0].id, ...l2tpRows.map(t => t.id), ...v2Rows.map(t => t.id)], [1, 3, 4, 5]);
  assert.equal(v2Rows[1].mtu, 65000);
  assert.ok(v2Rows.every(t => !("secret" in t)));
  await action({ action: "delete_l2tp_v2_tunnel", id: v2Rows[0].id });
  await action({ action: "delete_l2tp_v2_tunnel", id: v2Rows[1].id });
  await call("/admin/replicas", undefined, undefined, 404);
  await call("/admin/no-such-route", undefined, undefined, 404);
  await call("/admin/actions", "{", randomUUID(), 400);
  await call("/admin/actions", " ".repeat(4097), randomUUID(), 413);
  await action(
    { action: "rename_node", id: 999, name: "missing" },
    randomUUID(),
    404,
  );
  await action({ action: "rename_node", id: 1, name: "\n" }, randomUUID(), 409);
  await action(
    { action: "rename_node", id: 1, name: "x", extra: true },
    randomUUID(),
    400,
  );
  const key = randomUUID(),
    create = {
      action: "create_mesh",
      name: "Test",
      auto_wireguard: false,
      mtu: 0,
    };
  const first = (await action(create, key)).data;
  assert.deepEqual((await action(create, key)).data, first);
  await action({ ...create, name: "changed" }, key, 409);
  assert.equal(api.state.inventory.meshes.length, 2);
  assert.equal(api.state.inventory.meshes.at(-1).fec, false);
  assert.equal(api.state.inventory.meshes.at(-1).faketcp, false);
  const mtuKey = randomUUID();
  const mtuAction = { action: "set_mesh_mtu", id: 1, mtu: 1380 };
  const mtuResult = (await action(mtuAction, mtuKey)).data;
  assert.deepEqual(mtuResult.affected_nodes, [1, 2]);
  assert.deepEqual((await action(mtuAction, mtuKey)).data, mtuResult);
  const mtuInventory = inventoryFrom((await call("/admin/inventory")).data);
  assert.equal(mtuInventory.meshes[0].mtu, 1380);
  assert.equal(mtuInventory.tunnels[0].mtu, 1380);
  assert.deepEqual((await action(mtuAction)).data.affected_nodes, []);
  await action({ ...mtuAction, mtu: 1400 }, mtuKey, 409);
  for (const mtu of [1279, 9001, 1380.5, "1380", null])
    await action({ ...mtuAction, mtu }, randomUUID(), 409);
  await action({ ...mtuAction, id: first.mesh_id }, randomUUID(), 409);
  await action({ ...mtuAction, id: 999 }, randomUUID(), 404);
  await action({ ...mtuAction, extra: true }, randomUUID(), 400);
  const fecKey = randomUUID();
  const fecAction = { action: "set_mesh_fec", id: 1, fec: true };
  const fecResult = (await action(fecAction, fecKey)).data;
  assert.deepEqual((await action(fecAction, fecKey)).data, fecResult);
  assert.equal(
    inventoryFrom((await call("/admin/inventory")).data).meshes[0].fec,
    true,
  );
  await action({ ...fecAction, fec: false }, fecKey, 409);
  await action({ ...fecAction, fec: "true" }, randomUUID(), 409);
  await action({ ...fecAction, id: first.mesh_id }, randomUUID(), 409);
  await action({ ...fecAction, extra: true }, randomUUID(), 400);
  const fecMesh = (
    await action({
      ...create,
      name: "FEC",
      auto_wireguard: true,
      mtu: 1420,
      fec: true,
    })
  ).data;
  assert.equal(
    api.state.inventory.meshes.find((m) => m.id === fecMesh.mesh_id).fec,
    true,
  );
  await action({ ...create, fec: true }, randomUUID(), 409);
  const fakeAction = { action: "set_mesh_faketcp", id: 1, faketcp: true };
  const fakeKey = randomUUID();
  const fakeResult = (await action(fakeAction, fakeKey)).data;
  assert.deepEqual((await action(fakeAction, fakeKey)).data, fakeResult);
  assert.equal(inventoryFrom((await call("/admin/inventory")).data).meshes[0].faketcp, true);
  await action({ ...refresh, mode: "proxy" }, randomUUID(), 409);
  assert.equal(inventoryFrom((await call("/admin/inventory")).data).tunnels[0].refresh_mode, "current");
  await action({ ...refresh, mode: "dual_link" });
  await action({ ...refresh, mode: "current" });
  await action({ ...fakeAction, faketcp: false }, fakeKey, 409);
  await action({ ...fakeAction, faketcp: "true" }, randomUUID(), 409);
  await action({ ...fakeAction, id: first.mesh_id }, randomUUID(), 409);
  await action({ ...create, faketcp: true }, randomUUID(), 409);
  await action({ ...fakeAction, faketcp: false });
  await action({ action: "delete_mesh", id: fecMesh.mesh_id });
  await action({ action: "rename_node", id: 1, name: "renamed" });
  assert.equal(api.state.inventory.nodes[0].name, "renamed");
  const renameMesh = {
    action: "rename_mesh",
    id: first.mesh_id,
    name: "after",
  };
  const renameKey = randomUUID();
  const beforeRename = structuredClone(api.state.inventory);
  await action(renameMesh, renameKey);
  await action(renameMesh, renameKey);
  beforeRename.meshes.find((m) => m.id === first.mesh_id).name = "after";
  assert.deepEqual(api.state.inventory, beforeRename);
  await action({ ...renameMesh, name: "conflict" }, renameKey, 409);
  for (const name of [" ", "\n", "é".repeat(129)])
    await action({ ...renameMesh, name }, randomUUID(), 409);
  await action({ ...renameMesh, id: 999 }, randomUUID(), 404);
  await action({ ...renameMesh, extra: true }, randomUUID(), 400);
  await action({
    action: "add_membership",
    mesh_id: first.mesh_id,
    node_id: 3,
  });
  await action({
    action: "remove_membership",
    mesh_id: first.mesh_id,
    node_id: 3,
  });
  assert.ok(
    !api.state.inventory.memberships.some((m) => m.mesh_id === first.mesh_id),
  );
  const inviteKey = randomUUID(),
    invite = { expires_at: null, max_uses: 2, join_mesh: first.mesh_id };
  const issued = (await call("/admin/invites", invite, inviteKey)).data;
  assert.match(issued.invite_code, /^demo-invite-/);
  assert.deepEqual(
    (await call("/admin/invites", invite, inviteKey)).data,
    issued,
  );
  const standaloneKey = randomUUID();
  const standalone = { ...invite, join_mesh: null };
  await call("/admin/invites", standalone, standaloneKey);
  const invalidatedId = api.state.inventory.invites.at(-1).id;
  const beforeInvalidate = structuredClone(api.state.inventory);
  const invalidate = { action: "invalidate_invite", id: invalidatedId };
  const invalidateKey = randomUUID();
  const invalidation = (await action(invalidate, invalidateKey)).data;
  assert.deepEqual(
    (await action(invalidate, invalidateKey)).data,
    invalidation,
  );
  beforeInvalidate.invites = beforeInvalidate.invites.filter(
    (i) => i.id !== invalidatedId,
  );
  assert.deepEqual(api.state.inventory, beforeInvalidate);
  const invalidated = await call(
    "/admin/invites",
    standalone,
    standaloneKey,
    409,
  );
  assert.equal(invalidated.data.message, "invite invalidated by administrator");
  assert.ok(!Object.hasOwn(invalidated.data, "invite_code"));
  await action(invalidate, randomUUID(), 404);
  await action({ ...invalidate, id: 0 }, randomUUID(), 409);
  await action({ ...invalidate, extra: true }, randomUUID(), 400);
  await action({ ...invalidate, id: 1 }, invalidateKey, 409);
  assert.deepEqual(
    (await call("/admin/invites", invite, inviteKey)).data,
    issued,
  );
  await action({ action: "delete_mesh", id: first.mesh_id });
  await call("/admin/invites", invite, inviteKey, 409);
  await action({
    action: "remove_tunnel_intent",
    tunnel_id: 1,
    kind: "manual",
  });
  await action({
    action: "remove_tunnel_intent",
    tunnel_id: 1,
    kind: "legacy",
  });
  assert.equal(api.state.inventory.tunnels[0].intents.length, 1);
  await action({ action: "remove_membership", mesh_id: 1, node_id: 2 });
  assert.equal(api.state.inventory.tunnels.length, 0);
  await action({ action: "delete_node", id: 3 });
  inventoryFrom((await call("/admin/inventory")).data);

  const other = await call(
    "/admin/login",
    { username: "administrator", password: "demo-password" },
    undefined,
    200,
    "",
  );
  const otherCookie = other.response.headers.get("set-cookie").split(";")[0];
  await call("/admin/logout", {});
  await call("/admin/me", undefined, undefined, 401);
  await call("/admin/me", undefined, undefined, 200, otherCookie);
  const otherToken = otherCookie.split("=")[1];
  api.state.sessions.set(otherToken, Date.now() - 1);
  await call("/admin/me", undefined, undefined, 401, otherCookie);
  console.log("Mock API checks passed");
} finally {
  await new Promise((resolve, reject) =>
    server.close((e) => (e ? reject(e) : resolve())),
  );
}
