import assert from "node:assert/strict";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { createMockApi } from "../dev/mock-api.ts";
import { inventoryFrom } from "../src/api/inventory.ts";
import { replicasFrom, prepareGrant } from "../src/api/replicas.ts";

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
  replicasFrom((await call("/admin/replicas")).data);
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
  assert.equal(inventoryFrom((await call("/admin/inventory")).data).meshes[0].fec, true);
  await action({ ...fecAction, fec: false }, fecKey, 409);
  await action({ ...fecAction, fec: "true" }, randomUUID(), 409);
  await action({ ...fecAction, id: first.mesh_id }, randomUUID(), 409);
  await action({ ...fecAction, extra: true }, randomUUID(), 400);
  const fecMesh = (await action({ ...create, name: "FEC", auto_wireguard: true, mtu: 1420, fec: true })).data;
  assert.equal(api.state.inventory.meshes.find((m) => m.id === fecMesh.mesh_id).fec, true);
  await action({ ...create, fec: true }, randomUUID(), 409);
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

  const endpoint = "/admin/replicas/reconcile";
  const oldCode = (await call(endpoint, { action: "enrollment_code" })).data;
  const rotation = {
    action: "rotate_enrollment_code",
    expected_generation: oldCode.generation,
  };
  const rotated = (await call(endpoint, rotation)).data;
  assert.equal(rotated.generation, oldCode.generation + 1);
  assert.deepEqual((await call(endpoint, rotation)).data, rotated);
  await call(
    endpoint,
    { ...rotation, expected_generation: 50 },
    undefined,
    409,
  );
  await call(endpoint, { action: "enrollment_code" }, randomUUID(), 400);
  // Join bundle: one desired-state request, validation of the bootstrap, and a
  // copyable command with the node ID embedded. The bundle mirrors the real
  // join::Bundle shape; the code is embedded in the command output only.
  const { desiredState, joinCommand } = await import("../src/api/replicas.ts");
  const bundleBootstrap = "/ip4/203.0.113.9/tcp/9000/p2p/demo-peer-1";
  const currentCode = (await call(endpoint, { action: "enrollment_code" })).data;
  const bundle = (await call(endpoint, { action: "join_bundle", bootstrap: bundleBootstrap })).data;
  assert.equal(bundle.cluster_id, "demo-cluster");
  assert.equal(bundle.minimum_revision, 1);
  assert.equal(bundle.code, currentCode.code);
  assert.equal(typeof bundle.signing_key, "string");
  await assert.rejects(
    desiredState({ action: "join_bundle", bootstrap: "no" }),
  );
  await assert.rejects(
    desiredState({
      action: "join_bundle",
      bootstrap: bundleBootstrap.slice(0, -1),
    }),
  );
  assert.match(joinCommand(bundle, 4), /--node-id 4/);
  assert.match(joinCommand(bundle, 4), new RegExp(bundle.code));
  await call(endpoint, { action: "join_bundle" }, undefined, 400);
  await call(
    endpoint,
    { action: "join_bundle", bootstrap: "not-a-multiaddr" },
    undefined,
    409,
  );
  await call(
    endpoint,
    { action: "join_bundle", bootstrap: "/ip4/203.0.113.9/tcp/9000" },
    undefined,
    409,
  );
  await call(
    endpoint,
    {
      action: "join_bundle",
      bootstrap: bundleBootstrap,
      extra: true,
    },
    undefined,
    400,
  );
  await call(endpoint, { action: "promote_learner", node_id: 3 }, undefined, 409);
  await call(endpoint, { action: "activate_learner", node_id: 3 });
  await call(endpoint, { action: "promote_learner", node_id: 3 });
  const replicas = replicasFrom((await call("/admin/replicas")).data);
  assert.ok(replicas.membership_observation.membership.configs[0].includes(3));
  const grant = prepareGrant(
    replicas,
    3,
    "/ip4/203.0.113.3/tcp/443/p2p/demo-peer-3",
    "/ip4/127.0.0.1/tcp/9003/p2p/demo-peer-3",
  );
  const receipt = (await call(endpoint, grant.body)).data;
  assert.equal(receipt.semantics, "durable request receipt; not lease renewal");
  assert.deepEqual((await call(endpoint, grant.body)).data, receipt);
  await call(
    endpoint,
    { ...JSON.parse(grant.body), public_address: "/different" },
    undefined,
    409,
  );
  await call(
    endpoint,
    { ...JSON.parse(grant.body), request_id: randomUUID() },
    undefined,
    409,
  );
  await call(endpoint, { action: "revoke_replica", node_id: 3 });
  const revokedRevision = api.state.replicas.roster.revision;
  await call(endpoint, { action: "revoke_replica", node_id: 3 });
  assert.equal(api.state.replicas.roster.revision, revokedRevision);
  const after = replicasFrom((await call("/admin/replicas")).data);
  assert.equal(after.revocations["3"].complete, false);
  assert.ok(!after.roster.controllers.some((c) => c.peer_id === "demo-peer-3"));
  assert.deepEqual((await call(endpoint, grant.body)).data, receipt);
  await call(
    endpoint,
    { action: "activate_learner", node_id: 3 },
    undefined,
    409,
  );

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
