import assert from "node:assert/strict";
import { prepare, send, request, RequestError } from "../src/api/request.ts";
import { inventoryFrom } from "../src/api/inventory.ts";

const calls = [];
const originalFetch = globalThis.fetch;
try {
  const action = prepare(
    "/admin/actions",
    { action: "rename_node", id: 7, name: "Edge" },
    "Rename node",
  );
  assert.ok(Object.isFrozen(action));
  assert.equal(action.subject, "administrator:1");
  assert.throws(() => {
    action.body = "{}";
  }, TypeError);
  const responses = [
    new Error("disconnected"),
    new Response("", { status: 503 }),
    new Response("", { status: 401 }),
    new Response("bad json"),
    Response.json({ committed: true }),
  ];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, ...options });
    const next = responses.shift();
    if (next instanceof Error) throw next;
    return next;
  };
  for (const outcome of ["unknown", "unknown", "auth", "unknown"]) {
    await assert.rejects(
      send(action),
      (e) => e instanceof RequestError && e.outcome === outcome,
    );
  }
  assert.deepEqual(await send(action), { committed: true });
  for (const call of calls) {
    assert.equal(call.url, action.endpoint);
    assert.equal(call.body, action.body);
    assert.equal(call.headers["Idempotency-Key"], action.key);
    assert.equal(call.credentials, "same-origin");
    assert.equal(call.headers["Content-Type"], "application/json");
  }
  assert.notEqual(prepare("/admin/actions", {}, "Other").key, action.key);
  assert.throws(() =>
    prepare("/admin/actions", { name: "é".repeat(4096) }, "Large"),
  );
  globalThis.fetch = async () => new Response("", { status: 409 });
  await assert.rejects(send(action), (e) => e.outcome === "rejected");
  const invite = prepare(
    "/admin/invites",
    { expires_at: null, max_uses: 1, join_mesh: null },
    "Create invite",
  );
  globalThis.fetch = async () =>
    Response.json({ success: true, invite_code: "test-code" });
  assert.equal((await send(invite)).invite_code, "test-code");
  globalThis.fetch = async () => Response.json({ success: true });
  await assert.rejects(send(invite), (e) => e.outcome === "unknown");
  globalThis.fetch = async () => new Response(null, { status: 204 });
  assert.equal(await request("/admin/logout", "{}"), null);
  const inventory = {
    nodes: [],
    meshes: [],
    memberships: [],
    invites: [],
    l2tp_tunnels: [],
    l2tp_v2_tunnels: [],
    tunnels: [
      {
        id: 1,
        node_id_peer1: 2,
        node_id_peer2: 3,
        ipv6: true,
        mtu: 1420,
        intents: [
          { kind: "mesh", mesh_id: 4 },
          { kind: "legacy", mesh_id: null },
          { kind: "manual", mesh_id: null },
        ],
      },
    ],
  };
  assert.equal(inventoryFrom(inventory), inventory);
  for (const field of ["endpoint_peer1", "endpoint_peer2"]) {
    for (const endpoint of [
      undefined,
      null,
      "",
      "192.0.2.1:51820",
      "[2001:db8::1]:51820",
    ]) {
      const value = {
        ...inventory,
        tunnels: [{ ...inventory.tunnels[0], [field]: endpoint }],
      };
      assert.equal(inventoryFrom(value).tunnels[0][field], endpoint);
    }
    for (const endpoint of [123, {}, []]) {
      assert.throws(() =>
        inventoryFrom({
          ...inventory,
          tunnels: [{ ...inventory.tunnels[0], [field]: endpoint }],
        }),
      );
    }
  }
  assert.throws(() => inventoryFrom({ ...inventory, tunnels: undefined }));
  for (const intent of [
    { kind: "mesh", mesh_id: null },
    { kind: "manual", mesh_id: 4 },
    { kind: "unknown", mesh_id: null },
  ]) {
    assert.throws(() =>
      inventoryFrom({
        ...inventory,
        tunnels: [{ ...inventory.tunnels[0], intents: [intent] }],
      }),
    );
  }
  for (const payload of [
    { action: "add_membership", mesh_id: 4, node_id: 2 },
    { action: "remove_membership", mesh_id: 4, node_id: 2 },
    { action: "delete_mesh", id: 4 },
    { action: "delete_node", id: 2 },
    { action: "remove_tunnel_intent", tunnel_id: 1, kind: "legacy" },
    { action: "remove_tunnel_intent", tunnel_id: 1, kind: "manual" },
  ]) {
    const pending = prepare("/admin/actions", payload, payload.action);
    const attempts = [];
    const results = [
      { committed: true },
      { committed: true, convergence: "immediate", affected_nodes: [] },
      { committed: true, convergence: "polling", affected_nodes: ["2"] },
      { committed: true, convergence: "polling", affected_nodes: [2, 3] },
    ];
    globalThis.fetch = async (url, options) => {
      attempts.push({ url, ...options });
      return Response.json(results.shift());
    };
    for (let i = 0; i < 3; i++)
      await assert.rejects(send(pending), (e) => e.outcome === "unknown");
    assert.deepEqual((await send(pending)).affected_nodes, [2, 3]);
    for (const attempt of attempts) {
      assert.equal(attempt.url, "/admin/actions");
      assert.equal(attempt.body, JSON.stringify(payload));
      assert.equal(attempt.headers["Idempotency-Key"], pending.key);
    }
    globalThis.fetch = async () =>
      Response.json({
        committed: true,
        convergence: "polling",
        affected_nodes: [],
      });
    assert.deepEqual((await send(pending)).affected_nodes, []);
  }
  console.log("request/retry and standalone inventory assertions passed");
} finally {
  globalThis.fetch = originalFetch;
}
