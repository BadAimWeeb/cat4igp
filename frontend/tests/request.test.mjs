import assert from "node:assert/strict";
import { prepare, send, request, RequestError } from "../src/api/request.ts";
import { inventoryFrom } from "../src/api/inventory.ts";
import {
  desiredState,
  prepareGrant,
  replicasFrom,
} from "../src/api/replicas.ts";

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
    for (const endpoint of [undefined, null, "", "192.0.2.1:51820", "[2001:db8::1]:51820"]) {
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
  const replicaCalls = [];
  const enrollment = {
    generation: 3,
    code: "a".repeat(64),
    activated_at_ms: 1,
    expires_at_ms: 2,
    previous: ["b".repeat(64), 2],
  };
  for (const payload of [
    { action: "enrollment_code" },
    { action: "rotate_enrollment_code", expected_generation: 2 },
    ...["activate_learner", "promote_learner", "revoke_replica"].map(
      (action) => ({ action, node_id: 9 }),
    ),
  ]) {
    globalThis.fetch = async (url, options) => {
      replicaCalls.push({ url, ...options });
      return new Response("", { status: 503 });
    };
    const count = replicaCalls.length;
    await assert.rejects(
      desiredState(payload),
      (e) => e.outcome === "unknown" && /inspect/i.test(e.message),
    );
    assert.equal(replicaCalls.length, count + 1, "No automated retry");
    const call = replicaCalls.at(-1);
    assert.equal(call.url, "/admin/replicas/reconcile");
    assert.equal(call.body, JSON.stringify(payload));
    assert.equal(call.headers["Idempotency-Key"], undefined);
    assert.equal(call.cache, "no-store");
    assert.equal(call.credentials, "same-origin");
    globalThis.fetch = async () =>
      Response.json({ reconciled: true, semantics: "wrong" });
    await assert.rejects(desiredState(payload), (e) => e.outcome === "unknown");
    globalThis.fetch = async () =>
      Response.json(
        payload.action.includes("enrollment_code")
          ? enrollment
          : {
              reconciled: true,
              semantics: "desired_state; no request receipt",
            },
      );
    assert.deepEqual(
      await desiredState(payload),
      payload.action.includes("enrollment_code") ? enrollment : null,
    );
  }
  globalThis.fetch = async () => new Response("", { status: 409 });
  await assert.rejects(
    desiredState({ action: "enrollment_code" }),
    (e) => e.outcome === "rejected" && /bootstrap gateway/.test(e.message),
  );
  for (const invalid of [
    { ...enrollment, generation: "3" },
    { ...enrollment, code: "bad" },
    { ...enrollment, previous: ["bad", 1] },
    { ...enrollment, previous: ["b".repeat(64), "1"] },
  ]) {
    globalThis.fetch = async () => Response.json(invalid);
    await assert.rejects(
      desiredState({ action: "enrollment_code" }),
      (e) => e.outcome === "unknown",
    );
  }
  await assert.rejects(
    desiredState({ action: "activate_learner", node_id: 0 }),
  );
  await assert.rejects(
    desiredState({ action: "rotate_enrollment_code", expected_generation: -1 }),
  );
  const bundleResponse = {
    application_version: 6,
    cluster_id: "demo-cluster",
    signing_key: "e".repeat(64),
    bootstrap: "/ip4/203.0.113.9/tcp/9000/p2p/demo-peer-1",
    minimum_revision: 1,
    code: "a".repeat(64),
  };
  const bundlePayloads = [];
  globalThis.fetch = async (url, options) => {
    bundlePayloads.push({ url, ...options });
    return Response.json(bundleResponse);
  };
  assert.deepEqual(
    await desiredState({
      action: "join_bundle",
      bootstrap: bundleResponse.bootstrap,
    }),
    bundleResponse,
  );
  assert.equal(
    bundlePayloads.at(-1).url,
    "/admin/replicas/reconcile",
  );
  assert.equal(
    bundlePayloads.at(-1).body,
    JSON.stringify({
      action: "join_bundle",
      bootstrap: bundleResponse.bootstrap,
    }),
  );
  for (const invalid of [
    { ...bundleResponse, application_version: "4" },
    { ...bundleResponse, signing_key: "bad" },
    { ...bundleResponse, minimum_revision: -1 },
    { ...bundleResponse, node_id: 0 },
  ]) {
    globalThis.fetch = async () => Response.json(invalid);
    await assert.rejects(
      desiredState({
        action: "join_bundle",
        bootstrap: bundleResponse.bootstrap,
      }),
      (e) => e.outcome === "unknown",
    );
  }
  globalThis.fetch = originalFetch;
  await assert.rejects(desiredState({ action: "join_bundle", bootstrap: "" }));
  await assert.rejects(
    desiredState({ action: "join_bundle", bootstrap: "/ip4/1/tcp/1" }),
  );
  const replicas = {
    admitted: { 1: "peer" },
    pending: [],
    revocations: {},
    roster: null,
    observation: "not reachability",
    membership_observation: {
      node_id: 1,
      leader_id: 1,
      membership: {
        configs: [
          [1, 2],
          [1, 3],
        ],
        nodes: { 1: { addr: "/address" }, 4: { addr: "/learner" } },
      },
      last_applied: null,
      replication: null,
      scope: "leader local",
    },
  };
  assert.equal(replicasFrom(replicas), replicas);
  const grantInventory = {
    ...replicas,
    roster: {
      version: 1,
      cluster_id: "cluster",
      revision: 12,
      issued_at_ms: 1,
      expires_at_ms: 2,
      controllers: [],
    },
  };
  const publicAddress = "/ip4/203.0.113.9/tcp/9000/p2p/peer";
  const controlAddress = "/ip4/10.0.0.9/tcp/9001/p2p/peer";
  const grant = prepareGrant(grantInventory, 1, publicAddress, controlAddress);
  const frozenBody = grant.body;
  const grantPayload = JSON.parse(frozenBody);
  assert.ok(Object.isFrozen(grant));
  assert.throws(() => {
    grant.body = "{}";
  }, TypeError);
  assert.equal(grant.subject, "administrator:1");
  assert.equal(grant.key, undefined);
  assert.deepEqual(
    Object.keys(grantPayload).sort(),
    [
      "action",
      "node_id",
      "expected_roster_revision",
      "public_address",
      "control_address",
      "request_id",
    ].sort(),
  );
  assert.equal(grantPayload.action, "grant_serving");
  assert.equal(grantPayload.node_id, 1);
  assert.equal(grantPayload.expected_roster_revision, 12);
  assert.equal(grantPayload.public_address, publicAddress);
  assert.equal(grantPayload.control_address, controlAddress);
  assert.match(
    grantPayload.request_id,
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  );
  // Current inventory changes cannot alter a retry or turn historical success into renewal.
  grantInventory.roster.revision = 99;
  grantInventory.revocations = { 1: { peer: "peer", complete: true } };
  const historical = {
    committed: true,
    roster_revision: 13,
    issued_at_ms: 1,
    expires_at_ms: 2,
    semantics: "durable request receipt; not lease renewal",
  };
  const grantResponses = [
    new Error("timeout"),
    new Response("", { status: 503 }),
    new Response("", { status: 401 }),
    new Response("bad json"),
    Response.json({
      ...historical,
      semantics: "desired_state; no request receipt",
    }),
    Response.json(historical),
    Response.json(historical),
  ];
  const grantCalls = [];
  globalThis.fetch = async (url, options) => {
    grantCalls.push({ url, ...options });
    const next = grantResponses.shift();
    if (next instanceof Error) throw next;
    return next;
  };
  for (const outcome of ["unknown", "unknown", "auth", "unknown", "unknown"]) {
    const count = grantCalls.length;
    await assert.rejects(
      send(grant),
      (e) => e instanceof RequestError && e.outcome === outcome,
    );
    assert.equal(grantCalls.length, count + 1, "No automatic grant retry");
  }
  assert.deepEqual(await send(grant), historical);
  assert.deepEqual(await send(grant), historical);
  for (const call of grantCalls) {
    assert.equal(call.url, "/admin/replicas/reconcile");
    assert.equal(call.body, frozenBody);
    assert.equal(JSON.parse(call.body).request_id, grantPayload.request_id);
    assert.equal(call.headers["Idempotency-Key"], undefined);
    assert.equal(call.headers["Content-Type"], "application/json");
    assert.equal(call.credentials, "same-origin");
    assert.equal(call.cache, "no-store");
  }
  globalThis.fetch = async () => new Response("", { status: 409 });
  await assert.rejects(send(grant), (e) => e.outcome === "rejected");
  assert.equal(grant.body, frozenBody, "409 does not generate a new request");
  for (const invalid of [
    { ...historical, roster_revision: "13" },
    { ...historical, expires_at_ms: -1 },
    { ...historical, committed: false },
  ]) {
    globalThis.fetch = async () => Response.json(invalid);
    await assert.rejects(send(grant), (e) => e.outcome === "unknown");
  }
  const validInventory = { ...grantInventory, revocations: {} };
  assert.notEqual(
    JSON.parse(
      prepareGrant(validInventory, 1, publicAddress, controlAddress).body,
    ).request_id,
    grantPayload.request_id,
  );
  for (const invalid of [
    replicas,
    grantInventory,
    { ...validInventory, admitted: {} },
    {
      ...validInventory,
      membership_observation: {
        ...replicas.membership_observation,
        membership: { configs: [[2]], nodes: {} },
      },
    },
  ]) {
    assert.throws(() =>
      prepareGrant(invalid, 1, publicAddress, controlAddress),
    );
  }
  assert.throws(() =>
    prepareGrant(validInventory, 0, publicAddress, controlAddress),
  );
  assert.throws(() =>
    prepareGrant(validInventory, 1, publicAddress, publicAddress),
  );
  assert.throws(() =>
    prepareGrant(
      validInventory,
      1,
      publicAddress,
      "/ip4/10.0.0.9/tcp/9001/p2p/other",
    ),
  );
  assert.throws(() =>
    prepareGrant(validInventory, 1, publicAddress, `${controlAddress}\n`),
  );
  assert.throws(() =>
    prepareGrant(
      validInventory,
      1,
      `/${"x".repeat(4096)}/p2p/peer`,
      controlAddress,
    ),
  );
  assert.throws(() => replicasFrom({ ...replicas, pending: [{ node_id: 0 }] }));
  assert.throws(() =>
    replicasFrom({
      ...replicas,
      membership_observation: {
        ...replicas.membership_observation,
        membership: { configs: [["1"]], nodes: {} },
      },
    }),
  );
  console.log(
    "request/retry, durable serving receipt and replica desired-state assertions passed",
  );
} finally {
  globalThis.fetch = originalFetch;
}
