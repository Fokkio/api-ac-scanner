import assert from "node:assert/strict";
import test from "node:test";

const baseUrl = process.env.PORTAL_BASE_URL || "http://127.0.0.1:4100";
const aliceBearer = "alice-bearer-token-1234567890";

async function request(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, options);
  const text = await response.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  return { response, body, text };
}

test("health confirms PostgreSQL seed with three users", async () => {
  const { response, body } = await request("/health");
  assert.equal(response.status, 200);
  assert.deepEqual(body, { status: "ok", database: "connected", users: 3 });
});

test("browser login sets a session and renders Alice's database order", async () => {
  const login = await request("/ui/login", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username: "alice", password: "alice-password" }),
    redirect: "manual",
  });
  assert.equal(login.response.status, 303);
  const cookie = login.response.headers.get("set-cookie");
  assert.match(cookie, /^portal_session=/);
  assert.match(cookie, /HttpOnly/i);
  const portal = await request("/portal", { headers: { cookie: cookie.split(";")[0] } });
  assert.equal(portal.response.status, 200);
  assert.match(portal.text, /Welcome, Alice Owner/);
  assert.match(portal.text, /Disposable scanner verification order/);
  assert.doesNotMatch(portal.text, /alice-password/);
});

test("BOLA policy allows Alice and denies Bob and anonymous", async () => {
  const alice = await request("/api/orders/1", { headers: { authorization: `Bearer ${aliceBearer}` } });
  const bob = await request("/api/orders/1", { headers: { authorization: "Bearer bob-bearer-token-1234567890" } });
  const bobOwnOrder = await request("/api/orders/2", { headers: { authorization: "Bearer bob-bearer-token-1234567890" } });
  const anonymous = await request("/api/orders/1");
  assert.equal(alice.response.status, 200);
  assert.equal(alice.body.owner, "alice");
  assert.equal(bob.response.status, 403);
  assert.equal(bobOwnOrder.response.status, 200);
  assert.equal(bobOwnOrder.body.owner, "bob");
  assert.equal(anonymous.response.status, 401);
});

test("BFLA policy allows admin and denies owner role", async () => {
  const admin = await request("/api/admin/reports", { headers: { authorization: "Bearer admin-bearer-token-1234567890" } });
  const alice = await request("/api/admin/reports", { headers: { authorization: `Bearer ${aliceBearer}` } });
  assert.equal(admin.response.status, 200);
  assert.equal(admin.body.report, "order-summary");
  assert.equal(admin.body.orderCount, 3);
  assert.equal(alice.response.status, 403);
});

test("owner function allows Alice and denies viewer role", async () => {
  const alice = await request("/api/owner/summary", { headers: { authorization: `Bearer ${aliceBearer}` } });
  const bob = await request("/api/owner/summary", { headers: { authorization: "Bearer bob-bearer-token-1234567890" } });
  assert.equal(alice.response.status, 200);
  assert.equal(alice.body.visibleOrders, 1);
  assert.equal(bob.response.status, 403);
});

test("JSON login adapter contract returns a nested bounded token", async () => {
  const valid = await request("/__ac_test__/login", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "alice", password: "alice-password" }),
  });
  const invalid = await request("/__ac_test__/login", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "alice", password: "wrong" }),
  });
  assert.equal(valid.response.status, 200);
  assert.equal(valid.body.tokens.access, aliceBearer);
  assert.equal(invalid.response.status, 401);
  assert.equal(JSON.stringify(valid.body).includes("alice-password"), false);
});

test("POST PUT PATCH GET DELETE persist and remove one marked resource", async () => {
  const path = "/__ac_test__/resource-contract-workflow";
  const headers = { authorization: `Bearer ${aliceBearer}`, "content-type": "application/json" };
  const create = await request(path, { method: "POST", headers, body: JSON.stringify({ apiAcScannerTest: true, value: "created" }) });
  const replace = await request(path, { method: "PUT", headers, body: JSON.stringify({ apiAcScannerTest: true, value: "replaced" }) });
  const patch = await request(path, { method: "PATCH", headers, body: JSON.stringify({ apiAcScannerTest: true, patched: true }) });
  const read = await request(path, { headers });
  const remove = await request(path, { method: "DELETE", headers });
  const after = await request(path, { headers });
  assert.equal(create.response.status, 201);
  assert.equal(replace.response.status, 200);
  assert.equal(patch.response.status, 200);
  assert.equal(read.body.value.value, "replaced");
  assert.equal(read.body.value.patched, true);
  assert.equal(remove.response.status, 204);
  assert.equal(after.response.status, 404);
});

test("all identity adapters authorize the same disposable create-cleanup contract", async () => {
  const login = await request("/__ac_test__/login", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "alice", password: "alice-password" }),
  });
  const adapters = [
    ["bearer", { authorization: `Bearer ${aliceBearer}` }],
    ["basic", { authorization: `Basic ${Buffer.from("alice:alice-password").toString("base64")}` }],
    ["api-key", { "x-api-key": "alice-api-key-1234567890" }],
    ["cookie", { cookie: "portal_session=alice-session-token-1234567890" }],
    ["custom", { "x-demo-user": "alice", "x-demo-secret": "alice-custom-secret-1234567890" }],
    ["json-login", { authorization: `Bearer ${login.body.tokens.access}` }],
  ];
  for (const [name, authHeaders] of adapters) {
    const path = `/__ac_test__/resource-adapter-${name}`;
    const create = await request(path, {
      method: "POST", headers: { ...authHeaders, "content-type": "application/json" },
      body: JSON.stringify({ apiAcScannerTest: true, adapter: name }),
    });
    const remove = await request(path, { method: "DELETE", headers: authHeaders });
    assert.equal(create.response.status, 201, `${name} create`);
    assert.equal(remove.response.status, 204, `${name} cleanup`);
  }
});

test("mutation guard rejects missing marker, missing auth, and viewer role", async () => {
  const path = "/__ac_test__/resource-negative";
  const noMarker = await request(path, {
    method: "POST", headers: { authorization: `Bearer ${aliceBearer}`, "content-type": "application/json" }, body: "{}",
  });
  const anonymous = await request(path, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ apiAcScannerTest: true }),
  });
  const viewer = await request(path, {
    method: "POST", headers: { authorization: "Bearer bob-bearer-token-1234567890", "content-type": "application/json" }, body: JSON.stringify({ apiAcScannerTest: true }),
  });
  assert.equal(noMarker.response.status, 400);
  assert.equal(anonymous.response.status, 401);
  assert.equal(viewer.response.status, 403);
});
