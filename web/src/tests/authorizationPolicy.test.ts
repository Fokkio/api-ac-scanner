import assert from "node:assert/strict";
import test from "node:test";
import { ValidationError } from "../errors/AppError";
import { parseAuthorizationPolicy } from "../security/authorizationPolicy";
import type { TestIdentity } from "../types/domain";

const identities: [TestIdentity, TestIdentity] = [
  { label: "Alice", role: "owner", tenant: "a", headers: { authorization: "secret-a" } },
  { label: "Bob", role: "user", tenant: "b", headers: { authorization: "secret-b" } },
];

test("parses explicit bounded authorization policy rules", () => {
  const rules = parseAuthorizationPolicy(JSON.stringify([
    { method: "GET", path: "/api/orders/1", identity: "Alice", expected: "allow" },
    { method: "GET", path: "/api/orders/1", identity: "Bob", expected: "deny" },
    { method: "GET", path: "/api/orders/1", identity: "Anonymous", expected: "deny" },
  ]), identities);
  assert.equal(rules.length, 3);
});

test("rejects unknown identities and duplicate policy rules", () => {
  assert.throws(() => parseAuthorizationPolicy(JSON.stringify([
    { method: "GET", path: "/api/orders/1", identity: "Mallory", expected: "deny" },
  ]), identities), ValidationError);
  const duplicate = { method: "GET", path: "/api/orders/1", identity: "Alice", expected: "allow" };
  assert.throws(() => parseAuthorizationPolicy(JSON.stringify([duplicate, duplicate]), identities), ValidationError);
});
