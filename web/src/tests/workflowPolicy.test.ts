import assert from "node:assert/strict";
import test from "node:test";
import { ValidationError } from "../errors/AppError";
import { parseAuthenticationAdapter, parseWorkflowSteps } from "../security/workflowPolicy";

test("parses a bounded multi-method disposable workflow", () => {
  const steps = parseWorkflowSteps(JSON.stringify([
    { name: "create", method: "POST", path: "/__ac_test__/one", body: { apiAcScannerTest: true }, expected: "allow" },
    { name: "replace", method: "PUT", path: "/__ac_test__/one", body: { apiAcScannerTest: true }, expected: "allow" },
    { name: "patch", method: "PATCH", path: "/__ac_test__/one", body: { apiAcScannerTest: true }, expected: "allow" },
    { name: "delete", method: "DELETE", path: "/__ac_test__/one", expected: "allow" },
  ]));
  assert.deepEqual(steps.map((step) => step.method), ["POST", "PUT", "PATCH", "DELETE"]);
});

test("rejects workflow mutations outside the disposable namespace", () => {
  assert.throws(() => parseWorkflowSteps(JSON.stringify([
    { name: "unsafe", method: "DELETE", path: "/api/orders/1", expected: "deny" },
  ])), ValidationError);
});

test("parses a same-origin JSON login adapter", () => {
  const adapter = parseAuthenticationAdapter(JSON.stringify({
    type: "json-login", path: "/__ac_test__/login", username: "fixture", password: "password",
    tokenJsonPath: "tokens.access", headerName: "authorization", scheme: "Bearer",
  }));
  assert.equal(adapter.type, "json-login");
  assert.equal(adapter.tokenJsonPath, "tokens.access");
});

test("rejects an absolute login adapter URL", () => {
  assert.throws(() => parseAuthenticationAdapter(JSON.stringify({
    type: "json-login", path: "https://evil.example/login", username: "fixture", password: "password",
  })), ValidationError);
});

test("rejects login credentials whose serialized request exceeds the scanner limit", () => {
  assert.throws(() => parseAuthenticationAdapter(JSON.stringify({
    type: "json-login", path: "/__ac_test__/login",
    username: "u".repeat(2100), password: "p".repeat(2100),
  })), /4096 bytes/);
});

test("preserves meaningful whitespace in login credentials", () => {
  const adapter = parseAuthenticationAdapter(JSON.stringify({
    type: "json-login", path: "/__ac_test__/login",
    username: " fixture ", password: " password ",
  }));
  assert.equal(adapter.username, " fixture ");
  assert.equal(adapter.password, " password ");
});
