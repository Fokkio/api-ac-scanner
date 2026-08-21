import assert from "node:assert/strict";
import test from "node:test";
import express from "express";
import request from "supertest";
import { FORM_BODY_LIMIT_BYTES } from "../config/requestLimits";
import { parseIdentityProfile } from "../security/identityPolicy";
import { parseAuthenticationAdapter, parseWorkflowSteps } from "../security/workflowPolicy";

test("accepts an encoded workflow whose fields pass their individual limits", async () => {
  const bodyValue = "x".repeat(2400);
  const credential = "z".repeat(8192);
  const workflowSteps = JSON.stringify(Array.from({ length: 8 }, (_value, index) => ({
    name: `step-${index}`,
    method: "POST",
    path: `/__ac_test__/resource-${index}`,
    body: { apiAcScannerTest: true, value: bodyValue },
    expected: "allow",
  })));
  const authenticationAdapter = JSON.stringify({
    type: "json-login", path: "/__ac_test__/login",
    username: "u".repeat(1700), password: "p".repeat(1700),
  });
  const form = {
    identityLabel: "Owner", identityRole: "owner", identityTenant: "local",
    identityAuthType: "bearer", identityCredential: credential,
    authenticationAdapter, workflowSteps,
  };

  parseIdentityProfile({
    label: form.identityLabel, role: form.identityRole, tenant: form.identityTenant,
    authType: form.identityAuthType, credential: form.identityCredential,
  });
  parseAuthenticationAdapter(authenticationAdapter);
  parseWorkflowSteps(workflowSteps);
  const encodedSize = Buffer.byteLength(new URLSearchParams(form).toString(), "utf8");
  assert.ok(encodedSize > 32 * 1024);
  assert.ok(encodedSize < FORM_BODY_LIMIT_BYTES);

  const app = express();
  app.use(express.urlencoded({ extended: false, limit: FORM_BODY_LIMIT_BYTES }));
  app.post("/workflow", (_request, response) => response.sendStatus(204));
  await request(app).post("/workflow").type("form").send(form).expect(204);
});
