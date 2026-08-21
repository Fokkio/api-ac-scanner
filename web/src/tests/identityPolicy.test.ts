import assert from "node:assert/strict";
import test from "node:test";
import { ValidationError } from "../errors/AppError";
import { parseIdentityProfile } from "../security/identityPolicy";

test("builds bearer, basic, cookie, API-key and bounded custom-header profiles", () => {
  assert.deepEqual(parseIdentityProfile({
    label: "Alice", role: "owner", tenant: "a", authType: "bearer",
    credential: "Bearer owner-token-1234567890",
  }).headers, { authorization: "Bearer owner-token-1234567890" });
  assert.deepEqual(parseIdentityProfile({
    label: "Basic user", authType: "basic", credential: "fixture:password",
  }).headers, { authorization: "Basic Zml4dHVyZTpwYXNzd29yZA==" });
  assert.deepEqual(parseIdentityProfile({
    label: "Cookie user", authType: "cookie", credential: "sid=session-123",
  }).headers, { cookie: "sid=session-123" });
  assert.deepEqual(parseIdentityProfile({
    label: "Key user", authType: "api-key", headerName: "X-API-Key", credential: "key-value",
  }).headers, { "x-api-key": "key-value" });
  assert.deepEqual(parseIdentityProfile({
    label: "Custom", authType: "custom-headers", credential: '{"x-test-user":"alice"}',
  }).headers, { "x-test-user": "alice" });
});

test("rejects reserved or malformed identity headers", () => {
  assert.throws(() => parseIdentityProfile({
    label: "Bad", authType: "api-key", headerName: "Host", credential: "example.test",
  }), ValidationError);
  assert.throws(() => parseIdentityProfile({
    label: "Bad", authType: "custom-headers", credential: '{"connection":"close"}',
  }), ValidationError);
});

test("allows an empty base identity only for an authentication adapter", () => {
  const profile = parseIdentityProfile({
    label: "Adapter user", role: "owner", tenant: "local",
    authType: "none", credential: "",
  }, { allowEmptyAuthentication: true });
  assert.deepEqual(profile.headers, {});

  assert.throws(() => parseIdentityProfile({
    label: "Missing authentication", authType: "none", credential: "",
  }), ValidationError);
});
