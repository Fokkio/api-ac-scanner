import assert from "node:assert/strict";
import test from "node:test";
import { ValidationError } from "../errors/AppError";
import {
  isAllowedDiscoveryFile,
  isAllowedSourceFile,
  isDisposableTestPath,
  normalizePublicTarget,
  normalizeToken,
  parseRelativePaths,
} from "../security/inputPolicy";
import type { TargetPolicy } from "../config/appConfig";

test("normalizes an HTTP target and removes fragments", () => {
  assert.equal(normalizePublicTarget("https://Example.com/api?q=1#fragment"), "https://example.com/api?q=1");
});

test("accepts the disposable namespace only at the start of a path", () => {
  assert.equal(isDisposableTestPath("/__ac_test__/resource"), true);
  assert.equal(isDisposableTestPath("/api/__ac_test__/resource"), false);
});

test("rejects credentials and non-standard ports", () => {
  assert.throws(() => normalizePublicTarget("https://user:pass@example.com"), ValidationError);
  assert.throws(() => normalizePublicTarget("https://example.com:8443"), ValidationError);
});

test("accepts only bounded same-origin relative paths", () => {
  assert.deepEqual(parseRelativePaths("/orders/1\n/orders/1,/admin", 3), ["/orders/1", "/admin"]);
  assert.throws(() => parseRelativePaths("//evil.example/path", 3), ValidationError);
  assert.throws(() => parseRelativePaths("https://evil.example/path", 3), ValidationError);
  assert.throws(() => parseRelativePaths("/orders/1#different-resource", 3), ValidationError);
  assert.throws(() => parseRelativePaths("/orders/1\u0000", 3), ValidationError);
});

test("normalizes bearer values and applies an extension allowlist", () => {
  assert.equal(normalizeToken("Bearer abcdefghijklmnop"), "abcdefghijklmnop");
  assert.equal(isAllowedSourceFile("route.TS"), true);
  assert.equal(isAllowedSourceFile("archive.zip"), false);
  assert.equal(isAllowedDiscoveryFile("openapi.yaml"), true);
  assert.equal(isAllowedDiscoveryFile("traffic.har"), true);
  assert.equal(isAllowedDiscoveryFile("archive.zip"), false);
});

test("allows only explicitly configured local hosts and development ports", () => {
  const policy: TargetPolicy = {
    localMode: true,
    localAllowedHosts: new Set(["host.docker.internal"]),
    localAllowedPorts: new Set([4100]),
  };
  assert.equal(
    normalizePublicTarget("http://host.docker.internal:4100", policy),
    "http://host.docker.internal:4100/",
  );
  assert.throws(() => normalizePublicTarget("http://192.168.1.10:4100", policy), ValidationError);
});

test("normalizes bracketed IPv6 before applying the exact local allowlist", () => {
  const policy: TargetPolicy = {
    localMode: true,
    localAllowedHosts: new Set(["::1"]),
    localAllowedPorts: new Set([4100]),
  };
  assert.equal(normalizePublicTarget("http://[::1]:4100", policy), "http://[::1]:4100/");
});
