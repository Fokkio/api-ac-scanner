import assert from "node:assert/strict";
import test from "node:test";
import { loadAppConfig } from "../config/appConfig";

test("rejects a non-loopback deployment without HTTPS and secure cookies", () => {
  const previousEnvironment = { ...process.env };
  try {
    process.env.NODE_ENV = "test";
    process.env.PUBLIC_BASE_URL = "http://scanner.example.com";
    process.env.SESSION_COOKIE_SECURE = "false";
    assert.throws(() => loadAppConfig(), /require HTTPS/);
  } finally {
    process.env = previousEnvironment;
  }
});

test("allows loopback HTTP only with a non-secure session cookie", () => {
  const previousEnvironment = { ...process.env };
  try {
    process.env.NODE_ENV = "test";
    process.env.PUBLIC_BASE_URL = "http://127.0.0.1:3000";
    process.env.SESSION_COOKIE_SECURE = "false";
    assert.equal(loadAppConfig().publicBaseUrl, "http://127.0.0.1:3000/");
  } finally {
    process.env = previousEnvironment;
  }
});
