import assert from "node:assert/strict";
import test from "node:test";
import { loadAppConfig } from "../config/appConfig";

test("loads without administrator credentials because the tool has no login", () => {
  withIsolatedEnvironment(() => {
    process.env.NODE_ENV = "production";
    process.env.SESSION_SECRET = "session-secret-at-least-16-characters";
    process.env.SCANNER_INTERNAL_TOKEN = "scanner-token-at-least-16-characters";
    delete process.env.LISTEN_HOST;
    delete process.env.ADMIN_USERNAME;
    delete process.env.ADMIN_PASSWORD;
    const config = loadAppConfig();
    assert.equal(config.sessionSecret, "session-secret-at-least-16-characters");
    assert.equal(config.listenHost, "127.0.0.1");
    assert.equal("adminUsername" in config, false);
    assert.equal("adminPassword" in config, false);
  });
});

test("still requires the CSRF session secret", () => {
  withIsolatedEnvironment(() => {
    process.env.NODE_ENV = "production";
    delete process.env.SESSION_SECRET;
    process.env.SCANNER_INTERNAL_TOKEN = "scanner-token-at-least-16-characters";
    assert.throws(() => loadAppConfig(), /SESSION_SECRET/);
  });
});

test("rejects a direct-start listen address outside the explicit local or container values", () => {
  withIsolatedEnvironment(() => {
    process.env.NODE_ENV = "test";
    process.env.LISTEN_HOST = "192.168.1.20";
    assert.throws(() => loadAppConfig(), /LISTEN_HOST/);
  });
});

test("rejects a TCP port outside the valid range", () => {
  withIsolatedEnvironment(() => {
    process.env.NODE_ENV = "test";
    process.env.PORT = "65536";
    assert.throws(() => loadAppConfig(), /between 1 and 65535/);
  });
});

test("rejects integer settings with trailing non-numeric characters", () => {
  withIsolatedEnvironment(() => {
    process.env.NODE_ENV = "test";
    process.env.PORT = "3000oops";
    assert.throws(() => loadAppConfig(), /PORT/);

    process.env.PORT = "3000";
    process.env.LOCAL_ALLOWED_PORTS = "443x";
    assert.throws(() => loadAppConfig(), /LOCAL_ALLOWED_PORTS/);
  });
});

test("requires an exact HTTPS origin allowlist when remote safe mutation is enabled", () => {
  withIsolatedEnvironment(() => {
    process.env.NODE_ENV = "test";
    process.env.REMOTE_SAFE_MUTATION_ENABLED = "true";
    delete process.env.REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS;
    assert.throws(() => loadAppConfig(), /is required/);

    process.env.REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS = "https://staging.example.test";
    const policy = loadAppConfig().targetPolicy;
    assert.equal(policy.remoteSafeMutationEnabled, true);
    assert.deepEqual([...policy.remoteSafeMutationAllowedOrigins], ["https://staging.example.test"]);
  });
});

test("rejects HTTP paths and credentials in the remote mutation allowlist", () => {
  withIsolatedEnvironment(() => {
    process.env.NODE_ENV = "test";
    process.env.REMOTE_SAFE_MUTATION_ENABLED = "true";
    for (const invalidOrigin of [
      "http://staging.example.test",
      "https://staging.example.test/api",
      "https://user:password@staging.example.test",
    ]) {
      process.env.REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS = invalidOrigin;
      assert.throws(() => loadAppConfig(), /exact HTTPS origins/);
    }
  });
});

function withIsolatedEnvironment(assertions: () => void): void {
  const previousEnvironment = { ...process.env };
  try {
    assertions();
  } finally {
    process.env = previousEnvironment;
  }
}
