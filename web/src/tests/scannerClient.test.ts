import assert from "node:assert/strict";
import test from "node:test";
import { ScannerClient, WORKFLOW_TIMEOUT_MILLISECONDS } from "../clients/ScannerClient";

test("workflow client timeout exceeds the scanner worst-case request budget", () => {
  assert.ok(WORKFLOW_TIMEOUT_MILLISECONDS > 17 * 8_000);
});

test("serializes remote ownership proof at the scanner trust boundary", async () => {
  const originalFetch = globalThis.fetch;
  let capturedBody: Record<string, unknown> | undefined;
  try {
    globalThis.fetch = async (_input: string | URL | Request, init?: RequestInit) => {
      capturedBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(JSON.stringify({ findings: [], warnings: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };
    const client = new ScannerClient("http://scanner:8001", "test-internal-token-123456");
    await client.mutationScan({
      target: "https://staging.example.test",
      path: "/__ac_test__/one",
      body: { apiAcScannerTest: true },
      identity: { label: "Test", role: "owner", tenant: "test", headers: { authorization: "Bearer test" } },
      targetAuthorization: {
        mode: "verified-remote",
        challenge: "challenge-value-with-24-characters",
        verificationMethod: "dns",
      },
    });

    assert.deepEqual(capturedBody?.target_authorization, {
      mode: "verified-remote",
      challenge: "challenge-value-with-24-characters",
      verification_method: "dns",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
