import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import request from "supertest";
import { createApp } from "../app";
import { loadAppConfig } from "../config/appConfig";
import type { BoundedScanQueue } from "../queue/BoundedScanQueue";
import type { AssetService } from "../services/AssetService";
import type { ScanService } from "../services/ScanService";

test("opens the operator dashboard without a login route", async () => {
  const app = createLocalTestApp();
  await request(app).get("/dashboard").expect(200);
  await request(app).get("/login").expect(404);
});

test("rejects non-loopback Host headers before issuing a session", async () => {
  const app = createLocalTestApp();
  const response = await request(app)
    .get("/dashboard")
    .set("Host", "rebind.example")
    .expect(403);
  assert.match(response.text, /loopback Host headers only/);
  assert.equal(response.headers["set-cookie"], undefined);
});

test("keeps CSRF enforcement after removing login", async () => {
  const app = createLocalTestApp();
  const response = await request(app)
    .post("/assets")
    .set("Host", "127.0.0.1")
    .set("Origin", "http://127.0.0.1")
    .type("form")
    .send({ origin: "http://demo-api:4100" })
    .expect(403);
  assert.match(response.text, /Invalid or expired request token/);
});

test("allows a local operator to mutate state with a valid CSRF token and no login", async () => {
  const app = createLocalTestApp();
  const agent = request.agent(app);
  const dashboard = await agent.get("/dashboard").expect(200);
  const csrfToken = extractCsrfToken(dashboard.text);
  await agent
    .post("/assets")
    .type("form")
    .send({ _csrf: csrfToken, origin: "http://demo-api:4100" })
    .expect("Location", "/dashboard")
    .expect(302);
});

test("rejects cross-origin browser mutations before route processing", async () => {
  const app = createLocalTestApp();
  const response = await request(app)
    .post("/scans/source")
    .set("Origin", "https://untrusted.example")
    .attach("sources", Buffer.from("test"), "test.js")
    .expect(403);
  assert.match(response.text, /Cross-origin browser requests are not allowed/);
});

test("rejects an upload without CSRF before creating its directory", async () => {
  const uploadRoot = await fs.mkdtemp(path.join(os.tmpdir(), "api-ac-upload-csrf-"));
  try {
    const app = createLocalTestApp(uploadRoot);
    const response = await request(app)
      .post("/scans/source")
      .attach("sources", Buffer.from("test"), "test.js")
      .expect(403);
    assert.match(response.text, /Invalid or expired request token/);
    assert.deepEqual(await fs.readdir(uploadRoot), []);
  } finally {
    await fs.rm(uploadRoot, { recursive: true, force: true });
  }
});

test("removes files when multipart validation fails after writing begins", async () => {
  const uploadRoot = await fs.mkdtemp(path.join(os.tmpdir(), "api-ac-upload-cleanup-"));
  try {
    const app = createLocalTestApp(uploadRoot);
    const agent = request.agent(app);
    const sourcePage = await agent.get("/source").expect(200);
    const csrfToken = extractCsrfToken(sourcePage.text);
    await agent
      .post("/scans/source")
      .field("_csrf", csrfToken)
      .attach("sources", Buffer.from("const safe = true;"), "valid.js")
      .attach("sources", Buffer.from("blocked"), "invalid.exe")
      .expect(400);
    assert.deepEqual(await fs.readdir(uploadRoot), []);
  } finally {
    await fs.rm(uploadRoot, { recursive: true, force: true });
  }
});

test("returns 413 and removes files when an upload exceeds the file limit", async () => {
  const uploadRoot = await fs.mkdtemp(path.join(os.tmpdir(), "api-ac-upload-limit-"));
  try {
    const app = createLocalTestApp(uploadRoot);
    const agent = request.agent(app);
    const sourcePage = await agent.get("/source").expect(200);
    const csrfToken = extractCsrfToken(sourcePage.text);
    const response = await agent
      .post("/scans/source")
      .field("_csrf", csrfToken)
      .attach("sources", Buffer.alloc(1_048_577), "oversized.js")
      .expect(413);
    assert.match(response.text, /exceeded the 1 MiB limit/);
    assert.deepEqual(await fs.readdir(uploadRoot), []);
  } finally {
    await fs.rm(uploadRoot, { recursive: true, force: true });
  }
});

function createLocalTestApp(uploadRoot?: string) {
  const scanService = {
    getDiscoveryInventory: () => [],
  } as unknown as ScanService;
  const assetService = {
    listAssets: () => [],
    createAsset: async () => undefined,
  } as unknown as AssetService;
  const scanQueue = {
    getStats: () => ({ running: 0, queued: 0, capacity: 1 }),
  } as unknown as BoundedScanQueue;
  return createApp({
    config: { ...loadTestConfig(), ...(uploadRoot ? { uploadRoot } : {}) },
    scanService,
    assetService,
    scanQueue,
  });
}

function extractCsrfToken(html: string): string {
  const csrfToken = html.match(/name="_csrf" value="([^"]+)"/)?.[1];
  assert.ok(csrfToken);
  return csrfToken;
}

function loadTestConfig() {
  const previousNodeEnvironment = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = "test";
    return loadAppConfig();
  } finally {
    if (previousNodeEnvironment === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousNodeEnvironment;
  }
}
