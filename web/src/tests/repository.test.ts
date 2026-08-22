import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { JsonStateRepository } from "../repositories/JsonStateRepository";

test("persists scans atomically and recovers interrupted work", async (context) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "acsv2-repository-"));
  context.after(async () => fs.rm(directory, { recursive: true, force: true }));

  const repository = await JsonStateRepository.create(directory, 10);
  const scan = await repository.createScan({
    kind: "quick",
    target: "https://example.com/",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });

  const stateFile = path.join(directory, "state.json");
  const legacyState = JSON.parse(await fs.readFile(stateFile, "utf8")) as {
    version: number;
    scans: Array<Record<string, unknown>>;
  };
  const legacyScan = legacyState.scans[0];
  assert.ok(legacyScan);
  legacyScan.ownerScope = "admin";
  legacyState.version = 1;
  await fs.writeFile(stateFile, JSON.stringify(legacyState), "utf8");

  const reloaded = await JsonStateRepository.create(directory, 10);
  const recovered = reloaded.getScan(scan.id);
  assert.equal(recovered?.status, "error");
  assert.equal(recovered?.errorCode, "PROCESS_RESTARTED");
  assert.equal(recovered && "ownerScope" in recovered, false);
  const migratedState = await fs.readFile(stateFile, "utf8");
  assert.doesNotMatch(migratedState, /ownerScope/);
  assert.equal((JSON.parse(migratedState) as { version: number }).version, 2);
});

test("persists a completed v1 state migration even when no recovery write is needed", async (context) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "acsv2-state-migration-"));
  context.after(async () => fs.rm(directory, { recursive: true, force: true }));
  const stateFile = path.join(directory, "state.json");
  const now = new Date().toISOString();
  await fs.writeFile(stateFile, JSON.stringify({
    version: 1,
    scans: [{
      id: "legacy-completed-scan",
      kind: "source",
      target: "Uploaded source files",
      ownerScope: "admin",
      status: "done",
      progress: 100,
      stage: "Complete",
      findings: [],
      warnings: [],
      endpoints: [],
      matrix: [],
      createdAt: now,
      updatedAt: now,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    }],
    assets: [],
  }), "utf8");

  const repository = await JsonStateRepository.create(directory, 10);
  const migratedScan = repository.getScan("legacy-completed-scan");
  assert.ok(migratedScan);
  assert.equal("ownerScope" in migratedScan, false);
  const migratedState = await fs.readFile(stateFile, "utf8");
  assert.equal((JSON.parse(migratedState) as { version: number }).version, 2);
  assert.doesNotMatch(migratedState, /ownerScope/);
});
