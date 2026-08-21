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
    ownerScope: "public",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });

  const reloaded = await JsonStateRepository.create(directory, 10);
  const recovered = reloaded.getScan(scan.id);
  assert.equal(recovered?.status, "error");
  assert.equal(recovered?.errorCode, "PROCESS_RESTARTED");
});
