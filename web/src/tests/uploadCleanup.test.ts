import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { removeOrphanedUploadDirectories } from "../middlewares/upload";

test("startup cleanup removes request directories but preserves root files", async (context) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "acsv2-uploads-"));
  context.after(async () => fs.rm(root, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, "orphan"));
  await fs.writeFile(path.join(root, "orphan", "route.ts"), "temporary");
  await fs.writeFile(path.join(root, ".gitkeep"), "");

  await removeOrphanedUploadDirectories(root);

  assert.equal(await exists(path.join(root, "orphan")), false);
  assert.equal(await exists(path.join(root, ".gitkeep")), true);
});

async function exists(candidate: string): Promise<boolean> {
  try {
    await fs.access(candidate);
    return true;
  } catch {
    return false;
  }
}
