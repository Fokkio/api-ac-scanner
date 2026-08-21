import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import type { ScannerClient } from "../clients/ScannerClient";
import type { TargetPolicy } from "../config/appConfig";
import { JsonStateRepository } from "../repositories/JsonStateRepository";
import { AssetService } from "../services/AssetService";

const LOCAL_POLICY: TargetPolicy = {
  localMode: true,
  localAllowedHosts: new Set(["demo-api"]),
  localAllowedPorts: new Set([4100]),
};

test("auto-verifies only an explicitly allowlisted local asset", async () => {
  const dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "ac-scanner-assets-"));
  try {
    const repository = await JsonStateRepository.create(dataDirectory, 10);
    const scannerClient = {} as ScannerClient;
    const service = new AssetService(repository, scannerClient, LOCAL_POLICY);

    const asset = await service.createAsset("http://demo-api:4100");

    assert.equal(asset.origin, "http://demo-api:4100");
    assert.equal(asset.isVerified, true);
  } finally {
    await fs.rm(dataDirectory, { recursive: true, force: true });
  }
});
