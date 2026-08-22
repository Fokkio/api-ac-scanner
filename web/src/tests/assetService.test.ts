import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { ScannerClient } from "../clients/ScannerClient";
import type { TargetPolicy } from "../config/appConfig";
import { JsonStateRepository } from "../repositories/JsonStateRepository";
import { AssetService } from "../services/AssetService";

const LOCAL_POLICY: TargetPolicy = {
  localMode: true,
  localAllowedHosts: new Set(["demo-api"]),
  localAllowedPorts: new Set([4100]),
  remoteSafeMutationEnabled: false,
  remoteSafeMutationAllowedOrigins: new Set(),
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
    assert.equal(asset.verificationMethod, "local-allowlist");
  } finally {
    await fs.rm(dataDirectory, { recursive: true, force: true });
  }
});

test("records the external ownership method needed for live remote re-verification", async () => {
  const dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "ac-scanner-assets-"));
  try {
    const repository = await JsonStateRepository.create(dataDirectory, 10);
    const scannerClient = new ScannerClient("http://scanner.invalid", "test-internal-token-123456");
    scannerClient.verifyAsset = async () => true;
    const service = new AssetService(repository, scannerClient, LOCAL_POLICY);
    const pendingAsset = await service.createAsset("https://staging.example.test");

    const verifiedAsset = await service.verifyAsset(pendingAsset.id, "file");

    assert.equal(verifiedAsset.isVerified, true);
    assert.equal(verifiedAsset.verificationMethod, "file");
  } finally {
    await fs.rm(dataDirectory, { recursive: true, force: true });
  }
});
