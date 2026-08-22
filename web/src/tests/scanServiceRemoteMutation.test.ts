import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import type { ScannerClient } from "../clients/ScannerClient";
import type { TargetPolicy } from "../config/appConfig";
import { BoundedScanQueue } from "../queue/BoundedScanQueue";
import { JsonStateRepository } from "../repositories/JsonStateRepository";
import { REMOTE_MUTATION_CONFIRMATION } from "../security/mutationTargetPolicy";
import { ScanService } from "../services/ScanService";
import type { MutationTargetAuthorization, ScannerResult } from "../types/domain";

const REMOTE_ORIGIN = "https://staging.example.test";

test("passes verified remote proof from persisted asset through the scan-service boundary", async () => {
  const dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "ac-scanner-remote-service-"));
  try {
    const repository = await JsonStateRepository.create(dataDirectory, 20);
    const asset = await repository.createAsset(REMOTE_ORIGIN);
    await repository.markAssetVerified(asset.id, "header");

    let capturedAuthorization: MutationTargetAuthorization | undefined;
    const scannerClient = {
      mutationScan: async (request: { targetAuthorization: MutationTargetAuthorization }): Promise<ScannerResult> => {
        capturedAuthorization = request.targetAuthorization;
        return { findings: [], warnings: [] };
      },
    } as unknown as ScannerClient;
    const targetPolicy: TargetPolicy = {
      localMode: true,
      localAllowedHosts: new Set(["demo-api"]),
      localAllowedPorts: new Set([4100]),
      remoteSafeMutationEnabled: true,
      remoteSafeMutationAllowedOrigins: new Set([REMOTE_ORIGIN]),
    };
    const service = new ScanService(
      repository,
      new BoundedScanQueue(1, 2),
      scannerClient,
      1,
      targetPolicy,
    );

    const scan = await service.createMutationScan({
      assetId: asset.id,
      path: "/__ac_test__/remote-service-proof",
      body: JSON.stringify({ apiAcScannerTest: true }),
      confirmation: REMOTE_MUTATION_CONFIRMATION,
      identity: { label: "Fixture", role: "owner", tenant: "test", headers: {} },
    });
    await waitForScanCompletion(repository, scan.id);

    assert.deepEqual(capturedAuthorization, {
      mode: "verified-remote",
      challenge: asset.challenge,
      verificationMethod: "header",
    });
  } finally {
    await fs.rm(dataDirectory, { recursive: true, force: true });
  }
});

async function waitForScanCompletion(repository: JsonStateRepository, scanId: string): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (repository.getScan(scanId)?.status === "done") return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("Timed out waiting for queued scan completion");
}
