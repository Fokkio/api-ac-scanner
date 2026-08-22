import assert from "node:assert/strict";
import test from "node:test";
import type { TargetPolicy } from "../config/appConfig";
import { ForbiddenError } from "../errors/AppError";
import {
  getMutationConfirmation,
  getMutationTargetAuthorization,
  getWorkflowConfirmation,
  requireMutationTargetAuthorization,
} from "../security/mutationTargetPolicy";
import type { AssetRecord } from "../types/domain";

const BASE_ASSET: AssetRecord = {
  id: "asset-one",
  origin: "https://staging.example.test",
  challenge: "challenge-value-with-24-characters",
  isVerified: true,
  verificationMethod: "file",
  createdAt: "2026-08-22T00:00:00.000Z",
  verifiedAt: "2026-08-22T00:01:00.000Z",
};

const REMOTE_POLICY: TargetPolicy = {
  localMode: true,
  localAllowedHosts: new Set(["demo-api"]),
  localAllowedPorts: new Set([4100]),
  remoteSafeMutationEnabled: true,
  remoteSafeMutationAllowedOrigins: new Set(["https://staging.example.test"]),
};

test("authorizes only a verified exact remote origin with a reusable proof method", () => {
  assert.deepEqual(getMutationTargetAuthorization(BASE_ASSET, REMOTE_POLICY), {
    mode: "verified-remote",
    challenge: BASE_ASSET.challenge,
    verificationMethod: "file",
  });
});

test("rejects remote mutation when the feature is disabled or origin is not allowlisted", () => {
  assert.equal(getMutationTargetAuthorization(BASE_ASSET, {
    ...REMOTE_POLICY,
    remoteSafeMutationEnabled: false,
  }), undefined);
  assert.equal(getMutationTargetAuthorization(BASE_ASSET, {
    ...REMOTE_POLICY,
    remoteSafeMutationAllowedOrigins: new Set(["https://other.example.test"]),
  }), undefined);
});

test("requires legacy verified remote assets to be re-verified after upgrade", () => {
  const legacyAsset = structuredClone(BASE_ASSET);
  delete legacyAsset.verificationMethod;
  assert.throws(
    () => requireMutationTargetAuthorization(legacyAsset, REMOTE_POLICY),
    (error: unknown) => error instanceof ForbiddenError && /Re-verify/.test(error.message),
  );
});

test("keeps local and verified-remote confirmation phrases distinct", () => {
  assert.equal(getMutationConfirmation("local"), "MUTATE TEST RESOURCE");
  assert.equal(getMutationConfirmation("verified-remote"), "MUTATE VERIFIED REMOTE TEST RESOURCE");
  assert.equal(getWorkflowConfirmation("local"), "RUN DISPOSABLE WORKFLOW");
  assert.equal(getWorkflowConfirmation("verified-remote"), "RUN VERIFIED REMOTE DISPOSABLE WORKFLOW");
});
