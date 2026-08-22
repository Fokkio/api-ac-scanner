import { ForbiddenError } from "../errors/AppError";
import type { TargetPolicy } from "../config/appConfig";
import type { AssetRecord, ExternalAssetVerificationMethod, MutationTargetAuthorization } from "../types/domain";
import { isConfiguredLocalTarget } from "./inputPolicy";

export const LOCAL_MUTATION_CONFIRMATION = "MUTATE TEST RESOURCE";
export const REMOTE_MUTATION_CONFIRMATION = "MUTATE VERIFIED REMOTE TEST RESOURCE";
export const LOCAL_WORKFLOW_CONFIRMATION = "RUN DISPOSABLE WORKFLOW";
export const REMOTE_WORKFLOW_CONFIRMATION = "RUN VERIFIED REMOTE DISPOSABLE WORKFLOW";

const EXTERNAL_VERIFICATION_METHODS = new Set<ExternalAssetVerificationMethod>(["file", "header", "dns"]);

/** Returns the target proof when an asset is eligible for guarded state-changing checks. */
export function getMutationTargetAuthorization(
  asset: AssetRecord,
  policy: TargetPolicy,
): MutationTargetAuthorization | undefined {
  if (!asset.isVerified) return undefined;
  const target = new URL(asset.origin);
  if (isConfiguredLocalTarget(target, policy)) return { mode: "local" };
  if (
    !policy.remoteSafeMutationEnabled
    || target.protocol !== "https:"
    || !policy.remoteSafeMutationAllowedOrigins.has(target.origin)
    || !isExternalVerificationMethod(asset.verificationMethod)
  ) {
    return undefined;
  }
  return {
    mode: "verified-remote",
    challenge: asset.challenge,
    verificationMethod: asset.verificationMethod,
  };
}

/** Requires an eligible local or verified remote mutation target. */
export function requireMutationTargetAuthorization(
  asset: AssetRecord,
  policy: TargetPolicy,
): MutationTargetAuthorization {
  const authorization = getMutationTargetAuthorization(asset, policy);
  if (authorization) return authorization;
  if (!asset.isVerified) throw new ForbiddenError("Verify this asset before running a state-changing scan");
  if (!policy.remoteSafeMutationEnabled) {
    throw new ForbiddenError("Remote safe mutation is disabled by server configuration");
  }
  if (!policy.remoteSafeMutationAllowedOrigins.has(asset.origin)) {
    throw new ForbiddenError("This remote origin is not in the exact mutation allowlist");
  }
  if (!isExternalVerificationMethod(asset.verificationMethod)) {
    throw new ForbiddenError("Re-verify this remote asset before running a state-changing scan");
  }
  throw new ForbiddenError("Remote safe mutation requires an exact HTTPS origin on port 443");
}

/** Returns the exact phrase that distinguishes local and verified-remote mutation intent. */
export function getMutationConfirmation(mode: MutationTargetAuthorization["mode"]): string {
  return mode === "local" ? LOCAL_MUTATION_CONFIRMATION : REMOTE_MUTATION_CONFIRMATION;
}

/** Returns the exact phrase that distinguishes local and verified-remote workflow intent. */
export function getWorkflowConfirmation(mode: MutationTargetAuthorization["mode"]): string {
  return mode === "local" ? LOCAL_WORKFLOW_CONFIRMATION : REMOTE_WORKFLOW_CONFIRMATION;
}

function isExternalVerificationMethod(
  method: AssetRecord["verificationMethod"],
): method is ExternalAssetVerificationMethod {
  return typeof method === "string" && EXTERNAL_VERIFICATION_METHODS.has(method as ExternalAssetVerificationMethod);
}
