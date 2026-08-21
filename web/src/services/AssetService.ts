import { ForbiddenError, NotFoundError, ValidationError } from "../errors/AppError";
import { isConfiguredLocalTarget, normalizePublicTarget } from "../security/inputPolicy";
import type { TargetPolicy } from "../config/appConfig";
import type { ScannerClient } from "../clients/ScannerClient";
import type { JsonStateRepository } from "../repositories/JsonStateRepository";
import type { AssetRecord } from "../types/domain";

/** Manages ownership challenges required before authorized deep scans. */
export class AssetService {
  public constructor(
    private readonly repository: JsonStateRepository,
    private readonly scannerClient: ScannerClient,
    private readonly targetPolicy: TargetPolicy,
  ) {}

  /** Creates an asset record for one normalized origin. */
  public async createAsset(rawOrigin: unknown): Promise<AssetRecord> {
    const target = new URL(normalizePublicTarget(rawOrigin, this.targetPolicy));
    if (target.pathname !== "/" || target.search) {
      throw new ValidationError("Asset verification requires an origin without a path or query string");
    }
    const asset = await this.repository.createAsset(target.origin);
    if (isConfiguredLocalTarget(target, this.targetPolicy) && !asset.isVerified) {
      return this.repository.markAssetVerified(asset.id);
    }
    return asset;
  }

  /** Verifies the challenge file through the isolated outbound client. */
  public async verifyAsset(assetId: string, verificationMethod: string): Promise<AssetRecord> {
    const asset = this.repository.getAsset(assetId);
    if (!asset) throw new NotFoundError("Asset not found");
    const allowedMethods = new Set(["file", "header", "dns"]);
    if (!allowedMethods.has(verificationMethod)) {
      throw new ValidationError("Unsupported asset verification method");
    }
    const isVerified = await this.scannerClient.verifyAsset(asset.origin, asset.challenge, verificationMethod);
    if (!isVerified) {
      throw new ForbiddenError("Verification file was not found or did not contain the exact challenge");
    }
    return this.repository.markAssetVerified(asset.id);
  }

  /** Lists assets available to the authenticated administrator. */
  public listAssets(): AssetRecord[] {
    return this.repository.listAssets();
  }
}
