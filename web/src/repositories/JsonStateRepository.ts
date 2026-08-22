import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { NotFoundError } from "../errors/AppError";
import type { AssetRecord, AssetVerificationMethod, PersistedState, ScanKind, ScanRecord } from "../types/domain";

const CURRENT_STATE_VERSION = 2;
const EMPTY_STATE: PersistedState = { version: CURRENT_STATE_VERSION, scans: [], assets: [] };

interface StateLoadResult {
  state: PersistedState;
  requiresPersistence: boolean;
}

type LegacyScanRecord = ScanRecord & { ownerScope?: unknown };

export interface CreateScanInput {
  kind: ScanKind;
  target: string;
  expiresAt: string;
}

/** Single-process repository with serialized, atomic JSON persistence. */
export class JsonStateRepository {
  private writeTail: Promise<void> = Promise.resolve();

  private constructor(
    private readonly stateFile: string,
    private readonly maxStoredReports: number,
    private state: PersistedState,
  ) {}

  /** Loads repository state and recovers interrupted jobs as errors. */
  public static async create(dataDirectory: string, maxStoredReports: number): Promise<JsonStateRepository> {
    await fs.mkdir(dataDirectory, { recursive: true });
    const stateFile = path.join(dataDirectory, "state.json");
    const { state, requiresPersistence } = await JsonStateRepository.readState(stateFile);
    const repository = new JsonStateRepository(stateFile, maxStoredReports, state);
    await repository.recoverInterruptedScans();
    if (requiresPersistence) await repository.persist();
    return repository;
  }

  private static async readState(stateFile: string): Promise<StateLoadResult> {
    try {
      const parsedState = JSON.parse(await fs.readFile(stateFile, "utf8")) as Omit<PersistedState, "version" | "scans"> & {
        version: number;
        scans: LegacyScanRecord[];
      };
      if (![1, CURRENT_STATE_VERSION].includes(parsedState.version)
        || !Array.isArray(parsedState.scans)
        || !Array.isArray(parsedState.assets)) {
        throw new Error("Unsupported state file schema");
      }
      const containsLegacyScope = parsedState.scans.some((scan) => Object.hasOwn(scan, "ownerScope"));
      return {
        state: {
          ...parsedState,
          version: CURRENT_STATE_VERSION,
          scans: parsedState.scans.map(normalizePersistedScan),
        },
        requiresPersistence: parsedState.version !== CURRENT_STATE_VERSION || containsLegacyScope,
      };
    } catch (error: unknown) {
      if (isMissingFileError(error)) {
        return { state: structuredClone(EMPTY_STATE), requiresPersistence: false };
      }
      throw error;
    }
  }

  /** Creates a queued scan record with an opaque identifier. */
  public async createScan(input: CreateScanInput): Promise<ScanRecord> {
    return this.mutate(async () => {
      const now = new Date().toISOString();
      const scan: ScanRecord = {
        id: crypto.randomBytes(24).toString("hex"),
        kind: input.kind,
        target: input.target,
        status: "queued",
        progress: 0,
        stage: "Queued",
        findings: [],
        warnings: [],
        endpoints: [],
        matrix: [],
        createdAt: now,
        updatedAt: now,
        expiresAt: input.expiresAt,
      };
      this.state.scans.unshift(scan);
      this.pruneExpiredAndExcessScans();
      await this.persist();
      return structuredClone(scan);
    });
  }

  /** Updates mutable scan fields and persists the new state atomically. */
  public async updateScan(scanId: string, patch: Partial<ScanRecord>): Promise<ScanRecord> {
    return this.mutate(async () => {
      const index = this.state.scans.findIndex((scan) => scan.id === scanId);
      if (index < 0) throw new NotFoundError("Scan not found");
      const existingScan = this.state.scans[index];
      if (!existingScan) throw new NotFoundError("Scan not found");
      const updatedScan: ScanRecord = {
        ...existingScan,
        ...patch,
        id: existingScan.id,
        updatedAt: new Date().toISOString(),
      };
      this.state.scans[index] = updatedScan;
      await this.persist();
      return structuredClone(updatedScan);
    });
  }

  /** Returns a scan record without exposing mutable repository state. */
  public getScan(scanId: string): ScanRecord | undefined {
    const scan = this.state.scans.find((candidate) => candidate.id === scanId);
    return scan ? structuredClone(scan) : undefined;
  }

  /** Returns cloned scan summaries for local workflows. */
  public listScans(): ScanRecord[] {
    return structuredClone(this.state.scans);
  }

  /** Creates a pending asset-verification challenge for one exact origin. */
  public async createAsset(origin: string): Promise<AssetRecord> {
    return this.mutate(async () => {
      const existingAsset = this.state.assets.find((asset) => asset.origin === origin);
      if (existingAsset) return structuredClone(existingAsset);
      const asset: AssetRecord = {
        id: crypto.randomUUID(),
        origin,
        challenge: crypto.randomBytes(24).toString("base64url"),
        isVerified: false,
        createdAt: new Date().toISOString(),
      };
      this.state.assets.push(asset);
      await this.persist();
      return structuredClone(asset);
    });
  }

  /** Returns all configured assets ordered by creation date. */
  public listAssets(): AssetRecord[] {
    return structuredClone(this.state.assets).sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  }

  /** Returns one asset record. */
  public getAsset(assetId: string): AssetRecord | undefined {
    const asset = this.state.assets.find((candidate) => candidate.id === assetId);
    return asset ? structuredClone(asset) : undefined;
  }

  /** Marks an asset challenge as verified and records how control was proven. */
  public async markAssetVerified(assetId: string, verificationMethod: AssetVerificationMethod): Promise<AssetRecord> {
    return this.mutate(async () => {
      const index = this.state.assets.findIndex((asset) => asset.id === assetId);
      const existingAsset = this.state.assets[index];
      if (index < 0 || !existingAsset) throw new NotFoundError("Asset not found");
      const verifiedAsset: AssetRecord = {
        ...existingAsset,
        isVerified: true,
        verificationMethod,
        verifiedAt: new Date().toISOString(),
      };
      this.state.assets[index] = verifiedAsset;
      await this.persist();
      return structuredClone(verifiedAsset);
    });
  }

  private async recoverInterruptedScans(): Promise<void> {
    const interruptedScans = this.state.scans.filter(
      (scan) => scan.status === "queued" || scan.status === "running",
    );
    if (interruptedScans.length === 0) return;
    const now = new Date().toISOString();
    for (const scan of interruptedScans) {
      scan.status = "error";
      scan.stage = "Interrupted";
      scan.errorCode = "PROCESS_RESTARTED";
      scan.errorMessage = "The scan was interrupted by a service restart. Run it again.";
      scan.updatedAt = now;
    }
    await this.persist();
  }

  private pruneExpiredAndExcessScans(): void {
    const now = Date.now();
    this.state.scans = this.state.scans
      .filter((scan) => Date.parse(scan.expiresAt) > now)
      .slice(0, this.maxStoredReports);
  }

  private async persist(): Promise<void> {
    const temporaryFile = `${this.stateFile}.${crypto.randomBytes(6).toString("hex")}.tmp`;
    try {
      await fs.writeFile(temporaryFile, JSON.stringify(this.state, null, 2), { encoding: "utf8", mode: 0o600 });
      await fs.rename(temporaryFile, this.stateFile);
    } finally {
      try {
        await fs.rm(temporaryFile, { force: true });
      } catch (cleanupError: unknown) {
        console.error("Failed to remove a temporary state file", { temporaryFile, cleanupError });
      }
    }
  }

  private async mutate<Result>(operation: () => Promise<Result>): Promise<Result> {
    const resultPromise = this.writeTail.then(operation, operation);
    this.writeTail = resultPromise.then(() => undefined, () => undefined);
    return resultPromise;
  }
}

function isMissingFileError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error && error.code === "ENOENT";
}

function normalizePersistedScan(scan: LegacyScanRecord): ScanRecord {
  const normalizedScan = {
    ...scan,
    endpoints: Array.isArray(scan.endpoints) ? scan.endpoints : [],
    matrix: Array.isArray(scan.matrix) ? scan.matrix : [],
  };
  Reflect.deleteProperty(normalizedScan, "ownerScope");
  return normalizedScan;
}
