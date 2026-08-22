import fs from "node:fs/promises";
import type { ScannerClient } from "../clients/ScannerClient";
import { ForbiddenError, NotFoundError, ValidationError } from "../errors/AppError";
import type { BoundedScanQueue } from "../queue/BoundedScanQueue";
import type { JsonStateRepository } from "../repositories/JsonStateRepository";
import {
  isDisposableTestPath,
  normalizePublicTarget,
  parseRelativePaths,
} from "../security/inputPolicy";
import type { DeepScanInput, MutationScanInput, ScanRecord, ScannerResult, WorkflowScanInput } from "../types/domain";
import type { TargetPolicy } from "../config/appConfig";
import {
  getMutationConfirmation,
  getWorkflowConfirmation,
  requireMutationTargetAuthorization,
} from "../security/mutationTargetPolicy";

type ScanOperation = () => Promise<ScannerResult>;

/** Coordinates validation, queueing, scanner calls, persistence and cleanup. */
export class ScanService {
  public constructor(
    private readonly repository: JsonStateRepository,
    private readonly queue: BoundedScanQueue,
    private readonly scannerClient: ScannerClient,
    private readonly reportTtlHours: number,
    private readonly targetPolicy: TargetPolicy,
  ) {}

  /** Enqueues a public, tokenless quick scan after server-side consent validation. */
  public async createQuickScan(rawTarget: unknown, hasConsent: boolean): Promise<ScanRecord> {
    if (!hasConsent) throw new ValidationError("You must confirm that you are authorized to test this target");
    const target = normalizePublicTarget(rawTarget, this.targetPolicy);
    return this.createQueuedScan("quick", target, () => this.scannerClient.quickScan(target));
  }

  /** Enqueues a verified-asset deep scan while keeping credentials in memory only. */
  public async createDeepScan(input: DeepScanInput): Promise<ScanRecord> {
    const asset = this.repository.getAsset(input.assetId);
    if (!asset) throw new NotFoundError("Asset not found");
    if (!asset.isVerified) throw new ForbiddenError("Verify this asset before running a deep scan");

    const objectPaths = parseRelativePaths(input.objectPaths.join("\n"), 5);
    const adminPaths = parseRelativePaths(input.adminPaths.join("\n"), 5);
    const enumerationExistingPaths = parseOptionalRelativePaths(input.enumerationExistingPaths, 5);
    const enumerationMissingPaths = parseOptionalRelativePaths(input.enumerationMissingPaths, 5);
    if (enumerationExistingPaths.length !== enumerationMissingPaths.length) {
      throw new ValidationError("Enumeration existing and missing path lists must contain the same number of entries");
    }
    if (JSON.stringify(input.identities[0].headers) === JSON.stringify(input.identities[1].headers)) {
      throw new ValidationError("The two profiles must use different credentials");
    }

    return this.createQueuedScan("deep", asset.origin, () =>
      this.scannerClient.deepScan({
        target: asset.origin,
        object_paths: objectPaths,
        admin_paths: adminPaths,
        enumeration_existing_paths: enumerationExistingPaths,
        enumeration_missing_paths: enumerationMissingPaths,
        identities: input.identities,
        policy_rules: input.policyRules,
      }),
    );
  }

  /** Enqueues a static source scan and always removes its temporary upload directory. */
  public async createSourceScan(uploadDirectory: string): Promise<ScanRecord> {
    return this.createQueuedScan("source", "Uploaded source files", async () => {
      try {
        return await this.scannerClient.sourceScan(uploadDirectory);
      } finally {
        await fs.rm(uploadDirectory, { recursive: true, force: true });
      }
    });
  }

  /** Enqueues endpoint discovery for artifacts associated with one verified asset. */
  public async createDiscoveryScan(assetId: string, uploadDirectory: string): Promise<ScanRecord> {
    const asset = this.repository.getAsset(assetId);
    if (!asset) throw new NotFoundError("Asset not found");
    if (!asset.isVerified) throw new ForbiddenError("Verify this asset before importing endpoint artifacts");
    return this.createQueuedScan("discovery", asset.origin, async () => {
      try {
        return await this.scannerClient.discoveryScan(uploadDirectory, asset.origin);
      } finally {
        await fs.rm(uploadDirectory, { recursive: true, force: true });
      }
    });
  }

  /** Retrieves a report for the operator of this loopback-only tool. */
  public getScan(scanId: string): ScanRecord {
    const scan = this.repository.getScan(scanId);
    if (!scan) throw new NotFoundError("Scan report not found");
    return scan;
  }

  /** Returns only a completed discovery inventory for dashboard suggestions. */
  public getDiscoveryInventory(scanId: string): ScanRecord["endpoints"] {
    const scan = this.getScan(scanId);
    if (scan.kind !== "discovery" || scan.status !== "done") {
      throw new ValidationError("Select a completed discovery report");
    }
    return scan.endpoints;
  }

  /** Lists completed scans that can be selected for source/runtime correlation. */
  public listCompletedScans(kind: "source" | "deep"): ScanRecord[] {
    return this.repository.listScans().filter((scan) => scan.kind === kind && scan.status === "done");
  }

  /** Correlates route-aware static evidence with runtime evidence without claiming confirmation. */
  public async createCorrelationScan(sourceScanId: string, dynamicScanId: string): Promise<ScanRecord> {
    const source = this.getScan(sourceScanId);
    const dynamic = this.getScan(dynamicScanId);
    if (source.kind !== "source" || source.status !== "done") {
      throw new ValidationError("Select a completed source scan");
    }
    if (dynamic.kind !== "deep" || dynamic.status !== "done") {
      throw new ValidationError("Select a completed deep scan");
    }
    const expiresAt = new Date(Date.now() + this.reportTtlHours * 60 * 60 * 1000).toISOString();
    const scan = await this.repository.createScan({
      kind: "correlation", target: dynamic.target, expiresAt,
    });
    return this.repository.updateScan(scan.id, {
      status: "done",
      progress: 100,
      stage: "Correlation ready",
      findings: correlateFindings(source.findings, dynamic.findings),
      warnings: [
        "Correlation raises confidence only when category and normalized endpoint agree; it does not prove business authorization policy.",
      ],
    });
  }

  /** Runs one explicitly confirmed create-and-cleanup check against an eligible test asset. */
  public async createMutationScan(input: MutationScanInput): Promise<ScanRecord> {
    const asset = this.repository.getAsset(input.assetId);
    if (!asset) throw new NotFoundError("Asset not found");
    const targetAuthorization = requireMutationTargetAuthorization(asset, this.targetPolicy);
    if (input.confirmation !== getMutationConfirmation(targetAuthorization.mode)) {
      throw new ValidationError("Type the exact mutation confirmation phrase");
    }
    const [mutationPath] = parseRelativePaths(input.path, 1);
    if (!mutationPath || !isDisposableTestPath(mutationPath)) {
      throw new ValidationError("Mutation path must use the /__ac_test__/ namespace");
    }
    let body: unknown;
    try {
      body = JSON.parse(input.body);
    } catch {
      throw new ValidationError("Mutation body must be valid JSON");
    }
    if (!body || typeof body !== "object" || Array.isArray(body)
      || (body as Record<string, unknown>).apiAcScannerTest !== true) {
      throw new ValidationError("Mutation body must contain apiAcScannerTest: true");
    }
    if (Buffer.byteLength(JSON.stringify(body), "utf8") > 4096) {
      throw new ValidationError("Mutation body is too large");
    }
    return this.createQueuedScan("mutation", asset.origin, () => this.scannerClient.mutationScan({
      target: asset.origin,
      path: mutationPath,
      body: body as Record<string, unknown>,
      identity: input.identity,
      targetAuthorization,
    }));
  }

  /** Runs an explicitly confirmed multi-step workflow against an eligible disposable namespace. */
  public async createWorkflowScan(input: WorkflowScanInput): Promise<ScanRecord> {
    const asset = this.repository.getAsset(input.assetId);
    if (!asset) throw new NotFoundError("Asset not found");
    const targetAuthorization = requireMutationTargetAuthorization(asset, this.targetPolicy);
    if (input.confirmation !== getWorkflowConfirmation(targetAuthorization.mode)) {
      throw new ValidationError("Type the exact workflow confirmation phrase");
    }
    return this.createQueuedScan("workflow", asset.origin, () => this.scannerClient.workflowScan({
      target: asset.origin,
      identity: input.identity,
      authentication: input.authentication,
      steps: input.steps,
      targetAuthorization,
    }));
  }

  private async createQueuedScan(
    kind: ScanRecord["kind"],
    target: string,
    operation: ScanOperation,
  ): Promise<ScanRecord> {
    const expiresAt = new Date(Date.now() + this.reportTtlHours * 60 * 60 * 1000).toISOString();
    const scan = await this.repository.createScan({ kind, target, expiresAt });
    try {
      this.queue.enqueue({ scanId: scan.id, run: () => this.executeScan(scan.id, operation) });
    } catch (error: unknown) {
      await this.repository.updateScan(scan.id, {
        status: "error",
        stage: "Queue rejected",
        errorCode: "QUEUE_FULL",
        errorMessage: "The scanner is busy. Try again later.",
      });
      throw error;
    }
    return scan;
  }

  private async executeScan(scanId: string, operation: ScanOperation): Promise<void> {
    await this.repository.updateScan(scanId, { status: "running", progress: 15, stage: "Validating target" });
    try {
      await this.repository.updateScan(scanId, { progress: 35, stage: "Running bounded checks" });
      const result = await operation();
      await this.repository.updateScan(scanId, {
        status: "done",
        progress: 100,
        stage: "Report ready",
        findings: result.findings,
        warnings: result.warnings,
        endpoints: result.endpoints ?? [],
        matrix: result.matrix ?? [],
      });
    } catch (error: unknown) {
      console.error("Scan execution failed", { scanId, error });
      await this.repository.updateScan(scanId, {
        status: "error",
        progress: 100,
        stage: "Scan failed",
        errorCode: error instanceof Error ? error.name.toUpperCase() : "SCAN_FAILED",
        errorMessage: "The scan did not complete. No clean result was recorded.",
      });
    }
  }
}

function parseOptionalRelativePaths(paths: string[], maximumItems: number): string[] {
  const nonEmptyPaths = paths.map((value) => value.trim()).filter(Boolean);
  if (nonEmptyPaths.length === 0) return [];
  return parseRelativePaths(nonEmptyPaths.join("\n"), maximumItems);
}

function correlateFindings(
  sourceFindings: ScanRecord["findings"],
  dynamicFindings: ScanRecord["findings"],
): ScanRecord["findings"] {
  const correlated: ScanRecord["findings"] = [];
  for (const runtime of dynamicFindings) {
    if (!runtime.location || !["suspected", "needs-verification"].includes(runtime.state)) continue;
    const source = sourceFindings.find((candidate) => {
      const endpointPath = candidate.evidence.endpointPath;
      return candidate.category === runtime.category
        && typeof endpointPath === "string"
        && pathTemplateMatches(endpointPath, runtime.location ?? "");
    });
    if (!source) continue;
    correlated.push({
      ...runtime,
      id: `${source.id.slice(0, 12)}${runtime.id.slice(0, 12)}`,
      ruleId: "correlated-source-runtime",
      title: `Correlated source and runtime evidence: ${runtime.title}`,
      description: "A route-aware source pattern and runtime authorization result point to the same endpoint and category.",
      confidence: "high",
      state: "suspected",
      evidence: {
        sourceLocation: source.location ?? "unknown",
        sourceRuleId: source.ruleId,
        endpoint: runtime.location,
        runtimeRuleId: runtime.ruleId,
        runtimeState: runtime.state,
      },
      recommendation: "Review the cited source line, confirm the expected business policy, then reproduce with controlled test data.",
    });
  }
  return correlated;
}

export function pathTemplateMatches(template: string, actual: string): boolean {
  const templateSegments = template.split("/").filter(Boolean);
  const actualSegments = actual.split("?")[0]?.split("/").filter(Boolean) ?? [];
  if (templateSegments.length !== actualSegments.length) return false;
  return templateSegments.every((segment, index) => {
    if (/^\{[^}]+\}$/.test(segment) || /^:[A-Za-z_][A-Za-z0-9_]*$/.test(segment)) return true;
    return segment === actualSegments[index];
  });
}
