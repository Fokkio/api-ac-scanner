import { UpstreamError } from "../errors/AppError";
import type { ScannerResult } from "../types/domain";
import type { AuthenticationAdapter, MutationTargetAuthorization, WorkflowStep } from "../types/domain";

export const WORKFLOW_TIMEOUT_MILLISECONDS = 160_000;

interface DeepScannerRequest {
  target: string;
  object_paths: string[];
  admin_paths: string[];
  enumeration_existing_paths: string[];
  enumeration_missing_paths: string[];
  identities: Array<{
    label: string;
    role: string;
    tenant: string;
    headers: Record<string, string>;
  }>;
  policy_rules: Array<{
    method: "GET";
    path: string;
    identity: string;
    expected: "allow" | "deny";
  }>;
}

/** Internal HTTP client for the isolated scanner service. */
export class ScannerClient {
  public constructor(
    private readonly baseUrl: string,
    private readonly internalToken: string,
  ) {}

  /** Runs a public, tokenless quick scan. */
  public quickScan(target: string): Promise<ScannerResult> {
    return this.post<ScannerResult>("/v2/scans/quick", { target }, 45_000);
  }

  /** Runs an authorized cross-user scan with ephemeral credentials. */
  public deepScan(request: DeepScannerRequest): Promise<ScannerResult> {
    return this.post<ScannerResult>("/v2/scans/deep", request, 90_000);
  }

  /** Runs a static scan against one confined upload directory. */
  public sourceScan(repositoryPath: string): Promise<ScannerResult> {
    return this.post<ScannerResult>("/v2/scans/source", { repository_path: repositoryPath }, 330_000);
  }

  /** Builds an endpoint inventory from bounded local artifacts. */
  public discoveryScan(repositoryPath: string, target: string): Promise<ScannerResult> {
    return this.post<ScannerResult>(
      "/v2/discovery",
      { repository_path: repositoryPath, target },
      90_000,
    );
  }

  /** Creates and immediately cleans up one marked local or verified-remote test resource. */
  public mutationScan(request: {
    target: string;
    path: string;
    body: Record<string, unknown>;
    identity: DeepScannerRequest["identities"][number];
    targetAuthorization: MutationTargetAuthorization;
  }): Promise<ScannerResult> {
    return this.post<ScannerResult>("/v3/scans/mutation", {
      target: request.target,
      path: request.path,
      body: request.body,
      identity: request.identity,
      target_authorization: serializeTargetAuthorization(request.targetAuthorization),
    }, 45_000);
  }

  /** Runs a guarded local or verified-remote workflow with optional login acquisition. */
  public workflowScan(request: {
    target: string;
    identity: DeepScannerRequest["identities"][number];
    authentication: AuthenticationAdapter;
    steps: WorkflowStep[];
    targetAuthorization: MutationTargetAuthorization;
  }): Promise<ScannerResult> {
    return this.post<ScannerResult>("/v3/scans/workflow", {
      target: request.target,
      identity: request.identity,
      authentication: {
        type: request.authentication.type,
        path: request.authentication.path,
        username_field: request.authentication.usernameField,
        password_field: request.authentication.passwordField,
        username: request.authentication.username,
        password: request.authentication.password,
        token_json_path: request.authentication.tokenJsonPath,
        header_name: request.authentication.headerName,
        scheme: request.authentication.scheme,
      },
      steps: request.steps,
      target_authorization: serializeTargetAuthorization(request.targetAuthorization),
    }, WORKFLOW_TIMEOUT_MILLISECONDS);
  }

  /** Verifies an exact asset-ownership challenge. */
  public async verifyAsset(origin: string, challenge: string, verificationMethod: string): Promise<boolean> {
    const result = await this.post<{ verified: boolean }>(
      "/v2/assets/verify",
      { origin, challenge, verification_method: verificationMethod },
      15_000,
    );
    return result.verified === true;
  }

  private async post<Result>(endpoint: string, body: unknown, timeoutMilliseconds: number): Promise<Result> {
    const abortController = new AbortController();
    const timeoutHandle = setTimeout(() => abortController.abort(), timeoutMilliseconds);
    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-scanner-token": this.internalToken,
        },
        body: JSON.stringify(body),
        signal: abortController.signal,
      });
      if (!response.ok) {
        throw new UpstreamError(`Scanner rejected the request with status ${response.status}`);
      }
      return (await response.json()) as Result;
    } catch (error: unknown) {
      if (error instanceof UpstreamError) throw error;
      const cause = error instanceof Error ? error.message : "unknown scanner error";
      throw new UpstreamError(`Scanner request failed: ${cause}`);
    } finally {
      clearTimeout(timeoutHandle);
    }
  }
}

function serializeTargetAuthorization(authorization: MutationTargetAuthorization): Record<string, string> {
  if (authorization.mode === "local") return { mode: "local" };
  return {
    mode: authorization.mode,
    challenge: authorization.challenge,
    verification_method: authorization.verificationMethod,
  };
}
