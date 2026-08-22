export type ScanKind = "quick" | "deep" | "source" | "discovery" | "correlation" | "mutation" | "workflow";
export type ScanStatus = "queued" | "running" | "done" | "error";
export type FindingState =
  | "detected"
  | "suspected"
  | "needs-verification"
  | "passed"
  | "not-tested"
  | "error"
  | "verified";

export interface Finding {
  id: string;
  category: string;
  ruleId: string;
  title: string;
  description: string;
  state: FindingState;
  confidence: "high" | "medium" | "low";
  severity: "critical" | "high" | "medium" | "low" | "info";
  owaspId: string;
  location?: string;
  evidence: Record<string, string | number | boolean>;
  recommendation: string;
}

export interface ScanRecord {
  id: string;
  kind: ScanKind;
  target: string;
  status: ScanStatus;
  progress: number;
  stage: string;
  findings: Finding[];
  warnings: string[];
  endpoints: EndpointRecord[];
  matrix: AuthorizationMatrixRow[];
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  errorCode?: string;
  errorMessage?: string;
}

export interface AssetRecord {
  id: string;
  origin: string;
  challenge: string;
  isVerified: boolean;
  verificationMethod?: AssetVerificationMethod;
  createdAt: string;
  verifiedAt?: string;
}

export type ExternalAssetVerificationMethod = "file" | "header" | "dns";
export type AssetVerificationMethod = ExternalAssetVerificationMethod | "local-allowlist";

export type MutationTargetAuthorization =
  | { mode: "local" }
  | {
    mode: "verified-remote";
    challenge: string;
    verificationMethod: ExternalAssetVerificationMethod;
  };

export interface PersistedState {
  version: 2;
  scans: ScanRecord[];
  assets: AssetRecord[];
}

export interface ScannerResult {
  findings: Finding[];
  warnings: string[];
  endpoints?: EndpointRecord[];
  matrix?: AuthorizationMatrixRow[];
}

export type EndpointSourceType = "openapi" | "har" | "postman" | "source";
export type EndpointCandidateType = "object" | "function" | "enumeration" | "other";

export interface EndpointRecord {
  method: string;
  path: string;
  sourceType: EndpointSourceType;
  sourceFile: string;
  line: number;
  candidateType: EndpointCandidateType;
  confidence: "high" | "medium" | "low";
}

export interface AuthorizationMatrixRow {
  method: string;
  path: string;
  identity: string;
  role: string;
  tenant: string;
  expected: "allow" | "deny";
  actual: "allow" | "deny" | "indeterminate";
  actualStatus: number;
  matchesExpectation: boolean;
  skippedAfterPriorFailure?: boolean;
}

export interface DeepScanInput {
  assetId: string;
  objectPaths: string[];
  adminPaths: string[];
  enumerationExistingPaths: string[];
  enumerationMissingPaths: string[];
  identities: [TestIdentity, TestIdentity];
  policyRules: AuthorizationPolicyRule[];
}

export interface TestIdentity {
  label: string;
  role: string;
  tenant: string;
  headers: Record<string, string>;
}

export interface AuthorizationPolicyRule {
  method: "GET";
  path: string;
  identity: string;
  expected: "allow" | "deny";
}

export interface MutationScanInput {
  assetId: string;
  path: string;
  body: string;
  confirmation: string;
  identity: TestIdentity;
}

export interface WorkflowStep {
  name: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  body?: Record<string, unknown>;
  expected: "allow" | "deny";
}

export interface AuthenticationAdapter {
  type: "none" | "json-login";
  path?: string;
  usernameField?: string;
  passwordField?: string;
  username?: string;
  password?: string;
  tokenJsonPath?: string;
  headerName?: string;
  scheme?: string;
}

export interface WorkflowScanInput {
  assetId: string;
  confirmation: string;
  identity: TestIdentity;
  authentication: AuthenticationAdapter;
  steps: WorkflowStep[];
}
