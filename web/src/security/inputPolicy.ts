import path from "node:path";
import { ValidationError } from "../errors/AppError";
import type { TargetPolicy } from "../config/appConfig";

const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);
const ALLOWED_PORTS = new Set(["", "80", "443"]);
const SOURCE_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx", ".py", ".php", ".java"]);
const DISCOVERY_EXTENSIONS = new Set([...SOURCE_EXTENSIONS, ".json", ".yaml", ".yml", ".har"]);
const DISPOSABLE_TEST_NAMESPACE = "/__ac_test__/";

/** Validates and normalizes a public HTTP target supplied by a user. */
export function normalizePublicTarget(rawTarget: unknown, policy?: TargetPolicy): string {
  if (typeof rawTarget !== "string" || rawTarget.length < 8 || rawTarget.length > 2048) {
    throw new ValidationError("Enter a valid HTTP or HTTPS URL");
  }

  let targetUrl: URL;
  try {
    targetUrl = new URL(rawTarget.trim());
  } catch {
    throw new ValidationError("Enter a valid absolute URL");
  }

  if (!ALLOWED_PROTOCOLS.has(targetUrl.protocol)) {
    throw new ValidationError("Only HTTP and HTTPS targets are supported");
  }
  if (targetUrl.username || targetUrl.password) {
    throw new ValidationError("URLs containing credentials are not allowed");
  }
  const effectivePort = Number.parseInt(targetUrl.port || (targetUrl.protocol === "https:" ? "443" : "80"), 10);
  const isAllowedLocal = policy?.localMode === true
    && policy.localAllowedHosts.has(normalizeHostname(targetUrl.hostname));
  const isAllowedPort = isAllowedLocal
    ? policy.localAllowedPorts.has(effectivePort)
    : ALLOWED_PORTS.has(targetUrl.port);
  if (!isAllowedPort) {
    throw new ValidationError("Target host or port is not allowed by the active scan policy");
  }

  targetUrl.hash = "";
  return targetUrl.toString();
}

/** Returns true only for a host explicitly enabled by local-mode configuration. */
export function isConfiguredLocalTarget(targetUrl: URL, policy: TargetPolicy): boolean {
  return policy.localMode && policy.localAllowedHosts.has(normalizeHostname(targetUrl.hostname));
}

function normalizeHostname(hostname: string): string {
  return hostname.toLowerCase().replace(/^\[|\]$/g, "");
}

/** Parses a bounded list of same-origin relative paths. */
export function parseRelativePaths(rawPaths: unknown, maximumItems: number): string[] {
  if (typeof rawPaths !== "string") throw new ValidationError("Endpoint paths are required");
  const uniquePaths = [...new Set(rawPaths.split(/[\n,]/).map((value) => value.trim()).filter(Boolean))];
  if (uniquePaths.length === 0 || uniquePaths.length > maximumItems) {
    throw new ValidationError(`Provide between 1 and ${maximumItems} endpoint paths`);
  }

  for (const relativePath of uniquePaths) {
    const hasControlCharacter = [...relativePath].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint < 32 || codePoint === 127;
    });
    if (
      !relativePath.startsWith("/")
      || relativePath.startsWith("//")
      || relativePath.includes("\\")
      || relativePath.includes("#")
      || hasControlCharacter
    ) {
      throw new ValidationError("Endpoint entries must be relative paths beginning with one slash");
    }
    if (relativePath.length > 512) throw new ValidationError("An endpoint path is too long");
  }
  return uniquePaths;
}

/** Returns true only when a path starts inside the disposable test namespace. */
export function isDisposableTestPath(relativePath: string): boolean {
  return relativePath.startsWith(DISPOSABLE_TEST_NAMESPACE)
    && !relativePath.includes("?")
    && !relativePath.includes("#");
}

/** Normalizes a bearer token value without persisting or logging it. */
export function normalizeToken(rawToken: unknown): string {
  if (typeof rawToken !== "string") throw new ValidationError("Both test-user tokens are required");
  const normalizedToken = rawToken.trim().replace(/^Bearer\s+/i, "");
  if (normalizedToken.length < 16 || normalizedToken.length > 8192) {
    throw new ValidationError("Each token must contain between 16 and 8192 characters");
  }
  return normalizedToken;
}

/** Returns true when an uploaded source filename has a supported extension. */
export function isAllowedSourceFile(filename: string): boolean {
  return SOURCE_EXTENSIONS.has(path.extname(filename).toLowerCase());
}

/** Returns true when an uploaded API inventory artifact has a supported extension. */
export function isAllowedDiscoveryFile(filename: string): boolean {
  return DISCOVERY_EXTENSIONS.has(path.extname(filename).toLowerCase());
}
