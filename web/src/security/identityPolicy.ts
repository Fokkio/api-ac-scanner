import { ValidationError } from "../errors/AppError";
import type { TestIdentity } from "../types/domain";

const AUTH_TYPES = new Set(["none", "bearer", "basic", "cookie", "api-key", "custom-headers"]);
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const FORBIDDEN_HEADERS = new Set([
  "connection", "content-length", "host", "proxy-authorization", "te", "trailer",
  "transfer-encoding", "upgrade", "x-scanner-token",
]);

interface IdentityProfileOptions {
  allowEmptyAuthentication?: boolean;
}

/** Converts one form profile into bounded request headers kept only in job memory. */
export function parseIdentityProfile(
  input: Record<string, unknown>,
  options: IdentityProfileOptions = {},
): TestIdentity {
  const label = normalizeMetadata(input.label, "Identity label", true);
  const role = normalizeMetadata(input.role, "Role", false);
  const tenant = normalizeMetadata(input.tenant, "Tenant", false);
  const authType = readString(input.authType, "Authentication type");
  if (!AUTH_TYPES.has(authType)) throw new ValidationError("Unsupported authentication type");

  const credential = readString(input.credential, "Credential");
  if (authType === "none" || (options.allowEmptyAuthentication && credential.trim() === "")) {
    if (!options.allowEmptyAuthentication || credential.trim() !== "") {
      throw new ValidationError("Empty authentication is allowed only with a login adapter");
    }
    return { label, role, tenant, headers: {} };
  }
  if (credential.length < 3 || credential.length > 8192 || hasControlExceptTab(credential)) {
    throw new ValidationError("Credential length or characters are invalid");
  }
  const headers = buildHeaders(authType, credential, input.headerName);
  return { label, role, tenant, headers };
}

function buildHeaders(authType: string, credential: string, rawHeaderName: unknown): Record<string, string> {
  if (authType === "bearer") {
    const token = credential.trim().replace(/^Bearer\s+/i, "");
    if (token.length < 16) throw new ValidationError("Bearer token must contain at least 16 characters");
    return { authorization: `Bearer ${token}` };
  }
  if (authType === "basic") {
    const separator = credential.indexOf(":");
    if (separator < 1 || separator === credential.length - 1) {
      throw new ValidationError("Basic credential must use username:password");
    }
    return { authorization: `Basic ${Buffer.from(credential, "utf8").toString("base64")}` };
  }
  if (authType === "cookie") return { cookie: credential.trim() };
  if (authType === "api-key") {
    const name = normalizeHeaderName(readString(rawHeaderName, "API key header"));
    return { [name]: credential.trim() };
  }
  return parseCustomHeaders(credential);
}

function parseCustomHeaders(rawJson: string): Record<string, string> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch {
    throw new ValidationError("Custom headers must be a JSON object");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ValidationError("Custom headers must be a JSON object");
  }
  const entries = Object.entries(parsed as Record<string, unknown>);
  if (entries.length < 1 || entries.length > 5) {
    throw new ValidationError("Provide between 1 and 5 custom headers");
  }
  return Object.fromEntries(entries.map(([name, value]) => {
    if (typeof value !== "string" || value.length < 1 || value.length > 8192 || hasControlExceptTab(value)) {
      throw new ValidationError("Custom header values must be bounded strings");
    }
    return [normalizeHeaderName(name), value];
  }));
}

function normalizeHeaderName(rawName: string): string {
  const name = rawName.trim().toLowerCase();
  if (!HEADER_NAME.test(name) || FORBIDDEN_HEADERS.has(name)) {
    throw new ValidationError("Header name is invalid or reserved");
  }
  return name;
}

function normalizeMetadata(value: unknown, field: string, required: boolean): string {
  const normalized = typeof value === "string" ? value.trim() : "";
  if ((required && normalized.length < 1) || normalized.length > 64 || hasControlExceptTab(normalized)) {
    throw new ValidationError(`${field} is invalid`);
  }
  return normalized;
}

function readString(value: unknown, field: string): string {
  if (typeof value !== "string") throw new ValidationError(`${field} is required`);
  return value;
}

function hasControlExceptTab(value: string): boolean {
  return [...value].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return (code < 32 && code !== 9) || code === 127;
  });
}
