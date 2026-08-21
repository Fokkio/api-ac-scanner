import { ValidationError } from "../errors/AppError";
import type { AuthenticationAdapter, WorkflowStep } from "../types/domain";
import { isDisposableTestPath, parseRelativePaths } from "./inputPolicy";

const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const SAFE_NAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const MAX_AUTHENTICATION_REQUEST_BYTES = 4096;

/** Parses a bounded disposable workflow without retaining raw JSON after queueing. */
export function parseWorkflowSteps(raw: unknown): WorkflowStep[] {
  const parsed = parseJson(raw, "Workflow steps", 24_000);
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 8) {
    throw new ValidationError("Workflow must contain between 1 and 8 steps");
  }
  const names = new Set<string>();
  return parsed.map((value): WorkflowStep => {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new ValidationError("Each workflow step must be an object");
    }
    const step = value as Record<string, unknown>;
    const name = boundedString(step.name, "Workflow step name", 64);
    if (names.has(name)) throw new ValidationError("Workflow step names must be unique");
    names.add(name);
    const method = boundedString(step.method, "Workflow method", 8).toUpperCase();
    if (!METHODS.has(method)) throw new ValidationError("Workflow method is not supported");
    const [path] = parseRelativePaths(step.path, 1);
    if (!path || !isDisposableTestPath(path)) {
      throw new ValidationError("Workflow paths must be query-free and under /__ac_test__/");
    }
    if (step.expected !== "allow" && step.expected !== "deny") {
      throw new ValidationError("Workflow expected value must be allow or deny");
    }
    const body = step.body;
    if (["POST", "PUT", "PATCH"].includes(method)) {
      if (!body || typeof body !== "object" || Array.isArray(body)
        || (body as Record<string, unknown>).apiAcScannerTest !== true) {
        throw new ValidationError("POST, PUT and PATCH bodies must contain apiAcScannerTest: true");
      }
      if (Buffer.byteLength(JSON.stringify(body), "utf8") > 4096) {
        throw new ValidationError("Workflow step body is too large");
      }
    } else if (body !== undefined && body !== null) {
      throw new ValidationError("GET and DELETE workflow steps cannot include a body");
    }
    return {
      name,
      method: method as WorkflowStep["method"],
      path,
      ...(body && typeof body === "object" ? { body: body as Record<string, unknown> } : {}),
      expected: step.expected,
    };
  });
}

/** Parses an optional same-origin JSON login adapter; secrets remain in the queued closure only. */
export function parseAuthenticationAdapter(raw: unknown): AuthenticationAdapter {
  if (typeof raw !== "string" || raw.trim() === "") return { type: "none" };
  const parsed = parseJson(raw, "Authentication adapter", 20_000);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ValidationError("Authentication adapter must be a JSON object");
  }
  const adapter = parsed as Record<string, unknown>;
  if (adapter.type === "none") return { type: "none" };
  if (adapter.type !== "json-login") throw new ValidationError("Unsupported authentication adapter");
  const [path] = parseRelativePaths(adapter.path, 1);
  if (!path || path.includes("?")) throw new ValidationError("Login path must not contain a query");
  const usernameField = boundedSafeName(adapter.usernameField ?? "username", "Username field");
  const passwordField = boundedSafeName(adapter.passwordField ?? "password", "Password field");
  const tokenJsonPath = boundedString(adapter.tokenJsonPath ?? "accessToken", "Token JSON path", 128);
  if (!tokenJsonPath.split(".").every((part) => SAFE_NAME.test(part))) {
    throw new ValidationError("Token JSON path is invalid");
  }
  const headerName = boundedString(adapter.headerName ?? "authorization", "Token header", 64).toLowerCase();
  if (!HEADER_NAME.test(headerName) || ["host", "content-length", "x-scanner-token"].includes(headerName)) {
    throw new ValidationError("Token header is invalid or reserved");
  }
  const scheme = boundedString(adapter.scheme ?? "Bearer", "Token scheme", 32);
  if (!/^[A-Za-z][A-Za-z0-9._-]{0,31}$/.test(scheme)) {
    throw new ValidationError("Token scheme is invalid");
  }
  const username = boundedSecret(adapter.username, "Test username");
  const password = boundedSecret(adapter.password, "Test password");
  validateAuthenticationPayloadSize(usernameField, passwordField, username, password);
  return {
    type: "json-login", path,
    usernameField, passwordField,
    username, password,
    tokenJsonPath, headerName,
    scheme,
  };
}

function parseJson(raw: unknown, field: string, maxLength: number): unknown {
  if (typeof raw !== "string" || raw.length < 1 || raw.length > maxLength) {
    throw new ValidationError(`${field} JSON is required and must be bounded`);
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new ValidationError(`${field} must be valid JSON`);
  }
}

function boundedSafeName(value: unknown, field: string): string {
  const normalized = boundedString(value, field, 64);
  if (!SAFE_NAME.test(normalized)) throw new ValidationError(`${field} is invalid`);
  return normalized;
}

function boundedSecret(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 8192
    || /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(value)) {
    throw new ValidationError(`${field} is invalid`);
  }
  return value;
}

function validateAuthenticationPayloadSize(
  usernameField: string,
  passwordField: string,
  username: string,
  password: string,
): void {
  const payload = JSON.stringify({ [usernameField]: username, [passwordField]: password });
  if (Buffer.byteLength(payload, "utf8") > MAX_AUTHENTICATION_REQUEST_BYTES) {
    throw new ValidationError("Authentication request exceeded 4096 bytes");
  }
}

function boundedString(value: unknown, field: string, maximum: number): string {
  if (typeof value !== "string") throw new ValidationError(`${field} is required`);
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > maximum || /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(normalized)) {
    throw new ValidationError(`${field} is invalid`);
  }
  return normalized;
}
