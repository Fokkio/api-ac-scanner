import path from "node:path";

export interface AppConfig {
  port: number;
  isProduction: boolean;
  sessionCookieSecure: boolean;
  publicBaseUrl: string;
  sessionSecret: string;
  adminUsername: string;
  adminPassword: string;
  scannerInternalToken: string;
  scannerUrl: string;
  dataDirectory: string;
  uploadRoot: string;
  reportTtlHours: number;
  maxStoredReports: number;
  queueCapacity: number;
  scanConcurrency: number;
  maxSessions: number;
  targetPolicy: TargetPolicy;
}

export interface TargetPolicy {
  localMode: boolean;
  localAllowedHosts: ReadonlySet<string>;
  localAllowedPorts: ReadonlySet<number>;
}

function readBoolean(name: string, fallback: boolean): boolean {
  const value = process.env[name]?.trim().toLowerCase();
  if (!value) return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be either true or false`);
}

function readInteger(name: string, fallback: number, minimum: number): number {
  const rawValue = process.env[name];
  if (!rawValue) return fallback;
  const parsedValue = Number.parseInt(rawValue, 10);
  if (!Number.isInteger(parsedValue) || parsedValue < minimum) {
    throw new Error(`${name} must be an integer greater than or equal to ${minimum}`);
  }
  return parsedValue;
}

function readRequiredSecret(name: string, isTest: boolean): string {
  const value = process.env[name];
  if (value && value.length >= 16) return value;
  if (isTest) return `test-only-${name.toLowerCase()}-secret`;
  throw new Error(`${name} must be set and contain at least 16 characters`);
}

function readRequiredText(name: string, isTest: boolean): string {
  const value = process.env[name]?.trim();
  if (value) return value;
  if (isTest) return "admin";
  throw new Error(`${name} must be set`);
}

function readCsv(name: string, fallback: string): string[] {
  return (process.env[name] ?? fallback)
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
}

function readPortSet(name: string, fallback: string): ReadonlySet<number> {
  const ports = readCsv(name, fallback).map((value) => Number.parseInt(value, 10));
  if (ports.length === 0 || ports.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) {
    throw new Error(`${name} must contain comma-separated ports between 1 and 65535`);
  }
  return new Set(ports);
}

/** Loads and validates application configuration from environment variables. */
export function loadAppConfig(): AppConfig {
  const nodeEnvironment = process.env.NODE_ENV ?? "development";
  const isTest = nodeEnvironment === "test";
  const isProduction = nodeEnvironment === "production";
  const sessionCookieSecure = readBoolean("SESSION_COOKIE_SECURE", false);
  const publicBaseUrl = validatePublicBaseUrl(
    process.env.PUBLIC_BASE_URL ?? "http://127.0.0.1:3000",
    sessionCookieSecure,
  );

  return {
    port: readInteger("PORT", 3000, 1),
    isProduction,
    sessionCookieSecure,
    publicBaseUrl,
    sessionSecret: readRequiredSecret("SESSION_SECRET", isTest),
    adminUsername: readRequiredText("ADMIN_USERNAME", isTest),
    adminPassword: readRequiredSecret("ADMIN_PASSWORD", isTest),
    scannerInternalToken: readRequiredSecret("SCANNER_INTERNAL_TOKEN", isTest),
    scannerUrl: process.env.SCANNER_URL ?? "http://scanner:8001",
    dataDirectory: process.env.DATA_DIR ?? path.resolve(process.cwd(), "data"),
    uploadRoot: process.env.UPLOAD_ROOT ?? path.resolve(process.cwd(), "uploads"),
    reportTtlHours: readInteger("REPORT_TTL_HOURS", 168, 1),
    maxStoredReports: readInteger("MAX_STORED_REPORTS", 200, 10),
    queueCapacity: readInteger("QUEUE_CAPACITY", 50, 1),
    scanConcurrency: readInteger("SCAN_CONCURRENCY", 2, 1),
    maxSessions: readInteger("MAX_SESSIONS", 1000, 10),
    targetPolicy: {
      localMode: readBoolean("LOCAL_MODE", true),
      localAllowedHosts: new Set(readCsv(
        "LOCAL_ALLOWED_HOSTS",
        "host.docker.internal,localhost,127.0.0.1,::1,demo-api",
      )),
      localAllowedPorts: readPortSet(
        "LOCAL_ALLOWED_PORTS",
        "80,443,3000,4000,4100,5000,8000,8080,8443",
      ),
    },
  };
}

function validatePublicBaseUrl(rawValue: string, sessionCookieSecure: boolean): string {
  let publicUrl: URL;
  try {
    publicUrl = new URL(rawValue);
  } catch {
    throw new Error("PUBLIC_BASE_URL must be a valid absolute URL");
  }
  const isLoopback = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]).has(publicUrl.hostname);
  if (publicUrl.protocol !== "http:" && publicUrl.protocol !== "https:") {
    throw new Error("PUBLIC_BASE_URL must use HTTP or HTTPS");
  }
  if (!isLoopback && (publicUrl.protocol !== "https:" || !sessionCookieSecure)) {
    throw new Error("Non-loopback deployments require HTTPS and SESSION_COOKIE_SECURE=true");
  }
  if (publicUrl.protocol === "http:" && sessionCookieSecure) {
    throw new Error("Secure session cookies require an HTTPS PUBLIC_BASE_URL");
  }
  return publicUrl.toString();
}
