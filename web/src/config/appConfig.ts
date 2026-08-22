import path from "node:path";

const HTTPS_PORT = "443";
const MAX_TCP_PORT = 65_535;

export interface AppConfig {
  port: number;
  listenHost: "127.0.0.1" | "0.0.0.0";
  isProduction: boolean;
  sessionSecret: string;
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
  remoteSafeMutationEnabled: boolean;
  remoteSafeMutationAllowedOrigins: ReadonlySet<string>;
}

function readBoolean(name: string, fallback: boolean): boolean {
  const value = process.env[name]?.trim().toLowerCase();
  if (!value) return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be either true or false`);
}

function readInteger(name: string, fallback: number, minimum: number, maximum = Number.MAX_SAFE_INTEGER): number {
  const rawValue = process.env[name];
  if (!rawValue) return fallback;
  const normalizedValue = rawValue.trim();
  const parsedValue = /^\d+$/.test(normalizedValue) ? Number(normalizedValue) : Number.NaN;
  if (!Number.isInteger(parsedValue) || parsedValue < minimum || parsedValue > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return parsedValue;
}

function readListenHost(): AppConfig["listenHost"] {
  const listenHost = process.env.LISTEN_HOST?.trim() || "127.0.0.1";
  if (listenHost === "127.0.0.1" || listenHost === "0.0.0.0") return listenHost;
  throw new Error("LISTEN_HOST must be 127.0.0.1 or 0.0.0.0");
}

function readRequiredSecret(name: string, isTest: boolean): string {
  const value = process.env[name];
  if (value && value.length >= 16) return value;
  if (isTest) return `test-only-${name.toLowerCase()}-secret`;
  throw new Error(`${name} must be set and contain at least 16 characters`);
}

function readCsv(name: string, fallback: string): string[] {
  return (process.env[name] ?? fallback)
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
}

function readPortSet(name: string, fallback: string): ReadonlySet<number> {
  const ports = readCsv(name, fallback).map((value) => /^\d+$/.test(value) ? Number(value) : Number.NaN);
  if (ports.length === 0 || ports.some((port) => !Number.isInteger(port) || port < 1 || port > MAX_TCP_PORT)) {
    throw new Error(`${name} must contain comma-separated ports between 1 and ${MAX_TCP_PORT}`);
  }
  return new Set(ports);
}

function readHttpsOriginSet(name: string): ReadonlySet<string> {
  return new Set(readCsv(name, "").map((rawOrigin) => normalizeHttpsOrigin(name, rawOrigin)));
}

function normalizeHttpsOrigin(name: string, rawOrigin: string): string {
  let parsedOrigin: URL;
  try {
    parsedOrigin = new URL(rawOrigin);
  } catch {
    throw new Error(`${name} must contain valid absolute HTTPS origins`);
  }
  if (!isExactHttpsOrigin(parsedOrigin)) {
    throw new Error(`${name} must contain exact HTTPS origins on port 443 without paths or credentials`);
  }
  return parsedOrigin.origin;
}

function isExactHttpsOrigin(origin: URL): boolean {
  const hasCredentials = Boolean(origin.username || origin.password);
  const hasExtraLocation = origin.pathname !== "/" || Boolean(origin.search || origin.hash);
  const hasInvalidPort = Boolean(origin.port && origin.port !== HTTPS_PORT);
  return origin.protocol === "https:" && !hasCredentials && !hasExtraLocation && !hasInvalidPort;
}

/** Loads and validates application configuration from environment variables. */
export function loadAppConfig(): AppConfig {
  const nodeEnvironment = process.env.NODE_ENV ?? "development";
  const isTest = nodeEnvironment === "test";
  const isProduction = nodeEnvironment === "production";
  const remoteSafeMutationEnabled = readBoolean("REMOTE_SAFE_MUTATION_ENABLED", false);
  const remoteSafeMutationAllowedOrigins = readHttpsOriginSet("REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS");
  if (remoteSafeMutationEnabled && remoteSafeMutationAllowedOrigins.size === 0) {
    throw new Error("REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS is required when remote safe mutation is enabled");
  }

  return {
    port: readInteger("PORT", 3000, 1, MAX_TCP_PORT),
    listenHost: readListenHost(),
    isProduction,
    sessionSecret: readRequiredSecret("SESSION_SECRET", isTest),
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
      remoteSafeMutationEnabled,
      remoteSafeMutationAllowedOrigins,
    },
  };
}
