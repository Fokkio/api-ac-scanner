import type { NextFunction, Request, Response } from "express";
import { ForbiddenError } from "../errors/AppError";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

/** Rejects requests whose Host header is not an explicit loopback address. */
export function requireLoopbackHost(request: Request, _response: Response, next: NextFunction): void {
  const hostname = parseRequestHostname(request.protocol, request.get("host"));
  if (!hostname || !LOOPBACK_HOSTS.has(hostname)) {
    next(new ForbiddenError("The local tool accepts loopback Host headers only"));
    return;
  }
  next();
}

/** Rejects cross-origin browser mutations before request bodies or uploads are processed. */
export function requireSameOriginBrowserMutation(
  request: Request,
  _response: Response,
  next: NextFunction,
): void {
  if (SAFE_METHODS.has(request.method)) {
    next();
    return;
  }
  const fetchSite = request.get("sec-fetch-site");
  if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") {
    next(new ForbiddenError("Cross-origin browser requests are not allowed"));
    return;
  }
  const origin = request.get("origin");
  if (!origin) {
    next();
    return;
  }
  const host = request.get("host");
  if (!host || !matchesRequestOrigin(origin, request.protocol, host)) {
    next(new ForbiddenError("Cross-origin browser requests are not allowed"));
    return;
  }
  next();
}

function matchesRequestOrigin(origin: string, protocol: string, host: string): boolean {
  try {
    return new URL(origin).origin === new URL(`${protocol}://${host}`).origin;
  } catch {
    return false;
  }
}

function parseRequestHostname(protocol: string, host: string | undefined): string | undefined {
  if (!host) return undefined;
  try {
    const parsedHost = new URL(`${protocol}://${host}`);
    if (parsedHost.username || parsedHost.password || parsedHost.pathname !== "/") return undefined;
    return parsedHost.hostname.toLowerCase();
  } catch {
    return undefined;
  }
}
