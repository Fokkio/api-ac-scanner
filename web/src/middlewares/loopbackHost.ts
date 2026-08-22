import type { NextFunction, Request, Response } from "express";
import { ForbiddenError } from "../errors/AppError";

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
