import crypto from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { ForbiddenError } from "../errors/AppError";

function digest(value: string): Buffer {
  return crypto.createHash("sha256").update(value, "utf8").digest();
}

/** Returns the current session CSRF token, creating it when absent. */
export function getCsrfToken(request: Request): string {
  if (!request.session.csrfToken) request.session.csrfToken = crypto.randomBytes(32).toString("base64url");
  return request.session.csrfToken;
}

/** Rejects state-changing requests whose CSRF token does not match the session. */
export function requireCsrf(request: Request, _response: Response, next: NextFunction): void {
  const suppliedToken = extractCsrfToken(request);
  const expectedToken = request.session.csrfToken;
  if (!suppliedToken || !expectedToken || !crypto.timingSafeEqual(digest(suppliedToken), digest(expectedToken))) {
    next(new ForbiddenError("Invalid or expired request token"));
    return;
  }
  next();
}

function extractCsrfToken(request: Request): string | undefined {
  const headerValue = request.get("x-csrf-token");
  if (headerValue) return headerValue;
  if (typeof request.body?._csrf === "string") return request.body._csrf;
  return undefined;
}
