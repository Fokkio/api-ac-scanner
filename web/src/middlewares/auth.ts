import type { NextFunction, Request, Response } from "express";
import { AuthenticationError } from "../errors/AppError";

/** Requires an authenticated administrator session. */
export function requireAuthentication(request: Request, response: Response, next: NextFunction): void {
  if (request.session.isAuthenticated) {
    next();
    return;
  }
  if (request.path.startsWith("/api/")) {
    next(new AuthenticationError());
    return;
  }
  response.redirect("/login");
}
