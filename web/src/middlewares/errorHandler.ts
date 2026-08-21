import crypto from "node:crypto";
import type { ErrorRequestHandler, NextFunction, Request, Response } from "express";
import { AppError } from "../errors/AppError";
import { removeUploadDirectory } from "./upload";

/** Adds a per-request identifier used in error responses and server logs. */
export function assignRequestId(request: Request, response: Response, next: NextFunction): void {
  const requestId = crypto.randomUUID();
  response.locals.requestId = requestId;
  response.setHeader("x-request-id", requestId);
  next();
}

/** Renders stable error contracts without leaking stack traces or file paths. */
export const errorHandler: ErrorRequestHandler = (error: unknown, request: Request, response: Response, _next) => {
  void removeUploadDirectory(request.uploadDirectory).catch((cleanupError: unknown) => {
    console.error("Failed to remove request upload directory", {
      requestId: response.locals.requestId,
      cleanupError,
    });
  });
  const appError = error instanceof AppError ? error : undefined;
  const statusCode = appError?.statusCode ?? 500;
  const code = appError?.code ?? "INTERNAL_ERROR";
  const message = appError?.message ?? "An unexpected error occurred";

  if (!appError) {
    console.error("Unhandled request error", {
      requestId: response.locals.requestId,
      method: request.method,
      path: request.path,
      error,
    });
  }

  if (request.path.startsWith("/api/")) {
    response.status(statusCode).json({
      success: false,
      error: { code, message },
      timestamp: new Date().toISOString(),
      requestId: response.locals.requestId,
    });
    return;
  }
  response.status(statusCode).render("error", { code, message, requestId: response.locals.requestId });
};
