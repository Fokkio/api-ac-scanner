import crypto from "node:crypto";
import type { ErrorRequestHandler, NextFunction, Request, Response } from "express";
import multer from "multer";
import { AppError, RequestTooLargeError, ValidationError } from "../errors/AppError";
import { removeUploadDirectory } from "./upload";

/** Adds a per-request identifier used in error responses and server logs. */
export function assignRequestId(_request: Request, response: Response, next: NextFunction): void {
  const requestId = crypto.randomUUID();
  response.locals.requestId = requestId;
  response.setHeader("x-request-id", requestId);
  next();
}

/** Renders stable error contracts without leaking stack traces or file paths. */
export const errorHandler: ErrorRequestHandler = (error: unknown, request: Request, response: Response, _next) => {
  void handleRequestError(error, request, response);
};

async function handleRequestError(error: unknown, request: Request, response: Response): Promise<void> {
  try {
    await removeUploadDirectory(request.uploadDirectory);
  } catch (cleanupError: unknown) {
    console.error("Failed to remove request upload directory", {
      requestId: response.locals.requestId,
      cleanupError,
    });
  }
  const appError = normalizeKnownError(error);
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
}

function normalizeKnownError(error: unknown): AppError | undefined {
  if (error instanceof AppError) return error;
  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return new RequestTooLargeError("An uploaded file exceeded the 1 MiB limit");
    }
    return new ValidationError("The multipart upload did not match the expected limits or fields");
  }
  if (isBodyParserLimitError(error)) return new RequestTooLargeError();
  return undefined;
}

function isBodyParserLimitError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const candidate = error as { status?: unknown; type?: unknown };
  return candidate.status === 413 && candidate.type === "entity.too.large";
}
