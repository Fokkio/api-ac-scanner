import crypto from "node:crypto";
import fs from "node:fs";
import fsPromises from "node:fs/promises";
import path from "node:path";
import multer from "multer";
import type { RequestHandler } from "express";
import { ForbiddenError, ValidationError } from "../errors/AppError";
import { isAllowedDiscoveryFile, isAllowedSourceFile } from "../security/inputPolicy";
import { hasValidCsrfToken } from "./csrf";

const MAX_FILE_COUNT = 25;
const MAX_FILE_BYTES = 1_048_576;

/** Creates a bounded Multer handler that stores every request in one directory. */
export function createSourceUploadHandler(uploadRoot: string): RequestHandler {
  return createUploadHandler(uploadRoot, "sources", isAllowedSourceFile);
}

/** Creates a bounded upload handler for OpenAPI, HAR, Postman and source artifacts. */
export function createDiscoveryUploadHandler(uploadRoot: string): RequestHandler {
  return createUploadHandler(uploadRoot, "artifacts", isAllowedDiscoveryFile);
}

function createUploadHandler(
  uploadRoot: string,
  fieldName: string,
  isAllowedFile: (filename: string) => boolean,
): RequestHandler {
  const storage = multer.diskStorage({
    destination: (request, _file, callback) => {
      if (!request.uploadDirectory) {
        const directory = path.join(uploadRoot, crypto.randomBytes(24).toString("hex"));
        fs.mkdirSync(directory, { recursive: true });
        request.uploadDirectory = directory;
      }
      callback(null, request.uploadDirectory);
    },
    filename: (_request, file, callback) => {
      const safeName = path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g, "_");
      callback(null, `${crypto.randomBytes(6).toString("hex")}-${safeName}`);
    },
  });

  return multer({
    storage,
    limits: { files: MAX_FILE_COUNT, fileSize: MAX_FILE_BYTES, fields: 5 },
    fileFilter: (request, file, callback) => {
      if (!hasValidCsrfToken(request)) {
        callback(new ForbiddenError("Invalid or expired request token"));
        return;
      }
      if (!isAllowedFile(file.originalname)) {
        callback(new ValidationError("Unsupported upload file type"));
        return;
      }
      callback(null, true);
    },
  }).array(fieldName, MAX_FILE_COUNT);
}

/** Removes an upload directory created for a rejected or failed request. */
export async function removeUploadDirectory(uploadDirectory: string | undefined): Promise<void> {
  if (!uploadDirectory) return;
  await fsPromises.rm(uploadDirectory, { recursive: true, force: true });
}

/** Removes only request directories left behind by an interrupted prior process. */
export async function removeOrphanedUploadDirectories(uploadRoot: string): Promise<void> {
  const resolvedRoot = path.resolve(uploadRoot);
  const entries = await fsPromises.readdir(resolvedRoot, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const candidate = path.resolve(resolvedRoot, entry.name);
    if (path.dirname(candidate) !== resolvedRoot) {
      throw new Error("Refusing to clean an upload path outside the configured root");
    }
    await fsPromises.rm(candidate, { recursive: true, force: true });
  }
}
