import crypto from "node:crypto";
import fs from "node:fs";
import fsPromises from "node:fs/promises";
import path from "node:path";
import multer from "multer";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import { ValidationError } from "../errors/AppError";
import { isAllowedDiscoveryFile, isAllowedSourceFile } from "../security/inputPolicy";

const MAX_FILE_COUNT = 25;
const MAX_FILE_BYTES = 1_048_576;

/** Creates one request-scoped upload directory before Multer processes files. */
export function createUploadDirectory(uploadRoot: string): RequestHandler {
  return (request: Request, _response: Response, next: NextFunction) => {
    const directory = path.join(uploadRoot, crypto.randomBytes(24).toString("hex"));
    fs.mkdirSync(directory, { recursive: true });
    request.uploadDirectory = directory;
    next();
  };
}

/** Creates a bounded Multer handler that stores every request in one directory. */
export function createSourceUploadHandler(): RequestHandler {
  return createUploadHandler("sources", isAllowedSourceFile);
}

/** Creates a bounded upload handler for OpenAPI, HAR, Postman and source artifacts. */
export function createDiscoveryUploadHandler(): RequestHandler {
  return createUploadHandler("artifacts", isAllowedDiscoveryFile);
}

function createUploadHandler(
  fieldName: string,
  isAllowedFile: (filename: string) => boolean,
): RequestHandler {
  const storage = multer.diskStorage({
    destination: (request, _file, callback) => {
      if (!request.uploadDirectory) {
        callback(new Error("Upload directory was not initialized"), "");
        return;
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
    fileFilter: (_request, file, callback) => {
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
