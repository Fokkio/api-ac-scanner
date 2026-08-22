import type { Express, Request } from "express";
import { ValidationError } from "../errors/AppError";
import { asyncHandler } from "../middlewares/asyncHandler";
import { getCsrfToken, requireCsrf } from "../middlewares/csrf";
import {
  createDiscoveryUploadHandler,
  createSourceUploadHandler,
  removeUploadDirectory,
} from "../middlewares/upload";
import type { RouteDependencies } from "./registerRoutes";

export function registerDiscoveryRoutes(app: Express, dependencies: RouteDependencies): void {
  const uploadHandler = createDiscoveryUploadHandler(dependencies.config.uploadRoot);
  app.get("/discovery", (request, response) => {
    response.render("discovery", {
      csrfToken: getCsrfToken(request),
      assets: dependencies.assetService.listAssets().filter((asset) => asset.isVerified),
    });
  });
  app.post(
    "/scans/discovery",
    uploadHandler,
    requireCsrf,
    asyncHandler(async (request, response) => {
      const uploadedFiles = Array.isArray(request.files) ? request.files : [];
      if (!request.uploadDirectory || uploadedFiles.length === 0) {
        await removeUploadDirectory(request.uploadDirectory);
        throw new ValidationError("Select at least one discovery artifact");
      }
      try {
        const assetId = readBodyString(request, "assetId");
        const scan = await dependencies.scanService.createDiscoveryScan(assetId, request.uploadDirectory);
        response.redirect(`/reports/${scan.id}`);
      } catch (error: unknown) {
        await removeUploadDirectory(request.uploadDirectory);
        throw error;
      }
    }),
  );
}

export function registerSourceScanRoutes(app: Express, dependencies: RouteDependencies): void {
  const uploadHandler = createSourceUploadHandler(dependencies.config.uploadRoot);
  app.get("/source", (request, response) => {
    response.render("source", { csrfToken: getCsrfToken(request) });
  });
  app.post(
    "/scans/source",
    uploadHandler,
    requireCsrf,
    asyncHandler(async (request, response) => {
      const uploadedFiles = Array.isArray(request.files) ? request.files : [];
      if (!request.uploadDirectory || uploadedFiles.length === 0) {
        await removeUploadDirectory(request.uploadDirectory);
        throw new ValidationError("Select at least one supported source file");
      }
      try {
        const scan = await dependencies.scanService.createSourceScan(request.uploadDirectory);
        response.redirect(`/reports/${scan.id}`);
      } catch (error: unknown) {
        await removeUploadDirectory(request.uploadDirectory);
        throw error;
      }
    }),
  );
}

function readBodyString(request: Request, fieldName: string): string {
  const value: unknown = request.body[fieldName];
  if (typeof value !== "string") throw new ValidationError(`${fieldName} is required`);
  return value;
}
