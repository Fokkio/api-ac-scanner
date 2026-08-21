import type { Express, Request, Response } from "express";
import { rateLimit } from "express-rate-limit";
import type { AppConfig } from "../config/appConfig";
import { AuthenticationError, ValidationError } from "../errors/AppError";
import { areCredentialsValid } from "../security/credentialPolicy";
import { asyncHandler } from "../middlewares/asyncHandler";
import { requireAuthentication } from "../middlewares/auth";
import { getCsrfToken, requireCsrf } from "../middlewares/csrf";
import {
  createDiscoveryUploadHandler,
  createSourceUploadHandler,
  createUploadDirectory,
  removeUploadDirectory,
} from "../middlewares/upload";
import type { AssetService } from "../services/AssetService";
import type { ScanService } from "../services/ScanService";
import type { BoundedScanQueue } from "../queue/BoundedScanQueue";
import type { EndpointRecord } from "../types/domain";
import { parseIdentityProfile } from "../security/identityPolicy";
import { parseAuthorizationPolicy } from "../security/authorizationPolicy";
import { isConfiguredLocalTarget } from "../security/inputPolicy";
import { parseAuthenticationAdapter, parseWorkflowSteps } from "../security/workflowPolicy";
import { buildPdfReport, buildStandaloneHtmlReport } from "../services/ReportExportService";

interface RouteDependencies {
  config: AppConfig;
  scanService: ScanService;
  assetService: AssetService;
  scanQueue: BoundedScanQueue;
}

const quickScanLimiter = rateLimit({ windowMs: 60_000, limit: 5, standardHeaders: true, legacyHeaders: false });
const loginLimiter = rateLimit({ windowMs: 15 * 60_000, limit: 10, standardHeaders: true, legacyHeaders: false });

/** Registers all HTML and JSON routes for the V3.1 local-first application. */
export function registerRoutes(app: Express, dependencies: RouteDependencies): void {
  registerPublicRoutes(app, dependencies);
  registerAuthenticationRoutes(app, dependencies.config);
  registerAdministratorRoutes(app, dependencies);
}

function registerPublicRoutes(app: Express, dependencies: RouteDependencies): void {
  app.get("/", (request, response) => {
    response.render("index", { csrfToken: getCsrfToken(request) });
  });

  app.post("/scans/quick", quickScanLimiter, requireCsrf, asyncHandler(async (request, response) => {
    const scan = await dependencies.scanService.createQuickScan(
      request.body.target,
      request.body.authorized === "yes",
    );
    response.redirect(`/reports/${scan.id}`);
  }));

  app.get("/reports/:scanId", asyncHandler(async (request, response) => {
    const scan = dependencies.scanService.getScan(request.params.scanId ?? "", request.session.isAuthenticated === true);
    response.render("report", { scan });
  }));

  app.get("/api/scans/:scanId", asyncHandler(async (request, response) => {
    const scan = dependencies.scanService.getScan(request.params.scanId ?? "", request.session.isAuthenticated === true);
    response.json({ success: true, scan });
  }));

  app.get("/reports/:scanId/export.html", asyncHandler(async (request, response) => {
    const scan = dependencies.scanService.getScan(request.params.scanId ?? "", request.session.isAuthenticated === true);
    requireExportableReport(scan.status);
    response.setHeader("cache-control", "no-store");
    response.attachment(`api-ac-report-${scan.id}.html`).type("html").send(buildStandaloneHtmlReport(scan));
  }));

  app.get("/reports/:scanId/export.pdf", asyncHandler(async (request, response) => {
    const scan = dependencies.scanService.getScan(request.params.scanId ?? "", request.session.isAuthenticated === true);
    requireExportableReport(scan.status);
    const pdf = await buildPdfReport(scan);
    response.setHeader("cache-control", "no-store");
    response.attachment(`api-ac-report-${scan.id}.pdf`).type("application/pdf").send(pdf);
  }));

  app.get("/health", (_request, response) => {
    response.json({ status: "ok", queue: dependencies.scanQueue.getStats() });
  });
}

function requireExportableReport(status: string): void {
  if (status !== "done" && status !== "error") {
    throw new ValidationError("Wait for the scan to finish before exporting its report");
  }
}

function registerAuthenticationRoutes(app: Express, config: AppConfig): void {
  app.get("/login", (request, response) => {
    response.render("login", { csrfToken: getCsrfToken(request) });
  });

  app.post("/login", loginLimiter, requireCsrf, asyncHandler(async (request, response) => {
    const isValid = areCredentialsValid(
      request.body.username,
      request.body.password,
      config.adminUsername,
      config.adminPassword,
    );
    if (!isValid) throw new AuthenticationError("Invalid username or password");
    await regenerateSession(request);
    request.session.isAuthenticated = true;
    getCsrfToken(request);
    response.redirect("/dashboard");
  }));

  app.post("/logout", requireAuthentication, requireCsrf, asyncHandler(async (request, response) => {
    await destroySession(request);
    response.redirect("/");
  }));
}

function registerAdministratorRoutes(app: Express, dependencies: RouteDependencies): void {
  app.get("/dashboard", requireAuthentication, (request, response) => {
    const inventoryId = typeof request.query.inventory === "string" ? request.query.inventory : undefined;
    const inventory = inventoryId
      ? dependencies.scanService.getDiscoveryInventory(inventoryId)
      : [];
    const suggestions = buildInventorySuggestions(inventory);
    response.render("dashboard", {
      csrfToken: getCsrfToken(request),
      assets: dependencies.assetService.listAssets(),
      localMode: dependencies.config.targetPolicy.localMode,
      inventory,
      ...suggestions,
    });
  });

  registerAssetRoutes(app, dependencies);
  registerDeepScanRoute(app, dependencies);
  registerDiscoveryRoutes(app, dependencies);
  registerSourceScanRoutes(app, dependencies);
  registerCorrelationRoutes(app, dependencies);
  registerMutationRoutes(app, dependencies);
  registerWorkflowRoutes(app, dependencies);
}

function buildInventorySuggestions(endpoints: EndpointRecord[]): {
  suggestedObjectPaths: string[];
  suggestedFunctionPaths: string[];
} {
  const isConcreteGet = (endpoint: EndpointRecord): boolean => endpoint.method === "GET"
    && !/[{:][^/]+[}]?/.test(endpoint.path);
  return {
    suggestedObjectPaths: endpoints
      .filter((endpoint) => endpoint.candidateType === "object" && isConcreteGet(endpoint))
      .map((endpoint) => endpoint.path)
      .slice(0, 5),
    suggestedFunctionPaths: endpoints
      .filter((endpoint) => endpoint.candidateType === "function" && isConcreteGet(endpoint))
      .map((endpoint) => endpoint.path)
      .slice(0, 5),
  };
}

function registerAssetRoutes(app: Express, dependencies: RouteDependencies): void {
  app.post("/assets", requireAuthentication, requireCsrf, asyncHandler(async (request, response) => {
    await dependencies.assetService.createAsset(request.body.origin);
    response.redirect("/dashboard");
  }));

  app.post("/assets/:assetId/verify", requireAuthentication, requireCsrf, asyncHandler(async (request, response) => {
    await dependencies.assetService.verifyAsset(
      request.params.assetId ?? "",
      readBodyString(request, "verificationMethod"),
    );
    response.redirect("/dashboard");
  }));
}

function registerDiscoveryRoutes(app: Express, dependencies: RouteDependencies): void {
  const uploadHandler = createDiscoveryUploadHandler();
  app.get("/discovery", requireAuthentication, (request, response) => {
    response.render("discovery", {
      csrfToken: getCsrfToken(request),
      assets: dependencies.assetService.listAssets().filter((asset) => asset.isVerified),
    });
  });
  app.post(
    "/scans/discovery",
    requireAuthentication,
    createUploadDirectory(dependencies.config.uploadRoot),
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

function registerDeepScanRoute(app: Express, dependencies: RouteDependencies): void {
  app.post("/scans/deep", requireAuthentication, requireCsrf, asyncHandler(async (request, response) => {
    const identities = [
      parseIdentityProfile({
        label: request.body.primaryLabel, role: request.body.primaryRole,
        tenant: request.body.primaryTenant, authType: request.body.primaryAuthType,
        headerName: request.body.primaryHeaderName, credential: request.body.primaryCredential,
      }),
      parseIdentityProfile({
        label: request.body.alternateLabel, role: request.body.alternateRole,
        tenant: request.body.alternateTenant, authType: request.body.alternateAuthType,
        headerName: request.body.alternateHeaderName, credential: request.body.alternateCredential,
      }),
    ] as const;
    const scan = await dependencies.scanService.createDeepScan({
      assetId: readBodyString(request, "assetId"),
      objectPaths: readBodyString(request, "objectPaths").split(/[\n,]/),
      adminPaths: readBodyString(request, "adminPaths").split(/[\n,]/),
      enumerationExistingPaths: readBodyString(request, "enumerationExistingPaths").split(/[\n,]/),
      enumerationMissingPaths: readBodyString(request, "enumerationMissingPaths").split(/[\n,]/),
      identities: [identities[0], identities[1]],
      policyRules: parseAuthorizationPolicy(request.body.authorizationPolicy, [identities[0], identities[1]]),
    });
    response.redirect(`/reports/${scan.id}`);
  }));
}

function registerSourceScanRoutes(app: Express, dependencies: RouteDependencies): void {
  const uploadHandler = createSourceUploadHandler();
  app.get("/source", requireAuthentication, (request, response) => {
    response.render("source", { csrfToken: getCsrfToken(request) });
  });
  app.post(
    "/scans/source",
    requireAuthentication,
    createUploadDirectory(dependencies.config.uploadRoot),
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

function registerCorrelationRoutes(app: Express, dependencies: RouteDependencies): void {
  app.get("/correlation", requireAuthentication, (request, response) => {
    response.render("correlation", {
      csrfToken: getCsrfToken(request),
      sourceScans: dependencies.scanService.listCompletedScans("source"),
      dynamicScans: dependencies.scanService.listCompletedScans("deep"),
    });
  });
  app.post("/scans/correlation", requireAuthentication, requireCsrf, asyncHandler(async (request, response) => {
    const scan = await dependencies.scanService.createCorrelationScan(
      readBodyString(request, "sourceScanId"),
      readBodyString(request, "dynamicScanId"),
    );
    response.redirect(`/reports/${scan.id}`);
  }));
}

function registerMutationRoutes(app: Express, dependencies: RouteDependencies): void {
  app.get("/mutation", requireAuthentication, (request, response) => {
    const assets = dependencies.assetService.listAssets().filter((asset) =>
      asset.isVerified && isConfiguredLocalTarget(new URL(asset.origin), dependencies.config.targetPolicy));
    response.render("mutation", { csrfToken: getCsrfToken(request), assets });
  });
  app.post("/scans/mutation", requireAuthentication, requireCsrf, asyncHandler(async (request, response) => {
    const identity = parseIdentityProfile({
      label: request.body.identityLabel,
      role: request.body.identityRole,
      tenant: request.body.identityTenant,
      authType: request.body.identityAuthType,
      headerName: request.body.identityHeaderName,
      credential: request.body.identityCredential,
    });
    const scan = await dependencies.scanService.createMutationScan({
      assetId: readBodyString(request, "assetId"),
      path: readBodyString(request, "mutationPath"),
      body: readBodyString(request, "mutationBody"),
      confirmation: readBodyString(request, "confirmation"),
      identity,
    });
    response.redirect(`/reports/${scan.id}`);
  }));
}

function registerWorkflowRoutes(app: Express, dependencies: RouteDependencies): void {
  app.get("/workflow", requireAuthentication, (request, response) => {
    const assets = dependencies.assetService.listAssets().filter((asset) =>
      asset.isVerified && isConfiguredLocalTarget(new URL(asset.origin), dependencies.config.targetPolicy));
    response.render("workflow", { csrfToken: getCsrfToken(request), assets });
  });
  app.post("/scans/workflow", requireAuthentication, requireCsrf, asyncHandler(async (request, response) => {
    const authentication = parseAuthenticationAdapter(request.body.authenticationAdapter);
    const identity = parseIdentityProfile({
      label: request.body.identityLabel,
      role: request.body.identityRole,
      tenant: request.body.identityTenant,
      authType: request.body.identityAuthType,
      headerName: request.body.identityHeaderName,
      credential: request.body.identityCredential,
    }, { allowEmptyAuthentication: authentication.type === "json-login" });
    const scan = await dependencies.scanService.createWorkflowScan({
      assetId: readBodyString(request, "assetId"),
      confirmation: readBodyString(request, "confirmation"),
      identity,
      authentication,
      steps: parseWorkflowSteps(request.body.workflowSteps),
    });
    response.redirect(`/reports/${scan.id}`);
  }));
}

function readBodyString(request: Request, fieldName: string): string {
  const value: unknown = request.body[fieldName];
  if (typeof value !== "string") throw new ValidationError(`${fieldName} is required`);
  return value;
}

function regenerateSession(request: Request): Promise<void> {
  return new Promise((resolve, reject) => {
    request.session.regenerate((error) => error ? reject(error) : resolve());
  });
}

function destroySession(request: Request): Promise<void> {
  return new Promise((resolve, reject) => {
    request.session.destroy((error) => error ? reject(error) : resolve());
  });
}
