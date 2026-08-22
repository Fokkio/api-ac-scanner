import express from "express";
import helmet from "helmet";
import session from "express-session";
import path from "node:path";
import type { AppConfig } from "./config/appConfig";
import { FORM_BODY_LIMIT_BYTES } from "./config/requestLimits";
import { registerRoutes } from "./controllers/registerRoutes";
import { assignRequestId, errorHandler } from "./middlewares/errorHandler";
import { requireLoopbackHost } from "./middlewares/loopbackHost";
import type { BoundedScanQueue } from "./queue/BoundedScanQueue";
import type { AssetService } from "./services/AssetService";
import type { ScanService } from "./services/ScanService";
import { BoundedMemoryStore } from "./security/BoundedMemoryStore";

export interface AppDependencies {
  config: AppConfig;
  scanService: ScanService;
  assetService: AssetService;
  scanQueue: BoundedScanQueue;
}

/** Creates the Express application with security middleware and routes. */
export function createApp(dependencies: AppDependencies): express.Express {
  const app = express();
  app.disable("x-powered-by");
  app.set("view engine", "ejs");
  app.set("views", path.resolve(process.cwd(), "views"));

  app.use(assignRequestId);
  app.use(requireLoopbackHost);
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: null,
      },
    },
  }));
  app.use(express.urlencoded({ extended: false, limit: FORM_BODY_LIMIT_BYTES }));
  app.use(express.json({ limit: FORM_BODY_LIMIT_BYTES }));
  app.use(session({
    name: "acsv32.sid",
    secret: dependencies.config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: new BoundedMemoryStore(dependencies.config.maxSessions, 8 * 60 * 60 * 1000),
    cookie: {
      httpOnly: true,
      secure: false,
      sameSite: "strict",
      maxAge: 8 * 60 * 60 * 1000,
    },
  }));
  app.use(express.static(path.resolve(process.cwd(), "public"), { maxAge: dependencies.config.isProduction ? "1h" : 0 }));

  registerRoutes(app, dependencies);
  app.use(errorHandler);
  return app;
}
