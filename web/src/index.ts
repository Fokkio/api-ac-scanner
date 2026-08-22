import fs from "node:fs/promises";
import { createApp } from "./app";
import { ScannerClient } from "./clients/ScannerClient";
import { loadAppConfig } from "./config/appConfig";
import { BoundedScanQueue } from "./queue/BoundedScanQueue";
import { JsonStateRepository } from "./repositories/JsonStateRepository";
import { AssetService } from "./services/AssetService";
import { ScanService } from "./services/ScanService";
import { removeOrphanedUploadDirectories } from "./middlewares/upload";

/** Initializes dependencies and starts the V3.2 local-first web service. */
async function startServer(): Promise<void> {
  const config = loadAppConfig();
  await fs.mkdir(config.uploadRoot, { recursive: true });
  await removeOrphanedUploadDirectories(config.uploadRoot);
  const repository = await JsonStateRepository.create(config.dataDirectory, config.maxStoredReports);
  const scannerClient = new ScannerClient(config.scannerUrl, config.scannerInternalToken);
  const scanQueue = new BoundedScanQueue(config.scanConcurrency, config.queueCapacity);
  const scanService = new ScanService(repository, scanQueue, scannerClient, config.reportTtlHours, config.targetPolicy);
  const assetService = new AssetService(repository, scannerClient, config.targetPolicy);
  const app = createApp({ config, scanService, assetService, scanQueue });

  app.listen(config.port, config.listenHost, () => {
    console.info(`API AC Scanner V3.2 listening on ${config.listenHost}:${config.port}`);
  });
}

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled promise rejection", { reason });
  process.exit(1);
});

process.on("uncaughtException", (error) => {
  console.error("Uncaught exception", { error });
  process.exit(1);
});

void startServer().catch((error: unknown) => {
  console.error("Failed to start web service", { error });
  process.exit(1);
});
