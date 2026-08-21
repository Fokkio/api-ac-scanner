const fs = require("node:fs/promises");
const path = require("node:path");
const { chromium } = require("playwright");

const scannerUrl = "http://127.0.0.1:3000";
const portalUrl = "http://127.0.0.1:4100";
const targetOrigin = "http://demo-api:4100";
const outputDirectory = __dirname;

const credentials = {
  alice: {
    bearer: "alice-bearer-token-1234567890",
    basic: "alice:alice-password",
    cookie: "portal_session=alice-session-token-1234567890",
    apiKey: "alice-api-key-1234567890",
    custom: JSON.stringify({
      "x-demo-user": "alice",
      "x-demo-secret": "alice-custom-secret-1234567890",
    }),
  },
  bobBearer: "bob-bearer-token-1234567890",
  adminBearer: "admin-bearer-token-1234567890",
};

const knownSecrets = [
  process.env.SCANNER_ADMIN_PASSWORD,
  "alice-password",
  "bob-password",
  "admin-password",
  credentials.alice.bearer,
  credentials.bobBearer,
  credentials.adminBearer,
  credentials.alice.cookie,
  credentials.alice.apiKey,
  "alice-custom-secret-1234567890",
].filter(Boolean);

async function main() {
  if (!process.env.SCANNER_ADMIN_USERNAME || !process.env.SCANNER_ADMIN_PASSWORD) {
    throw new Error("Scanner admin credentials were not supplied through the environment");
  }
  await fs.mkdir(outputDirectory, { recursive: true });
  const browser = await chromium.launch({
    headless: true,
    executablePath: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  });
  const result = { portal: {}, scanner: { reports: [] }, secretLeakDetected: false };

  try {
    result.portal = await verifyPortalUsers(browser);
    const context = await browser.newContext({ acceptDownloads: true, viewport: { width: 1440, height: 1000 } });
    const page = await context.newPage();
    try {
      await loginToScanner(page);
      const assetValue = await ensureLocalAsset(page);
      result.scanner.asset = { origin: targetOrigin, verified: true };

      result.scanner.reports.push(await runDeepScan(page, assetValue, {
        name: "bola-owner-vs-viewer",
        functionPath: "/api/owner/summary",
        primary: { label: "Alice Owner", role: "owner", tenant: "tenant-a", token: credentials.alice.bearer },
        alternate: { label: "Bob Viewer", role: "viewer", tenant: "tenant-a", token: credentials.bobBearer },
        policy: [
          ["/api/orders/1", "Alice Owner", "allow"],
          ["/api/orders/1", "Bob Viewer", "deny"],
          ["/api/orders/1", "Anonymous", "deny"],
          ["/api/owner/summary", "Alice Owner", "allow"],
          ["/api/owner/summary", "Bob Viewer", "deny"],
          ["/api/owner/summary", "Anonymous", "deny"],
        ],
      }));

      result.scanner.reports.push(await runDeepScan(page, assetValue, {
        name: "bfla-admin-vs-owner",
        functionPath: "/api/admin/reports",
        primary: { label: "Ada Admin", role: "admin", tenant: "global", token: credentials.adminBearer },
        alternate: { label: "Alice Owner", role: "owner", tenant: "tenant-a", token: credentials.alice.bearer },
        policy: [
          ["/api/orders/3", "Ada Admin", "allow"],
          ["/api/orders/3", "Alice Owner", "deny"],
          ["/api/orders/3", "Anonymous", "deny"],
          ["/api/admin/reports", "Ada Admin", "allow"],
          ["/api/admin/reports", "Alice Owner", "deny"],
          ["/api/admin/reports", "Anonymous", "deny"],
        ],
      }));

      const mutation = await runMutationScan(page, assetValue);
      result.scanner.reports.push(mutation);
      await page.screenshot({ path: path.join(outputDirectory, "04-mutation-report.png"), fullPage: true });

      const adapters = [
        { name: "bearer", authType: "bearer", credential: credentials.alice.bearer },
        { name: "basic", authType: "basic", credential: credentials.alice.basic },
        { name: "cookie", authType: "cookie", credential: credentials.alice.cookie },
        { name: "api-key", authType: "api-key", headerName: "x-api-key", credential: credentials.alice.apiKey },
        { name: "custom-headers", authType: "custom-headers", credential: credentials.alice.custom },
        { name: "json-login", authType: "none", credential: "", adapter: {
          type: "json-login",
          path: "/__ac_test__/login",
          usernameField: "username",
          passwordField: "password",
          username: "alice",
          password: "alice-password",
          tokenJsonPath: "tokens.access",
          headerName: "authorization",
          scheme: "Bearer",
        } },
      ];

      for (const adapter of adapters) {
        const report = await runWorkflowScan(page, assetValue, adapter, adapter.name === "json-login");
        result.scanner.reports.push(report);
        if (adapter.name === "json-login") {
          await page.screenshot({ path: path.join(outputDirectory, "05-json-login-workflow-report.png"), fullPage: true });
          await downloadReport(page, "Download HTML", "workflow-report.html");
          await downloadReport(page, "Download PDF", "workflow-report.pdf");
        }
      }

      await page.goto(`${scannerUrl}/dashboard`, { waitUntil: "networkidle" });
      await page.screenshot({ path: path.join(outputDirectory, "03-scanner-dashboard.png"), fullPage: true });
      result.scanner.reportCount = result.scanner.reports.length;
      result.secretLeakDetected = await detectSecretLeak(result.scanner.reports);
    } finally {
      await context.close();
    }
  } catch (error) {
    const errorContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const errorPage = await errorContext.newPage();
    await errorPage.goto(scannerUrl).catch(() => undefined);
    await errorPage.screenshot({ path: path.join(outputDirectory, "error-state.png"), fullPage: true }).catch(() => undefined);
    await errorContext.close();
    throw error;
  } finally {
    await browser.close();
  }

  await fs.writeFile(path.join(outputDirectory, "full-e2e-result.json"), JSON.stringify(result, null, 2));
  process.stdout.write(JSON.stringify(result));
}

async function verifyPortalUsers(browser) {
  const users = [
    { username: "alice", password: "alice-password", expected: "Welcome, Alice Owner", visibleOrders: 1 },
    { username: "bob", password: "bob-password", expected: "Welcome, Bob Viewer", visibleOrders: 1 },
    { username: "admin", password: "admin-password", expected: "Welcome, Ada Admin", visibleOrders: 3 },
  ];
  const observed = [];
  for (const [index, user] of users.entries()) {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const page = await context.newPage();
    try {
      await page.goto(portalUrl, { waitUntil: "networkidle" });
      if (index === 0) await page.screenshot({ path: path.join(outputDirectory, "01-order-portal-login.png"), fullPage: true });
      await page.getByLabel("Username").fill(user.username);
      await page.getByLabel("Password").fill(user.password);
      await Promise.all([
        page.waitForURL(`${portalUrl}/portal`),
        page.getByRole("button", { name: "Open portal" }).click(),
      ]);
      const heading = await page.getByRole("heading", { level: 1 }).innerText();
      const orderRows = await page.locator("tbody tr").count();
      const empty = await page.getByText("No visible orders for this identity.").count();
      const visibleOrders = empty > 0 ? 0 : orderRows;
      if (heading !== user.expected || visibleOrders !== user.visibleOrders) {
        throw new Error(`Portal role view mismatch for ${user.username}`);
      }
      if (user.username === "alice") await page.screenshot({ path: path.join(outputDirectory, "02-alice-portal.png"), fullPage: true });
      observed.push({ username: user.username, heading, visibleOrders });
    } finally {
      await context.close();
    }
  }
  return { users: observed, databaseBackedRoleViewsPassed: true };
}

async function loginToScanner(page) {
  await page.goto(`${scannerUrl}/login`, { waitUntil: "networkidle" });
  await page.getByLabel("Username").fill(process.env.SCANNER_ADMIN_USERNAME);
  await page.getByLabel("Password").fill(process.env.SCANNER_ADMIN_PASSWORD);
  await Promise.all([
    page.waitForURL(`${scannerUrl}/dashboard`),
    page.getByRole("button", { name: "Continue" }).click(),
  ]);
}

async function ensureLocalAsset(page) {
  await page.goto(`${scannerUrl}/dashboard`, { waitUntil: "networkidle" });
  if (await page.getByRole("heading", { name: targetOrigin, exact: true }).count() === 0) {
    await page.getByLabel("Exact origin").fill(targetOrigin);
    await Promise.all([
      page.waitForURL(`${scannerUrl}/dashboard`),
      page.getByRole("button", { name: "Add asset" }).click(),
    ]);
  }
  const card = page.locator(".asset-card", { has: page.getByRole("heading", { name: targetOrigin, exact: true }) });
  if ((await card.getByText("Verified", { exact: true }).count()) !== 1) throw new Error("Local fixture asset was not auto-verified");
  await page.goto(`${scannerUrl}/workflow`, { waitUntil: "networkidle" });
  const option = page.locator('select[name="assetId"] option', { hasText: targetOrigin });
  const value = await option.getAttribute("value");
  if (!value) throw new Error("Verified asset option was not available");
  return value;
}

async function runDeepScan(page, assetValue, plan) {
  await page.goto(`${scannerUrl}/dashboard`, { waitUntil: "networkidle" });
  await page.locator('select[name="assetId"]').selectOption(assetValue);
  await page.locator('textarea[name="objectPaths"]').fill(plan.name === "bfla-admin-vs-owner" ? "/api/orders/3" : "/api/orders/1");
  await page.locator('textarea[name="adminPaths"]').fill(plan.functionPath);
  const policy = plan.policy.map(([pathValue, identity, expected]) => ({ method: "GET", path: pathValue, identity, expected }));
  await page.locator('textarea[name="authorizationPolicy"]').fill(JSON.stringify(policy));
  await fillIdentity(page, "primary", plan.primary);
  await fillIdentity(page, "alternate", plan.alternate);
  const payload = await submitAndWaitForReport(page, page.getByRole("button", { name: "Run authorized scan" }));
  return summarizeReport(plan.name, payload.scan);
}

async function fillIdentity(page, prefix, identity) {
  await page.locator(`input[name="${prefix}Label"]`).fill(identity.label);
  await page.locator(`input[name="${prefix}Role"]`).fill(identity.role);
  await page.locator(`input[name="${prefix}Tenant"]`).fill(identity.tenant);
  await page.locator(`select[name="${prefix}AuthType"]`).selectOption("bearer");
  await page.locator(`textarea[name="${prefix}Credential"]`).fill(identity.token);
}

async function runMutationScan(page, assetValue) {
  await page.goto(`${scannerUrl}/mutation`, { waitUntil: "networkidle" });
  await page.locator('select[name="assetId"]').selectOption(assetValue);
  await page.locator('input[name="mutationPath"]').fill("/__ac_test__/v3-safe-resource");
  await page.locator('textarea[name="mutationBody"]').fill(JSON.stringify({ apiAcScannerTest: true, value: "temporary" }));
  await page.locator('input[name="identityLabel"]').fill("Alice mutation owner");
  await page.locator('input[name="identityRole"]').fill("owner");
  await page.locator('input[name="identityTenant"]').fill("tenant-a");
  await page.locator('select[name="identityAuthType"]').selectOption("bearer");
  await page.locator('textarea[name="identityCredential"]').fill(credentials.alice.bearer);
  await page.locator('input[name="confirmation"]').fill("MUTATE TEST RESOURCE");
  const payload = await submitAndWaitForReport(page, page.getByRole("button", { name: "Create test resource and clean it up" }));
  return summarizeReport("mutation-post-delete", payload.scan);
}

async function runWorkflowScan(page, assetValue, adapter, fullWorkflow) {
  await page.goto(`${scannerUrl}/workflow`, { waitUntil: "networkidle" });
  await page.locator('select[name="assetId"]').selectOption(assetValue);
  await page.locator('input[name="identityLabel"]').fill(`Alice ${adapter.name}`);
  await page.locator('input[name="identityRole"]').fill("owner");
  await page.locator('input[name="identityTenant"]').fill("tenant-a");
  await page.locator('select[name="identityAuthType"]').selectOption(adapter.authType);
  if (adapter.headerName) await page.locator('input[name="identityHeaderName"]').fill(adapter.headerName);
  await page.locator('textarea[name="identityCredential"]').fill(adapter.credential);
  await page.locator('textarea[name="authenticationAdapter"]').fill(JSON.stringify(adapter.adapter || { type: "none" }));
  const resourcePath = `/__ac_test__/resource-${adapter.name}`;
  const steps = fullWorkflow ? [
    { name: "create", method: "POST", path: resourcePath, body: { apiAcScannerTest: true, value: "created" }, expected: "allow" },
    { name: "replace", method: "PUT", path: resourcePath, body: { apiAcScannerTest: true, value: "replaced" }, expected: "allow" },
    { name: "patch", method: "PATCH", path: resourcePath, body: { apiAcScannerTest: true, patched: true }, expected: "allow" },
    { name: "read", method: "GET", path: resourcePath, expected: "allow" },
    { name: "delete", method: "DELETE", path: resourcePath, expected: "allow" },
  ] : [
    { name: `create-with-${adapter.name}`, method: "POST", path: resourcePath, body: { apiAcScannerTest: true, adapter: adapter.name }, expected: "allow" },
  ];
  await page.locator('textarea[name="workflowSteps"]').fill(JSON.stringify(steps));
  await page.locator('input[name="confirmation"]').fill("RUN DISPOSABLE WORKFLOW");
  const payload = await submitAndWaitForReport(page, page.getByRole("button", { name: "Run disposable workflow" }));
  return summarizeReport(`workflow-${adapter.name}`, payload.scan);
}

async function submitAndWaitForReport(page, submitButton) {
  await Promise.all([page.waitForURL(/\/reports\/[a-f0-9-]+$/), submitButton.click()]);
  await page.waitForSelector('[data-report-status="done"], [data-report-status="error"]', { timeout: 90000 });
  const scanId = new URL(page.url()).pathname.split("/").pop();
  const payload = await page.evaluate(async (id) => {
    const response = await fetch(`/api/scans/${encodeURIComponent(id)}`, { headers: { accept: "application/json" } });
    return response.json();
  }, scanId);
  if (!payload.success || payload.scan.status !== "done") throw new Error(`Scanner report ${scanId} ended with ${payload.scan.status}`);
  return payload;
}

function summarizeReport(name, scan) {
  const counts = {};
  for (const finding of scan.findings) counts[finding.state] = (counts[finding.state] || 0) + 1;
  return {
    name,
    id: scan.id,
    kind: scan.kind,
    status: scan.status,
    counts,
    matrixRows: scan.matrix.length,
    matrixMatches: scan.matrix.filter((row) => row.matchesExpectation).length,
    matrix: scan.matrix.map((row) => ({
      method: row.method,
      path: row.path,
      identity: row.identity,
      expected: row.expected,
      actual: row.actual,
      actualStatus: row.actualStatus,
      matchesExpectation: row.matchesExpectation,
      skippedAfterPriorFailure: row.skippedAfterPriorFailure || false,
    })),
    findings: scan.findings.map((finding) => ({
      state: finding.state,
      title: finding.title,
      ruleId: finding.ruleId,
      evidence: finding.evidence,
    })),
  };
}

async function downloadReport(page, linkName, fileName) {
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("link", { name: linkName }).click();
  const download = await downloadPromise;
  await download.saveAs(path.join(outputDirectory, fileName));
}

async function detectSecretLeak(reports) {
  const serializedReports = JSON.stringify(reports);
  const html = await fs.readFile(path.join(outputDirectory, "workflow-report.html"), "utf8");
  const pdf = await fs.readFile(path.join(outputDirectory, "workflow-report.pdf"));
  return knownSecrets.some((secret) => serializedReports.includes(secret) || html.includes(secret) || pdf.includes(Buffer.from(secret)));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
