import assert from "node:assert/strict";
import test from "node:test";
import { buildPdfReport, buildStandaloneHtmlReport } from "../services/ReportExportService";
import type { ScanRecord } from "../types/domain";

const scan: ScanRecord = {
  id: "a".repeat(48), kind: "workflow", target: "http://local.test/<unsafe>?access_token=url-secret",
  status: "done", progress: 100, stage: "Report ready", warnings: ["review coverage"], endpoints: [], matrix: [],
  createdAt: "2026-08-21T00:00:00.000Z", updatedAt: "2026-08-21T00:00:01.000Z", expiresAt: "2026-08-22T00:00:00.000Z",
  findings: [{
    id: "finding-1", category: "workflow-authorization", ruleId: "test", title: "Policy <script>alert(1)</script>",
    description: "Observed result", state: "verified", confidence: "high", severity: "high", owaspId: "API5:2023",
    location: "/__ac_test__/one", evidence: { status: 200, authorization: "Bearer must-not-leak", note: "safe" },
    recommendation: "Fix the policy enforcement",
  }],
};

test("standalone HTML escapes content and redacts secret evidence", () => {
  const html = buildStandaloneHtmlReport(scan);
  assert.match(html, /Policy &lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(html, /must-not-leak/);
  assert.doesNotMatch(html, /url-secret/);
  assert.match(html, /\[redacted\]/);
  assert.match(html, /<html lang="th">/);
});

test("PDF export returns a non-empty PDF and excludes secret evidence", async () => {
  const pdf = await buildPdfReport(scan);
  assert.equal(pdf.subarray(0, 5).toString("ascii"), "%PDF-");
  assert.ok(pdf.length > 1000);
  assert.doesNotMatch(pdf.toString("latin1"), /must-not-leak/);
});

test("standalone Thai HTML labels unexecuted workflow rows as skipped", () => {
  const skippedScan: ScanRecord = {
    ...scan,
    matrix: [{
      method: "GET", path: "/__ac_test__/one", identity: "Owner", role: "owner", tenant: "local",
      expected: "allow", actual: "indeterminate", actualStatus: 0,
      matchesExpectation: false, skippedAfterPriorFailure: true,
    }],
  };
  assert.match(buildStandaloneHtmlReport(skippedScan), />ข้าม \(skipped\)<\/td>/);
});
