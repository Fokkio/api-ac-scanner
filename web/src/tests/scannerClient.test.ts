import assert from "node:assert/strict";
import test from "node:test";
import { WORKFLOW_TIMEOUT_MILLISECONDS } from "../clients/ScannerClient";

test("workflow client timeout exceeds the scanner worst-case request budget", () => {
  assert.ok(WORKFLOW_TIMEOUT_MILLISECONDS > 17 * 8_000);
});
