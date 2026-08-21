import assert from "node:assert/strict";
import test from "node:test";
import { pathTemplateMatches } from "../services/ScanService";

test("matches route templates only at the same normalized endpoint shape", () => {
  assert.equal(pathTemplateMatches("/api/orders/:id", "/api/orders/1"), true);
  assert.equal(pathTemplateMatches("/api/orders/{orderId}", "/api/orders/abc"), true);
  assert.equal(pathTemplateMatches("/api/orders/:id", "/other/orders/1"), false);
  assert.equal(pathTemplateMatches("/api/orders/:id", "/api/orders/1/items"), false);
});
