import fs from "fs";
import fetch from "node-fetch";
import { FixPreview } from "./types";

const SCANNER_URL = process.env.SCANNER_URL || "http://scanner:8001";

/**
 * Generate a preview-then-apply fix for a source finding by asking the scanner
 * service (which owns the Python fixers) to compute the diff.
 */
export async function fix_for_source(
  scanId: string,
  ruleId: string,
  filePath: string
): Promise<FixPreview | { error: string }> {
  if (!fs.existsSync(filePath)) return { error: "file not found" };
  try {
    const resp = await fetch(`${SCANNER_URL}/fix/preview`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file_path: filePath, rule_id: ruleId }),
    });
    const data = (await resp.json()) as any;
    if (data.detail) return { error: data.detail };
    return {
      scanId,
      ruleId,
      file: filePath,
      line: 0,
      original: data.original,
      fixed: data.fixed,
      changes: data.changes || [],
    };
  } catch (e: any) {
    return { error: e.message || "fix preview failed" };
  }
}

export async function apply_fix(preview: FixPreview): Promise<boolean> {
  try {
    const resp = await fetch(`${SCANNER_URL}/fix/apply`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file_path: preview.file, rule_id: preview.ruleId }),
    });
    const data = (await resp.json()) as any;
    return !!data.ok;
  } catch {
    return false;
  }
}
