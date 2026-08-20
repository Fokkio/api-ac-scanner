import fetch from "node-fetch";
import { Finding, ScanRecord } from "./types";
import { fix_for_source } from "./fixerClient";

const SCANNER_URL = process.env.SCANNER_URL || "http://scanner:8001";

export async function scanSource(scanId: string, repoPath: string): Promise<ScanRecord> {
  try {
    const resp = await fetch(`${SCANNER_URL}/scan/source`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_path: repoPath }),
    });
    if (!resp.ok) {
      return { id: scanId, kind: "source", target: repoPath, createdAt: new Date().toISOString(), findings: [], status: "error", error: `scanner responded ${resp.status}` };
    }
    const json = (await resp.json()) as { findings: Finding[] };
    return {
      id: scanId,
      kind: "source",
      target: repoPath,
      createdAt: new Date().toISOString(),
      findings: json.findings || [],
      status: "done",
    };
  } catch (e: any) {
    return { id: scanId, kind: "source", target: repoPath, createdAt: new Date().toISOString(), findings: [], status: "error", error: e.message || "source scan failed" };
  }
}

export async function scanDomain(
  scanId: string,
  target: string,
  authToken: string,
  altToken: string,
  objectUrls: string,
  mode: string
): Promise<ScanRecord> {
  try {
    const resp = await fetch(`${SCANNER_URL}/scan/domain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, auth_token: authToken, alt_token: altToken, object_urls: objectUrls, mode }),
    });
    if (!resp.ok) {
      return { id: scanId, kind: "domain", target, createdAt: new Date().toISOString(), findings: [], status: "error", error: `scanner responded ${resp.status}` };
    }
    const json = (await resp.json()) as { findings: Finding[] };
    return {
      id: scanId,
      kind: "domain",
      target,
      createdAt: new Date().toISOString(),
      findings: json.findings || [],
      status: "done",
    };
  } catch (e: any) {
    return { id: scanId, kind: "domain", target, createdAt: new Date().toISOString(), findings: [], status: "error", error: e.message || "domain scan failed" };
  }
}

export { fix_for_source };
