import fetch from "node-fetch";
import { Finding, ScanRecord } from "./types";
import { fix_for_source } from "./fixerClient";

const SCANNER_URL = process.env.SCANNER_URL || "http://scanner:8001";

export async function scanSource(scanId: string, repoPath: string): Promise<ScanRecord> {
  const resp = await fetch(`${SCANNER_URL}/scan/source`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_path: repoPath }),
  });
  const json = (await resp.json()) as { findings: Finding[] };
  const findings = json.findings || [];
  return {
    id: scanId,
    kind: "source",
    target: repoPath,
    createdAt: new Date().toISOString(),
    findings,
    status: "done",
  };
}

export async function scanDomain(
  scanId: string,
  target: string,
  authToken: string,
  altToken: string,
  objectUrls: string,
  mode: string
): Promise<ScanRecord> {
  const resp = await fetch(`${SCANNER_URL}/scan/domain`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, auth_token: authToken, alt_token: altToken, object_urls: objectUrls, mode }),
  });
  const json = (await resp.json()) as { findings: Finding[] };
  const findings = json.findings || [];
  return {
    id: scanId,
    kind: "domain",
    target,
    createdAt: new Date().toISOString(),
    findings,
    status: "done",
  };
}

export { fix_for_source };
