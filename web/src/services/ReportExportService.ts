import PDFDocument from "pdfkit";
import type { Finding, ScanRecord } from "../types/domain";

const SECRET_KEY = /(authorization|cookie|password|secret|token|credential|api[-_]?key|x-auth|x-session|sessionid|set-cookie|auth-token|access[-_]?token|refresh[-_]?token)/i;
const SECRET_VALUE = /^(bearer|basic)\s+\S+/i;

/** Builds a self-contained, escaped HTML report suitable for offline review. */
export function buildStandaloneHtmlReport(scan: ScanRecord): string {
  const summary = summarize(scan);
  const matrixRows = scan.matrix.map((row) => `<tr>
    <td>${escapeHtml(row.method)} ${escapeHtml(row.path)}</td>
    <td>${escapeHtml(row.identity)}</td><td>${escapeHtml(row.expected)}</td>
    <td>${escapeHtml(row.actual)} (${row.actualStatus})</td>
    <td>${row.skippedAfterPriorFailure ? "ข้าม (skipped)" : row.matchesExpectation ? "ตรง (match)" : "ไม่ตรง (mismatch)"}</td></tr>`).join("");
  const findings = scan.findings.map((finding) => findingHtml(finding)).join("");
  return `<!doctype html>
<html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>รายงาน API AC Scanner ${escapeHtml(scan.id)}</title>
<style>
body{font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#172033;max-width:1100px;margin:32px auto;padding:0 24px}h1{word-break:break-word}h2{margin-top:28px}code{font-family:ui-monospace,monospace;background:#eef2f7;padding:2px 5px}.meta,.warning,.finding{border:1px solid #d8deea;border-radius:10px;padding:14px;margin:12px 0}.warning{background:#fff8df}.summary{display:flex;gap:12px;flex-wrap:wrap}.summary span{background:#eef2f7;border-radius:999px;padding:7px 11px}table{width:100%;border-collapse:collapse}th,td{border:1px solid #d8deea;padding:8px;text-align:left;vertical-align:top}dt{font-weight:700}dd{margin:0 0 6px;word-break:break-word}@media print{body{margin:0;max-width:none}.finding{break-inside:avoid}}
</style></head><body>
<h1>รายงานตรวจสอบการควบคุมสิทธิ์ของ API</h1>
<section class="meta"><strong>${escapeHtml(scan.kind)} scan</strong><br>${escapeHtml(safeTarget(scan.target))}<br>
รหัสรายงาน: ${escapeHtml(scan.id)}<br>สร้างเมื่อ: ${escapeHtml(scan.createdAt)}<br>สถานะ: ${escapeHtml(scan.status)} / ${escapeHtml(scan.stage)}</section>
<section class="summary">${Object.entries(summary).map(([state, count]) => `<span>${escapeHtml(thaiStateLabel(state))} (${escapeHtml(state)}): ${count}</span>`).join("")}</section>
${scan.warnings.map((warning) => `<div class="warning">${escapeHtml(warning)}</div>`).join("")}
${scan.matrix.length ? `<h2>ตารางเปรียบเทียบสิทธิ์ (Authorization Matrix)</h2><table><thead><tr><th>Endpoint</th><th>Identity</th><th>ผลที่คาด</th><th>ผลจริง</th><th>ผลเปรียบเทียบ</th></tr></thead><tbody>${matrixRows}</tbody></table>` : ""}
<h2>รายการที่พบ (Findings)</h2>${findings || "<p>ไม่พบรายการผิดปกติ กรุณาตรวจขอบเขตและคำเตือนก่อนสรุปผล</p>"}
<p><small>สร้างโดย API AC Scanner V3.2 ระบบตัดหรือปกปิดข้อมูลลับ ผลที่พบเป็นหลักฐานสำหรับงานที่ได้รับอนุญาต ไม่ใช่ข้อยืนยันว่าระบบปลอดภัยทั้งหมด</small></p>
</body></html>`;
}

/** Builds a portable PDF without writing report data to temporary files. */
export function buildPdfReport(scan: ScanRecord): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const document = new PDFDocument({ size: "A4", margin: 48, info: {
      Title: `API Access-Control Assessment ${scan.id}`,
      Author: "API AC Scanner V3.2",
      Subject: "Authorized access-control assessment report",
    } });
    const chunks: Buffer[] = [];
    document.on("data", (chunk: Buffer) => chunks.push(chunk));
    document.on("error", reject);
    document.on("end", () => resolve(Buffer.concat(chunks)));

    document.fontSize(20).text("API Access-Control Assessment Report");
    document.moveDown(0.5).fontSize(10).fillColor("#334155");
    document.text(`Report ID: ${pdfText(scan.id)}`);
    document.text(`Kind: ${pdfText(scan.kind)}   Status: ${pdfText(scan.status)} / ${pdfText(scan.stage)}`);
    document.text(`Target: ${pdfText(safeTarget(scan.target))}`);
    document.text(`Created: ${pdfText(scan.createdAt)}   Expires: ${pdfText(scan.expiresAt)}`);

    document.moveDown().fontSize(14).fillColor("#111827").text("Summary");
    document.fontSize(10).text(Object.entries(summarize(scan)).map(([state, count]) => `${state}: ${count}`).join("   "));
    for (const warning of scan.warnings) {
      document.moveDown(0.35).fillColor("#92400e").text(`Warning: ${pdfText(warning)}`);
    }

    if (scan.matrix.length) {
      document.moveDown().fontSize(14).fillColor("#111827").text("Authorization matrix");
      document.fontSize(9);
      for (const row of scan.matrix) {
        const outcome = row.skippedAfterPriorFailure ? "skipped" : row.matchesExpectation ? "match" : "mismatch";
        document.text(`${row.method} ${pdfText(row.path)} | ${pdfText(row.identity)} | expected ${row.expected} | actual ${row.actual} (${row.actualStatus}) | ${outcome}`);
      }
    }

    document.moveDown().fontSize(14).text("Findings");
    document.fontSize(10);
    if (!scan.findings.length) document.text("No findings were produced. Review coverage and warnings before drawing conclusions.");
    scan.findings.forEach((finding, index) => {
      if (document.y > 700) document.addPage();
      document.moveDown(0.6).fillColor("#111827").fontSize(11)
        .text(`${index + 1}. [${finding.state}] ${pdfText(finding.title)}`);
      document.fontSize(9).fillColor("#334155")
        .text(`${finding.owaspId} | ${finding.severity} | ${finding.confidence} confidence`);
      if (finding.location) document.text(`Location: ${pdfText(finding.location)}`);
      document.text(pdfText(finding.description));
      for (const [key, value] of safeEvidence(finding.evidence)) {
        document.text(`${pdfText(key)}: ${pdfText(String(value))}`);
      }
      document.text(`Recommendation: ${pdfText(finding.recommendation)}`);
    });
    document.moveDown().fontSize(8).fillColor("#64748b")
      .text("Generated by API AC Scanner V3.2. Secrets are excluded or redacted. Findings require authorized review.");
    document.end();
  });
}

function findingHtml(finding: Finding): string {
  const evidence = safeEvidence(finding.evidence)
    .map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(String(value))}</dd>`).join("");
  return `<article class="finding"><h3>[${escapeHtml(thaiStateLabel(finding.state))} / ${escapeHtml(finding.state)}] ${escapeHtml(finding.title)}</h3>
  <p>${escapeHtml(finding.owaspId)} / ${escapeHtml(finding.severity)} / ความมั่นใจ ${escapeHtml(finding.confidence)}</p>
  ${finding.location ? `<code>${escapeHtml(finding.location)}</code>` : ""}<p>${escapeHtml(finding.description)}</p>
  <dl>${evidence}</dl><strong>วิธีตรวจยืนยันที่แนะนำ</strong><p>${escapeHtml(finding.recommendation)}</p></article>`;
}

function thaiStateLabel(state: string): string {
  return ({
    verified: "ยืนยันว่าขัดกับ Policy",
    detected: "ตรวจพบ",
    suspected: "น่าสงสัย",
    "needs-verification": "ต้องตรวจยืนยัน",
    passed: "ผ่าน",
    "not-tested": "ไม่ได้ทดสอบ",
    error: "ผิดพลาด",
  } as Record<string, string>)[state] ?? state;
}

function safeEvidence(evidence: Finding["evidence"]): Array<[string, string | number | boolean]> {
  return Object.entries(evidence).map(([key, value]) => [
    key,
    SECRET_KEY.test(key) || (typeof value === "string" && SECRET_VALUE.test(value)) ? "[redacted]" : value,
  ]);
}

function summarize(scan: ScanRecord): Record<string, number> {
  return Object.fromEntries(
    ["verified", "detected", "suspected", "needs-verification", "passed", "not-tested", "error"]
      .map((state) => [state, scan.findings.filter((finding) => finding.state === state).length]),
  );
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;",
  })[character] ?? character);
}

function pdfText(value: string): string {
  return [...value].map((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code >= 32 && code <= 126 ? character : code === 10 ? "\n" : "?";
  }).join("");
}

function safeTarget(rawTarget: string): string {
  try {
    const target = new URL(rawTarget);
    for (const key of [...target.searchParams.keys()]) {
      if (SECRET_KEY.test(key)) target.searchParams.set(key, "[redacted]");
    }
    return target.toString();
  } catch {
    return rawTarget;
  }
}
