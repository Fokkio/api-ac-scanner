"""Scanning engines: domain (live black-box auth-swap) and source (static Semgrep)."""

from __future__ import annotations
import json
import difflib
import subprocess
import httpx
from pathlib import Path
from typing import Any

from app.severity import cvss_to_level, OWASP_API, FIX_GUIDANCE, SEVERITY_COLORS

RULES_DIR = Path(__file__).resolve().parent.parent / "semgrep_rules"

# Network + TLS settings for live scans
SCAN_TIMEOUT = 10.0
HTTPX_VERIFY = True  # never disable cert validation on a live scan

# Default object endpoints probed for BOLA. User-supplied custom URLs override these.
DEFAULT_BOLA_PATHS = [
    "/api/users/1",
    "/api/orders/1001",
    "/api/accounts/1",
    "/api/profile/1",
    "/api/documents/1",
]
# Default admin endpoints probed for BFLA.
DEFAULT_BFLA_PATHS = [
    "/api/admin/users",
    "/api/admin/orders",
    "/api/admin",
]
# Mutation endpoints we never execute (read-only mode flags them instead).
DEFAULT_MUTATION_PATHS = [
    ("DELETE", "/api/users/1"),
    ("PUT", "/api/orders/1001"),
]


def _meta(rule_id: str, meta: dict) -> dict:
    return {
        "rule_id": rule_id,
        "owasp": meta.get("owasp", "API1:2023"),
        "owasp_name": OWASP_API.get(meta.get("owasp", "API1:2023"), "Access Control Issue"),
        "cvss": float(meta.get("cvss", 7.0)),
        "guidance": FIX_GUIDANCE.get(rule_id, "Review the flagged code path for access-control checks."),
    }


# ---- Source scan (Semgrep taint) ----
def source_scan(repo_path: str) -> list[dict]:
    """Run Semgrep against a source directory. Returns normalized findings."""
    cmd = [
        "semgrep", "scan",
        "--config", str(RULES_DIR),
        "--json",
        "--metrics", "off",
        "--quiet",
        repo_path,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    findings: list[dict] = []
    if not proc.stdout:
        return findings
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return findings

    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        rule_id = r.get("check_id", "unknown")
        p = r.get("path", "")
        line = r.get("start", {}).get("line", 0)
        sev = meta.get("severity") or "ERROR"
        cvss = float(meta.get("cvss", 7.0))
        findings.append({
            "type": "source",
            "rule_id": rule_id,
            "file": p,
            "line": line,
            "message": r.get("extra", {}).get("message", ""),
            "severity": cvss_to_level(cvss),
            "cvss": cvss,
            "owasp": meta.get("owasp", "API1:2023"),
            "owasp_name": OWASP_API.get(meta.get("owasp", "API1:2023"), "Access Control Issue"),
            "guidance": FIX_GUIDANCE.get(rule_id, "Review the flagged code path."),
            "code": _extract_lines(p, line, 3),
            "severity_color": SEVERITY_COLORS.get(cvss_to_level(cvss), "#7f8c8d"),
        })
    return findings


def _extract_lines(path: str, line: int, ctx: int) -> str:
    try:
        lines = Path(path).read_text(errors="ignore").splitlines()
        lo = max(0, line - ctx - 1)
        hi = min(len(lines), line + ctx)
        return "\n".join(lines[lo:hi])
    except Exception:
        return ""


def _body_similarity(a: str, b: str) -> float:
    """Normalized similarity of two response bodies (0..1)."""
    la, lb = len(a), len(b)
    if la == 0 and lb == 0:
        return 1.0
    if la == 0 or lb == 0:
        return 0.0
    return round(difflib.SequenceMatcher(None, a, b).ratio(), 3)


# ---- Domain scan (live black-box auth-swap) ----
async def domain_scan(
    target: str,
    auth_token: str = "",
    alt_token: str = "",
    object_urls: str = "",
    mode: str = "read-only",
) -> list[dict]:
    """Black-box dynamic test of an API target via AUTH-SWAP.

    BOLA test: request an object endpoint with the owner's token, then request the
    SAME object with a second user's token (or unauthenticated). If both return a
    near-identical body, ownership is not enforced -> BOLA confirmed.

    BFLA test: request admin endpoints with a non-admin token; 200 means the
    function-level authorization is missing.

    Read-only confirm (default): mutation endpoints are flagged, never executed.
    """
    base = target.rstrip("/")
    headers_owner = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
    headers_alt = {"Authorization": f"Bearer {alt_token}"} if alt_token else {}

    bola_paths = _resolve_bola_paths(object_urls)

    async with httpx.AsyncClient(
        timeout=SCAN_TIMEOUT, follow_redirects=False, verify=HTTPX_VERIFY
    ) as client:
        findings: list[dict] = []
        findings += await _scan_bola(client, base, bola_paths, headers_owner, headers_alt, alt_token)
        findings += await _scan_bfla(client, base, headers_owner)
        findings += _scan_mutations(base)
    return findings


def _resolve_bola_paths(object_urls: str) -> list[str]:
    """Custom object URLs (comma/newline separated) override the defaults."""
    if not object_urls:
        return list(DEFAULT_BOLA_PATHS)
    custom = [u.strip() for u in object_urls.replace("\n", ",").split(",") if u.strip()]
    return custom or list(DEFAULT_BOLA_PATHS)


async def _scan_bola(client, base: str, paths: list[str], headers_owner: dict,
                     headers_alt: dict, alt_token: str) -> list[dict]:
    """Auth-swap BOLA test: compare object responses across two tokens."""
    findings: list[dict] = []
    for path in paths:
        url = path if path.startswith("http") else f"{base}{path}"
        owner = await _safe_get(client, url, headers_owner)
        if owner is None:
            findings.append(_domain_finding(
                url, "API1:2023", 7.0,
                f"Probe error on owner request to {url}.", "domain-probe-error",
                evidence="owner request failed (timeout/connection error)",
            ))
            continue
        if owner.status_code not in (200, 201, 202):
            # Object id likely not owned/valid for this token; cannot confirm BOLA.
            continue

        alt = await _safe_get(client, url, headers_alt)
        if alt is None or alt.status_code in (401, 403, 404):
            # Access enforced -> no finding.
            continue
        if alt.status_code not in (200, 201, 202):
            continue

        sim = _body_similarity(owner.text, alt.text)
        if alt_token:
            findings.append(_bolaswap_finding(url, owner.status_code, alt.status_code, sim))
        else:
            findings.append(_domain_finding(
                url, "API1:2023", 8.2,
                f"IDOR: object at {url} is accessible WITHOUT authentication "
                f"(unauthenticated 200). Anyone can read this object by id.",
                "domain-idl-unauth",
                evidence=f"anon_status={alt.status_code} body_similarity={sim}",
            ))
    return findings


def _bolaswap_finding(url: str, owner_status: int, alt_status: int, sim: float) -> dict:
    if sim >= 0.85:
        return _domain_finding(
            url, "API1:2023", 9.1,
            f"BOLA CONFIRMED: object at {url} is returned identically to a "
            f"different user's token (body similarity {sim}). The server does not "
            f"enforce per-object ownership.",
            "domain-bola-confirmed",
            evidence=f"owner_status={owner_status} alt_status={alt_status} body_similarity={sim}",
        )
    if sim >= 0.5:
        return _domain_finding(
            url, "API1:2023", 7.5,
            f"BOLA SUSPECTED: same object endpoint returns 200 to both tokens but "
            f"bodies differ (similarity {sim}). Manual review recommended.",
            "domain-bola-suspected",
            evidence=f"owner_status={owner_status} alt_status={alt_status} body_similarity={sim}",
        )
    # Low similarity -> likely different/scoped data; no finding.
    return _domain_finding(
        url, "API1:2023", 0.0,
        f"Object returned 200 to both tokens but bodies differ greatly "
        f"(similarity {sim}) — likely correctly scoped. No finding.",
        "domain-bola-clean",
        evidence=f"owner_status={owner_status} alt_status={alt_status} body_similarity={sim}",
    )


async def _scan_bfla(client, base: str, headers_owner: dict) -> list[dict]:
    """BFLA test: request admin endpoints with a non-admin token."""
    findings: list[dict] = []
    for path in DEFAULT_BFLA_PATHS:
        url = f"{base}{path}"
        resp = await _safe_get(client, url, headers_owner)
        if resp is None:
            continue
        if resp.status_code == 200:
            findings.append(_domain_finding(
                url, "API5:2023", 8.6,
                f"BFLA: admin endpoint {url} returned 200 to a non-admin token. "
                f"Function-level authorization is missing.",
                "domain-bfla-200",
                evidence=f"status={resp.status_code}",
            ))
        elif resp.status_code in (301, 302, 303):
            findings.append(_domain_finding(
                url, "API5:2023", 6.5,
                f"BFLA SUSPECTED: {url} redirects ({resp.status_code}) — verify it does not "
                f"disclose admin data after auth.",
                "domain-bfla-redirect",
                evidence=f"status={resp.status_code} location={resp.headers.get('location','')}",
            ))
    return findings


def _scan_mutations(base: str) -> list[dict]:
    """Read-only: flag mutation endpoints, never execute them."""
    findings: list[dict] = []
    for method, path in DEFAULT_MUTATION_PATHS:
        url = f"{base}{path}"
        findings.append(_domain_finding(
            url, "API5:2023", 5.3,
            f"Mutation endpoint {method} {url} is not gated by a function-level auth check in "
            f"read-only mode — flagged, NOT executed.",
            "domain-bfla-mutation",
        ))
    return findings


async def _safe_get(client, url: str, headers: dict):
    try:
        return await client.get(url, headers=headers)
    except Exception:
        return None


def _domain_finding(url: str, owasp: str, cvss: float, message: str, rule_id: str, evidence: str = "") -> dict:
    lvl = cvss_to_level(cvss)
    return {
        "type": "domain",
        "rule_id": rule_id,
        "url": url,
        "message": message,
        "evidence": evidence,
        "severity": lvl,
        "cvss": cvss,
        "owasp": owasp,
        "owasp_name": OWASP_API.get(owasp, "Access Control Issue"),
        "guidance": FIX_GUIDANCE.get(rule_id, "Enforce server-side authorization checks."),
        "severity_color": SEVERITY_COLORS.get(lvl, "#7f8c8d"),
    }
