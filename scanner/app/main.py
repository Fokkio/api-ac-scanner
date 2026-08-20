"""Scanner service: FastAPI app exposing source + domain scan endpoints.

Communicates with the web service over the internal docker network.
"""

from __future__ import annotations
import subprocess
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from app.engines import source_scan, domain_scan

app = FastAPI(title="API Access-Control Scanner", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class SourceScanReq(BaseModel):
    repo_path: str  # path inside the mounted volume (e.g. /scans/<id>)


class DomainScanReq(BaseModel):
    target: str
    auth_token: Optional[str] = ""
    alt_token: Optional[str] = ""
    object_urls: Optional[str] = ""
    mode: Optional[str] = "read-only"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan/source")
def scan_source(req: SourceScanReq):
    """Static source-code scan. Returns findings from Semgrep rules."""
    from pathlib import Path
    p = Path(req.repo_path)
    if not p.exists():
        raise HTTPException(status_code=400, detail=f"path not found: {req.repo_path}")
    try:
        findings = source_scan(req.repo_path)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="scan timed out")
    return {"findings": findings, "count": len(findings)}


@app.post("/scan/domain")
async def scan_domain(req: DomainScanReq):
    """Live black-box domain scan (read-only confirm by default)."""
    if not req.target.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="target must be http(s)://")
    findings = await domain_scan(
        req.target,
        req.auth_token or "",
        req.alt_token or "",
        req.object_urls or "",
        req.mode or "read-only",
    )
    return {"findings": findings, "count": len(findings)}


class FixReq(BaseModel):
    file_path: str
    rule_id: str


@app.post("/fix/preview")
def fix_preview(req: FixReq):
    """Return a preview of the auto-fix for a source finding."""
    from app.fixers import fix_for
    from pathlib import Path
    p = Path(req.file_path)
    if not p.exists():
        raise HTTPException(status_code=400, detail=f"file not found: {req.file_path}")
    original = p.read_text(errors="ignore")
    fixed, changes = fix_for(req.rule_id, original)
    return {"original": original, "fixed": fixed, "changes": changes, "rule_id": req.rule_id}


@app.post("/fix/apply")
def fix_apply(req: FixReq):
    """Apply the auto-fix to the uploaded copy of the file."""
    from app.fixers import fix_for
    from pathlib import Path
    p = Path(req.file_path)
    if not p.exists():
        raise HTTPException(status_code=400, detail=f"file not found: {req.file_path}")
    original = p.read_text(errors="ignore")
    fixed, changes = fix_for(req.rule_id, original)
    if fixed != original:
        p.write_text(fixed, encoding="utf-8")
        return {"ok": True, "changes": changes}
    return {"ok": False, "reason": "no change generated"}
