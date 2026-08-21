"""Internal FastAPI boundary for bounded dynamic, source and discovery scans."""

from __future__ import annotations

import hmac
import os
from pathlib import Path
import subprocess

from fastapi import Depends, FastAPI, Header, HTTPException

from app.engines import AuthorizationPolicyRule, DeepScanPlan, TestIdentity, run_deep_scan, run_quick_scan
from app.errors import OutboundRequestError, PolicyError, ScannerExecutionError
from app.discovery import run_discovery
from app.models import (
    AssetVerificationRequest,
    DeepScanRequest,
    DiscoveryRequest,
    MutationScanRequest,
    WorkflowScanRequest,
    QuickScanRequest,
    SourceScanRequest,
)
from app.source_scan import run_source_scan
from app.verification import verify_asset_control
from app.mutation_engine import run_mutation_scan
from app.workflow_engine import run_workflow_scan

app = FastAPI(title="API Access-Control Scanner V3.1", version="3.1.0", docs_url=None, redoc_url=None)
INTERNAL_TOKEN = os.environ.get("SCANNER_INTERNAL_TOKEN", "")
if len(INTERNAL_TOKEN) < 16:
    raise RuntimeError("SCANNER_INTERNAL_TOKEN must contain at least 16 characters")


def require_internal_token(x_scanner_token: str = Header(default="")) -> None:
    """Authenticates calls from the private web orchestrator."""

    if not hmac.compare_digest(x_scanner_token, INTERNAL_TOKEN):
        raise HTTPException(status_code=401, detail="invalid internal credential")


@app.get("/health")
def health() -> dict[str, str]:
    """Returns scanner process health without exposing scan capabilities."""

    return {"status": "ok"}


@app.post("/v2/scans/quick", dependencies=[Depends(require_internal_token)])
async def quick_scan(request: QuickScanRequest) -> dict:
    """Runs a bounded tokenless scan."""

    return await _map_scan_errors(run_quick_scan(request.target))


@app.post("/v2/scans/deep", dependencies=[Depends(require_internal_token)])
async def deep_scan(request: DeepScanRequest) -> dict:
    """Runs a verified-origin cross-user scan with ephemeral secrets."""

    plan = DeepScanPlan(
        target=request.target,
        object_paths=request.object_paths,
        function_paths=request.admin_paths,
        enumeration_existing_paths=request.enumeration_existing_paths,
        enumeration_missing_paths=request.enumeration_missing_paths,
        identities=tuple(
            TestIdentity(
                label=profile.label,
                role=profile.role,
                tenant=profile.tenant,
                headers={name: value.get_secret_value() for name, value in profile.headers.items()},
            )
            for profile in request.identities
        ),
        policy_rules=tuple(
            AuthorizationPolicyRule(
                method=rule.method, path=rule.path, identity=rule.identity, expected=rule.expected,
            )
            for rule in request.policy_rules
        ),
    )
    return await _map_scan_errors(run_deep_scan(plan))


@app.post("/v2/scans/source", dependencies=[Depends(require_internal_token)])
def source_scan(request: SourceScanRequest) -> dict:
    """Runs a fail-closed static scan in a worker thread."""

    try:
        return run_source_scan(request.repository_path)
    except subprocess.TimeoutExpired as error:
        raise HTTPException(status_code=504, detail="static scan timed out") from error
    except PolicyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except ScannerExecutionError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error


@app.post("/v2/discovery", dependencies=[Depends(require_internal_token)])
def discovery(request: DiscoveryRequest) -> dict:
    """Builds an endpoint inventory from bounded local artifacts."""

    upload_root = os.environ.get("UPLOAD_ROOT", "/uploads")
    try:
        return run_discovery(request.repository_path, Path(upload_root), request.target)
    except PolicyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except ScannerExecutionError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.post("/v2/assets/verify", dependencies=[Depends(require_internal_token)])
async def verify_asset(request: AssetVerificationRequest) -> dict[str, bool]:
    """Checks an exact challenge file on one validated public origin."""

    try:
        verified = await verify_asset_control(
            request.origin, request.challenge, request.verification_method,
        )
        return {"verified": verified}
    except (PolicyError, OutboundRequestError):
        return {"verified": False}


@app.post("/v3/scans/mutation", dependencies=[Depends(require_internal_token)])
async def mutation_scan(request: MutationScanRequest) -> dict:
    """Runs one guarded local create-and-cleanup test."""

    identity = TestIdentity(
        label=request.identity.label,
        role=request.identity.role,
        tenant=request.identity.tenant,
        headers={name: value.get_secret_value() for name, value in request.identity.headers.items()},
    )
    return await _map_scan_errors(run_mutation_scan(
        request.target, request.path, request.body, identity,
    ))


@app.post("/v3/scans/workflow", dependencies=[Depends(require_internal_token)])
async def workflow_scan(request: WorkflowScanRequest) -> dict:
    """Runs a guarded local multi-step workflow with ephemeral authentication."""

    identity = TestIdentity(
        label=request.identity.label,
        role=request.identity.role,
        tenant=request.identity.tenant,
        headers={name: value.get_secret_value() for name, value in request.identity.headers.items()},
    )
    authentication = request.authentication.model_dump()
    for secret_name in ("username", "password"):
        secret = getattr(request.authentication, secret_name)
        authentication[secret_name] = secret.get_secret_value() if secret is not None else None
    steps = [step.model_dump() for step in request.steps]
    return await _map_scan_errors(run_workflow_scan(
        request.target, identity, authentication, steps,
    ))


async def _map_scan_errors(scan_coroutine) -> dict:
    try:
        return await scan_coroutine
    except PolicyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except OutboundRequestError as error:
        raise HTTPException(status_code=502, detail="target request failed") from error
