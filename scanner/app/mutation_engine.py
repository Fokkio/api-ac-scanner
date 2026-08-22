"""Guarded local or verified-remote create-and-cleanup mutation check."""

from __future__ import annotations

import json
from typing import Any

from app.deep_engine import TestIdentity, validate_identity_headers
from app.errors import OutboundRequestError, PolicyError
from app.findings import create_finding
from app.outbound import BoundedHttpClient
from app.remote_authorization import MutationTargetAuthorization, authorize_state_changing_client
from app.authorization_signals import HTTP_OK, HTTP_MULTIPLE_CHOICES

MUTATION_BODY_LIMIT = 16_384


async def run_mutation_scan(
    target: str,
    path: str,
    body: dict[str, object],
    identity: TestIdentity,
    target_authorization: MutationTargetAuthorization,
) -> dict[str, list[Any]]:
    """POSTs one marked test resource and DELETEs the same exact path."""

    if not path.startswith("/__ac_test__/") or "?" in path or ".." in path:
        raise PolicyError("Mutation path must be inside the /__ac_test__/ namespace without a query or parent traversal")
    if body.get("apiAcScannerTest") is not True:
        raise PolicyError("Mutation body must contain apiAcScannerTest=true")
    encoded_body = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded_body) > 4096:
        raise PolicyError("Mutation body exceeded 4096 bytes")
    headers = validate_identity_headers(identity)

    verification_request_count = 1 if target_authorization.mode == "verified-remote" else 0
    async with await BoundedHttpClient.create(target, request_limit=2 + verification_request_count) as client:
        target_mode = await authorize_state_changing_client(client, target_authorization)
        try:
            created = await client.request_mutation("POST", path, headers, encoded_body, MUTATION_BODY_LIMIT)
        except OutboundRequestError:
            created = None
        try:
            cleaned = await client.request_mutation("DELETE", path, headers, None, MUTATION_BODY_LIMIT)
        except OutboundRequestError:
            cleaned = None

    create_succeeded = created is not None and HTTP_OK <= created.status < HTTP_MULTIPLE_CHOICES
    cleanup_succeeded = cleaned is not None and (
        cleaned.status in {200, 202, 204}
        or (not create_succeeded and cleaned.status == 404)
    )
    state = "passed" if create_succeeded and cleanup_succeeded else "needs-verification"
    severity = "info" if state == "passed" else "high"
    finding = create_finding(
        category="safe-mutation",
        rule_id="guarded-test-resource-create-cleanup",
        title="Test resource was created and cleaned up" if state == "passed" else "Mutation or cleanup did not complete cleanly",
        description="A marked disposable resource received POST followed by DELETE at the exact same path.",
        state=state,
        confidence="high",
        severity=severity,
        owasp_id="API5:2023",
        evidence={
            "createStatus": created.status if created else "request-failed",
            "cleanupStatus": cleaned.status if cleaned else "request-failed",
            "cleanupSucceeded": cleanup_succeeded,
            "targetMode": target_mode,
        },
        recommendation="Keep mutation tests isolated to disposable fixtures and investigate any failed cleanup immediately.",
        location=path,
    )
    return {
        "findings": [finding],
        "warnings": [
            "V3.2 mutation is POST plus DELETE only and does not test PUT/PATCH or arbitrary resources.",
            "Verified-remote mode re-checks exact-origin ownership immediately before mutation.",
        ],
    }
