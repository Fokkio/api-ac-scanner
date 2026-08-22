"""Guarded local or verified-remote workflow and authentication adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.deep_engine import TestIdentity, validate_identity_headers
from app.errors import OutboundRequestError, PolicyError
from app.outbound import BoundedHttpClient, BoundedResponse
from app.workflow_auth import apply_authentication_adapter
from app.workflow_findings import (
    build_cleanup_finding,
    build_matrix_row,
    build_skipped_matrix_row,
    build_step_finding,
)
from app.workflow_policy import MUTATING_METHODS, TEST_NAMESPACE, encode_step_body, validate_workflow_steps
from app.remote_authorization import MutationTargetAuthorization, authorize_state_changing_client

BODY_LIMIT = 16_384


@dataclass
class _WorkflowExecutionState:
    findings: list[dict[str, Any]] = field(default_factory=list)
    matrix: list[dict[str, Any]] = field(default_factory=list)
    cleanup_paths: list[str] = field(default_factory=list)
    confirmed_mutation_paths: set[str] = field(default_factory=set)
    confirmed_deleted_paths: set[str] = field(default_factory=set)
    is_blocked: bool = False


async def run_workflow_scan(
    target: str,
    identity: TestIdentity,
    authentication: dict[str, Any],
    steps: list[dict[str, Any]],
    target_authorization: MutationTargetAuthorization,
) -> dict[str, list[Any]]:
    """Runs up to eight explicit guarded steps and always attempts reverse cleanup."""

    if not 1 <= len(steps) <= 8:
        raise PolicyError("Workflow must contain between 1 and 8 steps")
    adapter_type = str(authentication.get("type", "none"))
    headers = validate_identity_headers(identity, allow_empty=adapter_type == "json-login")
    validate_workflow_steps(steps)
    verification_request_count = 1 if target_authorization.mode == "verified-remote" else 0
    request_limit = min(19, len(steps) + len({step["path"] for step in steps}) + 1 + verification_request_count)
    state = _WorkflowExecutionState()

    async with await BoundedHttpClient.create(target, request_limit=request_limit) as client:
        target_mode = await authorize_state_changing_client(client, target_authorization)
        headers = await apply_authentication_adapter(client, headers, authentication)
        try:
            await _execute_steps(client, identity, headers, steps, state)
        finally:
            cleanup_results, cleanup_verified = await _cleanup_workflow(client, headers, state)

    state.findings.append(build_cleanup_finding(cleanup_results, cleanup_verified, TEST_NAMESPACE))
    return {
        "findings": state.findings,
        "warnings": [
            f"Workflow target mode: {target_mode}; every request remains inside the /__ac_test__/ namespace.",
            "Verified-remote mode re-checks exact-origin ownership immediately before authentication or mutation.",
            "Verified means an observed allow/deny result contradicted the explicit expected decision for that step.",
            "Remaining steps are skipped after the first mismatch or indeterminate result because later evidence is unreliable.",
            "Credentials and acquired tokens are used in memory only and are excluded from findings and reports.",
        ],
        "matrix": state.matrix,
    }


async def _execute_steps(
    client: BoundedHttpClient,
    identity: TestIdentity,
    headers: dict[str, str],
    steps: list[dict[str, Any]],
    state: _WorkflowExecutionState,
) -> None:
    for step in steps:
        if state.is_blocked:
            row = build_skipped_matrix_row(identity, step)
        else:
            response = await _execute_step(client, headers, step, state.cleanup_paths)
            _record_confirmed_state(step, response, state)
            row = build_matrix_row(identity, step, response)
            state.is_blocked = not row["matchesExpectation"]
        state.matrix.append(row)
        state.findings.append(build_step_finding(step, row))


async def _execute_step(
    client: BoundedHttpClient,
    headers: dict[str, str],
    step: dict[str, Any],
    cleanup_paths: list[str],
) -> BoundedResponse | None:
    method = str(step["method"]).upper()
    path = str(step["path"])
    body = encode_step_body(method, step.get("body"))
    if method in MUTATING_METHODS and path not in cleanup_paths:
        cleanup_paths.append(path)
    try:
        return await client.request_workflow(method, path, headers, body, BODY_LIMIT)
    except OutboundRequestError:
        return None


def _record_confirmed_state(
    step: dict[str, Any],
    response: BoundedResponse | None,
    state: _WorkflowExecutionState,
) -> None:
    if response is None or not 200 <= response.status < 300:
        return
    method = str(step["method"]).upper()
    path = str(step["path"])
    if method in MUTATING_METHODS:
        state.confirmed_mutation_paths.add(path)
    elif method == "DELETE":
        state.confirmed_deleted_paths.add(path)


async def _cleanup_workflow(
    client: BoundedHttpClient,
    headers: dict[str, str],
    state: _WorkflowExecutionState,
) -> tuple[dict[str, str | int], dict[str, bool]]:
    results: dict[str, str | int] = {}
    verified: dict[str, bool] = {}
    for path in reversed(state.cleanup_paths):
        try:
            response = await client.request_workflow("DELETE", path, headers, None, BODY_LIMIT)
            results[path] = response.status
        except OutboundRequestError:
            results[path] = "request-failed"
        verified[path] = _is_cleanup_verified(path, results[path], state)
    return results, verified


def _is_cleanup_verified(
    path: str,
    status: str | int,
    state: _WorkflowExecutionState,
) -> bool:
    if status in {200, 202, 204}:
        return True
    return status == 404 and (
        path not in state.confirmed_mutation_paths or path in state.confirmed_deleted_paths
    )
