"""Authorized cross-identity access-control scan orchestration."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from app.authorization_findings import (
    classify_anonymous_access,
    classify_enumeration,
    classify_function_access,
    classify_object_access,
    detect_property_exposure,
)
from app.errors import PolicyError
from app.findings import create_finding
from app.outbound import BoundedHttpClient
from app.policy import build_same_origin_url

DEEP_BODY_LIMIT = 16_384


@dataclass(frozen=True)
class DeepScanPlan:
    """Validated inputs needed to build an authorization matrix."""

    target: str
    object_paths: list[str]
    function_paths: list[str]
    enumeration_existing_paths: list[str]
    enumeration_missing_paths: list[str]
    identities: tuple["TestIdentity", "TestIdentity"]
    policy_rules: tuple["AuthorizationPolicyRule", ...]


@dataclass(frozen=True)
class TestIdentity:
    """One bounded test identity whose headers remain in job memory."""

    label: str
    role: str
    tenant: str
    headers: dict[str, str]


@dataclass(frozen=True)
class AuthorizationPolicyRule:
    """Explicit expected decision for one identity and endpoint."""

    method: str
    path: str
    identity: str
    expected: str


async def run_deep_scan(plan: DeepScanPlan) -> dict[str, list[Any]]:
    """Runs cross-user, lower-role, anonymous and enumeration checks."""

    owner_headers, alternate_headers = _build_identity_headers(plan)
    _validate_enumeration_pairs(plan)
    policy_index = _validate_policy(plan)
    findings: list[dict[str, Any]] = []
    matrix: list[dict[str, Any]] = []
    request_limit = _calculate_request_limit(plan)

    async with await BoundedHttpClient.create(plan.target, request_limit=request_limit) as client:
        _validate_all_paths(client, plan)
        for object_path in plan.object_paths:
            object_findings, object_matrix = await _check_object_access(
                client, object_path, plan.identities, owner_headers, alternate_headers,
                policy_index,
            )
            findings.extend(object_findings)
            matrix.extend(object_matrix)
        for function_path in plan.function_paths:
            function_findings, function_matrix = await _check_function_access(
                client, function_path, plan.identities, owner_headers, alternate_headers,
                policy_index,
            )
            findings.extend(function_findings)
            matrix.extend(function_matrix)
        for existing_path, missing_path in zip(
            plan.enumeration_existing_paths, plan.enumeration_missing_paths, strict=True,
        ):
            findings.append(await _check_enumeration(client, existing_path, missing_path))

    findings.extend(_verified_policy_findings(matrix, set(plan.object_paths)))

    warnings = [
        "Successful responses are behavioral evidence, not proof of unauthorized business data or actions."
    ]
    if plan.enumeration_existing_paths:
        warnings.append(
            "Enumeration uses one bounded sample per path; repeat manually before reporting timing-related differences."
        )
    warnings.append("Verified means the observed response contradicted an explicit user-supplied policy rule.")
    return {"findings": findings, "warnings": warnings, "matrix": matrix}


def _build_identity_headers(plan: DeepScanPlan) -> tuple[dict[str, str], dict[str, str]]:
    normalized = tuple(validate_identity_headers(identity) for identity in plan.identities)
    if normalized[0] == normalized[1]:
        raise PolicyError("Deep scan credentials must represent different identities")
    return normalized


def validate_identity_headers(identity: TestIdentity, allow_empty: bool = False) -> dict[str, str]:
    minimum_headers = 0 if allow_empty else 1
    if not identity.label.strip() or len(identity.label) > 64 or not minimum_headers <= len(identity.headers) <= 5:
        raise PolicyError("Identity profile is outside the accepted bounds")
    forbidden = {
        "connection", "content-length", "host", "proxy-authorization", "te", "trailer",
        "transfer-encoding", "upgrade", "x-scanner-token",
    }
    normalized: dict[str, str] = {}
    for raw_name, value in identity.headers.items():
        name = raw_name.strip().lower()
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or name in forbidden:
            raise PolicyError("Identity profile contains an invalid or reserved header")
        if len(value) not in range(1, 8193) or any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value):
            raise PolicyError("Identity profile contains an invalid header value")
        normalized[name] = value
    return normalized


def _validate_enumeration_pairs(plan: DeepScanPlan) -> None:
    if len(plan.enumeration_existing_paths) != len(plan.enumeration_missing_paths):
        raise PolicyError("Enumeration path lists must contain the same number of entries")


def _validate_policy(plan: DeepScanPlan) -> dict[tuple[str, str], str]:
    labels = [plan.identities[0].label, plan.identities[1].label, "Anonymous"]
    if len(set(labels)) != 3:
        raise PolicyError("Identity labels must be unique and cannot use Anonymous")
    paths = [*plan.object_paths, *plan.function_paths]
    expected_keys = {(path, label) for path in paths for label in labels}
    policy_index: dict[tuple[str, str], str] = {}
    for rule in plan.policy_rules:
        if rule.method not in {"GET", "POST", "PUT", "PATCH", "DELETE"} or rule.expected not in {"allow", "deny"}:
            raise PolicyError("Authorization policy contains an unsupported decision")
        key = (rule.path, rule.identity)
        if key in policy_index:
            raise PolicyError("Authorization policy contains a duplicate rule")
        policy_index[key] = rule.expected
    if set(policy_index) != expected_keys:
        raise PolicyError("Authorization policy must define every identity and scanned object/function path exactly once")
    return policy_index


def _calculate_request_limit(plan: DeepScanPlan) -> int:
    object_requests = len(plan.object_paths) * 3
    function_requests = len(plan.function_paths) * 3
    enumeration_requests = len(plan.enumeration_existing_paths) * 2
    return object_requests + function_requests + enumeration_requests


def _validate_all_paths(client: BoundedHttpClient, plan: DeepScanPlan) -> None:
    all_paths = (
        *plan.object_paths,
        *plan.function_paths,
        *plan.enumeration_existing_paths,
        *plan.enumeration_missing_paths,
    )
    for relative_path in all_paths:
        build_same_origin_url(client.target, relative_path)


async def _check_object_access(
    client: BoundedHttpClient,
    relative_path: str,
    identities: tuple[TestIdentity, TestIdentity],
    owner_headers: dict[str, str],
    alternate_headers: dict[str, str],
    policy_index: dict[tuple[str, str], str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    owner = await client.request_path("GET", relative_path, owner_headers, DEEP_BODY_LIMIT)
    alternate = await client.request_path("GET", relative_path, alternate_headers, DEEP_BODY_LIMIT)
    anonymous = await client.request_path("GET", relative_path, {}, DEEP_BODY_LIMIT)
    findings = [
        classify_object_access(relative_path, owner, alternate),
        classify_anonymous_access(relative_path, "object", owner, anonymous),
    ]
    property_finding = detect_property_exposure(relative_path, owner, alternate)
    if property_finding:
        findings.append(property_finding)
    matrix = _matrix_rows(relative_path, identities, owner, alternate, anonymous, policy_index)
    return findings, matrix


async def _check_function_access(
    client: BoundedHttpClient,
    relative_path: str,
    identities: tuple[TestIdentity, TestIdentity],
    privileged_headers: dict[str, str],
    lower_headers: dict[str, str],
    policy_index: dict[tuple[str, str], str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    privileged = await client.request_path("GET", relative_path, privileged_headers, DEEP_BODY_LIMIT)
    lower = await client.request_path("GET", relative_path, lower_headers, DEEP_BODY_LIMIT)
    anonymous = await client.request_path("GET", relative_path, {}, DEEP_BODY_LIMIT)
    findings = [
        classify_function_access(relative_path, privileged, lower),
        classify_anonymous_access(relative_path, "function", privileged, anonymous),
    ]
    return findings, _matrix_rows(relative_path, identities, privileged, lower, anonymous, policy_index)


def _matrix_rows(
    relative_path: str,
    identities: tuple[TestIdentity, TestIdentity],
    baseline: Any,
    alternate: Any,
    anonymous: Any,
    policy_index: dict[tuple[str, str], str],
) -> list[dict[str, Any]]:
    rows = [
        _matrix_row(relative_path, identities[0], policy_index[(relative_path, identities[0].label)], baseline, "GET"),
        _matrix_row(relative_path, identities[1], policy_index[(relative_path, identities[1].label)], alternate, "GET"),
        _matrix_row(
            relative_path, TestIdentity("Anonymous", "anonymous", "", {}),
            policy_index[(relative_path, "Anonymous")], anonymous, "GET",
        ),
    ]
    return rows


def _matrix_row(
    relative_path: str, identity: TestIdentity, expected: str, response: Any, method: str = "GET",
) -> dict[str, Any]:
    from app.authorization_signals import classify_decision
    actual = classify_decision(response.status, response.body)
    return {
        "method": method, "path": relative_path, "identity": identity.label,
        "role": identity.role, "tenant": identity.tenant, "expected": expected,
        "actual": actual, "actualStatus": response.status,
        "matchesExpectation": actual == expected,
    }


def _verified_policy_findings(
    matrix: list[dict[str, Any]], object_paths: set[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for row in matrix:
        if row["matchesExpectation"] or row["actual"] == "indeterminate":
            continue
        category = "bola" if row["path"] in object_paths else "bfla"
        owasp_id = "API1:2023" if category == "bola" else "API5:2023"
        findings.append(create_finding(
            category=category,
            rule_id="verified-explicit-policy-mismatch",
            title="Observed access contradicted the explicit authorization policy",
            description="The actual allow/deny outcome differed from the complete policy supplied for this scan.",
            state="verified",
            confidence="high",
            severity="high" if row["expected"] == "deny" else "medium",
            owasp_id=owasp_id,
            evidence={
                "identity": str(row["identity"]), "expected": str(row["expected"]),
                "actual": str(row["actual"]), "actualStatus": int(row["actualStatus"]),
            },
            recommendation="Confirm the policy declaration, then fix enforcement and keep this matrix as a regression test.",
            location=str(row["path"]),
        ))
    return findings


async def _check_enumeration(
    client: BoundedHttpClient,
    existing_path: str,
    missing_path: str,
) -> dict[str, Any]:
    existing = await client.request_path("GET", existing_path, {}, DEEP_BODY_LIMIT)
    missing = await client.request_path("GET", missing_path, {}, DEEP_BODY_LIMIT)
    return classify_enumeration(existing_path, missing_path, existing, missing)
