"""Tokenless discovery checks with explicit authorization limitations."""

from __future__ import annotations

from typing import Any

from app.errors import OutboundRequestError
from app.findings import body_evidence, create_finding
from app.outbound import BoundedHttpClient, BoundedResponse

QUICK_OBJECT_PATHS = ("/api/users/1", "/api/orders/1")
QUICK_ADMIN_PATHS = ("/api/admin", "/api/admin/users")


async def run_quick_scan(target: str) -> dict[str, list[Any]]:
    """Runs a tokenless discovery scan with strictly bounded requests."""

    findings: list[dict[str, Any]] = []
    warnings = [
        "Quick scan has no user identities; BOLA and BFLA cannot be confirmed in this mode."
    ]
    async with await BoundedHttpClient.create(target, request_limit=10) as client:
        response = await client.request_target("GET")
        findings.extend(_base_surface_findings(client.target.url, response))
        await _append_path_findings(client, QUICK_OBJECT_PATHS, "object", findings)
        await _append_path_findings(client, QUICK_ADMIN_PATHS, "admin", findings)
        findings.append(await _inspect_allowed_methods(client))

    findings.extend(_coverage_findings(client.target.origin))
    return {"findings": findings, "warnings": warnings}


def _base_surface_findings(url: str, response: BoundedResponse) -> list[dict[str, Any]]:
    findings = [create_finding(
        category="surface", rule_id="quick-target-response",
        title="Target responded to a bounded public request",
        description="The target was reachable without credentials. This is reachability evidence, not an access-control finding.",
        state="passed", confidence="high", severity="info", owasp_id="API9:2023",
        evidence={"status": response.status, **body_evidence(response.body, response.is_truncated)},
        recommendation="Review endpoint checks and run an authorized scan for ownership evidence.",
        location=url,
    )]
    missing_headers = _missing_security_headers(response.headers, url.startswith("https://"))
    if missing_headers:
        findings.append(create_finding(
            category="configuration", rule_id="quick-security-headers",
            title="Recommended response headers are missing",
            description="The initial response omitted defense-in-depth browser security headers.",
            state="detected", confidence="high", severity="low", owasp_id="API8:2023",
            evidence={"missingHeaders": ", ".join(missing_headers), "status": response.status},
            recommendation="Add the missing headers after compatibility testing.", location=url,
        ))
    return findings


async def _append_path_findings(
    client: BoundedHttpClient,
    paths: tuple[str, ...],
    path_kind: str,
    findings: list[dict[str, Any]],
) -> None:
    for relative_path in paths:
        try:
            response = await client.request_path("GET", relative_path)
        except OutboundRequestError:
            continue
        if 200 <= response.status < 300:
            findings.append(_public_path_finding(relative_path, path_kind, response))


def _public_path_finding(
    relative_path: str,
    path_kind: str,
    response: BoundedResponse,
) -> dict[str, Any]:
    is_admin_path = path_kind == "admin"
    return create_finding(
        category="bfla" if is_admin_path else "bola",
        rule_id=f"quick-public-{path_kind}-surface",
        title="Admin-like route answered without credentials" if is_admin_path else "Object-like route answered without credentials",
        description="A conventional path returned success without credentials. It may be public or a generic fallback.",
        state="suspected", confidence="low", severity="medium",
        owasp_id="API5:2023" if is_admin_path else "API1:2023",
        evidence={"status": response.status, **body_evidence(response.body, response.is_truncated)},
        recommendation="Confirm route purpose and expected authorization before treating this as a vulnerability.",
        location=relative_path,
    )


async def _inspect_allowed_methods(client: BoundedHttpClient) -> dict[str, Any]:
    try:
        response = await client.request_target("OPTIONS")
    except OutboundRequestError:
        return create_finding(
            category="method-surface", rule_id="quick-options-unavailable",
            title="HTTP method surface could not be enumerated",
            description="The target did not return a usable OPTIONS response.",
            state="not-tested", confidence="high", severity="info", owasp_id="API5:2023",
            evidence={"optionsRequestCompleted": False},
            recommendation="Review supported methods from the API specification.", location=client.target.url,
        )
    allow_header = response.headers.get("allow", "")
    has_write_method = any(method in allow_header.upper() for method in ("PUT", "PATCH", "DELETE"))
    return create_finding(
        category="method-surface", rule_id="quick-options-surface",
        title="HTTP method surface was enumerated",
        description="The Allow header is discovery evidence only; listed methods may still be authorized correctly.",
        state="needs-verification" if has_write_method else "passed",
        confidence="medium", severity="info", owasp_id="API5:2023",
        evidence={"status": response.status, "allow": allow_header or "not provided"},
        recommendation="Verify state-changing methods with authorized test accounts.", location=client.target.url,
    )


def _coverage_findings(origin: str) -> list[dict[str, Any]]:
    return [
        create_finding(
            category="bola", rule_id="quick-bola-not-tested",
            title="Cross-user object authorization was not tested",
            description="BOLA requires an object owner and a distinct second identity.",
            state="not-tested", confidence="high", severity="info", owasp_id="API1:2023",
            evidence={"ownerTokenProvided": False, "alternateTokenProvided": False},
            recommendation="Run an authorized scan with two dedicated test users.", location=origin,
        ),
        create_finding(
            category="bfla", rule_id="quick-bfla-not-tested",
            title="Role-bound function authorization was not tested",
            description="BFLA requires known role context and a restricted function.",
            state="not-tested", confidence="high", severity="info", owasp_id="API5:2023",
            evidence={"knownRoleContext": False},
            recommendation="Use a documented lower-privilege test identity.", location=origin,
        ),
    ]


def _missing_security_headers(headers: dict[str, str], is_https: bool) -> list[str]:
    expected_headers = ["content-security-policy", "x-content-type-options"]
    if is_https:
        expected_headers.append("strict-transport-security")
    return [header for header in expected_headers if header not in headers]
