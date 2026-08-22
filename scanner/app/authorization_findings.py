"""Pure classification helpers for authorization response evidence."""

from __future__ import annotations

from dataclasses import dataclass
import difflib
import json
from typing import Any

from app.findings import create_finding
from app.outbound import BoundedResponse
from app.authorization_signals import detect_body_signal, json_field_diff, classify_decision


@dataclass(frozen=True)
class FindingSpec:
    """Text and severity selected by one authorization decision."""

    rule_id: str
    title: str
    description: str
    state: str
    confidence: str
    severity: str
    recommendation: str


def classify_object_access(
    location: str,
    owner: BoundedResponse,
    alternate: BoundedResponse,
) -> dict[str, Any]:
    """Classifies cross-identity access to one owner-selected object."""

    evidence = {
        "ownerStatus": owner.status,
        "alternateStatus": alternate.status,
        "ownerBodyBytes": len(owner.body),
        "alternateBodyBytes": len(alternate.body),
        "bodySimilarity": body_similarity(owner.body, alternate.body),
        "bodiesIdentical": owner.body == alternate.body,
        "bodyFieldDiff": json_field_diff(owner.body, alternate.body),
    }
    if not is_success(owner.status):
        spec = FindingSpec(
            "deep-owner-baseline-unavailable", "Owner baseline could not be established",
            "The owner identity did not receive success, so cross-user authorization cannot be assessed.",
            "needs-verification", "high", "info",
            "Provide an object path owned by the first test identity.",
        )
    elif alternate.status in (401, 403, 404):
        spec = FindingSpec(
            "deep-object-access-denied", "Alternate identity was denied object access",
            "The response is consistent with object-level authorization enforcement.",
            "passed", "high", "info",
            "Keep a regression test for this exact identity and object boundary.",
        )
    else:
        spec = _successful_or_inconclusive_object_spec(alternate, evidence)
    return _create_access_finding("bola", "API1:2023", location, evidence, spec)


def _successful_or_inconclusive_object_spec(
    alternate: BoundedResponse,
    evidence: dict[str, Any],
) -> FindingSpec:
    if not is_success(alternate.status):
        return FindingSpec(
            "deep-object-inconclusive", "Alternate object response was inconclusive",
            "The alternate identity was neither clearly denied nor successfully served.",
            "needs-verification", "low", "info",
            "Review the response contract and local application logs.",
        )
    similarity = float(evidence["bodySimilarity"])
    identical = bool(evidence.get("bodiesIdentical", False))
    if identical:
        # Owner and alternate received byte-identical bodies: strongest shared-data signal.
        return FindingSpec(
            "deep-cross-user-object-response", "Both identities received a successful object response",
            "The owner and alternate identities received byte-identical object bodies; this is a strong "
            "shared-or-unauthorized-data signal (similarity is not proof of business authorization).",
            "suspected", "high", "high",
            "Confirm owner or tenant identifiers and the business sharing policy.",
        )
    return FindingSpec(
        "deep-cross-user-object-response", "Both identities received a successful object response",
        "The response may represent unauthorized, shared, public or generic data; field-level differences "
        "were found but similarity alone is not proof of authorization.",
        "suspected" if similarity >= 0.85 else "needs-verification",
        "medium" if similarity >= 0.85 else "low",
        "high" if similarity >= 0.85 else "medium",
        "Confirm owner or tenant identifiers and the business sharing policy.",
    )


def classify_function_access(
    location: str,
    privileged: BoundedResponse,
    lower: BoundedResponse,
) -> dict[str, Any]:
    """Classifies access by a lower-role identity to a restricted function."""

    evidence = {
        "privilegedStatus": privileged.status,
        "lowerPrivilegeStatus": lower.status,
        "lowerPrivilegeBodyBytes": len(lower.body),
        "lowerPrivilegeBodyTruncated": lower.is_truncated,
    }
    if not is_success(privileged.status):
        spec = FindingSpec(
            "deep-function-baseline-unavailable", "Privileged function baseline could not be established",
            "The expected privileged identity did not receive success, so role enforcement cannot be assessed.",
            "needs-verification", "high", "info",
            "Provide a working path and an identity that should be authorized.",
        )
    elif lower.status in (401, 403, 404):
        spec = FindingSpec(
            "deep-function-access-denied", "Lower-privilege identity was denied function access",
            "The response is consistent with function-level authorization enforcement.",
            "passed", "high", "info", "Retain a negative authorization regression test.",
        )
    else:
        spec = _successful_or_inconclusive_function_spec(lower)
    return _create_access_finding("bfla", "API5:2023", location, evidence, spec)


def _successful_or_inconclusive_function_spec(lower: BoundedResponse) -> FindingSpec:
    if is_success(lower.status):
        return FindingSpec(
            "deep-function-success-response", "Restricted-function candidate returned a successful response",
            "The lower-role identity reached a path identified as restricted; confirm privileged data or behavior.",
            "suspected", "medium", "high",
            "Verify the expected role matrix and response content before reporting BFLA.",
        )
    return FindingSpec(
        "deep-function-inconclusive", "Function-level response was inconclusive",
        "The route did not clearly allow or deny the lower-role identity.",
        "needs-verification", "low", "info",
        "Review application logs and the route error contract.",
    )


def classify_anonymous_access(
    location: str,
    path_kind: str,
    authorized: BoundedResponse,
    anonymous: BoundedResponse,
) -> dict[str, Any]:
    """Classifies an anonymous request against an authorized baseline."""

    evidence = {
        "authorizedStatus": authorized.status,
        "anonymousStatus": anonymous.status,
        "anonymousBodyBytes": len(anonymous.body),
        "bodySimilarity": body_similarity(authorized.body, anonymous.body),
        "bodyFieldDiff": json_field_diff(authorized.body, anonymous.body),
    }
    anonymous_decision = classify_decision(anonymous.status, anonymous.body)
    if not is_success(authorized.status):
        values = ("not-tested", "high", "info", "Anonymous-access baseline unavailable")
    elif anonymous_decision == "deny":
        values = ("passed", "high", "info", "Anonymous access was denied")
    elif anonymous_decision == "allow":
        values = ("suspected", "medium", "high", "Anonymous request received a successful response")
    else:
        values = ("needs-verification", "low", "medium", "Anonymous-access response was inconclusive")
    state, confidence, severity, title = values
    return create_finding(
        category="unauthenticated-access", rule_id=f"deep-anonymous-{path_kind}-access",
        title=title,
        description="The route was compared with the expected identity and without an Authorization header.",
        state=state, confidence=confidence, severity=severity,
        owasp_id="API5:2023" if path_kind == "function" else "API1:2023",
        evidence=evidence,
        recommendation="Confirm whether anonymous access is intended and add a deny-by-default test.",
        location=location,
    )


def detect_property_exposure(
    location: str,
    owner: BoundedResponse,
    alternate: BoundedResponse,
) -> dict[str, Any] | None:
    """Flags sensitive property names returned to the alternate identity."""

    if not (is_success(owner.status) and is_success(alternate.status)):
        return None
    keys = _top_level_json_keys(alternate.body)
    sensitive_names = {
        "email", "phone", "role", "roles", "permission", "permissions",
        "isadmin", "ownerid", "tenantid", "accountid", "userid",
    }
    sensitive_keys = sorted(key for key in keys if key.lower().replace("_", "") in sensitive_names)
    if not sensitive_keys:
        return None
    return create_finding(
        category="property-authorization", rule_id="deep-sensitive-property-response",
        title="Alternate identity received sensitive property names",
        description="The response included names tied to identity, tenancy or privilege. Values were not retained.",
        state="needs-verification", confidence="medium", severity="medium", owasp_id="API3:2023",
        evidence={"sensitivePropertyNames": ", ".join(sensitive_keys), "propertyCount": len(keys)},
        recommendation="Confirm field-level policy and return only authorized properties.", location=location,
    )


def classify_enumeration(
    existing_path: str,
    missing_path: str,
    existing: BoundedResponse,
    missing: BoundedResponse,
) -> dict[str, Any]:
    """Classifies bounded response differences between existing and missing resources."""

    maximum_length = max(len(existing.body), len(missing.body), 1)
    length_delta = abs(len(existing.body) - len(missing.body))
    materially_different = length_delta >= 64 and length_delta / maximum_length >= 0.20
    differs = existing.status != missing.status or materially_different
    return create_finding(
        category="enumeration", rule_id="deep-resource-enumeration-difference",
        title="Existing and missing resource responses differ" if differs else "Existing and missing responses were materially uniform",
        description="Known-existing and known-missing paths were compared by status, bounded size and timing.",
        state="suspected" if differs else "passed", confidence="medium",
        severity="medium" if differs else "info", owasp_id="API2:2023",
        evidence={
            "existingStatus": existing.status, "missingStatus": missing.status,
            "existingBodyBytes": len(existing.body), "missingBodyBytes": len(missing.body),
            "bodyLengthDelta": length_delta, "existingElapsedMs": existing.elapsed_ms,
            "missingElapsedMs": missing.elapsed_ms,
        },
        recommendation="Use uniform errors and rate limits; repeat timing tests before reporting.",
        location=f"{existing_path} vs {missing_path}",
    )


def _create_access_finding(
    category: str,
    owasp_id: str,
    location: str,
    evidence: dict[str, Any],
    spec: FindingSpec,
) -> dict[str, Any]:
    return create_finding(
        category=category, rule_id=spec.rule_id, title=spec.title,
        description=spec.description, state=spec.state, confidence=spec.confidence,
        severity=spec.severity, owasp_id=owasp_id, evidence=evidence,
        recommendation=spec.recommendation, location=location,
    )


def _top_level_json_keys(body: bytes) -> list[str]:
    try:
        payload = json.loads(body.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []
    return sorted(str(key) for key in payload.keys())[:50]


def body_similarity(left: bytes, right: bytes) -> float:
    """Returns a bounded similarity ratio for two capped response bodies."""
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    return round(difflib.SequenceMatcher(None, left, right, autojunk=True).ratio(), 3)


def is_success(status: int) -> bool:
    """Returns true for an HTTP success status."""

    return 200 <= status < 300
