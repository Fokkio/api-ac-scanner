"""Authorization matrix and finding builders for guarded workflows."""

from __future__ import annotations

from typing import Any

from app.deep_engine import TestIdentity
from app.findings import create_finding
from app.outbound import BoundedResponse


def build_matrix_row(
    identity: TestIdentity,
    step: dict[str, Any],
    response: BoundedResponse | None,
) -> dict[str, Any]:
    """Builds one expected-versus-actual workflow matrix row."""

    status = response.status if response else 0
    if response is None:
        actual = "indeterminate"
    elif 200 <= status < 300:
        actual = "allow"
    elif status in {401, 403, 404, 405}:
        actual = "deny"
    else:
        actual = "indeterminate"
    expected = str(step["expected"])
    return {
        "method": str(step["method"]).upper(), "path": str(step["path"]),
        "identity": identity.label, "role": identity.role, "tenant": identity.tenant,
        "expected": expected, "actual": actual, "actualStatus": status,
        "matchesExpectation": actual == expected,
        "skippedAfterPriorFailure": False,
    }


def build_skipped_matrix_row(
    identity: TestIdentity,
    step: dict[str, Any],
) -> dict[str, Any]:
    """Builds an indeterminate matrix row for a step that was not sent."""

    row = build_matrix_row(identity, step, None)
    row["skippedAfterPriorFailure"] = True
    return row


def build_step_finding(step: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    """Builds a finding that accurately distinguishes executed and skipped steps."""

    if row["skippedAfterPriorFailure"]:
        return _build_skipped_step_finding(step, row)
    indeterminate = row["actual"] == "indeterminate"
    mismatch = not row["matchesExpectation"] and not indeterminate
    state = "verified" if mismatch else "needs-verification" if indeterminate else "passed"
    severity = "high" if mismatch and row["expected"] == "deny" else "medium" if mismatch else "info"
    return create_finding(
        category="workflow-authorization",
        rule_id="explicit-workflow-policy-mismatch" if mismatch else "workflow-step-result",
        title=f"Workflow step {step['name']} contradicted policy" if mismatch else f"Workflow step {step['name']} completed",
        description="The observed allow/deny outcome was compared with the explicit expected decision for this step.",
        state=state,
        confidence="high" if not indeterminate else "low",
        severity=severity,
        owasp_id="API1:2023" if row["method"] in {"GET", "PUT", "PATCH", "DELETE"} else "API5:2023",
        evidence={
            "step": str(step["name"]), "method": row["method"],
            "expected": row["expected"], "actual": row["actual"],
            "status": row["actualStatus"],
        },
        recommendation="Confirm the declared policy, then fix authorization enforcement and retain this workflow as a regression test.",
        location=str(step["path"]),
    )


def build_cleanup_finding(
    results: dict[str, str | int],
    verified: dict[str, bool],
    location: str,
) -> dict[str, Any]:
    """Builds cleanup evidence without treating an ambiguous 404 as success."""

    cleanup_ok = all(verified.values())
    return create_finding(
        category="workflow-cleanup",
        rule_id="guarded-reverse-cleanup",
        title="Workflow cleanup completed" if cleanup_ok else "Workflow cleanup needs immediate review",
        description="The scanner attempted DELETE cleanup in reverse order for every mutated test path.",
        state="passed" if cleanup_ok else "needs-verification",
        confidence="high" if cleanup_ok else "medium",
        severity="info" if cleanup_ok else "high",
        owasp_id="API5:2023",
        evidence={
            "pathsAttempted": len(results),
            "cleanupSucceeded": cleanup_ok,
            **{f"cleanup:{path}": status for path, status in results.items()},
            **{f"cleanupVerified:{path}": value for path, value in verified.items()},
        },
        recommendation="Investigate any unverified cleanup before re-running the workflow.",
        location=location,
    )


def _build_skipped_step_finding(step: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    return create_finding(
        category="workflow-authorization",
        rule_id="workflow-step-skipped-after-prior-failure",
        title=f"Workflow step {step['name']} was skipped after a prior failure",
        description="The scanner did not execute this step because earlier workflow state was unreliable.",
        state="needs-verification",
        confidence="low",
        severity="info",
        owasp_id="API1:2023" if row["method"] in {"GET", "PUT", "PATCH", "DELETE"} else "API5:2023",
        evidence={
            "step": str(step["name"]), "method": row["method"],
            "expected": row["expected"], "actual": row["actual"],
            "status": row["actualStatus"], "skippedAfterPriorFailure": True,
        },
        recommendation="Resolve the first failed workflow step, then re-run the complete workflow.",
        location=str(step["path"]),
    )
