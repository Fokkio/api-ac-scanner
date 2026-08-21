"""Finding factories and evidence helpers shared by scan engines."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any


def create_finding(
    *,
    category: str,
    rule_id: str,
    title: str,
    description: str,
    state: str,
    confidence: str,
    severity: str,
    owasp_id: str,
    evidence: dict[str, str | int | bool],
    recommendation: str,
    location: str | None = None,
) -> dict[str, Any]:
    """Creates the stable finding contract consumed by the web service."""

    finding: dict[str, Any] = {
        "id": uuid.uuid4().hex,
        "category": category,
        "ruleId": rule_id,
        "title": title,
        "description": description,
        "state": state,
        "confidence": confidence,
        "severity": severity,
        "owaspId": owasp_id,
        "evidence": evidence,
        "recommendation": recommendation,
    }
    if location:
        finding["location"] = location
    return finding


def body_evidence(body: bytes, is_truncated: bool) -> dict[str, str | int | bool]:
    """Returns non-sensitive body length and digest evidence."""

    return {
        "bodyBytesCaptured": len(body),
        "bodySha256": hashlib.sha256(body).hexdigest()[:16],
        "bodyTruncated": is_truncated,
    }
