"""Field-level body comparison and explicit body-signal detection.

These helpers make the authorization classifier body-aware instead of relying
only on raw status codes and raw-byte similarity. They back the "hard
production-usable" remediation: 404-for-denied and 200-with-error-body traps
are no longer silently trusted.
"""

from __future__ import annotations

import json
from typing import Any

# Keywords that, when present in a parseable response body, signal an explicit
# denial/error even when the transport status code looks like success.
_DENIED_BODY_SIGNALS = (
    "unauthorized", "unauthenticated", "not authorized", "forbidden", "denied", "deny",
    "not allowed", "permission", "access denied", "auth required",
    "authentication required", "you do not have", "insufficient",
)

_SUCCESS_BODY_SIGNALS = ("ok", "success", "allowed")


def json_field_diff(left: bytes, right: bytes) -> str:
    """Returns a compact summary of differing top-level JSON field values.

    Empty string when either body is not a JSON object or there is no difference.
    This is field-level (not raw-byte) comparison, so shape-identical objects with
    different scalar values (e.g. {"id":1} vs {"id":2}) are reported as differing.
    """
    try:
        left_obj = json.loads(left.decode("utf-8", errors="strict"))
        right_obj = json.loads(right.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ""
    if not isinstance(left_obj, dict) or not isinstance(right_obj, dict):
        return ""
    if left_obj == right_obj:
        return ""
    differing: list[str] = []
    keys = sorted(set(left_obj) | set(right_obj))
    for key in keys:
        if left_obj.get(key) != right_obj.get(key):
            differing.append(str(key))
    return ",".join(differing[:20])


def detect_body_signal(body: bytes) -> str | None:
    """Detects an explicit denial/error signal inside a response body.

    Returns one of "denied" (body signals refusal) or "success" (body signals OK),
    or None when the body is not a clear signal. The signal is matched on parsed
    JSON fields first, then on a case-insensitive raw substring scan.
    """
    try:
        payload = json.loads(body.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None

    if isinstance(payload, dict):
        for field in ("success", "ok", "error", "status", "code"):
            value = payload.get(field)
            if isinstance(value, bool):
                return "success" if value else "denied"
            if isinstance(value, str):
                lowered = value.lower()
                if any(signal in lowered for signal in _DENIED_BODY_SIGNALS):
                    return "denied"
                if lowered in _SUCCESS_BODY_SIGNALS:
                    return "success"
            if isinstance(value, int) and value >= 400:
                return "denied"

    try:
        text = body.decode("utf-8", errors="replace").lower()
    except UnicodeDecodeError:
        return None
    if any(signal in text for signal in _DENIED_BODY_SIGNALS):
        return "denied"
    if '"success":true' in text or '"ok":true' in text:
        return "success"
    return None


def classify_decision(status: int, body: bytes) -> str:
    """Classifies allow/deny using status with body-signal correction.

    Status-only rules: 2xx => allow, 401/403/404 => deny. When the body signals
    the opposite of what the status implies, the result is downgraded to
    "indeterminate" so the classifier never asserts a wrong allow/deny.
    """
    status_implies_allow = 200 <= status < 300
    signal = detect_body_signal(body)
    if signal == "denied" and status_implies_allow:
        return "indeterminate"
    if signal == "success" and not status_implies_allow:
        return "indeterminate"
    if status_implies_allow:
        return "allow"
    if status in (401, 403, 404):
        return "deny"
    return "indeterminate"
