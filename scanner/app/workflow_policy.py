"""Validation and request-body policy for guarded local workflows."""

from __future__ import annotations

import json
from typing import Any

from app.errors import PolicyError

MAX_REQUEST_BODY_BYTES = 4096
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH"})
SUPPORTED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
TEST_NAMESPACE = "/__ac_test__/"


def validate_workflow_steps(steps: list[dict[str, Any]]) -> None:
    """Validates ordered workflow metadata, paths, methods, and test markers."""

    names: set[str] = set()
    for step in steps:
        method = _validate_step_metadata(step, names)
        _validate_step_body(method, step.get("body"))


def encode_step_body(method: str, body: object) -> bytes | None:
    """Encodes one mutation body while enforcing the scanner byte limit."""

    if method not in MUTATING_METHODS:
        return None
    encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_REQUEST_BODY_BYTES:
        raise PolicyError("Workflow step body exceeded 4096 bytes")
    return encoded


def _validate_step_metadata(step: dict[str, Any], names: set[str]) -> str:
    name = str(step.get("name", "")).strip()
    method = str(step.get("method", "")).upper()
    path = str(step.get("path", ""))
    if not name or len(name) > 64 or name in names:
        raise PolicyError("Workflow step names must be unique bounded strings")
    names.add(name)
    if method not in SUPPORTED_METHODS:
        raise PolicyError("Workflow contains an unsupported method")
    if not path.startswith(TEST_NAMESPACE) or "?" in path or "#" in path:
        raise PolicyError("Every workflow path must be under /__ac_test__/ without query or fragment")
    if step.get("expected") not in {"allow", "deny"}:
        raise PolicyError("Every workflow step requires expected allow or deny")
    return method


def _validate_step_body(method: str, body: object) -> None:
    if method in MUTATING_METHODS:
        if not isinstance(body, dict) or body.get("apiAcScannerTest") is not True:
            raise PolicyError("POST, PUT and PATCH bodies must contain apiAcScannerTest=true")
        return
    if body is not None:
        raise PolicyError("GET and DELETE workflow steps cannot include a body")
