"""Ephemeral same-origin authentication adapters for guarded workflows."""

from __future__ import annotations

import json
import re
from typing import Any

from app.errors import PolicyError
from app.outbound import BoundedHttpClient, BoundedResponse

AUTHENTICATION_BODY_LIMIT = 16_384
MAX_AUTHENTICATION_VALUE_LENGTH = 8192
MAX_REQUEST_BODY_BYTES = 4096
DELETE_CHARACTER_CODE = 127
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


async def apply_authentication_adapter(
    client: BoundedHttpClient,
    base_headers: dict[str, str],
    adapter: dict[str, Any],
) -> dict[str, str]:
    """Acquires one credential and replaces all base credentials when configured."""

    adapter_type = str(adapter.get("type", "none"))
    if adapter_type == "none":
        return base_headers
    if adapter_type != "json-login":
        raise PolicyError("Unsupported authentication adapter")
    path = _validate_adapter_path(adapter)
    payload = _build_login_payload(adapter)
    response = await client.request_workflow(
        "POST", path, {}, payload, AUTHENTICATION_BODY_LIMIT,
    )
    if not 200 <= response.status < 300:
        raise PolicyError("Authentication adapter did not receive a successful response")
    return _build_token_header(response, adapter)


def _validate_adapter_path(adapter: dict[str, Any]) -> str:
    path = str(adapter.get("path") or "")
    if not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path:
        raise PolicyError("Authentication adapter path must be a query-free same-origin relative path")
    return path


def _build_login_payload(adapter: dict[str, Any]) -> bytes:
    username = adapter.get("username")
    password = adapter.get("password")
    if not _is_bounded_secret(username) or not _is_bounded_secret(password):
        raise PolicyError("JSON login adapter requires bounded test credentials")
    username_field = str(adapter.get("username_field", "username"))
    password_field = str(adapter.get("password_field", "password"))
    if not _safe_json_key(username_field) or not _safe_json_key(password_field):
        raise PolicyError("Authentication field names are invalid")
    payload = json.dumps(
        {username_field: username, password_field: password},
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    if len(payload) > MAX_REQUEST_BODY_BYTES:
        raise PolicyError("Authentication request exceeded 4096 bytes")
    return payload


def _build_token_header(
    response: BoundedResponse,
    adapter: dict[str, Any],
) -> dict[str, str]:
    token = _extract_json_string(response, str(adapter.get("token_json_path", "accessToken")))
    header_name = str(adapter.get("header_name", "authorization")).strip().lower()
    if not HEADER_NAME.fullmatch(header_name) or header_name in {"host", "content-length", "x-scanner-token"}:
        raise PolicyError("Authentication adapter header is invalid or reserved")
    scheme = str(adapter.get("scheme", "Bearer")).strip()
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]{0,31}", scheme):
        raise PolicyError("Authentication token scheme is invalid")
    value = f"{scheme} {token}".strip()
    if len(value) > MAX_AUTHENTICATION_VALUE_LENGTH or _has_forbidden_control(value):
        raise PolicyError("Authentication adapter returned an oversized token")
    return {header_name: value}


def _is_bounded_secret(value: object) -> bool:
    return isinstance(value, str) and (
        1 <= len(value) <= MAX_AUTHENTICATION_VALUE_LENGTH
        and not _has_forbidden_control(value)
    )


def _safe_json_key(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", value))


def _has_forbidden_control(value: str) -> bool:
    return any(
        (ord(character) < 32 and character != "\t")
        or ord(character) == DELETE_CHARACTER_CODE
        for character in value
    )


def _extract_json_string(response: BoundedResponse, dotted_path: str) -> str:
    try:
        value: Any = json.loads(response.text)
    except json.JSONDecodeError as error:
        raise PolicyError("Authentication adapter response was not valid JSON") from error
    for segment in dotted_path.split("."):
        if not _safe_json_key(segment) or not isinstance(value, dict) or segment not in value:
            raise PolicyError("Authentication token field was not found")
        value = value[segment]
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_AUTHENTICATION_VALUE_LENGTH:
        raise PolicyError("Authentication token must be a bounded string")
    return value
