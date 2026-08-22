"""Exact-origin authorization policy for guarded state-changing scans."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Literal
from urllib.parse import SplitResult, urlsplit

from app.errors import OutboundRequestError, PolicyError
from app.outbound import BoundedHttpClient
from app.verification import verify_asset_control_with_client

AuthorizationMode = Literal["local", "verified-remote"]
ExternalVerificationMethod = Literal["file", "header", "dns"]
HTTPS_PORT = 443


@dataclass(frozen=True)
class MutationTargetAuthorization:
    """Proof and mode supplied by the trusted web orchestrator."""

    mode: AuthorizationMode = "local"
    challenge: str | None = None
    verification_method: ExternalVerificationMethod | None = None


async def authorize_state_changing_client(
    client: BoundedHttpClient,
    authorization: MutationTargetAuthorization,
) -> AuthorizationMode:
    """Authorizes a local target or re-verifies an exact remote HTTPS origin."""

    if client.target.is_local:
        return _authorize_local(authorization)
    challenge, verification_method = _require_remote_proof(authorization)
    _require_exact_remote_origin(client)
    _require_remote_feature_enabled(client.target.origin)
    await _verify_live_proof(client, challenge, verification_method)
    return "verified-remote"


def _authorize_local(authorization: MutationTargetAuthorization) -> AuthorizationMode:
    if authorization.mode != "local":
        raise PolicyError("Local targets require local target authorization")
    return "local"


def _require_remote_proof(
    authorization: MutationTargetAuthorization,
) -> tuple[str, ExternalVerificationMethod]:
    if authorization.mode != "verified-remote":
        raise PolicyError("Remote state-changing scans require verified-remote target authorization")
    if not authorization.challenge or not authorization.verification_method:
        raise PolicyError("Remote target authorization proof is incomplete")
    return authorization.challenge, authorization.verification_method


def _require_exact_remote_origin(client: BoundedHttpClient) -> None:
    if client.target.url != f"{client.target.origin}/":
        raise PolicyError("Remote state-changing targets must be exact origins without paths or queries")


async def _verify_live_proof(
    client: BoundedHttpClient,
    challenge: str,
    verification_method: ExternalVerificationMethod,
) -> None:
    try:
        is_verified = await verify_asset_control_with_client(
            client,
            challenge,
            verification_method,
        )
    except (OutboundRequestError, OSError) as error:
        raise PolicyError("Remote ownership verification could not be completed") from error
    if not is_verified:
        raise PolicyError("Remote ownership verification is no longer valid")


def _require_remote_feature_enabled(origin: str) -> None:
    enabled_value = os.environ.get("REMOTE_SAFE_MUTATION_ENABLED", "false").strip().lower()
    if enabled_value not in {"true", "false"}:
        raise PolicyError("REMOTE_SAFE_MUTATION_ENABLED must be true or false")
    if enabled_value != "true":
        raise PolicyError("Remote safe mutation is disabled")
    if not origin.startswith("https://"):
        raise PolicyError("Remote safe mutation requires HTTPS")
    allowed_origins = _read_allowed_origins()
    if origin not in allowed_origins:
        raise PolicyError("Remote origin is not in the exact mutation allowlist")


def _read_allowed_origins() -> frozenset[str]:
    raw_origins = os.environ.get("REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS", "")
    normalized_origins: set[str] = set()
    for raw_origin in raw_origins.split(","):
        candidate = raw_origin.strip()
        if not candidate:
            continue
        normalized_origins.add(_normalize_allowed_origin(candidate))
    if not normalized_origins:
        raise PolicyError("Remote mutation allowlist is empty")
    return frozenset(normalized_origins)


def _normalize_allowed_origin(candidate: str) -> str:
    parsed = urlsplit(candidate)
    port = _read_port(parsed)
    if not _is_exact_https_origin(parsed, port):
        raise PolicyError("Remote mutation allowlist must contain exact HTTPS origins on port 443")
    hostname = parsed.hostname or ""
    normalized_host = f"[{hostname.lower()}]" if ":" in hostname else hostname.lower()
    return f"https://{normalized_host}"


def _read_port(parsed: SplitResult) -> int | None:
    try:
        return parsed.port
    except ValueError as error:
        raise PolicyError("Remote mutation allowlist contains an invalid port") from error


def _is_exact_https_origin(parsed: SplitResult, port: int | None) -> bool:
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and not parsed.username
        and not parsed.password
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
        and port in {None, HTTPS_PORT}
    )
