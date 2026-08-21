"""Pure URL, IP and relative-path policy for bounded outbound scans."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import os
import socket
from urllib.parse import SplitResult, urlsplit, urlunsplit

from app.errors import PolicyError

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443})
DEFAULT_LOCAL_HOSTS = "host.docker.internal,localhost,127.0.0.1,::1,demo-api"
DEFAULT_LOCAL_PORTS = "80,443,3000,4000,4100,5000,8000,8080,8443"
MAX_URL_LENGTH = 2048
MAX_PATH_LENGTH = 512


@dataclass(frozen=True)
class ValidatedTarget:
    """Canonical target and the public addresses pinned for its hostname."""

    url: str
    origin: str
    hostname: str
    port: int
    addresses: tuple[str, ...]
    is_local: bool = False


async def validate_public_target(raw_url: str) -> ValidatedTarget:
    """Validates an HTTP target and resolves only globally routable addresses."""

    parsed = _parse_http_url(raw_url)
    hostname = parsed.hostname
    if not hostname:
        raise PolicyError("Target hostname is required")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    local_mode, local_hosts, local_ports = _read_local_policy()
    is_local = local_mode and hostname.lower() in local_hosts
    allowed_ports = local_ports if is_local else ALLOWED_PORTS
    if port not in allowed_ports:
        raise PolicyError("Target port is not allowed by the active scan policy")
    addresses = await _resolve_addresses(hostname, port, allow_non_public=is_local)
    canonical = urlunsplit((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))
    origin = urlunsplit((parsed.scheme, parsed.netloc.lower(), "", "", ""))
    return ValidatedTarget(canonical, origin, hostname.lower(), port, addresses, is_local)


def build_same_origin_url(target: ValidatedTarget, relative_path: str) -> str:
    """Builds an exact-origin URL from a validated relative path."""

    if not relative_path.startswith("/") or relative_path.startswith("//"):
        raise PolicyError("Endpoint paths must begin with exactly one slash")
    has_control_character = any(ord(character) < 32 or ord(character) == 127 for character in relative_path)
    if "\\" in relative_path or "#" in relative_path or has_control_character or len(relative_path) > MAX_PATH_LENGTH:
        raise PolicyError("Endpoint path is invalid or too long")
    candidate = urlsplit(f"{target.origin}{relative_path}")
    if candidate.hostname != target.hostname or (candidate.port or target.port) != target.port:
        raise PolicyError("Endpoint path changed the verified target origin")
    return urlunsplit((candidate.scheme, candidate.netloc, candidate.path, candidate.query, ""))


def _parse_http_url(raw_url: str) -> SplitResult:
    if not isinstance(raw_url, str) or len(raw_url) > MAX_URL_LENGTH:
        raise PolicyError("Target URL is missing or too long")
    try:
        parsed = urlsplit(raw_url.strip())
        _ = parsed.port
    except ValueError as error:
        raise PolicyError("Target URL is invalid") from error
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise PolicyError("Only HTTP and HTTPS targets are allowed")
    if parsed.username or parsed.password:
        raise PolicyError("Target URLs cannot contain credentials")
    if parsed.fragment:
        raise PolicyError("Target URL fragments are not allowed")
    return parsed


async def _resolve_addresses(hostname: str, port: int, allow_non_public: bool) -> tuple[str, ...]:
    try:
        address_info = await asyncio.to_thread(socket.getaddrinfo, hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise PolicyError("Target hostname could not be resolved") from error
    addresses = tuple(dict.fromkeys(item[4][0] for item in address_info))
    if not addresses:
        raise PolicyError("Target hostname resolved to no addresses")
    for address in addresses:
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError as error:
            raise PolicyError("Target resolved to an invalid address") from error
        if not allow_non_public and (
            not parsed_address.is_global
            or parsed_address.is_multicast
            or parsed_address.is_unspecified
            or parsed_address.is_reserved
            or parsed_address.is_loopback
            or parsed_address.is_link_local
            or parsed_address.is_private
        ):
            raise PolicyError("Target resolved to a non-public address")
    return addresses


def _read_local_policy() -> tuple[bool, frozenset[str], frozenset[int]]:
    local_mode = os.environ.get("LOCAL_MODE", "false").strip().lower() == "true"
    hosts = frozenset(
        value.strip().lower()
        for value in os.environ.get("LOCAL_ALLOWED_HOSTS", DEFAULT_LOCAL_HOSTS).split(",")
        if value.strip()
    )
    try:
        ports = frozenset(
            int(value.strip())
            for value in os.environ.get("LOCAL_ALLOWED_PORTS", DEFAULT_LOCAL_PORTS).split(",")
            if value.strip()
        )
    except ValueError as error:
        raise PolicyError("LOCAL_ALLOWED_PORTS contains an invalid port") from error
    if any(port < 1 or port > 65535 for port in ports):
        raise PolicyError("LOCAL_ALLOWED_PORTS contains an invalid port")
    return local_mode, hosts, ports
