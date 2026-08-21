"""DNS-pinned, size-capped and method-limited HTTP client."""

from __future__ import annotations

import socket
import time
from typing import Any

import aiohttp
from aiohttp.abc import AbstractResolver

from app.errors import OutboundRequestError, PolicyError
from app.policy import ValidatedTarget, build_same_origin_url, validate_public_target

ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MUTATION_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
WORKFLOW_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
DEFAULT_BODY_LIMIT = 65_536
DEFAULT_REQUEST_LIMIT = 45
DEFAULT_TIMEOUT_SECONDS = 8
MAX_BODY_LIMIT = 1_048_576


class PinnedResolver(AbstractResolver):
    """Resolves one expected hostname to its prevalidated public addresses."""

    def __init__(self, hostname: str, addresses: tuple[str, ...]) -> None:
        self._hostname = hostname
        self._addresses = addresses

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_UNSPEC,
    ) -> list[dict[str, Any]]:
        if host.lower() != self._hostname:
            raise OSError("Resolver refused an unexpected hostname")
        results: list[dict[str, Any]] = []
        for address in self._addresses:
            address_family = socket.AF_INET6 if ":" in address else socket.AF_INET
            if family not in (socket.AF_UNSPEC, address_family):
                continue
            results.append({
                "hostname": host,
                "host": address,
                "port": port,
                "family": address_family,
                "proto": 0,
                "flags": 0,
            })
        return results

    async def close(self) -> None:
        """Closes the resolver; it owns no external resources."""


class BoundedHttpClient:
    """Per-scan HTTP client pinned to one origin and bounded by request count."""

    def __init__(self, target: ValidatedTarget, session: aiohttp.ClientSession, request_limit: int) -> None:
        self.target = target
        self._session = session
        self._request_limit = request_limit
        self._request_count = 0

    @classmethod
    async def create(cls, raw_target: str, request_limit: int = DEFAULT_REQUEST_LIMIT) -> "BoundedHttpClient":
        """Validates a target and creates a DNS-pinned client session."""

        if request_limit < 1 or request_limit > DEFAULT_REQUEST_LIMIT:
            raise PolicyError("Scan request limit is outside the accepted range")
        target = await validate_public_target(raw_target)
        resolver = PinnedResolver(target.hostname, target.addresses)
        connector = aiohttp.TCPConnector(resolver=resolver, limit=4, ttl_dns_cache=0, use_dns_cache=False)
        timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT_SECONDS)
        session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            trust_env=False,
            headers={"user-agent": "API-AC-Scanner-V3.1/3.1"},
        )
        return cls(target, session, request_limit)

    async def __aenter__(self) -> "BoundedHttpClient":
        return self

    async def __aexit__(self, _error_type, _error, _traceback) -> None:
        await self.close()

    async def close(self) -> None:
        """Closes sockets owned by this scan client."""

        await self._session.close()

    async def request_target(
        self,
        method: str,
        headers: dict[str, str] | None = None,
        body_limit: int = DEFAULT_BODY_LIMIT,
    ) -> "BoundedResponse":
        """Requests the exact validated target URL."""

        return await self._request(method, self.target.url, headers, body_limit)

    async def request_path(
        self,
        method: str,
        relative_path: str,
        headers: dict[str, str] | None = None,
        body_limit: int = DEFAULT_BODY_LIMIT,
    ) -> "BoundedResponse":
        """Requests a validated same-origin relative path."""

        url = build_same_origin_url(self.target, relative_path)
        return await self._request(method, url, headers, body_limit)

    async def request_mutation(
        self,
        method: str,
        relative_path: str,
        headers: dict[str, str],
        body: bytes | None,
        body_limit: int = DEFAULT_BODY_LIMIT,
    ) -> "BoundedResponse":
        """Sends one mutation call for the guarded local mutation engine."""

        mutation_headers = dict(headers)
        if body is not None:
            mutation_headers.setdefault("content-type", "application/json")
        url = build_same_origin_url(self.target, relative_path)
        return await self._request(
            method, url, mutation_headers, body_limit, MUTATION_METHODS, body,
        )

    async def request_workflow(
        self,
        method: str,
        relative_path: str,
        headers: dict[str, str],
        body: bytes | None,
        body_limit: int = DEFAULT_BODY_LIMIT,
        content_type: str = "application/json",
    ) -> "BoundedResponse":
        """Sends one same-origin request for a guarded local workflow."""

        workflow_headers = dict(headers)
        if body is not None:
            workflow_headers.setdefault("content-type", content_type)
        url = build_same_origin_url(self.target, relative_path)
        return await self._request(
            method, url, workflow_headers, body_limit, WORKFLOW_METHODS, body,
        )

    async def _request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        body_limit: int,
        allowed_methods: frozenset[str] = ALLOWED_METHODS,
        body: bytes | None = None,
    ) -> "BoundedResponse":
        normalized_method = method.upper()
        if normalized_method not in allowed_methods:
            raise PolicyError("Outbound method is not allowed")
        if body_limit < 0 or body_limit > MAX_BODY_LIMIT:
            raise PolicyError("Response body limit is outside the accepted range")
        self._request_count += 1
        if self._request_count > self._request_limit:
            raise PolicyError("Scan request limit exceeded")

        try:
            started_at = time.monotonic()
            async with self._session.request(
                normalized_method,
                url,
                headers=headers,
                data=body,
                allow_redirects=False,
            ) as response:
                body, is_truncated = await _read_bounded_body(response, body_limit)
                normalized_headers = {key.lower(): value for key, value in response.headers.items()}
                elapsed_ms = round((time.monotonic() - started_at) * 1000, 1)
                return BoundedResponse(response.status, normalized_headers, body, is_truncated, elapsed_ms)
        except (aiohttp.ClientError, TimeoutError) as error:
            raise OutboundRequestError("Target request failed or timed out") from error


class BoundedResponse:
    """Minimal response evidence with a capped body."""

    def __init__(
        self,
        status: int,
        headers: dict[str, str],
        body: bytes,
        is_truncated: bool,
        elapsed_ms: float = 0.0,
    ) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.is_truncated = is_truncated
        self.elapsed_ms = elapsed_ms

    @property
    def text(self) -> str:
        """Decodes the capped body for similarity and exact challenge checks."""

        return self.body.decode("utf-8", errors="replace")


async def _read_bounded_body(response: aiohttp.ClientResponse, body_limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    bytes_read = 0
    async for chunk in response.content.iter_chunked(8192):
        remaining = body_limit - bytes_read
        if remaining <= 0:
            return b"".join(chunks), True
        chunks.append(chunk[:remaining])
        bytes_read += min(len(chunk), remaining)
        if len(chunk) > remaining:
            return b"".join(chunks), True
    return b"".join(chunks), False
