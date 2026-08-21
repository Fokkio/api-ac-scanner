"""Exact-origin ownership verification methods for public assets."""

from __future__ import annotations

import asyncio

import dns.exception
import dns.resolver

from app.outbound import BoundedHttpClient
from app.policy import validate_public_target

VERIFICATION_HEADER = "x-api-ac-scanner-verification"


async def verify_asset_control(origin: str, challenge: str, method: str) -> bool:
    """Verifies an exact origin through a well-known file, header or DNS TXT record."""

    if method == "file":
        return await _verify_file(origin, challenge)
    if method == "header":
        return await _verify_header(origin, challenge)
    if method == "dns":
        return await _verify_dns(origin, challenge)
    return False


async def _verify_file(origin: str, challenge: str) -> bool:
    expected = f"api-ac-scanner-v2.6-verification={challenge}"
    async with await BoundedHttpClient.create(origin, request_limit=1) as client:
        response = await client.request_path(
            "GET", "/.well-known/api-ac-scanner-verification.txt", body_limit=256,
        )
    return response.status == 200 and not response.is_truncated and response.text.strip() == expected


async def _verify_header(origin: str, challenge: str) -> bool:
    async with await BoundedHttpClient.create(origin, request_limit=1) as client:
        response = await client.request_target("HEAD", body_limit=0)
    return response.status < 400 and response.headers.get(VERIFICATION_HEADER, "").strip() == challenge


async def _verify_dns(origin: str, challenge: str) -> bool:
    target = await validate_public_target(origin)
    record_name = f"_api-ac-scanner.{target.hostname.rstrip('.')}"
    return await asyncio.to_thread(_dns_record_contains, record_name, challenge)


def _dns_record_contains(record_name: str, challenge: str) -> bool:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answers = resolver.resolve(record_name, "TXT", lifetime=5.0)
    except (dns.exception.DNSException, OSError):
        return False
    values = {
        b"".join(getattr(answer, "strings", ())).decode("utf-8", errors="replace")
        for answer in answers
    }
    return challenge in values
