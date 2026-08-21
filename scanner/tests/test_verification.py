import unittest
from unittest.mock import AsyncMock, patch

from app.outbound import BoundedResponse
from app.verification import _dns_record_contains, verify_asset_control


class FakeVerificationClient:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def request_path(self, *_args, **_kwargs):
        return self.response

    async def request_target(self, *_args, **_kwargs):
        return self.response


class VerificationTests(unittest.IsolatedAsyncioTestCase):
    @patch("app.verification.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_verifies_exact_well_known_file(self, create_client):
        challenge = "challenge-12345678901234567890"
        body = f"api-ac-scanner-v2.6-verification={challenge}".encode()
        create_client.return_value = FakeVerificationClient(BoundedResponse(200, {}, body, False))
        self.assertTrue(await verify_asset_control("https://example.com", challenge, "file"))

    @patch("app.verification.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_verifies_exact_response_header(self, create_client):
        challenge = "challenge-12345678901234567890"
        response = BoundedResponse(204, {"x-api-ac-scanner-verification": challenge}, b"", False)
        create_client.return_value = FakeVerificationClient(response)
        self.assertTrue(await verify_asset_control("https://example.com", challenge, "header"))

    async def test_rejects_unknown_verification_method(self):
        self.assertFalse(await verify_asset_control(
            "https://example.com", "challenge-12345678901234567890", "unknown",
        ))

    @patch("app.verification.dns.resolver.Resolver")
    async def test_dns_verification_requires_an_exact_txt_value(self, resolver_factory):
        answer = type("TxtAnswer", (), {"strings": (b"challenge-123", b"456")})()
        resolver_factory.return_value.resolve.return_value = [answer]

        self.assertTrue(_dns_record_contains("_api-ac-scanner.example.com", "challenge-123456"))
        self.assertFalse(_dns_record_contains("_api-ac-scanner.example.com", "challenge-123"))


if __name__ == "__main__":
    unittest.main()
