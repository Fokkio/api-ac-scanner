import unittest
from unittest.mock import AsyncMock, patch

from app.deep_engine import TestIdentity
from app.errors import PolicyError
from app.errors import OutboundRequestError
from app.mutation_engine import run_mutation_scan
from app.outbound import BoundedResponse
from app.policy import ValidatedTarget


class FakeMutationClient:
    def __init__(self, is_local=True):
        self.target = ValidatedTarget(
            "http://demo-api:4100/", "http://demo-api:4100", "demo-api", 4100,
            ("172.20.0.2",), is_local,
        )
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def request_mutation(self, method, path, headers, body, _body_limit):
        self.calls.append((method, path, headers, body))
        status = 201 if method == "POST" else 204
        return BoundedResponse(status, {}, b"", False)


class CreateTimeoutClient(FakeMutationClient):
    async def request_mutation(self, method, path, headers, body, _body_limit):
        self.calls.append((method, path, headers, body))
        if method == "POST":
            raise OutboundRequestError("simulated timeout after send")
        return BoundedResponse(204, {}, b"", False)


class MutationEngineTests(unittest.IsolatedAsyncioTestCase):
    @patch("app.mutation_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_creates_then_cleans_marked_local_resource(self, create_client):
        client = FakeMutationClient()
        create_client.return_value = client
        result = await run_mutation_scan(
            "http://demo-api:4100", "/__ac_test__/resource-1",
            {"apiAcScannerTest": True, "value": "temporary"},
            TestIdentity("Tester", "tester", "local", {"authorization": "Bearer test-token-123456"}),
        )
        self.assertEqual([call[0] for call in client.calls], ["POST", "DELETE"])
        self.assertEqual(result["findings"][0]["state"], "passed")

    @patch("app.mutation_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_rejects_non_local_target_before_mutation(self, create_client):
        client = FakeMutationClient(is_local=False)
        create_client.return_value = client
        with self.assertRaises(PolicyError):
            await run_mutation_scan(
                "https://example.com", "/__ac_test__/resource-1",
                {"apiAcScannerTest": True},
                TestIdentity("Tester", "", "", {"authorization": "Bearer test-token-123456"}),
            )
        self.assertEqual(client.calls, [])

    async def test_rejects_unmarked_path_without_network_access(self):
        with self.assertRaises(PolicyError):
            await run_mutation_scan(
                "http://demo-api:4100", "/api/orders/1", {"apiAcScannerTest": True},
                TestIdentity("Tester", "", "", {"authorization": "Bearer test-token-123456"}),
            )

    @patch("app.mutation_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_attempts_cleanup_after_create_request_failure(self, create_client):
        client = CreateTimeoutClient()
        create_client.return_value = client
        result = await run_mutation_scan(
            "http://demo-api:4100", "/__ac_test__/resource-1",
            {"apiAcScannerTest": True},
            TestIdentity("Tester", "", "", {"authorization": "Bearer test-token-123456"}),
        )
        self.assertEqual([call[0] for call in client.calls], ["POST", "DELETE"])
        self.assertEqual(result["findings"][0]["state"], "needs-verification")
        self.assertEqual(result["findings"][0]["evidence"]["createStatus"], "request-failed")


if __name__ == "__main__":
    unittest.main()
