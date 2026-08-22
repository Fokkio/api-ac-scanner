import unittest
from unittest.mock import AsyncMock, patch

from app.deep_engine import TestIdentity
from app.errors import PolicyError
from app.errors import OutboundRequestError
from app.mutation_engine import run_mutation_scan
from app.outbound import BoundedResponse
from app.policy import ValidatedTarget
from app.remote_authorization import MutationTargetAuthorization


class FakeMutationClient:
    def __init__(self, is_local=True):
        origin = "http://demo-api:4100" if is_local else "https://staging.example.test"
        self.target = ValidatedTarget(
            f"{origin}/", origin, "demo-api" if is_local else "staging.example.test",
            4100 if is_local else 443, ("172.20.0.2",), is_local,
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

    @patch("app.remote_authorization.verify_asset_control_with_client", new_callable=AsyncMock)
    @patch("app.mutation_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_remote_proof_is_checked_before_create_and_cleanup(self, create_client, verify_proof):
        client = FakeMutationClient(is_local=False)
        create_client.return_value = client
        verify_proof.return_value = True
        proof = MutationTargetAuthorization(
            mode="verified-remote", challenge="challenge-value-with-24-characters",
            verification_method="file",
        )
        with patch.dict("os.environ", {
            "REMOTE_SAFE_MUTATION_ENABLED": "true",
            "REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS": "https://staging.example.test",
        }, clear=False):
            result = await run_mutation_scan(
                "https://staging.example.test", "/__ac_test__/resource-1",
                {"apiAcScannerTest": True},
                TestIdentity("Tester", "", "", {"authorization": "Bearer test-token-123456"}),
                proof,
            )

        verify_proof.assert_awaited_once()
        self.assertEqual([call[0] for call in client.calls], ["POST", "DELETE"])
        self.assertEqual(result["findings"][0]["evidence"]["targetMode"], "verified-remote")


if __name__ == "__main__":
    unittest.main()
