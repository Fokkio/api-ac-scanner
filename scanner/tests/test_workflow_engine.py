import json
import unittest
from unittest.mock import AsyncMock, patch

from app.deep_engine import TestIdentity
from app.errors import PolicyError
from app.outbound import BoundedResponse
from app.policy import ValidatedTarget
from app.workflow_engine import run_workflow_scan


class FakeWorkflowClient:
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

    async def request_workflow(self, method, path, headers, body, *_args):
        self.calls.append((method, path, headers, body))
        if path == "/__ac_test__/login":
            return BoundedResponse(200, {}, json.dumps({"tokens": {"access": "issued-token-123456"}}).encode(), False)
        statuses = {"POST": 201, "PUT": 200, "PATCH": 200, "GET": 200, "DELETE": 204}
        return BoundedResponse(statuses[method], {}, b"{}", False)


class FailedCreateWorkflowClient(FakeWorkflowClient):
    async def request_workflow(self, method, path, headers, body, *_args):
        self.calls.append((method, path, headers, body))
        status = 500 if method == "POST" else 204
        return BoundedResponse(status, {}, b"{}", False)


class MissingCleanupWorkflowClient(FakeWorkflowClient):
    async def request_workflow(self, method, path, headers, body, *_args):
        self.calls.append((method, path, headers, body))
        status = 201 if method == "POST" else 404
        return BoundedResponse(status, {}, b"{}", False)


class WorkflowEngineTests(unittest.IsolatedAsyncioTestCase):
    @patch("app.workflow_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_runs_all_methods_and_reverse_cleanup(self, create_client):
        client = FakeWorkflowClient()
        create_client.return_value = client
        steps = [
            {"name": "create", "method": "POST", "path": "/__ac_test__/one", "body": {"apiAcScannerTest": True}, "expected": "allow"},
            {"name": "replace", "method": "PUT", "path": "/__ac_test__/one", "body": {"apiAcScannerTest": True}, "expected": "allow"},
            {"name": "patch", "method": "PATCH", "path": "/__ac_test__/one", "body": {"apiAcScannerTest": True}, "expected": "allow"},
            {"name": "read", "method": "GET", "path": "/__ac_test__/one", "body": None, "expected": "allow"},
            {"name": "delete", "method": "DELETE", "path": "/__ac_test__/one", "body": None, "expected": "allow"},
        ]
        result = await run_workflow_scan(
            "http://demo-api:4100", TestIdentity("Owner", "owner", "local", {"authorization": "Bearer static-token-123456"}),
            {"type": "none"}, steps,
        )
        self.assertEqual([call[0] for call in client.calls], ["POST", "PUT", "PATCH", "GET", "DELETE", "DELETE"])
        self.assertTrue(all(row["matchesExpectation"] for row in result["matrix"]))
        self.assertEqual(result["findings"][-1]["state"], "passed")

    @patch("app.workflow_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_json_login_adapter_acquires_ephemeral_token(self, create_client):
        client = FakeWorkflowClient()
        create_client.return_value = client
        await run_workflow_scan(
            "http://demo-api:4100", TestIdentity("Login user", "user", "local", {}),
            {
                "type": "json-login", "path": "/__ac_test__/login", "username_field": "username",
                "password_field": "password", "username": "fixture", "password": "fixture-password",
                "token_json_path": "tokens.access", "header_name": "authorization", "scheme": "Bearer",
            },
            [{"name": "read", "method": "GET", "path": "/__ac_test__/one", "body": None, "expected": "allow"}],
        )
        self.assertEqual(client.calls[0][0:2], ("POST", "/__ac_test__/login"))
        self.assertEqual(client.calls[0][2], {})
        self.assertEqual(client.calls[1][2], {"authorization": "Bearer issued-token-123456"})

    @patch("app.workflow_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_login_adapter_replaces_all_base_credentials(self, create_client):
        client = FakeWorkflowClient()
        create_client.return_value = client
        await run_workflow_scan(
            "http://demo-api:4100",
            TestIdentity("Login user", "user", "local", {
                "cookie": "admin-session=static",
                "x-api-key": "static-api-key",
            }),
            {
                "type": "json-login", "path": "/__ac_test__/login", "username_field": "username",
                "password_field": "password", "username": "fixture", "password": "fixture-password",
                "token_json_path": "tokens.access", "header_name": "authorization", "scheme": "Bearer",
            },
            [{"name": "read", "method": "GET", "path": "/__ac_test__/one", "body": None, "expected": "allow"}],
        )
        self.assertEqual(client.calls[1][2], {"authorization": "Bearer issued-token-123456"})

    @patch("app.workflow_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_uses_utf8_bytes_for_login_payload_limit(self, create_client):
        client = FakeWorkflowClient()
        create_client.return_value = client
        await run_workflow_scan(
            "http://demo-api:4100", TestIdentity("Login user", "user", "local", {}),
            {
                "type": "json-login", "path": "/__ac_test__/login", "username_field": "username",
                "password_field": "password", "username": "ก" * 1000, "password": "fixture-password",
                "token_json_path": "tokens.access", "header_name": "authorization", "scheme": "Bearer",
            },
            [{"name": "read", "method": "GET", "path": "/__ac_test__/one", "body": None, "expected": "allow"}],
        )
        self.assertIn("ก".encode("utf-8"), client.calls[0][3])

    @patch("app.workflow_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_skips_remaining_steps_after_an_indeterminate_prerequisite(self, create_client):
        client = FailedCreateWorkflowClient()
        create_client.return_value = client
        result = await run_workflow_scan(
            "http://demo-api:4100",
            TestIdentity("Owner", "owner", "local", {"authorization": "Bearer static-token-123456"}),
            {"type": "none"},
            [
                {"name": "create", "method": "POST", "path": "/__ac_test__/one", "body": {"apiAcScannerTest": True}, "expected": "allow"},
                {"name": "read", "method": "GET", "path": "/__ac_test__/one", "body": None, "expected": "allow"},
            ],
        )
        self.assertEqual([call[0] for call in client.calls], ["POST", "DELETE"])
        self.assertEqual(result["matrix"][1]["actual"], "indeterminate")
        self.assertTrue(result["matrix"][1]["skippedAfterPriorFailure"])
        self.assertEqual(result["findings"][1]["state"], "needs-verification")

    @patch("app.workflow_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_does_not_claim_cleanup_success_after_confirmed_create_and_delete_404(self, create_client):
        client = MissingCleanupWorkflowClient()
        create_client.return_value = client
        result = await run_workflow_scan(
            "http://demo-api:4100",
            TestIdentity("Owner", "owner", "local", {"authorization": "Bearer static-token-123456"}),
            {"type": "none"},
            [{"name": "create", "method": "POST", "path": "/__ac_test__/one", "body": {"apiAcScannerTest": True}, "expected": "allow"}],
        )
        self.assertEqual(result["findings"][-1]["state"], "needs-verification")
        self.assertFalse(result["findings"][-1]["evidence"]["cleanupSucceeded"])

    @patch("app.workflow_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_uses_utf8_bytes_for_workflow_body_limit(self, create_client):
        client = FakeWorkflowClient()
        create_client.return_value = client
        result = await run_workflow_scan(
            "http://demo-api:4100",
            TestIdentity("Owner", "owner", "local", {"authorization": "Bearer static-token-123456"}),
            {"type": "none"},
            [{
                "name": "unicode-create", "method": "POST", "path": "/__ac_test__/one",
                "body": {"apiAcScannerTest": True, "value": "ก" * 1000}, "expected": "allow",
            }],
        )
        self.assertEqual(result["matrix"][0]["actual"], "allow")
        self.assertIn("ก".encode("utf-8"), client.calls[0][3])

    async def test_rejects_any_mutation_outside_disposable_namespace(self):
        with self.assertRaises(PolicyError):
            await run_workflow_scan(
                "http://demo-api:4100", TestIdentity("Owner", "", "", {"authorization": "Bearer static-token-123456"}),
                {"type": "none"},
                [{"name": "unsafe", "method": "DELETE", "path": "/api/orders/1", "body": None, "expected": "deny"}],
            )

    @patch("app.workflow_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_policy_mismatch_is_verified(self, create_client):
        client = FakeWorkflowClient()
        create_client.return_value = client
        result = await run_workflow_scan(
            "http://demo-api:4100", TestIdentity("User", "user", "local", {"authorization": "Bearer static-token-123456"}),
            {"type": "none"},
            [{"name": "forbidden-create", "method": "POST", "path": "/__ac_test__/one", "body": {"apiAcScannerTest": True}, "expected": "deny"}],
        )
        self.assertEqual(result["findings"][0]["state"], "verified")


if __name__ == "__main__":
    unittest.main()
