from dataclasses import replace
import unittest
from unittest.mock import AsyncMock, patch

from app.engines import AuthorizationPolicyRule, DeepScanPlan, TestIdentity, run_deep_scan
from app.errors import PolicyError
from app.outbound import BoundedResponse
from app.policy import ValidatedTarget


class FakeClient:
    def __init__(self):
        self.target = ValidatedTarget(
            "https://example.com/", "https://example.com", "example.com", 443, ("93.184.216.34",),
        )
        self.request_count = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def request_path(self, _method, path, headers=None, body_limit=65536):
        del body_limit
        self.request_count += 1
        token = (headers or {}).get("authorization", "")
        if path == "/orders/1" and token.endswith("owner-1234567890"):
            return BoundedResponse(200, {}, b'{"id":1}', False)
        if path == "/orders/1":
            return BoundedResponse(403, {}, b"", False)
        if path == "/admin" and token.endswith("owner-1234567890"):
            return BoundedResponse(200, {}, b'{"admin":true}', False)
        return BoundedResponse(403, {}, b"", False)


class VulnerableFakeClient(FakeClient):
    async def request_path(self, _method, path, headers=None, body_limit=65536):
        del body_limit
        self.request_count += 1
        token = (headers or {}).get("authorization", "")
        if path == "/orders/1" and token:
            return BoundedResponse(
                200, {}, b'{"id":1,"owner_id":"user-a","email":"owner@example.test"}', False, 8.0,
            )
        if path == "/orders/1":
            return BoundedResponse(401, {}, b'{"error":"authentication required"}', False, 4.0)
        if path == "/admin" and token:
            return BoundedResponse(200, {}, b'{"admin":true}', False, 7.0)
        if path == "/admin":
            return BoundedResponse(401, {}, b'{"error":"authentication required"}', False, 4.0)
        if path == "/users/alice":
            return BoundedResponse(200, {}, b'{"username":"alice"}', False, 6.0)
        if path == "/users/missing":
            return BoundedResponse(404, {}, b'{"error":"not found"}', False, 5.0)
        return BoundedResponse(404, {}, b"", False)


class EngineTests(unittest.IsolatedAsyncioTestCase):
    @patch("app.deep_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_deep_scan_labels_denied_access_as_passed(self, create_client):
        create_client.return_value = FakeClient()
        result = await run_deep_scan(make_plan())
        self.assertEqual([item["state"] for item in result["findings"]], ["passed", "passed", "passed", "passed"])
        self.assertTrue(all(item["state"] != "confirmed" for item in result["findings"]))

    async def test_deep_scan_rejects_same_identity(self):
        with self.assertRaises(PolicyError):
            await run_deep_scan(make_plan(
                owner_headers={"authorization": "Bearer same-token-123456"},
                alternate_headers={"authorization": "Bearer same-token-123456"},
            ))

    @patch("app.deep_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_deep_scan_validates_every_path_before_requesting(self, create_client):
        client = FakeClient()
        create_client.return_value = client
        with self.assertRaises(PolicyError):
            await run_deep_scan(make_plan(
                object_paths=["/orders/1", "//evil.example/object"],
            ))
        self.assertEqual(client.request_count, 0)

    @patch("app.deep_engine.BoundedHttpClient.create", new_callable=AsyncMock)
    async def test_deep_scan_reports_suspected_access_control_evidence(self, create_client):
        client = VulnerableFakeClient()
        create_client.return_value = client
        result = await run_deep_scan(make_plan(
            existing_paths=["/users/alice"],
            missing_paths=["/users/missing"],
        ))

        findings = {
            item["category"]: item for item in result["findings"]
            if item["ruleId"] != "verified-explicit-policy-mismatch"
        }
        self.assertEqual(findings["bola"]["state"], "suspected")
        self.assertEqual(findings["bfla"]["state"], "suspected")
        self.assertEqual(findings["property-authorization"]["state"], "needs-verification")
        self.assertEqual(findings["enumeration"]["state"], "suspected")
        self.assertEqual(client.request_count, 8)
        self.assertEqual(len(result["matrix"]), 6)
        mismatches = [row for row in result["matrix"] if not row["matchesExpectation"]]
        self.assertEqual({row["identity"] for row in mismatches}, {"Alternate"})
        verified = [item for item in result["findings"] if item["state"] == "verified"]
        self.assertEqual({item["category"] for item in verified}, {"bola", "bfla"})

    async def test_deep_scan_rejects_unpaired_enumeration_paths(self):
        with self.assertRaises(PolicyError):
            await run_deep_scan(make_plan(existing_paths=["/users/alice"]))

    async def test_deep_scan_rejects_incomplete_policy_before_network_access(self):
        plan = make_plan()
        with self.assertRaises(PolicyError):
            await run_deep_scan(replace(plan, policy_rules=plan.policy_rules[:-1]))

    async def test_deep_scan_rejects_reserved_identity_headers(self):
        with self.assertRaises(PolicyError):
            await run_deep_scan(make_plan(owner_headers={"host": "evil.example"}))

    async def test_deep_scan_rejects_del_in_identity_header_value(self):
        with self.assertRaises(PolicyError):
            await run_deep_scan(make_plan(owner_headers={"x-test-user": "alice\x7f"}))


def make_plan(
    object_paths=None,
    existing_paths=None,
    missing_paths=None,
    owner_headers=None,
    alternate_headers=None,
):
    object_paths = object_paths or ["/orders/1"]
    function_paths = ["/admin"]
    labels = ("Owner", "Alternate", "Anonymous")
    policy_rules = tuple(
        AuthorizationPolicyRule("GET", path, label, "allow" if label == "Owner" else "deny")
        for path in [*object_paths, *function_paths]
        for label in labels
    )
    return DeepScanPlan(
        target="https://example.com",
        object_paths=object_paths,
        function_paths=function_paths,
        enumeration_existing_paths=existing_paths or [],
        enumeration_missing_paths=missing_paths or [],
        identities=(
            TestIdentity("Owner", "owner", "tenant-a", owner_headers or {
                "authorization": "Bearer owner-1234567890",
            }),
            TestIdentity("Alternate", "user", "tenant-b", alternate_headers or {
                "authorization": "Bearer alternate-123456",
            }),
        ),
        policy_rules=policy_rules,
    )


if __name__ == "__main__":
    unittest.main()
