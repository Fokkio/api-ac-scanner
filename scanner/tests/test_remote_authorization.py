import unittest
from unittest.mock import AsyncMock, patch

from app.errors import PolicyError
from app.policy import ValidatedTarget
from app.remote_authorization import MutationTargetAuthorization, authorize_state_changing_client


class FakeAuthorizationClient:
    def __init__(self, origin: str, is_local: bool, target_url: str | None = None):
        scheme = "https" if origin.startswith("https://") else "http"
        hostname = origin.split("://", maxsplit=1)[1]
        port = 443 if scheme == "https" else 80
        self.target = ValidatedTarget(
            target_url or f"{origin}/", origin, hostname, port, ("203.0.113.10",), is_local,
        )


class RemoteAuthorizationTests(unittest.IsolatedAsyncioTestCase):
    async def test_allows_local_target_only_with_local_mode(self):
        client = FakeAuthorizationClient("http://demo-api", is_local=True)
        mode = await authorize_state_changing_client(client, MutationTargetAuthorization())
        self.assertEqual(mode, "local")

        with self.assertRaises(PolicyError):
            await authorize_state_changing_client(
                client,
                MutationTargetAuthorization(
                    mode="verified-remote", challenge="challenge-value-with-24-characters",
                    verification_method="file",
                ),
            )

    async def test_rejects_remote_target_when_feature_is_disabled(self):
        client = FakeAuthorizationClient("https://staging.example.test", is_local=False)
        proof = MutationTargetAuthorization(
            mode="verified-remote", challenge="challenge-value-with-24-characters",
            verification_method="file",
        )
        with patch.dict("os.environ", {
            "REMOTE_SAFE_MUTATION_ENABLED": "false",
            "REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS": "https://staging.example.test",
        }, clear=False):
            with self.assertRaisesRegex(PolicyError, "disabled"):
                await authorize_state_changing_client(client, proof)

    async def test_rejects_invalid_remote_feature_flag(self):
        client = FakeAuthorizationClient("https://staging.example.test", is_local=False)
        proof = MutationTargetAuthorization(
            mode="verified-remote", challenge="challenge-value-with-24-characters",
            verification_method="file",
        )
        with patch.dict("os.environ", {
            "REMOTE_SAFE_MUTATION_ENABLED": "sometimes",
            "REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS": "https://staging.example.test",
        }, clear=False):
            with self.assertRaisesRegex(PolicyError, "must be true or false"):
                await authorize_state_changing_client(client, proof)

    async def test_rejects_non_origin_allowlist_entries(self):
        client = FakeAuthorizationClient("https://staging.example.test", is_local=False)
        proof = MutationTargetAuthorization(
            mode="verified-remote", challenge="challenge-value-with-24-characters",
            verification_method="file",
        )
        with patch.dict("os.environ", {
            "REMOTE_SAFE_MUTATION_ENABLED": "true",
            "REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS": "https://staging.example.test/not-an-origin",
        }, clear=False):
            with self.assertRaisesRegex(PolicyError, "exact HTTPS origins"):
                await authorize_state_changing_client(client, proof)

    @patch("app.remote_authorization.verify_asset_control_with_client", new_callable=AsyncMock)
    async def test_rechecks_live_proof_before_authorizing_exact_remote_origin(self, verify_proof):
        verify_proof.return_value = True
        client = FakeAuthorizationClient("https://staging.example.test", is_local=False)
        proof = MutationTargetAuthorization(
            mode="verified-remote", challenge="challenge-value-with-24-characters",
            verification_method="header",
        )
        with patch.dict("os.environ", {
            "REMOTE_SAFE_MUTATION_ENABLED": "true",
            "REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS": "https://staging.example.test",
        }, clear=False):
            mode = await authorize_state_changing_client(client, proof)

        self.assertEqual(mode, "verified-remote")
        verify_proof.assert_awaited_once_with(
            client, "challenge-value-with-24-characters", "header",
        )

    @patch("app.remote_authorization.verify_asset_control_with_client", new_callable=AsyncMock)
    async def test_rejects_stale_remote_proof_without_mutation_authorization(self, verify_proof):
        verify_proof.return_value = False
        client = FakeAuthorizationClient("https://staging.example.test", is_local=False)
        proof = MutationTargetAuthorization(
            mode="verified-remote", challenge="challenge-value-with-24-characters",
            verification_method="dns",
        )
        with patch.dict("os.environ", {
            "REMOTE_SAFE_MUTATION_ENABLED": "true",
            "REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS": "https://staging.example.test",
        }, clear=False):
            with self.assertRaisesRegex(PolicyError, "no longer valid"):
                await authorize_state_changing_client(client, proof)

    async def test_rejects_http_and_non_allowlisted_remote_origins(self):
        proof = MutationTargetAuthorization(
            mode="verified-remote", challenge="challenge-value-with-24-characters",
            verification_method="file",
        )
        with patch.dict("os.environ", {
            "REMOTE_SAFE_MUTATION_ENABLED": "true",
            "REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS": "https://staging.example.test",
        }, clear=False):
            with self.assertRaisesRegex(PolicyError, "HTTPS"):
                await authorize_state_changing_client(
                    FakeAuthorizationClient("http://staging.example.test", is_local=False), proof,
                )
            with self.assertRaisesRegex(PolicyError, "exact mutation allowlist"):
                await authorize_state_changing_client(
                    FakeAuthorizationClient("https://other.example.test", is_local=False), proof,
                )

    async def test_rejects_remote_target_paths_even_when_the_origin_is_allowlisted(self):
        proof = MutationTargetAuthorization(
            mode="verified-remote", challenge="challenge-value-with-24-characters",
            verification_method="file",
        )
        client = FakeAuthorizationClient(
            "https://staging.example.test", is_local=False,
            target_url="https://staging.example.test/api?unexpected=true",
        )
        with patch.dict("os.environ", {
            "REMOTE_SAFE_MUTATION_ENABLED": "true",
            "REMOTE_SAFE_MUTATION_ALLOWED_ORIGINS": "https://staging.example.test",
        }, clear=False):
            with self.assertRaisesRegex(PolicyError, "exact origins"):
                await authorize_state_changing_client(client, proof)


if __name__ == "__main__":
    unittest.main()
