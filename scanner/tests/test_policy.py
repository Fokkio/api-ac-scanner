import socket
import unittest
from unittest.mock import patch

from app.errors import PolicyError
from app.policy import ValidatedTarget, build_same_origin_url, validate_public_target


class PolicyTests(unittest.IsolatedAsyncioTestCase):
    @patch("app.policy.socket.getaddrinfo")
    async def test_accepts_and_pins_public_addresses(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        ]
        target = await validate_public_target("https://Example.com/api")
        self.assertEqual(target.url, "https://example.com/api")
        self.assertEqual(target.addresses, ("93.184.216.34",))

    async def test_rejects_fragments_at_scanner_boundary(self):
        with self.assertRaises(PolicyError):
            await validate_public_target("https://example.com/api#fragment")

    @patch("app.policy.socket.getaddrinfo")
    async def test_rejects_private_or_loopback_resolution(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]
        with self.assertRaises(PolicyError):
            await validate_public_target("https://example.com")

    @patch("app.policy.socket.getaddrinfo")
    async def test_rejects_multicast_even_when_ipaddress_marks_it_global(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("224.0.0.1", 443)),
        ]
        with self.assertRaises(PolicyError):
            await validate_public_target("https://example.com")

    @patch("app.policy.socket.getaddrinfo")
    async def test_allows_explicit_local_host_and_development_port(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.65.2", 4100)),
        ]
        environment = {
            "LOCAL_MODE": "true",
            "LOCAL_ALLOWED_HOSTS": "host.docker.internal",
            "LOCAL_ALLOWED_PORTS": "4100",
        }
        with patch.dict("os.environ", environment, clear=False):
            target = await validate_public_target("http://host.docker.internal:4100/api")
        self.assertTrue(target.is_local)
        self.assertEqual(target.port, 4100)

    @patch("app.policy.socket.getaddrinfo")
    async def test_does_not_allow_private_resolution_for_unlisted_host(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 4100)),
        ]
        environment = {
            "LOCAL_MODE": "true",
            "LOCAL_ALLOWED_HOSTS": "host.docker.internal",
            "LOCAL_ALLOWED_PORTS": "4100",
        }
        with patch.dict("os.environ", environment, clear=False):
            with self.assertRaises(PolicyError):
                await validate_public_target("http://unlisted.example:4100/api")

    @patch("app.policy.socket.getaddrinfo")
    async def test_blocks_rebinding_to_private_from_allowed_non_loopback_host(self, getaddrinfo):
        # demo-api is in the default allowlist, but resolving it to an internal
        # address must be rejected (DNS-rebinding protection in local mode).
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 4100)),
        ]
        environment = {
            "LOCAL_MODE": "true",
            "LOCAL_ALLOWED_HOSTS": "demo-api",
            "LOCAL_ALLOWED_PORTS": "4100",
        }
        with patch.dict("os.environ", environment, clear=False):
            with self.assertRaises(PolicyError):
                await validate_public_target("http://demo-api:4100/api")

    def test_relative_paths_cannot_change_origin(self):
        target = ValidatedTarget(
            "https://example.com/", "https://example.com", "example.com", 443, ("93.184.216.34",),
        )
        self.assertEqual(build_same_origin_url(target, "/orders/1"), "https://example.com/orders/1")
        with self.assertRaises(PolicyError):
            build_same_origin_url(target, "//evil.example/orders/1")

    def test_relative_paths_reject_fragments_and_control_characters(self):
        target = ValidatedTarget(
            "https://example.com/", "https://example.com", "example.com", 443, ("93.184.216.34",),
        )
        with self.assertRaises(PolicyError):
            build_same_origin_url(target, "/orders/1#different-resource")
        with self.assertRaises(PolicyError):
            build_same_origin_url(target, "/orders/1\u0000")


if __name__ == "__main__":
    unittest.main()
