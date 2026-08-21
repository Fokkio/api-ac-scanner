import json
from pathlib import Path
import tempfile
import unittest

from app.discovery import run_discovery
from app.errors import ScannerExecutionError


class DiscoveryTests(unittest.TestCase):
    def test_builds_inventory_from_openapi_har_postman_and_source(self):
        with tempfile.TemporaryDirectory() as root:
            upload_root = Path(root)
            scan_path = upload_root / "request"
            scan_path.mkdir()
            self._write_artifacts(scan_path)

            result = run_discovery(str(scan_path), upload_root, "http://api.test")

            endpoints = {(item["method"], item["path"]): item for item in result["endpoints"]}
            self.assertEqual(endpoints[("GET", "/api/orders/{id}")]["candidateType"], "object")
            self.assertEqual(endpoints[("GET", "/api/admin/users")]["candidateType"], "function")
            self.assertEqual(endpoints[("GET", "/api/users/alice")]["candidateType"], "enumeration")
            self.assertIn(("PATCH", "/api/orders/:id"), endpoints)
            self.assertIn(("POST", "/api/orders"), endpoints)
            self.assertNotIn(("GET", "/tracking"), endpoints)
            self.assertTrue(any("cross-origin" in warning for warning in result["warnings"]))

    def test_rejects_invalid_endpoint_paths(self):
        with tempfile.TemporaryDirectory() as root:
            upload_root = Path(root)
            scan_path = upload_root / "request"
            scan_path.mkdir()
            (scan_path / "openapi.json").write_text(json.dumps({
                "openapi": "3.1.0", "paths": {"relative": {"get": {}}},
            }), encoding="utf-8")
            with self.assertRaises(ScannerExecutionError):
                run_discovery(str(scan_path), upload_root, "http://api.test")

    @staticmethod
    def _write_artifacts(scan_path: Path) -> None:
        (scan_path / "openapi.json").write_text(json.dumps({
            "openapi": "3.1.0",
            "paths": {
                "/api/orders/{id}": {"get": {}},
                "/api/admin/users": {"get": {}},
            },
        }), encoding="utf-8")
        (scan_path / "traffic.har").write_text(json.dumps({
            "log": {"entries": [
                {"request": {"method": "POST", "url": "http://api.test/api/orders"}},
                {"request": {"method": "GET", "url": "https://analytics.invalid/tracking"}},
            ]},
        }), encoding="utf-8")
        (scan_path / "collection.json").write_text(json.dumps({
            "item": [
                {"name": "User", "request": {"method": "GET", "url": "{{baseUrl}}/api/users/alice"}},
                {"name": "Third party", "request": {"method": "GET", "url": "https://cdn.invalid/tracking"}},
            ],
        }), encoding="utf-8")
        (scan_path / "routes.ts").write_text(
            'router.patch("/api/orders/:id", updateOrder);\n', encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
