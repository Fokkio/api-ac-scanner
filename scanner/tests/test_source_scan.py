import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.errors import PolicyError, ScannerExecutionError
import app.source_scan as source_scan


class SourceScanTests(unittest.TestCase):
    def test_normalizes_metadata_without_source_code(self):
        with tempfile.TemporaryDirectory() as root:
            scan_path = Path(root, "request").resolve()
            scan_path.mkdir()
            (scan_path / "route.js").write_text(
                'router.get("/api/orders/:id", handler);\nconst order = await Model.findById(req.params.id);\n',
                encoding="utf-8",
            )
            source_scan.UPLOAD_ROOT = Path(root).resolve()
            payload = {
                "results": [{
                    "check_id": "rules.node-request-id-object-lookup",
                    "path": str(scan_path / "route.js"),
                    "start": {"line": 7},
                    "extra": {
                        "message": "review lookup",
                        "metadata": {
                            "category": "bola", "title": "Review", "confidence": "medium",
                            "severity_label": "high", "owasp_id": "API1:2023", "recommendation": "Authorize",
                        },
                        "lines": "secret source text",
                    },
                }],
            }
            with patch("app.source_scan._execute_semgrep", return_value=json.dumps(payload)):
                result = source_scan.run_source_scan(str(scan_path))
            finding = result["findings"][0]
            self.assertEqual(finding["location"], "route.js:7")
            self.assertNotIn("secret source text", json.dumps(finding))
            self.assertEqual(finding["evidence"]["endpointPath"], "/api/orders/:id")

    def test_fails_closed_on_analyzer_error(self):
        with tempfile.TemporaryDirectory() as root:
            scan_path = Path(root, "request").resolve()
            scan_path.mkdir()
            source_scan.UPLOAD_ROOT = Path(root).resolve()
            with patch("app.source_scan.subprocess.run", return_value=SimpleNamespace(returncode=2)):
                with self.assertRaises(ScannerExecutionError):
                    source_scan._execute_semgrep(["semgrep"], scan_path)

    def test_invokes_semgrep_with_json_output_flag(self):
        captured = {}
        def fake_run(command, **_kwargs):
            captured["command"] = list(command)
            return SimpleNamespace(returncode=0, stdout=b"", stderr=None)
        with patch("app.source_scan.subprocess.run", side_effect=fake_run):
            source_scan._execute_semgrep(["semgrep", "scan"], scan_path)
        self.assertIn("--json", captured["command"])
        self.assertIn("-o", captured["command"])

    def test_fails_closed_on_malformed_result_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            scan_path = Path(root, "request").resolve()
            scan_path.mkdir()
            source_scan.UPLOAD_ROOT = Path(root).resolve()
            payload = {"results": [{"check_id": "rule", "start": "invalid", "extra": {}}]}
            with patch("app.source_scan._execute_semgrep", return_value=json.dumps(payload)):
                with self.assertRaises(ScannerExecutionError):
                    source_scan.run_source_scan(str(scan_path))

    def test_rejects_upload_root_itself(self):
        with tempfile.TemporaryDirectory() as root:
            source_scan.UPLOAD_ROOT = Path(root).resolve()
            with self.assertRaises(PolicyError):
                source_scan.run_source_scan(root)


if __name__ == "__main__":
    unittest.main()
