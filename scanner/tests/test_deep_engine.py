"""Unit tests for deep_engine matrix row construction."""

import sys
import unittest
from unittest.mock import patch

import sys as _sys
_sys.path.insert(0, "scanner")

from app.deep_engine import _matrix_row
from app.outbound import BoundedResponse


class _FakeIdentity:
    def __init__(self, label="Owner", role="user", tenant="t1"):
        self.label = label
        self.role = role
        self.tenant = tenant


class MatrixRowTests(unittest.TestCase):
    def _response(self, status=200, body=b"{}"):
        return BoundedResponse(status=status, headers={}, body=body, is_truncated=False, elapsed_ms=1.0)

    def test_reports_passed_method(self):
        # The row must echo the actual request method, not hardcode "GET".
        row = _matrix_row("/api/x", _FakeIdentity(), "allow", self._response(), "POST")
        self.assertEqual(row["method"], "POST")

    def test_defaults_to_get_for_backward_compatibility(self):
        row = _matrix_row("/api/x", _FakeIdentity(), "allow", self._response())
        self.assertEqual(row["method"], "GET")

    def test_classifies_body_signal(self):
        # A 200 with an explicit denial body must NOT be asserted as allow; the
        # classifier downgrades to "indeterminate" so it never asserts a wrong
        # allow/deny (fail-soft design).
        row = _matrix_row(
            "/api/x", _FakeIdentity(), "allow",
            self._response(200, b'{"error": "unauthorized"}'), "GET",
        )
        self.assertEqual(row["actual"], "indeterminate")
        self.assertFalse(row["matchesExpectation"])

    def test_401_without_body_is_denied(self):
        row = _matrix_row(
            "/api/x", _FakeIdentity(), "deny",
            self._response(401, b""), "GET",
        )
        self.assertEqual(row["actual"], "deny")
        self.assertTrue(row["matchesExpectation"])


if __name__ == "__main__":
    unittest.main()
