import unittest

from app.authorization_signals import (
    classify_decision,
    detect_body_signal,
    json_field_diff,
)
from app.outbound import BoundedResponse


class BodySignalTests(unittest.TestCase):
    def test_404_status_is_deny(self):
        self.assertEqual(classify_decision(404, b""), "deny")

    def test_200_status_is_allow(self):
        self.assertEqual(classify_decision(200, b'{"id":1}'), "allow")

    def test_200_with_error_body_downgrades_to_indeterminate(self):
        # Servers that return 200 but an error body must not be trusted as "allow".
        self.assertEqual(
            classify_decision(200, b'{"error":"forbidden","success":false}'),
            "indeterminate",
        )

    def test_403_with_success_body_downgrades_to_indeterminate(self):
        self.assertEqual(
            classify_decision(403, b'{"success":true,"data":{}}'),
            "indeterminate",
        )

    def test_body_signal_detects_denied_json(self):
        self.assertEqual(detect_body_signal(b'{"error":"not authorized"}'), "denied")

    def test_body_signal_detects_success_json(self):
        self.assertEqual(detect_body_signal(b'{"success":true}'), "success")

    def test_body_signal_none_for_neutral_body(self):
        self.assertIsNone(detect_body_signal(b'{"id":1,"name":"alice"}'))


class FieldDiffTests(unittest.TestCase):
    def test_identical_objects_no_diff(self):
        self.assertEqual(
            json_field_diff(b'{"id":1}', b'{"id":1}'),
            "",
        )

    def test_shape_identical_different_values_reports_diff(self):
        # {"id":1} vs {"id":2} share a shape but differ in data -> not a false "same".
        self.assertEqual(
            json_field_diff(b'{"id":1,"name":"a"}', b'{"id":2,"name":"a"}'),
            "id",
        )

    def test_non_json_returns_empty(self):
        self.assertEqual(json_field_diff(b"not json", b"also not json"), "")


class DecisionOnBoundedResponse(unittest.TestCase):
    def test_200_error_body_is_indeterminate_response(self):
        response = BoundedResponse(200, {}, b'{"error":"forbidden"}', False)
        self.assertEqual(classify_decision(response.status, response.body), "indeterminate")


if __name__ == "__main__":
    unittest.main()
