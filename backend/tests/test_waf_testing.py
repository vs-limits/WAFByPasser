from __future__ import annotations

import unittest

import httpx

from app.waf_testing import (
    FormParser,
    WafConfig,
    classify,
    same_origin,
    verify_execution,
)


class WafTestingUnitTests(unittest.TestCase):
    def test_same_origin_rejects_external_redirect(self) -> None:
        config = WafConfig("http://127.0.0.1:81", "admin", "password")
        self.assertEqual(same_origin(config, "/vulnerabilities/exec/"), "http://127.0.0.1:81/vulnerabilities/exec/")
        with self.assertRaisesRegex(RuntimeError, "跨源"):
            same_origin(config, "https://example.com/")

    def test_form_parser_collects_standard_input(self) -> None:
        parser = FormParser()
        parser.feed('<form action="/vulnerabilities/exec/" method="post"><input name="ip"><input name="Submit"></form>')
        self.assertEqual(parser.forms[0]["method"], "post")
        self.assertIn("ip", parser.forms[0]["inputs"])

    def test_blocked_response_is_not_execution(self) -> None:
        request = httpx.Request("GET", "http://127.0.0.1/")
        response = httpx.Response(403, request=request, text="SafeLine WAF blocked")
        result, _ = classify(response)
        self.assertEqual(result, "waf_blocked")


class VerifyExecutionUnitTests(unittest.TestCase):
    """Tests for the new verify_execution function."""

    def test_marker_spec_confirmed_when_found(self):
        spec = {"type": "marker", "marker": "CANARY123"}
        result, _ = verify_execution("output CANARY123 end", spec, "orig")
        self.assertEqual(result, "execution_confirmed")

    def test_marker_spec_not_confirmed_when_missing(self):
        spec = {"type": "marker", "marker": "CANARY123"}
        result, _ = verify_execution("different output", spec, "orig")
        self.assertEqual(result, "application_response")

    def test_regex_spec_confirmed_when_matched(self):
        spec = {"type": "regex", "pattern": r"uid=\d+\([^)]+\)"}
        result, _ = verify_execution("uid=33(www-data)", spec, "orig")
        self.assertEqual(result, "execution_confirmed")

    def test_regex_spec_not_confirmed_when_unmatched(self):
        spec = {"type": "regex", "pattern": r"uid=\d+\([^)]+\)"}
        result, _ = verify_execution("command not found", spec, "orig")
        self.assertEqual(result, "application_response")

    def test_combo_spec_both_pass(self):
        spec = {"type": "combo", "marker": "OK", "pattern": r"uid=\d+"}
        result, _ = verify_execution("OK uid=33", spec, "orig")
        self.assertEqual(result, "execution_confirmed")

    def test_combo_spec_partial_fail(self):
        spec = {"type": "combo", "marker": "OK", "pattern": r"uid=\d+"}
        result, _ = verify_execution("OK but no uid", spec, "orig")
        self.assertEqual(result, "application_response")

    def test_legacy_fallback_with_ok_marker(self):
        result, _ = verify_execution(
            "response with DVWA_CMD_SEMI_OK inside",
            None,
            "127.0.0.1; echo DVWA_CMD_SEMI_OK",
        )
        self.assertEqual(result, "execution_confirmed")

    def test_legacy_fallback_marker_absent(self):
        result, _ = verify_execution(
            "response without marker",
            None,
            "127.0.0.1; echo DVWA_CMD_SEMI_OK",
        )
        self.assertEqual(result, "application_response")

    def test_no_spec_and_no_legacy_marker(self):
        result, _ = verify_execution(
            "some output",
            None,
            "127.0.0.1; whoami",  # no *_OK marker
        )
        self.assertEqual(result, "application_response")


if __name__ == "__main__":
    unittest.main()
