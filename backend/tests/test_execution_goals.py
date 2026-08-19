"""Tests for the execution goal catalog and verification infrastructure."""

import re
import unittest

from app.execution_goals import (
    EXECUTION_GOAL_CATALOG,
    ALL_GOAL_IDS,
    UNIX_GOAL_IDS,
    WINDOWS_GOAL_IDS,
    LEGACY_MARKER_PATTERN,
    goals_for_target,
    verification_for_goal,
    goal_category,
    goal_command,
    normalize_execution_goal_id,
)
from app.waf_testing import verify_execution

# Compile the legacy marker pattern for test usage
_LEGACY_RE = re.compile(LEGACY_MARKER_PATTERN)


class ExecutionGoalCatalogTests(unittest.TestCase):
    """Verify the execution goal catalog is well-formed."""

    def test_all_goals_have_required_fields(self):
        for goal_id, spec in EXECUTION_GOAL_CATALOG.items():
            with self.subTest(goal=goal_id):
                self.assertIn("command", spec, f"{goal_id} missing command")
                self.assertIn("verification", spec, f"{goal_id} missing verification")
                self.assertIn("category", spec, f"{goal_id} missing category")
                self.assertIn("type", spec["verification"], f"{goal_id} verification missing type")
                self.assertIn("description", spec["verification"], f"{goal_id} verification missing description")

    def test_all_verification_types_are_valid(self):
        valid_types = {"marker", "regex", "combo"}
        for goal_id, spec in EXECUTION_GOAL_CATALOG.items():
            with self.subTest(goal=goal_id):
                vtype = spec["verification"]["type"]
                self.assertIn(vtype, valid_types, f"{goal_id}: unknown type {vtype}")

    def test_marker_goals_have_placeholders(self):
        for goal_id, spec in EXECUTION_GOAL_CATALOG.items():
            if spec["verification"]["type"] == "marker":
                with self.subTest(goal=goal_id):
                    self.assertIn("placeholders", spec, f"{goal_id}: marker type needs placeholders")

    def test_id_format_is_colon_separated(self):
        valid_prefixes = ("identity", "system", "env", "output", "file", "dir", "process", "network")
        for goal_id in EXECUTION_GOAL_CATALOG:
            parts = goal_id.split(":")
            self.assertEqual(len(parts), 2, f"{goal_id}: should be 'category:name' format")
            self.assertIn(parts[0], valid_prefixes,
                          f"{goal_id}: unknown category prefix")

    def test_goals_for_target_dvwa_returns_unix_goals(self):
        goals = goals_for_target("DVWA")
        self.assertIn("identity:whoami", goals)
        self.assertIn("identity:id", goals)
        self.assertIn("system:uname", goals)
        self.assertIn("output:canary", goals)
        # Should not contain Windows-only goals (all Unix goals are a superset)
        self.assertEqual(len(goals), len(UNIX_GOAL_IDS))

    def test_goals_for_target_pikachu_returns_unix_goals(self):
        goals = goals_for_target("Pikachu")
        self.assertEqual(set(goals), UNIX_GOAL_IDS)

    def test_goals_for_target_generic_returns_unix_goals(self):
        goals = goals_for_target("通用")
        self.assertEqual(set(goals), UNIX_GOAL_IDS)

    def test_goals_for_target_windows_returns_limited_goals(self):
        goals = goals_for_target("Windows")
        self.assertEqual(set(goals), WINDOWS_GOAL_IDS)
        # Windows should NOT include Linux-only file/dir system goals
        self.assertNotIn("file:passwd", goals)
        self.assertNotIn("system:uname", goals)
        self.assertNotIn("dir:find-suid", goals)

    def test_goals_for_unknown_target_returns_all(self):
        goals = goals_for_target("UnknownTarget")
        self.assertEqual(set(goals), ALL_GOAL_IDS)

    def test_verification_for_goal_returns_copy(self):
        spec1 = verification_for_goal("identity:whoami")
        spec2 = verification_for_goal("identity:whoami")
        self.assertEqual(spec1, spec2)
        self.assertIsNot(spec1, spec2)  # Should be a copy

    def test_verification_for_goal_with_placeholders(self):
        spec = verification_for_goal("output:canary", {"{CANARY}": "TEST123"})
        self.assertEqual(spec["type"], "marker")
        self.assertEqual(spec["marker"], "TEST123")

    def test_verification_for_goal_unknown_raises(self):
        with self.assertRaises(ValueError):
            verification_for_goal("nonexistent:goal")

    def test_normalize_execution_goal_repairs_unique_short_tail(self):
        self.assertEqual(normalize_execution_goal_id("file:passw"), "file:passwd")
        self.assertEqual(normalize_execution_goal_id(" FILE:PASSW\n"), "file:passwd")

    def test_normalize_execution_goal_keeps_unknown_or_long_truncation_invalid(self):
        self.assertEqual(normalize_execution_goal_id("file:pas"), "file:pas")
        self.assertEqual(normalize_execution_goal_id("file:not-real"), "file:not-real")

    def test_goal_category_returns_string(self):
        for goal_id in EXECUTION_GOAL_CATALOG:
            cat = goal_category(goal_id)
            self.assertIsInstance(cat, str)
            self.assertTrue(len(cat) > 0, f"{goal_id}: empty category")

    def test_goal_command_returns_string(self):
        for goal_id in EXECUTION_GOAL_CATALOG:
            cmd = goal_command(goal_id)
            self.assertIsInstance(cmd, str)
            self.assertTrue(len(cmd) > 0, f"{goal_id}: empty command")


class LegacyMarkerTests(unittest.TestCase):
    """Verify legacy marker pattern still works for backward compatibility."""

    def test_legacy_pattern_matches_known_markers(self):
        markers = [
            "DVWA_CMD_LOW_OK",
            "PIKACHU_CMD_BASIC_OK",
            "BACKTICK_CMD_OK",
            "AWK_SYS_OK",
            "SCP_PC_OK",
            "FIND_EXEC_OK",
        ]
        for marker in markers:
            with self.subTest(marker=marker):
                self.assertIsNotNone(_LEGACY_RE.search(marker))

    def test_legacy_pattern_rejects_non_markers(self):
        non_markers = ["ok", "OK", "x_OK", "123_OK", "a_bc_OK"]
        for text in non_markers:
            with self.subTest(text=text):
                self.assertIsNone(_LEGACY_RE.search(text))


class VerifyExecutionTests(unittest.TestCase):
    """Test the verify_execution function in waf_testing.py."""

    def test_marker_spec_returns_execution_confirmed_when_found(self):
        spec = {"type": "marker", "marker": "CANARY123"}
        result, evidence = verify_execution(
            "some output containing CANARY123 in the middle",
            spec,
            "original content",
        )
        self.assertEqual(result, "execution_confirmed")
        self.assertIn("CANARY123", evidence)

    def test_marker_spec_returns_application_response_when_not_found(self):
        spec = {"type": "marker", "marker": "CANARY123"}
        result, evidence = verify_execution(
            "completely different output",
            spec,
            "original content",
        )
        self.assertEqual(result, "application_response")
        self.assertIn("CANARY123", evidence)

    def test_marker_spec_empty_marker(self):
        spec = {"type": "marker", "marker": ""}
        result, evidence = verify_execution("any response", spec, "content")
        self.assertEqual(result, "application_response")

    def test_regex_spec_returns_execution_confirmed_when_matched(self):
        spec = {"type": "regex", "pattern": r"uid=\d+\([^)]+\)"}
        result, evidence = verify_execution(
            "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
            spec,
            "content",
        )
        self.assertEqual(result, "execution_confirmed")
        self.assertIn("uid=", evidence)

    def test_regex_spec_returns_application_response_when_not_matched(self):
        spec = {"type": "regex", "pattern": r"uid=\d+\([^)]+\)"}
        result, evidence = verify_execution(
            "command not found: id",
            spec,
            "content",
        )
        self.assertEqual(result, "application_response")
        self.assertIn("不匹配", evidence)

    def test_regex_spec_empty_pattern(self):
        spec = {"type": "regex", "pattern": ""}
        result, evidence = verify_execution("any response", spec, "content")
        self.assertEqual(result, "application_response")

    def test_combo_spec_both_pass(self):
        spec = {
            "type": "combo",
            "marker": "CANARY_OK",
            "pattern": r"uid=\d+",
        }
        result, evidence = verify_execution(
            "CANARY_OK uid=33(www-data) extra output",
            spec,
            "content",
        )
        self.assertEqual(result, "execution_confirmed")
        self.assertIn("OK", evidence)

    def test_combo_spec_only_marker_passes(self):
        spec = {
            "type": "combo",
            "marker": "CANARY_OK",
            "pattern": r"uid=\d+",
        }
        result, evidence = verify_execution(
            "CANARY_OK but no uid pattern here",
            spec,
            "content",
        )
        self.assertEqual(result, "application_response")
        self.assertIn("FAIL", evidence)

    def test_combo_spec_only_regex_passes(self):
        spec = {
            "type": "combo",
            "marker": "CANARY_OK",
            "pattern": r"uid=\d+",
        }
        result, evidence = verify_execution(
            "uid=33(www-data) but no canary marker",
            spec,
            "content",
        )
        self.assertEqual(result, "application_response")
        self.assertIn("FAIL", evidence)

    def test_combo_spec_none_pass(self):
        spec = {
            "type": "combo",
            "marker": "CANARY_OK",
            "pattern": r"uid=\d+",
        }
        result, evidence = verify_execution(
            "completely different output",
            spec,
            "content",
        )
        self.assertEqual(result, "application_response")

    def test_legacy_fallback_when_spec_is_none(self):
        # Content contains a legacy *_OK marker, it's in the response
        result, evidence = verify_execution(
            "output with DVWA_CMD_SEMI_OK present",
            None,
            "127.0.0.1; echo DVWA_CMD_SEMI_OK",
        )
        self.assertEqual(result, "execution_confirmed")
        self.assertIn("Legacy", evidence)

    def test_legacy_fallback_when_marker_not_in_response(self):
        result, evidence = verify_execution(
            "output without the expected marker",
            None,
            "127.0.0.1; echo DVWA_CMD_SEMI_OK",
        )
        self.assertEqual(result, "application_response")

    def test_legacy_fallback_when_content_has_no_marker(self):
        result, evidence = verify_execution(
            "some generic output",
            None,
            "127.0.0.1; whoami",  # no *_OK marker
        )
        self.assertEqual(result, "application_response")

    def test_structured_spec_takes_priority_over_legacy(self):
        # Even though content has *_OK marker, structured spec is checked first
        spec = {"type": "regex", "pattern": r"uid=\d+"}
        result, evidence = verify_execution(
            "uid=33(www-data) but no MARKER_OK here",
            spec,
            "127.0.0.1; echo MARKER_OK",  # has legacy marker
        )
        # Structured regex matched, so execution confirmed (not legacy)
        self.assertEqual(result, "execution_confirmed")
        self.assertIn("结构化", evidence)

    def test_none_dict_like_spec_is_ignored(self):
        # Edge case: spec is not a dict
        result, evidence = verify_execution(
            "DVWA_CMD_SEMI_OK in response",
            None,
            "127.0.0.1; echo DVWA_CMD_SEMI_OK",
        )
        self.assertEqual(result, "execution_confirmed")


if __name__ == "__main__":
    unittest.main()
