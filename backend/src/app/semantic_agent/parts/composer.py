"""Deterministic recomposition from parts and semantic delta comparison."""

from __future__ import annotations

from typing import Any


_CMD_ORDER = {
    "safe_prefix": 10, "quote_context": 20, "separator": 30,
    "var_indirection": 35, "subshell": 38,
    "injection_command": 40, "path": 45,
    "brace_expansion": 47, "wildcard_part": 48,
    "argument": 50, "ifs_whitespace": 52,
    "pipeline": 60, "conditional": 70, "bounded_loop": 80,
    "here_string": 85, "stderr_handling": 90, "output_marker": 100,
}
_SQL_ORDER = {
    "prefix": 10, "quote_boundary": 20, "operator": 30,
    "predicate": 40, "comparison_value": 45, "subquery": 50,
    "join_or_union": 60, "whitespace_structure": 70, "comment_terminator": 80,
}
_XSS_ORDER = {
    "context_prefix": 10, "tag": 20, "attribute_boundary": 30,
    "event_handler": 40, "javascript_expression": 50,
    "closing_structure": 60, "text_spacing": 70,
}


def recompose_semantic_parts(parts: list[dict[str, Any]]) -> str:
    """Rebuild the full payload text from parts.

    Parts are ordered by their parser position; when an operation adds a part,
    the caller-provided dependencies act as its deterministic insertion anchor.
    The parser stores punctuation and spacing as component text, so this method
    deliberately does not insert a space between every adjacent component.
    """
    if not parts:
        return ""
    def sort_key(part: dict[str, Any]) -> tuple[int, int, str]:
        pos = part.get("position", {})
        return (int(pos.get("start", 10 ** 8)), int(pos.get("end", 10 ** 8)), part.get("part_id", ""))

    positioned = sorted(
        (p for p in parts
         if not p.get("added_by_operation") and not p.get("virtual")),
        key=sort_key,
    )
    added = [p for p in parts
             if p.get("added_by_operation") and not p.get("virtual")]
    if not positioned:
        return ""

    # Compose the original positioned sequence.  Separators, quotes and tag
    # boundaries must stay adjacent; ordinary command/SQL words need spacing.
    result = ""
    previous_type = ""
    compact_after = {"safe_prefix", "quote_context", "separator", "var_indirection",
                     "subshell", "brace_expansion", "quote_boundary", "attribute_boundary",
                     "event_handler", "closing_structure", "context_prefix"}
    compact_before = {"separator", "subshell", "pipeline", "conditional",
                      "quote_boundary", "comment_terminator", "closing_structure",
                      "here_string", "stderr_handling"}
    for part in positioned:
        raw = part.get("raw", "")
        if not raw:
            continue
        part_type = part.get("part_type", "")
        raw_starts_ws = raw[:1].isspace()
        result_ends_ws = bool(result) and result[-1:].isspace()
        needs_space = bool(result) and not raw_starts_ws and not result_ends_ws
        if part_type in compact_before or previous_type in compact_after:
            needs_space = False
        # Force a space between adjacent semantically-distinct words, but never
        # duplicate whitespace that either side already carries.
        if part_type in {"argument", "predicate", "operator", "pipeline", "conditional",
                         "bounded_loop", "stderr_handling", "ifs_whitespace",
                         "var_indirection", "wildcard_part"} \
           and previous_type not in {"separator", "quote_boundary", "var_indirection"} \
           and not raw_starts_ws and not result_ends_ws:
            needs_space = True
        if needs_space:
            result += " "
        result += raw
        previous_type = part_type

    # Insert additions after their last dependency when possible; additions
    # without a dependency are appended as a separate syntactic component.
    for part in sorted(added, key=sort_key):
        raw = part.get("raw", "")
        if not raw:
            continue
        separator = "" if raw[:1] in ";|&>#<" else " "
        result += separator + raw

    # Strip leading newlines that break URL encoding
    return result.lstrip('\n\r')


def compare_semantic_delta(
    base_parts: list[dict[str, Any]],
    candidate_parts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a structured delta between base and candidate parts."""
    base_by_id = {p["part_id"]: p for p in base_parts}
    cand_by_id = {p["part_id"]: p for p in candidate_parts}
    changed_parts: list[str] = []
    substantive = False

    # Find changed parts
    for pid, bp in base_by_id.items():
        if pid in cand_by_id:
            if bp.get("raw") != cand_by_id[pid].get("raw"):
                changed_parts.append(pid)
                # Only count as substantive if NOT just whitespace/case change
                old_raw = (bp.get("raw") or "").strip().lower()
                new_raw = (cand_by_id[pid].get("raw") or "").strip().lower()
                if old_raw != new_raw:
                    substantive = True
                # A standalone separator/whitespace variation is not enough;
                # predicate/operator/tag/event changes are material.
                if bp.get("part_type") in ("operator", "predicate", "quote_boundary", "event_handler", "javascript_expression", "injection_command"):
                    substantive = True
        else:
            changed_parts.append(pid)
            substantive = True  # Part removed

    # Added parts
    for pid in cand_by_id:
        if pid not in base_by_id:
            changed_parts.append(pid)
            substantive = True

    target_ok = _target_preserved(base_parts, candidate_parts)
    ctx_ok = _context_preserved(base_parts, candidate_parts)

    summary_parts: list[str] = []
    if changed_parts:
        summary_parts.append(f"变更部件：{', '.join(changed_parts)}")
    if not target_ok:
        summary_parts.append("⚠ 攻击目标已改变")

    return {
        "changed_parts": changed_parts,
        "operations": [],
        "target_preserved": target_ok,
        "context_preserved": ctx_ok,
        "substantive": substantive,
        "execution_changed": False,
        "control_flow_changed": False,
        "data_flow_changed": False,
        "summary": "；".join(summary_parts) if summary_parts else "无明显语义变化",
    }


def preserves_base_goal(
    base_parts: list[dict[str, Any]],
    candidate_or_ops: list[dict[str, Any]],
    _vulnerability: str = "",
) -> bool:
    """Check that target is preserved."""
    if not candidate_or_ops:
        return True

    base_by_id = {p["part_id"]: p for p in base_parts}

    # Detect mode: operations list or candidate parts list
    if candidate_or_ops and isinstance(candidate_or_ops[0], dict):
        if "operation" in candidate_or_ops[0]:
            # Operations mode
            for op in candidate_or_ops:
                if op.get("operation") == "replace":
                    pid = op["part_id"]
                    if pid in base_by_id and base_by_id[pid].get("part_type") == "injection_command":
                        old = _extract_cmd(base_by_id[pid].get("raw", ""))
                        new = _extract_cmd(op.get("value", ""))
                        if old and new and not _equiv(old, new):
                            return False
            return True

    # Candidate parts mode
    cand_by_id = {p["part_id"]: p for p in candidate_or_ops}
    for pid, bp in base_by_id.items():
        if bp.get("part_type") == "injection_command" and pid in cand_by_id:
            old = _extract_cmd(bp.get("raw", ""))
            new = _extract_cmd(cand_by_id[pid].get("raw", ""))
            if old and new and not _equiv(old, new):
                return False
    return True


def _target_preserved(base: list[dict[str, Any]], cand: list[dict[str, Any]]) -> bool:
    """Check injection_command target is preserved."""
    return preserves_base_goal(base, cand)


def _context_preserved(base: list[dict[str, Any]], cand: list[dict[str, Any]]) -> bool:
    cand_ids = {p["part_id"] for p in cand}
    for bp in base:
        if bp.get("required") and bp["part_id"] not in cand_ids:
            return False
    return True


def _extract_cmd(raw: str) -> str:
    import re
    c = re.sub(r"2>/dev/null|2>&[12]?", "", raw).strip()
    c = re.sub(r"\$\{IFS\}|\$IFS", " ", c)
    c = re.sub(r"\{[^}]*,[^}]*\}", "", c)
    if "|" in c:
        c = c.split("|")[0]
    ws = c.split()
    return ws[0].lower() if ws else c.lower()


def _equiv(old: str, new: str) -> bool:
    ob = old.split("/")[-1].lower()
    nb = new.split("/")[-1].lower()
    if ob == nb:
        return True
    groups = {
        "echo": {"echo", "printf"},
        "cat": {"cat", "head", "tail", "nl"},
        "whoami": {"whoami", "id"},
        "netstat": {"netstat", "ss"},
    }
    for g in groups.values():
        if ob in g and nb in g:
            return True
    return False
