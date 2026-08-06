"""Apply part operations to base parts and return modified parts."""

from __future__ import annotations

import copy
from typing import Any


def apply_part_operations(
    base_parts: list[dict[str, Any]],
    operations: list[dict[str, Any]],
    _vulnerability: str = "",
) -> list[dict[str, Any]]:
    """Execute a list of operations against base_parts.

    Returns a new list of parts (does not mutate base_parts).
    The optional _vulnerability parameter is accepted for caller compatibility.
    """
    parts = copy.deepcopy(base_parts)
    pid_map: dict[str, dict[str, Any]] = {p["part_id"]: p for p in parts}

    for op in operations:
        op_type = op["operation"]
        part_id = op["part_id"]
        part_type = op.get("part_type", "")
        value = op.get("value", "")

        if op_type == "replace":
            if part_id in pid_map:
                pid_map[part_id]["raw"] = value

        elif op_type == "remove":
            parts = [p for p in parts if p["part_id"] != part_id]
            pid_map = {p["part_id"]: p for p in parts}

        elif op_type == "add":
            deps = op.get("dependencies", [])
            pos = {"start": 0, "end": len(value)}
            if deps:
                max_end = max((pid_map[d]["position"]["end"] for d in deps if d in pid_map), default=0)
                pos = {"start": max_end, "end": max_end + len(value)}

            new_part = {
                "part_id": part_id, "part_type": part_type, "raw": value,
                "position": pos, "required": False,
                "semantic_role": op.get("role", f"新增 {part_type}"),
                "dependencies": deps, "confidence": 0.85, "added_by_operation": True,
            }
            parts.append(new_part)
            pid_map = {p["part_id"]: p for p in parts}

    return parts
