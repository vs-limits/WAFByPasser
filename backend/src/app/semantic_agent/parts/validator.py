"""Validate part operations against base parts and vulnerability rules."""

from __future__ import annotations

from typing import Any

from app.semantic_agent.parts.parser import VULNERABILITY_PART_TYPES


def validate_semantic_parts(
    base_parts_or_ops: list[dict[str, Any]],
    vulnerability_or_base: str | list[dict[str, Any]] = "",
    vuln: str = "",
) -> list[str]:
    """Check operations are legal. Returns list of error strings (empty = valid).

    Can be called as:
      validate_semantic_parts(base_parts, vulnerability)  — validates parts themselves
      validate_semantic_parts(operations, base_parts, vulnerability)  — validates ops

    When called with just (base_parts, vulnerability), validates that parts
    are well-formed (every required part has raw text, etc).
    When called with (operations, base_parts, vulnerability), validates ops.
    """
    # Resolve overloaded signature
    operations: list[dict[str, Any]] = []
    base_parts: list[dict[str, Any]] = []
    vulnerability = ""

    if isinstance(vulnerability_or_base, str):
        # Called as validate_semantic_parts(base_parts, vulnerability)
        base_parts = base_parts_or_ops
        vulnerability = vulnerability_or_base
        # Parts-validity check mode
        for p in base_parts:
            # separator 和 quote_context 允许为空（如隐式分隔符、无引号上下文）
            if p.get("required") and not p.get("raw", "").strip() and p.get("part_type") not in ("quote_context", "separator"):
                return [f"必选部件 {p['part_id']} ({p['part_type']}) 缺少 raw 内容"]
        return []
    elif isinstance(vulnerability_or_base, list):
        if isinstance(vuln, str) and vuln:
            # Called as validate_semantic_parts(operations, base_parts, vuln)
            operations = base_parts_or_ops
            base_parts = vulnerability_or_base
            vulnerability = vuln
        else:
            # Called as validate_semantic_parts(base_parts) — malformed
            base_parts = base_parts_or_ops
            for p in base_parts:
                # separator 和 quote_context 允许为空（如隐式分隔符、无引号上下文）
                if p.get("required") and not p.get("raw", "").strip() and p.get("part_type") not in ("quote_context", "separator"):
                    return [f"必选部件 {p['part_id']} ({p['part_type']}) 缺少 raw 内容"]
            return []
    errors: list[str] = []
    catalogue = VULNERABILITY_PART_TYPES.get(vulnerability, {})
    parts_by_id: dict[str, dict[str, Any]] = {p["part_id"]: p for p in base_parts}

    for i, op in enumerate(operations):
        op_type = op.get("operation")
        part_id = op.get("part_id", "")
        part_type = op.get("part_type", "")

        if op_type not in ("replace", "add", "remove"):
            errors.append(f"操作[{i}]：不支持的操作 '{op_type}'")
            continue

        part_def = catalogue.get(part_type)
        if not part_def:
            errors.append(f"操作[{i}]：未知部件类型 '{part_type}'")
            continue

        # 放松操作类型限制 - 允许所有操作类型
        # allowed = part_def.get("allowed_ops", [])
        # if op_type not in allowed:
        #     errors.append(f"操作[{i}]：'{part_type}' 不允许 {op_type}（仅 {allowed}）")
        #     continue

        if op_type in ("replace", "remove"):
            if part_id not in parts_by_id:
                errors.append(f"操作[{i}]：部件 '{part_id}' 不存在")
                continue
            existing = parts_by_id[part_id]
            if existing.get("required") and op_type == "remove":
                errors.append(f"操作[{i}]：不能删除必选部件 '{part_id}' ({existing.get('part_type')})")

        if op_type == "replace":
            value = op.get("value")
            if not isinstance(value, str):
                op["value"] = "" if value is None else str(value)

        if op_type == "add":
            if not part_id.startswith("new_"):
                errors.append(f"操作[{i}]：add 的 part_id 必须以 'new_' 开头")
            if part_id in parts_by_id:
                errors.append(f"操作[{i}]：add 目标 '{part_id}' 与已有部件冲突")
            if not op.get("value") or not str(op.get("value", "")).strip():
                errors.append(f"操作[{i}]：add 操作必须有非空 value")
            deps = op.get("dependencies", [])
            if deps and (not isinstance(deps, list) or any(dep not in parts_by_id for dep in deps)):
                errors.append(f"操作[{i}]：add 的依赖部件不存在")

    return errors
