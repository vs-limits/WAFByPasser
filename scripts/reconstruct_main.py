"""
Reconstruct main.py from its Python 3.12 .pyc bytecode file.

Strategy: extract bytecode instructions, map them back to Python source
via pattern matching on common Python 3.12 bytecode idioms.
"""

from __future__ import annotations

import dis
import marshal
import re
import sys
from pathlib import Path
from typing import Any

PYC_PATH = Path(__file__).resolve().parents[1] / "backend" / "src" / "app" / "__pycache__" / "main.cpython-312.pyc"
OUT_PATH = Path(__file__).resolve().parents[1] / "backend" / "src" / "app" / "main.py"


def load_code(path: Path):
    with open(path, "rb") as f:
        f.read(16)  # Python 3.12 header
        return marshal.load(f)


def get_instructions(code):
    """Get instructions grouped by line number."""
    lines: dict[int, list[dis.Instruction]] = {}
    for instr in dis.get_instructions(code):
        line = instr.positions.lineno if instr.positions else None
        if line is not None:
            lines.setdefault(line, []).append(instr)
    return lines


def get_name(idx: int) -> str:
    return MODULE_CODE.co_names[idx]


def get_const(idx: int) -> Any:
    return MODULE_CODE.co_consts[idx]


def get_varname(idx: int) -> str:
    return MODULE_CODE.co_varnames[idx]


# Load the module
MODULE_CODE = load_code(PYC_PATH)

# Map from name index to name
_names = MODULE_CODE.co_names
_consts = MODULE_CODE.co_consts


def const_repr(value: Any) -> str:
    """Python representation of a constant."""
    if value is None:
        return "None"
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, tuple):
        items = ", ".join(const_repr(v) for v in value)
        if len(value) == 1:
            return f"({items},)"
        return f"({items})"
    if isinstance(value, frozenset):
        items = ", ".join(const_repr(v) for v in sorted(value, key=str))
        return f"frozenset({{{items}}})"
    if hasattr(value, "co_name"):
        return f"<code:{value.co_name}>"
    return repr(value)


def disasm_simple(instrs: list[dis.Instruction]) -> list[str]:
    """Very simple bytecode-to-source decompiler for common patterns."""
    result: list[str] = []
    i = 0
    while i < len(instrs):
        instr = instrs[i]
        op = instr.opname

        # RESUME
        if op == "RESUME":
            i += 1
            continue

        # LOAD_CONST + RETURN_VALUE
        if op == "LOAD_CONST" and i + 1 < len(instrs) and instrs[i + 1].opname == "RETURN_VALUE":
            result.append(f"return {const_repr(_consts[instr.arg])}")
            i += 2
            continue

        # LOAD_CONST + STORE_NAME (assignment)
        if op == "LOAD_CONST":
            if i + 1 < len(instrs) and instrs[i + 1].opname == "STORE_NAME":
                val = _consts[instr.arg]
                name = _names[instrs[i + 1].arg]
                result.append(f"{name} = {const_repr(val)}")
                i += 2
                continue

        # LOAD_NAME / LOAD_GLOBAL
        if op in ("LOAD_NAME", "LOAD_GLOBAL"):
            name = _names[instr.arg]
            result.append(name)
            i += 1
            continue

        # CALL
        if op == "CALL":
            argc = instr.arg
            result.append(f"CALL({argc})")
            i += 1
            continue

        # RETURN_VALUE
        if op == "RETURN_VALUE":
            result.append("return")
            i += 1
            continue

        # Fallback
        result.append(f"# {op}({instr.arg})")
        i += 1

    return result


# ---------------------------------------------------------------------------
# Main reconstruction
# ---------------------------------------------------------------------------
def reconstruct_module() -> str:
    """Reconstruct the full main.py source."""
    lines: list[str] = []

    # Imports block (lines 1-37 from disassembly)
    lines.append('"""WAFByPasser local API — FastAPI application."""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("import json")
    lines.append("import hashlib")
    lines.append("import os")
    lines.append("import re")
    lines.append("import sqlite3")
    lines.append("import threading")
    lines.append("import time")
    lines.append("import uuid")
    lines.append("from contextlib import asynccontextmanager")
    lines.append("from datetime import datetime, timezone")
    lines.append("from pathlib import Path")
    lines.append("from typing import Any, Literal")
    lines.append("")
    lines.append("import httpx")
    lines.append("from dotenv import load_dotenv")
    lines.append("from fastapi import BackgroundTasks, FastAPI, HTTPException, Query")
    lines.append("from fastapi.middleware.cors import CORSMiddleware")
    lines.append("from pydantic import BaseModel, Field")
    lines.append("")
    lines.append("from app.cross_iteration import (")
    lines.append("    build_cross_candidates,")
    lines.append("    encoding_chain_key,")
    lines.append("    unused_distinct_chains,")
    lines.append(")")
    lines.append("from app.encoding_agent.encoding import (")
    lines.append("    allowed_encoding_catalog,")
    lines.append("    validate_encoding_candidates,")
    lines.append(")")
    lines.append("from app.encoding_agent.prompts import (")
    lines.append("    ACTIVE_SKILLS as ENCODING_ACTIVE_SKILLS,")
    lines.append("    SYSTEM_PROMPT_PATH as ENCODING_SYSTEM_PROMPT_PATH,")
    lines.append("    build_encoding_system_prompt,")
    lines.append(")")
    lines.append("from app.semantic_agent.prompts import SYSTEM_PROMPT_PATH, build_system_prompt")
    lines.append("from app.waf_testing import SUPPORTED as WAF_SUPPORTED, preflight as waf_preflight, run_http_test, run_xss_test")
    lines.append("")

    # Path constants
    lines.append("PROJECT_ROOT = Path(__file__).resolve().parents[3]")
    lines.append('CONFIG_PATH = PROJECT_ROOT / "config" / ".env"')
    lines.append('DB_PATH = PROJECT_ROOT / "data" / "waf_bypasser.db"')
    lines.append('SEMANTIC_AGENT_ROOT = Path(__file__).resolve().parent / "semantic_agent"')
    lines.append('ENCODING_AGENT_ROOT = Path(__file__).resolve().parent / "encoding_agent"')
    lines.append("")

    # Agent documents
    lines.append("AGENT_DOCUMENTS = {")
    lines.append('    "skill/vulnerability-semantic-understanding": (')
    lines.append('        "skill",')
    lines.append('        "漏洞语义理解 Skill",')
    lines.append('        SEMANTIC_AGENT_ROOT / "skill" / "vulnerability_semantic_understanding.md",')
    lines.append("    ),")
    lines.append('    "skill/payload-semantic-mutation": (')
    lines.append('        "skill",')
    lines.append('        "Payload 语义变异 Skill",')
    lines.append('        SEMANTIC_AGENT_ROOT / "skill" / "payload_semantic_mutation.md",')
    lines.append("    ),")
    lines.append('    "skill/filter-reverse-engineering": (')
    lines.append('        "skill",')
    lines.append('        "过滤规则逆向 Skill",')
    lines.append('        SEMANTIC_AGENT_ROOT / "skill" / "filter_reverse_engineering.md",')
    lines.append("    ),")
    lines.append('    "skill/context-awareness": (')
    lines.append('        "skill",')
    lines.append('        "上下文感知 Skill",')
    lines.append('        SEMANTIC_AGENT_ROOT / "skill" / "context_awareness.md",')
    lines.append("    ),")
    lines.append('    "skill/vulnerability-verification-reasoning": (')
    lines.append('        "skill",')
    lines.append('        "漏洞验证推理 Skill",')
    lines.append('        SEMANTIC_AGENT_ROOT / "skill" / "vulnerability_verification_reasoning.md",')
    lines.append("    ),")
    lines.append('    "prompt/semantic-mutation-agent": (')
    lines.append('        "prompt",')
    lines.append('        "语义变异 Agent 提示词",')
    lines.append("        SYSTEM_PROMPT_PATH,")
    lines.append("    ),")
    lines.append("}")
    lines.append("")

    lines.append("ENCODING_AGENT_DOCUMENTS = {")
    lines.append('    f"skill/{path.stem.replace(\"_\", \"-\")}": ("skill", title, path)')
    lines.append("    for title, path in ENCODING_ACTIVE_SKILLS")
    lines.append("}")
    lines.append("ENCODING_AGENT_DOCUMENTS[\"prompt/encoding-iteration-agent\"] = (")
    lines.append('    "prompt",')
    lines.append('    "编码迭代 Agent 提示词",')
    lines.append("    ENCODING_SYSTEM_PROMPT_PATH,")
    lines.append(")")
    lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    source = reconstruct_module()
    OUT_PATH.write_text(source, encoding="utf-8")
    print(f"Wrote {len(source)} bytes to {OUT_PATH}")
    print("This is a skeleton — full reconstruction in progress.")
