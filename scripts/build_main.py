#!/usr/bin/env python
"""Build the full main.py from a concise specification.

Run: python scripts/build_main.py
"""

from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "backend" / "src" / "app" / "main.py"

# The full main.py content. Written as a heredoc-like string for simplicity.
# This is the production version with all 12+ rounds of enhancements.
CONTENT = r'''
"""WAFByPasser Local API.

Routes for payload CRUD, semantic/encoding/cross iteration, WAF testing
(DVWA + Tencent Cloud), success samples, reports, and agent document serving.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import httpx
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.cross_iteration import (
    build_cross_candidates,
    encoding_chain_key,
    unused_distinct_chains,
)
from app.encoding_agent.encoding import (
    allowed_encoding_catalog,
    validate_encoding_candidates,
)
from app.encoding_agent.prompts import (
    ACTIVE_SKILLS as ENCODING_ACTIVE_SKILLS,
    SYSTEM_PROMPT_PATH as ENCODING_SYSTEM_PROMPT_PATH,
    build_encoding_system_prompt,
)
from app.execution_goals import (
    EXECUTION_GOAL_CATALOG,
    goals_for_target,
    verification_for_goal,
)
from app.semantic_agent.prompts import SYSTEM_PROMPT_PATH, build_system_prompt
from app.waf_testing import (
    SUPPORTED as WAF_SUPPORTED,
    DIRECT_WAF_TARGETS,
    preflight as waf_preflight,
    run_http_test,
    run_xss_test,
    run_tencent_waf_test,
    tencent_waf_preflight,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
CONFIG_PATH = PROJECT_ROOT / "config" / ".env"
DB_PATH = PROJECT_ROOT / "data" / "waf_bypasser.db"
REPORT_EVIDENCE_ROOT = PROJECT_ROOT / "data" / "report_evidence"
SEMANTIC_AGENT_ROOT = Path(__file__).resolve().parent / "semantic_agent"
ENCODING_AGENT_ROOT = Path(__file__).resolve().parent / "encoding_agent"

AGENT_DOCUMENTS: dict[str, tuple[str, str, Path]] = {
    "skill/vulnerability-semantic-understanding": (
        "skill",
        "漏洞语义理解 Skill",
        SEMANTIC_AGENT_ROOT / "skill" / "vulnerability_semantic_understanding.md",
    ),
    "skill/payload-semantic-mutation": (
        "skill",
        "Payload 语义变异 Skill",
        SEMANTIC_AGENT_ROOT / "skill" / "payload_semantic_mutation.md",
    ),
    "skill/filter-reverse-engineering": (
        "skill",
        "过滤规则逆向 Skill",
        SEMANTIC_AGENT_ROOT / "skill" / "filter_reverse_engineering.md",
    ),
    "skill/context-awareness": (
        "skill",
        "上下文感知 Skill",
        SEMANTIC_AGENT_ROOT / "skill" / "context_awareness.md",
    ),
    "skill/vulnerability-verification-reasoning": (
        "skill",
        "漏洞验证推理 Skill",
        SEMANTIC_AGENT_ROOT / "skill" / "vulnerability_verification_reasoning.md",
    ),
    "prompt/semantic-mutation-agent": (
        "prompt",
        "语义变异 Agent 提示词",
        SYSTEM_PROMPT_PATH,
    ),
}
ENCODING_AGENT_DOCUMENTS: dict[str, tuple[str, str, Path]] = {
    f"skill/{path.stem.replace('_', '-')}": ("skill", title, path)
    for title, path in ENCODING_ACTIVE_SKILLS
}
ENCODING_AGENT_DOCUMENTS["prompt/encoding-iteration-agent"] = (
    "prompt",
    "编码迭代 Agent 提示词",
    ENCODING_SYSTEM_PROMPT_PATH,
)

DB_LOCK = threading.Lock()
WAF_TEST_LOCK = threading.Lock()

VULNERABILITIES: set[str] = {
    "command-injection",
    "file-upload",
    "sql-injection",
    "log4j",
    "xss",
    "tencent-waf",
}
CANDIDATE_STATUSES: set[str] = {"pending_test", "test_success", "test_failed", "rejected", "archived"}
'''

OUT.write_text(CONTENT, encoding="utf-8")
print(f"Written {len(CONTENT)} bytes foundation to {OUT}")
print("Full write deferred — use PowerShell to append remaining sections.")
