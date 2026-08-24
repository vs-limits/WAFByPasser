
"""WAFByPasser Local API.

Routes for payload CRUD, semantic/encoding/cross iteration, WAF testing
(DVWA + Tencent Cloud), success samples, reports, and agent document serving.
"""

from __future__ import annotations

import json
import hashlib
import logging
import os
import re
import shutil
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

import httpx
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.cross_iteration import (
    build_cross_candidates,
    encoding_chain_key,
    unused_distinct_chains,
)
from app.encoding_agent.encoding import (
    allowed_encoding_catalog,
    realize_encoding_intent,
    validate_encoding_candidates,
    _verify_reversible,
)
from app.encoding_agent.prompts import (
    ACTIVE_SKILLS as ENCODING_ACTIVE_SKILLS,
    SYSTEM_PROMPT_PATH as ENCODING_SYSTEM_PROMPT_PATH,
    build_encoding_system_prompt,
)
from app.execution_goals import (
    EXECUTION_GOAL_CATALOG,
    goals_for_target,
    normalize_execution_goal_id,
    verification_for_goal,
)
from app.semantic_agent.prompts import SYSTEM_PROMPT_PATH, build_system_prompt
from app.semantic_agent.parts import (
    SUPPORTED_VULNERABILITIES as SEMANTIC_PART_VULNERABILITIES,
    apply_part_operations,
    compare_semantic_delta,
    parse_semantic_parts,
    preserves_base_goal,
    recompose_semantic_parts,
    semantic_part_directions,
    validate_semantic_parts,
)
from app.waf_testing import (
    SUPPORTED as WAF_SUPPORTED,
    preflight as waf_preflight,
    run_http_test,
    run_xss_test,
)
from app.verification_agent.adapters import (
    PASS_ROUTES,
    PHP_PASS_ROUTES,
    TargetEvidence,
    resolve_adapter,
    verification_targets,
)
from app.verification_agent.judge import (
    OUTCOME_EXECUTION_CONFIRMED,
    OUTCOME_REQUEST_ERROR,
    OUTCOME_UNSUPPORTED_CONTEXT,
    OUTCOME_WAF_BLOCKED,
    build_judge_user_message,
    check_error_verdict,
    is_unverifiable_payload,
    normalize_verdict,
    parse_verdict,
)
from app.verification_agent.prompts import build_judge_system_prompt
from app.knowledge_base_agent import (
    KNOWLEDGE_BASE_AGENT_SYSTEM_PROMPT_PATH,
    technique_dimension,
    technique_group,
)
from app.knowledge_base_agent.prompts import (
    ACTIVE_SKILLS as KNOWLEDGE_BASE_ACTIVE_SKILLS,
)
from app.knowledge_base_agent.exhaustion import (
    build_exhaustion_user_message,
    exhaustion_summary,
    infer_backend_from_primitive,
    prune_techniques_for_exhaustion,
    EXHAUSTION_SYSTEM_PROMPT,
)
from app.knowledge_base_agent.features import (
    feature_insights,
    record_features,
)
from app.knowledge_base_agent.generalization import (
    build_exploit_user_message,
    build_pioneer_user_message,
    normalize_vulnerability,
    prefilter_generated_technique,
    signature_for_candidate,
    EXPLOIT_SYSTEM_PROMPT,
    PIONEER_SYSTEM_PROMPT,
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
    "skill/cmd-injection-mutation": (
        "skill",
        "命令注入语义变异 Skill",
        SEMANTIC_AGENT_ROOT / "skill" / "cmd_injection_mutation.md",
    ),
    "skill/sql-injection-mutation": (
        "skill",
        "SQL 注入语义变异 Skill",
        SEMANTIC_AGENT_ROOT / "skill" / "sql_injection_mutation_production.md",
    ),
    "skill/xss-mutation": (
        "skill",
        "XSS 语义变异 Skill",
        SEMANTIC_AGENT_ROOT / "skill" / "xss_mutation_production.md",
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
VERIFICATION_AGENT_DOCUMENTS: dict[str, tuple[str, str, Path]] = {
    "prompt/verification-judge": (
        "prompt",
        "检验 Agent 判定提示词",
        Path(__file__).resolve().parent / "verification_agent" / "prompt" / "verification_judge.md",
    ),
}
KNOWLEDGE_BASE_AGENT_DOCUMENTS: dict[str, tuple[str, str, Path]] = {
    f"skill/{path.stem.replace('_', '-')}": ("skill", title, path)
    for title, path in KNOWLEDGE_BASE_ACTIVE_SKILLS
}
KNOWLEDGE_BASE_AGENT_DOCUMENTS["prompt/knowledge-base-agent"] = (
    "prompt",
    "知识库管理 Agent 提示词",
    KNOWLEDGE_BASE_AGENT_SYSTEM_PROMPT_PATH,
)

DB_LOCK = threading.Lock()
WAF_TEST_LOCK = threading.Lock()
# 检验 worker 池协调原语：空闲等待通知 + 停机信号。
VERIFICATION_WAKE = threading.Condition()
VERIFICATION_STOP_EVENT = threading.Event()
VERIFICATION_POOL_STARTED = False
VERIFICATION_POOL_LOCK = threading.Lock()
VERIFICATION_WORKERS: list[threading.Thread] = []
LOGGER = logging.getLogger("wafbypasser.api")
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
_MISSING = object()

VULNERABILITIES: set[str] = {
    "command-injection",
    "file-upload",
    "sql-injection",
    "log4j",
    "xss",
}
CANDIDATE_STATUSES: set[str] = {"pending_test", "test_success", "test_failed", "rejected", "archived"}
PAYLOAD_SEVERITIES: set[str] = {"低危", "中危", "高危", "严重"}


def payload_internal_name(content: str) -> str:
    """Return a stable internal label without requiring a user-supplied name."""
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
    return f"Payload · {digest}"


class IterationPoolAddRequest(BaseModel):
    source_payload_id: str = Field(min_length=1)


class WafTestRequest(BaseModel):
    agent: Literal["semantic", "encoding", "cross"]
    candidate_id: str = Field(min_length=1)


class CandidateUpdateRequest(BaseModel):
    status: str = Field(min_length=1)
    test_note: str | None = None


class IterationPoolStartRequest(BaseModel):
    pass


class SemanticIterationRequest(BaseModel):
    base_payload_id: str = Field(min_length=1)


class EncodingIterationRequest(BaseModel):
    base_payload_id: str = Field(min_length=1)


class CrossIterationRequest(BaseModel):
    cross_source_id: str = Field(min_length=1)


class CrossPoolAddRequest(BaseModel):
    cross_source_id: str = Field(min_length=1)


class ExhaustionIterationRequest(BaseModel):
    base_payload_id: str = Field(min_length=1)


class GeneralizationRequest(BaseModel):
    vulnerability: str = Field(min_length=1)
    candidate_count: int = Field(default=8, ge=1, le=20)
    textbook: str = Field(default="")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def start_background_thread(target: Any, *args: Any) -> None:
    threading.Thread(target=target, args=args, daemon=True).start()


def _llm_config(prefix: str, provider_default: str) -> dict[str, str]:
    """Read one OpenAI-compatible LLM configuration from the environment."""
    return {
        "base_url": os.getenv(f"{prefix}_BASEURL", "").strip().rstrip("/"),
        "api_key": os.getenv(f"{prefix}_APIKEY", "").strip(),
        "model": os.getenv(f"{prefix}_MODEL", "").strip(),
        "provider": os.getenv(f"{prefix}_PROVIDER", provider_default).strip() or provider_default,
        "source": prefix,
    }


def _llm_config_complete(config: dict[str, str]) -> bool:
    return all(config.get(key, "").strip() for key in ("base_url", "api_key", "model"))


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _env_positive_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = int(value.strip())
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def model_config() -> dict[str, str]:
    load_dotenv(CONFIG_PATH)
    return _llm_config("LLM", "OpenAI-compatible")


def semantic_model_config() -> dict[str, str]:
    """Resolve the LLM provider for both the semantic and encoding agents.

    两个迭代 Agent 统一使用 `LLM_*` 配置（最初的通用 LLM 配置）。
    """
    return model_config()


def strip_json_fence(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.I)
        stripped = re.sub(r"\s*```$", "", stripped)
    return stripped.strip()


def _extract_json_payload(message: str) -> Any:
    """Best-effort salvage of a JSON object/array from a model response.

    The model occasionally wraps its answer in prose or emits an unterminated
    trailing string.  We try a direct parse first, then attempt to locate the
    outermost {...} / [...] block, then a light trailing-comma cleanup.
    Returns the parsed value or None when nothing usable can be recovered.
    """
    stripped = strip_json_fence(message or "")
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    for open_ch, close_ch in (("{", "}"), ("[", "]")):
        start = stripped.find(open_ch)
        end = stripped.rfind(close_ch)
        if start != -1 and end > start:
            snippet = stripped[start : end + 1]
            try:
                return json.loads(snippet)
            except json.JSONDecodeError:
                # Strip trailing commas that break strict JSON
                cleaned = re.sub(r",(\s*[}\]])", r"\1", snippet)
                try:
                    return json.loads(cleaned)
                except json.JSONDecodeError:
                    continue
    return None


def _chat_completion_endpoint(base_url: str) -> str:
    endpoint = base_url.rstrip("/")
    if not endpoint.endswith("/chat/completions"):
        endpoint += "/chat/completions"
    return endpoint


def _post_chat_completion(config: dict[str, str], messages: list[dict[str, str]]) -> httpx.Response:
    return httpx.post(
        _chat_completion_endpoint(config["base_url"]),
        headers={"Authorization": f"Bearer {config['api_key']}"},
        json={"model": config["model"], "messages": messages, "temperature": 0.6},
        timeout=180,
    )


def _post_semantic_batch(
    config: dict[str, str],
    messages: list[dict[str, str]],
    batch_number: int,
) -> httpx.Response:
    max_retries = _env_positive_int("SEMANTIC_LLM_MAX_RETRIES", 2)
    for attempt in range(max_retries + 1):
        try:
            response = _post_chat_completion(config, messages)
        except httpx.TransportError:
            if attempt >= max_retries:
                raise
            LOGGER.warning(
                "Semantic LLM batch %s transport failure; retrying (%s/%s)",
                batch_number,
                attempt + 1,
                max_retries,
            )
            time.sleep(min(2 ** attempt, 4))
            continue
        if response.status_code < 500 or attempt >= max_retries:
            return response
        LOGGER.warning(
            "Semantic LLM batch %s returned HTTP %s; retrying (%s/%s)",
            batch_number,
            response.status_code,
            attempt + 1,
            max_retries,
        )
        time.sleep(min(2 ** attempt, 4))
    raise RuntimeError("Semantic LLM retry loop ended unexpectedly")


def _response_text(response: Any) -> str:
    try:
        return str(response.text or "")
    except Exception:
        return ""


def _is_quota_error(response: Any) -> bool:
    """Recognize explicit quota exhaustion without treating every 429 as quota."""
    try:
        status = int(response.status_code)
    except (TypeError, ValueError, AttributeError):
        return False
    if status not in {402, 429}:
        return False
    body = _response_text(response).casefold()
    return any(
        marker in body
        for marker in (
            "insufficient_quota",
            "quota exceeded",
            "quota exhausted",
            "quota limit",
            "insufficient balance",
            "余额不足",
            "额度不足",
            "配额不足",
        )
    )


def _same_llm_config(left: dict[str, str], right: dict[str, str]) -> bool:
    return all(left.get(key, "") == right.get(key, "") for key in ("base_url", "api_key", "model"))


def call_model(
    payload: dict[str, Any],
    rule_hints: list[str],
    candidate_count: int,
    direction_context_: dict[str, Any] | None = None,
    techniques: list[dict[str, Any]] | None = None,
    per_batch: Callable[[int, int, list[dict[str, Any]], int], None] | None = None,
) -> list[dict[str, Any]]:
    config = semantic_model_config()
    if not _llm_config_complete(config):
        raise RuntimeError("Semantic LLM configuration is incomplete; check config/.env")
    batch_size = min(
        candidate_count,
        _env_positive_int("SEMANTIC_LLM_BATCH_SIZE", 10),
    )
    all_candidates: list[dict[str, Any]] = []

    for offset in range(0, candidate_count, batch_size):
        current_count = min(batch_size, candidate_count - offset)
        batch_context = dict(direction_context_ or {})
        directions = list(batch_context.get("available_directions", []))
        if directions:
            shift = offset % len(directions)
            batch_context["available_directions"] = directions[shift:] + directions[:shift]
        batch_hints = list(rule_hints)
        if batch_hints:
            shift = offset % len(batch_hints)
            batch_hints = batch_hints[shift:] + batch_hints[:shift]
        batch_techniques = (techniques or [])[offset:offset + current_count]

        messages = [
            {
                "role": "system",
                "content": build_system_prompt(current_count, payload["vulnerability"]),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "base_payload": payload["content"],
                        "vulnerability": payload["vulnerability"],
                        "category": payload["category"],
                        "delivery": payload["delivery"],
                        "target": payload["target"],
                        "rule_hints": batch_hints,
                        "direction_context": batch_context,
                        "techniques": batch_techniques,
                        "candidate_count": current_count,
                        "output_requirement": f"Return exactly {current_count} candidates.",
                    },
                    ensure_ascii=False,
                ),
            },
        ]
        batch_number = offset // batch_size + 1
        response = _post_semantic_batch(config, messages, batch_number)
        if (
            _is_quota_error(response)
            and config.get("source") == "SEMANTIC_LLM"
            and _env_bool("SEMANTIC_LLM_ALLOW_FALLBACK", True)
        ):
            legacy = model_config()
            if _llm_config_complete(legacy) and not _same_llm_config(config, legacy):
                LOGGER.warning("Semantic LLM quota exhausted; retrying once with legacy LLM provider")
                try:
                    response = _post_chat_completion(legacy, messages)
                except Exception as fallback_error:
                    raise RuntimeError(
                        f"Semantic LLM quota exhausted and legacy LLM fallback failed: {fallback_error}"
                    ) from fallback_error
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as error:
            body = _response_text(response).strip()
            preview = body[:1000] if body else "<empty response>"
            raise RuntimeError(
                f"Semantic LLM batch {batch_number} failed with HTTP "
                f"{response.status_code}: {preview}"
            ) from error
        message = response.json()["choices"][0]["message"]["content"] or ""

        decoded = _extract_json_payload(message)
        if decoded is None:
            preview = (message[:500] + "…") if len(message) > 500 else message
            raise ValueError(
                f"模型返回的内容无法解析为JSON\n预览: {preview or '<空响应>'}"
            )

        if isinstance(decoded, dict):
            candidates = decoded.get("candidates")
            if candidates is None:
                candidates = [decoded] if decoded.get("part_operations") else None
        else:
            candidates = decoded

        if not isinstance(candidates, list):
            raise ValueError("模型响应中未找到 candidates 数组")

        valid_candidates = [c for c in candidates if isinstance(c, dict)]
        if not valid_candidates:
            raise ValueError("模型返回的候选均无效（非对象格式）")
        batch_candidates = valid_candidates[:current_count]
        all_candidates.extend(batch_candidates)
        if per_batch is not None:
            per_batch(offset, current_count, batch_candidates, batch_number)

    return all_candidates[:candidate_count]


def _existing_candidate_contents(vulnerability: str, base_payload_id: str) -> set[str]:
    """Contents already generated (any status) for cross-task dedupe.

    We look up both same-base-payload candidates AND any candidate produced from
    a sibling seed with the same vulnerability + target so that different seeds
    do not converge on the same trivial mutation.
    """
    rows_same_base = db_rows(
        "SELECT content FROM candidates WHERE base_payload_id = ?",
        (base_payload_id,),
    )
    rows_same_vuln = db_rows(
        """
        SELECT c.content FROM candidates c
        JOIN payloads p ON p.id = c.base_payload_id
        WHERE p.vulnerability = ?
        """,
        (vulnerability,),
    )
    return (
        {row["content"] for row in rows_same_base if row["content"]}
        | {row["content"] for row in rows_same_vuln if row["content"]}
    )


# --- SQL-specific attack-signature detection ------------------------------
# A generated SQL-injection payload must contain at least one of these markers
# to be considered a real attack vector (not a harmless placeholder string).
_SQL_ATTACK_SIGNATURES = re.compile(
    r"("
    r"\bSELECT\b|\bUNION\b|\bFROM\b|\bWHERE\b|\bORDER\s+BY\b|\bGROUP\s+BY\b|\bHAVING\b"
    r"|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bCREATE\b|\bALTER\b|\bEXEC\b"
    r"|\bCASE\b|\bWHEN\b|\bEXISTS\b|\bBETWEEN\b|\bLIKE\b|\bREGEXP\b|\bRLIKE\b|\bIN\b|\bIS\b"
    r"|\bOR\b|\bAND\b|\bXOR\b|\bNOT\b|\|\||&&"
    r"|\bSLEEP\b|\bBENCHMARK\b|\bGET_LOCK\b|\bpg_sleep\b|\bWAITFOR\b"
    r"|\bUpdateXML\b|\bExtractValue\b|\bGTID_SUBSET\b|\bFLOOR\b|\bEXP\b"
    r"|\bdatabase\b|\bschema\b|\bversion\b|\buser\b|\bcurrent_user\b"
    r"|\bCONCAT\b|\bCONCAT_WS\b|\bSUBSTRING\b|\bSUBSTR\b|\bMID\b"
    r"|\bCHAR\b|\bHEX\b|\bUNHEX\b|\bASCII\b|\bORD\b|\bCAST\b|\bCONVERT\b"
    r"|\bLOAD_FILE\b|\bINTO\s+OUTFILE\b|\bINTO\s+DUMPFILE\b"
    r"|--\s|--$|/\*|\*/|;%00|#\s|@@|0x[0-9a-fA-F]{2,}"
    r"|[<>!]=|<=>|<>"
    r")",
    re.IGNORECASE,
)


def _has_sql_attack_signature(content: str) -> bool:
    """Return True iff the payload carries at least one real SQL attack marker."""
    if not content:
        return False
    return bool(_SQL_ATTACK_SIGNATURES.search(content))


def _sql_url_path_unsafe(content: str) -> str:
    """Return a rejection reason if the payload violates URL-path delivery rules.

    Under Tencent WAF direct testing the payload is placed into the URL path
    after the leading slash. In this context:
      - `#` starts a URL fragment; the server never sees anything after it.
        This makes MySQL single-line-comment `#` non-functional for the WAF.
      - a naked `?` starts the query string, splitting the payload.
      - a naked `/` is a path segment separator; safe only inside `/*...*/`.
    """
    if not content:
        return ""
    # Reject payloads whose sole terminator is `#` (WAF never sees the rest).
    tail = content.rstrip()
    if tail.endswith("#"):
        return "URL 路径投递下 `#` 会被浏览器/发送器视为片段起始，注释在服务端不生效；请改用 `-- -`, `/**/`, `;%00`"
    if "?" in content and "%3f" not in content.lower():
        return "URL 路径投递下 `?` 会开启 query string，切断 payload"
    return ""


def _sql_signature_set(content: str) -> frozenset[str]:
    """A rough SQL-mutation fingerprint used to reject trivially-similar candidates.

    Two payloads with identical uppercase-alphanumeric skeletons (letters+digits
    only, ordered) are considered "trivially similar" — differing only in
    whitespace, punctuation, or case.
    """
    skel = re.sub(r"[^A-Za-z0-9]+", " ", content or "").upper().split()
    return frozenset(skel)


def semantic_task_context(payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    parsed = parse_semantic_parts(
        payload["content"], payload["vulnerability"], payload["delivery"]
    )
    if parsed.get("status") != "supported":
        raise HTTPException(
            status_code=422,
            detail=parsed.get("unsupported_reason") or "This Payload cannot be parsed by the semantic agent",
        )
    metadata = json_value(payload.get("iteration_metadata_json"), {})
    used = set(metadata.get("used_direction_ids", []))
    directions = [
        item
        for item in semantic_part_directions(parsed["parts"], payload["vulnerability"])
        if item["id"] not in used
    ]

    # Cross-task duplicate awareness: give the LLM a preview of already-generated
    # contents (truncated) so it can steer away from them. The backend still
    # rejects duplicates deterministically after generation.
    existing = _existing_candidate_contents(payload["vulnerability"], payload["id"])
    # Keep the preview bounded to avoid blowing up the prompt context.
    existing_preview = sorted(existing)[:80]

    context = {
        "base_parts": parsed["parts"],
        "available_directions": directions,
        "used_direction_ids": sorted(used),
        "ancestor_content_fingerprints": metadata.get("content_fingerprints", []),
        "existing_candidate_contents": existing_preview,
        "existing_candidate_count": len(existing),
    }
    return parsed, context


def run_semantic_generation(task_id: str) -> None:
    delivered_count = 0
    try:
        with DB_LOCK:
            connection = sqlite3.connect(DB_PATH)
            connection.row_factory = sqlite3.Row
            task_record = connection.execute(
                "SELECT * FROM generation_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if not task_record:
                connection.close()
                return
            task = dict(task_record)
            payload_record = connection.execute(
                "SELECT * FROM payloads WHERE id = ?", (task["base_payload_id"],)
            ).fetchone()
            payload = dict(payload_record)
            connection.execute(
                "UPDATE generation_tasks SET status = 'running' WHERE id = ?", (task_id,)
            )
            connection.commit()
            connection.close()

        context = json_value(task.get("direction_context_json"), {})
        base_parts = context.get("base_parts", [])
        available = context.get("available_directions", [])
        available_ids = {item["id"] for item in available}
        # 知识库手法为主：按漏洞类型 + semantic 组筛选，去掉已用，一次性全量遍历。
        metadata = json_value(payload.get("iteration_metadata_json"), {})
        used_technique_ids = set(metadata.get("used_technique_ids", []))
        kb_techniques = [
            t for t in _select_techniques(
                payload["vulnerability"], "semantic",
                content=payload.get("content", ""), category=payload.get("category", ""),
            )
            if t["technique_id"] not in used_technique_ids
        ]
        techniques = kb_techniques or None
        target_count = len(kb_techniques)
        if target_count == 0:
            # 空库：无手法可遍历，直接完成（0 候选），不再回退默认条数。
            timestamp = utc_now()
            with DB_LOCK:
                connection = connect()
                try:
                    connection.execute(
                        "UPDATE generation_tasks SET status = 'completed', completed_at = ?, error_message = NULL WHERE id = ?",
                        (timestamp, task_id),
                    )
                    connection.commit()
                finally:
                    connection.close()
            return

        # Existing content pool (this base + siblings) — used for cross-task dedupe.
        existing_contents = _existing_candidate_contents(
            payload["vulnerability"], payload["id"]
        )
        existing_signatures = {_sql_signature_set(c) for c in existing_contents}
        base_signature = _sql_signature_set(payload["content"])
        seen_contents: set[str] = set()
        seen_signatures: set[frozenset[str]] = set()
        skipped_reasons: list[str] = []
        fallback_direction_id = available[0]["id"] if available else ""

        def process_batch(batch_raw: list[dict[str, Any]], offset: int) -> int:
            """校验并落库一批候选，返回该批实际入队数。"""
            nonlocal delivered_count
            batch_candidates: list[dict[str, Any]] = []
            for i, raw in enumerate(batch_raw, start=offset):
                label = f"候选#{i + 1}"
                try:
                    if not isinstance(raw, dict):
                        skipped_reasons.append(f"{label}：不是 JSON 对象，跳过")
                        continue
                    operations = raw.get("part_operations")
                    if not isinstance(operations, list) or not operations:
                        skipped_reasons.append(f"{label}：缺少 part_operations，跳过")
                        continue
                    errors = validate_semantic_parts(operations, base_parts, payload["vulnerability"])
                    if errors:
                        skipped_reasons.append(f"{label}：{'; '.join(errors)}")
                        continue
                    candidate_parts = apply_part_operations(
                        base_parts, operations, payload["vulnerability"]
                    )
                    content = recompose_semantic_parts(candidate_parts)
                    if not content:
                        skipped_reasons.append(f"{label}：重组结果为空，跳过")
                        continue

                    # Reject payloads starting with newline
                    if content.startswith('\n') or content.startswith('%0a') or content.startswith('%0A'):
                        skipped_reasons.append(f"{label}：payload 以换行符开头，URL 编码时会产生问题")
                        continue

                    if content == payload["content"]:
                        skipped_reasons.append(f"{label}：内容与原 Payload 一致，跳过")
                        continue
                    if content in seen_contents:
                        skipped_reasons.append(f"{label}：与本轮已生成候选重复，跳过")
                        continue

                    # Cross-task duplication: reject payloads already present in DB
                    if content in existing_contents:
                        skipped_reasons.append(
                            f"{label}：与历史候选重复（跨任务），跳过"
                        )
                        continue

                    # Trivial-similarity signature check (same alnum skeleton = trivial variant)
                    sig = _sql_signature_set(content)
                    if sig and sig == base_signature:
                        skipped_reasons.append(
                            f"{label}：与基础 payload 语义骨架完全相同（仅空白/大小写差异），跳过"
                        )
                        continue
                    if sig and (sig in seen_signatures or sig in existing_signatures):
                        skipped_reasons.append(
                            f"{label}：与已有候选语义骨架重复（仅表面差异），跳过"
                        )
                        continue

                    # SQL-specific: content must carry a real attack signature.
                    if payload["vulnerability"] == "sql-injection":
                        if not _has_sql_attack_signature(content):
                            skipped_reasons.append(
                                f"{label}：payload 缺少 SQL 攻击特征（关键字/运算符/函数/注释），"
                                f"疑似无害占位串，跳过"
                            )
                            continue
                        url_path_issue = _sql_url_path_unsafe(content)
                        if url_path_issue:
                            skipped_reasons.append(f"{label}：{url_path_issue}")
                            continue

                    seen_contents.add(content)
                    if sig:
                        seen_signatures.add(sig)

                    # Filter out harmless marker-only payloads
                    harmless_marker_pattern = re.compile(r'^[A-Z][A-Z0-9_]{2,}_OK\s*$', re.IGNORECASE)
                    if harmless_marker_pattern.match(content.strip()):
                        skipped_reasons.append(f"{label}：生成的是无害验证标记而非实际攻击 payload")
                        continue

                    raw_direction_ids = raw.get("direction_ids") or []
                    if not isinstance(raw_direction_ids, list):
                        raw_direction_ids = [raw_direction_ids] if raw_direction_ids else []
                    direction_ids = [d for d in raw_direction_ids if d in available_ids]
                    if not direction_ids:
                        if available:
                            direction_ids = [available[i % len(available)]["id"]]
                        elif fallback_direction_id:
                            direction_ids = [fallback_direction_id]

                    delta = compare_semantic_delta(base_parts, candidate_parts)
                    delta["operations"] = operations
                    next_directions = [item for item in available if item["id"] not in direction_ids]
                    # 手法来源：LLM 显式声明优先；否则按遍历顺序映射到第 i 个手法。
                    declared_technique_ids = [
                        tid for tid in (raw.get("technique_ids") or []) if isinstance(tid, str)
                    ]
                    if not declared_technique_ids and kb_techniques and i < len(kb_techniques):
                        declared_technique_ids = [kb_techniques[i]["technique_id"]]
                    batch_candidates.append(
                        {
                            "content": content,
                            "direction_ids": direction_ids,
                            "rule_labels": raw.get("rule_labels") or direction_ids,
                            "explanation": raw.get("explanation") or delta.get("summary", ""),
                            "confidence": float(raw.get("confidence", 0.7)),
                            "operations": operations,
                            "candidate_parts": candidate_parts,
                            "delta": delta,
                            "next_directions": next_directions[:6],
                            "verification_spec": raw.get("verification_spec"),
                            "execution_goal_id": normalize_execution_goal_id(
                                raw.get("execution_goal_id") or ""
                            ),
                            "technique_ids": declared_technique_ids,
                        }
                    )
                except Exception as candidate_error:
                    skipped_reasons.append(f"{label}：处理异常 - {candidate_error}")
                    continue

            if batch_candidates:
                timestamp = utc_now()
                with DB_LOCK:
                    connection = sqlite3.connect(DB_PATH)
                    try:
                        for candidate in batch_candidates:
                            candidate_id = str(uuid.uuid4())
                            connection.execute(
                                """
                                INSERT INTO candidates (
                                    id, task_id, base_payload_id, content, delivery, rule_labels_json,
                                    explanation, confidence, status, test_note, created_at, updated_at,
                                    used_direction_ids_json, next_directions_json, execution_goal_id,
                                    semantic_dimension_ids_json, semantic_delta_json, verification_spec_json,
                                    base_parts_json, candidate_parts_json, part_operations_json,
                                    parser_confidence, parser_status, unsupported_reason, technique_ids_json
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending_test', NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    candidate_id, task_id, payload["id"], candidate["content"],
                                    payload["delivery"], json.dumps(candidate["rule_labels"], ensure_ascii=False),
                                    candidate["explanation"], candidate["confidence"], timestamp, timestamp,
                                    json.dumps(candidate["direction_ids"], ensure_ascii=False),
                                    json.dumps(candidate["next_directions"], ensure_ascii=False),
                                    candidate["execution_goal_id"],
                                    json.dumps(candidate["direction_ids"], ensure_ascii=False),
                                    json.dumps(candidate["delta"], ensure_ascii=False),
                                    json.dumps(candidate["verification_spec"], ensure_ascii=False) if candidate["verification_spec"] is not None else None,
                                    json.dumps(base_parts, ensure_ascii=False),
                                    json.dumps(candidate["candidate_parts"], ensure_ascii=False),
                                    json.dumps(candidate["operations"], ensure_ascii=False),
                                    task.get("parser_confidence", 0), task.get("parser_status", "supported"),
                                    task.get("unsupported_reason"),
                                    json.dumps(candidate.get("technique_ids", []), ensure_ascii=False),
                                ),
                            )
                            # 自动路由到检验 Agent
                            enqueue_verification(
                                connection,
                                "semantic",
                                candidate_id,
                                "candidates",
                                payload,
                                candidate["content"],
                                payload["delivery"],
                                execution_goal_id=candidate["execution_goal_id"],
                                verification_spec=candidate["verification_spec"],
                                technique_ids=candidate.get("technique_ids", []),
                            )
                        _feed_verification_queue(connection)
                        connection.commit()
                    finally:
                        connection.close()
                _wake_verification_workers()
            delivered_count += len(batch_candidates)
            return len(batch_candidates)

        callback_invoked = [False]

        def per_batch(offset: int, current_count: int, batch_raw: list[dict[str, Any]], batch_number: int) -> None:
            callback_invoked[0] = True
            process_batch(batch_raw, offset)

        raw_candidates = call_model(
            payload,
            json_value(task.get("rule_hints_json"), []),
            target_count,
            context,
            techniques=techniques,
            per_batch=per_batch,
        )
        # 兜底：call_model 被 mock / 未触发回调时，用全量结果单次落库（保持原语义）。
        if not callback_invoked[0]:
            process_batch(raw_candidates, 0)

        if delivered_count == 0:
            reason_detail = "; ".join(skipped_reasons[:5]) if skipped_reasons else "无有效候选"
            raise ValueError(f"所有候选均处理失败：{reason_detail}")

        warning_message: str | None = None
        if skipped_reasons:
            preview = "; ".join(skipped_reasons[:3])
            if len(skipped_reasons) > 3:
                preview += f"; ...（共 {len(skipped_reasons)} 条被跳过）"
            warning_message = f"{delivered_count} 个候选入队；{len(skipped_reasons)} 个被跳过：{preview}"

        timestamp = utc_now()
        with DB_LOCK:
            connection = sqlite3.connect(DB_PATH)
            try:
                if warning_message:
                    connection.execute(
                        "UPDATE generation_tasks SET status = 'completed', completed_at = ?, error_message = ? WHERE id = ?",
                        (timestamp, warning_message[:1000], task_id),
                    )
                else:
                    connection.execute(
                        "UPDATE generation_tasks SET status = 'completed', completed_at = ?, error_message = NULL WHERE id = ?",
                        (timestamp, task_id),
                    )
                connection.commit()
            finally:
                connection.close()
        # 语义迭代收尾：自动触发泛化，从已验证技法泛化新技法（frontier）
        _trigger_generalization(payload["vulnerability"])
    except Exception as error:
        with DB_LOCK:
            connection = sqlite3.connect(DB_PATH)
            detail = str(error)[:1000]
            if delivered_count:
                detail = f"（已落库 {delivered_count} 条候选后失败）{detail}"
            connection.execute(
                "UPDATE generation_tasks SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?",
                (detail, utc_now(), task_id),
            )
            connection.execute(
                "UPDATE iteration_pool_items SET status = 'pending' WHERE task_id = ?",
                (task_id,),
            )
            connection.commit()
            connection.close()


def call_encoding_model(
    payload: dict[str, Any],
    candidate_count: int,
    direction_context_: dict[str, Any] | None = None,
    techniques: list[dict[str, Any]] | None = None,
    per_batch: Callable[[int, int, list[dict[str, Any]], int], None] | None = None,
) -> list[dict[str, Any]]:
    """Call the LLM to produce `candidate_count` encoding candidates.

    Uses the same provider resolution as the semantic agent (dedicated
    provider first, then legacy fallback). Returned candidates are validated
    against the 28-encoding catalog in `run_encoding_generation`.
    """
    config = semantic_model_config()
    if not _llm_config_complete(config):
        raise RuntimeError("Semantic LLM configuration is incomplete; check config/.env")

    allowed = allowed_encoding_catalog(payload["vulnerability"], payload["content"])
    batch_size = min(
        candidate_count,
        _env_positive_int("SEMANTIC_LLM_BATCH_SIZE", 10),
    )
    all_candidates: list[dict[str, Any]] = []
    tech_list = techniques or []

    for offset in range(0, candidate_count, batch_size):
        current_count = min(batch_size, candidate_count - offset)
        batch_techniques = tech_list[offset:offset + current_count]
        system_prompt = build_encoding_system_prompt(current_count)
        user_body = {
            "base_payload": payload["content"],
            "vulnerability": payload["vulnerability"],
            "category": payload.get("category", ""),
            "delivery": payload.get("delivery", ""),
            "target": payload.get("target", ""),
            "allowed_encodings": allowed,
            "direction_context": direction_context_ or {},
            "techniques": batch_techniques,
            "candidate_count": current_count,
            "output_requirement": f"Return exactly {current_count} candidates.",
        }
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_body, ensure_ascii=False)},
        ]

        response = _post_chat_completion(config, messages)
        if (
            _is_quota_error(response)
            and config.get("source") == "SEMANTIC_LLM"
            and _env_bool("SEMANTIC_LLM_ALLOW_FALLBACK", True)
        ):
            legacy = model_config()
            if _llm_config_complete(legacy) and not _same_llm_config(config, legacy):
                LOGGER.warning("Semantic LLM quota exhausted; retrying once with legacy LLM provider")
                response = _post_chat_completion(legacy, messages)

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as error:
            body = _response_text(response).strip()
            preview = body[:1000] if body else "<empty response>"
            raise RuntimeError(
                f"Encoding LLM failed with HTTP {response.status_code}: {preview}"
            ) from error

        message = response.json()["choices"][0]["message"]["content"] or ""
        decoded = _extract_json_payload(message)
        if decoded is None:
            preview = (message[:500] + "…") if len(message) > 500 else message
            raise ValueError(f"模型返回的内容无法解析为JSON\n预览: {preview or '<空响应>'}")

        if isinstance(decoded, dict):
            candidates = decoded.get("candidates")
        else:
            candidates = decoded
        if not isinstance(candidates, list):
            raise ValueError("模型响应中未找到 candidates 数组")

        valid_candidates = [c for c in candidates if isinstance(c, dict)]
        if not valid_candidates:
            raise ValueError("模型返回的候选均无效（非对象格式）")
        batch_candidates = valid_candidates[:current_count]
        all_candidates.extend(batch_candidates)
        if per_batch is not None:
            per_batch(offset, current_count, batch_candidates, offset // batch_size + 1)

    return all_candidates[:candidate_count]


# ---------------------------------------------------------------------------
# 穷举生成：一条原语 × 剪枝后的技法，逐技法产出一个变体（命中 200 不停）。
# ---------------------------------------------------------------------------

_EXHAUSTION_BATCH_SIZE = 15


def _exhaustion_llm(
    base_content: str,
    vulnerability: str,
    techniques: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """分批调用 LLM，为每个技法产出一个变体。返回 [{technique_id, content, explanation}]。"""
    config = semantic_model_config()
    if not _llm_config_complete(config):
        raise RuntimeError("Semantic LLM configuration is incomplete; check config/.env")

    results: list[dict[str, Any]] = []
    for offset in range(0, len(techniques), _EXHAUSTION_BATCH_SIZE):
        batch = techniques[offset : offset + _EXHAUSTION_BATCH_SIZE]
        messages = [
            {"role": "system", "content": EXHAUSTION_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": build_exhaustion_user_message(base_content, vulnerability, batch),
            },
        ]
        response = _post_semantic_batch(config, messages, offset // _EXHAUSTION_BATCH_SIZE + 1)
        response.raise_for_status()
        raw_message = response.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        decoded = _extract_json_payload(raw_message)
        if isinstance(decoded, dict):
            decoded = decoded.get("candidates")
        if not isinstance(decoded, list):
            raise ValueError("穷举生成响应中未找到 candidates 数组")
        results.extend([c for c in decoded if isinstance(c, dict)])

    # 按技法 id 对齐：只保留输入技法对应的变体，去重
    by_tech: dict[str, dict[str, Any]] = {}
    for r in results:
        tid = str(r.get("technique_id") or "").strip()
        content = str(r.get("content") or "").strip()
        if not tid or not content:
            continue
        if tid not in by_tech:
            by_tech[tid] = {
                "technique_id": tid,
                "content": content,
                "explanation": str(r.get("explanation") or "").strip(),
            }
    return [by_tech[t["technique_id"]] for t in techniques if t["technique_id"] in by_tech]


def run_exhaustion_generation(task_id: str) -> None:
    """Background task：剪枝 → 逐技法生成变体 → 落 candidates → 自动验证。"""
    try:
        with DB_LOCK:
            connection = connect()
            task_record = connection.execute(
                "SELECT * FROM exhaustion_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if not task_record:
                connection.close()
                return
            task = dict(task_record)
            payload_record = connection.execute(
                "SELECT * FROM payloads WHERE id = ?", (task["base_payload_id"],)
            ).fetchone()
            if not payload_record:
                connection.execute(
                    "UPDATE exhaustion_tasks SET status='failed', error_message='Base Payload not found', completed_at=? WHERE id=?",
                    (utc_now(), task_id),
                )
                connection.commit()
                connection.close()
                return
            payload = dict(payload_record)
            connection.execute(
                "UPDATE exhaustion_tasks SET status='running', provider=?, model=? WHERE id=?",
                (semantic_model_config().get("provider"), semantic_model_config().get("model"), task_id),
            )
            connection.commit()
            connection.close()

        vulnerability = payload["vulnerability"]
        primitive_backend = infer_backend_from_primitive(payload["content"], vulnerability)

        with DB_LOCK:
            connection = connect()
            techniques = prune_techniques_for_exhaustion(
                connection, vulnerability, primitive_backend
            )
            connection.close()

        if not techniques:
            raise ValueError("剪枝后无可用技法")

        generated = _exhaustion_llm(payload["content"], vulnerability, techniques)

        # 落 candidates（复用语义候选表，rule_labels 记技法 id）
        timestamp = utc_now()
        inserted = 0
        with DB_LOCK:
            connection = connect()
            try:
                for g in generated:
                    candidate_id = str(uuid.uuid4())
                    content = g["content"]
                    connection.execute(
                        """
                        INSERT INTO candidates (
                            id, task_id, base_payload_id, content, delivery, rule_labels_json,
                            explanation, confidence, status, test_note, created_at, updated_at,
                            used_direction_ids_json, next_directions_json, semantic_dimension_ids_json,
                            semantic_delta_json, base_parts_json, candidate_parts_json,
                            part_operations_json, parser_confidence, parser_status, technique_ids_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0.8, 'pending_test', NULL, ?, ?, '[]', '[]', ?, '{}', '[]', '[]', '[]', '0', 'supported', ?)
                        """,
                        (
                            candidate_id, task_id, payload["id"], content,
                            payload["delivery"],
                            json.dumps([g["technique_id"]], ensure_ascii=False),
                            g["explanation"], timestamp, timestamp,
                            json.dumps([g["technique_id"]], ensure_ascii=False),
                            json.dumps([g["technique_id"]], ensure_ascii=False),
                        ),
                    )
                    enqueue_verification(
                        connection, "semantic", candidate_id, "candidates",
                        payload, content, payload["delivery"],
                        technique_ids=[g["technique_id"]],
                    )
                    inserted += 1
                connection.execute(
                    "UPDATE exhaustion_tasks SET status='completed', completed_at=?, technique_count=? WHERE id=?",
                    (utc_now(), inserted, task_id),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        # 触发验证 worker 消费刚入队的任务
        _start_verification_pool()
        # 穷举收尾：自动触发泛化，从已验证技法泛化新技法（frontier）
        _trigger_generalization(payload["vulnerability"])
    except Exception as exc:
        LOGGER.exception("exhaustion generation failed task=%s", task_id)
        with DB_LOCK:
            connection = connect()
            connection.execute(
                "UPDATE exhaustion_tasks SET status='failed', error_message=?, completed_at=? WHERE id=?",
                (str(exc)[:1000], utc_now(), task_id),
            )
            connection.commit()
            connection.close()


# ---------------------------------------------------------------------------
# 泛化引擎：从已有技法 + 绕过率（+ 教材）泛化新技法（frontier）。
# ---------------------------------------------------------------------------

def _fuel_techniques(connection: sqlite3.Connection, vulnerability: str, limit: int = 50) -> list[dict[str, Any]]:
    """取泛化燃料：该漏洞类型下所有活跃技法，含绕过率，按 bypass_count 降序。"""
    rows = connection.execute(
        """
        SELECT technique_id, name, vulnerability, mechanism_id, family_id,
               backend, source_note, bypass_count, attempt_count
        FROM kb_techniques
        WHERE vulnerability = ? AND status != 'retired'
        ORDER BY bypass_count DESC, attempt_count DESC
        LIMIT ?
        """,
        (vulnerability, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def _recent_textbook(connection: sqlite3.Connection, limit: int = 3) -> str:
    """读取最近的教材文章（用于拓新子任务燃料）。"""
    rows = connection.execute(
        "SELECT source_name FROM textbook_notes ORDER BY created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    notes_dir = PROJECT_ROOT / "data" / "knowledge_base" / "notes"
    chunks: list[str] = []
    for r in rows:
        safe = r["source_name"].replace("/", "_").replace("\\", "_")
        path = notes_dir / safe
        if path.exists():
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n\n".join(chunks)


def _existing_signatures(connection: sqlite3.Connection) -> set[tuple[str, str, str]]:
    """已有技法的 L1 签名集合（机制+族+模板骨架）。"""
    from app.knowledge_base_agent.generalization import _template_signature

    sigs: set[tuple[str, str, str]] = set()
    rows = connection.execute(
        "SELECT technique_id, mechanism_id, family_id FROM kb_techniques"
    ).fetchall()
    for r in rows:
        tpl_rows = connection.execute(
            "SELECT payload FROM technique_templates WHERE technique_id = ? LIMIT 1",
            (r["technique_id"],),
        ).fetchall()
        for tpl in tpl_rows:
            sigs.add((r["mechanism_id"] or "", r["family_id"] or "", _template_signature(tpl["payload"])))
    return sigs


def _persist_generalized_techniques(
    connection: sqlite3.Connection,
    candidates: list[dict[str, Any]],
    vulnerability: str,
    existing_sigs: set[tuple[str, str, str]],
    origin: str,
) -> tuple[int, int]:
    """落库泛化/拓新候选技法（frontier），含 L1 去重与新 family/mechanism 自动注册。

    返回 (generated, deduped)。
    """
    timestamp = utc_now()
    generated = 0
    deduped = 0
    for c in candidates:
        tid = str(c.get("technique_id") or "").strip()
        name = str(c.get("name") or "").strip()
        vuln = str(c.get("vulnerability") or vulnerability).strip()
        # 归一化漏洞类型：LLM 可能输出 sqli/cmdi 等短名，落库前统一为全名；
        # 无法识别时回退到任务目标漏洞类型。
        normalized_vuln = normalize_vulnerability(vuln)
        if normalized_vuln is None:
            normalized_vuln = vulnerability
        vuln = normalized_vuln
        mech = str(c.get("mechanism_id") or "").strip()
        family = str(c.get("family_id") or "").strip()
        principle = str(c.get("principle") or "").strip()
        template = str(c.get("template") or "").strip()
        novelty = str(c.get("novelty_reason") or "").strip()
        if not tid or not name or not template:
            continue
        # 生成侧预筛：编码层/协议层/死方法 → 拒绝
        ok, reject_reason = prefilter_generated_technique(c)
        if not ok:
            deduped += 1  # 计入「被筛除」计数，与去重共用
            continue
        # 规范化 mechanism/family：LLM 可能填成路径式（父/子），取最后一段
        mech = mech.split("/")[-1].strip()
        family = family.split("/")[-1].strip()
        # L1 签名去重：撞车拒收
        sig = signature_for_candidate({"mechanism_id": mech, "family_id": family, "template": template})
        if sig in existing_sigs:
            deduped += 1
            continue
        existing_sigs.add(sig)
        # 新 family / mechanism 自动注册（拓新会提新 family）
        if family:
            connection.execute(
                "INSERT OR IGNORE INTO families (id, mechanism_id, desc) VALUES (?, ?, ?)",
                (family, mech or "", f"拓新生成：{name}"),
            )
        if mech:
            connection.execute(
                "INSERT OR IGNORE INTO mechanisms (id, name, desc) VALUES (?, ?, ?)",
                (mech, mech, f"拓新生成机制"),
            )
        connection.execute(
            """
            INSERT INTO kb_techniques (
                id, technique_id, name, vulnerability, status, success_count,
                labels_json, source_note, principle, template, created_at, updated_at,
                origin, protected, mechanism_id, family_id, backend,
                version_gate, composable, priority
            ) VALUES (?, ?, ?, ?, 'frontier', 0, '[]', ?, ?, ?, ?, ?, ?, 0, ?, ?, 'generic', '', 0, 3)
            ON CONFLICT(technique_id) DO UPDATE SET
                name = excluded.name,
                source_note = excluded.source_note,
                mechanism_id = excluded.mechanism_id,
                family_id = excluded.family_id,
                updated_at = excluded.updated_at
            """,
            (
                str(uuid.uuid4()), tid, name, vuln,
                f"原理：{principle} 新颖性：{novelty}",
                principle, template, timestamp, timestamp,
                origin, mech, family,
            ),
        )
        for tpl in template.split("、"):
            tpl = tpl.strip(" `。")
            if tpl:
                connection.execute(
                    "INSERT INTO technique_templates (technique_id, payload, note) VALUES (?, ?, ?)",
                    (tid, tpl, name),
                )
        connection.execute(
            """
            INSERT INTO kb_technique_events (id, technique_id, event, detail, created_at)
            VALUES (?, ?, 'generate', ?, ?)
            """,
            (str(uuid.uuid4()), tid, novelty, timestamp),
        )
        generated += 1
    return generated, deduped


def _call_generalization_llm(system_prompt: str, user_message: str) -> list[dict[str, Any]]:
    """调用 LLM 生成技法候选列表。"""
    config = semantic_model_config()
    if not _llm_config_complete(config):
        raise RuntimeError("Semantic LLM configuration is incomplete; check config/.env")
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]
    response = _post_semantic_batch(config, messages, 1)
    response.raise_for_status()
    raw_message = response.json().get("choices", [{}])[0].get("message", {}).get("content", "")
    decoded = _extract_json_payload(raw_message)
    if isinstance(decoded, dict):
        decoded = decoded.get("techniques")
    if not isinstance(decoded, list):
        raise ValueError("泛化响应中未找到 techniques 数组")
    return [c for c in decoded if isinstance(c, dict)]


def _trigger_generalization(vulnerability: str) -> None:
    """迭代收尾触发泛化：建 generalization_tasks 记录并起后台线程。

    挂在语义/编码/交叉/穷举生成成功完成之后，作为「学习收尾」自动衔接
    （设计文档 §八：不单设按钮，一轮穷举验证跑完自动泛化）。
    燃料不足（该漏洞类型无活跃技法）时静默跳过，不报错。
    """
    if vulnerability not in VULNERABILITIES:
        return
    with DB_LOCK:
        connection = connect()
        try:
            fuel_count = len(_fuel_techniques(connection, vulnerability))
        finally:
            connection.close()
    if fuel_count == 0:
        return
    config = semantic_model_config()
    task_id = str(uuid.uuid4())
    with DB_LOCK:
        connection = connect()
        try:
            connection.execute(
                """
                INSERT INTO generalization_tasks (
                    id, vulnerability, status, provider, model, fuel_count, created_at
                ) VALUES (?, ?, 'queued', ?, ?, ?, ?)
                """,
                (
                    task_id,
                    vulnerability,
                    config["provider"],
                    config["model"],
                    fuel_count,
                    utc_now(),
                ),
            )
            connection.commit()
        finally:
            connection.close()
    start_background_thread(run_generalization, task_id)


def run_generalization(task_id: str, textbook: str = "") -> None:
    """Background task：挖深(70%) + 拓新(30%) 两个子任务 → L1 去重 → 落 frontier。

    挖深：燃料 = KB 已有技法（含绕过率）+ 特征统计。
    拓新：燃料 = 教材 + LLM 知识兜底（KB 技法仅参考）。
    """
    try:
        with DB_LOCK:
            connection = connect()
            task = connection.execute(
                "SELECT * FROM generalization_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if not task:
                connection.close()
                return
            task = dict(task)
            vulnerability = task["vulnerability"]
            connection.execute(
                "UPDATE generalization_tasks SET status='running', provider=?, model=? WHERE id=?",
                (semantic_model_config().get("provider"), semantic_model_config().get("model"), task_id),
            )
            connection.commit()
            connection.close()

        with DB_LOCK:
            connection = connect()
            fuel = _fuel_techniques(connection, vulnerability)
            existing_sigs = _existing_signatures(connection)
            insights = feature_insights(connection, vulnerability)
            recent_textbook = _recent_textbook(connection) if not textbook.strip() else textbook
            connection.close()

        if not fuel:
            raise ValueError("无泛化燃料（该漏洞类型下无活跃技法）")

        # 70/30 分配：挖深 70%，拓新 30%（各自生成，比例体现在 prompt 要求与落库统计）
        exploit_candidates = _call_generalization_llm(
            EXPLOIT_SYSTEM_PROMPT,
            build_exploit_user_message(vulnerability, fuel, insights),
        )
        pioneer_candidates = _call_generalization_llm(
            PIONEER_SYSTEM_PROMPT,
            build_pioneer_user_message(vulnerability, fuel, recent_textbook),
        )

        with DB_LOCK:
            connection = connect()
            try:
                gen_e, ded_e = _persist_generalized_techniques(
                    connection, exploit_candidates, vulnerability, existing_sigs, "generated"
                )
                gen_p, ded_p = _persist_generalized_techniques(
                    connection, pioneer_candidates, vulnerability, existing_sigs, "generated"
                )
                connection.execute(
                    "UPDATE generalization_tasks SET status='completed', completed_at=?, "
                    "generated_count=?, deduped_count=?, exploit_count=?, pioneer_count=? WHERE id=?",
                    (utc_now(), gen_e + gen_p, ded_e + ded_p, gen_e, gen_p, task_id),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
    except Exception as exc:
        LOGGER.exception("generalization failed task=%s", task_id)
        with DB_LOCK:
            connection = connect()
            connection.execute(
                "UPDATE generalization_tasks SET status='failed', error_message=?, completed_at=? WHERE id=?",
                (str(exc)[:1000], utc_now(), task_id),
            )
            connection.commit()
            connection.close()


def run_encoding_generation(task_id: str) -> None:
    """Background task: generate, validate, and persist encoding candidates."""
    delivered_count = 0
    try:
        with DB_LOCK:
            connection = connect()
            task_record = connection.execute(
                "SELECT * FROM encoding_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if not task_record:
                connection.close()
                return
            task = dict(task_record)
            payload = read_payload(connection, task["base_payload_id"])
            if not payload:
                raise ValueError("Base Payload not found")
            connection.execute(
                "UPDATE encoding_tasks SET status = 'running' WHERE id = ?", (task_id,)
            )
            connection.commit()
            connection.close()

        direction_context = json_value(task.get("direction_context_json"), {})
        # 知识库手法为主：encoding 组，去掉已用，一次性全量遍历。
        metadata = json_value(payload.get("iteration_metadata_json"), {})
        used_technique_ids = set(metadata.get("used_technique_ids", []))
        kb_techniques = [
            t for t in _select_techniques(
                payload["vulnerability"], "encoding",
                content=payload.get("content", ""), category=payload.get("category", ""),
            )
            if t["technique_id"] not in used_technique_ids
        ]
        target_count = len(kb_techniques)
        if target_count == 0:
            # 空库：无手法可遍历，直接完成（0 候选）。
            timestamp = utc_now()
            with DB_LOCK:
                connection = connect()
                try:
                    connection.execute(
                        "UPDATE encoding_tasks SET status = 'completed', completed_at = ?, error_message = NULL WHERE id = ?",
                        (timestamp, task_id),
                    )
                    connection.commit()
                finally:
                    connection.close()
            return
        seen_contents: set[str] = set()

        def process_batch(batch_raw: list[dict[str, Any]], offset: int) -> int:
            """确定性生成并落库一批编码候选，返回该批实际入队数。"""
            nonlocal delivered_count
            batch_candidates: list[dict[str, Any]] = []
            for i, intent in enumerate(batch_raw, start=offset):
                declared_tids = [
                    tid for tid in (intent.get("technique_ids") or []) if isinstance(tid, str)
                ]
                if not declared_tids and kb_techniques and i < len(kb_techniques):
                    declared_tids = [kb_techniques[i]["technique_id"]]
                for candidate in realize_encoding_intent(
                    payload["content"], intent, payload["vulnerability"]
                ):
                    if candidate["content"] in seen_contents:
                        continue
                    seen_contents.add(candidate["content"])
                    candidate["technique_ids"] = declared_tids
                    batch_candidates.append(candidate)

            if batch_candidates:
                timestamp = utc_now()
                with DB_LOCK:
                    connection = connect()
                    try:
                        for candidate in batch_candidates:
                            candidate_id = str(uuid.uuid4())
                            connection.execute(
                                """
                                INSERT INTO encoding_candidates (
                                    id, task_id, base_payload_id, content, delivery,
                                    encoding_chain_json, decode_path_json, rule_labels_json,
                                    explanation, confidence, status, test_note, created_at,
                                    updated_at, origin, used_direction_ids_json,
                                    next_directions_json, technique_ids_json
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_test', NULL, ?, ?, 'generated', '[]', '[]', ?)
                                """,
                                (
                                    candidate_id,
                                    task_id,
                                    payload["id"],
                                    candidate["content"],
                                    payload["delivery"],
                                    json.dumps(candidate["encoding_chain"], ensure_ascii=False),
                                    json.dumps(candidate["decode_path"], ensure_ascii=False),
                                    json.dumps(candidate["rule_labels"], ensure_ascii=False),
                                    candidate["explanation"],
                                    candidate["confidence"],
                                    timestamp,
                                    timestamp,
                                    json.dumps(candidate.get("technique_ids", []), ensure_ascii=False),
                                ),
                            )
                            # 自动路由到检验 Agent
                            enqueue_verification(
                                connection,
                                "encoding",
                                candidate_id,
                                "encoding_candidates",
                                payload,
                                candidate["content"],
                                payload["delivery"],
                                execution_goal_id=None,
                                verification_spec=None,
                                technique_ids=candidate.get("technique_ids", []),
                            )
                        _feed_verification_queue(connection)
                        connection.commit()
                    finally:
                        connection.close()
                _wake_verification_workers()
            delivered_count += len(batch_candidates)
            return len(batch_candidates)

        callback_invoked = [False]

        def per_batch(offset: int, current_count: int, batch_raw: list[dict[str, Any]], batch_number: int) -> None:
            callback_invoked[0] = True
            process_batch(batch_raw, offset)

        raw_candidates = call_encoding_model(
            payload, target_count, direction_context,
            techniques=kb_techniques or None,
            per_batch=per_batch,
        )
        if not callback_invoked[0]:
            process_batch(raw_candidates, 0)

        if delivered_count == 0:
            raise ValueError("所有编码意图均未能生成有效候选")

        timestamp = utc_now()
        with DB_LOCK:
            connection = connect()
            try:
                connection.execute(
                    "UPDATE encoding_tasks SET status = 'completed', completed_at = ?, error_message = NULL WHERE id = ?",
                    (timestamp, task_id),
                )
                connection.commit()
            finally:
                connection.close()
        # 编码迭代收尾：自动触发泛化，从已验证技法泛化新技法（frontier）
        _trigger_generalization(payload["vulnerability"])
    except Exception as error:
        with DB_LOCK:
            connection = connect()
            detail = str(error)[:1000]
            if delivered_count:
                detail = f"（已落库 {delivered_count} 条候选后失败）{detail}"
            connection.execute(
                "UPDATE encoding_tasks SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?",
                (detail, utc_now(), task_id),
            )
            connection.commit()
            connection.close()


def run_cross_generation(task_id: str) -> None:
    """后台任务：对语义输出（cross_source）用编码 agent（LLM）做编码叠加，落库并自动入队检验。"""
    try:
        with DB_LOCK:
            connection = connect()
            task_record = connection.execute(
                "SELECT * FROM cross_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if not task_record:
                connection.close()
                return
            task = dict(task_record)
            source_record = connection.execute(
                "SELECT * FROM cross_sources WHERE id = ?", (task["cross_source_id"],)
            ).fetchone()
            if not source_record:
                raise ValueError("Cross iteration source not found")
            source = dict(source_record)
            connection.execute(
                "UPDATE cross_tasks SET status = 'running' WHERE id = ?", (task_id,)
            )
            connection.commit()
            connection.close()

        used_chain_keys = {
            entry["chain_key"]
            for entry in db_rows(
                "SELECT chain_key FROM cross_chain_history WHERE cross_source_id = ?",
                (source["id"],),
            )
        }

        # 构造 payload 供编码 agent 使用（语义源已是语义变异后的归档结果）
        payload = {
            "content": source["content"],
            "vulnerability": source["vulnerability"],
            "delivery": source["delivery"],
            "category": source.get("category") or "",
            "target": source.get("target") or "",
            "difficulty": source.get("difficulty") or "",
        }
        # 知识库手法为主：encoding 组，去掉已用，一次性全量遍历。
        metadata = json_value(source.get("iteration_metadata_json"), {})
        used_technique_ids = set(metadata.get("used_technique_ids", []))
        kb_techniques = [
            t for t in _select_techniques(
                source["vulnerability"], "encoding",
                content=source.get("content", ""), category=source.get("category", ""),
            )
            if t["technique_id"] not in used_technique_ids
        ]
        target_count = len(kb_techniques)
        if target_count == 0:
            # 空库：无手法可遍历，直接完成（0 候选）。
            timestamp = utc_now()
            with DB_LOCK:
                connection = connect()
                try:
                    connection.execute(
                        "UPDATE cross_tasks SET status = 'completed', completed_at = ?, error_message = NULL WHERE id = ?",
                        (timestamp, task_id),
                    )
                    connection.commit()
                finally:
                    connection.close()
            return
        seen_contents: set[str] = set()
        inserted = 0

        def process_batch(batch_raw: list[dict[str, Any]], offset: int) -> int:
            """确定性生成并落库一批交叉候选，返回该批实际入队数。"""
            nonlocal inserted
            batch_candidates: list[dict[str, Any]] = []
            for i, intent in enumerate(batch_raw, start=offset):
                declared_tids = [
                    tid for tid in (intent.get("technique_ids") or []) if isinstance(tid, str)
                ]
                if not declared_tids and kb_techniques and i < len(kb_techniques):
                    declared_tids = [kb_techniques[i]["technique_id"]]
                for candidate in realize_encoding_intent(
                    source["content"], intent, source["vulnerability"]
                ):
                    if candidate["content"] in seen_contents:
                        continue
                    seen_contents.add(candidate["content"])
                    candidate["technique_ids"] = declared_tids
                    batch_candidates.append(candidate)

            if batch_candidates:
                timestamp = utc_now()
                with DB_LOCK:
                    connection = connect()
                    try:
                        for candidate in batch_candidates:
                            chain_key = encoding_chain_key(candidate["encoding_chain"])
                            if chain_key in used_chain_keys:
                                continue
                            candidate_id = str(uuid.uuid4())
                            connection.execute(
                                """
                                INSERT INTO cross_candidates (
                                    id, task_id, cross_source_id, content, encoding_chain_json,
                                    decode_path_json, rule_labels_json, status, test_note,
                                    created_at, updated_at, technique_ids_json
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_test', NULL, ?, ?, ?)
                                """,
                                (
                                    candidate_id,
                                    task_id,
                                    source["id"],
                                    candidate["content"],
                                    json.dumps(candidate["encoding_chain"], ensure_ascii=False),
                                    json.dumps(candidate["decode_path"], ensure_ascii=False),
                                    json.dumps(candidate["rule_labels"], ensure_ascii=False),
                                    timestamp,
                                    timestamp,
                                    json.dumps(candidate.get("technique_ids", []), ensure_ascii=False),
                                ),
                            )
                            connection.execute(
                                """
                                INSERT OR IGNORE INTO cross_chain_history (
                                    cross_source_id, chain_key, content, created_at
                                ) VALUES (?, ?, ?, ?)
                                """,
                                (
                                    source["id"],
                                    chain_key,
                                    candidate["content"],
                                    timestamp,
                                ),
                            )
                            used_chain_keys.add(chain_key)
                            enqueue_verification(
                                connection,
                                "cross",
                                candidate_id,
                                "cross_candidates",
                                source,
                                candidate["content"],
                                source["delivery"],
                                execution_goal_id=None,
                                verification_spec=None,
                                technique_ids=candidate.get("technique_ids", []),
                            )
                            inserted += 1
                        _feed_verification_queue(connection)
                        connection.commit()
                    finally:
                        connection.close()
                _wake_verification_workers()
            return inserted

        callback_invoked = [False]

        def per_batch(offset: int, current_count: int, batch_raw: list[dict[str, Any]], batch_number: int) -> None:
            callback_invoked[0] = True
            process_batch(batch_raw, offset)

        raw_candidates = call_encoding_model(
            payload, target_count, techniques=kb_techniques or None,
            per_batch=per_batch,
        )
        if not callback_invoked[0]:
            process_batch(raw_candidates, 0)

        if inserted == 0:
            raise ValueError("所有编码意图均未能生成有效候选")

        timestamp = utc_now()
        with DB_LOCK:
            connection = connect()
            try:
                connection.execute(
                    "UPDATE cross_tasks SET status = 'completed', completed_at = ?, error_message = NULL WHERE id = ?",
                    (timestamp, task_id),
                )
                connection.commit()
            finally:
                connection.close()
        # 交叉迭代收尾：自动触发泛化，从已验证技法泛化新技法（frontier）
        _trigger_generalization(source["vulnerability"])
    except Exception as error:
        with DB_LOCK:
            connection = connect()
            detail = str(error)[:1000]
            if inserted:
                detail = f"（已落库 {inserted} 条候选后失败）{detail}"
            connection.execute(
                "UPDATE cross_tasks SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?",
                (detail, utc_now(), task_id),
            )
            connection.commit()
            connection.close()


# ---------------------------------------------------------------------------
# 数据库连接 / 行转换 / 时间戳 / 读取辅助函数
# ---------------------------------------------------------------------------


def now() -> str:
    return utc_now()


def connect() -> sqlite3.Connection:
    """Create a row-factory connection with foreign keys enabled (context-managed)."""
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def row(record: Any) -> dict[str, Any] | None:
    """Convert a single sqlite3.Row (or None) into a dict."""
    return dict(record) if record is not None else None


def read_payload(connection: sqlite3.Connection, payload_id: str) -> dict[str, Any] | None:
    record = connection.execute("SELECT * FROM payloads WHERE id = ?", (payload_id,)).fetchone()
    return dict(record) if record else None


def _column_exists(connection: sqlite3.Connection, table: str, column: str) -> bool:
    """Return True if `column` exists on `table`."""
    return any(
        row[1] == column
        for row in connection.execute(f"PRAGMA table_info({table})")
    )


def _ensure_columns(
    connection: sqlite3.Connection,
    table: str,
    columns: list[tuple[str, str]],
) -> None:
    """Add any missing columns (idempotent) so legacy tables match the full schema."""
    existing = {
        col[1]
        for col in connection.execute(f"PRAGMA table_info({table})")
    }
    for name, ddl in columns:
        if name not in existing:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def _migrate_verification_jobs_status(connection: sqlite3.Connection) -> None:
    """确保 verification_jobs.status 支持 'waiting'（SQLite 需重建表以改 CHECK）。

    幂等：仅当现有表的 CHECK 不含 'waiting' 时重建。数据全保留，不重判。
    """
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='verification_jobs'"
    ).fetchone()
    if row and row[0] and "'waiting'" in row[0]:
        return
    connection.execute("ALTER TABLE verification_jobs RENAME TO verification_jobs_old")
    connection.execute(
        """
        CREATE TABLE verification_jobs (
            id TEXT PRIMARY KEY,
            source_agent TEXT NOT NULL,
            source_candidate_id TEXT NOT NULL,
            candidate_kind TEXT NOT NULL,
            base_name TEXT NOT NULL,
            vulnerability TEXT NOT NULL,
            payload_snapshot TEXT NOT NULL,
            delivery TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('waiting', 'queued', 'running', 'completed', 'failed')),
            target_key TEXT NOT NULL,
            raw_evidence_json TEXT,
            verdict_json TEXT,
            bypass_verdict TEXT,
            execution_verdict TEXT,
            failure_stage TEXT,
            library_record_id TEXT,
            error_message TEXT,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            verification_spec_json TEXT,
            execution_goal_id TEXT,
            sent_payload_snapshot TEXT,
            payload_fidelity TEXT NOT NULL DEFAULT 'exact',
            route_hint_json TEXT,
            technique_ids_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            UNIQUE(source_agent, source_candidate_id)
        );
        """
    )
    # 仅复制旧表实际存在的列（旧库可能缺部分后加的列，避免复制失败）。
    old_cols = {
        row[1]
        for row in connection.execute("PRAGMA table_info(verification_jobs_old)")
    }
    new_cols = [
        row[1]
        for row in connection.execute("PRAGMA table_info(verification_jobs)")
    ]
    copy_cols = [c for c in new_cols if c in old_cols]
    col_list = ", ".join(copy_cols)
    connection.execute(
        f"INSERT INTO verification_jobs ({col_list}) SELECT {col_list} FROM verification_jobs_old"
    )
    connection.execute("DROP TABLE verification_jobs_old")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_verification_jobs_status "
        "ON verification_jobs(status, created_at)"
    )


def initialize_database() -> None:
    """Create the full schema and migrate legacy tables to the current shape."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)

    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS payloads (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                vulnerability TEXT NOT NULL,
                category TEXT NOT NULL,
                delivery TEXT NOT NULL,
                target TEXT NOT NULL,
                difficulty TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                archived_from_candidate_id TEXT UNIQUE,
                source_agent TEXT,
                source_candidate_id TEXT,
                iteration_metadata_json TEXT,
                is_pool_snapshot INTEGER NOT NULL DEFAULT 0,
                severity TEXT NOT NULL DEFAULT '中危',
                is_executable INTEGER NOT NULL DEFAULT 1,
                usage_method TEXT NOT NULL DEFAULT '',
                success_indicators TEXT NOT NULL DEFAULT '',
                is_deleted INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS generation_tasks (
                id TEXT PRIMARY KEY,
                base_payload_id TEXT NOT NULL,
                status TEXT NOT NULL,
                provider TEXT,
                model TEXT,
                rule_hints_json TEXT NOT NULL,
                error_message TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                direction_context_json TEXT NOT NULL DEFAULT '{}',
                base_parts_json TEXT NOT NULL DEFAULT '[]',
                parser_confidence REAL NOT NULL DEFAULT 0,
                parser_status TEXT NOT NULL DEFAULT 'unsupported',
                unsupported_reason TEXT
            );
            CREATE TABLE IF NOT EXISTS candidates (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                base_payload_id TEXT NOT NULL,
                content TEXT NOT NULL,
                delivery TEXT NOT NULL,
                rule_labels_json TEXT NOT NULL,
                explanation TEXT NOT NULL,
                confidence REAL NOT NULL,
                status TEXT NOT NULL,
                test_note TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                used_direction_ids_json TEXT NOT NULL DEFAULT '[]',
                next_directions_json TEXT NOT NULL DEFAULT '[]',
                execution_goal_id TEXT,
                semantic_dimension_ids_json TEXT NOT NULL DEFAULT '[]',
                semantic_delta_json TEXT NOT NULL DEFAULT '{}',
                verification_spec_json TEXT,
                base_parts_json TEXT NOT NULL DEFAULT '[]',
                candidate_parts_json TEXT NOT NULL DEFAULT '[]',
                part_operations_json TEXT NOT NULL DEFAULT '[]',
                parser_confidence TEXT NOT NULL DEFAULT '0',
                parser_status TEXT NOT NULL DEFAULT 'unsupported',
                unsupported_reason TEXT,
                technique_ids_json TEXT NOT NULL DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS encoding_tasks (
                id TEXT PRIMARY KEY,
                base_payload_id TEXT NOT NULL,
                status TEXT NOT NULL,
                provider TEXT,
                model TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                direction_context_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS encoding_candidates (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                base_payload_id TEXT NOT NULL,
                content TEXT NOT NULL,
                delivery TEXT NOT NULL,
                encoding_chain_json TEXT NOT NULL,
                decode_path_json TEXT NOT NULL,
                rule_labels_json TEXT NOT NULL,
                explanation TEXT NOT NULL,
                confidence REAL NOT NULL,
                status TEXT NOT NULL,
                test_note TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                origin TEXT NOT NULL DEFAULT 'generated',
                migration_note TEXT,
                migrated_from_candidate_id TEXT,
                used_direction_ids_json TEXT NOT NULL DEFAULT '[]',
                next_directions_json TEXT NOT NULL DEFAULT '[]',
                technique_ids_json TEXT NOT NULL DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS cross_sources (
                id TEXT PRIMARY KEY,
                archived_payload_id TEXT NOT NULL UNIQUE,
                semantic_candidate_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                vulnerability TEXT NOT NULL,
                category TEXT NOT NULL,
                delivery TEXT NOT NULL,
                target TEXT NOT NULL,
                difficulty TEXT NOT NULL,
                content TEXT NOT NULL,
                rule_labels_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cross_tasks (
                id TEXT PRIMARY KEY,
                cross_source_id TEXT NOT NULL,
                status TEXT NOT NULL,
                error_message TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS cross_candidates (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                cross_source_id TEXT NOT NULL,
                content TEXT NOT NULL,
                encoding_chain_json TEXT NOT NULL,
                decode_path_json TEXT NOT NULL,
                rule_labels_json TEXT NOT NULL,
                status TEXT NOT NULL,
                test_note TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                technique_ids_json TEXT NOT NULL DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS cross_chain_history (
                cross_source_id TEXT NOT NULL,
                chain_key TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (cross_source_id, chain_key),
                UNIQUE (cross_source_id, content)
            );
            CREATE TABLE IF NOT EXISTS iteration_pool_items (
                id TEXT PRIMARY KEY,
                agent TEXT NOT NULL CHECK(agent IN ('semantic', 'encoding')),
                source_payload_id TEXT NOT NULL,
                snapshot_payload_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL CHECK(status IN ('pending', 'started')),
                task_id TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT
            );
            CREATE TABLE IF NOT EXISTS cross_pool_items (
                id TEXT PRIMARY KEY,
                cross_source_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending', 'started')),
                task_id TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT
            );
            CREATE TABLE IF NOT EXISTS exhaustion_tasks (
                id TEXT PRIMARY KEY,
                base_payload_id TEXT NOT NULL,
                status TEXT NOT NULL,
                provider TEXT,
                model TEXT,
                primitive_backend TEXT NOT NULL DEFAULT 'generic',
                technique_count INTEGER NOT NULL DEFAULT 0,
                error_message TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS generalization_tasks (
                id TEXT PRIMARY KEY,
                vulnerability TEXT NOT NULL,
                status TEXT NOT NULL,
                provider TEXT,
                model TEXT,
                fuel_count INTEGER NOT NULL DEFAULT 0,
                generated_count INTEGER NOT NULL DEFAULT 0,
                deduped_count INTEGER NOT NULL DEFAULT 0,
                exploit_count INTEGER NOT NULL DEFAULT 0,
                pioneer_count INTEGER NOT NULL DEFAULT 0,
                error_message TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS mechanisms (
                id TEXT PRIMARY KEY,
                name TEXT,
                desc TEXT
            );
            CREATE TABLE IF NOT EXISTS families (
                id TEXT PRIMARY KEY,
                mechanism_id TEXT,
                desc TEXT
            );
            CREATE TABLE IF NOT EXISTS technique_templates (
                technique_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                note TEXT
            );
            CREATE TABLE IF NOT EXISTS technique_conflicts (
                technique_id TEXT NOT NULL,
                conflict_id TEXT NOT NULL,
                PRIMARY KEY (technique_id, conflict_id)
            );
            CREATE TABLE IF NOT EXISTS waf_features (
                feature TEXT PRIMARY KEY,
                first_seen TEXT,
                last_seen TEXT,
                n_403 INTEGER NOT NULL DEFAULT 0,
                n_200 INTEGER NOT NULL DEFAULT 0,
                pass_rate REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS kb_technique_events (
                id TEXT PRIMARY KEY,
                technique_id TEXT NOT NULL,
                event TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS technique_primitive_uses (
                technique_id TEXT NOT NULL,
                base_payload_id TEXT NOT NULL,
                PRIMARY KEY (technique_id, base_payload_id)
            );
            CREATE TABLE IF NOT EXISTS textbook_notes (
                note_id TEXT PRIMARY KEY,
                source_name TEXT,
                content_hash TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL DEFAULT 'user',
                credibility REAL NOT NULL DEFAULT 0.5,
                uses INTEGER NOT NULL DEFAULT 0,
                success INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS eval_bench (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL UNIQUE,
                vulnerability TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual',
                baseline_bypass INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS success_samples (
                id TEXT PRIMARY KEY,
                agent TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                archived_payload_id TEXT,
                name TEXT NOT NULL,
                vulnerability TEXT NOT NULL,
                category TEXT NOT NULL,
                delivery TEXT NOT NULL,
                target TEXT NOT NULL,
                difficulty TEXT NOT NULL,
                content TEXT NOT NULL,
                test_note TEXT,
                provenance_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (agent, candidate_id)
            );
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                success_sample_id TEXT NOT NULL UNIQUE,
                source_agent TEXT NOT NULL,
                source_candidate_id TEXT NOT NULL,
                source_archived_payload_id TEXT,
                sample_name TEXT NOT NULL,
                vulnerability TEXT NOT NULL,
                category TEXT NOT NULL,
                delivery TEXT NOT NULL,
                target TEXT NOT NULL,
                payload_content TEXT NOT NULL,
                sample_test_note TEXT,
                provenance_json TEXT NOT NULL,
                sample_created_at TEXT NOT NULL,
                title TEXT NOT NULL,
                verification_environment TEXT NOT NULL DEFAULT '',
                prerequisites TEXT NOT NULL DEFAULT '',
                verification_steps TEXT NOT NULL DEFAULT '',
                actual_result TEXT NOT NULL DEFAULT '',
                conclusion TEXT NOT NULL DEFAULT '',
                tester TEXT NOT NULL DEFAULT '',
                verification_date TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS report_images (
                id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL,
                original_name TEXT NOT NULL,
                relative_path TEXT NOT NULL UNIQUE,
                media_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                caption TEXT NOT NULL DEFAULT '',
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS waf_test_runs (
                id TEXT PRIMARY KEY,
                agent TEXT NOT NULL CHECK(agent IN ('semantic', 'encoding', 'cross')),
                candidate_id TEXT NOT NULL,
                base_name TEXT NOT NULL,
                vulnerability TEXT NOT NULL,
                payload_snapshot TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('queued', 'running', 'completed', 'failed')),
                result TEXT,
                evidence TEXT,
                request_summary TEXT,
                response_excerpt TEXT,
                http_status INTEGER,
                error_message TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS verification_jobs (
                id TEXT PRIMARY KEY,
                source_agent TEXT NOT NULL,
                source_candidate_id TEXT NOT NULL,
                candidate_kind TEXT NOT NULL,
                base_name TEXT NOT NULL,
                source_payload_id TEXT,
                vulnerability TEXT NOT NULL,
                payload_snapshot TEXT NOT NULL,
                delivery TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('waiting', 'queued', 'running', 'completed', 'failed')),
                target_key TEXT NOT NULL,
                raw_evidence_json TEXT,
                verdict_json TEXT,
                bypass_verdict TEXT,
                execution_verdict TEXT,
                failure_stage TEXT,
                library_record_id TEXT,
                error_message TEXT,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                verification_spec_json TEXT,
                execution_goal_id TEXT,
                sent_payload_snapshot TEXT,
                payload_fidelity TEXT NOT NULL DEFAULT 'exact',
                route_hint_json TEXT,
                technique_ids_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                UNIQUE(source_agent, source_candidate_id)
            );
            CREATE INDEX IF NOT EXISTS idx_verification_jobs_status
                ON verification_jobs(status, created_at);
            CREATE TABLE IF NOT EXISTS bypass_library (
                id TEXT PRIMARY KEY,
                source_agent TEXT NOT NULL,
                source_candidate_id TEXT NOT NULL,
                candidate_kind TEXT NOT NULL,
                name TEXT NOT NULL,
                vulnerability TEXT NOT NULL,
                delivery TEXT NOT NULL,
                target_key TEXT NOT NULL,
                content TEXT NOT NULL,
                confidence REAL NOT NULL,
                rationale TEXT NOT NULL,
                provenance_json TEXT NOT NULL,
                bypass_success INTEGER NOT NULL DEFAULT 0,
                verification_success INTEGER NOT NULL DEFAULT 0,
                labels_json TEXT NOT NULL DEFAULT '[]',
                verification_job_id TEXT,
                target_profile_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(source_agent, source_candidate_id)
            );
            CREATE INDEX IF NOT EXISTS idx_bypass_library_vuln
                ON bypass_library(vulnerability, created_at DESC);
            CREATE TABLE IF NOT EXISTS block_library (
                id TEXT PRIMARY KEY,
                source_agent TEXT NOT NULL,
                source_candidate_id TEXT NOT NULL,
                candidate_kind TEXT NOT NULL,
                name TEXT NOT NULL,
                vulnerability TEXT NOT NULL,
                delivery TEXT NOT NULL,
                target_key TEXT NOT NULL,
                content TEXT NOT NULL,
                failure_stage TEXT NOT NULL,
                confidence REAL NOT NULL,
                rationale TEXT NOT NULL,
                provenance_json TEXT NOT NULL,
                bypass_success INTEGER NOT NULL DEFAULT 0,
                verification_success INTEGER NOT NULL DEFAULT 0,
                labels_json TEXT NOT NULL DEFAULT '[]',
                verification_job_id TEXT,
                target_profile_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(source_agent, source_candidate_id)
            );
            CREATE INDEX IF NOT EXISTS idx_block_library_stage
                ON block_library(failure_stage, created_at DESC);
            CREATE TABLE IF NOT EXISTS unverified_library (
                id TEXT PRIMARY KEY,
                source_agent TEXT NOT NULL,
                source_candidate_id TEXT NOT NULL,
                candidate_kind TEXT NOT NULL,
                name TEXT NOT NULL,
                vulnerability TEXT NOT NULL,
                delivery TEXT NOT NULL,
                target_key TEXT NOT NULL,
                content TEXT NOT NULL,
                confidence REAL NOT NULL,
                rationale TEXT NOT NULL,
                provenance_json TEXT NOT NULL,
                verification_job_id TEXT,
                target_profile_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(source_agent, source_candidate_id)
            );
            CREATE INDEX IF NOT EXISTS idx_unverified_library_vuln
                ON unverified_library(vulnerability, created_at DESC);
            CREATE TABLE IF NOT EXISTS kb_observations (
                id TEXT PRIMARY KEY,
                source_payload_id TEXT NOT NULL,
                source_agent TEXT NOT NULL,
                source_candidate_id TEXT NOT NULL,
                candidate_kind TEXT NOT NULL,
                vulnerability TEXT NOT NULL,
                target_key TEXT NOT NULL,
                bypass_success INTEGER NOT NULL,
                verification_success INTEGER NOT NULL,
                labels_json TEXT NOT NULL,
                failure_stage TEXT,
                raw_evidence_json TEXT,
                verdict_json TEXT,
                target_profile_json TEXT,
                waf_policy_version TEXT,
                backend_version TEXT,
                technique_ids_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_kb_observations_payload
                ON kb_observations(source_payload_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS kb_prune_events (
                id TEXT PRIMARY KEY,
                technique_id TEXT,
                primitive TEXT,
                reason TEXT,
                metadata_json TEXT,
                version TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS kb_techniques (
                id TEXT PRIMARY KEY,
                technique_id TEXT NOT NULL UNIQUE,
                name TEXT,
                vulnerability TEXT,
                status TEXT NOT NULL DEFAULT 'frontier',
                success_count INTEGER NOT NULL DEFAULT 0,
                labels_json TEXT,
                source_note TEXT,
                principle TEXT,
                template TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                origin TEXT NOT NULL DEFAULT 'generated',
                protected INTEGER NOT NULL DEFAULT 0,
                mechanism_id TEXT,
                family_id TEXT,
                backend TEXT NOT NULL DEFAULT 'generic',
                version_gate TEXT NOT NULL DEFAULT '',
                composable INTEGER NOT NULL DEFAULT 0,
                priority INTEGER NOT NULL DEFAULT 3,
                bypass_count INTEGER NOT NULL DEFAULT 0,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                distinct_primitive_count INTEGER NOT NULL DEFAULT 0,
                retired_at TEXT
            );
            """
        )

        # Migrate legacy tables that predate some columns (idempotent).
        _ensure_columns(
            connection,
            "payloads",
            [
                ("archived_from_candidate_id", "TEXT"),
                ("source_agent", "TEXT"),
                ("source_candidate_id", "TEXT"),
                ("iteration_metadata_json", "TEXT"),
                ("is_pool_snapshot", "INTEGER NOT NULL DEFAULT 0"),
                ("severity", "TEXT NOT NULL DEFAULT '中危'"),
                ("is_executable", "INTEGER NOT NULL DEFAULT 1"),
                ("usage_method", "TEXT NOT NULL DEFAULT ''"),
                ("success_indicators", "TEXT NOT NULL DEFAULT ''"),
                ("is_deleted", "INTEGER NOT NULL DEFAULT 0"),
                ("labels_json", "TEXT NOT NULL DEFAULT '[\"未绕过\",\"未验证\"]'"),
            ],
        )
        connection.execute("UPDATE payloads SET severity = '中危' WHERE severity IS NULL OR TRIM(severity) = ''")
        connection.execute("UPDATE payloads SET is_executable = 1 WHERE is_executable IS NULL")
        connection.execute("UPDATE payloads SET labels_json = '[\"未绕过\",\"未验证\"]' WHERE labels_json IS NULL OR TRIM(labels_json) = ''")
        if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='payload_library_archive'").fetchone():
            _ensure_columns(
                connection,
                "payload_library_archive",
                [
                    ("severity", "TEXT NOT NULL DEFAULT '中危'"),
                    ("is_executable", "INTEGER NOT NULL DEFAULT 1"),
                ],
            )
            connection.execute("UPDATE payload_library_archive SET severity = '中危' WHERE severity IS NULL OR TRIM(severity) = ''")
            connection.execute("UPDATE payload_library_archive SET is_executable = 1 WHERE is_executable IS NULL")
        _ensure_columns(
            connection,
            "generation_tasks",
            [
                ("direction_context_json", "TEXT NOT NULL DEFAULT '{}'"),
                ("base_parts_json", "TEXT NOT NULL DEFAULT '[]'"),
                ("parser_confidence", "REAL NOT NULL DEFAULT 0"),
                ("parser_status", "TEXT NOT NULL DEFAULT 'unsupported'"),
                ("unsupported_reason", "TEXT"),
            ],
        )
        _ensure_columns(
            connection,
            "candidates",
            [
                ("used_direction_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
                ("next_directions_json", "TEXT NOT NULL DEFAULT '[]'"),
                ("execution_goal_id", "TEXT"),
                ("semantic_dimension_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
                ("semantic_delta_json", "TEXT NOT NULL DEFAULT '{}'"),
                ("verification_spec_json", "TEXT"),
                ("base_parts_json", "TEXT NOT NULL DEFAULT '[]'"),
                ("candidate_parts_json", "TEXT NOT NULL DEFAULT '[]'"),
                ("part_operations_json", "TEXT NOT NULL DEFAULT '[]'"),
                ("parser_confidence", "TEXT NOT NULL DEFAULT '0'"),
                ("parser_status", "TEXT NOT NULL DEFAULT 'unsupported'"),
                ("unsupported_reason", "TEXT"),
            ],
        )
        _ensure_columns(
            connection,
            "encoding_tasks",
            [("direction_context_json", "TEXT NOT NULL DEFAULT '{}'")],
        )
        _ensure_columns(
            connection,
            "encoding_candidates",
            [
                ("origin", "TEXT NOT NULL DEFAULT 'generated'"),
                ("migration_note", "TEXT"),
                ("migrated_from_candidate_id", "TEXT"),
                ("used_direction_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
                ("next_directions_json", "TEXT NOT NULL DEFAULT '[]'"),
            ],
        )
        # 双成功标签 + 观测字段（老库增量迁移）
        _ensure_columns(
            connection,
            "bypass_library",
            [
                ("bypass_success", "INTEGER NOT NULL DEFAULT 0"),
                ("verification_success", "INTEGER NOT NULL DEFAULT 0"),
                ("labels_json", "TEXT NOT NULL DEFAULT '[]'"),
                ("verification_job_id", "TEXT"),
                ("target_profile_id", "TEXT"),
            ],
        )
        _ensure_columns(
            connection,
            "block_library",
            [
                ("bypass_success", "INTEGER NOT NULL DEFAULT 0"),
                ("verification_success", "INTEGER NOT NULL DEFAULT 0"),
                ("labels_json", "TEXT NOT NULL DEFAULT '[]'"),
                ("verification_job_id", "TEXT"),
                ("target_profile_id", "TEXT"),
            ],
        )
        _ensure_columns(
            connection,
            "unverified_library",
            [
                ("verification_job_id", "TEXT"),
                ("target_profile_id", "TEXT"),
            ],
        )
        _ensure_columns(
            connection,
            "verification_jobs",
            [
                ("source_payload_id", "TEXT"),
                ("verification_spec_json", "TEXT"),
                ("execution_goal_id", "TEXT"),
                ("sent_payload_snapshot", "TEXT"),
                ("payload_fidelity", "TEXT NOT NULL DEFAULT 'exact'"),
                ("route_hint_json", "TEXT"),
                ("technique_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
            ],
        )
        _ensure_columns(
            connection,
            "candidates",
            [("technique_ids_json", "TEXT NOT NULL DEFAULT '[]'")],
        )
        _ensure_columns(
            connection,
            "encoding_candidates",
            [("technique_ids_json", "TEXT NOT NULL DEFAULT '[]'")],
        )
        _ensure_columns(
            connection,
            "cross_candidates",
            [("technique_ids_json", "TEXT NOT NULL DEFAULT '[]'")],
        )
        _ensure_columns(
            connection,
            "kb_observations",
            [("technique_ids_json", "TEXT NOT NULL DEFAULT '[]'")],
        )
        _ensure_columns(
            connection,
            "kb_techniques",
            [
                ("principle", "TEXT"),
                ("template", "TEXT"),
                ("origin", "TEXT NOT NULL DEFAULT 'generated'"),
                ("protected", "INTEGER NOT NULL DEFAULT 0"),
                ("mechanism_id", "TEXT"),
                ("family_id", "TEXT"),
                ("backend", "TEXT NOT NULL DEFAULT 'generic'"),
                ("version_gate", "TEXT NOT NULL DEFAULT ''"),
                ("composable", "INTEGER NOT NULL DEFAULT 0"),
                ("priority", "INTEGER NOT NULL DEFAULT 3"),
                ("bypass_count", "INTEGER NOT NULL DEFAULT 0"),
                ("attempt_count", "INTEGER NOT NULL DEFAULT 0"),
                ("distinct_primitive_count", "INTEGER NOT NULL DEFAULT 0"),
                ("retired_at", "TEXT"),
            ],
        )
        # 状态机迁移：pending→frontier，pruned→retired（promoted/seed 保留）
        connection.execute(
            "UPDATE kb_techniques SET status = 'frontier' WHERE status = 'pending'"
        )
        connection.execute(
            "UPDATE kb_techniques SET status = 'retired', retired_at = COALESCE(retired_at, updated_at) "
            "WHERE status = 'pruned'"
        )
        # 旧 pending/pruned 技法没有 protected 标记，统一为生成类（非主力，可淘汰）
        connection.execute(
            "UPDATE kb_techniques SET protected = 0 WHERE protected IS NULL"
        )
        connection.execute(
            "UPDATE kb_techniques SET origin = 'generated' WHERE origin IS NULL OR TRIM(origin) = ''"
        )

        # verification_jobs.status 需支持 'waiting'（限容内队列缓冲态）。
        # SQLite 无法 ALTER CHECK 约束，旧库需幂等重建表（数据全保留）。
        _migrate_verification_jobs_status(connection)

        # 迭代逻辑改为「遍历知识库手法」后，任务表不再使用 candidate_count 列。
        # 旧库可能残留该列，幂等删除（SQLite >= 3.35 支持 DROP COLUMN）。
        for table in ("generation_tasks", "encoding_tasks", "cross_tasks"):
            if _column_exists(connection, table, "candidate_count"):
                connection.execute(f"ALTER TABLE {table} DROP COLUMN candidate_count")

        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_waf_test_runs_candidate_latest "
            "ON waf_test_runs(agent, candidate_id, created_at DESC)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_success_samples_active_created "
            "ON success_samples(status, created_at DESC)"
        )
        # 知识库自学习：幂等灌入机制/族 + 内置 part:* 方向（标 origin='system' protected=1）
        from app.knowledge_base_agent.kb_catalog import seed_kb_catalog

        seed_kb_catalog(connection)
        connection.commit()
        connection.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database and resources on startup."""
    load_dotenv(CONFIG_PATH)
    initialize_database()
    _recover_stale_generation_tasks()
    _start_verification_pool()
    try:
        yield
    finally:
        _shutdown_verification_pool()


app = FastAPI(title="WAFByPasser API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5184", "http://localhost:5184"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_timing(request: Request, call_next):
    """Log slow local API calls without buffering response bodies."""
    request_id = uuid.uuid4().hex[:12]
    started = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - started) * 1000
    response.headers["X-Request-Id"] = request_id
    if elapsed_ms >= 1000:
        LOGGER.warning(
            "slow_api_request id=%s method=%s path=%s status=%s elapsed_ms=%.1f bytes=%s",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
            response.headers.get("content-length", "streamed"),
        )
    return response


def db_connection() -> sqlite3.Connection:
    """Create an isolated SQLite connection suitable for concurrent reads."""
    connection = sqlite3.connect(DB_PATH, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=5000")
    return connection


def db_rows(sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    """Run a read query without serializing independent SQLite readers."""
    connection = db_connection()
    try:
        return connection.execute(sql, params).fetchall()
    finally:
        connection.close()


def db_row(sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
    result = db_rows(sql, params)
    return result[0] if result else None


def json_value(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def latest_waf_runs(agent: str, candidate_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Fetch latest WAF runs for a page in one indexed query."""
    ids = [candidate_id for candidate_id in candidate_ids if candidate_id]
    if not ids:
        return {}
    placeholders = ", ".join("?" for _ in ids)
    records = db_rows(
        f"""
        SELECT * FROM (
            SELECT waf_test_runs.*,
                   ROW_NUMBER() OVER (
                       PARTITION BY candidate_id ORDER BY created_at DESC
                   ) AS latest_rank
            FROM waf_test_runs
            WHERE agent = ? AND candidate_id IN ({placeholders})
        ) WHERE latest_rank = 1
        """,
        (agent, *ids),
    )
    return {record["candidate_id"]: dict(record) for record in records}


def latest_waf_run(agent: str | None, candidate_id: str | None) -> dict[str, Any] | None:
    if not agent or not candidate_id:
        return None
    return latest_waf_runs(agent, [candidate_id]).get(candidate_id)


def latest_verification_jobs(agent: str, candidate_ids: list[str]) -> dict[str, str]:
    """批量查候选对应的最新 verification_jobs.status（无对应 job 时不在结果中）。"""
    ids = [cid for cid in candidate_ids if cid]
    if not ids:
        return {}
    placeholders = ", ".join("?" for _ in ids)
    records = db_rows(
        f"""
        SELECT source_candidate_id, status FROM verification_jobs
        WHERE source_agent = ? AND source_candidate_id IN ({placeholders})
        """,
        (agent, *ids),
    )
    return {r["source_candidate_id"]: r["status"] for r in records}


def verification_status_for(agent: str, candidate_id: str | None) -> str | None:
    if not candidate_id:
        return None
    return latest_verification_jobs(agent, [candidate_id]).get(candidate_id)


def paged_response(
    sql: str,
    params: tuple[Any, ...],
    limit: int | None,
    cursor: int,
    view: Any,
) -> list[dict[str, Any]] | dict[str, Any]:
    """Return the legacy list unless a page size was explicitly requested."""
    if limit is None:
        return [view(record) for record in db_rows(sql, params)]
    page_size = min(limit, MAX_PAGE_SIZE)
    total = db_row(f"SELECT COUNT(*) AS count FROM ({sql})", params)["count"]
    records = db_rows(f"{sql} LIMIT ? OFFSET ?", (*params, page_size, cursor))
    items = [view(record) for record in records]
    next_cursor = cursor + len(items)
    return {
        "items": items,
        "total": total,
        "next_cursor": next_cursor if next_cursor < total else None,
    }


def payload_page_items(records: list[sqlite3.Row]) -> list[dict[str, Any]]:
    latest_by_source: dict[tuple[str, str], dict[str, Any]] = {}
    for agent in ("semantic", "encoding", "cross"):
        candidate_ids = [
            record["source_candidate_id"]
            for record in records
            if record["source_agent"] == agent and record["source_candidate_id"]
        ]
        latest_by_source.update({(agent, key): value for key, value in latest_waf_runs(agent, candidate_ids).items()})
    result = []
    for record in records:
        item = payload_view(record)
        item["latest_waf_test"] = latest_by_source.get(
            (record["source_agent"], record["source_candidate_id"])
        )
        result.append(item)
    return result


def paged_payload_response(
    sql: str,
    limit: int | None,
    cursor: int,
    params: tuple[Any, ...] = (),
) -> list[dict[str, Any]] | dict[str, Any]:
    if limit is None:
        return payload_page_items(db_rows(sql, params))
    page_size = min(limit, MAX_PAGE_SIZE)
    total = db_row(f"SELECT COUNT(*) AS count FROM ({sql})", params)["count"]
    records = db_rows(f"{sql} LIMIT ? OFFSET ?", (*params, page_size, cursor))
    items = payload_page_items(records)
    next_cursor = cursor + len(items)
    return {"items": items, "total": total, "next_cursor": next_cursor if next_cursor < total else None}


def payload_view(source: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(source)
    metadata = json_value(item.pop("iteration_metadata_json", None), {})
    archived_from_candidate_id = item.pop("archived_from_candidate_id", None)
    source_agent = item.pop("source_agent", None)
    source_candidate_id = item.pop("source_candidate_id", None)
    item.pop("is_pool_snapshot", None)
    item.pop("is_deleted", None)
    # These legacy authoring fields remain in storage for compatibility with
    # candidate/report history, but are no longer part of the source Payload
    # API contract.
    for field in ("name", "category", "target", "difficulty", "usage_method", "success_indicators"):
        item.pop(field, None)
    item["severity"] = item.get("severity") or "中危"
    item["is_executable"] = bool(item.get("is_executable", 1))
    item["labels"] = json_value(item.pop("labels_json", None), ["未绕过", "未验证"])
    item["used_direction_ids"] = metadata.get("used_direction_ids", [])
    item["next_directions"] = metadata.get("next_directions", [])
    archive_outcome = metadata.get("archive_outcome")
    if archive_outcome not in {"bypass_success", "bypass_failure"}:
        archive_outcome = (
            "bypass_success"
            if archived_from_candidate_id
            and source_candidate_id
            and source_agent in {"semantic", "encoding"}
            else None
        )
    item["archive_outcome"] = archive_outcome
    return item


def candidate_view(
    source: sqlite3.Row | dict[str, Any],
    latest_waf_test: dict[str, Any] | None | object = _MISSING,
    verification_status: str | None | object = _MISSING,
) -> dict[str, Any]:
    item = dict(source)
    json_fields = {
        "rule_labels_json": ("rule_labels", []),
        "used_direction_ids_json": ("used_direction_ids", []),
        "next_directions_json": ("next_directions", []),
        "technique_ids_json": ("technique_ids", []),
        "semantic_dimension_ids_json": ("semantic_dimension_ids", []),
        "semantic_delta_json": ("semantic_delta", {}),
        "verification_spec_json": ("verification_spec", None),
        "base_parts_json": ("base_parts", []),
        "candidate_parts_json": ("candidate_parts", []),
        "part_operations_json": ("part_operations", []),
    }
    for column, (name, default) in json_fields.items():
        item[name] = json_value(item.pop(column, None), default)
    try:
        item["parser_confidence"] = float(item.get("parser_confidence") or 0)
    except (TypeError, ValueError):
        item["parser_confidence"] = 0.0
    item["latest_waf_test"] = latest_waf_run("semantic", item.get("id")) if latest_waf_test is _MISSING else latest_waf_test
    item["verification_status"] = (
        verification_status_for("semantic", item.get("id"))
        if verification_status is _MISSING
        else verification_status
    )
    return item


def encoding_candidate_view(
    source: sqlite3.Row | dict[str, Any],
    latest_waf_test: dict[str, Any] | None | object = _MISSING,
    verification_status: str | None | object = _MISSING,
) -> dict[str, Any]:
    item = dict(source)
    json_fields = {
        "encoding_chain_json": ("encoding_chain", []),
        "decode_path_json": ("decode_path", []),
        "rule_labels_json": ("rule_labels", []),
        "used_direction_ids_json": ("used_direction_ids", []),
        "next_directions_json": ("next_directions", []),
        "technique_ids_json": ("technique_ids", []),
    }
    for column, (name, default) in json_fields.items():
        item[name] = json_value(item.pop(column, None), default)
    item["latest_waf_test"] = latest_waf_run("encoding", item.get("id")) if latest_waf_test is _MISSING else latest_waf_test
    item["verification_status"] = (
        verification_status_for("encoding", item.get("id"))
        if verification_status is _MISSING
        else verification_status
    )
    return item


def cross_source_view(
    source: sqlite3.Row | dict[str, Any],
    history: list[sqlite3.Row] | object = _MISSING,
    generated: list[sqlite3.Row] | object = _MISSING,
) -> dict[str, Any]:
    item = dict(source)
    item["rule_labels"] = json_value(item.pop("rule_labels_json", None), [])
    if history is _MISSING:
        history = db_rows(
            "SELECT chain_key, content FROM cross_chain_history WHERE cross_source_id = ?",
            (item["id"],),
        )
    if generated is _MISSING:
        generated = db_rows(
            "SELECT content FROM cross_candidates WHERE cross_source_id = ?",
            (item["id"],),
        )
    available = unused_distinct_chains(
        item["content"],
        {entry["chain_key"] for entry in history},
        {entry["content"] for entry in history} | {entry["content"] for entry in generated},
    )
    item["available_chain_count"] = len(available)
    return item


def cross_source_page_items(records: list[sqlite3.Row]) -> list[dict[str, Any]]:
    source_ids = [record["id"] for record in records]
    if not source_ids:
        return []
    placeholders = ", ".join("?" for _ in source_ids)
    history_by_source: dict[str, list[sqlite3.Row]] = {source_id: [] for source_id in source_ids}
    generated_by_source: dict[str, list[sqlite3.Row]] = {source_id: [] for source_id in source_ids}
    for record in db_rows(
        f"SELECT cross_source_id, chain_key, content FROM cross_chain_history WHERE cross_source_id IN ({placeholders})",
        tuple(source_ids),
    ):
        history_by_source[record["cross_source_id"]].append(record)
    for record in db_rows(
        f"SELECT cross_source_id, content FROM cross_candidates WHERE cross_source_id IN ({placeholders})",
        tuple(source_ids),
    ):
        generated_by_source[record["cross_source_id"]].append(record)
    return [
        cross_source_view(record, history_by_source[record["id"]], generated_by_source[record["id"]])
        for record in records
    ]


def paged_cross_source_response(limit: int | None, cursor: int) -> list[dict[str, Any]] | dict[str, Any]:
    sql = "SELECT * FROM cross_sources ORDER BY created_at DESC"
    if limit is None:
        return cross_source_page_items(db_rows(sql))
    page_size = min(limit, MAX_PAGE_SIZE)
    total = db_row(f"SELECT COUNT(*) AS count FROM ({sql})")["count"]
    records = db_rows(f"{sql} LIMIT ? OFFSET ?", (page_size, cursor))
    items = cross_source_page_items(records)
    next_cursor = cursor + len(items)
    return {"items": items, "total": total, "next_cursor": next_cursor if next_cursor < total else None}


def cross_candidate_view(
    source: sqlite3.Row | dict[str, Any],
    latest_waf_test: dict[str, Any] | None | object = _MISSING,
    verification_status: str | None | object = _MISSING,
) -> dict[str, Any]:
    item = dict(source)
    json_fields = {
        "encoding_chain_json": ("encoding_chain", []),
        "decode_path_json": ("decode_path", []),
        "rule_labels_json": ("rule_labels", []),
        "semantic_rule_labels_json": ("semantic_rule_labels", []),
        "technique_ids_json": ("technique_ids", []),
    }
    for column, (name, default) in json_fields.items():
        item[name] = json_value(item.pop(column, None), default)
    item["latest_waf_test"] = latest_waf_run("cross", item.get("id")) if latest_waf_test is _MISSING else latest_waf_test
    item["verification_status"] = (
        verification_status_for("cross", item.get("id"))
        if verification_status is _MISSING
        else verification_status
    )
    return item


def candidate_page_view(agent: Literal["semantic", "encoding", "cross"], view: Any) -> Any:
    """Build a page mapper that uses one latest-WAF + one verification-status lookup for all its rows."""
    def map_records(records: list[sqlite3.Row]) -> list[dict[str, Any]]:
        latest_by_candidate = latest_waf_runs(agent, [record["id"] for record in records])
        verification_by_candidate = latest_verification_jobs(agent, [record["id"] for record in records])
        return [
            view(record, latest_by_candidate.get(record["id"]), verification_by_candidate.get(record["id"]))
            for record in records
        ]

    return map_records


def paginate_candidate_records(
    sql: str,
    params: tuple[Any, ...],
    limit: int | None,
    cursor: int,
    agent: Literal["semantic", "encoding", "cross"],
    view: Any,
) -> list[dict[str, Any]] | dict[str, Any]:
    """Paginate candidate rows while avoiding N+1 latest-run lookups."""
    def page_items(records: list[sqlite3.Row]) -> list[dict[str, Any]]:
        return candidate_page_view(agent, view)(records)

    if limit is None:
        return page_items(db_rows(sql, params))
    page_size = min(limit, MAX_PAGE_SIZE)
    total = db_row(f"SELECT COUNT(*) AS count FROM ({sql})", params)["count"]
    records = db_rows(f"{sql} LIMIT ? OFFSET ?", (*params, page_size, cursor))
    items = page_items(records)
    next_cursor = cursor + len(items)
    return {"items": items, "total": total, "next_cursor": next_cursor if next_cursor < total else None}


def success_sample_view(source: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(source)
    item["provenance"] = json_value(item.pop("provenance_json", None), {})
    item.pop("status", None)
    return item


def update_candidate_record(
    agent: Literal["semantic", "encoding"],
    candidate_id: str,
    body: CandidateUpdateRequest,
) -> dict[str, Any]:
    if body.status not in CANDIDATE_STATUSES or body.status == "archived":
        raise HTTPException(status_code=422, detail="Unknown candidate status")
    table = "candidates" if agent == "semantic" else "encoding_candidates"
    transitions = {
        "pending_test": {"test_success", "test_failed", "rejected"},
        "test_success": {"pending_test"},
        "test_failed": {"pending_test"},
        "rejected": set(),
        "archived": set(),
    }
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            record = connection.execute(
                f"SELECT * FROM {table} WHERE id = ?", (candidate_id,)
            ).fetchone()
            if not record:
                raise HTTPException(status_code=404, detail="Candidate not found")
            candidate = dict(record)
            if body.status not in transitions.get(candidate["status"], set()):
                raise HTTPException(
                    status_code=409,
                    detail="The current candidate status does not allow this transition",
                )
            base_record = connection.execute(
                "SELECT * FROM payloads WHERE id = ?", (candidate["base_payload_id"],)
            ).fetchone()
            if not base_record:
                raise HTTPException(status_code=409, detail="Base Payload not found")
            connection.execute(
                f"UPDATE {table} SET status = ?, test_note = ?, updated_at = ? WHERE id = ?",
                (body.status, body.test_note, utc_now(), candidate_id),
            )
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()

    if agent == "semantic":
        records = db_rows(
            """
            SELECT candidates.*, payloads.name AS base_payload_name,
                   payloads.vulnerability AS base_vulnerability,
                   payloads.target AS base_target, payloads.difficulty AS base_difficulty
            FROM candidates JOIN payloads ON candidates.base_payload_id = payloads.id
            WHERE candidates.id = ?
            """,
            (candidate_id,),
        )
        return candidate_view(records[0])
    records = db_rows(
        """
        SELECT encoding_candidates.*, payloads.name AS base_payload_name,
               payloads.vulnerability AS base_vulnerability,
               payloads.target AS base_target, payloads.difficulty AS base_difficulty
        FROM encoding_candidates
        JOIN payloads ON encoding_candidates.base_payload_id = payloads.id
        WHERE encoding_candidates.id = ?
        """,
        (candidate_id,),
    )
    return encoding_candidate_view(records[0])


def delete_candidate_record(
    agent: Literal["semantic", "encoding"], candidate_id: str
) -> None:
    table = "candidates" if agent == "semantic" else "encoding_candidates"
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            candidate = connection.execute(
                f"SELECT status FROM {table} WHERE id = ?", (candidate_id,)
            ).fetchone()
            if not candidate:
                raise HTTPException(status_code=404, detail="Candidate not found")
            if candidate["status"] == "archived":
                raise HTTPException(
                    status_code=409,
                    detail="Archived candidates cannot be deleted from the queue",
                )

            # 级联清理检验任务与库记录
            connection.execute(
                "DELETE FROM verification_jobs WHERE source_agent = ? AND source_candidate_id = ?",
                (agent, candidate_id),
            )
            connection.execute(
                "DELETE FROM bypass_library WHERE source_agent = ? AND source_candidate_id = ?",
                (agent, candidate_id),
            )
            connection.execute(
                "DELETE FROM block_library WHERE source_agent = ? AND source_candidate_id = ?",
                (agent, candidate_id),
            )
            connection.execute(
                "DELETE FROM unverified_library WHERE source_agent = ? AND source_candidate_id = ?",
                (agent, candidate_id),
            )
            connection.execute(f"DELETE FROM {table} WHERE id = ?", (candidate_id,))
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()


def archive_candidate_record(
    agent: Literal["semantic", "encoding"], candidate_id: str
) -> dict[str, Any]:
    table = "candidates" if agent == "semantic" else "encoding_candidates"
    prefix = "语义迭代" if agent == "semantic" else "编码迭代"
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            candidate_record = connection.execute(
                f"SELECT * FROM {table} WHERE id = ?", (candidate_id,)
            ).fetchone()
            if not candidate_record:
                raise HTTPException(status_code=404, detail="Candidate not found")
            candidate = dict(candidate_record)
            candidate_status = candidate["status"]
            if candidate_status not in {"test_success", "test_failed"}:
                raise HTTPException(
                    status_code=409,
                    detail="Only candidates with a completed test result can be archived",
                )
            archive_outcome = (
                "bypass_success" if candidate_status == "test_success" else "bypass_failure"
            )
            base_record = connection.execute(
                "SELECT * FROM payloads WHERE id = ?", (candidate["base_payload_id"],)
            ).fetchone()
            if not base_record:
                raise HTTPException(status_code=409, detail="Base Payload not found")
            base = dict(base_record)
            guidance = base
            if base.get("is_pool_snapshot"):
                source_record = connection.execute(
                    """
                    SELECT payloads.* FROM iteration_pool_items
                    JOIN payloads ON payloads.id = iteration_pool_items.source_payload_id
                    WHERE iteration_pool_items.snapshot_payload_id = ?
                    """,
                    (base["id"],),
                ).fetchone()
                if source_record:
                    guidance = dict(source_record)

            used_directions = json_value(candidate.get("used_direction_ids_json"), [])
            next_directions = json_value(candidate.get("next_directions_json"), [])
            used_technique_ids = json_value(candidate.get("technique_ids_json"), [])
            base_metadata = json_value(base.get("iteration_metadata_json"), {})
            lineage = list(base_metadata.get("direction_lineage", []))
            lineage_entry: dict[str, Any] = {
                "agent": agent,
                "candidate_id": candidate_id,
                "archive_outcome": archive_outcome,
                "used_direction_ids": used_directions,
                "used_technique_ids": used_technique_ids,
            }
            if agent == "semantic":
                lineage_entry["part_operations"] = json_value(
                    candidate.get("part_operations_json"), []
                )
            lineage.append(lineage_entry)
            metadata: dict[str, Any] = {
                **base_metadata,
                "source_agent": agent,
                "archive_outcome": archive_outcome,
                "used_direction_ids": used_directions,
                "used_technique_ids": used_technique_ids,
                "direction_lineage": lineage,
                "next_directions": next_directions,
            }
            if agent == "semantic":
                metadata.update(
                    {
                        "rule_labels": json_value(candidate.get("rule_labels_json"), []),
                        "base_parts": json_value(candidate.get("base_parts_json"), []),
                        "candidate_parts": json_value(candidate.get("candidate_parts_json"), []),
                    }
                )
            else:
                metadata.update(
                    {
                        "encoding_chain": json_value(candidate.get("encoding_chain_json"), []),
                        "decode_path": json_value(candidate.get("decode_path_json"), []),
                        "origin": candidate.get("origin") or "generated",
                    }
                )

            payload_id = str(uuid.uuid4())
            timestamp = utc_now()
            archived_values = {
                "id": payload_id,
                "name": f"{prefix} · {payload_internal_name(candidate['content'])}",
                "vulnerability": base["vulnerability"],
                "category": base["category"],
                "delivery": candidate["delivery"],
                "target": base["target"],
                "difficulty": base["difficulty"],
                "content": candidate["content"],
                "created_at": timestamp,
                "archived_from_candidate_id": candidate_id,
                "source_agent": agent,
                "source_candidate_id": candidate_id,
                "iteration_metadata_json": json.dumps(metadata, ensure_ascii=False),
                "is_pool_snapshot": 0,
                "severity": base.get("severity") or "中危",
                "is_executable": 1,
                "usage_method": guidance.get("usage_method") or "",
                "success_indicators": guidance.get("success_indicators") or "",
                "is_deleted": 0,
            }
            table_columns = {column[1] for column in connection.execute("PRAGMA table_info(payloads)")}
            insert_columns = [column for column in archived_values if column in table_columns]
            connection.execute(
                f"INSERT INTO payloads ({', '.join(insert_columns)}) VALUES ({', '.join('?' for _ in insert_columns)})",
                tuple(archived_values[column] for column in insert_columns),
            )
            connection.execute(
                f"UPDATE {table} SET status = 'archived', updated_at = ? WHERE id = ?",
                (timestamp, candidate_id),
            )
            archived_record = connection.execute(
                "SELECT * FROM payloads WHERE id = ?", (payload_id,)
            ).fetchone()
            archived = dict(archived_record)
            if agent == "semantic" and candidate_status == "test_success":
                new_source_id = str(uuid.uuid4())
                connection.execute(
                    """
                    INSERT OR IGNORE INTO cross_sources (
                        id, archived_payload_id, semantic_candidate_id, name,
                        vulnerability, category, delivery, target, difficulty,
                        content, rule_labels_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_source_id,
                        payload_id,
                        candidate_id,
                        archived["name"],
                        archived["vulnerability"],
                        archived["category"],
                        archived["delivery"],
                        archived["target"],
                        archived["difficulty"],
                        archived["content"],
                        candidate.get("rule_labels_json") or "[]",
                        timestamp,
                    ),
                )
                # cross_source 一经产生即进入待交叉池（不再有「待交叉来源」展示区）
                _auto_enqueue_cross_source(connection, new_source_id)
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise HTTPException(
                status_code=409, detail="This candidate has already been archived"
            ) from exc
        finally:
            connection.close()

    result = payload_view(archived)
    result["source_agent"] = agent
    result["source_candidate_id"] = candidate_id
    result["latest_waf_test"] = latest_waf_run(agent, candidate_id)
    return result


def report_image_view(source: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(source)
    item["content_url"] = f"/api/report-images/{item['id']}/content"
    return item


def report_view(source: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(source)
    item["provenance"] = json_value(item.pop("provenance_json", None), {})
    item["source_status"] = item.pop("source_status", None) or "deleted"
    images = db_rows(
        "SELECT * FROM report_images WHERE report_id = ? ORDER BY sort_order, created_at",
        (item["id"],),
    )
    item["images"] = [report_image_view(image) for image in images]
    return item


def waf_candidate_source(
    connection: sqlite3.Connection,
    agent: Literal["semantic", "encoding", "cross"],
    candidate_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if agent == "semantic":
        table = "candidates"
    elif agent == "encoding":
        table = "encoding_candidates"
    else:
        table = "cross_candidates"

    candidate_record = connection.execute(
        f"SELECT * FROM {table} WHERE id = ?", (candidate_id,)
    ).fetchone()
    if not candidate_record:
        raise HTTPException(status_code=404, detail="Candidate not found")
    candidate = dict(candidate_record)

    if agent == "cross":
        source_record = connection.execute(
            "SELECT * FROM cross_sources WHERE id = ?",
            (candidate["cross_source_id"],),
        ).fetchone()
        if not source_record:
            raise HTTPException(status_code=404, detail="Cross iteration source not found")
        source = dict(source_record)
        base = {
            "name": source["name"],
            "vulnerability": source["vulnerability"],
            "target": source["target"],
            "content": source["content"],
        }
        return candidate, base

    base_record = connection.execute(
        "SELECT * FROM payloads WHERE id = ?", (candidate["base_payload_id"],)
    ).fetchone()
    if not base_record:
        raise HTTPException(status_code=409, detail="Base Payload not found")
    return candidate, dict(base_record)


def run_waf_test(run_id: str) -> None:
    with WAF_TEST_LOCK:
        with DB_LOCK:
            connection = sqlite3.connect(DB_PATH)
            connection.row_factory = sqlite3.Row
            try:
                run_record = connection.execute(
                    "SELECT * FROM waf_test_runs WHERE id = ?", (run_id,)
                ).fetchone()
                if not run_record:
                    return
                run = dict(run_record)
                connection.execute(
                    "UPDATE waf_test_runs SET status = 'running', started_at = ? WHERE id = ?",
                    (utc_now(), run_id),
                )
                connection.commit()
            finally:
                connection.close()

        try:
            waf_preflight(str(CONFIG_PATH))
            if run["vulnerability"] == "xss":
                outcome = run_xss_test(str(CONFIG_PATH), run["payload_snapshot"])
            else:
                verification_spec = None
                if run["agent"] == "semantic":
                    candidate = db_row(
                        "SELECT verification_spec_json FROM candidates WHERE id = ?",
                        (run["candidate_id"],),
                    )
                    if candidate:
                        verification_spec = json_value(candidate["verification_spec_json"], None)
                outcome = run_http_test(
                    str(CONFIG_PATH),
                    run["vulnerability"],
                    run["payload_snapshot"],
                    verification_spec,
                )
            status = "failed" if outcome.get("result") == "request_error" else "completed"
            values = (
                status,
                outcome.get("result"),
                outcome.get("evidence"),
                outcome.get("request_summary"),
                outcome.get("response_excerpt"),
                outcome.get("http_status"),
                outcome.get("evidence") if status == "failed" else None,
                utc_now(),
                run_id,
            )
        except Exception as error:
            error_message = (
                "DVWA 测试场连接超时，请检查 WAF_DVWA_BASE_URL 和网络连通性"
                if isinstance(error, httpx.TimeoutException)
                else str(error)
            )
            values = (
                "failed",
                "request_error",
                error_message,
                None,
                None,
                None,
                error_message[:1000],
                utc_now(),
                run_id,
            )

        with DB_LOCK:
            connection = sqlite3.connect(DB_PATH)
            try:
                connection.execute(
                    """
                    UPDATE waf_test_runs
                    SET status = ?, result = ?, evidence = ?, request_summary = ?,
                        response_excerpt = ?, http_status = ?, error_message = ?, completed_at = ?
                    WHERE id = ?
                    """,
                    values,
                )
                connection.commit()
            finally:
                connection.close()


# =============================================================================
# 独立 LLM 检验 Agent：自动入队 + 后台受控并发 worker + bypass/block 库落库
# =============================================================================

VERIFIABLE_VULNERABILITIES = {"command-injection", "sql-injection", "xss", "log4j", "file-upload"}


def enqueue_verification(
    connection: sqlite3.Connection,
    agent: str,
    candidate_id: str,
    candidate_kind: str,
    base: dict[str, Any],
    content: str,
    delivery: str,
    *,
    execution_goal_id: str | None = None,
    verification_spec: dict[str, Any] | None = None,
    technique_ids: list[str] | None = None,
) -> str | None:
    """把一条 candidate 写入 verification_jobs（幂等 upsert）。

    不在此 commit——由调用方的 ``with DB_LOCK:`` 事务统一提交。
    返回 job id；未启用自动检验或不可验证的漏洞类型时返回 None。

    execution_goal_id / verification_spec / technique_ids 来自候选自身（非 base
    payloads）；execution_goal_id 仅当命中服务端目录时才落库，否则存 NULL。
    """
    if not _env_bool("AUTO_VERIFY", True):
        return None
    vulnerability = base.get("vulnerability", "")
    if vulnerability not in VERIFIABLE_VULNERABILITIES:
        return None
    normalized_goal = normalize_execution_goal_id(execution_goal_id or "")
    stored_goal = normalized_goal if normalized_goal in EXECUTION_GOAL_CATALOG else None
    spec_json = json.dumps(verification_spec, ensure_ascii=False) if verification_spec else None
    technique_json = json.dumps(
        [tid for tid in (technique_ids or []) if isinstance(tid, str)], ensure_ascii=False
    )
    timestamp = utc_now()
    job_id = str(uuid.uuid4())
    connection.execute(
        """
        INSERT INTO verification_jobs (
            id, source_agent, source_candidate_id, candidate_kind, base_name,
            source_payload_id, vulnerability, payload_snapshot, delivery, status, target_key,
            raw_evidence_json, verdict_json, bypass_verdict, execution_verdict,
            failure_stage, library_record_id, error_message, attempt_count,
            verification_spec_json, execution_goal_id, sent_payload_snapshot,
            payload_fidelity, route_hint_json, technique_ids_json,
            created_at, started_at, completed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'waiting', '', NULL, NULL, NULL, NULL,
                  NULL, NULL, NULL, 0, ?, ?, NULL, 'exact', NULL, ?, ?, NULL, NULL)
        ON CONFLICT(source_agent, source_candidate_id) DO UPDATE SET
            source_payload_id = excluded.source_payload_id,
            payload_snapshot = excluded.payload_snapshot,
            delivery = excluded.delivery,
            status = 'waiting',
            error_message = NULL,
            verification_spec_json = excluded.verification_spec_json,
            execution_goal_id = excluded.execution_goal_id,
            sent_payload_snapshot = NULL,
            payload_fidelity = 'exact',
            route_hint_json = NULL,
            technique_ids_json = excluded.technique_ids_json,
            created_at = excluded.created_at
        """,
        (
            job_id,
            agent,
            candidate_id,
            candidate_kind,
            base.get("name", ""),
            base.get("id", "") or None,
            vulnerability,
            content,
            delivery,
            spec_json,
            stored_goal,
            technique_json,
            timestamp,
        ),
    )
    return job_id


def _wake_verification_workers() -> None:
    """唤醒所有空闲 worker（入队 / reverify 后调用）。"""
    with VERIFICATION_WAKE:
        VERIFICATION_WAKE.notify_all()


def _feed_verification_queue(connection: sqlite3.Connection) -> int:
    """把 waiting 任务按容量推进为 queued（限容内队列 feeder）。

    在调用方已持有 DB_LOCK 的连接上执行；返回推进条数。
    内队列容量 = VERIFY_QUEUE_CAPACITY（默认 5），已入队(queued)+运行中(running) 不超容量。
    """
    capacity = _env_positive_int("VERIFY_QUEUE_CAPACITY", 5)
    fed = 0
    while True:
        inflight = connection.execute(
            "SELECT COUNT(*) AS n FROM verification_jobs WHERE status IN ('queued', 'running')"
        ).fetchone()
        inflight_n = inflight[0] if inflight else 0
        if inflight_n >= capacity:
            break
        record = connection.execute(
            """
            SELECT id FROM verification_jobs
            WHERE status = 'waiting'
            ORDER BY created_at ASC LIMIT 1
            """
        ).fetchone()
        if record is None:
            break
        connection.execute(
            "UPDATE verification_jobs SET status = 'queued' WHERE id = ?",
            (record[0],),
        )
        fed += 1
    return fed


def _feed_verification_queue_locked() -> int:
    """独立事务版 feeder（worker 循环 / 启动恢复用）。"""
    with DB_LOCK:
        connection = connect()
        try:
            fed = _feed_verification_queue(connection)
            connection.commit()
            return fed
        finally:
            connection.close()


def _claim_verification_job() -> dict[str, Any] | None:
    """用独立连接 + BEGIN IMMEDIATE 原子认领一条 queued 任务。

    认领不持 DB_LOCK（避免引入单写瓶颈）；多 worker / 有限多进程竞争时，
    数据库锁冲突返回 None（由其他 worker 抢到），其余异常向上抛。
    """
    connection = sqlite3.connect(DB_PATH, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA busy_timeout=2000")
        connection.execute("BEGIN IMMEDIATE")
        record = connection.execute(
            """
            SELECT * FROM verification_jobs
            WHERE status = 'queued'
            ORDER BY created_at ASC LIMIT 1
            """
        ).fetchone()
        if record is None:
            connection.rollback()
            return None
        job = dict(record)
        connection.execute(
            """
            UPDATE verification_jobs
            SET status = 'running', started_at = ?, attempt_count = attempt_count + 1
            WHERE id = ?
            """,
            (utc_now(), job["id"]),
        )
        connection.commit()
        return job
    except sqlite3.OperationalError as error:
        if "locked" in str(error).lower():
            return None
        raise
    finally:
        connection.close()


def _recover_stale_verification_jobs() -> None:
    """启动时把遗留 running 任务恢复为 queued，并按容量推进 waiting。"""
    with DB_LOCK:
        connection = connect()
        try:
            connection.execute(
                """
                UPDATE verification_jobs
                SET status = 'queued', started_at = NULL, attempt_count = attempt_count + 1
                WHERE status = 'running'
                """
            )
            _feed_verification_queue(connection)
            connection.commit()
        finally:
            connection.close()


def _recover_stale_generation_tasks() -> None:
    """启动时把遗留 running/queued 的生成任务标为 failed。

    服务异常退出（如进程被 kill）会留下卡在 running/queued 的语义/编码/交叉
    任务，且其部分候选可能已落库。这些任务不会自动恢复执行（生成 LLM 调用
    无重入语义），故统一标记为 failed，并在 error_message 说明原因，避免前端
    出现永久 running 的任务。
    """
    timestamp = utc_now()
    with DB_LOCK:
        connection = connect()
        try:
            for table in ("generation_tasks", "encoding_tasks", "cross_tasks"):
                connection.execute(
                    f"UPDATE {table} SET status = 'failed', error_message = ?, completed_at = ? "
                    "WHERE status IN ('running', 'queued')",
                    ("服务重启前中断（进程退出），已标记为 failed", timestamp),
                )
            connection.commit()
        finally:
            connection.close()


def _start_verification_pool() -> None:
    """启动固定数量的常驻 daemon worker（并发数来自 VERIFY_CONCURRENCY）。"""
    global VERIFICATION_POOL_STARTED, VERIFICATION_WORKERS
    with VERIFICATION_POOL_LOCK:
        if VERIFICATION_POOL_STARTED:
            return
        VERIFICATION_POOL_STARTED = True
    concurrency = _env_positive_int("VERIFY_CONCURRENCY", 3)
    _recover_stale_verification_jobs()
    workers = [
        threading.Thread(target=_verification_worker_loop, args=(worker_id,), daemon=True)
        for worker_id in range(concurrency)
    ]
    VERIFICATION_WORKERS.extend(workers)
    for worker in workers:
        worker.start()


def _shutdown_verification_pool() -> None:
    """设置停机信号并唤醒所有 worker，停止领取新任务。"""
    global VERIFICATION_WORKERS
    VERIFICATION_STOP_EVENT.set()
    with VERIFICATION_WAKE:
        VERIFICATION_WAKE.notify_all()
    for worker in VERIFICATION_WORKERS:
        worker.join(timeout=3.0)
    VERIFICATION_WORKERS = []


def _verification_worker_loop(worker_id: int) -> None:
    """常驻 worker：认领 queued 任务执行；空闲时等待通知，不退出。"""
    while not VERIFICATION_STOP_EVENT.is_set():
        job = _claim_verification_job()
        if job is None:
            # 空闲时也推进一次 waiting → queued，避免「无 queued/running 时
            # waiting 永久卡住」：服务重启后可能没有队列头任务来触发 feeder。
            try:
                _feed_verification_queue_locked()
            except Exception:  # noqa: BLE001
                LOGGER.exception("verification feeder failed worker=%s", worker_id)
            with VERIFICATION_WAKE:
                # 空闲等待，2s 兜底唤醒以处理漏通知。
                VERIFICATION_WAKE.wait(timeout=2.0)
            continue
        try:
            _process_verification_job(job)
        except Exception as error:  # noqa: BLE001
            LOGGER.exception("verification worker %s job=%s", worker_id, job.get("id"))
            try:
                _fail_verification_job(job, f"worker 异常：{error}")
            except Exception:  # noqa: BLE001
                pass
        # 处理完一条后，按容量把 waiting 推进为 queued。
        try:
            _feed_verification_queue_locked()
        except Exception:  # noqa: BLE001
            LOGGER.exception("verification feeder failed worker=%s", worker_id)
        _wake_verification_workers()


def _oob_listener_url() -> str:
    """返回 OOB 监听服务基地址（未配置则为空串）。"""
    return os.getenv("OOB_LISTENER_URL", "").strip().rstrip("/")


def _expand_oob_placeholder(content: str, token: str) -> tuple[str, str]:
    """仅展开 ``{{OOB_CALLBACK_URL}}`` 占位符为带 token 的回调地址。

    返回 ``(替换后内容, fidelity)``；无占位符时原样返回 ``(content, "exact")``。
    绝不透明替换外部 URL 或追加外发脚本。
    """
    oob = _oob_listener_url()
    if not oob:
        return content, "exact"
    if "{{OOB_CALLBACK_URL}}" in content:
        callback = f"{oob}/?id={token}&c="
        return content.replace("{{OOB_CALLBACK_URL}}", callback), "template_expanded"
    return content, "exact"


def _check_oob_callback(token: str, wait_seconds: float) -> bool:
    """轮询 OOB 服务，返回该 token 是否收到回连。"""
    oob = _oob_listener_url()
    if not oob:
        return False
    check_url = f"{oob}/api/oob/check?token={token}"
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        try:
            response = httpx.get(check_url, timeout=3)
            if response.status_code == 200:
                payload = response.json()
                if payload.get("found"):
                    return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(1.0)
    return False


def _server_verification_spec(job: dict[str, Any]) -> tuple[dict[str, Any] | None, bool]:
    """从任务快照的 execution_goal_id 解析服务端权威 verification spec。

    返回 ``(spec, deterministic_verifier_present)``；只有命中服务端目录的 goal
    才产生确定性验证器。LLM 咨询性 spec 不在此解析。
    """
    goal_id = normalize_execution_goal_id(job.get("execution_goal_id") or "")
    if goal_id in EXECUTION_GOAL_CATALOG:
        try:
            return verification_for_goal(goal_id), True
        except ValueError:
            return None, False
    return None, False


def _route_hint_from_verdict(verdict: dict[str, Any], vulnerability: str) -> int | None:
    """仅保留契合漏洞的正整数路由提示（sql -> lesson；upload -> passNN）。"""
    hint = verdict.get("lesson_hint")
    if not isinstance(hint, int) or isinstance(hint, bool) or hint <= 0:
        return None
    if vulnerability == "sql-injection":
        return hint
    if vulnerability == "file-upload" and (hint in PASS_ROUTES or hint in PHP_PASS_ROUTES):
        return hint
    return None


def _encoding_chain_reversible(candidate: dict[str, Any], base: dict[str, Any], candidate_kind: str) -> tuple[bool, str]:
    """判断编码/交叉候选是否满足「链长 ≤3 且可逆重放」，作为确定性验证成功依据。

    仅对 encoding_candidates / cross_candidates 有意义（semantic 无 encoding_chain）。
    """
    del candidate_kind  # 保留参数用于调用方语义；判定仅依赖 candidate/base。
    chain = json_value(candidate.get("encoding_chain_json"), None)
    if not isinstance(chain, list) or not (1 <= len(chain) <= 3):
        return False, "编码链为空或超过 3 层"
    base_payload = base.get("content", "")
    if not base_payload:
        return False, "缺少可逆重放的基准 payload"
    try:
        _verify_reversible(base_payload, candidate.get("content", ""), chain)
    except (ValueError, UnicodeError) as error:
        return False, f"逆向解码失败：{error}"
    return True, f"编码链 {len(chain)} 层可逆重放确认"


def _process_verification_job(job: dict[str, Any]) -> None:
    """对单个 job 执行：解析 candidate → 靶场发请求 → 确定性判定 + LLM 分析 → 落库。"""
    agent = job["source_agent"]
    candidate_id = job["source_candidate_id"]
    candidate_kind = job["candidate_kind"]
    vulnerability = job["vulnerability"]
    content = job["payload_snapshot"]

    try:
        candidate, base = _resolve_candidate_for_verification(
            agent, candidate_id, candidate_kind, content, vulnerability
        )
    except HTTPException as error:
        _fail_verification_job(job, f"解析候选失败：{error.detail}")
        return

    # 优先使用任务快照的 target_key 并校验其漏洞类型；不匹配或为空回退默认。
    try:
        target_key, adapter = resolve_adapter(vulnerability, job.get("target_key") or "")
    except ValueError as error:
        _fail_verification_job(job, str(error))
        return

    # 服务端权威 verification spec（仅目录中的 marker/regex/combo 可产生确定性成功）。
    server_spec, deterministic_verifier_present = _server_verification_spec(job)

    # 判断是否无法自动闭环（外带/盲注等），决定 execution 是否可标 unverified。
    exec_unverifiable = is_unverifiable_payload(content, vulnerability)

    # OOB 外带若配置了监听，且 payload 显式含占位符，才展开为带 token 的回调地址。
    oob_token: str | None = None
    payload_to_send, fidelity = content, "exact"
    if vulnerability in {"xss", "log4j"} and exec_unverifiable and _oob_listener_url():
        oob_token = uuid.uuid4().hex
        payload_to_send, fidelity = _expand_oob_placeholder(content, oob_token)

    # 1. 靶场发真实请求（网络/浏览器，期间不持 DB_LOCK）。
    route_hint = json_value(job.get("route_hint_json"), None)
    try:
        kwargs: dict[str, Any] = {
            "candidate_kind": candidate_kind,
            "delivery": job.get("delivery", ""),
            "verification_spec": server_spec,
        }
        if route_hint:
            kwargs["lesson_hint"] = route_hint
        evidence: TargetEvidence = adapter(str(CONFIG_PATH), payload_to_send, base, **kwargs)
    except Exception as error:  # noqa: BLE001
        _fail_verification_job(job, f"靶场请求异常：{error}")
        return

    # 2. 若启用了 OOB（仅当占位符已展开），轮询是否收到回连。
    oob_confirmed = False
    if oob_token and fidelity == "template_expanded" and evidence.outcome not in {
        "waf_blocked",
        "request_error",
        "unsupported_context",
    }:
        wait = _env_positive_int("OOB_WAIT_SECONDS", 8)
        oob_confirmed = _check_oob_callback(oob_token, float(wait))

    # 3. 确定性提示 + LLM 分析（LLM 不决定 verdict 值）。
    deterministic_hints = {
        "adapter_outcome": evidence.outcome,
        "adapter_evidence": evidence.evidence,
    }

    # 编码/交叉候选：放行后若编码链 ≤3 层且可逆重放，则确定性判「验证成功」。
    encoding_reversible_confirmed = False
    if (
        evidence.outcome == "application_response"
        and candidate_kind in {"encoding_candidates", "cross_candidates"}
    ):
        reversible, reversible_reason = _encoding_chain_reversible(candidate, base, candidate_kind)
        if reversible:
            evidence = TargetEvidence(
                target_key=evidence.target_key,
                vulnerability=evidence.vulnerability,
                request_summary=evidence.request_summary,
                http_status=evidence.http_status,
                response_excerpt=evidence.response_excerpt,
                response_headers=evidence.response_headers,
                outcome="execution_confirmed",
                evidence=reversible_reason,
                baseline_excerpt=evidence.baseline_excerpt,
                sent_body=evidence.sent_body,
                request_digest=evidence.request_digest,
            )
            encoding_reversible_confirmed = True

    if oob_confirmed:
        # 收到 OOB 回连 = 确定性执行成功。
        evidence = TargetEvidence(
            target_key=evidence.target_key,
            vulnerability=evidence.vulnerability,
            request_summary=evidence.request_summary,
            http_status=evidence.http_status,
            response_excerpt=evidence.response_excerpt,
            response_headers=evidence.response_headers,
            outcome="execution_confirmed",
            evidence=f"OOB 回连确认（token={oob_token}）",
            baseline_excerpt=evidence.baseline_excerpt,
            sent_body=evidence.sent_body,
            request_digest=evidence.request_digest,
        )
        verdict = normalize_verdict(None, "execution_confirmed")
    elif encoding_reversible_confirmed:
        verdict = normalize_verdict(None, "execution_confirmed")
    else:
        verdict = _call_verification_judge(
            evidence, payload_to_send, vulnerability, deterministic_hints,
            agent, candidate_id, exec_unverifiable,
            deterministic_verifier_present=deterministic_verifier_present,
            fidelity=fidelity,
            delivery=job.get("delivery", ""),
            execution_goal_id=job.get("execution_goal_id", ""),
            server_spec=server_spec,
        )

    # 4. 落库 + 同步 bypass/block/unverified 库。
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            _persist_verification_result(
                connection, job, evidence, verdict, base,
                fidelity=fidelity, server_spec=server_spec,
                deterministic_verifier_present=deterministic_verifier_present,
            )
            connection.commit()
        except Exception as error:  # noqa: BLE001
            connection.rollback()
            LOGGER.exception("verification persist failed job=%s", job["id"])
            _fail_verification_job_locked(connection, job, f"落库异常：{error}")
        finally:
            connection.close()


def _resolve_candidate_for_verification(
    agent: str,
    candidate_id: str,
    candidate_kind: str,
    content: str,
    vulnerability: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """解析 candidate 与 base payload（复用 waf_candidate_source）。

    找不到 candidate 时回退构造一个最小 base（保留 payload 内容与漏洞类型），
    避免因候选被删导致检验中断。
    """
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        return waf_candidate_source(connection, agent, candidate_id)  # type: ignore[arg-type]
    except HTTPException:
        base = {"name": "", "vulnerability": vulnerability, "content": content}
        return {"id": candidate_id, "content": content}, base
    finally:
        connection.close()


def _call_verification_judge(
    evidence: TargetEvidence,
    content: str,
    vulnerability: str,
    deterministic_hints: dict[str, Any],
    agent: str,
    candidate_id: str,
    exec_unverifiable: bool = False,
    *,
    deterministic_verifier_present: bool = False,
    fidelity: str = "exact",
    delivery: str = "",
    execution_goal_id: str = "",
    server_spec: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """调用 LLM 做分析并归一化；确定性结果短路，LLM 不决定 verdict 值。"""
    # 确定性短路：无需 LLM 即可定论。
    if evidence.outcome in {
        "waf_blocked", "request_error", "unsupported_context", "execution_confirmed",
    }:
        return normalize_verdict(None, evidence.outcome)

    config = _verify_llm_config()
    if not _llm_config_complete(config):
        # 无 LLM 配置时，仅凭确定性真值表给出保守判定。
        return normalize_verdict(
            None, evidence.outcome, exec_unverifiable=exec_unverifiable,
            deterministic_verifier_present=deterministic_verifier_present,
        )

    system_prompt = build_judge_system_prompt()
    user_message = build_judge_user_message(
        evidence, content, vulnerability, deterministic_hints,
        sent_payload=content, payload_fidelity=fidelity, delivery=delivery,
        execution_goal_id=execution_goal_id, verification_spec=server_spec,
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]
    try:
        response = _post_chat_completion(config, messages)
        response.raise_for_status()
    except Exception as error:  # noqa: BLE001
        LOGGER.warning("verification judge LLM failed job=%s/%s: %s", agent, candidate_id, error)
        return check_error_verdict("LLM 请求失败，按检验异常处理")

    raw_message = response.json().get("choices", [{}])[0].get("message", {}).get("content", "")
    parsed = parse_verdict(raw_message, _extract_json_payload)
    if parsed is None:
        return check_error_verdict("LLM 输出不可解析，按检验异常处理")
    return normalize_verdict(
        parsed, evidence.outcome, exec_unverifiable=exec_unverifiable,
        deterministic_verifier_present=deterministic_verifier_present,
    )


def _verify_llm_config() -> dict[str, str]:
    """检验 Agent 专用 LLM 配置，缺省回退到通用 LLM_*。"""
    verify = _llm_config("VERIFY_LLM", "Verification-Judge")
    if _llm_config_complete(verify):
        return verify
    return _llm_config("LLM", "OpenAI-compatible")


def _derive_labels(verdict: dict[str, Any]) -> list[str]:
    """由 verdict 派生标签列表（绕过状态 + 验证状态）。"""
    labels: list[str] = []
    bypass = verdict.get("bypass_verdict")
    execution = verdict.get("execution_verdict")
    if bypass == "bypass":
        labels.append("绕过成功")
    elif bypass == "block":
        labels.append("绕过失败")
    # bypass == "error" 不追加绕过标签
    if execution == "confirmed":
        labels.append("验证成功")
    elif execution == "not_confirmed":
        labels.append("验证失败")
    elif execution == "unverified":
        labels.append("未验证")
    return labels


def _record_observation(
    connection: sqlite3.Connection,
    job: dict[str, Any],
    base: dict[str, Any],
    evidence: TargetEvidence,
    verdict: dict[str, Any],
    timestamp: str,
    *,
    fidelity: str = "exact",
    server_spec: dict[str, Any] | None = None,
    deterministic_verifier_present: bool = False,
) -> None:
    """插入一条不可变历史观测。"""
    import hashlib

    bypass_success = 1 if verdict.get("bypass_verdict") == "bypass" else 0
    verification_success = 1 if verdict.get("execution_verdict") == "confirmed" else 0
    labels = _derive_labels(verdict)
    raw_evidence = {
        "target_key": evidence.target_key,
        "request_summary": evidence.request_summary,
        "http_status": evidence.http_status,
        "response_excerpt": evidence.response_excerpt,
        "response_headers": evidence.response_headers,
        "outcome": evidence.outcome,
        "evidence": evidence.evidence,
        "baseline_excerpt": evidence.baseline_excerpt,
        "original_payload_digest": hashlib.sha256(
            job.get("payload_snapshot", "").encode("utf-8")
        ).hexdigest(),
        "sent_payload_snapshot": evidence.sent_body,
        "payload_fidelity": fidelity,
        "final_request_digest": evidence.request_digest,
        "execution_goal_id": job.get("execution_goal_id"),
        "verification_spec": server_spec,
        "deterministic_verifier_present": deterministic_verifier_present,
        "analysis": verdict.get("analysis"),
    }
    connection.execute(
        """
        INSERT INTO kb_observations (
            id, source_payload_id, source_agent, source_candidate_id, candidate_kind,
            vulnerability, target_key, bypass_success, verification_success, labels_json,
            failure_stage, raw_evidence_json, verdict_json, target_profile_json,
            waf_policy_version, backend_version, technique_ids_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            base.get("id", ""),
            job["source_agent"],
            job["source_candidate_id"],
            job["candidate_kind"],
            job["vulnerability"],
            evidence.target_key,
            bypass_success,
            verification_success,
            json.dumps(labels, ensure_ascii=False),
            verdict.get("failure_stage"),
            json.dumps(raw_evidence, ensure_ascii=False),
            json.dumps(verdict, ensure_ascii=False),
            json.dumps(json_value(job.get("technique_ids_json"), []), ensure_ascii=False),
            timestamp,
        ),
    )
    # 特征统计回写：从 payload 抽取危险片段，统计 200/403 通过率
    record_features(
        connection,
        job.get("vulnerability", ""),
        job.get("payload_snapshot", ""),
        bool(bypass_success),
        timestamp,
    )


def _resolve_job_technique_ids(job: dict[str, Any]) -> list[str]:
    """解析 candidate 实际使用的技法 ID（优先精确 technique_ids_json）。"""
    technique_ids = json_value(job.get("technique_ids_json"), [])
    if not isinstance(technique_ids, list):
        return []
    return [tid for tid in technique_ids if isinstance(tid, str)]


def _promote_techniques(
    connection: sqlite3.Connection,
    job: dict[str, Any],
    verdict: dict[str, Any],
    timestamp: str,
) -> None:
    """按 candidate 实际使用的技法 ID 精确关联转正。

    bypass（绕过成功）即有价值 → 该技法 bypass_count+1，≥1 次 → status=promoted
    （protected/community 主力保持原状态）。绕过失败 → attempt_count+1（绕过率分母）。
    同时记录「技法 × 原语」关联，用于淘汰的 distinct_primitive_count。
    """
    bypass_success = verdict.get("bypass_verdict") == "bypass"
    technique_ids = _resolve_job_technique_ids(job)
    base_payload_id = job.get("source_payload_id") or ""

    for tid in set(technique_ids):
        # 记录技法×原语关联（幂等）
        if base_payload_id:
            connection.execute(
                "INSERT OR IGNORE INTO technique_primitive_uses (technique_id, base_payload_id) VALUES (?, ?)",
                (tid, base_payload_id),
            )
        if bypass_success:
            connection.execute(
                """
                UPDATE kb_techniques
                SET bypass_count = bypass_count + 1,
                    attempt_count = attempt_count + 1,
                    success_count = success_count + 1,
                    status = CASE WHEN protected = 1 OR origin = 'community' THEN status ELSE 'promoted' END,
                    updated_at = ?
                WHERE technique_id = ?
                """,
                (timestamp, tid),
            )
        else:
            connection.execute(
                "UPDATE kb_techniques SET attempt_count = attempt_count + 1, updated_at = ? WHERE technique_id = ?",
                (timestamp, tid),
            )


def _retire_techniques(
    connection: sqlite3.Connection,
    timestamp: str,
) -> int:
    """淘汰：非 protected 且采样充分(≥10 原语) 且 0 绕过 → retired。

    采样数 = technique_primitive_uses 里该技法关联的不同原语数。
    只淘汰 origin='generated'（自己生成的），主力(protected=1)永不淘汰。
    """
    rows = connection.execute(
        """
        SELECT t.technique_id, t.origin, t.protected, t.bypass_count,
               (SELECT COUNT(*) FROM technique_primitive_uses u WHERE u.technique_id = t.technique_id) AS sampled
        FROM kb_techniques t
        WHERE t.status != 'retired'
          AND t.protected = 0
          AND t.origin != 'community'
        """,
    ).fetchall()
    retired = 0
    for r in rows:
        sampled = r["sampled"] or 0
        bypass = r["bypass_count"] or 0
        if sampled >= 10 and bypass == 0:
            connection.execute(
                "UPDATE kb_techniques SET status = 'retired', retired_at = ? WHERE technique_id = ?",
                (timestamp, r["technique_id"]),
            )
            connection.execute(
                """
                INSERT INTO kb_technique_events (id, technique_id, event, detail, created_at)
                VALUES (?, ?, 'retire', ?, ?)
                """,
                (str(uuid.uuid4()), r["technique_id"], f"采样 {sampled} 原语且 0 绕过", timestamp),
            )
            retired += 1
    return retired


def _persist_verification_result(
    connection: sqlite3.Connection,
    job: dict[str, Any],
    evidence: TargetEvidence,
    verdict: dict[str, Any],
    base: dict[str, Any] | None = None,
    *,
    fidelity: str = "exact",
    server_spec: dict[str, Any] | None = None,
    deterministic_verifier_present: bool = False,
) -> None:
    """写入 job 的 verdict，并同步 bypass/block 库（同一事务，幂等）。"""
    import hashlib

    timestamp = utc_now()
    raw_evidence = {
        "target_key": evidence.target_key,
        "request_summary": evidence.request_summary,
        "http_status": evidence.http_status,
        "response_excerpt": evidence.response_excerpt,
        "response_headers": evidence.response_headers,
        "outcome": evidence.outcome,
        "evidence": evidence.evidence,
        "baseline_excerpt": evidence.baseline_excerpt,
        "original_payload_digest": hashlib.sha256(
            job.get("payload_snapshot", "").encode("utf-8")
        ).hexdigest(),
        "sent_payload_snapshot": evidence.sent_body,
        "payload_fidelity": fidelity,
        "final_request_digest": evidence.request_digest,
        "execution_goal_id": job.get("execution_goal_id"),
        "verification_spec": server_spec,
        "deterministic_verifier_present": deterministic_verifier_present,
        "analysis": verdict.get("analysis"),
    }
    verdict_json = json.dumps(verdict, ensure_ascii=False)
    failure_stage = verdict.get("failure_stage")
    route_hint = _route_hint_from_verdict(verdict, job["vulnerability"])
    # 1. 落不可变历史观测
    _record_observation(
        connection, job, base or {}, evidence, verdict, timestamp,
        fidelity=fidelity, server_spec=server_spec,
        deterministic_verifier_present=deterministic_verifier_present,
    )
    # 2. 技巧转正回写（精确 technique_id，bypass≥1 转正）
    _promote_techniques(connection, job, verdict, timestamp)
    # 2.6 技巧淘汰回写（非 protected 且采样≥10 且 0 绕过 → retired）
    _retire_techniques(connection, timestamp)
    # 3. 投影到 bypass/block/unverified 库
    library_record_id = _sync_verification_library(
        connection, job, evidence, verdict, timestamp
    )
    connection.execute(
        """
        UPDATE verification_jobs
        SET status = 'completed',
            target_key = ?,
            raw_evidence_json = ?,
            verdict_json = ?,
            bypass_verdict = ?,
            execution_verdict = ?,
            failure_stage = ?,
            library_record_id = ?,
            sent_payload_snapshot = ?,
            payload_fidelity = ?,
            route_hint_json = ?,
            error_message = NULL,
            completed_at = ?
        WHERE id = ?
        """,
        (
            evidence.target_key,
            json.dumps(raw_evidence, ensure_ascii=False),
            verdict_json,
            verdict.get("bypass_verdict"),
            verdict.get("execution_verdict"),
            failure_stage,
            library_record_id,
            evidence.sent_body,
            fidelity,
            json.dumps(route_hint, ensure_ascii=False) if route_hint is not None else None,
            timestamp,
            job["id"],
        ),
    )


def _sync_verification_library(
    connection: sqlite3.Connection,
    job: dict[str, Any],
    evidence: TargetEvidence,
    verdict: dict[str, Any],
    timestamp: str,
) -> str | None:
    """按判定结果把 candidate 写入 bypass/block/unverified 三库之一，返回库记录 id。"""
    agent = job["source_agent"]
    candidate_id = job["source_candidate_id"]
    name = f"{_agent_label(agent)} · {payload_internal_name(job['payload_snapshot'])}"
    provenance = {
        "base_payload_id": job.get("base_name", ""),
        "verification_job_id": job["id"],
        "target_key": evidence.target_key,
        "request_summary": evidence.request_summary,
    }
    provenance_json = json.dumps(provenance, ensure_ascii=False)
    confidence = float(verdict.get("confidence", 0.0))
    rationale = verdict.get("rationale", "")

    execution = verdict.get("execution_verdict")
    bypass_success = 1 if verdict.get("bypass_verdict") == "bypass" else 0
    verification_success = 1 if execution == "confirmed" else 0
    labels = _derive_labels(verdict)
    labels_json = json.dumps(labels, ensure_ascii=False)
    is_bypass = bool(bypass_success and verification_success)
    is_unverified = execution == "unverified"

    # 统一清理对侧库，保证三库互斥。
    def _clear_other_libraries() -> None:
        for table in ("bypass_library", "block_library", "unverified_library"):
            connection.execute(
                f"DELETE FROM {table} WHERE source_agent = ? AND source_candidate_id = ?",
                (agent, candidate_id),
            )

    if is_unverified:
        record_id = str(uuid.uuid4())
        _clear_other_libraries()
        connection.execute(
            """
            INSERT INTO unverified_library (
                id, source_agent, source_candidate_id, candidate_kind, name,
                vulnerability, delivery, target_key, content, confidence, rationale,
                provenance_json, verification_job_id, target_profile_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
            ON CONFLICT(source_agent, source_candidate_id) DO UPDATE SET
                name = excluded.name,
                vulnerability = excluded.vulnerability,
                delivery = excluded.delivery,
                target_key = excluded.target_key,
                content = excluded.content,
                confidence = excluded.confidence,
                rationale = excluded.rationale,
                provenance_json = excluded.provenance_json,
                verification_job_id = excluded.verification_job_id,
                target_profile_id = excluded.target_profile_id,
                updated_at = excluded.updated_at
            """,
            (
                record_id,
                agent,
                candidate_id,
                job["candidate_kind"],
                name,
                job["vulnerability"],
                job["delivery"],
                evidence.target_key,
                job["payload_snapshot"],
                confidence,
                rationale,
                provenance_json,
                job["id"],
                timestamp,
                timestamp,
            ),
        )
        return record_id

    if is_bypass:
        record_id = str(uuid.uuid4())
        _clear_other_libraries()
        connection.execute(
            """
            INSERT INTO bypass_library (
                id, source_agent, source_candidate_id, candidate_kind, name,
                vulnerability, delivery, target_key, content, confidence, rationale,
                provenance_json, bypass_success, verification_success, labels_json,
                verification_job_id, target_profile_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
            ON CONFLICT(source_agent, source_candidate_id) DO UPDATE SET
                name = excluded.name,
                vulnerability = excluded.vulnerability,
                delivery = excluded.delivery,
                target_key = excluded.target_key,
                content = excluded.content,
                confidence = excluded.confidence,
                rationale = excluded.rationale,
                provenance_json = excluded.provenance_json,
                bypass_success = excluded.bypass_success,
                verification_success = excluded.verification_success,
                labels_json = excluded.labels_json,
                verification_job_id = excluded.verification_job_id,
                target_profile_id = excluded.target_profile_id,
                updated_at = excluded.updated_at
            """,
            (
                record_id,
                agent,
                candidate_id,
                job["candidate_kind"],
                name,
                job["vulnerability"],
                job["delivery"],
                evidence.target_key,
                job["payload_snapshot"],
                confidence,
                rationale,
                provenance_json,
                bypass_success,
                verification_success,
                labels_json,
                job["id"],
                timestamp,
                timestamp,
            ),
        )
        return record_id

    failure_stage = verdict.get("failure_stage") or "check_error"
    record_id = str(uuid.uuid4())
    _clear_other_libraries()
    connection.execute(
        """
        INSERT INTO block_library (
            id, source_agent, source_candidate_id, candidate_kind, name,
            vulnerability, delivery, target_key, content, failure_stage, confidence,
            rationale, provenance_json, bypass_success, verification_success, labels_json,
            verification_job_id, target_profile_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
        ON CONFLICT(source_agent, source_candidate_id) DO UPDATE SET
            name = excluded.name,
            vulnerability = excluded.vulnerability,
            delivery = excluded.delivery,
            target_key = excluded.target_key,
            content = excluded.content,
            failure_stage = excluded.failure_stage,
            confidence = excluded.confidence,
            rationale = excluded.rationale,
            provenance_json = excluded.provenance_json,
            bypass_success = excluded.bypass_success,
            verification_success = excluded.verification_success,
            labels_json = excluded.labels_json,
            verification_job_id = excluded.verification_job_id,
            target_profile_id = excluded.target_profile_id,
            updated_at = excluded.updated_at
        """,
        (
            record_id,
            agent,
            candidate_id,
            job["candidate_kind"],
            name,
            job["vulnerability"],
            job["delivery"],
            evidence.target_key,
            job["payload_snapshot"],
            failure_stage,
            confidence,
            rationale,
            provenance_json,
            bypass_success,
            verification_success,
            labels_json,
            job["id"],
            timestamp,
            timestamp,
        ),
    )
    return record_id


def _agent_label(agent: str) -> str:
    return {"semantic": "语义迭代", "encoding": "编码迭代", "cross": "交叉迭代"}.get(agent, agent)


def _fail_verification_job_locked(
    connection: sqlite3.Connection,
    job: dict[str, Any],
    message: str,
) -> None:
    """在已持有 DB_LOCK / 已打开连接时把 job 标记为 failed 并同步 block_library（check_error）。

    不在此获取锁或打开/关闭连接，由调用方负责。
    """
    evidence = TargetEvidence(
        target_key=job.get("target_key") or "",
        vulnerability=job["vulnerability"],
        request_summary="",
        http_status=0,
        response_excerpt="",
        outcome="request_error",
        evidence=message,
    )
    verdict = check_error_verdict(message)
    connection.execute(
        """
        UPDATE verification_jobs
        SET status = 'failed', error_message = ?, completed_at = ?,
            bypass_verdict = 'error', execution_verdict = 'not_confirmed',
            failure_stage = 'check_error'
        WHERE id = ?
        """,
        (message[:1000], utc_now(), job["id"]),
    )
    _sync_verification_library(connection, job, evidence, verdict, utc_now())
    connection.commit()


def _fail_verification_job(job: dict[str, Any], message: str) -> None:
    """把 job 标记为 failed 并同步到 block_library（check_error）。"""
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            _fail_verification_job_locked(connection, job, message)
        finally:
            connection.close()


@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "ok", "message": "WAFByPasser API is running"}


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/api/dashboard-summary")
def dashboard_summary():
    """Small first-paint payload; detailed collections load per workspace.

    数据口径（基于自动验证流水线，不再依赖已废弃的人工标记状态）：
      - 待测试数量 = 各 agent 仍处于「等待检验」的候选数（verification_jobs.status='waiting'）。
      - 成功 = 该 agent 落入 bypass 库的条数（绕过成功 + 验证成功）。
      - 失败 = 该 agent 落入 block 库的条数（未同时满足绕过成功 + 验证成功）。
    """
    waiting_by_agent = {
        row["source_agent"]: row["count"]
        for row in db_rows(
            "SELECT source_agent, COUNT(*) AS count FROM verification_jobs "
            "WHERE status = 'waiting' GROUP BY source_agent"
        )
    }
    bypass_by_agent = {
        row["source_agent"]: row["count"]
        for row in db_rows(
            "SELECT source_agent, COUNT(*) AS count FROM bypass_library GROUP BY source_agent"
        )
    }
    block_by_agent = {
        row["source_agent"]: row["count"]
        for row in db_rows(
            "SELECT source_agent, COUNT(*) AS count FROM block_library GROUP BY source_agent"
        )
    }

    agents: dict[str, dict[str, Any]] = {}
    for agent in ("semantic", "encoding", "cross"):
        pending = waiting_by_agent.get(agent, 0)
        success = bypass_by_agent.get(agent, 0)
        failed = block_by_agent.get(agent, 0)
        completed = success + failed
        agents[agent] = {
            "pending": pending,
            "success": success,
            "failed": failed,
            "completed": completed,
            "rate": (success / completed * 100) if completed else None,
        }

    pool_counts = {
        row["agent"]: row["count"]
        for row in db_rows(
            "SELECT agent, COUNT(*) AS count FROM iteration_pool_items "
            "WHERE status = 'pending' GROUP BY agent"
        )
    }
    success = sum(agent["success"] for agent in agents.values())
    failed = sum(agent["failed"] for agent in agents.values())
    completed = success + failed
    return {
        "payload_count": db_row(
            "SELECT COUNT(*) AS count FROM payloads WHERE is_deleted = 0 AND is_pool_snapshot = 0"
        )["count"],
        "technique_count": db_row(
            "SELECT COUNT(*) AS count FROM kb_techniques"
        )["count"],
        "bypass_library_count": db_row(
            "SELECT COUNT(*) AS count FROM bypass_library"
        )["count"],
        "block_library_count": db_row(
            "SELECT COUNT(*) AS count FROM block_library"
        )["count"],
        "agents": agents,
        "semantic_pool_pending": pool_counts.get("semantic", 0),
        "encoding_pool_pending": pool_counts.get("encoding", 0),
        "pending": sum(agent["pending"] for agent in agents.values()),
        "success": success,
        "failed": failed,
        "completed": completed,
        "rate": (success / completed * 100) if completed else None,
    }


# Payload CRUD endpoints
@app.get("/api/payloads")
def list_payloads(
    vulnerability: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    cursor: int = Query(default=0, ge=0),
):
    sql = "SELECT * FROM payloads WHERE is_deleted = 0 AND is_pool_snapshot = 0"
    params: tuple[Any, ...] = ()
    if vulnerability:
        sql += " AND vulnerability = ?"
        params = (vulnerability,)
    sql += " ORDER BY created_at DESC"
    return paged_payload_response(sql, limit, cursor, params)


@app.get("/api/payloads/{payload_id}")
async def get_payload(payload_id: str):
    record = db_row(
        """
        SELECT * FROM payloads
        WHERE id = ? AND is_deleted = 0 AND is_pool_snapshot = 0
        """,
        (payload_id,),
    )
    if not record:
        raise HTTPException(status_code=404, detail="Payload not found")
    item = payload_view(record)
    raw = dict(record)
    item["latest_waf_test"] = latest_waf_run(
        raw.get("source_agent"), raw.get("source_candidate_id")
    )
    return item


@app.patch("/api/payloads/{payload_id}")
async def update_payload(payload_id: str, payload: dict):
    editable_fields = {
        "content",
        "delivery",
        "severity",
    }
    unknown_fields = set(payload) - editable_fields
    if unknown_fields:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported payload fields: {', '.join(sorted(unknown_fields))}",
        )
    if not payload:
        raise HTTPException(status_code=422, detail="No payload fields to update")

    updates: dict[str, str] = {}
    for field, value in payload.items():
        if not isinstance(value, str) or not value.strip():
            raise HTTPException(status_code=422, detail=f"{field} must not be empty")
        updates[field] = value.strip() if field != "content" else value
    if "severity" in updates and updates["severity"] not in PAYLOAD_SEVERITIES:
        raise HTTPException(status_code=422, detail="severity must be one of: 低危, 中危, 高危, 严重")

    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            existing = connection.execute(
                """
                SELECT * FROM payloads
                WHERE id = ? AND is_deleted = 0 AND is_pool_snapshot = 0
                """,
                (payload_id,),
            ).fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Payload not found")

            columns = {
                column[1] for column in connection.execute("PRAGMA table_info(payloads)")
            }
            assignments = [f"{field} = ?" for field in updates]
            values: list[str] = list(updates.values())
            if "updated_at" in columns:
                assignments.append("updated_at = ?")
                values.append(utc_now())
            connection.execute(
                f"UPDATE payloads SET {', '.join(assignments)} WHERE id = ?",
                (*values, payload_id),
            )
            connection.commit()
            updated = connection.execute(
                "SELECT * FROM payloads WHERE id = ?", (payload_id,)
            ).fetchone()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()

    item = payload_view(updated)
    raw = dict(updated)
    item["latest_waf_test"] = latest_waf_run(
        raw.get("source_agent"), raw.get("source_candidate_id")
    )
    return item


@app.delete("/api/payloads/{payload_id}", status_code=204)
async def delete_payload(payload_id: str) -> None:
    relation_queries = (
        "SELECT COUNT(*) FROM candidates WHERE base_payload_id = ?",
        "SELECT COUNT(*) FROM generation_tasks WHERE base_payload_id = ?",
        "SELECT COUNT(*) FROM encoding_candidates WHERE base_payload_id = ?",
        "SELECT COUNT(*) FROM encoding_tasks WHERE base_payload_id = ?",
        "SELECT COUNT(*) FROM cross_sources WHERE archived_payload_id = ?",
        "SELECT COUNT(*) FROM iteration_pool_items WHERE source_payload_id = ?",
    )
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            payload = connection.execute(
                "SELECT is_pool_snapshot, is_deleted FROM payloads WHERE id = ?",
                (payload_id,),
            ).fetchone()
            if not payload or payload["is_pool_snapshot"] or payload["is_deleted"]:
                raise HTTPException(status_code=404, detail="Payload not found")

            has_related_records = any(
                connection.execute(query, (payload_id,)).fetchone()[0]
                for query in relation_queries
            )
            if has_related_records:
                connection.execute(
                    "UPDATE payloads SET is_deleted = 1 WHERE id = ?", (payload_id,)
                )
            else:
                connection.execute("DELETE FROM payloads WHERE id = ?", (payload_id,))
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()


@app.post("/api/payloads", status_code=201)
async def create_payload(payload: dict):
    """Create a new payload."""
    required_fields = {"vulnerability", "severity", "delivery", "content"}
    missing_fields = [
        field
        for field in sorted(required_fields)
        if not isinstance(payload.get(field), str) or not payload[field].strip()
    ]
    if missing_fields:
        raise HTTPException(
            status_code=422,
            detail=f"Required payload fields are missing: {', '.join(missing_fields)}",
        )
    if payload["vulnerability"] not in VULNERABILITIES:
        raise HTTPException(status_code=422, detail="Unknown vulnerability type")
    if payload["severity"] not in PAYLOAD_SEVERITIES:
        raise HTTPException(status_code=422, detail="severity must be one of: 低危, 中危, 高危, 严重")

    payload_id = str(uuid.uuid4())
    timestamp = utc_now()
    values_by_column = {
        "id": payload_id,
        "vulnerability": payload["vulnerability"],
        "name": payload_internal_name(payload["content"]),
        "category": "",
        "delivery": payload["delivery"].strip(),
        "target": "",
        "difficulty": "",
        "severity": payload["severity"],
        "is_executable": 1,
        "content": payload["content"],
        "usage_method": "",
        "success_indicators": "",
        "labels_json": '["未绕过","未验证"]',
        "created_at": timestamp,
    }

    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            table_columns = {
                column[1] for column in connection.execute("PRAGMA table_info(payloads)")
            }
            if "updated_at" in table_columns:
                values_by_column["updated_at"] = timestamp
            insert_columns = [
                column for column in values_by_column if column in table_columns
            ]
            placeholders = ", ".join("?" for _ in insert_columns)
            connection.execute(
                f"INSERT INTO payloads ({', '.join(insert_columns)}) VALUES ({placeholders})",
                tuple(values_by_column[column] for column in insert_columns),
            )
            connection.commit()
            record = connection.execute(
                "SELECT * FROM payloads WHERE id = ?", (payload_id,)
            ).fetchone()
        finally:
            connection.close()

    return payload_view(record)


@app.get("/api/candidates")
def list_candidates(
    status: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    cursor: int = Query(default=0, ge=0),
):
    sql = """
        SELECT candidates.*, payloads.name AS base_payload_name,
               payloads.vulnerability AS base_vulnerability,
               payloads.target AS base_target,
               payloads.difficulty AS base_difficulty
        FROM candidates
        JOIN payloads ON candidates.base_payload_id = payloads.id
    """
    params: tuple[Any, ...] = ()
    if status:
        sql += " WHERE candidates.status = ?"
        params = (status,)
    else:
        # 默认只返回队列中的候选（未归档、未拒绝），避免分页器按已归档/已拒绝条目计数。
        sql += " WHERE candidates.status NOT IN ('archived', 'rejected')"
    sql += " ORDER BY candidates.created_at DESC"
    return paginate_candidate_records(sql, params, limit, cursor, "semantic", candidate_view)


@app.patch("/api/candidates/{candidate_id}")
async def update_candidate(candidate_id: str, body: CandidateUpdateRequest):
    return update_candidate_record("semantic", candidate_id, body)


@app.delete("/api/candidates/{candidate_id}", status_code=204)
async def delete_candidate(candidate_id: str) -> None:
    delete_candidate_record("semantic", candidate_id)


@app.post("/api/candidates/{candidate_id}/archive", status_code=201)
async def archive_candidate(candidate_id: str):
    return archive_candidate_record("semantic", candidate_id)


@app.post("/api/semantic-iterations", status_code=202)
async def create_semantic_iteration(
    body: SemanticIterationRequest,
    background_tasks: BackgroundTasks,
):
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            payload_record = connection.execute(
                "SELECT * FROM payloads WHERE id = ?", (body.base_payload_id,)
            ).fetchone()
            if not payload_record:
                raise HTTPException(status_code=404, detail="Base Payload not found")
            payload = dict(payload_record)
            if payload["vulnerability"] not in SEMANTIC_PART_VULNERABILITIES:
                raise HTTPException(
                    status_code=422,
                    detail="This vulnerability is not supported by the semantic part engine",
                )
            parsed, context = semantic_task_context(payload)
            config = semantic_model_config()
            task_id = str(uuid.uuid4())
            timestamp = utc_now()
            rule_hints = [item["id"] for item in context["available_directions"]]
            connection.execute(
                """
                INSERT INTO generation_tasks (
                    id, base_payload_id, status, provider, model, rule_hints_json,
                    error_message, created_at, completed_at,
                    direction_context_json, base_parts_json, parser_confidence,
                    parser_status, unsupported_reason
                ) VALUES (?, ?, 'queued', ?, ?, ?, NULL, ?, NULL, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    payload["id"],
                    config["provider"],
                    config["model"],
                    json.dumps(rule_hints, ensure_ascii=False),
                    timestamp,
                    json.dumps(context, ensure_ascii=False),
                    json.dumps(parsed["parts"], ensure_ascii=False),
                    parsed.get("confidence", 0),
                    parsed.get("status", "supported"),
                    parsed.get("unsupported_reason"),
                ),
            )
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()

    background_tasks.add_task(run_semantic_generation, task_id)
    return {
        "id": task_id,
        "status": "queued",
    }


@app.get("/api/semantic-iterations/{task_id}")
async def get_semantic_iteration(task_id: str):
    task = db_row("SELECT * FROM generation_tasks WHERE id = ?", (task_id,))
    if not task:
        raise HTTPException(status_code=404, detail="Semantic iteration not found")
    candidate_records = db_rows(
        """
        SELECT candidates.*, payloads.name AS base_payload_name,
               payloads.vulnerability AS base_vulnerability,
               payloads.target AS base_target,
               payloads.difficulty AS base_difficulty
        FROM candidates
        JOIN payloads ON candidates.base_payload_id = payloads.id
        WHERE candidates.task_id = ?
        ORDER BY candidates.created_at DESC
        """,
        (task_id,),
    )
    result = dict(task)
    result["rule_hints"] = json_value(result.pop("rule_hints_json", None), [])
    result["direction_context"] = json_value(result.pop("direction_context_json", None), {})
    result["base_parts"] = json_value(result.pop("base_parts_json", None), [])
    result["candidates"] = [candidate_view(record) for record in candidate_records]
    return result


@app.post("/api/exhaustive-iterations", status_code=202)
async def create_exhaustive_iteration(
    body: ExhaustionIterationRequest,
    background_tasks: BackgroundTasks,
):
    """穷举：一条原语 × 剪枝后的技法，逐技法产出一个变体。"""
    with DB_LOCK:
        connection = connect()
        try:
            payload_record = connection.execute(
                "SELECT * FROM payloads WHERE id = ?", (body.base_payload_id,)
            ).fetchone()
            if not payload_record:
                raise HTTPException(status_code=404, detail="Base Payload not found")
            payload = dict(payload_record)
            if payload["vulnerability"] not in SEMANTIC_PART_VULNERABILITIES:
                raise HTTPException(
                    status_code=422,
                    detail="穷举仅支持 command-injection / sql-injection / xss",
                )
            primitive_backend = infer_backend_from_primitive(
                payload["content"], payload["vulnerability"]
            )
            techniques = prune_techniques_for_exhaustion(
                connection, payload["vulnerability"], primitive_backend
            )
            if not techniques:
                raise HTTPException(status_code=409, detail="剪枝后无可用技法")

            config = semantic_model_config()
            task_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO exhaustion_tasks (
                    id, base_payload_id, status, provider, model,
                    primitive_backend, technique_count, created_at
                ) VALUES (?, ?, 'queued', ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    payload["id"],
                    config["provider"],
                    config["model"],
                    primitive_backend,
                    len(techniques),
                    utc_now(),
                ),
            )
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()

    background_tasks.add_task(run_exhaustion_generation, task_id)
    return {
        "id": task_id,
        "status": "queued",
        "primitive_backend": primitive_backend,
        "technique_count": len(techniques),
    }


@app.get("/api/exhaustive-iterations/{task_id}")
async def get_exhaustive_iteration(task_id: str):
    task = db_row("SELECT * FROM exhaustion_tasks WHERE id = ?", (task_id,))
    if not task:
        raise HTTPException(status_code=404, detail="Exhaustion task not found")
    candidate_records = db_rows(
        """
        SELECT candidates.*, payloads.name AS base_payload_name,
               payloads.vulnerability AS base_vulnerability
        FROM candidates
        JOIN payloads ON candidates.base_payload_id = payloads.id
        WHERE candidates.task_id = ?
        ORDER BY candidates.created_at DESC
        """,
        (task_id,),
    )
    result = dict(task)
    result["candidates"] = [candidate_view(record) for record in candidate_records]
    return result


@app.get("/api/exhaustion-summary")
def get_exhaustion_summary(
    base_payload_id: str = Query(min_length=1),
):
    """穷举前剪枝统计（前端展示）。"""
    with DB_LOCK:
        connection = connect()
        payload_record = connection.execute(
            "SELECT * FROM payloads WHERE id = ?", (base_payload_id,)
        ).fetchone()
        if not payload_record:
            connection.close()
            raise HTTPException(status_code=404, detail="Payload not found")
        payload = dict(payload_record)
        primitive_backend = infer_backend_from_primitive(
            payload["content"], payload["vulnerability"]
        )
        summary = exhaustion_summary(connection, payload["vulnerability"], primitive_backend)
        connection.close()
    return summary


@app.post("/api/generalization", status_code=202)
async def create_generalization(
    body: GeneralizationRequest,
    background_tasks: BackgroundTasks,
):
    """泛化：从已有技法 + 绕过率（+ 教材）泛化新技法，落 frontier。"""
    if body.vulnerability not in VULNERABILITIES:
        raise HTTPException(status_code=422, detail="Unknown vulnerability type")

    with DB_LOCK:
        connection = connect()
        fuel_count = len(_fuel_techniques(connection, body.vulnerability))
        connection.close()
    if fuel_count == 0:
        raise HTTPException(status_code=409, detail="该漏洞类型下无活跃技法可作为泛化燃料")

    config = semantic_model_config()
    task_id = str(uuid.uuid4())
    with DB_LOCK:
        connection = connect()
        connection.execute(
            """
            INSERT INTO generalization_tasks (
                id, vulnerability, status, provider, model, fuel_count, created_at
            ) VALUES (?, ?, 'queued', ?, ?, ?, ?)
            """,
            (
                task_id,
                body.vulnerability,
                config["provider"],
                config["model"],
                fuel_count,
                utc_now(),
            ),
        )
        connection.commit()
        connection.close()

    background_tasks.add_task(run_generalization, task_id, body.textbook)
    return {"id": task_id, "status": "queued", "vulnerability": body.vulnerability, "fuel_count": fuel_count}


@app.get("/api/generalization/{task_id}")
async def get_generalization(task_id: str):
    task = db_row("SELECT * FROM generalization_tasks WHERE id = ?", (task_id,))
    if not task:
        raise HTTPException(status_code=404, detail="Generalization task not found")
    result = dict(task)
    result["frontier_techniques"] = [
        dict(r)
        for r in db_rows(
            """
            SELECT technique_id, name, mechanism_id, family_id, source_note
            FROM kb_techniques
            WHERE status = 'frontier' AND origin = 'generated'
            ORDER BY created_at DESC
            """
        )
    ]
    return result


# ---------------------------------------------------------------------------
# 盲测集 eval_bench：隔离于日常评分的评测集，衡量「学习是否真变强」。
# ---------------------------------------------------------------------------

class EvalBenchAddRequest(BaseModel):
    payload: str = Field(min_length=1)
    vulnerability: str = Field(min_length=1)
    source: str = Field(default="manual")


@app.post("/api/eval-bench", status_code=201)
async def add_eval_bench_item(body: EvalBenchAddRequest):
    """往盲测集加一条 held-out payload（隔离，不参与日常评分/生成）。"""
    if body.vulnerability not in VULNERABILITIES:
        raise HTTPException(status_code=422, detail="Unknown vulnerability type")
    item_id = str(uuid.uuid4())
    with DB_LOCK:
        connection = connect()
        try:
            connection.execute(
                """
                INSERT INTO eval_bench (id, payload, vulnerability, source, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (item_id, body.payload, body.vulnerability, body.source, utc_now()),
            )
            connection.commit()
        finally:
            connection.close()
    return {"id": item_id, "payload": body.payload}


@app.get("/api/eval-bench")
def list_eval_bench():
    """列出盲测集（不返回 baseline 之外的评分结果，保持隔离）。"""
    return [dict(r) for r in db_rows("SELECT * FROM eval_bench ORDER BY created_at DESC")]


@app.get("/api/eval-bench/stats")
def eval_bench_stats():
    """盲测集统计：按漏洞类型的 held-out 条目数。

    盲测绕过率 = 用当前技法库对盲测集跑穷举验证，统计 bypass 比例。
    该指标隔离于日常评分，只在此处一次性计算，不反向影响技法转正/淘汰。
    """
    rows = db_rows(
        "SELECT vulnerability, COUNT(*) AS n FROM eval_bench GROUP BY vulnerability"
    )
    return {
        "total": db_row("SELECT COUNT(*) AS n FROM eval_bench")["n"],
        "by_vulnerability": [dict(r) for r in rows],
        "note": "盲测集隔离于日常评分；盲测绕过率需用当前技法库对盲测集跑穷举验证后计算",
    }


@app.get("/api/encoding-candidates")
def list_encoding_candidates(
    status: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    cursor: int = Query(default=0, ge=0),
):
    sql = """
        SELECT encoding_candidates.*, payloads.name AS base_payload_name,
               payloads.vulnerability AS base_vulnerability,
               payloads.target AS base_target,
               payloads.difficulty AS base_difficulty
        FROM encoding_candidates
        JOIN payloads ON encoding_candidates.base_payload_id = payloads.id
    """
    params: tuple[Any, ...] = ()
    if status:
        sql += " WHERE encoding_candidates.status = ?"
        params = (status,)
    else:
        sql += " WHERE encoding_candidates.status NOT IN ('archived', 'rejected')"
    sql += " ORDER BY encoding_candidates.created_at DESC"
    return paginate_candidate_records(sql, params, limit, cursor, "encoding", encoding_candidate_view)


@app.patch("/api/encoding-candidates/{candidate_id}")
async def update_encoding_candidate(candidate_id: str, body: CandidateUpdateRequest):
    return update_candidate_record("encoding", candidate_id, body)


@app.delete("/api/encoding-candidates/{candidate_id}", status_code=204)
async def delete_encoding_candidate(candidate_id: str) -> None:
    delete_candidate_record("encoding", candidate_id)


@app.post("/api/encoding-candidates/{candidate_id}/archive", status_code=201)
async def archive_encoding_candidate(candidate_id: str):
    return archive_candidate_record("encoding", candidate_id)


@app.post("/api/encoding-iterations", status_code=202)
async def create_encoding_iteration(
    body: EncodingIterationRequest,
    background_tasks: BackgroundTasks,
):
    with DB_LOCK:
        connection = connect()
        try:
            payload_record = connection.execute(
                "SELECT * FROM payloads WHERE id = ?", (body.base_payload_id,)
            ).fetchone()
            if not payload_record:
                raise HTTPException(status_code=404, detail="Base Payload not found")
            payload = dict(payload_record)
            if payload["vulnerability"] not in {
                "command-injection",
                "sql-injection",
                "xss",
            }:
                raise HTTPException(
                    status_code=422,
                    detail="The encoding iteration agent supports command injection, SQL injection, and XSS",
                )
            config = semantic_model_config()
            task_id = str(uuid.uuid4())
            timestamp = utc_now()
            connection.execute(
                """
                INSERT INTO encoding_tasks (
                    id, base_payload_id, status, provider, model,
                    error_message, created_at, completed_at,
                    direction_context_json
                ) VALUES (?, ?, 'queued', ?, ?, NULL, ?, NULL, '{}')
                """,
                (
                    task_id,
                    payload["id"],
                    config["provider"],
                    config["model"],
                    timestamp,
                ),
            )
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()

    background_tasks.add_task(run_encoding_generation, task_id)
    return {
        "id": task_id,
        "status": "queued",
    }


@app.get("/api/encoding-iterations/{task_id}")
async def get_encoding_iteration(task_id: str):
    task = db_row("SELECT * FROM encoding_tasks WHERE id = ?", (task_id,))
    if not task:
        raise HTTPException(status_code=404, detail="Encoding iteration not found")
    candidate_records = db_rows(
        """
        SELECT encoding_candidates.*, payloads.name AS base_payload_name,
               payloads.vulnerability AS base_vulnerability,
               payloads.target AS base_target,
               payloads.difficulty AS base_difficulty
        FROM encoding_candidates
        JOIN payloads ON encoding_candidates.base_payload_id = payloads.id
        WHERE encoding_candidates.task_id = ?
        ORDER BY encoding_candidates.created_at DESC
        """,
        (task_id,),
    )
    result = dict(task)
    result["direction_context"] = json_value(result.pop("direction_context_json", None), {})
    result["candidates"] = [encoding_candidate_view(record) for record in candidate_records]
    return result


@app.post("/api/cross-iterations", status_code=202)
async def create_cross_iteration(
    body: CrossIterationRequest,
    background_tasks: BackgroundTasks,
):
    with DB_LOCK:
        connection = connect()
        try:
            source_record = connection.execute(
                "SELECT * FROM cross_sources WHERE id = ?", (body.cross_source_id,)
            ).fetchone()
            if not source_record:
                raise HTTPException(status_code=404, detail="Cross iteration source not found")
            source = dict(source_record)
            task_id = str(uuid.uuid4())
            timestamp = utc_now()
            connection.execute(
                """
                INSERT INTO cross_tasks (
                    id, cross_source_id, status, error_message,
                    created_at, completed_at
                ) VALUES (?, ?, 'queued', NULL, ?, NULL)
                """,
                (task_id, source["id"], timestamp),
            )
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()

    background_tasks.add_task(run_cross_generation, task_id)
    return {
        "id": task_id,
        "status": "queued",
    }


@app.patch("/api/cross-candidates/{candidate_id}")
async def update_cross_candidate(candidate_id: str, body: CandidateUpdateRequest):
    if body.status not in CANDIDATE_STATUSES or body.status == "archived":
        raise HTTPException(status_code=422, detail="Unknown candidate status")
    with DB_LOCK:
        connection = connect()
        try:
            record = connection.execute(
                "SELECT * FROM cross_candidates WHERE id = ?", (candidate_id,)
            ).fetchone()
            if not record:
                raise HTTPException(status_code=404, detail="Candidate not found")
            candidate = dict(record)
            transitions = {
                "pending_test": {"test_success", "test_failed", "rejected"},
                "test_success": {"pending_test"},
                "test_failed": {"pending_test"},
                "rejected": set(),
                "archived": set(),
            }
            if body.status not in transitions.get(candidate["status"], set()):
                raise HTTPException(
                    status_code=409,
                    detail="The current candidate status does not allow this transition",
                )
            connection.execute(
                "UPDATE cross_candidates SET status = ?, test_note = ?, updated_at = ? WHERE id = ?",
                (body.status, body.test_note, utc_now(), candidate_id),
            )
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()
    record = db_row(
        """
        SELECT cross_candidates.*, cross_sources.name AS source_name,
               cross_sources.vulnerability AS source_vulnerability,
               cross_sources.target AS source_target,
               cross_sources.difficulty AS source_difficulty,
               cross_sources.delivery AS source_delivery,
               cross_sources.content AS semantic_content,
               cross_sources.rule_labels_json AS semantic_rule_labels_json
        FROM cross_candidates
        JOIN cross_sources ON cross_sources.id = cross_candidates.cross_source_id
        WHERE cross_candidates.id = ?
        """,
        (candidate_id,),
    )
    return cross_candidate_view(record)


@app.delete("/api/cross-candidates/{candidate_id}", status_code=204)
async def delete_cross_candidate(candidate_id: str) -> None:
    with DB_LOCK:
        connection = connect()
        try:
            record = connection.execute(
                "SELECT id FROM cross_candidates WHERE id = ?", (candidate_id,)
            ).fetchone()
            if not record:
                raise HTTPException(status_code=404, detail="Candidate not found")
            # 保留 cross_chain_history（链历史不被删除，避免重复生成）
            connection.execute(
                "DELETE FROM verification_jobs WHERE source_agent = 'cross' AND source_candidate_id = ?",
                (candidate_id,),
            )
            connection.execute(
                "DELETE FROM bypass_library WHERE source_agent = 'cross' AND source_candidate_id = ?",
                (candidate_id,),
            )
            connection.execute(
                "DELETE FROM block_library WHERE source_agent = 'cross' AND source_candidate_id = ?",
                (candidate_id,),
            )
            connection.execute(
                "DELETE FROM unverified_library WHERE source_agent = 'cross' AND source_candidate_id = ?",
                (candidate_id,),
            )
            connection.execute("DELETE FROM cross_candidates WHERE id = ?", (candidate_id,))
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()


@app.get("/api/cross-sources")
def list_cross_sources(
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    cursor: int = Query(default=0, ge=0),
):
    return paged_cross_source_response(limit, cursor)


@app.post("/api/cross-sources/from-payload", status_code=201)
async def create_cross_source_from_payload(payload: dict[str, Any]):
    source_payload_id = str(payload.get("source_payload_id") or "").strip()
    if not source_payload_id:
        raise HTTPException(status_code=422, detail="source_payload_id is required")
    timestamp = utc_now()
    source_id = str(uuid.uuid4())
    semantic_candidate_id = f"manual:{source_payload_id}"
    with DB_LOCK:
        connection = connect()
        try:
            source = connection.execute(
                "SELECT * FROM payloads WHERE id = ? AND is_deleted = 0 AND is_pool_snapshot = 0",
                (source_payload_id,),
            ).fetchone()
            if not source:
                raise HTTPException(status_code=404, detail="Payload not found")
            existing = connection.execute(
                "SELECT id FROM cross_sources WHERE archived_payload_id = ?",
                (source_payload_id,),
            ).fetchone()
            if existing:
                raise HTTPException(status_code=409, detail="This Payload is already in the cross-iteration sources")
            item = dict(source)
            connection.execute(
                """
                INSERT INTO cross_sources (
                    id, archived_payload_id, semantic_candidate_id, name,
                    vulnerability, category, delivery, target, difficulty,
                    content, rule_labels_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?)
                """,
                (
                    source_id,
                    source_payload_id,
                    semantic_candidate_id,
                    payload_internal_name(item["content"]),
                    item["vulnerability"],
                    item.get("category") or "",
                    item["delivery"],
                    item.get("target") or "",
                    item.get("difficulty") or "",
                    item["content"],
                    timestamp,
                ),
            )
            # cross_source 一经产生即进入待交叉池（不再有「待交叉来源」展示区）
            _auto_enqueue_cross_source(connection, source_id)
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()
    record = db_row("SELECT * FROM cross_sources WHERE id = ?", (source_id,))
    return cross_source_view(record) if record else {}


@app.get("/api/cross-candidates")
def list_cross_candidates(
    status: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    cursor: int = Query(default=0, ge=0),
):
    sql = """
        SELECT cross_candidates.*, cross_sources.name AS source_name,
               cross_sources.vulnerability AS source_vulnerability,
               cross_sources.target AS source_target,
               cross_sources.difficulty AS source_difficulty,
               cross_sources.delivery AS source_delivery,
               cross_sources.content AS semantic_content,
               cross_sources.rule_labels_json AS semantic_rule_labels_json
        FROM cross_candidates
        JOIN cross_sources ON cross_sources.id = cross_candidates.cross_source_id
    """
    params: tuple[Any, ...] = ()
    if status:
        sql += " WHERE cross_candidates.status = ?"
        params = (status,)
    else:
        sql += " WHERE cross_candidates.status NOT IN ('archived', 'rejected')"
    sql += " ORDER BY cross_candidates.created_at DESC"
    return paginate_candidate_records(sql, params, limit, cursor, "cross", cross_candidate_view)


@app.get("/api/cross-iterations/{task_id}")
async def get_cross_iteration(task_id: str):
    task = db_row("SELECT * FROM cross_tasks WHERE id = ?", (task_id,))
    if not task:
        raise HTTPException(status_code=404, detail="Cross iteration not found")
    candidates = paginate_candidate_records(
        """
        SELECT cross_candidates.*, cross_sources.name AS source_name,
               cross_sources.vulnerability AS source_vulnerability,
               cross_sources.target AS source_target,
               cross_sources.difficulty AS source_difficulty,
               cross_sources.delivery AS source_delivery,
               cross_sources.content AS semantic_content,
               cross_sources.rule_labels_json AS semantic_rule_labels_json
        FROM cross_candidates
        JOIN cross_sources ON cross_sources.id = cross_candidates.cross_source_id
        WHERE cross_candidates.task_id = ?
        ORDER BY cross_candidates.created_at DESC
        """,
        (task_id,),
        None,
        0,
        "cross",
        cross_candidate_view,
    )
    result = dict(task)
    result["candidates"] = candidates
    return result


@app.get("/api/success-samples")
def list_success_samples(
    agent: Literal["semantic", "encoding", "cross"] | None = Query(default=None),
    vulnerability: str | None = Query(default=None),
    target: str | None = Query(default=None),
    delivery: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    cursor: int = Query(default=0, ge=0),
):
    filters = ["status = 'active'"]
    params: list[Any] = []
    for column, value in (
        ("agent", agent),
        ("vulnerability", vulnerability),
        ("target", target),
        ("delivery", delivery),
    ):
        if value:
            filters.append(f"{column} = ?")
            params.append(value)
    return paged_response(
        f"SELECT * FROM success_samples WHERE {' AND '.join(filters)} ORDER BY created_at DESC",
        tuple(params),
        limit,
        cursor,
        success_sample_view,
    )


@app.get("/api/success-samples/{sample_id}")
async def get_success_sample(sample_id: str):
    record = db_row(
        "SELECT * FROM success_samples WHERE id = ? AND status = 'active'",
        (sample_id,),
    )
    if not record:
        raise HTTPException(status_code=404, detail="Success sample not found")
    return success_sample_view(record)


@app.delete("/api/success-samples/{sample_id}", status_code=204)
async def delete_success_sample(sample_id: str) -> None:
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        try:
            cursor = connection.execute(
                """
                UPDATE success_samples
                SET status = 'deleted', updated_at = ?
                WHERE id = ? AND status = 'active'
                """,
                (utc_now(), sample_id),
            )
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Success sample not found")
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()


@app.get("/api/iteration-pools/semantic")
async def list_semantic_pool():
    return list_iteration_pool_records("semantic")


@app.post("/api/iteration-pools/semantic", status_code=201)
async def add_semantic_pool_item(body: IterationPoolAddRequest):
    return add_iteration_pool_record("semantic", body.source_payload_id)


@app.get("/api/iteration-pools/encoding")
async def list_encoding_pool():
    return list_iteration_pool_records("encoding")


@app.post("/api/iteration-pools/encoding", status_code=201)
async def add_encoding_pool_item(body: IterationPoolAddRequest):
    return add_iteration_pool_record("encoding", body.source_payload_id)


def add_iteration_pool_record(
    agent: Literal["semantic", "encoding"], source_payload_id: str
) -> dict[str, Any]:
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            source = connection.execute(
                """
                SELECT * FROM payloads
                WHERE id = ? AND is_deleted = 0 AND is_pool_snapshot = 0
                """,
                (source_payload_id,),
            ).fetchone()
            if not source:
                raise HTTPException(status_code=404, detail="Payload not found")
            payload = dict(source)
            if agent == "semantic" and payload["vulnerability"] == "log4j":
                raise HTTPException(
                    status_code=422,
                    detail="Log4j is not supported by the semantic iteration agent",
                )
            if agent == "encoding" and payload["vulnerability"] not in {
                "command-injection",
                "sql-injection",
                "xss",
            }:
                raise HTTPException(
                    status_code=422,
                    detail="The encoding iteration agent supports command injection, SQL injection, and XSS",
                )
            existing = connection.execute(
                """
                SELECT id FROM iteration_pool_items
                WHERE agent = ? AND source_payload_id = ? AND status = 'pending'
                """,
                (agent, source_payload_id),
            ).fetchone()
            if existing:
                raise HTTPException(
                    status_code=409,
                    detail="This Payload already has a pending iteration pool item",
                )

            snapshot_id = str(uuid.uuid4())
            item_id = str(uuid.uuid4())
            created_at = utc_now()
            connection.execute(
                """
                INSERT INTO payloads (
                    id, name, vulnerability, category, delivery, target, difficulty,
                    content, created_at, archived_from_candidate_id, source_agent,
                    source_candidate_id, iteration_metadata_json, is_pool_snapshot,
                    severity, is_executable, usage_method, success_indicators, is_deleted
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, 1, ?, 1, '', '', 0)
                """,
                (
                    snapshot_id,
                    payload["name"],
                    payload["vulnerability"],
                    payload["category"],
                    payload["delivery"],
                    payload["target"],
                    payload["difficulty"],
                    payload["content"],
                    created_at,
                    payload.get("iteration_metadata_json") or "{}",
                    payload.get("severity") or "中危",
                ),
            )
            connection.execute(
                """
                INSERT INTO iteration_pool_items (
                    id, agent, source_payload_id, snapshot_payload_id, status,
                    task_id, created_at, started_at
                ) VALUES (?, ?, ?, ?, 'pending', NULL, ?, NULL)
                """,
                (item_id, agent, source_payload_id, snapshot_id, created_at),
            )
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise HTTPException(status_code=409, detail="Unable to add iteration pool item") from exc
        finally:
            connection.close()

    return next(item for item in list_iteration_pool_records(agent) if item["id"] == item_id)


def list_iteration_pool_records(agent: Literal["semantic", "encoding"]) -> list[dict[str, Any]]:
    task_table = "generation_tasks" if agent == "semantic" else "encoding_tasks"
    records = db_rows(
        f"""
        SELECT pool.*, snapshot.name AS snapshot_name,
               snapshot.vulnerability AS snapshot_vulnerability,
               snapshot.category AS snapshot_category,
               snapshot.delivery AS snapshot_delivery,
               snapshot.target AS snapshot_target,
               snapshot.difficulty AS snapshot_difficulty,
               snapshot.content AS snapshot_content,
               snapshot.iteration_metadata_json AS snapshot_iteration_metadata_json,
               task.status AS task_status,
               task.error_message AS task_error
        FROM iteration_pool_items AS pool
        JOIN payloads AS snapshot ON snapshot.id = pool.snapshot_payload_id
        LEFT JOIN {task_table} AS task ON task.id = pool.task_id
        WHERE pool.agent = ?
        ORDER BY pool.created_at DESC
        """,
        (agent,),
    )
    result = []
    for record in records:
        item = dict(record)
        metadata = json_value(item.pop("snapshot_iteration_metadata_json", None), {})
        item["snapshot"] = {
            "id": item.pop("snapshot_payload_id"),
            "name": item.pop("snapshot_name"),
            "vulnerability": item.pop("snapshot_vulnerability"),
            "category": item.pop("snapshot_category"),
            "delivery": item.pop("snapshot_delivery"),
            "target": item.pop("snapshot_target"),
            "difficulty": item.pop("snapshot_difficulty"),
            "content": item.pop("snapshot_content"),
            "used_direction_ids": metadata.get("used_direction_ids", []),
            "next_directions": metadata.get("next_directions", []),
        }
        item["snapshot_payload_id"] = item["snapshot"]["id"]
        if item["task_id"] and not item["task_status"]:
            item["task_status"] = "unknown"
        result.append(item)
    return result


@app.delete("/api/iteration-pools/{item_id}", status_code=204)
async def delete_iteration_pool_item(item_id: str) -> None:
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            item = connection.execute(
                "SELECT status, snapshot_payload_id FROM iteration_pool_items WHERE id = ?",
                (item_id,),
            ).fetchone()
            if not item:
                raise HTTPException(status_code=404, detail="Iteration pool item not found")
            if item["status"] != "pending":
                raise HTTPException(
                    status_code=409,
                    detail="Started items cannot be removed from the iteration pool",
                )

            connection.execute(
                "DELETE FROM iteration_pool_items WHERE id = ?", (item_id,)
            )
            connection.execute(
                "DELETE FROM payloads WHERE id = ?", (item["snapshot_payload_id"],)
            )
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()


@app.post("/api/iteration-pools/{item_id}/start", status_code=202)
async def start_iteration_pool_item(
    item_id: str,
    body: IterationPoolStartRequest,
    background_tasks: BackgroundTasks,
):
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            item_record = connection.execute(
                "SELECT * FROM iteration_pool_items WHERE id = ?", (item_id,)
            ).fetchone()
            if not item_record:
                raise HTTPException(status_code=404, detail="Iteration pool item not found")
            item = dict(item_record)
            if item["agent"] not in {"semantic", "encoding"}:
                raise HTTPException(
                    status_code=422,
                    detail="Unknown iteration agent",
                )

            task_table = "generation_tasks" if item["agent"] == "semantic" else "encoding_tasks"
            if item["status"] == "started" and item.get("task_id"):
                active = connection.execute(
                    f"SELECT status FROM {task_table} WHERE id = ?", (item["task_id"],)
                ).fetchone()
                if active and active["status"] in {"queued", "running"}:
                    raise HTTPException(status_code=409, detail="This iteration task is already running")

            payload_record = connection.execute(
                "SELECT * FROM payloads WHERE id = ?", (item["snapshot_payload_id"],)
            ).fetchone()
            if not payload_record:
                raise HTTPException(status_code=409, detail="Iteration snapshot not found")
            payload = dict(payload_record)

            timestamp = utc_now()
            if item["agent"] == "encoding":
                if payload["vulnerability"] not in {
                    "command-injection",
                    "sql-injection",
                    "xss",
                }:
                    raise HTTPException(
                        status_code=422,
                        detail="The encoding iteration agent supports command injection, SQL injection, and XSS",
                    )
                config = semantic_model_config()
                task_id = str(uuid.uuid4())
                connection.execute(
                    """
                    INSERT INTO encoding_tasks (
                        id, base_payload_id, status, provider, model,
                        error_message, created_at, completed_at,
                        direction_context_json
                    ) VALUES (?, ?, 'queued', ?, ?, NULL, ?, NULL, '{}')
                    """,
                    (
                        task_id,
                        payload["id"],
                        config["provider"],
                        config["model"],
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    UPDATE iteration_pool_items
                    SET status = 'started', task_id = ?, started_at = ?
                    WHERE id = ?
                    """,
                    (task_id, timestamp, item_id),
                )
                connection.commit()
                background_task = run_encoding_generation
                agent = "encoding"
            else:
                if payload["vulnerability"] not in SEMANTIC_PART_VULNERABILITIES:
                    raise HTTPException(
                        status_code=422,
                        detail="This vulnerability is not supported by the semantic part engine",
                    )
                parsed, context = semantic_task_context(payload)
                config = semantic_model_config()
                task_id = str(uuid.uuid4())
                rule_hints = [item["id"] for item in context["available_directions"]]
                connection.execute(
                    """
                    INSERT INTO generation_tasks (
                        id, base_payload_id, status, provider, model, rule_hints_json,
                        error_message, created_at, completed_at,
                        direction_context_json, base_parts_json, parser_confidence,
                        parser_status, unsupported_reason
                    ) VALUES (?, ?, 'queued', ?, ?, ?, NULL, ?, NULL, ?, ?, ?, ?, ?)
                    """,
                    (
                        task_id,
                        payload["id"],
                        config["provider"],
                        config["model"],
                        json.dumps(rule_hints, ensure_ascii=False),
                        timestamp,
                        json.dumps(context, ensure_ascii=False),
                        json.dumps(parsed["parts"], ensure_ascii=False),
                        parsed.get("confidence", 0),
                        parsed.get("status", "supported"),
                        parsed.get("unsupported_reason"),
                    ),
                )
                connection.execute(
                    """
                    UPDATE iteration_pool_items
                    SET status = 'started', task_id = ?, started_at = ?
                    WHERE id = ?
                    """,
                    (task_id, timestamp, item_id),
                )
                connection.commit()
                background_task = run_semantic_generation
                agent = "semantic"
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()
    background_tasks.add_task(background_task, task_id)
    return {
        "id": task_id,
        "agent": agent,
        "status": "queued",
        "pool_item_id": item_id,
    }


# ---------------------------------------------------------------------------
# 正向交叉迭代池：输入为 cross_source（语义归档/手动加入的待交叉来源）。
# 与语义/编码迭代池对齐，但池子条目直接引用 cross_source，不再做 payload 快照。
# ---------------------------------------------------------------------------

def _auto_enqueue_cross_source(connection: sqlite3.Connection, cross_source_id: str) -> None:
    """幂等把 cross_source 加入待交叉池（若无 pending 条目）。

    供 cross_source 创建点直接调用：前端不再有「待交叉来源」展示区，
    cross_source 一经产生即进入待迭代池，用户在池子里 start 交叉迭代。
    """
    existing = connection.execute(
        "SELECT id FROM cross_pool_items WHERE cross_source_id = ? AND status = 'pending'",
        (cross_source_id,),
    ).fetchone()
    if existing:
        return
    connection.execute(
        """
        INSERT INTO cross_pool_items (
            id, cross_source_id, status, task_id, created_at, started_at
        ) VALUES (?, ?, 'pending', NULL, ?, NULL)
        """,
        (str(uuid.uuid4()), cross_source_id, utc_now()),
    )


@app.get("/api/iteration-pools/cross")
async def list_cross_pool():
    return list_cross_pool_records()


@app.post("/api/iteration-pools/cross", status_code=201)
async def add_cross_pool_item(body: CrossPoolAddRequest):
    return add_cross_pool_record(body.cross_source_id)


def add_cross_pool_record(cross_source_id: str) -> dict[str, Any]:
    with DB_LOCK:
        connection = connect()
        try:
            source = connection.execute(
                "SELECT * FROM cross_sources WHERE id = ?", (cross_source_id,)
            ).fetchone()
            if not source:
                raise HTTPException(status_code=404, detail="Cross source not found")
            existing = connection.execute(
                """
                SELECT id FROM cross_pool_items
                WHERE cross_source_id = ? AND status = 'pending'
                """,
                (cross_source_id,),
            ).fetchone()
            if existing:
                raise HTTPException(
                    status_code=409,
                    detail="This cross source already has a pending iteration pool item",
                )
            item_id = str(uuid.uuid4())
            created_at = utc_now()
            connection.execute(
                """
                INSERT INTO cross_pool_items (
                    id, cross_source_id, status, task_id, created_at, started_at
                ) VALUES (?, ?, 'pending', NULL, ?, NULL)
                """,
                (item_id, cross_source_id, created_at),
            )
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()
    return next(item for item in list_cross_pool_records() if item["id"] == item_id)


def list_cross_pool_records() -> list[dict[str, Any]]:
    records = db_rows(
        """
        SELECT pool.*, src.name AS source_name,
               src.vulnerability AS source_vulnerability,
               src.category AS source_category,
               src.delivery AS source_delivery,
               src.target AS source_target,
               src.difficulty AS source_difficulty,
               src.content AS source_content,
               src.rule_labels_json AS source_rule_labels_json,
               task.status AS task_status,
               task.error_message AS task_error
        FROM cross_pool_items AS pool
        JOIN cross_sources AS src ON src.id = pool.cross_source_id
        LEFT JOIN cross_tasks AS task ON task.id = pool.task_id
        ORDER BY pool.created_at DESC
        """
    )
    result = []
    for record in records:
        item = dict(record)
        item["source"] = {
            "id": item.pop("cross_source_id"),
            "name": item.pop("source_name"),
            "vulnerability": item.pop("source_vulnerability"),
            "category": item.pop("source_category"),
            "delivery": item.pop("source_delivery"),
            "target": item.pop("source_target"),
            "difficulty": item.pop("source_difficulty"),
            "content": item.pop("source_content"),
            "rule_labels": json_value(item.pop("source_rule_labels_json", None), []),
        }
        if item["task_id"] and not item["task_status"]:
            item["task_status"] = "unknown"
        result.append(item)
    return result


@app.delete("/api/iteration-pools/cross/{item_id}", status_code=204)
async def delete_cross_pool_item(item_id: str) -> None:
    with DB_LOCK:
        connection = connect()
        try:
            item = connection.execute(
                "SELECT status FROM cross_pool_items WHERE id = ?", (item_id,)
            ).fetchone()
            if not item:
                raise HTTPException(status_code=404, detail="Cross pool item not found")
            if item["status"] != "pending":
                raise HTTPException(
                    status_code=409,
                    detail="Started items cannot be removed from the cross iteration pool",
                )
            connection.execute("DELETE FROM cross_pool_items WHERE id = ?", (item_id,))
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()


@app.post("/api/iteration-pools/cross/{item_id}/start", status_code=202)
async def start_cross_pool_item(
    item_id: str,
    body: IterationPoolStartRequest,
    background_tasks: BackgroundTasks,
):
    with DB_LOCK:
        connection = connect()
        try:
            item_record = connection.execute(
                "SELECT * FROM cross_pool_items WHERE id = ?", (item_id,)
            ).fetchone()
            if not item_record:
                raise HTTPException(status_code=404, detail="Cross pool item not found")
            item = dict(item_record)
            if item["status"] == "started" and item.get("task_id"):
                active = connection.execute(
                    "SELECT status FROM cross_tasks WHERE id = ?", (item["task_id"],)
                ).fetchone()
                if active and active["status"] in {"queued", "running"}:
                    raise HTTPException(status_code=409, detail="This cross iteration task is already running")
            source = connection.execute(
                "SELECT * FROM cross_sources WHERE id = ?", (item["cross_source_id"],)
            ).fetchone()
            if not source:
                raise HTTPException(status_code=409, detail="Cross source not found")

            timestamp = utc_now()
            task_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO cross_tasks (
                    id, cross_source_id, status, error_message, created_at, completed_at
                ) VALUES (?, ?, 'queued', NULL, ?, NULL)
                """,
                (task_id, item["cross_source_id"], timestamp),
            )
            connection.execute(
                """
                UPDATE cross_pool_items
                SET status = 'started', task_id = ?, started_at = ?
                WHERE id = ?
                """,
                (task_id, timestamp, item_id),
            )
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()
    background_tasks.add_task(run_cross_generation, task_id)
    return {
        "id": task_id,
        "agent": "cross",
        "status": "queued",
        "pool_item_id": item_id,
    }


REPORT_EDITABLE_FIELDS = {
    "payload_content",
    "title",
    "verification_environment",
    "prerequisites",
    "verification_steps",
    "actual_result",
    "conclusion",
    "tester",
    "verification_date",
    "notes",
}
REPORT_IMAGE_TYPES = {
    "image/png": (".png", lambda content: content.startswith(b"\x89PNG\r\n\x1a\n")),
    "image/jpeg": (".jpg", lambda content: content.startswith(b"\xff\xd8\xff")),
    "image/webp": (
        ".webp",
        lambda content: len(content) >= 12
        and content.startswith(b"RIFF")
        and content[8:12] == b"WEBP",
    ),
}
MAX_REPORT_IMAGES = 10
MAX_REPORT_IMAGE_BYTES = 10 * 1024 * 1024


def read_report(report_id: str) -> dict[str, Any]:
    record = db_row(
        """
        SELECT reports.*, success_samples.status AS source_status
        FROM reports
        LEFT JOIN success_samples ON success_samples.id = reports.success_sample_id
        WHERE reports.id = ?
        """,
        (report_id,),
    )
    if not record:
        raise HTTPException(status_code=404, detail="Report not found")
    return report_view(record)


def report_evidence_path(relative_path: str) -> Path:
    root = REPORT_EVIDENCE_ROOT.resolve()
    path = (root / relative_path).resolve()
    if not path.is_relative_to(root):
        raise HTTPException(status_code=422, detail="Invalid report image path")
    return path


@app.post("/api/reports/from-sample/{sample_id}", status_code=201)
async def create_report_from_sample(sample_id: str):
    existing = db_row("SELECT id FROM reports WHERE success_sample_id = ?", (sample_id,))
    if existing:
        return read_report(existing["id"])

    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            sample_record = connection.execute(
                "SELECT * FROM success_samples WHERE id = ? AND status = 'active'",
                (sample_id,),
            ).fetchone()
            if not sample_record:
                raise HTTPException(status_code=404, detail="Success sample not found")
            sample = dict(sample_record)
            report_id = str(uuid.uuid4())
            timestamp = utc_now()
            verification_date = str(sample["created_at"])[:10]
            connection.execute(
                """
                INSERT INTO reports (
                    id, success_sample_id, source_agent, source_candidate_id,
                    source_archived_payload_id, sample_name, vulnerability,
                    category, delivery, target, payload_content, sample_test_note,
                    provenance_json, sample_created_at, title,
                    verification_environment, prerequisites, verification_steps,
                    actual_result, conclusion, tester, verification_date, notes,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', ?, ?, '', ?, '', ?, ?)
                """,
                (
                    report_id,
                    sample["id"],
                    sample["agent"],
                    sample["candidate_id"],
                    sample["archived_payload_id"],
                    sample["name"],
                    sample["vulnerability"],
                    sample["category"],
                    sample["delivery"],
                    sample["target"],
                    sample["content"],
                    sample["test_note"],
                    sample["provenance_json"],
                    sample["created_at"],
                    f"{sample['name']} 验证报告",
                    sample["target"],
                    sample["test_note"] or "",
                    "验证成功",
                    verification_date,
                    timestamp,
                    timestamp,
                ),
            )
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        except sqlite3.IntegrityError:
            connection.rollback()
            existing = connection.execute(
                "SELECT id FROM reports WHERE success_sample_id = ?", (sample_id,)
            ).fetchone()
            if not existing:
                raise
            report_id = existing["id"]
        finally:
            connection.close()
    return read_report(report_id)


@app.get("/api/reports")
def list_reports(
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    cursor: int = Query(default=0, ge=0),
):
    return paged_response(
        """
        SELECT reports.*, success_samples.status AS source_status
        FROM reports
        LEFT JOIN success_samples ON success_samples.id = reports.success_sample_id
        ORDER BY reports.updated_at DESC
        """,
        (),
        limit,
        cursor,
        report_view,
    )


@app.get("/api/reports/{report_id}")
async def get_report(report_id: str):
    return read_report(report_id)


@app.patch("/api/reports/{report_id}")
async def update_report(report_id: str, body: dict):
    unknown_fields = set(body) - REPORT_EDITABLE_FIELDS
    if unknown_fields:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported report fields: {', '.join(sorted(unknown_fields))}",
        )
    if not body:
        raise HTTPException(status_code=422, detail="No report fields to update")
    if any(not isinstance(value, str) for value in body.values()):
        raise HTTPException(status_code=422, detail="Report fields must be strings")
    if "title" in body and not body["title"].strip():
        raise HTTPException(status_code=422, detail="title must not be empty")
    if "payload_content" in body and not body["payload_content"].strip():
        raise HTTPException(status_code=422, detail="payload_content must not be empty")
    verification_date = body.get("verification_date")
    if verification_date:
        try:
            datetime.strptime(verification_date, "%Y-%m-%d")
        except ValueError as exc:
            raise HTTPException(
                status_code=422, detail="verification_date must use YYYY-MM-DD"
            ) from exc

    assignments = [f"{field} = ?" for field in body]
    values = [body[field].strip() if field == "title" else body[field] for field in body]
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        try:
            cursor = connection.execute(
                f"UPDATE reports SET {', '.join(assignments)}, updated_at = ? WHERE id = ?",
                (*values, utc_now(), report_id),
            )
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Report not found")
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()
    return read_report(report_id)


@app.delete("/api/reports/{report_id}", status_code=204)
async def delete_report(report_id: str) -> None:
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            report = connection.execute(
                "SELECT id FROM reports WHERE id = ?", (report_id,)
            ).fetchone()
            if not report:
                raise HTTPException(status_code=404, detail="Report not found")
            connection.execute("DELETE FROM report_images WHERE report_id = ?", (report_id,))
            connection.execute("DELETE FROM reports WHERE id = ?", (report_id,))
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()

    report_dir = report_evidence_path(report_id)
    if report_dir.is_dir():
        shutil.rmtree(report_dir)


@app.post("/api/reports/{report_id}/images", status_code=201)
async def upload_report_image(report_id: str, file: UploadFile = File(...)):
    if file.content_type not in REPORT_IMAGE_TYPES:
        raise HTTPException(status_code=422, detail="Only PNG, JPEG, and WebP images are supported")
    content = await file.read(MAX_REPORT_IMAGE_BYTES + 1)
    if not content or len(content) > MAX_REPORT_IMAGE_BYTES:
        raise HTTPException(status_code=422, detail="Image is empty or exceeds 10 MB")
    extension, matches_signature = REPORT_IMAGE_TYPES[file.content_type]
    if not matches_signature(content):
        raise HTTPException(status_code=422, detail="Image content does not match its media type")

    image_id = str(uuid.uuid4())
    timestamp = utc_now()
    relative_path = f"{report_id}/{image_id}{extension}"
    path = report_evidence_path(relative_path)
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            if not connection.execute(
                "SELECT id FROM reports WHERE id = ?", (report_id,)
            ).fetchone():
                raise HTTPException(status_code=404, detail="Report not found")
            image_count = connection.execute(
                "SELECT COUNT(*) FROM report_images WHERE report_id = ?", (report_id,)
            ).fetchone()[0]
            if image_count >= MAX_REPORT_IMAGES:
                raise HTTPException(status_code=409, detail="A report can contain at most 10 images")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            connection.execute(
                """
                INSERT INTO report_images (
                    id, report_id, original_name, relative_path, media_type,
                    size_bytes, caption, sort_order, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?)
                """,
                (
                    image_id,
                    report_id,
                    file.filename or f"image{extension}",
                    relative_path,
                    file.content_type,
                    len(content),
                    image_count,
                    timestamp,
                    timestamp,
                ),
            )
            connection.commit()
            record = connection.execute(
                "SELECT * FROM report_images WHERE id = ?", (image_id,)
            ).fetchone()
        except HTTPException:
            connection.rollback()
            if path.is_file():
                path.unlink()
            raise
        except Exception:
            connection.rollback()
            if path.is_file():
                path.unlink()
            raise
        finally:
            connection.close()
    return report_image_view(record)


@app.patch("/api/report-images/{image_id}")
async def update_report_image(image_id: str, body: dict):
    unknown_fields = set(body) - {"caption", "sort_order"}
    if unknown_fields or not body:
        raise HTTPException(status_code=422, detail="Only caption and sort_order can be updated")
    if "caption" in body and not isinstance(body["caption"], str):
        raise HTTPException(status_code=422, detail="caption must be a string")
    if "sort_order" in body and (
        not isinstance(body["sort_order"], int) or body["sort_order"] < 0
    ):
        raise HTTPException(status_code=422, detail="sort_order must be a non-negative integer")

    assignments = [f"{field} = ?" for field in body]
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            cursor = connection.execute(
                f"UPDATE report_images SET {', '.join(assignments)}, updated_at = ? WHERE id = ?",
                (*body.values(), utc_now(), image_id),
            )
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Report image not found")
            connection.commit()
            record = connection.execute(
                "SELECT * FROM report_images WHERE id = ?", (image_id,)
            ).fetchone()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()
    return report_image_view(record)


@app.delete("/api/report-images/{image_id}", status_code=204)
async def delete_report_image(image_id: str) -> None:
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            image = connection.execute(
                "SELECT * FROM report_images WHERE id = ?", (image_id,)
            ).fetchone()
            if not image:
                raise HTTPException(status_code=404, detail="Report image not found")
            connection.execute("DELETE FROM report_images WHERE id = ?", (image_id,))
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()
    path = report_evidence_path(image["relative_path"])
    if path.is_file():
        path.unlink()


@app.get("/api/report-images/{image_id}/content")
async def get_report_image_content(image_id: str):
    image = db_row("SELECT * FROM report_images WHERE id = ?", (image_id,))
    if not image:
        raise HTTPException(status_code=404, detail="Report image not found")
    path = report_evidence_path(image["relative_path"])
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Report image file not found")
    return FileResponse(path, media_type=image["media_type"], filename=image["original_name"])


@app.get("/api/waf-test-scene")
async def get_waf_scene():
    """Get WAF test scene configuration (DVWA only; direct WAF target removed)."""
    load_dotenv(CONFIG_PATH)

    dvwa_base = os.getenv("WAF_DVWA_BASE_URL", os.getenv("DVWA_BASE_URL", "")).strip()
    dvwa_user = os.getenv("WAF_DVWA_USERNAME", os.getenv("DVWA_USERNAME", "")).strip()
    dvwa_pass = os.getenv("WAF_DVWA_PASSWORD", os.getenv("DVWA_PASSWORD", "")).strip()
    dvwa_configured = bool(dvwa_base and dvwa_user and dvwa_pass)

    supported_vulns = ["command-injection", "sql-injection", "xss"]

    scene = {
        "configured": dvwa_configured,
        "supported": supported_vulns,
    }

    if dvwa_configured:
        scene["base_url"] = dvwa_base
        scene["dvwa"] = {
            "configured": True,
            "base_url": dvwa_base,
        }
    else:
        scene["dvwa"] = {
            "configured": False,
            "error": "DVWA 未配置，请在 config/.env 中设置 WAF_DVWA_BASE_URL、WAF_DVWA_USERNAME、WAF_DVWA_PASSWORD"
        }

    return scene


@app.get("/api/waf-test-runs")
async def list_waf_runs(result: str | None = Query(default=None)):
    sql = "SELECT * FROM waf_test_runs"
    params: tuple[Any, ...] = ()
    if result:
        sql += " WHERE result = ?"
        params = (result,)
    sql += " ORDER BY created_at DESC"
    return [dict(record) for record in db_rows(sql, params)]


@app.post("/api/waf-test-runs", status_code=202)
async def create_waf_run(body: WafTestRequest):
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        try:
            candidate, base = waf_candidate_source(
                connection, body.agent, body.candidate_id
            )
            if base["vulnerability"] not in WAF_SUPPORTED:
                raise HTTPException(
                    status_code=422,
                    detail="This vulnerability type does not support automated WAF testing",
                )
            active = connection.execute(
                """
                SELECT id FROM waf_test_runs
                WHERE agent = ? AND candidate_id = ?
                  AND status IN ('queued', 'running')
                """,
                (body.agent, body.candidate_id),
            ).fetchone()
            if active:
                raise HTTPException(
                    status_code=409,
                    detail="This candidate already has an active WAF test",
                )

            run_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO waf_test_runs (
                    id, agent, candidate_id, base_name, vulnerability,
                    payload_snapshot, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?)
                """,
                (
                    run_id,
                    body.agent,
                    body.candidate_id,
                    base["name"],
                    base["vulnerability"],
                    candidate["content"],
                    utc_now(),
                ),
            )
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()

    start_background_thread(run_waf_test, run_id)
    record = db_row("SELECT * FROM waf_test_runs WHERE id = ?", (run_id,))
    return dict(record) if record else {"id": run_id, "status": "queued"}


@app.get("/api/waf-test-runs/{run_id}")
async def get_waf_run(run_id: str):
    record = db_row("SELECT * FROM waf_test_runs WHERE id = ?", (run_id,))
    if not record:
        raise HTTPException(status_code=404, detail="WAF test run not found")
    return dict(record)


@app.get("/api/semantic-agent/documents")
async def list_semantic_documents():
    """List semantic agent documents."""
    documents = []
    for doc_id, (kind, title, path) in AGENT_DOCUMENTS.items():
        try:
            content = path.read_text(encoding="utf-8")
            documents.append({"id": doc_id, "kind": kind, "title": title, "content": content})
        except Exception:
            pass
    return documents


@app.get("/api/encoding-agent/documents")
async def list_encoding_documents():
    """List encoding agent documents."""
    documents = []
    for doc_id, (kind, title, path) in ENCODING_AGENT_DOCUMENTS.items():
        try:
            content = path.read_text(encoding="utf-8")
            documents.append({"id": doc_id, "kind": kind, "title": title, "content": content})
        except Exception:
            pass
    return documents


@app.get("/api/verification-agent/documents")
async def list_verification_documents():
    """List verification agent documents."""
    documents = []
    for doc_id, (kind, title, path) in VERIFICATION_AGENT_DOCUMENTS.items():
        try:
            content = path.read_text(encoding="utf-8")
            documents.append({"id": doc_id, "kind": kind, "title": title, "content": content})
        except Exception:
            pass
    return documents


@app.get("/api/knowledge-base-agent/documents")
async def list_knowledge_base_agent_documents():
    """List knowledge-base agent documents."""
    documents = []
    for doc_id, (kind, title, path) in KNOWLEDGE_BASE_AGENT_DOCUMENTS.items():
        try:
            content = path.read_text(encoding="utf-8")
            documents.append({"id": doc_id, "kind": kind, "title": title, "content": content})
        except Exception:
            pass
    return documents


@app.get("/api/verification-targets")
async def list_verification_targets():
    """List all registered verification target ranges (for the target page)."""
    return verification_targets(str(CONFIG_PATH))


# ---------------------------------------------------------------------------
# 检验任务（verification_jobs）与 bypass/block 库
# ---------------------------------------------------------------------------

def _verification_job_view(source: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(source)
    item["raw_evidence"] = json_value(item.pop("raw_evidence_json", None), None)
    item["verdict"] = json_value(item.pop("verdict_json", None), None)
    item["verification_spec"] = json_value(item.pop("verification_spec_json", None), None)
    item["route_hint"] = json_value(item.pop("route_hint_json", None), None)
    item["technique_ids"] = json_value(item.pop("technique_ids_json", None), [])
    return item


def _library_entry_view(source: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(source)
    item["provenance"] = json_value(item.pop("provenance_json", None), {})
    return item


def _paged_library_response(
    table: str,
    filters: list[str],
    params: tuple[Any, ...],
    limit: int | None,
    cursor: int,
) -> list[dict[str, Any]] | dict[str, Any]:
    sql = f"SELECT * FROM {table}"
    if filters:
        sql += " WHERE " + " AND ".join(filters)
    sql += " ORDER BY created_at DESC"
    if limit is None:
        return [_library_entry_view(record) for record in db_rows(sql, params)]
    page_size = min(limit, MAX_PAGE_SIZE)
    total = db_row(f"SELECT COUNT(*) AS count FROM {table}" + (f" WHERE {' AND '.join(filters)}" if filters else ""), params)["count"]
    records = db_rows(f"{sql} LIMIT ? OFFSET ?", (*params, page_size, cursor))
    items = [_library_entry_view(record) for record in records]
    next_cursor = cursor + len(items)
    return {"items": items, "total": total, "next_cursor": next_cursor if next_cursor < total else None}


@app.get("/api/bypass-library")
def list_bypass_library(
    vulnerability: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    cursor: int = Query(default=0, ge=0),
):
    filters: list[str] = []
    params: list[Any] = []
    if vulnerability:
        filters.append("vulnerability = ?")
        params.append(vulnerability)
    return _paged_library_response("bypass_library", filters, tuple(params), limit, cursor)


@app.get("/api/bypass-library/{entry_id}")
async def get_bypass_library_entry(entry_id: str):
    record = db_row("SELECT * FROM bypass_library WHERE id = ?", (entry_id,))
    if not record:
        raise HTTPException(status_code=404, detail="Bypass library entry not found")
    return _library_entry_view(record)


@app.get("/api/block-library")
def list_block_library(
    failure_stage: str | None = Query(default=None),
    vulnerability: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    cursor: int = Query(default=0, ge=0),
):
    filters: list[str] = []
    params: list[Any] = []
    if failure_stage:
        filters.append("failure_stage = ?")
        params.append(failure_stage)
    if vulnerability:
        filters.append("vulnerability = ?")
        params.append(vulnerability)
    return _paged_library_response("block_library", filters, tuple(params), limit, cursor)


@app.get("/api/block-library/{entry_id}")
async def get_block_library_entry(entry_id: str):
    record = db_row("SELECT * FROM block_library WHERE id = ?", (entry_id,))
    if not record:
        raise HTTPException(status_code=404, detail="Block library entry not found")
    return _library_entry_view(record)


@app.get("/api/unverified-library")
def list_unverified_library(
    vulnerability: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    cursor: int = Query(default=0, ge=0),
):
    filters: list[str] = []
    params: list[Any] = []
    if vulnerability:
        filters.append("vulnerability = ?")
        params.append(vulnerability)
    return _paged_library_response("unverified_library", filters, tuple(params), limit, cursor)


@app.get("/api/unverified-library/{entry_id}")
async def get_unverified_library_entry(entry_id: str):
    record = db_row("SELECT * FROM unverified_library WHERE id = ?", (entry_id,))
    if not record:
        raise HTTPException(status_code=404, detail="Unverified library entry not found")
    return _library_entry_view(record)


@app.post("/api/unverified-library/{entry_id}/resolve", status_code=200)
async def resolve_unverified_library_entry(entry_id: str, payload: dict[str, Any]):
    """人工复核：把 unverified 记录转为 bypass（confirmed）或 block（failed）。"""
    outcome = payload.get("outcome")
    if outcome not in {"confirmed", "failed"}:
        raise HTTPException(status_code=422, detail="outcome must be 'confirmed' or 'failed'")
    timestamp = utc_now()
    with DB_LOCK:
        connection = connect()
        try:
            record = connection.execute(
                "SELECT * FROM unverified_library WHERE id = ?", (entry_id,)
            ).fetchone()
            if not record:
                raise HTTPException(status_code=404, detail="Unverified library entry not found")
            entry = dict(record)
            agent = entry["source_agent"]
            candidate_id = entry["source_candidate_id"]

            if outcome == "confirmed":
                verdict = {
                    "bypass_verdict": "bypass",
                    "execution_verdict": "confirmed",
                    "failure_stage": None,
                    "confidence": 1.0,
                    "rationale": "人工复核确认成功",
                }
                labels = ["绕过成功", "验证成功"]
                connection.execute(
                    "DELETE FROM block_library WHERE source_agent = ? AND source_candidate_id = ?",
                    (agent, candidate_id),
                )
                connection.execute(
                    """
                    INSERT INTO bypass_library (
                        id, source_agent, source_candidate_id, candidate_kind, name,
                        vulnerability, delivery, target_key, content, confidence, rationale,
                        provenance_json, bypass_success, verification_success, labels_json,
                        verification_job_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?, ?)
                    ON CONFLICT(source_agent, source_candidate_id) DO UPDATE SET
                        bypass_success = 1, verification_success = 1,
                        labels_json = excluded.labels_json,
                        verification_job_id = excluded.verification_job_id,
                        updated_at = excluded.updated_at
                    """,
                    (
                        str(uuid.uuid4()), agent, candidate_id, entry["candidate_kind"],
                        entry["name"], entry["vulnerability"], entry["delivery"],
                        entry["target_key"], entry["content"], 1.0, "人工复核确认成功",
                        entry["provenance_json"],
                        json.dumps(labels, ensure_ascii=False),
                        entry.get("verification_job_id"), timestamp, timestamp,
                    ),
                )
            else:
                labels = ["绕过成功", "验证失败"]
                connection.execute(
                    "DELETE FROM bypass_library WHERE source_agent = ? AND source_candidate_id = ?",
                    (agent, candidate_id),
                )
                connection.execute(
                    """
                    INSERT INTO block_library (
                        id, source_agent, source_candidate_id, candidate_kind, name,
                        vulnerability, delivery, target_key, content, failure_stage, confidence,
                        rationale, provenance_json, bypass_success, verification_success, labels_json,
                        verification_job_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'verify_failed', ?, ?, ?, 1, 0, ?, ?, ?, ?)
                    ON CONFLICT(source_agent, source_candidate_id) DO UPDATE SET
                        failure_stage = 'verify_failed',
                        labels_json = excluded.labels_json,
                        verification_job_id = excluded.verification_job_id,
                        updated_at = excluded.updated_at
                    """,
                    (
                        str(uuid.uuid4()), agent, candidate_id, entry["candidate_kind"],
                        entry["name"], entry["vulnerability"], entry["delivery"],
                        entry["target_key"], entry["content"], 1.0, "人工复核确认失败",
                        entry["provenance_json"],
                        json.dumps(labels, ensure_ascii=False),
                        entry.get("verification_job_id"), timestamp, timestamp,
                    ),
                )

            # 从 unverified 库删除
            connection.execute("DELETE FROM unverified_library WHERE id = ?", (entry_id,))
            # 更新 verification_jobs 的 verdict
            if entry.get("verification_job_id"):
                connection.execute(
                    """
                    UPDATE verification_jobs
                    SET bypass_verdict = ?, execution_verdict = ?, failure_stage = ?,
                        completed_at = ?
                    WHERE id = ?
                    """,
                    (
                        "bypass",
                        "confirmed" if outcome == "confirmed" else "not_confirmed",
                        None if outcome == "confirmed" else "verify_failed",
                        timestamp,
                        entry["verification_job_id"],
                    ),
                )
            connection.commit()
        finally:
            connection.close()
    return {"resolved": outcome}


@app.get("/api/verification-jobs")
def list_verification_jobs(
    status: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    cursor: int = Query(default=0, ge=0),
):
    filters: list[str] = []
    params: list[Any] = []
    if status:
        filters.append("status = ?")
        params.append(status)
    sql = "SELECT * FROM verification_jobs"
    if filters:
        sql += " WHERE " + " AND ".join(filters)
    sql += " ORDER BY created_at DESC"
    if limit is None:
        return [_verification_job_view(record) for record in db_rows(sql, tuple(params))]
    page_size = min(limit, MAX_PAGE_SIZE)
    total = db_row(
        "SELECT COUNT(*) AS count FROM verification_jobs" + (f" WHERE {' AND '.join(filters)}" if filters else ""),
        tuple(params),
    )["count"]
    records = db_rows(f"{sql} LIMIT ? OFFSET ?", (*params, page_size, cursor))
    items = [_verification_job_view(record) for record in records]
    next_cursor = cursor + len(items)
    return {"items": items, "total": total, "next_cursor": next_cursor if next_cursor < total else None}


@app.get("/api/verification-jobs/{job_id}")
async def get_verification_job(job_id: str):
    record = db_row("SELECT * FROM verification_jobs WHERE id = ?", (job_id,))
    if not record:
        raise HTTPException(status_code=404, detail="Verification job not found")
    return _verification_job_view(record)


@app.post("/api/verification-jobs/{job_id}/reverify", status_code=202)
async def reverify_verification_job(job_id: str):
    record = db_row("SELECT * FROM verification_jobs WHERE id = ?", (job_id,))
    if not record:
        raise HTTPException(status_code=404, detail="Verification job not found")
    with DB_LOCK:
        connection = connect()
        try:
            # 保留旧 verdict 中的有效路由提示到 route_hint_json，避免二次运行丢失路由。
            prior_verdict = json_value(record["verdict_json"], {})
            route_hint = _route_hint_from_verdict(prior_verdict, record["vulnerability"])
            connection.execute(
                """
                UPDATE verification_jobs
                SET status = 'queued',
                    raw_evidence_json = NULL,
                    verdict_json = NULL,
                    bypass_verdict = NULL,
                    execution_verdict = NULL,
                    failure_stage = NULL,
                    library_record_id = NULL,
                    error_message = NULL,
                    sent_payload_snapshot = NULL,
                    payload_fidelity = 'exact',
                    route_hint_json = ?,
                    started_at = NULL,
                    completed_at = NULL
                WHERE id = ?
                """,
                (
                    json.dumps(route_hint, ensure_ascii=False) if route_hint is not None else None,
                    job_id,
                ),
            )
            connection.commit()
        finally:
            connection.close()
    _wake_verification_workers()
    return {"id": job_id, "status": "queued"}


# ---------------------------------------------------------------------------
# 知识库管理（kb_techniques / 技巧分组 / 文章导入 / 转正）
# ---------------------------------------------------------------------------

def _technique_applies_to_payload(technique_id: str, content: str, category: str = "") -> bool:
    """确定性内容预筛：排除与当前 payload 平台/方言明显不匹配的手法。

    平台/方言专属维度（mssql/oracle/win/win 相关）按确定性关键字判定；
    无法确定平台时保守保留（交给 LLM 泛化时最终判断）。
    """
    dim = technique_dimension(technique_id)
    lowered = (content or "").lower()
    cat = (category or "").lower()
    blob = f"{lowered} {cat}"

    def has(*tokens: str) -> bool:
        return any(t in blob for t in tokens)

    if dim == "mssql":
        # MSSQL 专属：payload 无任何 MSSQL 特征时排除。
        mssql_markers = (
            "waitfor", "openrowset", "hashbytes", "char(",
            "@@version", "db_name()", "xp_cmdshell", "mssql", "sqlserver",
        )
        return has(*mssql_markers)
    if dim == "oracle":
        oracle_markers = (
            "utl_http", "utl_inaddr", "ctxsys", "sys_context", "dbms_",
            "oracle", "decode(", "q'[", "from dual",
        )
        return has(*oracle_markers)
    if dim == "win":
        # Windows/PowerShell 专属：payload 无 Windows 特征时排除。
        win_markers = (
            "powershell", "cmd.exe", "cmd /c", "\\windows", "whoami /",
            "ntfs", "::", "$env:", "-enc",
        )
        return has(*win_markers)
    # 其余维度：无确定性平台信号，保留。
    return True


def _select_techniques(
    vulnerability: str,
    group: str,
    content: str = "",
    category: str = "",
) -> list[dict[str, Any]]:
    """按漏洞类型 + 分组筛选可用手法，供遍历生成使用。

    数据驱动 + 自净化（与知识库自学习闭环接线）：
    - 排除 retired（已淘汰）与 origin='system'（part:* 框架方向走
      available_directions，不在这里重复消费）；
    - 后端剪枝：技法 backend 与原语推断后端不符时排除（generic 表示跨后端通用）；
    - 内容预筛：维度级平台/方言（mssql/oracle/win）确定性排除；
    - 绕过率排序：已知绕过率（bypass_count/attempt_count）降序，未验证垫底，
      同率按 technique_id 稳定排序。

    只返回 {technique_id, name, principle, template}。
    """
    primitive_backend = infer_backend_from_primitive(content, vulnerability)
    records = db_rows(
        """
        SELECT technique_id, name, principle, template, backend, mechanism_id,
               bypass_count, attempt_count
        FROM kb_techniques
        WHERE vulnerability = ? AND status != 'retired' AND origin != 'system'
        """,
        (vulnerability,),
    )
    scored: list[tuple[float, str, dict[str, Any]]] = []
    for r in records:
        if technique_group(r["technique_id"]) != group:
            continue
        if not _technique_applies_to_payload(r["technique_id"], content, category):
            continue
        backend = r["backend"] or "generic"
        if (
            backend != "generic"
            and primitive_backend != "generic"
            and backend != primitive_backend
        ):
            continue
        attempt = r["attempt_count"] or 0
        bypass = r["bypass_count"] or 0
        rate = (bypass / attempt) if attempt else -1.0
        scored.append(
            (
                rate,
                r["technique_id"],
                {
                    "technique_id": r["technique_id"],
                    "name": r["name"] or "",
                    "principle": r["principle"] or "",
                    "template": r["template"] or "",
                },
            )
        )
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [item[2] for item in scored]


def _kb_technique_view(source: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(source)
    item["group"] = technique_group(item.get("technique_id", ""), item.get("mechanism_id"))
    item["labels"] = json_value(item.pop("labels_json", None), [])
    return item


@app.get("/api/kb-techniques")
def list_kb_techniques(
    group: str | None = Query(default=None),
    vulnerability: str | None = Query(default=None),
    status: str | None = Query(default=None),
):
    """列出知识库技巧，按 group（semantic/encoding）过滤。"""
    records = db_rows("SELECT * FROM kb_techniques")
    items = [_kb_technique_view(r) for r in records]
    if group:
        items = [it for it in items if it["group"] == group]
    if vulnerability:
        items = [it for it in items if it["vulnerability"] == vulnerability]
    if status:
        items = [it for it in items if it["status"] == status]
    items.sort(key=lambda it: (it["group"], it["vulnerability"], it["technique_id"]))
    return items


@app.get("/api/kb-techniques/stats")
def kb_techniques_stats():
    """知识库统计：语义/编码两组的技巧数、已转正数。"""
    records = db_rows("SELECT technique_id, status, vulnerability, mechanism_id FROM kb_techniques")
    stats = {"semantic": {"total": 0, "promoted": 0}, "encoding": {"total": 0, "promoted": 0}}
    for r in records:
        g = technique_group(r["technique_id"], r["mechanism_id"])
        stats[g]["total"] += 1
        if r["status"] == "promoted":
            stats[g]["promoted"] += 1
    return stats


@app.post("/api/kb-techniques/import", status_code=201)
async def import_kb_techniques(payload: dict[str, Any]):
    """教材文章摄入：只存原文为「拓新燃料」，不直接提取落库。

    铁律：教材只作拓新 Agent 的燃料（_recent_textbook 读取 notes 原文），
    提取/泛化新技法由拓新 Agent（run_generalization 的 pioneer 子任务）负责。
    这里只做：原文存 notes + 签名去重（textbook_notes.content_hash）。
    """
    content = str(payload.get("content") or "").strip()
    if not content:
        raise HTTPException(status_code=422, detail="content is required")
    source_name = str(payload.get("source_name") or "manual_article.md").strip()

    # 0. 教材签名去重：同内容不重复导入
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    with DB_LOCK:
        connection = connect()
        existing = connection.execute(
            "SELECT note_id FROM textbook_notes WHERE content_hash = ?", (content_hash,)
        ).fetchone()
        if existing:
            connection.close()
            raise HTTPException(status_code=409, detail="该教材文章已导入过（签名去重）")

    # 1. 存 notes 原文（拓新 Agent 的燃料）
    kb_notes = PROJECT_ROOT / "data" / "knowledge_base" / "notes"
    kb_notes.mkdir(parents=True, exist_ok=True)
    safe_name = source_name.replace("/", "_").replace("\\", "_")
    (kb_notes / safe_name).write_text(content, encoding="utf-8")

    # 2. 记录教材笔记（供拓新 Agent 读取，不做技法提取落库）
    timestamp = utc_now()
    with DB_LOCK:
        connection = connect()
        try:
            connection.execute(
                """
                INSERT INTO textbook_notes (note_id, source_name, content_hash, source, credibility, created_at)
                VALUES (?, ?, ?, 'user', 0.5, ?)
                """,
                (str(uuid.uuid4()), source_name, content_hash, timestamp),
            )
            connection.commit()
        finally:
            connection.close()
    return {"inserted": 0, "parsed": 0, "content_hash": content_hash, "note": "教材已存为拓新燃料，技法由拓新 Agent 后续生成"}



@app.get("/api/kb-agent-handovers")
def kb_agent_handovers():
    """语义/编码 agent 实际使用手法统计（rule_labels / 编码链频次）。"""
    semantic_counts = db_rows(
        "SELECT rule_labels_json FROM candidates WHERE rule_labels_json IS NOT NULL"
    )
    from collections import Counter
    semantic_counter: Counter = Counter()
    for r in semantic_counts:
        for label in json_value(r["rule_labels_json"], []):
            semantic_counter[label] += 1
    encoding_counter: Counter = Counter()
    for r in db_rows("SELECT encoding_chain_json FROM encoding_candidates WHERE encoding_chain_json IS NOT NULL"):
        for step in json_value(r["encoding_chain_json"], []):
            encoding_counter[step.get("type", "unknown")] += 1
    return {
        "semantic": [{"label": k, "count": v} for k, v in semantic_counter.most_common()],
        "encoding": [{"label": k, "count": v} for k, v in encoding_counter.most_common()],
    }
