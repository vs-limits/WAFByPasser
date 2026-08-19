
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
from typing import Any, Literal

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

DB_LOCK = threading.Lock()
WAF_TEST_LOCK = threading.Lock()
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
    "tencent-waf",
}
CANDIDATE_STATUSES: set[str] = {"pending_test", "test_success", "test_failed", "rejected", "archived"}


class IterationPoolAddRequest(BaseModel):
    source_payload_id: str = Field(min_length=1)


class WafTestRequest(BaseModel):
    agent: Literal["semantic", "encoding", "cross"]
    candidate_id: str = Field(min_length=1)


class DirectWafTestRequest(BaseModel):
    target: str = Field(min_length=1)
    content: str = Field(min_length=1)
    name: str = Field(default="Direct WAF test", min_length=1)
    agent: Literal["semantic", "encoding", "cross"] = "semantic"
    candidate_id: str | None = Field(default=None, min_length=1)
    vulnerability: str | None = Field(default=None, min_length=1)


class CandidateUpdateRequest(BaseModel):
    status: str = Field(min_length=1)
    test_note: str | None = None


class IterationPoolStartRequest(BaseModel):
    candidate_count: int = Field(default=5, ge=1, le=20)


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


def model_config() -> dict[str, str]:
    load_dotenv(CONFIG_PATH)
    return _llm_config("LLM", "OpenAI-compatible")


def semantic_model_config() -> dict[str, str]:
    """Prefer the dedicated semantic-agent provider, then fall back to LLM_*."""
    load_dotenv(CONFIG_PATH)
    semantic = _llm_config("SEMANTIC_LLM", "OpenAI-compatible")
    if _llm_config_complete(semantic):
        return semantic
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
) -> list[dict[str, Any]]:
    config = semantic_model_config()
    if not _llm_config_complete(config):
        raise RuntimeError("Semantic LLM configuration is incomplete; check config/.env")
    messages = [
        {"role": "system", "content": build_system_prompt(candidate_count)},
        {
            "role": "user",
            "content": json.dumps(
                {
                    "base_payload": payload["content"],
                    "vulnerability": payload["vulnerability"],
                    "category": payload["category"],
                    "delivery": payload["delivery"],
                    "target": payload["target"],
                    "rule_hints": rule_hints,
                    "direction_context": direction_context_ or {},
                    "candidate_count": candidate_count,
                    "output_requirement": f"Return exactly {candidate_count} candidates.",
                },
                ensure_ascii=False,
            ),
        },
    ]
    response = _post_chat_completion(config, messages)
    if _is_quota_error(response) and config.get("source") == "SEMANTIC_LLM":
        legacy = model_config()
        if _llm_config_complete(legacy) and not _same_llm_config(config, legacy):
            LOGGER.warning("Semantic LLM quota exhausted; retrying once with legacy LLM provider")
            try:
                response = _post_chat_completion(legacy, messages)
            except Exception as fallback_error:
                raise RuntimeError(
                    f"Semantic LLM quota exhausted and legacy LLM fallback failed: {fallback_error}"
                ) from fallback_error
    response.raise_for_status()
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
            # Some models return a single candidate object directly
            candidates = [decoded] if decoded.get("part_operations") else None
    else:
        candidates = decoded

    if not isinstance(candidates, list):
        raise ValueError("模型响应中未找到 candidates 数组")

    # 只保留 dict 类型的候选，其他跳过（而不是让整个任务失败）
    valid_candidates = [c for c in candidates if isinstance(c, dict)]
    if not valid_candidates:
        raise ValueError("模型返回的候选均无效（非对象格式）")

    return valid_candidates[:candidate_count] if len(valid_candidates) > candidate_count else valid_candidates


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
        raw_candidates = call_model(
            payload,
            json_value(task.get("rule_hints_json"), []),
            task["candidate_count"],
            context,
        )
        # Existing content pool (this base + siblings) — used for cross-task dedupe.
        existing_contents = _existing_candidate_contents(
            payload["vulnerability"], payload["id"]
        )
        existing_signatures = {_sql_signature_set(c) for c in existing_contents}
        base_signature = _sql_signature_set(payload["content"])
        candidates: list[dict[str, Any]] = []
        seen_contents: set[str] = set()
        seen_signatures: set[frozenset[str]] = set()
        skipped_reasons: list[str] = []
        fallback_direction_id = available[0]["id"] if available else ""
        for index, raw in enumerate(raw_candidates):
            label = f"候选#{index + 1}"
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
                        direction_ids = [available[index % len(available)]["id"]]
                    elif fallback_direction_id:
                        direction_ids = [fallback_direction_id]

                delta = compare_semantic_delta(base_parts, candidate_parts)
                delta["operations"] = operations
                next_directions = [item for item in available if item["id"] not in direction_ids]
                candidates.append(
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
                        "execution_goal_id": raw.get("execution_goal_id"),
                    }
                )
            except Exception as candidate_error:
                skipped_reasons.append(f"{label}：处理异常 - {candidate_error}")
                continue

        if not candidates:
            reason_detail = "; ".join(skipped_reasons[:5]) if skipped_reasons else "无有效候选"
            raise ValueError(f"所有候选均处理失败：{reason_detail}")

        warning_message: str | None = None
        if skipped_reasons:
            preview = "; ".join(skipped_reasons[:3])
            if len(skipped_reasons) > 3:
                preview += f"; ...（共 {len(skipped_reasons)} 条被跳过）"
            warning_message = f"{len(candidates)} 个候选入队；{len(skipped_reasons)} 个被跳过：{preview}"

        timestamp = utc_now()
        with DB_LOCK:
            connection = sqlite3.connect(DB_PATH)
            for candidate in candidates:
                connection.execute(
                    """
                    INSERT INTO candidates (
                        id, task_id, base_payload_id, content, delivery, rule_labels_json,
                        explanation, confidence, status, test_note, created_at, updated_at,
                        used_direction_ids_json, next_directions_json, execution_goal_id,
                        semantic_dimension_ids_json, semantic_delta_json, verification_spec_json,
                        base_parts_json, candidate_parts_json, part_operations_json,
                        parser_confidence, parser_status, unsupported_reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending_test', NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()), task_id, payload["id"], candidate["content"],
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
                    ),
                )
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
            connection.close()
    except Exception as error:
        with DB_LOCK:
            connection = sqlite3.connect(DB_PATH)
            connection.execute(
                "UPDATE generation_tasks SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?",
                (str(error)[:1000], utc_now(), task_id),
            )
            connection.execute(
                "UPDATE iteration_pool_items SET status = 'pending' WHERE task_id = ?",
                (task_id,),
            )
            connection.commit()
            connection.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database and resources on startup."""
    load_dotenv(CONFIG_PATH)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)

    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS payloads (
                id TEXT PRIMARY KEY,
                vulnerability TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        # Existing installations own the full schema.  Fresh legacy databases
        # may only have payloads at this point, so index only existing tables.
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        if "waf_test_runs" in tables:
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_waf_test_runs_candidate_latest "
                "ON waf_test_runs(agent, candidate_id, created_at DESC)"
            )
        if "success_samples" in tables:
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_success_samples_active_created "
                "ON success_samples(status, created_at DESC)"
            )
        conn.commit()
        conn.close()

    yield


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


def paged_payload_response(sql: str, limit: int | None, cursor: int) -> list[dict[str, Any]] | dict[str, Any]:
    if limit is None:
        return payload_page_items(db_rows(sql))
    page_size = min(limit, MAX_PAGE_SIZE)
    total = db_row(f"SELECT COUNT(*) AS count FROM ({sql})")["count"]
    records = db_rows(f"{sql} LIMIT ? OFFSET ?", (page_size, cursor))
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
    source: sqlite3.Row | dict[str, Any], latest_waf_test: dict[str, Any] | None | object = _MISSING
) -> dict[str, Any]:
    item = dict(source)
    json_fields = {
        "rule_labels_json": ("rule_labels", []),
        "used_direction_ids_json": ("used_direction_ids", []),
        "next_directions_json": ("next_directions", []),
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
    return item


def encoding_candidate_view(
    source: sqlite3.Row | dict[str, Any], latest_waf_test: dict[str, Any] | None | object = _MISSING
) -> dict[str, Any]:
    item = dict(source)
    json_fields = {
        "encoding_chain_json": ("encoding_chain", []),
        "decode_path_json": ("decode_path", []),
        "rule_labels_json": ("rule_labels", []),
        "used_direction_ids_json": ("used_direction_ids", []),
        "next_directions_json": ("next_directions", []),
    }
    for column, (name, default) in json_fields.items():
        item[name] = json_value(item.pop(column, None), default)
    item["latest_waf_test"] = latest_waf_run("encoding", item.get("id")) if latest_waf_test is _MISSING else latest_waf_test
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
    source: sqlite3.Row | dict[str, Any], latest_waf_test: dict[str, Any] | None | object = _MISSING
) -> dict[str, Any]:
    item = dict(source)
    json_fields = {
        "encoding_chain_json": ("encoding_chain", []),
        "decode_path_json": ("decode_path", []),
        "rule_labels_json": ("rule_labels", []),
        "semantic_rule_labels_json": ("semantic_rule_labels", []),
    }
    for column, (name, default) in json_fields.items():
        item[name] = json_value(item.pop(column, None), default)
    item["latest_waf_test"] = latest_waf_run("cross", item.get("id")) if latest_waf_test is _MISSING else latest_waf_test
    return item


def candidate_page_view(agent: Literal["semantic", "encoding", "cross"], view: Any) -> Any:
    """Build a page mapper that uses one latest-WAF lookup for all its rows."""
    def map_records(records: list[sqlite3.Row]) -> list[dict[str, Any]]:
        latest_by_candidate = latest_waf_runs(agent, [record["id"] for record in records])
        return [view(record, latest_by_candidate.get(record["id"])) for record in records]

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


def sync_candidate_success_sample(
    connection: sqlite3.Connection,
    agent: Literal["semantic", "encoding"],
    candidate: dict[str, Any],
    base: dict[str, Any],
    status: str,
    test_note: str | None,
) -> None:
    timestamp = utc_now()
    if status != "test_success":
        connection.execute(
            """
            UPDATE success_samples SET status = 'deleted', updated_at = ?
            WHERE agent = ? AND candidate_id = ?
            """,
            (timestamp, agent, candidate["id"]),
        )
        return

    archived = connection.execute(
        """
        SELECT id FROM payloads
        WHERE source_agent = ? AND source_candidate_id = ? AND is_deleted = 0
        ORDER BY created_at DESC LIMIT 1
        """,
        (agent, candidate["id"]),
    ).fetchone()
    archived_payload_id = archived["id"] if archived else None
    if agent == "semantic":
        provenance = {
            "base_payload_id": candidate["base_payload_id"],
            "rule_labels": json_value(candidate.get("rule_labels_json"), []),
            "execution_goal_id": candidate.get("execution_goal_id"),
        }
        prefix = "语义迭代"
    else:
        provenance = {
            "base_payload_id": candidate["base_payload_id"],
            "encoding_chain": json_value(candidate.get("encoding_chain_json"), []),
            "decode_path": json_value(candidate.get("decode_path_json"), []),
            "origin": candidate.get("origin") or "generated",
        }
        prefix = "编码迭代"

    connection.execute(
        """
        INSERT INTO success_samples (
            id, agent, candidate_id, archived_payload_id, name, vulnerability,
            category, delivery, target, difficulty, content, test_note,
            provenance_json, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
        ON CONFLICT(agent, candidate_id) DO UPDATE SET
            archived_payload_id = excluded.archived_payload_id,
            name = excluded.name,
            vulnerability = excluded.vulnerability,
            category = excluded.category,
            delivery = excluded.delivery,
            target = excluded.target,
            difficulty = excluded.difficulty,
            content = excluded.content,
            test_note = excluded.test_note,
            provenance_json = excluded.provenance_json,
            status = 'active',
            updated_at = excluded.updated_at
        """,
        (
            str(uuid.uuid4()),
            agent,
            candidate["id"],
            archived_payload_id,
            f"{prefix} · {base['name']}",
            base["vulnerability"],
            base["category"],
            candidate["delivery"],
            base["target"],
            base["difficulty"],
            candidate["content"],
            test_note,
            json.dumps(provenance, ensure_ascii=False),
            timestamp,
            timestamp,
        ),
    )


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
            sync_candidate_success_sample(
                connection,
                agent,
                candidate,
                dict(base_record),
                body.status,
                body.test_note,
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

            connection.execute(
                """
                UPDATE success_samples
                SET status = 'invalidated', updated_at = ?
                WHERE agent = ? AND candidate_id = ? AND status != 'deleted'
                """,
                (utc_now(), agent, candidate_id),
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
            base_metadata = json_value(base.get("iteration_metadata_json"), {})
            lineage = list(base_metadata.get("direction_lineage", []))
            lineage_entry: dict[str, Any] = {
                "agent": agent,
                "candidate_id": candidate_id,
                "archive_outcome": archive_outcome,
                "used_direction_ids": used_directions,
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
            connection.execute(
                """
                INSERT INTO payloads (
                    id, name, vulnerability, category, delivery, target, difficulty,
                    content, created_at, archived_from_candidate_id, source_agent,
                    source_candidate_id, iteration_metadata_json, is_pool_snapshot,
                    usage_method, success_indicators, is_deleted
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0)
                """,
                (
                    payload_id,
                    f"{prefix} · {base['name']}",
                    base["vulnerability"],
                    base["category"],
                    candidate["delivery"],
                    base["target"],
                    base["difficulty"],
                    candidate["content"],
                    timestamp,
                    candidate_id,
                    agent,
                    candidate_id,
                    json.dumps(metadata, ensure_ascii=False),
                    guidance.get("usage_method") or "",
                    guidance.get("success_indicators") or "",
                ),
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
                connection.execute(
                    """
                    INSERT OR IGNORE INTO cross_sources (
                        id, archived_payload_id, semantic_candidate_id, name,
                        vulnerability, category, delivery, target, difficulty,
                        content, rule_labels_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
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
            sync_candidate_success_sample(
                connection, agent, candidate, base, candidate_status, candidate.get("test_note")
            )
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


def run_direct_waf_test(run_id: str, target: str, content: str) -> None:
    started_at = utc_now()
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        try:
            connection.execute(
                "UPDATE waf_test_runs SET status = 'running', started_at = ? WHERE id = ?",
                (started_at, run_id),
            )
            connection.commit()
        finally:
            connection.close()

    try:
        if target != "tencent-waf":
            raise ValueError(f"Unsupported direct WAF target: {target}")
        outcome = run_tencent_waf_test(str(CONFIG_PATH), content)
        result = outcome.get("result") or "request_error"
        status = "failed" if result == "request_error" else "completed"
        error_message = outcome.get("evidence") if status == "failed" else None
        values = (
            status,
            result,
            outcome.get("evidence"),
            outcome.get("request_summary"),
            outcome.get("response_excerpt"),
            outcome.get("http_status"),
            error_message,
            utc_now(),
            run_id,
        )
    except Exception as exc:
        values = (
            "failed",
            "request_error",
            str(exc),
            None,
            None,
            None,
            str(exc),
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
    """Small first-paint payload; detailed collections load per workspace."""
    def summarize(table: str, agent: Literal["semantic", "encoding", "cross"]) -> dict[str, Any]:
        counts = {row["status"]: row["count"] for row in db_rows(
            f"SELECT status, COUNT(*) AS count FROM {table} GROUP BY status"
        )}
        archived_failures = 0
        if agent in {"semantic", "encoding"}:
            archived_failures = db_row(
                """
                SELECT COUNT(*) AS count FROM payloads
                WHERE source_agent = ? AND is_deleted = 0
                  AND json_extract(iteration_metadata_json, '$.archive_outcome') = 'bypass_failure'
                """,
                (agent,),
            )["count"]
        pending = counts.get("pending_test", 0)
        success = counts.get("test_success", 0) + counts.get("archived", 0) - archived_failures
        failed = counts.get("test_failed", 0) + counts.get("rejected", 0) + archived_failures
        completed = success + failed
        return {
            "pending": pending,
            "success": success,
            "failed": failed,
            "completed": completed,
            "rate": (success / completed * 100) if completed else None,
        }

    agents = {
        "semantic": summarize("candidates", "semantic"),
        "encoding": summarize("encoding_candidates", "encoding"),
        "cross": summarize("cross_candidates", "cross"),
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
        "success_sample_count": db_row(
            "SELECT COUNT(*) AS count FROM success_samples WHERE status = 'active'"
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
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    cursor: int = Query(default=0, ge=0),
):
    return paged_payload_response(
        """
        SELECT * FROM payloads
        WHERE is_deleted = 0 AND is_pool_snapshot = 0
        ORDER BY created_at DESC
        """,
        limit,
        cursor,
    )


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
        "name",
        "content",
        "delivery",
        "usage_method",
        "success_indicators",
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
    required_fields = {
        "name",
        "vulnerability",
        "delivery",
        "content",
        "usage_method",
        "success_indicators",
    }
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

    payload_id = str(uuid.uuid4())
    timestamp = utc_now()
    values_by_column = {
        "id": payload_id,
        "vulnerability": payload["vulnerability"],
        "name": payload["name"].strip(),
        "category": str(payload.get("category", "")),
        "delivery": payload["delivery"].strip(),
        "target": str(payload.get("target", "")),
        "difficulty": str(payload.get("difficulty", "")),
        "content": payload["content"],
        "usage_method": payload["usage_method"],
        "success_indicators": payload["success_indicators"],
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


@app.get("/api/cross-sources")
def list_cross_sources(
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    cursor: int = Query(default=0, ge=0),
):
    return paged_cross_source_response(limit, cursor)


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
                    usage_method, success_indicators, is_deleted
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, 1, '', '', 0)
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
            if item["agent"] != "semantic":
                raise HTTPException(
                    status_code=422,
                    detail="This endpoint currently supports semantic iteration items",
                )
            if item["status"] == "started" and item.get("task_id"):
                active = connection.execute(
                    "SELECT status FROM generation_tasks WHERE id = ?", (item["task_id"],)
                ).fetchone()
                if active and active["status"] in {"queued", "running"}:
                    raise HTTPException(status_code=409, detail="This iteration task is already running")
            payload_record = connection.execute(
                "SELECT * FROM payloads WHERE id = ?", (item["snapshot_payload_id"],)
            ).fetchone()
            if not payload_record:
                raise HTTPException(status_code=409, detail="Iteration snapshot not found")
            payload = dict(payload_record)
            if payload["vulnerability"] not in SEMANTIC_PART_VULNERABILITIES:
                raise HTTPException(
                    status_code=422,
                    detail="This vulnerability is not supported by the semantic part engine",
                )
            parsed, context = semantic_task_context(payload)
            if len(context["available_directions"]) < body.candidate_count:
                raise HTTPException(
                    status_code=409,
                    detail=f"Only {len(context['available_directions'])} semantic directions remain",
                )
            config = model_config()
            task_id = str(uuid.uuid4())
            timestamp = utc_now()
            rule_hints = [item["id"] for item in context["available_directions"]]
            connection.execute(
                """
                INSERT INTO generation_tasks (
                    id, base_payload_id, status, provider, model, rule_hints_json,
                    error_message, created_at, completed_at, candidate_count,
                    direction_context_json, base_parts_json, parser_confidence,
                    parser_status, unsupported_reason
                ) VALUES (?, ?, 'queued', ?, ?, ?, NULL, ?, NULL, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    payload["id"],
                    config["provider"],
                    config["model"],
                    json.dumps(rule_hints, ensure_ascii=False),
                    timestamp,
                    body.candidate_count,
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
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()
    background_tasks.add_task(run_semantic_generation, task_id)
    return {
        "id": task_id,
        "agent": "semantic",
        "status": "queued",
        "candidate_count": body.candidate_count,
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
    """Get WAF test scene configuration."""
    load_dotenv(CONFIG_PATH)

    # Check DVWA configuration
    dvwa_base = os.getenv("WAF_DVWA_BASE_URL", os.getenv("DVWA_BASE_URL", "")).strip()
    dvwa_user = os.getenv("WAF_DVWA_USERNAME", os.getenv("DVWA_USERNAME", "")).strip()
    dvwa_pass = os.getenv("WAF_DVWA_PASSWORD", os.getenv("DVWA_PASSWORD", "")).strip()
    dvwa_configured = bool(dvwa_base and dvwa_user and dvwa_pass)

    # Check Tencent WAF configuration
    tencent_ip = os.getenv("TENCENT_WAF_IP", "").strip()
    tencent_host = os.getenv("TENCENT_WAF_HOST", "").strip()
    tencent_configured = bool(tencent_ip and tencent_host)

    # Supported vulnerabilities for DVWA
    supported_vulns = ["command-injection", "sql-injection", "xss"]

    scene = {
        "configured": dvwa_configured or tencent_configured,
        "supported": supported_vulns,
        "direct_targets": DIRECT_WAF_TARGETS,
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

    if tencent_configured:
        scene["tencent_waf"] = {
            "configured": True,
            "ip": tencent_ip,
            "host": tencent_host,
        }
    else:
        scene["tencent_waf"] = {
            "configured": False,
            "error": "腾讯云 WAF 未配置，请在 config/.env 中设置 TENCENT_WAF_IP, TENCENT_WAF_HOST"
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


@app.post("/api/waf-test-runs/direct", status_code=202)
async def create_direct_waf_run(body: DirectWafTestRequest):
    if body.target not in DIRECT_WAF_TARGETS:
        raise HTTPException(status_code=422, detail="Unknown direct WAF target")
    run_id = str(uuid.uuid4())
    candidate_id = body.candidate_id or run_id
    vulnerability = body.vulnerability or body.target
    created_at = utc_now()
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        try:
            if body.candidate_id:
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
                    candidate_id,
                    body.name.strip(),
                    vulnerability,
                    body.content,
                    created_at,
                ),
            )
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        finally:
            connection.close()
    start_background_thread(run_direct_waf_test, run_id, body.target, body.content)
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
