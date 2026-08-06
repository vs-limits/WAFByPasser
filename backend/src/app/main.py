
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
        SEMANTIC_AGENT_ROOT / "skill" / "sql_injection_mutation.md",
    ),
    "skill/xss-mutation": (
        "skill",
        "XSS 语义变异 Skill",
        SEMANTIC_AGENT_ROOT / "skill" / "xss_mutation.md",
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


class IterationPoolAddRequest(BaseModel):
    source_payload_id: str = Field(min_length=1)


class DirectWafTestRequest(BaseModel):
    target: str = Field(min_length=1)
    content: str = Field(min_length=1)
    name: str = Field(default="Direct WAF test", min_length=1)


class CandidateUpdateRequest(BaseModel):
    status: str = Field(min_length=1)
    test_note: str | None = None


class IterationPoolStartRequest(BaseModel):
    candidate_count: int = Field(default=5, ge=1, le=20)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def model_config() -> dict[str, str]:
    load_dotenv(CONFIG_PATH)
    return {
        "base_url": os.getenv("LLM_BASEURL", "").rstrip("/"),
        "api_key": os.getenv("LLM_APIKEY", ""),
        "model": os.getenv("LLM_MODEL", ""),
        "provider": os.getenv("LLM_PROVIDER", "OpenAI-compatible"),
    }


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


def call_model(
    payload: dict[str, Any],
    rule_hints: list[str],
    candidate_count: int,
    direction_context_: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    config = model_config()
    if not config["base_url"] or not config["api_key"] or not config["model"]:
        raise RuntimeError("LLM configuration is incomplete; check config/.env")
    endpoint = config["base_url"]
    if not endpoint.endswith("/chat/completions"):
        endpoint += "/chat/completions"
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
    response = httpx.post(
        endpoint,
        headers={"Authorization": f"Bearer {config['api_key']}"},
        json={"model": config["model"], "messages": messages, "temperature": 0.6},
        timeout=180,  # 增加到180秒，避免超时
    )
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
    context = {
        "base_parts": parsed["parts"],
        "available_directions": directions,
        "used_direction_ids": sorted(used),
        "ancestor_content_fingerprints": metadata.get("content_fingerprints", []),
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
        candidates: list[dict[str, Any]] = []
        seen_contents: set[str] = set()
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
                    skipped_reasons.append(f"{label}：与已生成候选重复，跳过")
                    continue
                seen_contents.add(content)

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


def db_rows(sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    """Run a read query against the project database."""
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
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


def latest_waf_run(agent: str | None, candidate_id: str | None) -> dict[str, Any] | None:
    if not agent or not candidate_id:
        return None
    latest = db_row(
        """
        SELECT * FROM waf_test_runs
        WHERE agent = ? AND candidate_id = ?
        ORDER BY created_at DESC LIMIT 1
        """,
        (agent, candidate_id),
    )
    return dict(latest) if latest else None


def payload_view(source: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(source)
    metadata = json_value(item.pop("iteration_metadata_json", None), {})
    item.pop("archived_from_candidate_id", None)
    item.pop("source_agent", None)
    item.pop("source_candidate_id", None)
    item.pop("is_pool_snapshot", None)
    item.pop("is_deleted", None)
    item["used_direction_ids"] = metadata.get("used_direction_ids", [])
    item["next_directions"] = metadata.get("next_directions", [])
    return item


def candidate_view(source: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
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
    item["latest_waf_test"] = latest_waf_run("semantic", item.get("id"))
    return item


def encoding_candidate_view(source: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
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
    item["latest_waf_test"] = latest_waf_run("encoding", item.get("id"))
    return item


def cross_source_view(source: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(source)
    item["rule_labels"] = json_value(item.pop("rule_labels_json", None), [])
    history = db_rows(
        "SELECT chain_key, content FROM cross_chain_history WHERE cross_source_id = ?",
        (item["id"],),
    )
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


def cross_candidate_view(source: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    item = dict(source)
    json_fields = {
        "encoding_chain_json": ("encoding_chain", []),
        "decode_path_json": ("decode_path", []),
        "rule_labels_json": ("rule_labels", []),
        "semantic_rule_labels_json": ("semantic_rule_labels", []),
    }
    for column, (name, default) in json_fields.items():
        item[name] = json_value(item.pop(column, None), default)
    item["latest_waf_test"] = latest_waf_run("cross", item.get("id"))
    return item


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
            if candidate["status"] != "test_success":
                raise HTTPException(
                    status_code=409,
                    detail="Only candidates marked as successful can be archived",
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
            if agent == "semantic":
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
                connection, agent, candidate, base, "test_success", candidate.get("test_note")
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


@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "ok", "message": "WAFByPasser API is running"}


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


# Payload CRUD endpoints
@app.get("/api/payloads")
async def list_payloads():
    records = db_rows(
        """
        SELECT * FROM payloads
        WHERE is_deleted = 0 AND is_pool_snapshot = 0
        ORDER BY created_at DESC
        """
    )
    result = []
    for record in records:
        item = payload_view(record)
        raw = dict(record)
        item["latest_waf_test"] = latest_waf_run(
            raw.get("source_agent"), raw.get("source_candidate_id")
        )
        result.append(item)
    return result


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


@app.post("/api/payloads")
async def create_payload(payload: dict):
    """Create a new payload."""
    import uuid
    from datetime import datetime, timezone

    payload_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            """INSERT INTO payloads (id, vulnerability, name, category, delivery, target, difficulty,
               content, usage_method, success_indicators, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (payload_id, payload.get("vulnerability"), payload.get("name"), payload.get("category", ""),
             payload.get("delivery"), payload.get("target", ""), payload.get("difficulty", ""),
             payload.get("content"), payload.get("usage_method", ""), payload.get("success_indicators", ""),
             now, now)
        )
        conn.commit()
        conn.close()

    return {"id": payload_id, **payload, "created_at": now, "updated_at": now}


@app.get("/api/candidates")
async def list_candidates(status: str | None = Query(default=None)):
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
    return [candidate_view(record) for record in db_rows(sql, params)]


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
    candidates = await list_candidates(status=None)
    result = dict(task)
    result["rule_hints"] = json_value(result.pop("rule_hints_json", None), [])
    result["direction_context"] = json_value(result.pop("direction_context_json", None), {})
    result["base_parts"] = json_value(result.pop("base_parts_json", None), [])
    result["candidates"] = [item for item in candidates if item["task_id"] == task_id]
    return result


@app.get("/api/encoding-candidates")
async def list_encoding_candidates(status: str | None = Query(default=None)):
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
    return [encoding_candidate_view(record) for record in db_rows(sql, params)]


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
    candidates = await list_encoding_candidates(status=None)
    result = dict(task)
    result["direction_context"] = json_value(result.pop("direction_context_json", None), {})
    result["candidates"] = [item for item in candidates if item["task_id"] == task_id]
    return result


@app.get("/api/cross-sources")
async def list_cross_sources():
    records = db_rows("SELECT * FROM cross_sources ORDER BY created_at DESC")
    return [cross_source_view(record) for record in records]


@app.get("/api/cross-candidates")
async def list_cross_candidates(status: str | None = Query(default=None)):
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
    return [cross_candidate_view(record) for record in db_rows(sql, params)]


@app.get("/api/cross-iterations/{task_id}")
async def get_cross_iteration(task_id: str):
    task = db_row("SELECT * FROM cross_tasks WHERE id = ?", (task_id,))
    if not task:
        raise HTTPException(status_code=404, detail="Cross iteration not found")
    candidates = await list_cross_candidates(status=None)
    result = dict(task)
    result["candidates"] = [item for item in candidates if item["task_id"] == task_id]
    return result


@app.get("/api/success-samples")
async def list_success_samples(
    agent: Literal["semantic", "encoding", "cross"] | None = Query(default=None),
    vulnerability: str | None = Query(default=None),
    target: str | None = Query(default=None),
    delivery: str | None = Query(default=None),
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
    records = db_rows(
        f"SELECT * FROM success_samples WHERE {' AND '.join(filters)} ORDER BY created_at DESC",
        tuple(params),
    )
    return [success_sample_view(record) for record in records]


@app.get("/api/success-samples/{sample_id}")
async def get_success_sample(sample_id: str):
    record = db_row(
        "SELECT * FROM success_samples WHERE id = ? AND status = 'active'",
        (sample_id,),
    )
    if not record:
        raise HTTPException(status_code=404, detail="Success sample not found")
    return success_sample_view(record)


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


@app.get("/api/reports")
async def list_reports():
    records = db_rows(
        """
        SELECT reports.*, success_samples.status AS source_status
        FROM reports
        LEFT JOIN success_samples ON success_samples.id = reports.success_sample_id
        ORDER BY reports.updated_at DESC
        """
    )
    return [report_view(record) for record in records]


@app.get("/api/reports/{report_id}")
async def get_report(report_id: str):
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


@app.get("/api/report-images/{image_id}/content")
async def get_report_image_content(image_id: str):
    image = db_row("SELECT * FROM report_images WHERE id = ?", (image_id,))
    if not image:
        raise HTTPException(status_code=404, detail="Report image not found")
    root = REPORT_EVIDENCE_ROOT.resolve()
    path = (root / image["relative_path"]).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise HTTPException(status_code=404, detail="Report image file not found")
    return FileResponse(path, media_type=image["media_type"], filename=image["original_name"])


@app.get("/api/waf-test-scene")
async def get_waf_scene():
    """Get WAF test scene configuration."""
    load_dotenv(CONFIG_PATH)

    # Check DVWA configuration
    dvwa_base = os.getenv("DVWA_BASE_URL", "").strip()
    dvwa_user = os.getenv("DVWA_USERNAME", "").strip()
    dvwa_pass = os.getenv("DVWA_PASSWORD", "").strip()
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
            "error": "DVWA 未配置，请在 config/.env 中设置 DVWA_BASE_URL, DVWA_USERNAME, DVWA_PASSWORD"
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


@app.post("/api/waf-test-runs/direct", status_code=202)
async def create_direct_waf_run(
    body: DirectWafTestRequest, background_tasks: BackgroundTasks
):
    if body.target not in DIRECT_WAF_TARGETS:
        raise HTTPException(status_code=422, detail="Unknown direct WAF target")
    run_id = str(uuid.uuid4())
    created_at = utc_now()
    with DB_LOCK:
        connection = sqlite3.connect(DB_PATH)
        try:
            connection.execute(
                """
                INSERT INTO waf_test_runs (
                    id, agent, candidate_id, base_name, vulnerability,
                    payload_snapshot, status, created_at
                ) VALUES (?, 'semantic', ?, ?, ?, ?, 'queued', ?)
                """,
                (
                    run_id,
                    run_id,
                    body.name.strip(),
                    body.target,
                    body.content,
                    created_at,
                ),
            )
            connection.commit()
        finally:
            connection.close()
    background_tasks.add_task(run_direct_waf_test, run_id, body.target, body.content)
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
