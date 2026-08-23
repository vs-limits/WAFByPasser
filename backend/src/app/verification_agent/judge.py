"""LLM 检验 Agent 的判定逻辑（纯函数，不含 LLM 调用，便于单测）。

LLM 实际调用在 ``main.py``（复用 ``_post_chat_completion`` / ``_extract_json_payload``），
这里只负责：组装 LLM 输入消息、解析 LLM 返回的 JSON、对判定做确定性归一化。
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.verification_agent.adapters import TargetEvidence


# 靶场动态返回的确定性结果（adapter outcome）。
OUTCOME_WAF_BLOCKED = "waf_blocked"
OUTCOME_REQUEST_ERROR = "request_error"
OUTCOME_EXECUTION_CONFIRMED = "execution_confirmed"
OUTCOME_APPLICATION_RESPONSE = "application_response"

# 归一化后的最终判定值。
BYPASS_BYPASS = "bypass"
BYPASS_BLOCK = "block"
BYPASS_ERROR = "error"
EXEC_CONFIRMED = "confirmed"
EXEC_NOT_CONFIRMED = "not_confirmed"
EXEC_UNVERIFIED = "unverified"
FAILURE_BYPASS = "bypass_failed"
FAILURE_VERIFY = "verify_failed"
FAILURE_CHECK = "check_error"

VALID_FAILURE_STAGES = {FAILURE_BYPASS, FAILURE_VERIFY, FAILURE_CHECK}
VALID_EXECUTION_VERDICTS = {EXEC_CONFIRMED, EXEC_NOT_CONFIRMED, EXEC_UNVERIFIED}

# 无法从靶场响应自动闭环验证的外带/盲注特征。
_SQL_OOB_RE = re.compile(
    r"\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE|UPDATEXML|EXTRACTVALUE)\b"
    r"|\b(SLEEP|BENCHMARK|pg_sleep|WAITFOR\s+DELAY)\b"
    r"|\\\\[a-zA-Z0-9_.-]+\.",
    re.IGNORECASE,
)
_XSS_EXFIL_RE = re.compile(
    r"document\.cookie"
    r"|\b(fetch|XMLHttpRequest|Image|sendBeacon)\b"
    r"|<(script|iframe|img)\b[^>]*src\s*=\s*['\"]?\s*https?://",
    re.IGNORECASE,
)
_LOG4J_OOB_RE = re.compile(r"\$\{jndi:", re.IGNORECASE)


def is_unverifiable_payload(content: str, vulnerability: str) -> bool:
    """判断 payload 是否无法自动闭环验证（需人工验证）。

    返回 True 表示「无法自动判断执行结果」，检验时 execution 应标 unverified。
    仅识别明确的外带/盲注特征；普通回显型 payload 返回 False（可自动判定）。
    """
    if not content:
        return False
    if vulnerability == "sql-injection":
        return bool(_SQL_OOB_RE.search(content))
    if vulnerability == "xss":
        return bool(_XSS_EXFIL_RE.search(content))
    if vulnerability == "log4j":
        # log4j 的 jndi 触发需 OOB，单靠响应无法确认执行。
        return bool(_LOG4J_OOB_RE.search(content))
    if vulnerability == "file-upload":
        # 文件上传依赖上传后访问确认；若无明确回显标记则视为需人工确认。
        return True
    return False


def build_judge_user_message(
    evidence: TargetEvidence,
    payload: str,
    vulnerability: str,
    deterministic_hints: dict[str, Any],
) -> str:
    """组装发送给检验 Agent 的用户消息（JSON 字符串）。"""
    body = {
        "vulnerability": vulnerability,
        "payload": payload,
        "target_key": evidence.target_key,
        "request_summary": evidence.request_summary,
        "http_status": evidence.http_status,
        "response_headers": evidence.response_headers,
        "response_excerpt": evidence.response_excerpt,
        "baseline_excerpt": evidence.baseline_excerpt,
        "adapter_outcome": evidence.outcome,
        "adapter_evidence": evidence.evidence,
        "deterministic_hints": deterministic_hints,
    }
    return json.dumps(body, ensure_ascii=False)


def parse_verdict(raw_message: str, extract_json: Any) -> dict[str, Any] | None:
    """用注入的 JSON 提取器解析 LLM 返回的判定。

    ``extract_json`` 复用 ``main._extract_json_payload``；注入以避免循环导入。
    """
    if not raw_message:
        return None
    decoded = extract_json(raw_message)
    if isinstance(decoded, dict):
        return decoded
    return None


def normalize_verdict(
    parsed: dict[str, Any] | None,
    target_outcome: str,
    exec_unverifiable: bool = False,
) -> dict[str, Any]:
    """把 LLM 返回 + 靶场确定性结果归一化为最终判定。

    确定性结果优先级高于 LLM：waf_blocked / request_error 强制覆盖，
    避免 LLM 对明显拦截/异常给出不一致判断。返回结构化 verdict：
      {bypass_verdict, execution_verdict, failure_stage, confidence, rationale, lesson_hint}

    三态执行结论：
      - confirmed      已确认执行成功
      - not_confirmed  已确认未执行（确定性失败）
      - unverified     无法自动判断（外带/OOB/盲注等），等待人工验证
    ``exec_unverifiable=True`` 时，若执行未被确定性确认，则标 unverified 而非
    not_confirmed（避免把「无法自动判断」误判为「验证失败」）。
    """
    if target_outcome == OUTCOME_WAF_BLOCKED:
        return _verdict(
            bypass=BYPASS_BLOCK,
            execution=EXEC_NOT_CONFIRMED,
            failure_stage=FAILURE_BYPASS,
            confidence=1.0,
            rationale="靶场返回 WAF 拦截特征，判定绕过失败",
        )
    if target_outcome == OUTCOME_REQUEST_ERROR:
        return _verdict(
            bypass=BYPASS_ERROR,
            execution=EXEC_NOT_CONFIRMED,
            failure_stage=FAILURE_CHECK,
            confidence=1.0,
            rationale="靶场请求异常/不可达，判定检验异常",
        )

    if not isinstance(parsed, dict):
        return _verdict(
            bypass=BYPASS_BLOCK,
            execution=EXEC_NOT_CONFIRMED,
            failure_stage=FAILURE_CHECK,
            confidence=0.0,
            rationale="LLM 判定不可解析，按检验异常处理",
        )

    bypass = _pick(parsed.get("bypass_verdict"), {BYPASS_BYPASS, BYPASS_BLOCK, BYPASS_ERROR}, BYPASS_BLOCK)
    execution = _pick(
        parsed.get("execution_verdict"),
        VALID_EXECUTION_VERDICTS,
        EXEC_NOT_CONFIRMED,
    )
    failure_stage = _pick(
        parsed.get("failure_stage"),
        VALID_FAILURE_STAGES,
        None,
    )
    confidence = _confidence(parsed.get("confidence"))
    rationale = str(parsed.get("rationale") or "").strip()
    lesson_hint = parsed.get("lesson_hint", parsed.get("sql_lesson_hint"))

    # 确定性执行结果：adapter 已确认执行 → 覆盖 execution。
    if target_outcome == OUTCOME_EXECUTION_CONFIRMED:
        execution = EXEC_CONFIRMED

    # 无法自动闭环且未确定性确认 → 标 unverified（等待人工），而非验证失败。
    if exec_unverifiable and execution != EXEC_CONFIRMED:
        execution = EXEC_UNVERIFIED

    # 一致性收口：绕过成功但未确认执行 → 验证失败；放行失败 → 绕过失败。
    if execution == EXEC_UNVERIFIED:
        failure_stage = None
    elif bypass == BYPASS_BYPASS and execution != EXEC_CONFIRMED:
        failure_stage = FAILURE_VERIFY
    elif bypass == BYPASS_BLOCK:
        failure_stage = FAILURE_BYPASS
    elif bypass == BYPASS_ERROR:
        failure_stage = FAILURE_CHECK
    elif bypass == BYPASS_BYPASS and execution == EXEC_CONFIRMED:
        failure_stage = None

    return _verdict(
        bypass=bypass,
        execution=execution,
        failure_stage=failure_stage,
        confidence=confidence,
        rationale=rationale or "LLM 判定完成",
        lesson_hint=lesson_hint,
    )


def _verdict(
    bypass: str,
    execution: str,
    failure_stage: str | None,
    confidence: float,
    rationale: str,
    lesson_hint: Any = None,
) -> dict[str, Any]:
    return {
        "bypass_verdict": bypass,
        "execution_verdict": execution,
        "failure_stage": failure_stage,
        "confidence": confidence,
        "rationale": rationale,
        "lesson_hint": lesson_hint,
    }


def _pick(value: Any, allowed: set[str], default: str | None) -> str | None:
    return value if value in allowed else default


def _confidence(value: Any) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, parsed))
