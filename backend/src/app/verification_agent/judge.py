"""LLM 检验 Agent 的判定逻辑（纯函数，不含 LLM 调用，便于单测）。

LLM 实际调用在 ``main.py``（复用 ``_post_chat_completion`` / ``_extract_json_payload``），
这里只负责：组装 LLM 输入消息、解析 LLM 返回的 JSON、对判定做确定性归一化。

关键约束：最终 ``bypass_verdict`` / ``execution_verdict`` / ``failure_stage`` **只由确定性
真值表决定**，LLM 仅贡献 ``analysis`` / ``rationale`` / ``confidence`` / 路由建议，
即使 LLM 输出 ``confirmed`` 也会被归一化层降级，绝不直接产生成功记录。
"""

from __future__ import annotations

import re
from typing import Any

from app.verification_agent.adapters import TargetEvidence


# 靶场动态返回的确定性结果（adapter outcome）。
OUTCOME_WAF_BLOCKED = "waf_blocked"
OUTCOME_REQUEST_ERROR = "request_error"
OUTCOME_EXECUTION_CONFIRMED = "execution_confirmed"
OUTCOME_APPLICATION_RESPONSE = "application_response"
OUTCOME_UNSUPPORTED_CONTEXT = "unsupported_context"

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

# 真值表禁止产生的非法组合（防御性守卫）。
_FORBIDDEN_COMBINATIONS = {
    (BYPASS_BLOCK, EXEC_CONFIRMED),
    (BYPASS_BLOCK, EXEC_UNVERIFIED),
    (BYPASS_ERROR, EXEC_CONFIRMED),
}

# LLM 允许输出的 analysis 子字段白名单（其余丢弃，字段内容长度截断）。
_ANALYSIS_FIELDS = {"bypass_assessment", "execution_assessment", "notable_signals"}

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
    *,
    sent_payload: str = "",
    payload_fidelity: str = "exact",
    delivery: str = "",
    execution_goal_id: str = "",
    verification_spec: dict[str, Any] | None = None,
) -> str:
    """组装发送给检验 Agent 的用户消息（JSON 字符串）。"""
    import json

    body = {
        "vulnerability": vulnerability,
        "payload": payload,
        "sent_payload": sent_payload or payload,
        "payload_fidelity": payload_fidelity,
        "delivery": delivery,
        "execution_goal_id": execution_goal_id,
        "verification_spec": verification_spec,
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
    仅当返回值为 dict 时返回，否则返回 None（调用方按「LLM 不可解析」处理）。
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
    *,
    exec_unverifiable: bool = False,
    deterministic_verifier_present: bool = False,
) -> dict[str, Any]:
    """把 LLM 返回 + 靶场确定性结果归一化为最终判定。

    最终 ``bypass_verdict`` / ``execution_verdict`` / ``failure_stage`` **只由确定性
    真值表决定**；LLM 的 ``bypass_verdict`` / ``execution_verdict`` / ``failure_stage``
    字段一律忽略。LLM 仅贡献 ``analysis`` / ``rationale`` / ``confidence`` /
    ``lesson_hint``（路由建议）。

    真值表（application_response 的两行由确定性验证器是否存在决定）：
      - waf_blocked                       -> block / not_confirmed / bypass_failed
      - request_error / unsupported_context -> error / not_confirmed / check_error
      - execution_confirmed               -> bypass / confirmed / None
      - application_response + verifier   -> bypass / not_confirmed / verify_failed
      - application_response (无 verifier) -> bypass / unverified / None
    """
    # 外带/盲注型 payload 无法被确定性判否，即使存在验证器也视为无确定性验证方式。
    if exec_unverifiable:
        deterministic_verifier_present = False

    if target_outcome == OUTCOME_WAF_BLOCKED:
        return _verdict(
            bypass=BYPASS_BLOCK,
            execution=EXEC_NOT_CONFIRMED,
            failure_stage=FAILURE_BYPASS,
            confidence=1.0,
            rationale="靶场返回 WAF 拦截特征，判定绕过失败",
        )
    if target_outcome in (OUTCOME_REQUEST_ERROR, OUTCOME_UNSUPPORTED_CONTEXT):
        label = (
            "靶场请求异常/不可达"
            if target_outcome == OUTCOME_REQUEST_ERROR
            else "投递上下文与靶场入口不兼容"
        )
        return _verdict(
            bypass=BYPASS_ERROR,
            execution=EXEC_NOT_CONFIRMED,
            failure_stage=FAILURE_CHECK,
            confidence=1.0,
            rationale=f"{label}，判定检验异常",
        )
    if target_outcome == OUTCOME_EXECUTION_CONFIRMED:
        return _verdict(
            bypass=BYPASS_BYPASS,
            execution=EXEC_CONFIRMED,
            failure_stage=None,
            confidence=1.0,
            rationale="确定性硬证据命中，确认执行成功",
            analysis=_analysis(parsed),
        )

    # application_response：应用放行，但无硬证据成功。
    if deterministic_verifier_present:
        bypass = BYPASS_BYPASS
        execution = EXEC_NOT_CONFIRMED
        failure_stage = FAILURE_VERIFY
    else:
        bypass = BYPASS_BYPASS
        execution = EXEC_UNVERIFIED
        failure_stage = None

    analysis = _analysis(parsed)
    rationale = _rationale(parsed)
    confidence = _confidence(parsed.get("confidence") if isinstance(parsed, dict) else None)
    lesson_hint = _route_hint(parsed)

    return _verdict(
        bypass=bypass,
        execution=execution,
        failure_stage=failure_stage,
        confidence=confidence,
        rationale=rationale or "应用放行，但无确定性执行证据",
        analysis=analysis,
        lesson_hint=lesson_hint,
    )


def check_error_verdict(rationale: str) -> dict[str, Any]:
    """LLM 请求失败 / 输出不可解析 / 字段非法时的确定性结果。

    与真值表一致地产生 ``error / not_confirmed / check_error``，且绝不伪装成
    ``block``（不追加「绕过失败」标签）。
    """
    return _verdict(
        bypass=BYPASS_ERROR,
        execution=EXEC_NOT_CONFIRMED,
        failure_stage=FAILURE_CHECK,
        confidence=0.0,
        rationale=rationale or "LLM 判定不可用，按检验异常处理",
    )


def _verdict(
    bypass: str,
    execution: str,
    failure_stage: str | None,
    confidence: float,
    rationale: str,
    analysis: dict[str, Any] | None = None,
    lesson_hint: Any = None,
) -> dict[str, Any]:
    _enforce_forbidden(bypass, execution)
    return {
        "bypass_verdict": bypass,
        "execution_verdict": execution,
        "failure_stage": failure_stage,
        "confidence": confidence,
        "rationale": rationale,
        "analysis": analysis,
        "lesson_hint": lesson_hint,
    }


def _enforce_forbidden(bypass: str, execution: str) -> None:
    if (bypass, execution) in _FORBIDDEN_COMBINATIONS:
        raise ValueError(f"非法判定组合：bypass={bypass}, execution={execution}")


def _analysis(parsed: dict[str, Any] | None) -> dict[str, Any] | None:
    """严格校验并裁剪 LLM 提供的 ``analysis``（非 dict / 非法字段 -> None）。"""
    if not isinstance(parsed, dict):
        return None
    raw = parsed.get("analysis")
    if not isinstance(raw, dict):
        return None
    out: dict[str, Any] = {}
    for key in _ANALYSIS_FIELDS:
        value = raw.get(key)
        if value is None:
            continue
        out[key] = str(value)[:2000]
    return out or None


def _rationale(parsed: dict[str, Any] | None) -> str:
    if not isinstance(parsed, dict):
        return ""
    value = parsed.get("rationale")
    if not isinstance(value, str):
        return ""
    return value.strip()[:2000]


def _route_hint(parsed: dict[str, Any] | None) -> int | None:
    """提取 LLM 提供的路由建议（sqli-labs lesson / 上传 passNN），仅正整数有效。"""
    if not isinstance(parsed, dict):
        return None
    value = parsed.get("route_suggestion", parsed.get("lesson_hint"))
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _confidence(value: Any) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, parsed))
