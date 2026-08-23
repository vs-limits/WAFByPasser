"""独立 LLM 检验 Agent：靶场适配器 + LLM 判定 + 判定归一化。"""

from app.verification_agent.adapters import (
    ADAPTERS,
    DEFAULT_RANGE,
    TargetEvidence,
    resolve_adapter,
)
from app.verification_agent.judge import (
    build_judge_user_message,
    normalize_verdict,
    parse_verdict,
)
from app.verification_agent.prompts import (
    SYSTEM_PROMPT_PATH as VERIFICATION_SYSTEM_PROMPT_PATH,
    build_judge_system_prompt,
)

__all__ = [
    "ADAPTERS",
    "DEFAULT_RANGE",
    "TargetEvidence",
    "resolve_adapter",
    "build_judge_user_message",
    "normalize_verdict",
    "parse_verdict",
    "VERIFICATION_SYSTEM_PROMPT_PATH",
    "build_judge_system_prompt",
]
