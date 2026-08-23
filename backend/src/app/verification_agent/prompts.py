from pathlib import Path


VERIFICATION_AGENT_ROOT = Path(__file__).resolve().parent
PROMPT_ROOT = VERIFICATION_AGENT_ROOT / "prompt"
SYSTEM_PROMPT_PATH = PROMPT_ROOT / "verification_judge.md"


def build_judge_system_prompt() -> str:
    """读取检验 Agent 的系统提示词。"""
    content = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8").strip()
    if not content:
        raise RuntimeError(f"检验 Agent 提示词为空：{SYSTEM_PROMPT_PATH}")
    return content
