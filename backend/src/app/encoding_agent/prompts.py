from pathlib import Path


ENCODING_AGENT_ROOT = Path(__file__).resolve().parent
SKILL_ROOT = ENCODING_AGENT_ROOT / "skill"
PROMPT_ROOT = ENCODING_AGENT_ROOT / "prompt"
SYSTEM_PROMPT_PATH = PROMPT_ROOT / "encoding_iteration_agent.md"

ACTIVE_SKILLS = (
    ("编码上下文理解", SKILL_ROOT / "encoding_context_understanding.md"),
    ("编码策略与组合", SKILL_ROOT / "encoding_strategy_composition.md"),
    ("规范化与解码路径推理", SKILL_ROOT / "canonicalization_decode_reasoning.md"),
    ("语义保持与重放验证", SKILL_ROOT / "semantic_replay_verification.md"),
    ("候选审阅与反馈迭代", SKILL_ROOT / "candidate_review_iteration.md"),
)


def _read_document(path: Path, name: str) -> str:
    try:
        content = path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise RuntimeError(f"无法读取编码 Agent 文档 {name}：{path}") from error
    if not content:
        raise RuntimeError(f"编码 Agent 文档 {name} 为空：{path}")
    return content


def build_encoding_system_prompt(candidate_count: int = 5) -> str:
    base_prompt = _read_document(SYSTEM_PROMPT_PATH, "系统提示词")
    skill_sections = "\n\n---\n\n".join(
        f"## 附加技能：{title}\n\n{_read_document(path, title)}"
        for title, path in ACTIVE_SKILLS
    )
    return "\n\n".join(
        (
            base_prompt,
            "---",
            "# 技能模块\n\n以下技能模块是对主提示词的深化和补充，提供详细的上下文分析、策略选择、解码推理和验证方法。与主提示词冲突时，以更严格的安全边界和更保守的置信度为准。",
            skill_sections,
            "---",
            f"# 输出约束\n\n本次任务必须生成恰好 {candidate_count} 条编码候选。严格按照主提示词第 7 节的 JSON 格式输出，不使用 Markdown 代码围栏。",
        )
    )
