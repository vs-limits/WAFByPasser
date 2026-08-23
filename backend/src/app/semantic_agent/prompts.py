"""Semantic iteration prompt and Skill loader."""

from pathlib import Path


SEMANTIC_AGENT_ROOT = Path(__file__).resolve().parent
SKILL_ROOT = SEMANTIC_AGENT_ROOT / "skill"
PROMPT_ROOT = SEMANTIC_AGENT_ROOT / "prompt"
SYSTEM_PROMPT_PATH = PROMPT_ROOT / "semantic_mutation_agent.md"

ACTIVE_SKILLS = (
    ("漏洞语义理解 Skill", SKILL_ROOT / "vulnerability_semantic_understanding.md"),
    ("命令注入语义变异 Skill", SKILL_ROOT / "cmd_injection_mutation.md"),
    ("SQL 注入语义变异 Skill", SKILL_ROOT / "sql_injection_mutation_production.md"),
    ("XSS 语义变异 Skill", SKILL_ROOT / "xss_mutation_production.md"),
    ("过滤规则逆向 Skill", SKILL_ROOT / "filter_reverse_engineering.md"),
    ("上下文感知 Skill", SKILL_ROOT / "context_awareness.md"),
    ("漏洞验证推理 Skill", SKILL_ROOT / "vulnerability_verification_reasoning.md"),
)

COMMON_SKILLS = (
    ACTIVE_SKILLS[0],
    ACTIVE_SKILLS[4],
    ACTIVE_SKILLS[5],
    ACTIVE_SKILLS[6],
)

VULNERABILITY_SKILLS = {
    "command-injection": ACTIVE_SKILLS[1],
    "sql-injection": ACTIVE_SKILLS[2],
    "xss": ACTIVE_SKILLS[3],
}


def _read_document(path: Path, document_name: str) -> str:
    try:
        content = path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise RuntimeError(f"无法读取 Agent {document_name}：{path}") from error
    if not content:
        raise RuntimeError(f"Agent {document_name}为空：{path}")
    return content


def build_system_prompt(candidate_count: int = 5, vulnerability: str | None = None) -> str:
    """Return the part-operation-only prompt assembled with active Skills."""
    base_prompt = _read_document(SYSTEM_PROMPT_PATH, "提示词")
    selected_skills = list(COMMON_SKILLS)
    vulnerability_skill = VULNERABILITY_SKILLS.get((vulnerability or "").strip().casefold())
    if vulnerability_skill:
        selected_skills.insert(1, vulnerability_skill)
    elif vulnerability is None:
        selected_skills = list(ACTIVE_SKILLS)
    skill_sections = "\n\n".join(
        f"# 已启用 Skill：{title}\n\n{_read_document(path, title)}"
        for title, path in selected_skills
    )
    return "\n\n".join((
        base_prompt,
        "# Skill 调用约束\n\n"
        "模型必须基于后端给出的 base_parts 与 available_directions 工作。\n"
        "模型只提出 1–3 个 part_operations；后端会验证、重组并拒绝不安全或不等价结果。\n"
        "保持基础 Payload 的攻击和验证目标，仅改变表达方式而非攻击类别。\n"
        "禁止编码、解码、转义、外部请求、持久化、写入、提权、反弹 Shell 及资源消耗性结构。\n"
        "优先从 available_directions 中选择未使用的方向；优先组合 2+ 种不同方向族的技术。",
        skill_sections,
        f"# 本次输出数量\n\n必须输出恰好 {candidate_count} 条 candidates。"
        f"每条候选包含 1–3 个 part_operations，覆盖 1–3 个 direction_ids。\n"
        f"不允许输出少于 {candidate_count} 条（除非 available_directions 已耗尽且明确无法产生新变异）。",
    ))
