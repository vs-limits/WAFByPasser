"""知识库管理 Agent 提示词与 Skill 加载器。"""

from pathlib import Path


KNOWLEDGE_BASE_AGENT_ROOT = Path(__file__).resolve().parent
SKILL_ROOT = KNOWLEDGE_BASE_AGENT_ROOT / "skill"
PROMPT_ROOT = KNOWLEDGE_BASE_AGENT_ROOT / "prompt"
SYSTEM_PROMPT_PATH = PROMPT_ROOT / "knowledge_base_agent.md"

ACTIVE_SKILLS = (
    ("技巧提取规范 Skill", SKILL_ROOT / "technique_extraction_spec.md"),
)


def _read_document(path: Path, name: str) -> str:
    try:
        content = path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise RuntimeError(f"无法读取知识库管理 Agent 文档 {name}：{path}") from error
    if not content:
        raise RuntimeError(f"知识库管理 Agent 文档 {name} 为空：{path}")
    return content


def build_knowledge_base_agent_prompt() -> str:
    """读取系统提示词并组装启用 Skill。"""
    base_prompt = _read_document(SYSTEM_PROMPT_PATH, "系统提示词")
    skill_sections = "\n\n---\n\n".join(
        f"## 附加技能：{title}\n\n{_read_document(path, title)}"
        for title, path in ACTIVE_SKILLS
    )
    return "\n\n".join(
        (
            base_prompt,
            "---",
            "# 技能模块\n\n以下技能模块是对主提示词的深化和补充。与主提示词冲突时，以更严格的输出格式约束为准。",
            skill_sections,
        )
    )
