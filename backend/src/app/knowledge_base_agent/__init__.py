"""知识库管理 Agent：文章解析 + LLM 浓缩提取 + 维度分组 + 自学习引擎。"""

from app.knowledge_base_agent.agent import extract_techniques
from app.knowledge_base_agent.parser import (
    ENCODING_DIMENSIONS,
    PREFIX_VULN,
    SECTION_VULN,
    SEMANTIC_DIMENSIONS,
    parse_techniques,
    technique_dimension,
    technique_group,
)
from app.knowledge_base_agent.prompts import (
    SYSTEM_PROMPT_PATH as KNOWLEDGE_BASE_AGENT_SYSTEM_PROMPT_PATH,
    build_knowledge_base_agent_prompt,
)

__all__ = [
    "ENCODING_DIMENSIONS",
    "PREFIX_VULN",
    "SECTION_VULN",
    "SEMANTIC_DIMENSIONS",
    "extract_techniques",
    "parse_techniques",
    "technique_dimension",
    "technique_group",
    "KNOWLEDGE_BASE_AGENT_SYSTEM_PROMPT_PATH",
    "build_knowledge_base_agent_prompt",
]
