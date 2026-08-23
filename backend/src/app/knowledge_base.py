"""知识库管理：技巧解析 + 维度分组 + 转正回写。

供导入脚本（backend/scripts/import_techniques.py）与 API 端点共用。
"""

from __future__ import annotations

import re
from typing import Any

# 技法维度 → 分组（语义层 / 编码层）。
# 技巧 ID 形如 `sqli:lexical:xxx`，第二段是 dimension。
SEMANTIC_DIMENSIONS = {
    "semantic", "mutation", "context", "lexical", "syntactic", "parser",
    "shell", "oracle", "dialect", "token", "ast", "dom", "csp", "intent",
    "alias", "argv0", "fd", "history", "indirect", "redirect", "lookup",
    "mssql", "win", "type", "param", "xslt", "server", "misc", "extension",
}
ENCODING_DIMENSIONS = {
    "obfuscation", "charset", "encoding", "mime", "carrier", "format",
    "config", "filename", "content", "protocol", "ext", "hash",
}

# 章节标题 -> vulnerability
SECTION_VULN = {
    "SQL": "sql-injection",
    "命令注入": "command-injection",
    "XSS": "xss",
    "文件上传": "file-upload",
    "Log4j": "log4j",
}

# 技巧 ID 前缀 -> vulnerability（兜底）
PREFIX_VULN = {
    "sqli:": "sql-injection",
    "cmdi:": "command-injection",
    "xss:": "xss",
    "upload:": "file-upload",
    "log4j2:": "log4j",
}

TECHNIQUE_RE = re.compile(r"^###\s+([a-z0-9]+):(.+?)\s+—\s+(.+)$")
SECTION_RE = re.compile(r"^##\s+(.+)")
FIELD_RE = re.compile(r"^\s*\*\*\s*(原理|风险|模板)\s*\*\*\s*[:：]\s*(.*)$")


def technique_dimension(technique_id: str) -> str:
    """返回技巧 ID 的技法维度（第二段）。"""
    parts = technique_id.split(":")
    return parts[1] if len(parts) >= 2 else ""


def technique_group(technique_id: str) -> str:
    """返回技巧所属分组：semantic / encoding。"""
    dim = technique_dimension(technique_id)
    if dim in ENCODING_DIMENSIONS:
        return "encoding"
    return "semantic"  # 默认归语义层（含未分类维度）


def parse_techniques(text: str) -> list[dict[str, Any]]:
    """解析 markdown 技巧文章，返回 [{technique_id, name, vulnerability, source_note}]。"""
    techniques: list[dict[str, Any]] = []
    current_section = ""
    current_vuln = ""
    current_tech: dict[str, Any] | None = None

    for line in text.splitlines():
        stripped = line.strip()
        m = SECTION_RE.match(stripped)
        if m:
            current_section = m.group(1)
            for key, vuln in SECTION_VULN.items():
                if key in current_section:
                    current_vuln = vuln
                    break
            continue
        m = TECHNIQUE_RE.match(stripped)
        if m:
            prefix, tid_suffix, name = m.group(1), m.group(2), m.group(3)
            technique_id = f"{prefix}:{tid_suffix}"
            vuln = PREFIX_VULN.get(f"{prefix}:", current_vuln)
            current_tech = {
                "technique_id": technique_id,
                "name": name.strip(),
                "vulnerability": vuln,
                "source_note": "",
            }
            techniques.append(current_tech)
            continue
        if current_tech is not None:
            fm = FIELD_RE.match(line)
            if fm and fm.group(1) == "模板":
                current_tech["source_note"] = (current_tech.get("source_note", "") + " " + fm.group(2)).strip()

    return techniques


# LLM 浓缩提取绕过技巧的提示词（文章输入 → 结构化技巧）。
TECHNIQUE_EXTRACT_SYSTEM_PROMPT = (
    "你是一个 WAF 绕过知识库维护 Agent。阅读用户提供的教材文章，从中**浓缩提取**出"
    "有实战价值的绕过技巧（纯绕过层，不含攻击原语/具体攻击目标）。\n"
    "每个技巧输出一个对象，字段：\n"
    "- technique_id：三段式稳定 ID，格式 `<漏洞前缀>:<技法维度>:<名称slug>`，"
    "如 `sqli:lexical:case_flip`、`xss:obfuscation:unicode`。漏洞前缀用 "
    "sqli/cmdi/xss/upload/log4j2 之一。\n"
    "- name：技巧中文名（简短）。\n"
    "- vulnerability：漏洞类型，只能是 command-injection / sql-injection / xss / file-upload / log4j 之一。\n"
    "- dimension：技法维度（第二段），如 lexical/semantic/obfuscation/charset/parser 等。\n"
    "- principle：原理（一段话，说明绕过机制）。\n"
    "- template：模板/示例 payload（可多个，用顿号或换行分隔）。\n"
    "只输出 JSON 对象：{\"techniques\": [...]}，不要输出其他文字。"
    "若文章里没有可提取的绕过技巧，返回 {\"techniques\": []}。"
)
