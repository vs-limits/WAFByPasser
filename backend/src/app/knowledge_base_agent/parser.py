"""知识库技巧解析：技巧解析 + 维度分组。

供导入脚本（backend/scripts/import_techniques.py）、知识库管理 Agent 与 API 端点共用。
"""

from __future__ import annotations

import re
from typing import Any

# 技法维度 → 分组（语义层 / 编码层）。
# 技巧 ID 形如 `sqli:lexical:xxx`，第二段是 dimension。
SEMANTIC_DIMENSIONS = {
    "semantic", "mutation", "context", "syntactic", "parser",
    "shell", "oracle", "dialect", "token", "ast", "dom", "csp", "intent",
    "alias", "argv0", "fd", "history", "indirect", "redirect", "lookup",
    "mssql", "win", "type", "param", "xslt", "server", "misc", "extension",
    "lexical",
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
# 匹配 `- **原理**: ...` / `- **模板**: ...`（兼容无前导 `- ` 的旧格式）。
FIELD_RE = re.compile(r"^\s*-?\s*\*\*\s*(原理|风险|模板)\s*\*\*\s*[:：]\s*(.*)$")


def technique_dimension(technique_id: str) -> str:
    """返回技巧 ID 的技法维度（第二段）。"""
    parts = technique_id.split(":")
    return parts[1] if len(parts) >= 2 else ""


def technique_group(technique_id: str, mechanism_id: str | None = None) -> str:
    """返回技巧所属分组：semantic / encoding。

    权威依据是 mechanism_id：kb_techniques 里的 8 大机制全是「语义绕过」机制
    （编码线走 encoding.py 独立能力，不进 kb_techniques），因此有 mechanism_id 的
    一律归 semantic。无 mechanism_id 时（旧数据）fallback 到 dimension 二分。
    """
    if mechanism_id:
        return "semantic"
    dim = technique_dimension(technique_id)
    if dim in ENCODING_DIMENSIONS:
        return "encoding"
    return "semantic"  # 默认归语义层（含未分类维度）


def parse_techniques(text: str) -> list[dict[str, Any]]:
    """解析 markdown 技巧文章，返回 [{technique_id, name, vulnerability, principle, template, source_note}]。"""
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
                "principle": "",
                "template": "",
                "source_note": "",
            }
            techniques.append(current_tech)
            continue
        if current_tech is not None:
            fm = FIELD_RE.match(line)
            if fm:
                field = fm.group(1)
                value = fm.group(2).strip()
                if field == "原理":
                    current_tech["principle"] = value
                elif field == "模板":
                    current_tech["template"] = value
                    current_tech["source_note"] = (
                        (current_tech.get("source_note", "") + " " + value).strip()
                    )

    return techniques
