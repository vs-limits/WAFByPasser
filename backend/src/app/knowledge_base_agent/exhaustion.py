"""穷举 + 剪枝：从原语后端推断 + 剪枝出活跃技法清单。

plan §2/§3 的落地：
- 穷举前先做三道语法兼容性剪枝（P1 场景 / P2 后端 / P3 版本）。
- 剪枝是「死的」元数据过滤，不靠概率、不生成 payload。
- 本模块只输出「技法清单」（technique_id + 元数据），payload 变体由 LLM 现生成。

后端推断：从原始 payload（原语）推断其隐含后端，用于 P2 后端剪枝。
- 命令注入/XSS/文件上传/Log4j 默认 generic（与后端无关或后端未知）。
- SQL 注入按特征推断 mysql/oracle/mssql/postgresql/sqlite。
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# 原语后端推断（infer_backend_from_primitive）
# ---------------------------------------------------------------------------

# 各后端的高置信特征（按优先级匹配）
_BACKEND_MARKERS: list[tuple[str, re.Pattern]] = [
    # Oracle
    ("oracle", re.compile(
        r"\bDECODE\s*\(|\bCTXSYS\.|\bSYS_CONTEXT\s*\(|\bUTL_HTTP\b|\bUTL_INADDR\b"
        r"|\bDBMS_XMLTRANSLATIONS\b|\bq'\[|FROM\s+dual\b|\bVARCHAR2\b|\bROWNUM\b",
        re.IGNORECASE,
    )),
    # MSSQL
    ("mssql", re.compile(
        r"\bWAITFOR\s+DELAY\b|\bxp_cmdshell\b|\bOPENROWSET\b|\bHASHBYTES\s*\("
        r"|\bCONVERT\s*\(\s*int\b|\bCHAR\s*\(\s*0x|\bsysobjects\b|\bDB_NAME\s*\(|@\w+\s*=",
        re.IGNORECASE,
    )),
    # PostgreSQL
    ("postgresql", re.compile(
        r"\$\$\w*\$\$|\bpg_sleep\b|\bOPERATOR\s*\(\s*pg_catalog|::\w+\b|\bCAST\s*\(\s*\w+\s+AS\s+"
        r"|\bILIKE\b|#>>|->>",
        re.IGNORECASE,
    )),
    # SQLite
    ("sqlite", re.compile(
        r"\bsqlite_version\b|\bsqlite_master\b|\bGLOB\b|\bMATCH\b",
        re.IGNORECASE,
    )),
    # MySQL
    ("mysql", re.compile(
        r"UNION\s+SELECT|/\*!\d|0x[0-9a-fA-F]+|\bSLEEP\s*\(|\bBENCHMARK\s*\(|\bGET_LOCK\s*\("
        r"|\bINFORMATION_SCHEMA\b|`\w+`|\bUpdateXML\b|\bExtractValue\b|\bLOAD_FILE\b",
        re.IGNORECASE,
    )),
]


def infer_backend_from_primitive(content: str, vulnerability: str) -> str:
    """从原始 payload 推断隐含后端。

    非 SQL 注入 → generic（命令注入/XSS/上传/Log4j 与后端无关）。
    SQL 注入 → 按特征返回 oracle/mssql/postgresql/sqlite/mysql；
    无特征 → generic（无法确定，不剪后端）。
    """
    if vulnerability != "sql-injection":
        return "generic"
    for backend, pattern in _BACKEND_MARKERS:
        if pattern.search(content or ""):
            return backend
    return "generic"


# ---------------------------------------------------------------------------
# 剪枝：从 kb_techniques 挑出活跃且语法兼容的技法
# ---------------------------------------------------------------------------

def prune_techniques_for_exhaustion(
    connection: Any,
    vulnerability: str,
    primitive_backend: str,
) -> list[dict[str, Any]]:
    """穷举前剪枝，返回应穷举的技法清单（含模板）。

    三道剪枝：
    - P1 场景：vulnerability 必须匹配（sqli 原语只套 sqli 技法）。
    - P2 后端：技法 backend 为 generic 或与 primitive_backend 相同；后端未知(generic)则不剪。
    - P3 版本：version_gate 非空时暂不硬剪（本轮先保留，标注说明）。

    只返回活跃状态（seed/frontier/promoted），排除 retired。
    """
    rows = connection.execute(
        """
        SELECT technique_id, name, vulnerability, mechanism_id, family_id,
               backend, version_gate, source_note
        FROM kb_techniques
        WHERE status != 'retired'
          AND vulnerability = ?
        ORDER BY mechanism_id, family_id, technique_id
        """,
        (vulnerability,),
    ).fetchall()

    pruned: list[dict[str, Any]] = []
    skipped: dict[str, list[str]] = {"scene": [], "backend": []}
    for r in rows:
        tech = dict(r)
        backend = tech.get("backend") or "generic"
        # P1 场景剪枝：vulnerability 不匹配（查询已过滤，此处兜底）
        if tech["vulnerability"] != vulnerability:
            skipped["scene"].append(tech["technique_id"])
            continue
        # P2 后端剪枝：技法后端专属 且 与原语后端不符
        if backend != "generic" and primitive_backend != "generic" and backend != primitive_backend:
            skipped["backend"].append(tech["technique_id"])
            continue
        pruned.append(tech)

    # 每个技法附模板
    for tech in pruned:
        tpl_rows = connection.execute(
            "SELECT payload FROM technique_templates WHERE technique_id = ?",
            (tech["technique_id"],),
        ).fetchall()
        tech["templates"] = [t["payload"] for t in tpl_rows if t["payload"]][:3]

    return pruned


def exhaustion_summary(
    connection: Any,
    vulnerability: str,
    primitive_backend: str,
) -> dict[str, Any]:
    """穷举前的剪枝统计（供端点返回给前端展示）。"""
    all_rows = connection.execute(
        """
        SELECT COUNT(*) AS total FROM kb_techniques
        WHERE status != 'retired' AND vulnerability = ?
        """,
        (vulnerability,),
    ).fetchone()
    pruned = prune_techniques_for_exhaustion(connection, vulnerability, primitive_backend)
    backend_skipped = connection.execute(
        """
        SELECT COUNT(*) AS n FROM kb_techniques
        WHERE status != 'retired' AND vulnerability = ?
          AND backend != 'generic' AND backend != ?
        """,
        (vulnerability, primitive_backend),
    ).fetchone()
    return {
        "vulnerability": vulnerability,
        "primitive_backend": primitive_backend,
        "total_active": all_rows["total"] if all_rows else 0,
        "after_prune": len(pruned),
        "pruned_count": (all_rows["total"] if all_rows else 0) - len(pruned),
        "backend_pruned": backend_skipped["n"] if backend_skipped else 0,
    }


# ---------------------------------------------------------------------------
# 穷举生成提示词
# ---------------------------------------------------------------------------

EXHAUSTION_SYSTEM_PROMPT = """你服务于已授权的本地安全测试环境。你的任务是：给定一条基础攻击 payload（原语）和一组绕过技法，为**每一个技法**产出一条「用该技法改写基础 payload」的变体。

## 核心原则

1. **穷举覆盖**：每个技法都要产出一条变体，不能跳过、不能合并。技法之间互不干扰。
2. **保持攻击目标**：变体必须保留基础 payload 的漏洞类型、攻击意图与验证目标，只改变「表达方式」。
3. **一个技法 = 一个变体**：每条变体只应用它对应的那一个技法（该技法的 mechanism/family 已在输入里给出）。
4. **直接产出最终 payload 文本**：不要 part_operations，不要编码。产出后端/浏览器能直接解析的原始语义文本。
5. **安全边界**：禁止反弹 Shell、持久化、提权、文件写入/删除、下载执行、无限循环、后台执行、大量输出 DoS。

## 输出格式

只输出严格 JSON：

```json
{
  "candidates": [
    {
      "technique_id": "sqli:lexical:case_flip",
      "content": "uNiOn sElEcT 1,2,3",
      "explanation": "大小写混写 UNION SELECT"
    }
  ]
}
```

- `technique_id` 必须来自输入技法清单里的 id。
- `content` 是最终 payload 文本（不含 URL 百分号编码，编码由发送层处理）。
- 每个输入技法恰好对应一条 candidate，candidates 数量 = 输入技法数量。
"""


def build_exhaustion_user_message(
    base_payload: str,
    vulnerability: str,
    techniques: list[dict[str, Any]],
) -> str:
    """构造穷举生成的 user message（技法清单 + base payload）。"""
    technique_list = [
        {
            "technique_id": t["technique_id"],
            "name": t.get("name", ""),
            "mechanism": t.get("mechanism_id", ""),
            "family": t.get("family_id", ""),
            "backend": t.get("backend", "generic"),
            "templates": t.get("templates", []),
            "source_note": t.get("source_note", ""),
        }
        for t in techniques
    ]
    return (
        f"基础攻击 payload（原语）：{base_payload}\n"
        f"漏洞类型：{vulnerability}\n"
        f"待穷举的技法清单（共 {len(techniques)} 个，每个都要产出一条变体）：\n"
        + "\n".join(
            f"- {t['technique_id']} ({t.get('name','')})：{t.get('source_note','')[:200]}"
            for t in techniques
        )
        + f"\n\n请为上述 {len(techniques)} 个技法各产出一条变体。"
    )
