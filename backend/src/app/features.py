"""特征统计：从验证结果的 payload 抽取「危险特征片段」，统计 200/403 通过率。

plan §3.4 的落地：穷举天然打全 200/403 分布，直接数「每个特征片段」在
绕过(200) 与 被拦(403) 样本里各出现几次，得到 pass_rate。

用途（只做方向倾向，绝不删除）：
- 高 pass_rate 片段 = WAF 盲区 → 挖深时优先复用
- 低 pass_rate 片段 = 易被拦 → 挖深时优先规避（但不禁用，因为组合后可能绕过）

特征片段定义：按漏洞类型枚举「危险 token / 符号」——确定性正则抽取，不涉及 LLM。
"""

from __future__ import annotations

import re
from typing import Any

# 各漏洞类型的特征片段（危险 token/符号）。
# 每条是 (feature_id, 正则 pattern, 说明)。
_FEATURES: dict[str, list[tuple[str, re.Pattern, str]]] = {
    "sql-injection": [
        ("comment_split", re.compile(r"/\*!?\s?\*/|/\*\*/", re.IGNORECASE), "注释拆分"),
        ("inline_comment", re.compile(r"/\*!?\d*", re.IGNORECASE), "内联/版本注释"),
        ("hash_comment", re.compile(r"#|--\s?", re.IGNORECASE), "行注释终止"),
        ("hex_literal", re.compile(r"0x[0-9a-fA-F]{2,}", re.IGNORECASE), "十六进制字面量"),
        ("union_select", re.compile(r"UNION\s+SELECT", re.IGNORECASE), "UNION SELECT"),
        ("parenthesis_union", re.compile(r"UNION\s*\(|SELECT\s*\(", re.IGNORECASE), "括号重构"),
        ("sleep_benchmark", re.compile(r"SLEEP\s*\(|BENCHMARK\s*\(|GET_LOCK\s*\(|pg_sleep\s*\(", re.IGNORECASE), "延时函数"),
        ("char_concat", re.compile(r"CHAR\s*\(|CONCAT\s*\(|UNHEX\s*\(", re.IGNORECASE), "CHAR/CONCAT 构造"),
        ("error_func", re.compile(r"UpdateXML|ExtractValue|GTID_SUBSET|exp\s*\(~", re.IGNORECASE), "报错函数"),
        ("whitespace_alt", re.compile(r"%0a|%09|%0b|%0c|\+", re.IGNORECASE), "空白替换"),
        ("operator_alt", re.compile(r"<=>|&&|\|\||<>|!=", re.IGNORECASE), "运算符替换"),
    ],
    "command-injection": [
        ("ifs", re.compile(r"\$\{?IFS\}?|\$IFS", re.IGNORECASE), "IFS 空白"),
        ("backslash_split", re.compile(r"\\[a-z]", re.IGNORECASE), "反斜杠拆分"),
        ("quote_split", re.compile(r"[a-z]'[a-z]", re.IGNORECASE), "引号拆分"),
        ("subshell", re.compile(r"\$\(|`", re.IGNORECASE), "子 Shell"),
        ("brace_expand", re.compile(r"\{[a-z/,.]+\}", re.IGNORECASE), "花括号展开"),
        ("wildcard", re.compile(r"\?|\[[a-z]\]|\*", re.IGNORECASE), "通配符"),
        ("redir", re.compile(r"2>/dev/null|2>&-|<&|<>", re.IGNORECASE), "重定向/错误抑制"),
        ("var_indirect", re.compile(r"\$[a-zA-Z_]|\$\{", re.IGNORECASE), "变量间接"),
        ("separator_alt", re.compile(r"%0a|&&|\|\||;", re.IGNORECASE), "分隔符"),
    ],
    "xss": [
        ("script_tag", re.compile(r"<script", re.IGNORECASE), "script 标签"),
        ("svg_tag", re.compile(r"<svg", re.IGNORECASE), "svg 标签"),
        ("img_tag", re.compile(r"<img", re.IGNORECASE), "img 标签"),
        ("event_handler", re.compile(r"on\w+\s*=", re.IGNORECASE), "事件处理器"),
        ("javascript_proto", re.compile(r"javascript:", re.IGNORECASE), "javascript: 协议"),
        ("data_uri", re.compile(r"data:", re.IGNORECASE), "data: URI"),
        ("entity", re.compile(r"&#x?[0-9a-f]+;|&\w+;", re.IGNORECASE), "实体编码"),
        ("template_literal", re.compile(r"\$\{.*\}|`", re.IGNORECASE), "模板字面量"),
        ("eval_alert", re.compile(r"alert\s*\(|eval\s*\(|prompt\s*\(|confirm\s*\(", re.IGNORECASE), "JS 执行"),
    ],
    "file-upload": [
        ("php_ext", re.compile(r"\.php", re.IGNORECASE), "php 扩展名"),
        ("jsp_ext", re.compile(r"\.jsp", re.IGNORECASE), "jsp 扩展名"),
        ("htaccess", re.compile(r"\.htaccess|AddType|SetHandler", re.IGNORECASE), "htaccess"),
        ("user_ini", re.compile(r"\.user\.ini|auto_prepend", re.IGNORECASE), "user.ini"),
        ("magic_bytes", re.compile(r"GIF89a|PNG|MZ", re.IGNORECASE), "魔术字节"),
        ("multipart", re.compile(r"multipart/form-data|filename\*?=", re.IGNORECASE), "multipart 字段"),
        ("double_ext", re.compile(r"\.[a-z]+\.[a-z]+", re.IGNORECASE), "多扩展名"),
    ],
    "log4j": [
        ("jndi", re.compile(r"\$\{jndi:", re.IGNORECASE), "jndi lookup"),
        ("lower_upper", re.compile(r"\$\{lower:|\$\{upper:", re.IGNORECASE), "大小写 lookup"),
        ("env_lookup", re.compile(r"\$\{env:", re.IGNORECASE), "env lookup"),
        ("default_value", re.compile(r":-", re.IGNORECASE), "默认值拼接"),
        ("nested", re.compile(r"\$\{\$\{", re.IGNORECASE), "深嵌套"),
    ],
}


def extract_features(vulnerability: str, payload: str) -> list[str]:
    """从 payload 抽取命中的特征片段 id 列表。"""
    if not payload:
        return []
    features = _FEATURES.get(vulnerability, [])
    hit: list[str] = []
    for fid, pattern, _desc in features:
        if pattern.search(payload):
            hit.append(fid)
    return hit


def record_features(
    connection: Any,
    vulnerability: str,
    payload: str,
    bypass_success: bool,
    timestamp: str,
) -> None:
    """把一条验证结果的特征统计回写 waf_features。

    bypass_success=True → 该 payload 命中的特征 n_200+1
    bypass_success=False → n_403+1
    pass_rate = n_200 / (n_200 + n_403)
    """
    for fid in extract_features(vulnerability, payload):
        row = connection.execute(
            "SELECT n_200, n_403 FROM waf_features WHERE feature = ?", (fid,)
        ).fetchone()
        if row:
            n_200, n_403 = row["n_200"], row["n_403"]
        else:
            n_200, n_403 = 0, 0
        if bypass_success:
            n_200 += 1
        else:
            n_403 += 1
        total = n_200 + n_403
        pass_rate = round(n_200 / total, 4) if total else 0.0
        connection.execute(
            """
            INSERT INTO waf_features (feature, first_seen, last_seen, n_403, n_200, pass_rate)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(feature) DO UPDATE SET
                last_seen = excluded.last_seen,
                n_403 = excluded.n_403,
                n_200 = excluded.n_200,
                pass_rate = excluded.pass_rate
            """,
            (fid, timestamp, timestamp, n_403, n_200, pass_rate),
        )


def feature_insights(connection: Any, vulnerability: str, min_samples: int = 3) -> dict[str, list[dict[str, Any]]]:
    """读特征统计，返回挖深用的「盲区(高通过率)」与「雷区(低通过率)」清单。

    门槛：采样 ≥ min_samples 才采信（防小样本噪声）。
    """
    rows = connection.execute(
        """
        SELECT feature, n_200, n_403, pass_rate
        FROM waf_features
        WHERE (n_200 + n_403) >= ?
        ORDER BY pass_rate DESC
        """,
        (min_samples,),
    ).fetchall()
    blindspots = []  # 高通过率 = 盲区，可复用
    minefields = []  # 低通过率 = 雷区，规避
    for r in rows:
        item = {
            "feature": r["feature"],
            "n_200": r["n_200"],
            "n_403": r["n_403"],
            "pass_rate": r["pass_rate"],
        }
        if r["pass_rate"] >= 0.7:
            blindspots.append(item)
        elif r["pass_rate"] <= 0.3:
            minefields.append(item)
    return {"blindspots": blindspots, "minefields": minefields}
