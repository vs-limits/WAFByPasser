"""Generate part-level direction catalogues for the semantic agent.

Production-grade catalogue with comprehensive semantic mutation strategies
for command-injection, SQL-injection, and XSS.
"""

from __future__ import annotations

from typing import Any

from app.semantic_agent.parts.parser import VULNERABILITY_PART_TYPES

# ---------------------------------------------------------------------------
# Direction catalogue per vulnerability — part-level
# ---------------------------------------------------------------------------

CMD_DIRECTIONS: list[dict[str, str]] = [
    # ── Command-equivalent replacement family ──
    {"id":"part:command-equivalent","label":"命令等价替换","reason":"保持相同验证目标的命令等价表达（cat→head/tail/nl, whoami→id, ls→find .）"},
    # ── Separator replacement family ──
    {"id":"part:separator-change","label":"分隔符替换","reason":"替换命令分隔符为等价结构（; → | → || → && → %0a → $(...) → ``）"},
    # ── Argument transformation family ──
    {"id":"part:argument-change","label":"参数组织变换","reason":"改变命令参数的顺序、格式或路径组织方式（/etc/./passwd, /etc//passwd）"},
    {"id":"part:argument-add","label":"添加无害参数","reason":"添加不影响执行目标的非破坏性参数（cat -n, ls -la）"},
    # ── Control flow family ──
    {"id":"part:control-add","label":"添加控制流","reason":"添加管道或条件执行结构（| head, && echo DONE）"},
    {"id":"part:control-remove","label":"移除控制流","reason":"移除可选的管道或条件执行结构"},
    # ── Path resolution family ──
    {"id":"part:path-change","label":"路径解析变换","reason":"改变命令路径的引用方式（绝对路径→相对路径→PATH解析→which查找）"},
    # ── IFS / whitespace family ──
    {"id":"part:ifs-change","label":"空白分隔变换","reason":"使用 IFS、空格、制表符等不同空白方式（${IFS}, $IFS, \\t）"},
    # ── Error handling family ──
    {"id":"part:stderr-add","label":"添加错误抑制","reason":"添加 2>/dev/null 或 2>&- 非破坏性错误处理"},
    {"id":"part:stderr-remove","label":"移除错误抑制","reason":"移除 2>/dev/null 等错误抑制（测试 WAF 是否依赖错误输出）"},
    # ── Variable indirection family ──
    {"id":"part:var-indirect","label":"变量间接引用","reason":"通过变量间接构造命令名（c=cat;$c, x=ca;y=t;$x$y）"},
    # ── Brace expansion family ──
    {"id":"part:brace-expand","label":"花括号展开","reason":"使用 {a,b} 语法构造命令或参数（{cat,head}, {c,h}at, {/etc,/tmp}）"},
    # ── Wildcard family ──
    {"id":"part:wildcard","label":"通配符路径","reason":"使用 ? * [] 匹配命令或文件路径（/etc/pass?d, /etc/[p]asswd, /bin/c?t）"},
    # ── Bounded loop family ──
    {"id":"part:loop-add","label":"添加有限循环","reason":"添加有限次数、可终止的循环结构（for i in 1; do ...; done）"},
    {"id":"part:loop-remove","label":"移除循环","reason":"移除可选的有限循环结构"},
    # ── Subshell family ──
    {"id":"part:subshell-add","label":"添加子Shell","reason":"用 $(...) 或 `` 包装命令（$(cat /etc/passwd), `cat /etc/passwd`）"},
    {"id":"part:subshell-remove","label":"移除子Shell","reason":"移除子Shell包装，直接执行命令"},
    # ── Here-string / redirect family ──
    {"id":"part:herestring-add","label":"添加Here-string","reason":"使用 <<< 或 < 重定向输入替代命令行参数"},
    {"id":"part:herestring-remove","label":"移除Here-string","reason":"移除 Here-string / 输入重定向，恢复命令行参数形式"},
    # ── Structural recombination family ──
    {"id":"part:combine-two","label":"双技术组合","reason":"组合两个不同家族的语义变异技术（如分隔符替换+变量间接引用）"},
    {"id":"part:combine-three","label":"三技术组合","reason":"组合三个不同家族的语义变异技术（深层组合绕过）"},
    # ── Shell-specific family ──
    {"id":"part:bash-ism","label":"Bash特性利用","reason":"利用 bash 特有语法（ANSI-C引用 $'...', process substitution <(...), parameter expansion）"},
]

SQL_DIRECTIONS: list[dict[str, str]] = [
    # ── Predicate rewrite family ──
    {"id":"part:predicate-rewrite","label":"谓词表达式重写","reason":"等价替换布尔谓词（1=1→1 BETWEEN 0 AND 2→1 IN (1)→NOT(1<>1)→CASE WHEN）"},
    # ── Operator switch family ──
    {"id":"part:operator-switch","label":"逻辑运算符切换","reason":"替换 OR/AND 为等价表达（OR→||, AND→&&, NOT→!）"},
    # ── Comment terminator family ──
    {"id":"part:comment-change","label":"注释结束符替换","reason":"替换 -- / # / ;%00 / /**/ 注释方式"},
    # ── Whitespace family ──
    {"id":"part:ws-change","label":"空白结构替换","reason":"替换空白/间隔为等价 SQL 语法（空格→\\t→\\n→/**/→括号）"},
    # ── Subquery family ──
    {"id":"part:subquery-add","label":"添加子查询","reason":"添加等价子查询包装（id=1→id=(SELECT 1)→id=(SELECT id FROM users LIMIT 1)）"},
    {"id":"part:subquery-remove","label":"移除子查询","reason":"移除子查询包装，恢复直接比较"},
    # ── Value rewrite family ──
    {"id":"part:value-rewrite","label":"比较值重写","reason":"等价替换比较运算符右值（'admin' 通过子查询/函数等价获取）"},
    # ── Clause restructuring family ──
    {"id":"part:clause-restructure","label":"子句结构重组","reason":"重组 WHERE 子句结构（括号重排、条件重序）"},
    # ── Join/Union family ──
    {"id":"part:join-add","label":"添加JOIN结构","reason":"通过等价 JOIN 替代简单查询"},
    # ── Structural combination family ──
    {"id":"part:sql-combine","label":"SQL技术组合","reason":"组合 2+ 种 SQL 语义变异技术（谓词重写+注释替换+空白替换）"},
]

XSS_DIRECTIONS: list[dict[str, str]] = [
    # ── Tag switch family ──
    {"id":"part:tag-switch","label":"标签替换","reason":"替换 HTML 标签为等价 XSS 触发标签（<script>→<img>→<svg>→<details>→<body>→<input>）"},
    # ── Event handler family ──
    {"id":"part:event-switch","label":"事件处理器替换","reason":"替换事件处理器为不同触发事件（onerror→onload→ontoggle→onfocus→onstart）"},
    # ── JS expression family ──
    {"id":"part:expression-rewrite","label":"JS 表达式重写","reason":"等价替换 JavaScript 执行表达式（alert(1)→prompt(1)→confirm(1)→eval('alert(1)')）"},
    # ── Closure family ──
    {"id":"part:closure-change","label":"闭合结构变换","reason":"替换标签闭合方式（>→/>→autofocus>→/onerror=...>）"},
    # ── Spacing family ──
    {"id":"part:spacing-change","label":"文本间距变换","reason":"替换空白/间距结构（空格→\\t→\\n→\\r→\\f→无空格属性语法）"},
    # ── Namespace family ──
    {"id":"part:namespace-switch","label":"命名空间替换","reason":"使用 SVG/MathML 等不同 XML 命名空间触发 XSS"},
    # ── Structural combination family ──
    {"id":"part:xss-combine","label":"XSS技术组合","reason":"组合 2+ 种 XSS 语义变异技术（标签替换+事件替换+表达式重写）"},
    # ── Attribute boundary family ──
    {"id":"part:attr-boundary","label":"属性边界变换","reason":"改变属性引号/边界样式（单引号→双引号→无引号→反引号）"},
]

DIRECTIONS_BY_VULN: dict[str, list[dict[str, str]]] = {
    "command-injection": CMD_DIRECTIONS,
    "sql-injection": SQL_DIRECTIONS,
    "xss": XSS_DIRECTIONS,
}


def semantic_part_directions(
    vulnerability_or_parts: str | list[dict[str, Any]],
    vulnerability: str | None = None,
    base_parts: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """Return the applicable part-level direction catalogue.

    Can be called as:
        semantic_part_directions(vulnerability)   — all directions for that vuln
        semantic_part_directions(parts, vulnerability) — filtered to applicable

    Args:
        vulnerability_or_parts: Either a vulnerability string or list of parsed parts
        vulnerability: Required when first arg is parts
        base_parts: (deprecated alias, use first arg)

    Returns:
        List of {id, label, reason} direction dictionaries
    """
    # Resolve overloaded first argument
    if isinstance(vulnerability_or_parts, str):
        vuln = vulnerability_or_parts
        parts = base_parts or []
    elif isinstance(vulnerability_or_parts, list):
        vuln = vulnerability or ""
        parts = vulnerability_or_parts
    else:
        return []

    if not vuln:
        return []

    all_directions = DIRECTIONS_BY_VULN.get(vuln, [])
    if not parts:
        # Return all directions unfiltered when no parts context available
        return [dict(d) for d in all_directions]

    part_types = {p.get("part_type") for p in parts}

    applicable: list[dict[str, str]] = []
    for d in all_directions:
        did = d["id"]

        # ── Command injection filtering ──

        # stderr-add: only if no stderr_handling present
        if did == "part:stderr-add":
            if "stderr_handling" not in part_types:
                applicable.append(dict(d))
        elif did == "part:stderr-remove":
            if "stderr_handling" in part_types:
                applicable.append(dict(d))

        # control-add: only if no pipeline/conditional present
        elif did == "part:control-add":
            if "pipeline" not in part_types and "conditional" not in part_types:
                applicable.append(dict(d))
        elif did == "part:control-remove":
            if "pipeline" in part_types or "conditional" in part_types:
                applicable.append(dict(d))

        # loop-add/remove
        elif did == "part:loop-add":
            if "bounded_loop" not in part_types:
                applicable.append(dict(d))
        elif did == "part:loop-remove":
            if "bounded_loop" in part_types:
                applicable.append(dict(d))

        # subshell-add/remove
        elif did == "part:subshell-add":
            if "subshell" not in part_types:
                applicable.append(dict(d))
        elif did == "part:subshell-remove":
            if "subshell" in part_types:
                applicable.append(dict(d))

        # herestring-add/remove
        elif did == "part:herestring-add":
            if "here_string" not in part_types:
                applicable.append(dict(d))
        elif did == "part:herestring-remove":
            if "here_string" in part_types:
                applicable.append(dict(d))

        # var-indirect: always applicable for command-injection
        elif did == "part:var-indirect":
            applicable.append(dict(d))

        # brace-expand: always applicable for command-injection
        elif did == "part:brace-expand":
            applicable.append(dict(d))

        # wildcard: applicable if argument exists
        elif did == "part:wildcard":
            if "argument" in part_types or "injection_command" in part_types:
                applicable.append(dict(d))

        # combine: always applicable (encourages multi-technique)
        elif did in ("part:combine-two", "part:combine-three",
                     "part:sql-combine", "part:xss-combine"):
            applicable.append(dict(d))

        # bash-ism: always applicable for command-injection (but note limited shell compatibility)
        elif did == "part:bash-ism":
            applicable.append(dict(d))

        # ── SQL injection filtering ──

        elif did == "part:subquery-add":
            if "subquery" not in part_types:
                applicable.append(dict(d))
        elif did == "part:subquery-remove":
            if "subquery" in part_types:
                applicable.append(dict(d))

        elif did == "part:join-add":
            if "join_or_union" not in part_types:
                applicable.append(dict(d))

        # ── Default: include ──

        else:
            applicable.append(dict(d))

    return applicable
