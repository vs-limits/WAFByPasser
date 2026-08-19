"""Deterministic payload part parser for command-injection, SQL-injection, XSS."""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Part-type catalogues per vulnerability
# ---------------------------------------------------------------------------

CMD_INJECTION_PART_TYPES: dict[str, dict[str, Any]] = {
    "safe_prefix":      {"label":"安全前缀","required_default":True,"allowed_ops":["replace"]},
    "quote_context":    {"label":"引号/参数上下文","required_default":True,"allowed_ops":["replace"]},
    "separator":        {"label":"命令分隔符","required_default":True,"allowed_ops":["replace"]},
    "injection_command":{"label":"注入命令","required_default":True,"allowed_ops":["replace"]},
    "pipeline":         {"label":"管道结构","required_default":False,"allowed_ops":["add","remove","replace"]},
    "conditional":      {"label":"条件/逻辑结构","required_default":False,"allowed_ops":["add","remove","replace"]},
    "bounded_loop":     {"label":"有限循环","required_default":False,"allowed_ops":["add","remove","replace"]},
    "path":             {"label":"命令路径","required_default":False,"allowed_ops":["replace","add","remove"]},
    "argument":         {"label":"命令参数","required_default":False,"allowed_ops":["replace","add","remove"]},
    "stderr_handling":  {"label":"错误输出处理","required_default":False,"allowed_ops":["add","remove","replace"]},
    "ifs_whitespace":   {"label":"IFS/空白结构","required_default":False,"allowed_ops":["replace","add","remove"]},
    "var_indirection":  {"label":"变量间接引用","required_default":False,"allowed_ops":["add","remove","replace"]},
    "brace_expansion":  {"label":"花括号展开","required_default":False,"allowed_ops":["add","remove","replace"]},
    "wildcard_part":    {"label":"通配符模式","required_default":False,"allowed_ops":["add","remove","replace"]},
    "subshell":         {"label":"子Shell包装","required_default":False,"allowed_ops":["add","remove","replace"]},
    "here_string":      {"label":"Here-string重定向","required_default":False,"allowed_ops":["add","remove","replace"]},
    "output_marker":    {"label":"验证标记","required_default":True,"allowed_ops":["replace"]},
}

SQL_INJECTION_PART_TYPES: dict[str, dict[str, Any]] = {
    "prefix":              {"label":"合法前缀","required_default":True,"allowed_ops":["replace"]},
    "quote_boundary":      {"label":"引号边界","required_default":True,"allowed_ops":["replace"]},
    "operator":            {"label":"逻辑/比较运算符","required_default":True,"allowed_ops":["replace"]},
    "predicate":           {"label":"谓词表达式","required_default":True,"allowed_ops":["replace"]},
    "subquery":            {"label":"子查询/子表达式","required_default":False,"allowed_ops":["add","remove"]},
    "join_or_union":       {"label":"JOIN/UNION","required_default":False,"allowed_ops":["add","remove"]},
    "whitespace_structure":{"label":"空白结构","required_default":True,"allowed_ops":["replace"]},
    "comment_terminator":  {"label":"注释结束符","required_default":True,"allowed_ops":["replace"]},
    "comparison_value":    {"label":"比较值","required_default":True,"allowed_ops":["replace"]},
}

XSS_PART_TYPES: dict[str, dict[str, Any]] = {
    "context_prefix":        {"label":"上下文前缀","required_default":True,"allowed_ops":["replace"]},
    "attribute_boundary":    {"label":"属性边界","required_default":True,"allowed_ops":["replace"]},
    "tag":                   {"label":"HTML 标签","required_default":True,"allowed_ops":["replace"]},
    "event_handler":         {"label":"事件处理器","required_default":True,"allowed_ops":["replace"]},
    "javascript_expression": {"label":"JS 表达式","required_default":True,"allowed_ops":["replace"]},
    "closing_structure":     {"label":"闭合结构","required_default":True,"allowed_ops":["replace"]},
    "text_spacing":          {"label":"文本间距","required_default":False,"allowed_ops":["replace","add","remove"]},
}

VULNERABILITY_PART_TYPES: dict[str, dict[str, dict[str, Any]]] = {
    "command-injection": CMD_INJECTION_PART_TYPES,
    "sql-injection": SQL_INJECTION_PART_TYPES,
    "xss": XSS_PART_TYPES,
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_semantic_parts(content: str, vulnerability: str, delivery: str) -> dict[str, Any]:
    """Parse payload content into structured semantic parts.

    Returns:
      {"parts": [...], "status": "supported"|"unsupported", "confidence": float,
       "label": str, "unsupported_reason": str|None}
    """
    if vulnerability not in VULNERABILITY_PART_TYPES:
        return {"parts":[],"status":"unsupported","confidence":0.0,"label":"","unsupported_reason":f"不支持漏洞类型：{vulnerability}"}
    if vulnerability == "command-injection":
        return _parse_command_injection(content)
    if vulnerability == "sql-injection":
        return _parse_sql_injection(content)
    if vulnerability == "xss":
        return _parse_xss(content)
    return {"parts":[],"status":"unsupported","confidence":0.0,"label":"","unsupported_reason":""}


# =============================================================================
# Command-injection parser (enhanced — detects all declared part types)
# =============================================================================

_KNOWN_COMMANDS = {
    "whoami","id","uname","hostname","pwd","echo","cat","head","tail",
    "ls","find","grep","ps","netstat","ss","curl","wget","ifconfig",
    "arp","ping","env","df","free","uptime","date","wc","sort","nl",
    "cut","xargs","which","type","printf","awk","sed","more","less",
    "tac","rev","dir","tree","lsof",
}

# Patterns for detecting shell features
_RE_IFS = re.compile(r"\$\{?IFS\}?", re.IGNORECASE)
_RE_VAR_INDIRECT = re.compile(
    r"(?:^|(?<=[;&|]))\s*\w+=(?:[^;&|]+?)\s*[;&|]\s*\$\{?\w+\}?",
    re.MULTILINE,
)
_RE_BRACE_EXPAND = re.compile(r"\{[^},]*(?:,[^},]*)+[^}]*\}")
_RE_WILDCARD = re.compile(r"(?:[?*]|\[[^\]]+\])(?=[^/\s]*)")
_RE_SUBSHELL = re.compile(r"\$\([^)]+\)|`[^`]+`")
_RE_HERE_STRING = re.compile(r"<<<\s*\S+")
_RE_BOUNDED_LOOP = re.compile(
    r"\b(?:for\s+\w+\s+in\s+(?:\d+(?:\s+\d+)*|\S+)\s*;?\s*do\b"
    r"|while\s+\[?\s*\$\w+\s+-[a-z]+\s+\d+\s*\]?\s*;?\s*do\b"
    r"|for\s*\(\s*\(?\s*\w+\s*=\s*\d+)",
    re.IGNORECASE | re.MULTILINE,
)
_RE_CONDITIONAL = re.compile(r"(?:&&|\|\|)\s*\S+")
_RE_PATH_REF = re.compile(r"^(/(?:usr/)?(?:s?bin|usr/local/bin)/\w+)")
_RE_INPUT_REDIRECT = re.compile(r"<\s*\S+")


def _part(pid: str, ptype: str, raw: str, start: int, end: int, required: bool,
          role: str, deps: list[str] | None = None, conf: float = 0.9) -> dict[str, Any]:
    return {"part_id":pid,"part_type":ptype,"raw":raw,
            "position":{"start":start,"end":end},"required":required,
            "semantic_role":role,"dependencies":deps or [],"confidence":conf}


def _parse_command_injection(content: str) -> dict[str, Any]:
    txt = content.strip()
    issues: list[str] = []
    parts: list[dict[str, Any]] = []
    used_ranges: list[tuple[int, int]] = []  # Track covered character ranges
    pid_counter = [0]

    def _next_pid() -> str:
        pid_counter[0] += 1
        return f"p{pid_counter[0]}"

    def _add_part(ptype: str, raw: str, start: int, end: int,
                  required: bool | None = None, role: str = "",
                  deps: list[str] | None = None, conf: float = 0.9) -> str:
        """Add a part and return its ID. Uses catalogue default for required."""
        if required is None:
            required = CMD_INJECTION_PART_TYPES.get(ptype, {}).get("required_default", False)
        pid = _next_pid()
        # Avoid overlapping ranges
        for r_start, r_end in used_ranges:
            if start < r_end and end > r_start:
                conf = max(0.3, conf - 0.2)
        used_ranges.append((start, end))
        parts.append(_part(pid, ptype, raw, start, end, required, role or ptype, deps, conf))
        return pid

    # ── Phase 1: Sequential structural parsing ──────────────────────────

    # 1. safe_prefix — IP address
    ip_m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", txt)
    prefix_id = ""
    if ip_m:
        prefix_id = _add_part("safe_prefix", ip_m.group(1), 0, ip_m.end(),
                              True, "DVWA 兼容 IP 前缀", conf=0.95)
        pos = ip_m.end()
    else:
        prefix_id = _add_part("safe_prefix", "", 0, 0, False, "无安全前缀", conf=0.5)
        pos = 0

    # 2. quote_context — whitespace/quotes after IP
    after_ip = txt[pos:]
    qm = re.match(r"(\s*)", after_ip)
    qs = qm.group(1)
    quote_id = _add_part("quote_context", qs, pos, pos + len(qs),
                         bool("'" in qs or '"' in qs),
                         "引号/空白上下文", [prefix_id], conf=0.85)
    pos += len(qs)
    after_ip = txt[pos:]

    # 3. separator — try each pattern in priority order
    sep_patterns = [
        (r";", ";"),
        (r"&&", "&&"),
        (r"\|\|", "||"),
        (r"\|", "|"),
        (r"\n|%0a|%0A", "\\n"),
        (r"\$\(.*?\)", "$()"),
        (r"`[^`]*`", "`...`"),
        (r"&(?!&)", "&"),
    ]
    sep_match = None
    for pattern, _name in sep_patterns:
        m = re.match(pattern, after_ip, re.IGNORECASE)
        if m:
            sep_match = m
            break

    sep_id = ""
    if sep_match:
        sep_text = sep_match.group(0)
        sep_id = _add_part("separator", sep_text, pos, pos + len(sep_text),
                           True, "命令分隔符", [prefix_id], conf=0.9)
        pos += len(sep_text)
        after_ip = txt[pos:]
    elif not after_ip.strip():
        issues.append("无后续命令体")
        sep_id = _add_part("separator", "", pos, pos, True,
                           "无分隔符（未检测到命令）", [prefix_id], conf=0.3)
    else:
        sep_id = _add_part("separator", "", pos, pos, True,
                           "隐式分隔符（直接命令）", [prefix_id], conf=0.6)

    # 4. injection_command + argument + path
    remaining = after_ip.strip()
    cmd_id = ""
    arg_id = ""
    if remaining:
        cmd_end = _find_command_end(remaining)
        cmd_text = remaining[:cmd_end].strip()
        rest = remaining[cmd_end:]

        if cmd_text:
            words = cmd_text.split()
            cmd_word = words[0]
            cmd_start = pos + (after_ip.find(cmd_word) if cmd_word in after_ip else 0)
            cmd_abs_start = txt.find(cmd_word, pos) if cmd_word else pos
            if cmd_abs_start == -1:
                cmd_abs_start = pos

            # Detect path prefix on command (e.g. /bin/cat, ./cat)
            path_m = _RE_PATH_REF.match(cmd_word)
            if path_m:
                path_text = path_m.group(1)
                cmd_base = cmd_word[len(path_text):]
                _add_part("path", path_text, cmd_abs_start, cmd_abs_start + len(path_text),
                          False, f"命令路径 {{{path_text}}}", [sep_id], conf=0.9)
                cmd_id = _add_part("injection_command", cmd_base,
                                   cmd_abs_start + len(path_text),
                                   cmd_abs_start + len(cmd_word),
                                   True, "注入命令（路径去前缀）", [sep_id],
                                   conf=0.88)
            else:
                is_known = any(
                    kw in cmd_word.lower()
                    .replace("${ifs}", " ").replace("$ifs", " ")
                    .replace("{", "").replace("}", "").replace(",", "")
                    for kw in _KNOWN_COMMANDS
                )
                conf = 0.92 if is_known else 0.55
                cmd_id = _add_part("injection_command", cmd_word,
                                   cmd_abs_start, cmd_abs_start + len(cmd_word),
                                   True,
                                   ("已知命令" if is_known else "未识别命令（建议人工复核）"),
                                   [sep_id], conf=conf)

            # arguments
            args = cmd_text[len(cmd_word):].strip()
            if args:
                arg_abs_start = cmd_abs_start + len(cmd_word)
                arg_id = _add_part("argument", args, arg_abs_start,
                                   arg_abs_start + len(args),
                                   False, "命令参数", [cmd_id], conf=0.85)

        # ── Phase 2: Scan remaining text for optional structures ────────────

        # pipeline
        pipe_m = re.search(r"(?<!\d)>?\s*\|(?!\|)\s*", rest)
        if pipe_m:
            pipe_start = pos + (after_ip.find(rest[pipe_m.start():]) if after_ip else 0)
            pipe_text = rest[pipe_m.start():].strip()
            _add_part("pipeline", pipe_text, pipe_start, pipe_start + len(pipe_text),
                      False, "管道后续处理", [cmd_id] if cmd_id else [], conf=0.8)

        # conditional (&& / ||)
        cond_m = re.search(r"(?:^|\s)(&&|\|\|)\s*(\S.*)$", rest)
        if cond_m and "|" not in cond_m.group(1):  # Avoid matching single pipe
            cond_start = pos + (after_ip.find(cond_m.group(0)) if after_ip else 0)
            _add_part("conditional", cond_m.group(0).strip(),
                      cond_start, cond_start + len(cond_m.group(0)),
                      False, f"条件执行 {{{cond_m.group(1)}}}",
                      [cmd_id] if cmd_id else [], conf=0.85)

        # stderr handling
        stderr_m = re.search(r"(2>&1\s*>/dev/null|>/dev/null\s*2>&1|2>&-\s*1>&-|2>/tmp/null|2>/dev/null|2>&-|2>&1)", rest)
        if stderr_m:
            se_start = pos + (after_ip.find(stderr_m.group(0)) if after_ip else 0)
            _add_part("stderr_handling", stderr_m.group(0),
                      se_start, se_start + len(stderr_m.group(0)),
                      False, "错误输出抑制", [cmd_id] if cmd_id else [], conf=0.88)

        # bounded_loop
        loop_m = _RE_BOUNDED_LOOP.search(txt)
        if loop_m:
            _add_part("bounded_loop", loop_m.group(0),
                      loop_m.start(), loop_m.end(),
                      False, "有限循环结构", [cmd_id] if cmd_id else [], conf=0.82)

    # ── Phase 3: Global scans for shell-feature parts ────────────────────

    # IFS whitespace
    for m in _RE_IFS.finditer(txt):
        if not _overlaps_any(m.start(), m.end(), parts):
            _add_part("ifs_whitespace", m.group(0), m.start(), m.end(),
                      False, "IFS 空白替换", [cmd_id] if cmd_id else [], conf=0.88)

    # Variable indirection (e.g., x=cat; $x /etc/passwd)
    for m in _RE_VAR_INDIRECT.finditer(txt):
        if not _overlaps_any(m.start(), m.end(), parts):
            _add_part("var_indirection", m.group(0).strip(),
                      m.start(), m.end(), False,
                      "变量间接引用", [cmd_id] if cmd_id else [], conf=0.85)

    # Brace expansion
    for m in _RE_BRACE_EXPAND.finditer(txt):
        if not _overlaps_any(m.start(), m.end(), parts):
            # Avoid false positives on JSON-like or regex-like patterns
            raw = m.group(0)
            if raw.count(",") >= 1 and len(raw) <= 60:
                _add_part("brace_expansion", raw, m.start(), m.end(),
                          False, "花括号展开", [cmd_id] if cmd_id else [], conf=0.82)

    # Wildcard patterns in arguments/paths
    for m in _RE_WILDCARD.finditer(txt):
        if not _overlaps_any(m.start(), m.end(), parts):
            _add_part("wildcard_part", m.group(0), m.start(), m.end(),
                      False, "通配符模式", [arg_id or cmd_id] if (arg_id or cmd_id) else [], conf=0.8)

    # Subshell wrapping
    for m in _RE_SUBSHELL.finditer(txt):
        if not _overlaps_any(m.start(), m.end(), parts):
            _add_part("subshell", m.group(0), m.start(), m.end(),
                      False, "子Shell包装", [cmd_id] if cmd_id else [], conf=0.85)

    # Here-string
    for m in _RE_HERE_STRING.finditer(txt):
        if not _overlaps_any(m.start(), m.end(), parts):
            _add_part("here_string", m.group(0), m.start(), m.end(),
                      False, "Here-string 重定向", [cmd_id] if cmd_id else [], conf=0.88)

    # Input redirect (cat < /etc/passwd style)
    for m in _RE_INPUT_REDIRECT.finditer(txt):
        if not _overlaps_any(m.start(), m.end(), parts):
            raw = m.group(0)
            # Only capture if it looks like a file input redirect (not << or <<<)
            if not raw.startswith("<<"):
                _add_part("here_string", raw, m.start(), m.end(),
                          False, "输入重定向", [cmd_id] if cmd_id else [], conf=0.78)

    # ── Phase 4: output_marker ──────────────────────────────────────────

    ok_m = re.search(r"[A-Z][A-Z0-9_]{2,}_OK\b", txt)
    if ok_m:
        if not _overlaps_any(ok_m.start(), ok_m.end(), parts):
            _add_part("output_marker", ok_m.group(0), ok_m.start(), ok_m.end(),
                      True, "回显验证标记", conf=0.95)

    # ── Finalize ─────────────────────────────────────────────────────────

    # Sort by position
    parts.sort(key=lambda p: p["position"]["start"])

    avg_conf = sum(p["confidence"] for p in parts) / max(len(parts), 1)
    status = "supported" if avg_conf >= 0.50 else "unsupported"
    label = "命令注入部件解析"

    return {
        "parts": parts, "status": status, "confidence": round(avg_conf, 3),
        "label": label,
        "unsupported_reason": "; ".join(issues) if issues else None,
    }


def _overlaps_any(start: int, end: int, existing_parts: list[dict[str, Any]]) -> bool:
    """Check if a character range overlaps any existing part."""
    for p in existing_parts:
        ps = p["position"]["start"]
        pe = p["position"]["end"]
        if start < pe and end > ps:
            return True
    return False


def _find_command_end(text: str) -> int:
    """Find where the command + args portion ends (before pipe, stderr, etc)."""
    stops = []
    for pat in [r"2>/dev/null", r"2>&-", r"2>&1", r"\|", r"\s+&&\s+",
                r"\s+\|\|\s+", r"<<<\s", r"\s+&\s*$"]:
        for m in re.finditer(pat, text):
            stops.append(m.start())
    if stops:
        return min(stops)
    return len(text)


# =============================================================================
# SQL-injection parser
# =============================================================================

# SQL keyword / function catalogues (used to enrich parse granularity)
_SQL_UNION_JOIN_RE = re.compile(
    r"\b(UNION(?:\s+ALL)?(?:\s+SELECT)?|JOIN|INNER\s+JOIN|LEFT\s+JOIN|RIGHT\s+JOIN|CROSS\s+JOIN)\b",
    re.IGNORECASE,
)
_SQL_TIME_FN_RE = re.compile(
    r"\b(SLEEP|BENCHMARK|GET_LOCK|pg_sleep|WAITFOR\s+DELAY)\s*\(",
    re.IGNORECASE,
)
_SQL_ERROR_FN_RE = re.compile(
    r"\b(UpdateXML|ExtractValue|GTID_SUBSET|EXP|FLOOR|POLYGON|LINESTRING|MULTIPOINT)\s*\(",
    re.IGNORECASE,
)
_SQL_INFO_FN_RE = re.compile(
    r"\b(database|schema|version|user|current_user|session_user|system_user|"
    r"@@version|@@global\.version|@@innodb_version|LOAD_FILE|CONCAT|CONCAT_WS|"
    r"CHAR|HEX|UNHEX|ASCII|ORD|SUBSTRING|SUBSTR|MID|LEFT|RIGHT)\b",
    re.IGNORECASE,
)
_SQL_STACKED_RE = re.compile(r";\s*(?:DROP|INSERT|UPDATE|DELETE|CREATE|ALTER|SELECT|EXEC|WAITFOR)",
                             re.IGNORECASE)


def _parse_sql_injection(content: str) -> dict[str, Any]:
    """Parse SQL injection payload into granular semantic parts.

    Emits (in position order):
      - prefix (leading integer / empty string)
      - quote_boundary (opening ' or ")
      - operator (OR / AND / NOT / XOR / && / || / !)
      - join_or_union (UNION [ALL] SELECT / JOIN variants, optional)
      - predicate (main boolean / value expression)
      - subquery (parenthesised SELECT, optional)
      - whitespace_structure (space or comment used as separator)
      - comment_terminator (-- / # / ;%00 / /*...*/ / stacked ; DROP…)

    The parser is intentionally conservative: parts it cannot locate are
    replaced with empty-required parts so downstream operations can still add
    or replace them.
    """
    txt = content.strip()
    parts: list[dict[str, Any]] = []
    used_pid = [0]

    def _mkid() -> str:
        used_pid[0] += 1
        return f"p{used_pid[0]}"

    pos = 0

    # 1. prefix — MUST anchor at position 0 (avoids picking digits from UNION SELECT 1,2,3)
    prefix_m = re.match(r"^(\d+)", txt)
    if prefix_m:
        parts.append(_part(_mkid(), "prefix", prefix_m.group(1), 0, prefix_m.end(),
                           True, "查询参数前缀", conf=0.92))
        pos = prefix_m.end()
    else:
        # explicit empty prefix so operations can replace it later
        parts.append(_part(_mkid(), "prefix", "", 0, 0, True, "空前缀（无数字）", conf=0.7))

    # 2. quote_boundary — opening quote (single/double)
    qm = re.match(r"['\"]", txt[pos:])
    if qm:
        parts.append(_part(_mkid(), "quote_boundary", qm.group(0), pos, pos + qm.end(),
                           True, "SQL 引号边界", conf=0.92))
        pos += qm.end()
    else:
        parts.append(_part(_mkid(), "quote_boundary", "", pos, pos,
                           True, "无引号边界（数值型注入）", conf=0.6))

    # 3. operator — logical operator (word or symbolic). Include the leading
    # whitespace in the operator's raw so roundtripping preserves original
    # spacing.  The LLM is free to replace with a new operator; the composer
    # keeps the raw verbatim.
    op_re = re.compile(r"(\s*)(\|\||&&|\bOR\b|\bAND\b|\bNOT\b|\bXOR\b|!(?!=))", re.IGNORECASE)
    op_m = op_re.match(txt[pos:])
    if op_m and op_m.group(2):
        raw_op = op_m.group(0)  # include leading ws
        parts.append(_part(_mkid(), "operator", raw_op,
                           pos, pos + len(raw_op),
                           True, "逻辑运算符", conf=0.9))
        pos += op_m.end()
    else:
        # empty operator so replace ops can still hit it
        parts.append(_part(_mkid(), "operator", "", pos, pos,
                           True, "隐式/缺失逻辑运算符", conf=0.55))

    # 4. Locate the comment / stacked terminator to bound the middle segment.
    comment_m = re.search(
        r"(?:--\s+.*$|--\s*$|#\s*$|#\s+.*$|;%00.*$|/\*.*?\*/\s*$|/\*[^*]*$)",
        txt[pos:],
    )
    stacked_m = _SQL_STACKED_RE.search(txt[pos:])
    if stacked_m and (not comment_m or stacked_m.start() <= comment_m.start()):
        terminator_start = stacked_m.start()
    elif comment_m:
        terminator_start = comment_m.start()
    else:
        terminator_start = len(txt) - pos

    middle_start = pos
    middle_end = pos + terminator_start
    middle_text = txt[middle_start:middle_end]
    cursor = middle_start

    # 5. join_or_union — optional, occupies the head of the middle segment.
    # Include any leading whitespace so the round-trip preserves it.
    join_m = _SQL_UNION_JOIN_RE.search(middle_text)
    if join_m and join_m.start() < 8:
        lead_ws = middle_text[:join_m.start()]
        raw_join = lead_ws + join_m.group(0)
        j_start = middle_start
        j_end = middle_start + join_m.end()
        parts.append(_part(_mkid(), "join_or_union", raw_join,
                           j_start, j_end, False, "UNION/JOIN 结构", conf=0.9))
        cursor = j_end

    # 6. predicate — everything left in the middle segment (may include internal
    #    subquery / comparison_value markers, which are appended as VIRTUAL parts).
    predicate_text = txt[cursor:middle_end].strip(" \t")
    if predicate_text:
        pred_id = _mkid()
        parts.append(_part(pred_id, "predicate", txt[cursor:middle_end],
                           cursor, middle_end, True,
                           "谓词/表达式", conf=0.85))

        # Virtual subquery marker (not recomposed; describes an interior structure)
        sub_m = re.search(r"\(\s*SELECT\b[^)]*\)", predicate_text, re.IGNORECASE)
        if sub_m:
            v = _part(_mkid(), "subquery", sub_m.group(0),
                      cursor + sub_m.start(), cursor + sub_m.end(),
                      False, "子查询(内嵌)", [pred_id], conf=0.86)
            v["virtual"] = True
            parts.append(v)

        # Virtual comparison_value hint (RHS of the leftmost comparator)
        cmp_m = re.search(
            r"(?:=|<=>|<>|!=|>=|<=|>|<|\bLIKE\b|\bREGEXP\b|\bRLIKE\b|\bIN\b|\bBETWEEN\b)\s*(.+)$",
            predicate_text, re.IGNORECASE)
        if cmp_m:
            v_start = cursor + predicate_text.find(cmp_m.group(1))
            v = _part(_mkid(), "comparison_value", cmp_m.group(1).strip(),
                      v_start, v_start + len(cmp_m.group(1)),
                      False, "比较值(标注)", [pred_id], conf=0.78)
            v["virtual"] = True
            parts.append(v)
    else:
        parts.append(_part(_mkid(), "predicate", "", cursor, cursor,
                           True, "空谓词（可注入位）", conf=0.55))

    pos = middle_end

    # 7. whitespace_structure between predicate and terminator (may be zero-length)
    ws_text = ""
    if pos < len(txt):
        ws_match = re.match(r"^\s+", txt[pos:])
        if ws_match:
            ws_text = ws_match.group(0)
    parts.append(_part(_mkid(), "whitespace_structure", ws_text,
                       pos, pos + len(ws_text), True, "空白结构",
                       conf=0.75 if ws_text else 0.5))
    pos += len(ws_text)

    # 8. comment_terminator OR stacked-query tail
    if pos < len(txt):
        term_text = txt[pos:].strip()
        parts.append(_part(_mkid(), "comment_terminator", term_text,
                           pos, len(txt), True, "注释/终止/堆叠尾部", conf=0.9))
    else:
        parts.append(_part(_mkid(), "comment_terminator", "", pos, pos,
                           True, "缺失注释终结（可能被 WAF 拦截前拦截）", conf=0.5))

    parts.sort(key=lambda p: p["position"]["start"])
    avg_conf = sum(p["confidence"] for p in parts) / max(len(parts), 1)
    status = "supported" if avg_conf >= 0.55 else "unsupported"

    # extra semantic tags surfaced via semantic_role for the LLM to reason on
    payload_upper = txt.upper()
    if _SQL_TIME_FN_RE.search(txt):
        _tag_parts(parts, "predicate", "attack_class=time")
    elif _SQL_ERROR_FN_RE.search(txt):
        _tag_parts(parts, "predicate", "attack_class=error")
    elif "UNION" in payload_upper:
        _tag_parts(parts, "predicate", "attack_class=union")
    elif _SQL_STACKED_RE.search(txt):
        _tag_parts(parts, "predicate", "attack_class=stacked")
    else:
        _tag_parts(parts, "predicate", "attack_class=boolean")

    return {
        "parts": parts,
        "status": status,
        "confidence": round(avg_conf, 3),
        "label": "SQL 注入部件解析",
        "unsupported_reason": None,
    }


def _tag_parts(parts: list[dict[str, Any]], target_type: str, tag: str) -> None:
    """Append a tag hint to a part's semantic_role (used to inform the LLM)."""
    for p in parts:
        if p.get("part_type") == target_type:
            role = p.get("semantic_role", "")
            if tag not in role:
                p["semantic_role"] = f"{role}｜{tag}" if role else tag
            break


# =============================================================================
# XSS parser
# =============================================================================

_XSS_TAG_RE = re.compile(
    r"<(script|img|svg|body|input|details|marquee|iframe|a|keygen|math|"
    r"video|audio|source|embed|object|form|isindex|base|link|meta|style|"
    r"div|span|p|h1|h2|h3|table|td|tr|select|textarea|button|label)",
    re.IGNORECASE
)
_XSS_EVENT_RE = re.compile(
    r"\b(onerror|onload|onfocus|ontoggle|onstart|onclick|onmouseover|"
    r"onmousedown|onmouseup|onmousemove|onmouseenter|onmouseleave|"
    r"ondblclick|oncontextmenu|onkeydown|onkeyup|onkeypress|"
    r"onsubmit|onchange|oninput|onpaste|oncopy|oncut|"
    r"onbeforeunload|onhashchange|onpageshow|onpagehide|"
    r"onanimationstart|onanimationend|ontransitionend|"
    r"onpointerover|onpointerenter|onpointerdown|onpointerup|"
    r"onseeking|onseeked|oncanplay|oncanplaythrough|ontimeupdate|"
    r"onended|onabort|onstalled|onsuspend|onwaiting|ondurationchange|"
    r"onloadstart|onloadedmetadata|onloadeddata|onprogress|onplay|onpause|"
    r"onvolumechange|onratechange|onauxclick|onwheel|onscroll|onresize|"
    r"onsearch|ontoggle|onshow|oninvalid|onreset|onselect|onselectstart|"
    r"onselectionchange|ondrag|ondragstart|ondragend|ondragover|ondragenter|"
    r"ondragleave|ondrop|onbeforecopy|onbeforecut|onbeforepaste|"
    r"onafterprint|onbeforeprint|onmessage|onmessageerror|ononline|onoffline|"
    r"onpopstate|onstorage|onunhandledrejection|onrejectionhandled)\b",
    re.IGNORECASE
)


def _try_parse_non_tag_xss(txt: str) -> dict[str, Any] | None:
    """Try to parse non-HTML-tag XSS patterns (template injection, JS context, etc.)."""
    parts: list[dict[str, Any]] = []

    # Pattern 1: Template injection - <%= ... %>, <% ... %>
    template_erb = re.match(r"(<%=?)\s*(.+?)\s*(%>)", txt, re.DOTALL)
    if template_erb:
        parts.append(_part("p1", "context_prefix", template_erb.group(1), 0, len(template_erb.group(1)),
                          True, "ERB/JSP 模板起始标记", conf=0.9))
        expr_start = len(template_erb.group(1))
        expr_end = expr_start + len(template_erb.group(2))
        parts.append(_part("p2", "javascript_expression", template_erb.group(2).strip(),
                          expr_start, expr_end, True, "模板注入表达式", conf=0.9))
        parts.append(_part("p3", "closing_structure", template_erb.group(3),
                          expr_end, len(txt), True, "模板结束标记", conf=0.9))
        return {"parts": parts, "status": "supported", "confidence": 0.9,
                "label": "XSS 部件解析（模板注入）", "unsupported_reason": None}

    # Pattern 2: Template engine - {{ ... }}
    template_double = re.match(r"({{)\s*(.+?)\s*(}})", txt, re.DOTALL)
    if template_double:
        parts.append(_part("p1", "context_prefix", template_double.group(1), 0, len(template_double.group(1)),
                          True, "模板引擎起始标记 {{", conf=0.9))
        expr_start = len(template_double.group(1))
        expr_end = expr_start + len(template_double.group(2))
        parts.append(_part("p2", "javascript_expression", template_double.group(2).strip(),
                          expr_start, expr_end, True, "模板表达式", conf=0.9))
        parts.append(_part("p3", "closing_structure", template_double.group(3),
                          expr_end, len(txt), True, "模板结束标记 }}", conf=0.9))
        return {"parts": parts, "status": "supported", "confidence": 0.9,
                "label": "XSS 部件解析（模板引擎）", "unsupported_reason": None}

    # Pattern 3: JavaScript template literal - ${ ... }
    template_literal = re.match(r"(\$\{)\s*(.+?)\s*(\})", txt, re.DOTALL)
    if template_literal:
        parts.append(_part("p1", "context_prefix", template_literal.group(1), 0, len(template_literal.group(1)),
                          True, "JS 模板字面量起始 ${", conf=0.9))
        expr_start = len(template_literal.group(1))
        expr_end = expr_start + len(template_literal.group(2))
        parts.append(_part("p2", "javascript_expression", template_literal.group(2).strip(),
                          expr_start, expr_end, True, "JS 表达式", conf=0.9))
        parts.append(_part("p3", "closing_structure", template_literal.group(3),
                          expr_end, len(txt), True, "模板字面量结束 }", conf=0.9))
        return {"parts": parts, "status": "supported", "confidence": 0.9,
                "label": "XSS 部件解析（JS 模板字面量）", "unsupported_reason": None}

    # Pattern 4: Attribute injection - starts with quote and event handler
    attr_injection = re.match(r"([\"'])\s*(on\w+)\s*=\s*(.+)", txt, re.IGNORECASE)
    if attr_injection:
        parts.append(_part("p1", "context_prefix", attr_injection.group(1), 0, len(attr_injection.group(1)),
                          True, "引号边界（属性注入）", conf=0.85))
        event_start = len(attr_injection.group(1))
        event_match = attr_injection.group(2)
        event_end = event_start + len(event_match) + txt[event_start + len(event_match):].find('=') + 1
        parts.append(_part("p2", "event_handler", txt[event_start:event_end],
                          event_start, event_end, True, f"事件处理器 {event_match}", conf=0.9))
        parts.append(_part("p3", "javascript_expression", attr_injection.group(3).strip(),
                          event_end, len(txt), True, "JS 执行表达式", conf=0.85))
        return {"parts": parts, "status": "supported", "confidence": 0.85,
                "label": "XSS 部件解析（属性注入）", "unsupported_reason": None}

    # Pattern 5: Pure JavaScript context - quoted string with function call
    js_context = re.match(r"(['\"])\s*-?\s*(\w+)\s*\(([^)]*)\)\s*-?\s*\1?", txt)
    if js_context and js_context.group(2) in ('alert', 'prompt', 'confirm', 'eval', 'Function', 'setTimeout'):
        parts.append(_part("p1", "context_prefix", js_context.group(1), 0, len(js_context.group(1)),
                          True, "字符串上下文边界", conf=0.8))
        func_start = len(js_context.group(1))
        func_name = js_context.group(2)
        func_args = js_context.group(3)
        func_end = txt.find(')', func_start) + 1
        parts.append(_part("p2", "javascript_expression", txt[func_start:func_end].strip(),
                          func_start, func_end, True, f"JS 函数调用 {func_name}()", conf=0.9))
        if func_end < len(txt):
            parts.append(_part("p3", "closing_structure", txt[func_end:],
                              func_end, len(txt), True, "字符串闭合", conf=0.7))
        return {"parts": parts, "status": "supported", "confidence": 0.8,
                "label": "XSS 部件解析（JS 上下文）", "unsupported_reason": None}

    return None


def _parse_xss(content: str) -> dict[str, Any]:
    txt = content.strip()
    parts: list[dict[str, Any]] = []
    pos = 0

    # Try to detect non-HTML-tag XSS patterns first
    non_tag_result = _try_parse_non_tag_xss(txt)
    if non_tag_result:
        return non_tag_result

    tag_m = _XSS_TAG_RE.search(txt)
    if not tag_m:
        parts.append(_part("p1","context_prefix","",0,0,False,"无显式上下文前缀",conf=0.4))
        parts.append(_part("p2","tag",txt,0,len(txt),True,"未识别标签",conf=0.4))
        return {"parts":parts,"status":"unsupported","confidence":0.4,
                "label":"XSS 部件解析","unsupported_reason":"无法可靠识别 XSS 标签结构"}

    # context_prefix
    prefix = txt[:tag_m.start()]
    parts.append(_part("p1","context_prefix",prefix,0,tag_m.start(),
                       False,"XSS 触发前上下文",conf=0.8 if prefix else 0.6))

    # tag
    tag_end = tag_m.end()
    # Find full tag open: <tagname ...  up to >
    full_tag = re.search(r"<\w+\b[^>]*", txt[tag_m.start():])
    if full_tag:
        tag_end = tag_m.start() + full_tag.end()

    parts.append(_part("p2","tag",txt[tag_m.start():tag_end],tag_m.start(),tag_end,
                       True,f"XSS 标签 <{tag_m.group(1)}>",conf=0.9))
    pos = tag_end

    # attribute_boundary
    am = re.match(r"(\s+)", txt[pos:])
    if am:
        parts.append(_part("p3","attribute_boundary",am.group(1),pos,pos+len(am.group(1)),
                           True,"标签属性间距",["p2"],conf=0.85))
        pos += len(am.group(1))

    # event_handler
    ev_m = _XSS_EVENT_RE.search(txt, pos)
    if ev_m:
        eq_m = re.search(r"=\s*", txt[ev_m.end():])
        ev_end = ev_m.end() + (eq_m.end() if eq_m else 0)
        parts.append(_part("p4","event_handler",txt[ev_m.start():ev_end],
                           ev_m.start(),ev_end,True,f"事件 {ev_m.group(1)}",conf=0.9))
        pos = ev_end

    # javascript_expression
    js_m = re.search(r"(?:alert|prompt|confirm|eval)\s*\([^)]*\)", txt[pos:])
    if js_m:
        parts.append(_part("p5","javascript_expression",js_m.group(0),
                           pos+js_m.start(),pos+js_m.end(),
                           True,"JS 执行表达式",conf=0.9))
        pos += js_m.end()

    # closing_structure
    close_m = re.search(r"(>|/>|</\w+>)", txt[pos:])
    if close_m:
        parts.append(_part("p6","closing_structure",close_m.group(0),
                           pos+close_m.start(),pos+close_m.end(),
                           True,"标签闭合结构",conf=0.85))

    parts.sort(key=lambda p: p["position"]["start"])
    avg_conf = sum(p["confidence"] for p in parts) / max(len(parts), 1)
    return {"parts":parts,"status":"supported" if avg_conf>=0.55 else "unsupported",
            "confidence":round(avg_conf,3),"label":"XSS 部件解析","unsupported_reason":None}
