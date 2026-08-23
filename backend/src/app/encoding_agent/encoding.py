from __future__ import annotations

import base64
import binascii
import gzip
import json as _json
import random
import re
import urllib.parse
from typing import Any, Callable

# ============================================================
# 1. 确定性种子 RNG（同一 payload 多次运行结果一致）
# ============================================================


def _stable_hash(s: str) -> int:
    """跨进程稳定的字符串哈希（替代 Python 内置 hash，避免 PYTHONHASHSEED 随机化）。"""
    h = 0
    for c in s:
        h = ((h * 31) + ord(c)) & 0xFFFFFFFF
    return h


def _rng(seed: int) -> random.Random:
    return random.Random(seed)


# ============================================================
# 2. 编码器 / 解码器（28 种，A-H 共 8 组）
# ============================================================


# ---- A 组：URL 编码类（4 种）----


def enc_url(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def dec_url(s: str) -> str:
    return urllib.parse.unquote(s)


def enc_url_fullwidth(s: str) -> str:
    return enc_url(s).replace("%", "％")


def dec_url_fullwidth(s: str) -> str:
    return urllib.parse.unquote(s.replace("％", "%"))


def enc_url_unicode(s: str) -> str:
    return "".join("%%u%04x" % ord(ch) for ch in s)


def dec_url_unicode(s: str) -> str:
    return re.sub(r"%u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)


def enc_jetty_url(s: str) -> str:
    return "".join("%%u%04X" % ord(ch) for ch in s)


def dec_jetty_url(s: str) -> str:
    return re.sub(r"%u([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), s)


# ---- B 组：实体 / 转义类（5 种）----


def enc_html_dec(s: str) -> str:
    return "".join("&#%d;" % ord(ch) for ch in s)


def dec_html_dec(s: str) -> str:
    return re.sub(
        r"&#(\d+);",
        lambda m: chr(int(m.group(1))) if int(m.group(1)) < 0x110000 else m.group(0),
        s,
    )


def enc_html_hex(s: str) -> str:
    return "".join("&#x%x;" % ord(ch) for ch in s)


def dec_html_hex(s: str) -> str:
    return re.sub(
        r"&#x([0-9a-fA-F]+);",
        lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 0x110000 else m.group(0),
        s,
    )


def enc_js_octal(s: str) -> str | None:
    out = []
    for ch in s:
        b = ord(ch)
        if b >= 0x110000:
            return None
        out.append("\\" + format(b, "o"))
    return "".join(out)


def dec_js_octal(s: str) -> str:
    return re.sub(
        r"\\([0-7]+)",
        lambda m: chr(int(m.group(1), 8)) if int(m.group(1), 8) < 0x110000 else m.group(0),
        s,
    )


def enc_js_hex(s: str) -> str | None:
    out = []
    for byte in s.encode("utf-8"):
        out.append("\\x%02x" % byte)
    return "".join(out)


def dec_js_hex(s: str) -> str:
    out = bytearray()
    i = 0
    pattern = re.compile(r"\\x([0-9a-fA-F]{2})")
    for m in pattern.finditer(s):
        out += s[i : m.start()].encode("utf-8")
        out.append(int(m.group(1), 16))
        i = m.end()
    out += s[i:].encode("utf-8")
    return out.decode("utf-8", errors="replace")


def enc_js_unicode(s: str) -> str:
    return "".join("\\u%04x" % ord(ch) for ch in s)


def dec_js_unicode(s: str) -> str:
    return re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)


# ---- C 组：进制编码类（2 种）----


def enc_hex(s: str) -> str:
    return s.encode("utf-8").hex()


def dec_hex(s: str) -> str:
    return bytes.fromhex(s).decode("utf-8")


def enc_binary(s: str) -> str:
    return " ".join(format(byte, "08b") for byte in s.encode("utf-8"))


def dec_binary(s: str) -> str:
    return bytes(int(b, 2) for b in s.split(" ")).decode("utf-8")


# ---- D 组：算法编码类（3 种）----


def enc_base64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def dec_base64(s: str) -> str:
    return base64.b64decode(s).decode("utf-8")


def enc_base64_datauri(s: str) -> str:
    return "data:text/html;base64," + base64.b64encode(s.encode("utf-8")).decode("ascii")


def dec_base64_datauri(s: str) -> str:
    prefix = "data:text/html;base64,"
    if not s.startswith(prefix):
        raise ValueError("base64_datauri 前缀不匹配")
    return base64.b64decode(s[len(prefix):]).decode("utf-8")


def enc_quoted_printable(s: str) -> str:
    encoded = binascii.b2a_qp(s.encode("utf-8"))
    if encoded.endswith(b"\r\n"):
        encoded = encoded[:-2]
    return encoded.decode("ascii")


def dec_quoted_printable(s: str) -> str:
    return binascii.a2b_qp(s.encode("ascii")).decode("utf-8")


# ---- E 组：字符集编码类（3 种）----


def enc_utf7(s: str) -> str | None:
    try:
        return s.encode("utf-7").decode("ascii")
    except Exception:
        return None


def dec_utf7(s: str) -> str:
    return s.encode("ascii").decode("utf-7")


def enc_cp037(s: str) -> str | None:
    try:
        return s.encode("cp037").hex()
    except Exception:
        return None


def dec_cp037(s: str) -> str:
    return bytes.fromhex(s).decode("cp037")


def enc_utf16be(s: str) -> str:
    return s.encode("utf-16-be").hex()


def dec_utf16be(s: str) -> str:
    return bytes.fromhex(s).decode("utf-16-be")


# ---- F 组：结构转义类（4 种）----


def enc_json(s: str) -> str:
    return _json.dumps(s, ensure_ascii=False)[1:-1]


def dec_json(s: str) -> str:
    return _json.loads('"' + s + '"')


def enc_xml(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def dec_xml(s: str) -> str:
    s = s.replace("&amp;", "\x00AMP\x00")
    s = s.replace("&apos;", "'")
    s = s.replace("&quot;", '"')
    s = s.replace("&gt;", ">")
    s = s.replace("&lt;", "<")
    s = s.replace("\x00AMP\x00", "&")
    return s


def enc_xml_entity(s: str) -> str:
    return "".join("&#x%X;" % ord(ch) for ch in s)


def dec_xml_entity(s: str) -> str:
    return re.sub(
        r"&#x([0-9A-Fa-f]+);",
        lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 0x110000 else m.group(0),
        s,
    )


def enc_graphql(s: str) -> str:
    out = []
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "/":
            out.append("\\/")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif c < 0x20:
            out.append("\\u%04x" % c)
        else:
            out.append(ch)
    return "".join(out)


def dec_graphql(s: str) -> str:
    return _json.loads('"' + s + '"')


# ---- G 组：隐形变形类（5 种，有损）----

_ZW_CHARS = ("​", "‌", "‍", "﻿")


def enc_ghostbits(s: str) -> str:
    rng = _rng(_stable_hash(s) ^ (_stable_hash("ghostbits") & 0xFFFFFFFF))
    out = []
    for ch in s:
        out.append(ch)
        if rng.random() < 0.4:
            out.append(rng.choice(_ZW_CHARS))
    return "".join(out)


def dec_ghostbits(s: str) -> str:
    for zw in _ZW_CHARS:
        s = s.replace(zw, "")
    return s


_SQL_PAT = re.compile(
    r"\b(?:SELECT|UNION|FROM|WHERE|AND|OR|INSERT|UPDATE|DELETE|DROP|EXEC|HAVING|GROUP|ORDER|INTO|VALUES|SET)\b",
    re.IGNORECASE,
)


def enc_comment_sql(s: str) -> str:
    def _repl(m: re.Match) -> str:
        kw = m.group(0)
        if len(kw) >= 3:
            mid = len(kw) // 2
            return kw[:mid] + "/**/" + kw[mid:]
        return kw

    return _SQL_PAT.sub(_repl, s)


def dec_comment_sql(s: str) -> str:
    return s.replace("/**/", "")


_HTML_TAG_PAT = re.compile(r"(</?[a-zA-Z][a-zA-Z0-9]*)")


def enc_comment_html(s: str) -> str:
    def _repl(m: re.Match) -> str:
        tag = m.group(1)
        if len(tag) >= 2:
            return tag[:1] + "<!-- -->" + tag[1:]
        return tag

    return _HTML_TAG_PAT.sub(_repl, s)


def dec_comment_html(s: str) -> str:
    return s.replace("<!-- -->", "")


_SPACE_VARS = ("%09", "%0a", "%0d", "/**/", "\t")


def enc_space_morph(s: str) -> str:
    rng = _rng(_stable_hash(s) ^ (_stable_hash("space_morph") & 0xFFFFFFFF))
    out = []
    for ch in s:
        if ch == " ":
            out.append(rng.choice(_SPACE_VARS))
        else:
            out.append(ch)
    return "".join(out)


def dec_space_morph(s: str) -> str:
    s = s.replace("\t", " ")
    s = s.replace("%09", " ")
    s = s.replace("%0a", " ")
    s = s.replace("%0d", " ")
    s = s.replace("/**/", " ")
    return s


def enc_case_morph(s: str) -> str:
    rng = _rng(_stable_hash(s) ^ (_stable_hash("case_morph") & 0xFFFFFFFF))
    out = []
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if rng.random() < 0.5 else ch.lower())
        else:
            out.append(ch)
    return "".join(out)


def dec_case_morph(s: str) -> str:
    return s.lower()


# ---- H 组：压缩 / 序列化类（2 种）----


def enc_gzip(s: str) -> str:
    return gzip.compress(s.encode("utf-8")).hex()


def dec_gzip(s: str) -> str:
    return gzip.decompress(bytes.fromhex(s)).decode("utf-8")


def enc_php_serialize(s: str) -> str | None:
    if '"' in s or "\\" in s or "\x00" in s:
        return None
    return 's:%d:"%s";' % (len(s.encode("utf-8")), s)


def dec_php_serialize(s: str) -> str:
    m = re.match(r'^s:(\d+):"(.*)";$', s)
    if not m:
        raise ValueError("php_serialize 格式不正确")
    length = int(m.group(1))
    content = m.group(2)
    if len(content.encode("utf-8")) != length:
        raise ValueError("php_serialize 长度不匹配")
    return content


# ============================================================
# 3. 编码注册表
# ============================================================

# 格式：(组号, encode_fn, decode_fn, is_lossy)
ENCODINGS: dict[str, tuple[str, Callable[[str], str | None], Callable[[str], str], bool]] = {
    # A 组
    "url": ("A", enc_url, dec_url, False),
    "url_fullwidth": ("A", enc_url_fullwidth, dec_url_fullwidth, False),
    "url_unicode": ("A", enc_url_unicode, dec_url_unicode, False),
    "jetty_url": ("A", enc_jetty_url, dec_jetty_url, False),
    # B 组
    "html_dec": ("B", enc_html_dec, dec_html_dec, False),
    "html_hex": ("B", enc_html_hex, dec_html_hex, False),
    "js_octal": ("B", enc_js_octal, dec_js_octal, False),
    "js_hex": ("B", enc_js_hex, dec_js_hex, False),
    "js_unicode": ("B", enc_js_unicode, dec_js_unicode, False),
    # C 组
    "hex": ("C", enc_hex, dec_hex, False),
    "binary": ("C", enc_binary, dec_binary, False),
    # D 组
    "base64": ("D", enc_base64, dec_base64, False),
    "base64_datauri": ("D", enc_base64_datauri, dec_base64_datauri, False),
    "quoted_printable": ("D", enc_quoted_printable, dec_quoted_printable, False),
    # E 组
    "utf7": ("E", enc_utf7, dec_utf7, False),
    "cp037": ("E", enc_cp037, dec_cp037, False),
    "utf16be": ("E", enc_utf16be, dec_utf16be, False),
    # F 组
    "json": ("F", enc_json, dec_json, False),
    "xml": ("F", enc_xml, dec_xml, False),
    "xml_entity": ("F", enc_xml_entity, dec_xml_entity, False),
    "graphql": ("F", enc_graphql, dec_graphql, False),
    # G 组（有损）
    "ghostbits": ("G", enc_ghostbits, dec_ghostbits, True),
    "comment_sql": ("G", enc_comment_sql, dec_comment_sql, True),
    "comment_html": ("G", enc_comment_html, dec_comment_html, True),
    "space_morph": ("G", enc_space_morph, dec_space_morph, True),
    "case_morph": ("G", enc_case_morph, dec_case_morph, True),
    # H 组
    "gzip": ("H", enc_gzip, dec_gzip, False),
    "php_serialize": ("H", enc_php_serialize, dec_php_serialize, False),
}

# 字符级编码（适用于部分编码）
CHAR_LEVEL_ENCODINGS = [
    "url", "url_fullwidth", "url_unicode", "jetty_url",
    "html_dec", "html_hex", "js_octal", "js_hex", "js_unicode",
    "hex", "binary",
    "xml_entity",
]

XML_LIKE_ENCODINGS = ["xml", "xml_entity"]

# 完整目录：编码名 → 可用的「确定性整句」模式。整句模式对所有编码可用。
# 部分编码（partial）是携带 `segs` 的独立步骤，不属于可枚举的裸链模式，
# 因此不在此目录中列出；其能力由 CHAR_LEVEL_ENCODINGS 界定。
ENCODING_CATALOG: dict[str, set[str]] = {name: {"full"} for name in ENCODINGS}

# 可做部分编码的字符级编码集合
PARTIAL_CAPABLE_ENCODINGS: set[str] = set(CHAR_LEVEL_ENCODINGS)

# 向后兼容：解释器级策略在新引擎中已移除（由部分编码与结构转义取代）。
INTERPRETER_ENCODING_CATALOG: dict[str, set[str]] = {}
ALL_ENCODING_CATALOG = {**ENCODING_CATALOG, **INTERPRETER_ENCODING_CATALOG}

ENCODING_LABELS = {
    "url": "URL 百分号编码",
    "url_fullwidth": "URL 全角百分号编码",
    "url_unicode": "URL Unicode 编码 (IIS)",
    "jetty_url": "Jetty URL Unicode 编码",
    "html_dec": "HTML 十进制实体",
    "html_hex": "HTML 十六进制实体",
    "js_octal": "JS 八进制转义",
    "js_hex": "JS 十六进制转义",
    "js_unicode": "JS Unicode 转义",
    "hex": "十六进制文本",
    "binary": "二进制文本",
    "base64": "Base64",
    "base64_datauri": "Base64 Data URI",
    "quoted_printable": "Quoted-Printable",
    "utf7": "UTF-7",
    "cp037": "CP-037 (EBCDIC)",
    "utf16be": "UTF-16BE",
    "json": "JSON 字符串转义",
    "xml": "XML 特殊字符转义",
    "xml_entity": "XML 十六进制实体",
    "graphql": "GraphQL 字符串转义",
    "ghostbits": "零宽字符植入",
    "comment_sql": "SQL 注释分割",
    "comment_html": "HTML 注释分割",
    "space_morph": "空白字符变形",
    "case_morph": "大小写变形",
    "gzip": "gzip 压缩",
    "php_serialize": "PHP serialize 封装",
}

MODE_LABELS = {
    "full": "整句",
    "partial": "部分",
}

# ============================================================
# 4. 场景过滤表
# ============================================================

SCENARIO_FILTER: dict[str, dict[str, bool]] = {
    "url": {"xss": True, "sql": True, "cmdi": True, "log4j": True, "upload": True},
    "url_fullwidth": {"xss": True, "sql": True, "cmdi": True, "log4j": True, "upload": True},
    "url_unicode": {"xss": True, "sql": True, "cmdi": True, "log4j": True, "upload": True},
    "jetty_url": {"xss": True, "sql": True, "cmdi": True, "log4j": True, "upload": True},
    "html_dec": {"xss": True, "sql": True, "cmdi": False, "log4j": False, "upload": False},
    "html_hex": {"xss": True, "sql": False, "cmdi": False, "log4j": False, "upload": False},
    "js_octal": {"xss": True, "sql": False, "cmdi": True, "log4j": False, "upload": False},
    "js_hex": {"xss": True, "sql": False, "cmdi": False, "log4j": False, "upload": False},
    "js_unicode": {"xss": True, "sql": False, "cmdi": False, "log4j": True, "upload": False},
    "hex": {"xss": True, "sql": True, "cmdi": True, "log4j": True, "upload": False},
    "binary": {"xss": True, "sql": True, "cmdi": True, "log4j": False, "upload": False},
    "base64": {"xss": True, "sql": False, "cmdi": True, "log4j": True, "upload": False},
    "base64_datauri": {"xss": True, "sql": False, "cmdi": False, "log4j": False, "upload": False},
    "quoted_printable": {"xss": True, "sql": False, "cmdi": False, "log4j": True, "upload": False},
    "utf7": {"xss": True, "sql": False, "cmdi": False, "log4j": False, "upload": False},
    "cp037": {"xss": False, "sql": False, "cmdi": False, "log4j": True, "upload": False},
    "utf16be": {"xss": True, "sql": False, "cmdi": False, "log4j": True, "upload": True},
    "json": {"xss": True, "sql": False, "cmdi": False, "log4j": True, "upload": False},
    "xml": {"xss": True, "sql": False, "cmdi": False, "log4j": True, "upload": True},
    "xml_entity": {"xss": True, "sql": False, "cmdi": False, "log4j": True, "upload": True},
    "graphql": {"xss": True, "sql": False, "cmdi": False, "log4j": True, "upload": False},
    "ghostbits": {"xss": True, "sql": True, "cmdi": True, "log4j": True, "upload": True},
    "comment_sql": {"xss": False, "sql": True, "cmdi": False, "log4j": False, "upload": False},
    "comment_html": {"xss": True, "sql": False, "cmdi": False, "log4j": False, "upload": False},
    "space_morph": {"xss": True, "sql": True, "cmdi": True, "log4j": True, "upload": True},
    "case_morph": {"xss": True, "sql": True, "cmdi": False, "log4j": False, "upload": False},
    "gzip": {"xss": True, "sql": True, "cmdi": True, "log4j": True, "upload": True},
    "php_serialize": {"xss": False, "sql": False, "cmdi": True, "log4j": False, "upload": True},
}

# 漏洞类型 → 场景键
VULNERABILITY_SCENARIO = {
    "command-injection": "cmdi",
    "sql-injection": "sql",
    "xss": "xss",
    "file-upload": "upload",
    "log4j": "log4j",
}


def _scenario_key(vulnerability: str | None) -> str | None:
    if not vulnerability:
        return None
    return VULNERABILITY_SCENARIO.get(vulnerability)


def scenario_ok(name: str, vulnerability: str | None) -> bool:
    scenario = _scenario_key(vulnerability)
    if scenario is None:
        return True
    return SCENARIO_FILTER.get(name, {}).get(scenario, False)


def scenario_ok_chain(names: list[str], vulnerability: str | None) -> bool:
    scenario = _scenario_key(vulnerability)
    if scenario is None:
        return True
    return all(SCENARIO_FILTER.get(n, {}).get(scenario, False) for n in names)


# ============================================================
# 5. 关键字 / Token / 特殊字符识别库
# ============================================================

SQL_KW = [
    "union", "select", "from", "where", "and", "or", "insert", "update", "delete",
    "drop", "exec", "execute", "having", "group", "order", "by", "into", "values",
    "set", "waitfor", "declare", "cast", "convert", "substring", "ascii", "char",
    "hex", "benchmark", "sleep", "database", "schema", "information_schema", "table",
    "column", "procedure", "version", "user", "password", "null", "like", "in",
    "exists", "between", "join", "inner", "outer", "left", "right", "limit", "offset",
    "distinct", "regexp", "rlike", "sounds", "concat", "group_concat", "count",
    "sum", "avg", "min", "max", "case", "when", "then", "else", "end", "if", "is",
    "not", "xor", "mod", "div", "all", "any", "some",
]

XSS_KW = [
    "script", "alert", "prompt", "confirm", "onerror", "onload", "onclick",
    "onmouseover", "onfocus", "onblur", "onsubmit", "onchange", "oninput",
    "onkeydown", "onkeyup", "onkeypress", "svg", "img", "iframe", "frame",
    "src", "href", "data", "javascript", "vbscript", "expression", "eval",
    "function", "var", "let", "const", "document", "window", "location",
    "cookie", "fetch", "xmlhttprequest", "createelement", "innerhtml",
    "outerhtml", "writeln", "base", "object", "embed", "applet", "meta",
    "style", "link", "form", "input", "textarea", "button", "select",
    "option", "body", "title", "head", "marquee", "video", "audio", "source",
    "track", "math", "animate", "setattribute", "getattribute",
]

CMDI_KW = [
    "cat", "ls", "pwd", "whoami", "id", "uname", "hostname", "ifconfig",
    "ipconfig", "base64", "curl", "wget", "nc", "netcat", "ncat", "bash",
    "sh", "zsh", "fish", "powershell", "cmd", "system", "eval", "exec",
    "spawn", "fork", "kill", "sleep", "wait", "mkdir", "rmdir", "touch",
    "rm", "mv", "cp", "chmod", "chown", "chgrp", "head", "tail", "more",
    "less", "sort", "uniq", "wc", "grep", "egrep", "fgrep", "sed", "awk",
    "cut", "tr", "tee", "xargs", "find", "locate", "which", "whereis",
    "echo", "printf", "read", "write", "open", "close", "chdir", "getcwd",
    "getenv", "setenv", "crontab", "top", "ps", "pidof", "pgrep", "pkill",
    "killall", "jobs", "bg", "fg", "env", "export",
]

LOG4J_KW = ["jndi", "ldap", "ldaps", "rmi", "dns", "iiop", "corba", "http", "https"]

UPLOAD_KW = [
    "filename", "filepath", "content", "type", "boundary", "multipart", "form",
    "data", "name", "file", "path", "tmp", "temp", "upload", "php", "jsp", "asp", "aspx",
]


def _keywords_for_scenario(vulnerability: str | None) -> list[str]:
    scenario = _scenario_key(vulnerability)
    if scenario is None:
        pool = set(SQL_KW) | set(XSS_KW) | set(CMDI_KW)
    elif scenario == "sql":
        pool = set(SQL_KW)
    elif scenario == "xss":
        pool = set(XSS_KW)
    elif scenario == "cmdi":
        pool = set(CMDI_KW)
    elif scenario == "log4j":
        pool = set(LOG4J_KW)
    elif scenario == "upload":
        pool = set(UPLOAD_KW)
    else:
        pool = set(SQL_KW) | set(XSS_KW) | set(CMDI_KW)
    return sorted(pool, key=lambda x: (-len(x), x))


SPECIAL_CHARS = set("'\"<>(){}[];,.\\/#=&?!@$%^~|`+-*: \t\n\r")
TOKEN_PAT = re.compile(r"[a-zA-Z0-9_$.]+")

# 部分编码子模式
PARTIAL_SUBMODES = ("特殊字符", "关键字", "首字符", "断点", "随机")


# ============================================================
# 6. 部分编码（5 种子模式）
#
# SegRecord = (input_pos, input_len, encoding, original_substr)
#   - input_pos：本段在「该步输入字符串」中的起始位置（字符下标）
#   - input_len：原文字段长度（通常 1，关键字段为关键字长度）
#   - encoding：编码名
#   - original_substr：被编码的原文字段
# 段按 input_pos 升序，互不重叠。
# ============================================================

SegRecord = tuple[int, int, str, str]


def _encode_substr(encoding_name: str, substr: str) -> str | None:
    enc_fn = ENCODINGS[encoding_name][1]
    try:
        out = enc_fn(substr)
    except Exception:
        return None
    if out is None or out == substr:
        return None
    return out


def dec_one_seg(encoding_name: str, encoded: str) -> str | None:
    dec_fn = ENCODINGS[encoding_name][2]
    try:
        return dec_fn(encoded)
    except Exception:
        return None


def _mk_partial_step(encoding: str, submode: str, segs: list[SegRecord]) -> dict[str, Any]:
    return {"type": encoding, "mode": "partial", "submode": submode, "segs": segs}


def _keyword_matches(payload: str, vulnerability: str | None) -> list[re.Match]:
    keywords = _keywords_for_scenario(vulnerability)
    if not keywords:
        return []
    pattern = re.compile("|".join(re.escape(k) for k in keywords), re.IGNORECASE)
    return list(pattern.finditer(payload))


# ---- 子模式 2.1：特殊字符编码 ----

def partial_special_chars(payload: str, encoding: str, vulnerability: str | None) -> list[tuple[dict, str]]:
    if not scenario_ok(encoding, vulnerability):
        return []
    is_xml = encoding == "xml"
    is_xml_entity = encoding == "xml_entity"
    if not is_xml and not is_xml_entity and encoding not in CHAR_LEVEL_ENCODINGS:
        return []

    out_parts: list[str] = []
    segs: list[SegRecord] = []
    for i, ch in enumerate(payload):
        if is_xml:
            need = ch in ("&", "<", ">", '"', "'")
        elif is_xml_entity:
            need = True
        else:
            need = (not ch.isalnum()) and (ch in SPECIAL_CHARS)

        if not need:
            out_parts.append(ch)
            continue

        e = _encode_substr(encoding, ch)
        if e is None:
            out_parts.append(ch)
            continue

        out_parts.append(e)
        segs.append((i, 1, encoding, ch))

    if not segs:
        return []
    return [(_mk_partial_step(encoding, "特殊字符", segs), "".join(out_parts))]


# ---- 子模式 2.2：关键字编码（每个关键字首个出现位置 1 条）----

def partial_keyword(payload: str, encoding: str, vulnerability: str | None) -> list[tuple[dict, str]]:
    if not scenario_ok(encoding, vulnerability):
        return []

    results: list[tuple[dict, str]] = []
    seen_kws: set[tuple[str, str]] = set()
    for m in _keyword_matches(payload, vulnerability):
        kw = m.group(0)
        key = (kw.lower(), encoding)
        if key in seen_kws:
            continue
        seen_kws.add(key)
        encoded_kw = _encode_substr(encoding, kw)
        if encoded_kw is None:
            continue
        var = payload[: m.start()] + encoded_kw + payload[m.end():]
        segs = [(m.start(), len(kw), encoding, kw)]
        results.append((_mk_partial_step(encoding, "关键字", segs), var))
    return results


# ---- 子模式 2.3：首字符编码 ----

def partial_first_char(payload: str, encoding: str, vulnerability: str | None) -> list[tuple[dict, str]]:
    if not scenario_ok(encoding, vulnerability):
        return []
    if encoding not in CHAR_LEVEL_ENCODINGS:
        return []

    out_parts: list[str] = []
    segs: list[SegRecord] = []
    last = 0
    for m in TOKEN_PAT.finditer(payload):
        out_parts.append(payload[last:m.start()])
        token = m.group(0)
        e = _encode_substr(encoding, token[0])
        if e is None:
            out_parts.append(token)
        else:
            out_parts.append(e)
            out_parts.append(token[1:])
            segs.append((m.start(), 1, encoding, token[0]))
        last = m.end()
    out_parts.append(payload[last:])
    if not segs:
        return []
    return [(_mk_partial_step(encoding, "首字符", segs), "".join(out_parts))]


# ---- 子模式 2.4：关键字内断点编码（每个关键字 × 内部位置 1 条）----

def partial_keyword_breakpoint(payload: str, encoding: str, vulnerability: str | None) -> list[tuple[dict, str]]:
    if not scenario_ok(encoding, vulnerability):
        return []
    if encoding not in CHAR_LEVEL_ENCODINGS:
        return []

    results: list[tuple[dict, str]] = []
    seen_combos: set[tuple[str, str, int]] = set()
    for m in _keyword_matches(payload, vulnerability):
        kw = m.group(0)
        kw_start = m.start()
        if len(kw) < 3:
            continue
        for i in range(1, len(kw) - 1):
            key = (kw.lower(), encoding, i)
            if key in seen_combos:
                continue
            seen_combos.add(key)
            target_char = kw[i]
            target_pos = kw_start + i
            e = _encode_substr(encoding, target_char)
            if e is None:
                continue
            var = payload[:target_pos] + e + payload[target_pos + 1:]
            segs = [(target_pos, 1, encoding, target_char)]
            results.append((_mk_partial_step(encoding, "断点", segs), var))
    return results


# ---- 子模式 2.5：随机比例编码（每个比例 1 条确定性变体）----

def partial_random_ratio(
    payload: str, encoding: str, vulnerability: str | None, ratio: float
) -> list[tuple[dict, str]]:
    if not scenario_ok(encoding, vulnerability):
        return []
    if encoding not in CHAR_LEVEL_ENCODINGS:
        return []
    if not payload:
        return []

    rng = _rng(_stable_hash(payload) ^ int(ratio * 1000) ^ (_stable_hash(encoding) & 0xFFFF))
    n = len(payload)

    target_positions: set[int] = set()
    for i in range(n):
        if rng.random() < ratio:
            target_positions.add(i)
    if not target_positions:
        target_positions.add(rng.randrange(n))

    out_parts: list[str] = []
    segs: list[SegRecord] = []
    encoded_count = 0
    for i, ch in enumerate(payload):
        if i in target_positions:
            e = _encode_substr(encoding, ch)
            if e is None:
                out_parts.append(ch)
                continue
            out_parts.append(e)
            segs.append((i, 1, encoding, ch))
            encoded_count += 1
        else:
            out_parts.append(ch)

    if encoded_count == 0:
        return []
    submode = "随机%.0f%%" % (ratio * 100)
    return [(_mk_partial_step(encoding, submode, segs), "".join(out_parts))]


# ============================================================
# 7. 编码链的确定性重放 / 逆向 / 校验
# ============================================================


def _full_encode(encoding_name: str, value: str) -> str:
    enc_fn = ENCODINGS[encoding_name][1]
    try:
        out = enc_fn(value)
    except Exception as error:
        raise ValueError(f"编码 {encoding_name} 失败：{error}") from error
    if out is None:
        raise ValueError(f"编码 {encoding_name} 无法处理当前 payload")
    return out


def _full_decode(encoding_name: str, value: str) -> str:
    dec_fn = ENCODINGS[encoding_name][2]
    try:
        return dec_fn(value)
    except Exception as error:
        raise ValueError(f"解码 {encoding_name} 失败：{error}") from error


def _apply_partial_segments(value: str, segs: list[SegRecord]) -> str:
    out_parts: list[str] = []
    last = 0
    for input_pos, input_len, encoding_name, original_substr in sorted(segs, key=lambda s: s[0]):
        if input_pos < last or input_pos + input_len > len(value):
            raise ValueError("部分编码段位置越界或重叠")
        encoded_substr = _encode_substr(encoding_name, original_substr)
        if encoded_substr is None:
            raise ValueError("部分编码段无法由原文重放")
        out_parts.append(value[last:input_pos])
        out_parts.append(encoded_substr)
        last = input_pos + input_len
    out_parts.append(value[last:])
    return "".join(out_parts)


def _reverse_partial_segments(value: str, segs: list[SegRecord]) -> str:
    rebuilt: list[str] = []
    last_end = 0
    offset = 0
    for input_pos, input_len, encoding_name, original_substr in sorted(segs, key=lambda s: s[0]):
        encoded_substr = _encode_substr(encoding_name, original_substr)
        if encoded_substr is None:
            raise ValueError("部分编码段无法由原文重放")
        out_pos = input_pos + offset
        if out_pos < 0 or out_pos + len(encoded_substr) > len(value):
            raise ValueError("部分编码段位置越界")
        if value[out_pos:out_pos + len(encoded_substr)] != encoded_substr:
            raise ValueError("部分编码段与内容不一致")
        decoded = dec_one_seg(encoding_name, encoded_substr)
        if decoded is None or decoded != original_substr:
            raise ValueError("部分编码段解码后未恢复原文")
        rebuilt.append(value[last_end:out_pos])
        rebuilt.append(original_substr)
        last_end = out_pos + len(encoded_substr)
        offset += len(encoded_substr) - input_len
    rebuilt.append(value[last_end:])
    return "".join(rebuilt)


def apply_encoding_step(value: str, step: dict[str, Any]) -> str:
    encoding_type = step.get("type")
    mode = step.get("mode")
    if encoding_type not in ENCODINGS:
        raise ValueError(f"未知编码类型：{encoding_type}")
    if mode == "full":
        return _full_encode(encoding_type, value)
    if mode == "partial":
        segs = step.get("segs")
        if not isinstance(segs, list) or not segs:
            raise ValueError("部分编码步骤必须携带 segs")
        return _apply_partial_segments(value, segs)
    raise ValueError(f"编码 {encoding_type} 不支持模式：{mode}")


def decode_encoding_step(value: str, step: dict[str, Any]) -> str:
    encoding_type = step.get("type")
    mode = step.get("mode")
    if encoding_type not in ENCODINGS:
        raise ValueError(f"未知编码类型：{encoding_type}")
    if mode == "full":
        return _full_decode(encoding_type, value)
    if mode == "partial":
        segs = step.get("segs")
        if not isinstance(segs, list) or not segs:
            raise ValueError("部分编码步骤必须携带 segs")
        return _reverse_partial_segments(value, segs)
    raise ValueError(f"编码 {encoding_type} 不支持模式：{mode}")


def normalize_encoding_chain(chain: Any) -> list[dict[str, Any]]:
    if not isinstance(chain, list) or not 1 <= len(chain) <= 3:
        raise ValueError("encoding_chain 必须包含 1 到 3 层")
    normalized: list[dict[str, Any]] = []
    for step in chain:
        if not isinstance(step, dict):
            raise ValueError("编码步骤必须是对象")
        encoding_type = step.get("type")
        mode = step.get("mode")
        if not isinstance(encoding_type, str) or not isinstance(mode, str):
            raise ValueError("编码步骤字段必须是字符串")
        if encoding_type not in ENCODINGS:
            raise ValueError(f"不支持的编码步骤：{encoding_type}/{mode}")
        if mode == "full":
            pass
        elif mode == "partial":
            if encoding_type not in PARTIAL_CAPABLE_ENCODINGS:
                raise ValueError(f"编码 {encoding_type} 不支持部分编码")
        else:
            raise ValueError(f"编码 {encoding_type} 不支持模式：{mode}")
        normalized_step: dict[str, Any] = {"type": encoding_type, "mode": mode}
        if mode == "partial":
            submode = step.get("submode")
            if not isinstance(submode, str):
                raise ValueError("部分编码步骤必须携带 submode")
            normalized_step["submode"] = submode
            segs = step.get("segs")
            if isinstance(segs, list):
                normalized_step["segs"] = segs
        normalized.append(normalized_step)
    return normalized


def replay_encoding_chain(base_payload: str, chain: list[dict[str, Any]]) -> str:
    value = base_payload
    for step in chain:
        value = apply_encoding_step(value, step)
    return value


def reverse_encoding_chain(encoded_payload: str, chain: list[dict[str, Any]]) -> str:
    value = encoded_payload
    for step in reversed(chain):
        value = decode_encoding_step(value, step)
    return value


def expected_decode_path(chain: list[dict[str, Any]]) -> list[str]:
    return [step["type"] for step in reversed(chain)]


def encoding_chain_labels(chain: list[dict[str, Any]]) -> list[str]:
    labels: list[str] = []
    for step in chain:
        name = step["type"]
        label = ENCODING_LABELS.get(name, name)
        if step.get("mode") == "partial":
            submode = step.get("submode", "部分")
            labels.append(f"{label} · 部分[{submode}]")
        else:
            labels.append(f"{label} · 整句")
    return labels


def _lossy_normalize(s: str, has_case_morph: bool = False) -> str:
    for zw in _ZW_CHARS:
        s = s.replace(zw, "")
    s = s.replace("/**/", "")
    s = s.replace("<!-- -->", "")
    s = s.replace("%09", " ")
    s = s.replace("%0a", " ")
    s = s.replace("%0d", " ")
    s = s.replace("\t", " ")
    s = s.replace("\n", " ")
    s = s.replace("\r", " ")
    s = re.sub(r" {2,}", " ", s).strip()
    if has_case_morph:
        s = s.lower()
    return s


def _chain_has_lossy(chain: list[dict[str, Any]]) -> tuple[bool, bool]:
    has_lossy = False
    has_case = False
    for step in chain:
        encoding_type = step.get("type")
        if encoding_type not in ENCODINGS:
            continue
        if ENCODINGS[encoding_type][3]:
            has_lossy = True
            if encoding_type == "case_morph":
                has_case = True
    return has_lossy, has_case


def _verify_reversible(base_payload: str, content: str, chain: list[dict[str, Any]]) -> None:
    try:
        reversed_value = reverse_encoding_chain(content, chain)
    except (ValueError, UnicodeError) as error:
        raise ValueError(f"候选内容逆向解码失败：{error}") from error
    has_lossy, has_case = _chain_has_lossy(chain)
    if has_lossy:
        if _lossy_normalize(reversed_value, has_case) != _lossy_normalize(base_payload, has_case):
            raise ValueError("候选内容逆向解码（归一化）后未恢复基础 Payload")
    else:
        if reversed_value != base_payload:
            raise ValueError("候选内容逆向解码后未恢复基础 Payload")


def allowed_encoding_catalog(vulnerability: str | None, base_payload: str = "") -> dict[str, list[str]]:
    del base_payload  # 保留签名兼容；新引擎不依赖 payload 结构判定
    allowed: dict[str, list[str]] = {}
    for encoding_type, modes in ENCODING_CATALOG.items():
        if not scenario_ok(encoding_type, vulnerability):
            continue
        allowed[encoding_type] = sorted(modes)
    return allowed


def validate_encoding_candidates(
    candidates: Any,
    base_payload: str,
    candidate_count: int,
    vulnerability: str | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(candidates, list) or len(candidates) != candidate_count:
        raise ValueError(f"模型输出必须包含恰好 {candidate_count} 条编码候选")

    validated: list[dict[str, Any]] = []
    seen_contents: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise ValueError("编码候选必须是对象")
        content = candidate.get("content")
        explanation = candidate.get("explanation")
        confidence = candidate.get("confidence")
        chain = normalize_encoding_chain(candidate.get("encoding_chain"))
        decode_path = candidate.get("decode_path")

        # 场景过滤：链中所有编码都必须适用于当前漏洞场景
        if not scenario_ok_chain([step["type"] for step in chain], vulnerability):
            raise ValueError("编码链包含不适用于当前场景的编码")

        if not isinstance(content, str) or not content or len(content) > 5000:
            raise ValueError("编码候选 content 不合规")
        if content in seen_contents:
            raise ValueError("编码候选内容不能重复")
        if not isinstance(explanation, str) or not explanation.strip() or len(explanation) > 1000:
            raise ValueError("编码候选 explanation 不合规")
        if not isinstance(confidence, (int, float)) or not 0 <= float(confidence) <= 1:
            raise ValueError("编码候选 confidence 不合规")
        expected_path = expected_decode_path(chain)
        if decode_path != expected_path:
            raise ValueError("decode_path 与编码链逆序不一致")

        # 确定性重放：由声明的链重放必须得到候选内容
        try:
            replayed = replay_encoding_chain(base_payload, chain)
        except (ValueError, UnicodeError) as error:
            raise ValueError(f"候选内容无法由声明的编码链重放：{error}") from error
        if replayed != content:
            raise ValueError("候选内容无法由声明的编码链重放")

        # 可逆性：逆向解码后恢复基础 Payload（有损链走归一化）
        _verify_reversible(base_payload, content, chain)

        seen_contents.add(content)
        validated.append(
            {
                "content": content,
                "encoding_chain": chain,
                "decode_path": expected_path,
                "rule_labels": encoding_chain_labels(chain),
                "explanation": explanation.strip(),
                "confidence": float(confidence),
            }
        )
    return validated


# ============================================================
# 8. 编码意图 → 确定性候选生成（LLM 只给意图，后端算 content/segs）
# ============================================================

# partial 子模式名 → 生成函数
_PARTIAL_GENERATORS = {
    "特殊字符": partial_special_chars,
    "关键字": partial_keyword,
    "首字符": partial_first_char,
    "断点": partial_keyword_breakpoint,
    "随机": partial_random_ratio,
}


def _realize_partial_step(
    payload: str,
    encoding: str,
    submode: str,
    vulnerability: str | None,
) -> tuple[dict[str, Any], str] | None:
    """根据 partial 子模式生成一步（含 segs）与编码后内容。"""
    if submode == "随机":
        results = partial_random_ratio(payload, encoding, vulnerability, 0.3)
    elif submode in _PARTIAL_GENERATORS:
        results = _PARTIAL_GENERATORS[submode](payload, encoding, vulnerability)
    else:
        return None
    if not results:
        return None
    return results[0]


def realize_encoding_intent(
    base_payload: str,
    intent: dict[str, Any],
    vulnerability: str | None,
) -> list[dict[str, Any]]:
    """把 LLM 的编码意图转化为确定性候选。

    intent 字段：
      - intent: "full" | "partial" | "nested"
      - encoding_type: 单层编码类型（full/partial 时）
      - submode: partial 子模式（partial 时；nested 时 chain 中每个 partial 步可带）
      - chain: 嵌套链（nested 时），每个元素 {type, mode, submode?}
      - explanation / confidence

    返回 [{content, encoding_chain, decode_path, rule_labels, explanation, confidence}]。
    """
    kind = intent.get("intent")
    explanation = str(intent.get("explanation") or "").strip()
    try:
        confidence = float(intent.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5

    def _candidate(content: str, chain: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "content": content,
            "encoding_chain": chain,
            "decode_path": expected_decode_path(chain),
            "rule_labels": encoding_chain_labels(chain),
            "explanation": explanation,
            "confidence": confidence,
        }

    if kind == "full":
        encoding = intent.get("encoding_type")
        if not isinstance(encoding, str) or encoding not in ENCODINGS:
            return []
        try:
            content = _full_encode(encoding, base_payload)
        except (ValueError, UnicodeError):
            return []
        chain = [{"type": encoding, "mode": "full"}]
        if content == base_payload:
            return []
        return [_candidate(content, chain)]

    if kind == "partial":
        encoding = intent.get("encoding_type")
        submode = intent.get("submode")
        if not isinstance(encoding, str) or encoding not in CHAR_LEVEL_ENCODINGS:
            return []
        realized = _realize_partial_step(base_payload, encoding, str(submode or ""), vulnerability)
        if realized is None:
            return []
        step, content = realized
        if content == base_payload:
            return []
        return [_candidate(content, [step])]

    if kind == "nested":
        chain = intent.get("chain")
        if not isinstance(chain, list) or not chain:
            return []
        # 逐层构造完整 step（partial 层由后端生成 segs）
        realized_chain: list[dict[str, Any]] = []
        value = base_payload
        for layer in chain:
            if not isinstance(layer, dict):
                return []
            ltype = layer.get("type")
            lmode = layer.get("mode")
            if not isinstance(ltype, str) or ltype not in ENCODINGS:
                return []
            if lmode == "full":
                step = {"type": ltype, "mode": "full"}
                try:
                    value = _full_encode(ltype, value)
                except (ValueError, UnicodeError):
                    return []
            elif lmode == "partial":
                lsub = layer.get("submode")
                realized = _realize_partial_step(value, ltype, str(lsub or ""), vulnerability)
                if realized is None:
                    return []
                step, value = realized
            else:
                return []
            realized_chain.append(step)
        if value == base_payload:
            return []
        return [_candidate(value, realized_chain)]

    return []
