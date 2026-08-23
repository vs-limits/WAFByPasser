"""导入红队原语到 payload 库。

一次性脚本：扫描 `C:\\Users\\limit\\Desktop\\原语\\*.txt`，解析出可执行原语，
替换占位符 → 标记危害性(severity) → 按漏洞类型分类 → 去重 → 直接写入 SQLite。

用法（在仓库根目录运行）：
    python backend/scripts/import_primitives.py [--dry-run]

依赖：仅 Python 标准库。
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# 原语文件夹（用户桌面）
PRIMITIVES_DIR = Path(r"C:\Users\limit\Desktop\原语")

# 仓库根目录（脚本在 backend/scripts/ 下，向上两级）
REPO_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = REPO_ROOT / "data" / "waf_bypasser.db"

# 占位符替换
PLACEHOLDER_HOSTS = ("ATTACKER", "attacker.com", "10.0.0.1", "10.0.0.100", "10.0.0.2")
OOB_HOST = "8.129.25.140"
OOB_PORT = "12345"

# 漏洞类型识别：文件名关键字 -> vulnerability
VULN_KEYWORDS = [
    (("cmdi",), "command-injection"),
    (("fileupload", "upload"), "file-upload"),
    (("log4j",), "log4j"),
    (("sqli",), "sql-injection"),
    (("xss",), "xss"),
]

# 默认投递方式
DEFAULT_DELIVERY = {
    "command-injection": "表单字段",
    "sql-injection": "URL 查询参数",
    "xss": "表单字段",
    "file-upload": "multipart/form-data 文件字段",
    "log4j": "请求头/参数",
}

# 危害性映射：章节标题关键字 -> severity
SEVERITY_RULES = [
    # (severity, 关键字元组)
    ("低危", ("侦察", "探测", "验证锚点", "版本", "发现", "基础信息", "指纹", "探针")),
    ("严重", ("RCE", "命令执行", "WebShell", "webshell", "反序列化", "反弹", "C2", "横向移动",
              "持久化", "后门", "写文件", "落盘", "破坏", "影响", "外带", "OOB", "DNS 外带",
              "提权", "权限提升", "执行", "利用", "Webshell", "上传", "远程加载", "回连")),
    ("高危", ("窃取", "凭证", "文件读取", "信息收集", "越权", "CSRF", "认证绕过", "绕过",
              "钓鱼", "社工", "页面篡改", "键盘记录", "会话劫持", "Cookie 窃取", "拖库")),
]

# 攻击特征：用于判断一行是否为 payload（避免把说明文字当 payload）
ATTACK_SIGNATURES = re.compile(
    r""
    r"^[;|&`$()\s]+[a-zA-Z]"   # 命令注入：行首至少一个分隔符/替换符，后接命令字母
    r"|(?:^|\s)(whoami|id|uname|cat|ls|pwd|env|ifconfig|ip |netstat|ps |echo|printf"
    r"|curl|wget|nc |ncat|socat|bash|sh |python|perl|ruby|php|powershell|cmd |who|w |last"
    r"|ssh|scp|ping |nslookup|nmap|tar|zip|gzip|dd|cp |rsync|find|grep|more|less|head|tail"
    r"|strings|tac|nl|od|sort|sudo|which|getcap|iptables|systemctl|service|ufw|setenforce"
    r"|rm |shutdown|reboot|modprobe|mkfifo|openssl|mount|df |free|top|ss |lsof|arp|route|crontab"
    r"|hostname|uptime|date|type|net |systeminfo|ipconfig)\b"
    r"|\$\{jndi:|\$\{env:|\$\{sys:"
    r"|<\?php|<%|<\?=|<\? |<jsp:|<svg|<script|<img|<iframe|<body|<input|<details|<select"
    r"|<textarea|<marquee|<a |<object|<video|<audio|javascript:"
    r"|\bSELECT\b|\bUNION\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bEXEC\b|\bSLEEP\b"
    r"|\bBENCHMARK\b|\bload_file\b|\bINTO OUTFILE\b|\bxp_cmdshell\b|\bATTACH\b|\bCOPY\b"
    r"|=>\s*<|=>\s*\$|=>\s*%",
    re.IGNORECASE,
)

# 应跳过的行（标题/分隔/纯说明）
SKIP_PATTERNS = re.compile(
    r"^={3,}|^-{3,}|^#{1,6}\s|^说明|^依据|^铁律|^格式|^变量|^占位|^闭合|^后端|^注入点|^链路"
    r"|^附|^版本注意|^分隔符|^载荷格式|^变量占位|^载体|^--------------------------------------------------------------------",
    re.IGNORECASE,
)

# 章节标题行（用于 severity 上下文；本身不是 payload，需跳过）
CHAPTER_TITLE_RE = re.compile(
    r"^(一、|二、|三、|四、|五、|六、|七、|八、|九、|十、|目的|##\s*目的|\d+\))"
)


def payload_internal_name(content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
    return f"Payload · {digest}"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def detect_vulnerability(filename: str) -> str | None:
    lower = filename.lower()
    for keywords, vuln in VULN_KEYWORDS:
        if any(k in lower for k in keywords):
            return vuln
    return None


def replace_placeholders(content: str) -> str:
    """替换占位符：ATTACKER/attacker.com/内网IP -> OOB host，PORT -> OOB port。"""
    out = content
    for host in PLACEHOLDER_HOSTS:
        # 大小写不敏感替换，但保留 PORT 单独处理
        out = re.sub(re.escape(host), OOB_HOST, out, flags=re.IGNORECASE)
    out = re.sub(r"\bPORT\b", OOB_PORT, out)
    # 处理 `ATTACKER:PORT` 形式已被上面两步覆盖（先 host 后 port）
    return out


def default_filename_for(content: str) -> str:
    """根据裸 file-upload 内容推断默认文件名。"""
    lower = content.lower()
    if "<%@" in content or "aspx" in lower or "page language" in lower:
        return "shell.aspx"
    if "<%eval" in lower or "request(" in lower:
        return "shell.asp"
    if "<jsp:" in lower or ".jsp" in lower or "runtime.getruntime" in lower:
        return "shell.jsp"
    if "<cfexecute" in lower or "coldfusion" in lower:
        return "shell.cfm"
    if "<svg" in lower:
        return "x.svg"
    if ".htaccess" in lower or "addtype" in lower or "setHandler" in lower:
        return ".htaccess"
    if "user.ini" in lower:
        return ".user.ini"
    if "web.config" in lower or "<configuration>" in lower:
        return "web.config"
    if "twig" in lower or "{{" in lower:
        return "index.twig"
    if "smarty" in lower or "{php}" in lower:
        return "index.tpl"
    if "<?xml" in lower or "<!doctype" in lower or "<!entity" in lower:
        return "xxe.xml"
    if "<script>" in lower or "document.cookie" in lower or "fetch(" in lower:
        return "x.js"
    if "<?php" in lower or "<?=" in lower:
        return "shell.php"
    return "shell.txt"


def severity_for_context(chapter_title: str, content: str) -> str:
    """根据章节标题 + 内容关键字判定危害性。"""
    text = f"{chapter_title} {content}".lower()
    # 严重优先（破坏/RCE 类）
    for severity, keywords in SEVERITY_RULES:
        if severity in ("严重",):
            for kw in keywords:
                if kw.lower() in text:
                    return "严重"
    for severity, keywords in SEVERITY_RULES:
        if severity == "高危":
            for kw in keywords:
                if kw.lower() in text:
                    return "高危"
    for severity, keywords in SEVERITY_RULES:
        if severity == "低危":
            for kw in keywords:
                if kw.lower() in text:
                    return "低危"
    return "中危"  # 兜底


def parse_file(path: Path) -> list[tuple[str, str, str]]:
    """解析一个文件，返回 [(vulnerability, severity, content)]。"""
    vulnerability = detect_vulnerability(path.name)
    if not vulnerability:
        return []
    results: list[tuple[str, str, str]] = []
    chapter_title = ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        # 章节标题：记录为上下文（用于 severity），本身不是 payload，跳过。
        if CHAPTER_TITLE_RE.match(stripped):
            chapter_title = stripped
            continue
        if SKIP_PATTERNS.match(stripped):
            continue

        # file-upload 的 文件名 => 内容 键值对
        m = re.match(r"^(.+?)\s*=>\s*(.+)$", stripped)
        if m and vulnerability == "file-upload":
            fname = m.group(1).strip()
            fcontent = m.group(2).strip()
            if ATTACK_SIGNATURES.search(fcontent) or fcontent:
                content = f"filename: {fname}\ncontent: {fcontent}"
                content = replace_placeholders(content)
                severity = severity_for_context(chapter_title, fcontent)
                results.append((vulnerability, severity, content))
                continue

        # 普通 payload 行：需命中攻击特征
        if ATTACK_SIGNATURES.search(stripped):
            content = replace_placeholders(stripped)
            # 跳过替换后仍是纯占位/说明的行
            if not content or content.startswith(("#", "//", "说明", "示例", "占位")):
                continue
            # file-upload 裸内容：自动配默认文件名，统一结构化。
            if vulnerability == "file-upload" and "filename:" not in content:
                content = f"filename: {default_filename_for(content)}\ncontent: {content}"
            severity = severity_for_context(chapter_title, content)
            results.append((vulnerability, severity, content))

    return results


def import_primitives(dry_run: bool = False) -> None:
    if not PRIMITIVES_DIR.exists():
        print(f"错误：原语文件夹不存在 {PRIMITIVES_DIR}")
        sys.exit(1)

    files = sorted(PRIMITIVES_DIR.glob("*.txt"))
    if not files:
        print("错误：未找到任何 .txt 文件")
        sys.exit(1)

    all_entries: list[tuple[str, str, str]] = []
    for path in files:
        entries = parse_file(path)
        print(f"  解析 {path.name}: {len(entries)} 条")
        all_entries.extend(entries)

    # 去重（占位符替换后按 content 精确去重）
    seen: set[str] = set()
    deduped: list[tuple[str, str, str]] = []
    for vuln, severity, content in all_entries:
        if content in seen:
            continue
        seen.add(content)
        deduped.append((vuln, severity, content))

    print(f"\n  去重后: {len(deduped)} 条（原始 {len(all_entries)} 条）")

    if dry_run:
        # 打印统计，不写库
        from collections import Counter
        stat = Counter((v, s) for v, s, _ in deduped)
        print("\n  分类统计（vulnerability, severity）:")
        for (v, s), c in sorted(stat.items()):
            print(f"    {v:20} {s:4} {c}")
        return

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        # 库中已有 content（精确去重）
        existing = {r[0] for r in con.execute(
            "SELECT content FROM payloads WHERE is_deleted=0 AND is_pool_snapshot=0"
        )}
        inserted = 0
        for vuln, severity, content in deduped:
            if content in existing:
                continue
            con.execute(
                """
                INSERT INTO payloads (
                    id, name, vulnerability, category, delivery, target, difficulty,
                    content, created_at, is_pool_snapshot, severity, is_executable,
                    usage_method, success_indicators, labels_json, is_deleted
                ) VALUES (?, ?, ?, '', ?, '', '', ?, ?, 0, ?, 1, '', '', '[\"未绕过\",\"未验证\"]', 0)
                """,
                (
                    str(uuid.uuid4()),
                    payload_internal_name(content),
                    vuln,
                    DEFAULT_DELIVERY.get(vuln, "表单字段"),
                    content,
                    utc_now(),
                    severity,
                ),
            )
            inserted += 1
        con.commit()
        print(f"\n  新插入: {inserted} 条")
    finally:
        con.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="导入红队原语到 payload 库")
    parser.add_argument("--dry-run", action="store_true", help="只解析不写库")
    args = parser.parse_args()
    import_primitives(dry_run=args.dry_run)
