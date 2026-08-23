"""清理 payload 库：删除无红队价值的探测原语 + 带绕过手段的变体 + 误提取说明文字。

用法（dry-run 只打印清单，不删除）：
    python backend/scripts/clean_payloads.py --dry-run
    python backend/scripts/clean_payloads.py            # 实际删除
"""

from __future__ import annotations

import argparse
import re
import sqlite3
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = REPO_ROOT / "data" / "waf_bypasser.db"

# 纯验证命令（去掉分隔符前缀后判断）——这些无红队价值，仅用于验证注入点存在。
# 注意：ps/top/df/netstat/ss/lsof/arp/route/ifconfig/ip/who/w/last 等「环境信息收集」
# 命令有横向移动前侦察价值，保留。
CMDI_PROBE_EXACT = {"id", "whoami", "hostname", "pwd", "uptime", "date", "env", "printenv"}
CMDI_PROBE_PREFIXES = ("echo $", "uname")

SQL_FINGERPRINT_RE = re.compile(
    r"@@version|version\(\)|user\(\)|database\(\)|current_user|system_user|db_name\(\)|user_name\(\)|current_database",
    re.IGNORECASE,
)

XSS_PROBE_RE = re.compile(r"alert\(1\)|prompt\(1\)|confirm\(1\)|alert\(document\.domain\)|document\.write\('xss'\)")

LOG4J_PROBE_RE = re.compile(r"\$\{jndi:(ldap|rmi|ldaps|dns)://[^/]+/(a|probe)\}")


def should_delete(vuln: str, content: str) -> tuple[bool, str]:
    c = content.strip()
    # 1. 误提取的说明文字（log4j 注入点位置说明）
    if c.startswith(("Header", "Query", "JSON", "Form", "X-Real-IP", "X-Forwarded", "X-Client-IP", "X-Originating-IP", "X-Forwarded-Host", "CF-Connecting-IP")):
        return True, "说明文字"
    # 2. 命令替换绕过（cmdi 的 `...` / $(...)；file-upload 的反引号 webshell）
    if vuln == "command-injection" and ("`" in c or "$(" in c):
        return True, "命令替换绕过"
    if vuln == "file-upload" and "`" in c:
        return True, "命令替换绕过"
    # 3. 引号闭合绕过（cmdi/xss 的 ' " ] 前缀）
    if vuln in ("command-injection", "xss") and c.startswith(("'", '"', "]")):
        return True, "引号闭合绕过"
    # 4. 无红队价值的纯探测
    if vuln == "command-injection":
        cmd = c.lstrip(";|& \t\n")
        if cmd in CMDI_PROBE_EXACT or any(cmd.startswith(p) for p in CMDI_PROBE_PREFIXES):
            # 但排除含攻击价值的关键命令（cat/ls 等文件读取不算纯探测）
            if not re.search(r"\b(cat|ls|find|grep|tail|head|more|less|strings|tac|nl|od|sort|dd|cp|tar|zip|gzip|rsync|ssh|scp|curl|wget|nc|ncat|socat|bash|sh|python|perl|ruby|php|powershell|cmd|nmap)\b", cmd):
                return True, "无价值探测"
    if vuln == "sql-injection":
        # 纯指纹探测：version/user/database 且不含拖库（group_concat/FROM 表）
        if SQL_FINGERPRINT_RE.search(c) and "group_concat" not in c and "FROM information_schema" not in c and "FROM users" not in c:
            return True, "指纹探测"
    if vuln == "xss":
        if XSS_PROBE_RE.search(c):
            return True, "验证锚点"
    if vuln == "log4j":
        if LOG4J_PROBE_RE.search(c):
            return True, "存活探针"
    return False, ""


def main(dry_run: bool) -> None:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        to_delete: list[tuple[str, str, str]] = []  # (id, vuln, reason)
        for vuln in ("command-injection", "sql-injection", "xss", "log4j", "file-upload"):
            for r in con.execute(
                "SELECT id, content FROM payloads WHERE is_deleted=0 AND is_pool_snapshot=0 AND vulnerability=?",
                (vuln,),
            ):
                d, reason = should_delete(vuln, r["content"])
                if d:
                    to_delete.append((r["id"], vuln, reason))

        stat = Counter((v, reason) for _, v, reason in to_delete)
        print(f"待删除共 {len(to_delete)} 条：")
        for (vuln, reason), cnt in sorted(stat.items()):
            print(f"  {vuln:20} {reason:10} {cnt}")

        if dry_run:
            print("\n[dry-run] 未实际删除")
            return

        for pid, _, _ in to_delete:
            con.execute("UPDATE payloads SET is_deleted = 1 WHERE id = ?", (pid,))
        con.commit()
        print(f"\n已软删除 {len(to_delete)} 条（is_deleted=1）")
    finally:
        con.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    main(args.dry_run)
