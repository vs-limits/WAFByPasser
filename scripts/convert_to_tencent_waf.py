#!/usr/bin/env python3
"""将所有DVWA类型的payload转换为腾讯云WAF测试用payload"""

import sqlite3
from pathlib import Path

def convert_to_tencent_waf(db_path: str, dry_run: bool = False):
    """将command-injection, sql-injection, xss类型的payload转换为tencent-waf类型"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 要转换的漏洞类型
    source_types = ['command-injection', 'sql-injection', 'xss']

    for source_type in source_types:
        cursor.execute('''
            SELECT id, name, content, delivery
            FROM payloads
            WHERE vulnerability = ?
              AND is_deleted = 0
        ''', (source_type,))

        payloads = cursor.fetchall()

        if not payloads:
            continue

        print(f'\n{source_type}: {len(payloads)} 个payload')

        for payload_id, name, content, delivery in payloads:
            # 清理内容：移除查询参数前缀
            cleaned_content = content
            if content.startswith('?'):
                # 提取查询参数后的实际payload
                # 例如：?ip=127.0.0.1;cat /etc/passwd -> ;cat /etc/passwd
                parts = content.split(';', 1)
                if len(parts) > 1:
                    cleaned_content = ';' + parts[1]
                else:
                    parts = content.split('|', 1)
                    if len(parts) > 1:
                        cleaned_content = '|' + parts[1]
                    else:
                        # 保持原样
                        cleaned_content = content.lstrip('?')

            if dry_run:
                if content != cleaned_content:
                    print(f"  [{payload_id[:8]}] {name[:50]}")
                    print(f"    旧: {content[:80]}")
                    print(f"    新: {cleaned_content[:80]}")
            else:
                # 更新为tencent-waf类型
                cursor.execute('''
                    UPDATE payloads
                    SET vulnerability = 'tencent-waf',
                        delivery = 'URL路径',
                        target = '腾讯云WAF',
                        content = ?,
                        usage_method = '直接发送到腾讯云WAF测试，payload会附加在URL路径中',
                        success_indicators = '观察WAF是否拦截（403/405等）或放行（200/404等）'
                    WHERE id = ?
                ''', (cleaned_content, payload_id))

    if not dry_run:
        conn.commit()

        # 统计结果
        cursor.execute("SELECT COUNT(*) FROM payloads WHERE vulnerability = 'tencent-waf' AND is_deleted = 0")
        total = cursor.fetchone()[0]
        print(f'\n完成！现在共有 {total} 个腾讯云WAF测试payload')
    else:
        print('\n预览模式 - 使用 --apply 参数执行实际转换')

    conn.close()

if __name__ == "__main__":
    import sys
    repo_root = Path(__file__).parent.parent
    db_path = repo_root / "data" / "waf_bypasser.db"

    if not db_path.exists():
        print(f"错误: 数据库文件不存在: {db_path}")
        sys.exit(1)

    dry_run = "--apply" not in sys.argv

    if dry_run:
        print("="*80)
        print("预览模式 - 将转换以下payload为腾讯云WAF测试用")
        print("="*80)

    convert_to_tencent_waf(str(db_path), dry_run=dry_run)
