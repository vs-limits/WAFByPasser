#!/usr/bin/env python3
"""将腾讯云WAF payload重新分类到实际的漏洞类型"""

import sqlite3
from pathlib import Path

# 分类映射规则
CATEGORY_TO_VULNERABILITY = {
    # 命令注入相关的所有分类
    'command-injection': [
        '系统文件读取', 'Web源码读取', '配置文件读取', '敏感文件读取', '临时文件读取',
        '日志文件读取', '命令组合注入', '条件语句', 'awk命令注入', 'find命令注入',
        'sed命令注入', 'grep命令注入', 'scp命令注入', 'tar命令注入', 'git命令注入',
        'zip命令注入', 'ssh命令注入', 'rsync命令注入', 'wget命令注入', 'curl命令注入',
        'xargs命令注入', 'tmux命令注入', 'screen命令注入', 'make命令注入', 'strace命令注入',
        'script命令注入', 'printf命令注入', 'dd命令注入', 'time命令注入', 'timeout命令注入',
        'sort命令注入', 'nice命令注入', 'env命令注入', 'diff命令注入',
        '通用参数绕过', '通用语法', '管道组合', '命令拼接', '逻辑符', '变量替换',
        '命令注入', '盲注探测'
    ],

    # SQL注入
    'sql-injection': ['SQL注入'],

    # XSS
    'xss': ['XSS'],

    # 路径遍历
    'path-traversal': ['路径遍历'],

    # 代码执行
    'code-execution': ['代码执行'],

    # SSRF
    'ssrf': ['SSRF'],

    # XXE
    'xxe': ['XXE'],

    # 文件包含
    'file-inclusion': ['文件包含'],
}

def reclassify_payloads(db_path: str, dry_run: bool = False):
    """重新分类腾讯云WAF payload"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 获取所有tencent-waf类型的payload
    cursor.execute('''
        SELECT id, name, category
        FROM payloads
        WHERE vulnerability = 'tencent-waf' AND is_deleted = 0
    ''')

    payloads = cursor.fetchall()
    print(f'找到 {len(payloads)} 个需要重新分类的payload\n')

    # 统计
    stats = {}
    unmapped = []

    for payload_id, name, category in payloads:
        # 查找匹配的漏洞类型
        new_vuln = None

        # 首先尝试直接匹配category
        for vuln_type, categories in CATEGORY_TO_VULNERABILITY.items():
            if category in categories:
                new_vuln = vuln_type
                break

        # 如果没有匹配，尝试从名称中提取关键词
        if not new_vuln:
            name_lower = name.lower()
            category_lower = category.lower()

            # 命令注入相关
            if any(kw in name_lower or kw in category_lower for kw in ['命令', 'command', 'injection', '注入']):
                if 'sql' not in name_lower and 'xss' not in name_lower:
                    new_vuln = 'command-injection'
            # SQL注入
            elif 'sql' in name_lower or 'sql' in category_lower or '宽字节' in name or '条件判断' in category:
                new_vuln = 'sql-injection'
            # XSS
            elif 'xss' in name_lower or 'xss' in category_lower:
                new_vuln = 'xss'
            # 路径遍历
            elif any(kw in name_lower or kw in category_lower for kw in ['路径', 'traversal', '目录']):
                new_vuln = 'path-traversal'
            # 文件上传
            elif any(kw in name_lower or kw in category_lower for kw in ['上传', 'upload']):
                new_vuln = 'file-upload'
            # SSRF
            elif 'ssrf' in name_lower or 'ssrf' in category_lower:
                new_vuln = 'ssrf'
            # XXE
            elif 'xxe' in name_lower or 'xxe' in category_lower:
                new_vuln = 'xxe'
            # 文件包含
            elif any(kw in name_lower or kw in category_lower for kw in ['包含', 'inclusion', 'include']):
                new_vuln = 'file-inclusion'

        if new_vuln:
            stats[new_vuln] = stats.get(new_vuln, 0) + 1

            if not dry_run:
                cursor.execute('''
                    UPDATE payloads
                    SET vulnerability = ?
                    WHERE id = ?
                ''', (new_vuln, payload_id))
        else:
            unmapped.append((payload_id, name, category))

    if dry_run:
        print('预览模式 - 分类统计：')
        print('-' * 60)
        for vuln_type, count in sorted(stats.items()):
            print(f'{vuln_type:30s} : {count:3d} 条')

        if unmapped:
            print(f'\n未映射的分类 ({len(unmapped)} 条):')
            for pid, name, cat in unmapped[:10]:
                print(f'  - {cat}: {name[:50]}')
            if len(unmapped) > 10:
                print(f'  ... 还有 {len(unmapped) - 10} 条')

        print('\n使用 --apply 参数执行实际重分类')
    else:
        conn.commit()
        print('[OK] 重分类完成！')
        print('-' * 60)
        for vuln_type, count in sorted(stats.items()):
            print(f'{vuln_type:30s} : {count:3d} 条')

        if unmapped:
            print(f'\n[警告] {len(unmapped)} 条payload未能映射，保持为tencent-waf')

    conn.close()

if __name__ == "__main__":
    import sys
    repo_root = Path(__file__).parent.parent
    db_path = repo_root / "data" / "waf_bypasser.db"

    if not db_path.exists():
        print(f"错误: 数据库文件不存在: {db_path}")
        sys.exit(1)

    dry_run = "--apply" not in sys.argv
    reclassify_payloads(str(db_path), dry_run=dry_run)
