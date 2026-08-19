# 编码上下文理解 Skill

根据漏洞类型、投递方式、靶场和难度选择可能适用的编码表示。不得臆造目标解码器；缺少解码路径信息时必须在说明中保留前提并降低置信度。

---

## 1. 漏洞类型 → 编码映射

| 漏洞类型 | 优先编码 | 次选编码 | 避免使用 | 原因 |
|----------|---------|---------|---------|------|
| **command-injection** | `url_percent` | `hex_text`, `base64url` | `html_entity_*` | Shell 不解析 HTML 实体；URL 编码在 HTTP 传输层自动解码；hex/base64 需应用层显式解码 |
| **sql-injection** | `url_percent` | `hex_text`（配合 `UNHEX()`）, `base64`（配合 `FROM_BASE64()`） | `html_entity_*`（除非 SQL 错误反射到 HTML） | SQL 引擎本身不处理 HTML 实体；反射到 HTML 页面的 SQL 错误才需考虑实体编码 |
| **xss** | `html_entity_hex`, `html_entity_decimal` | `url_percent`, `unicode_escape` | `base64`, `hex_text` | 浏览器自动解码 HTML 实体（渲染层）；`<script>` 内 JS 引擎解码 `\uXXXX`；base64/hex 在 HTML 上下文中不会被自动解码 |

## 2. 投递方式对编码的约束

| 投递方式 | 传输层自动解码 | 推荐编码 | 不推荐编码 | 原因 |
|----------|-------------|---------|-----------|------|
| **URL 查询参数** | URL 解码（HTTP 标准） | `url_percent` | — | GET 参数自动 URL 解码，是最可靠的编码目标 |
| **POST 表单字段** | URL 解码（`application/x-www-form-urlencoded`） | `url_percent` | — | 同 URL 参数 |
| **HTTP Header** | **无自动解码** | — | `url_percent` | Header 值不被 Web 服务器自动 URL 解码；选择需确认应用是否手动解码 |
| **JSON Body** | JSON 解析（`\uXXXX` → Unicode） | `json_unicode_escape` | `url_percent` | JSON 解析器自动解码 `\uXXXX`；URL 编码在 JSON 中只是字面量 |
| **Multipart** | **无自动解码** | — | `url_percent` | Multipart 字段不被自动 URL 解码 |

## 3. 靶场解码器画像

### DVWA (PHP + MySQL)
- **传输层:** PHP `$_GET` / `$_POST` 自动 URL 解码 ✅
- **渲染层:** 手动 `echo` 输出到 HTML，浏览器正常 HTML 解析 ✅
- **应用层:** 默认无 Base64/Hex 自动解码 ❌
- **关键特征:** Low 难度无过滤；Medium 使用 `str_replace` 黑名单；High 使用正则/白名单

### Pikachu (PHP + MySQL)
- **传输层:** 同 DVWA，PHP 自动 URL 解码 ✅
- **渲染层:** 浏览器正常 HTML 解析 ✅
- **应用层:** 同 DVWA，无自动 Base64/Hex 解码 ❌
- **关键特征:** 部分关卡使用 `addslashes()` 转义；GBK 字符集可能存在宽字节注入

## 4. 难度等级含义

| 难度 | 过滤特征 | 编码策略建议 |
|------|---------|------------|
| **Low** | 无过滤或极简过滤 | `special` 模式优先（保持可读性）；`url_percent` 足够 |
| **Medium** | 黑名单字面量匹配（`str_replace`） | `full` 模式 URL 编码；考虑 HTML 实体绕过关键字检测 |
| **High** | 正则/白名单/输入验证 | 双层编码；考虑传输层 + 应用层组合；降低置信度 |

## 5. 上下文推断

从 `base_payload` 结构推断编码优先级：
- 含 `;` `|` `&&` `$()` → 命令注入上下文 → 优先 `url_percent`（传输层）
- 含 `'` `OR` `UNION` `SELECT` → SQL 注入上下文 → 优先 `url_percent`（传输层）
- 含 `<script>` `<img` `onerror=` → XSS 上下文 → 优先 `html_entity_hex`（渲染层）
- 含 `${` `jndi:` → Log4j/表达式注入 → **超出编码 Agent 支持范围，应拒绝**

## 6. 关键约束

- **不得臆造解码器:** 声称目标会 Base64 解码时，必须有上下文证据（如 `base64_decode()` 在代码中可见，或 payload 来自已知有此逻辑的靶场）
- **投递不可变:** delivery 字段确定后，编码必须与该传输方式兼容
- **保守优先:** 不确定解码器是否存在时，降低 confidence 而非删除候选——让人工测试者决定
