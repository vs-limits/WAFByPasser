# 编码上下文理解 Skill

根据漏洞类型、投递方式、靶场和难度，选择适用编码并套用场景过滤表。不得臆造目标解码器；缺少解码路径信息时必须在说明中保留前提并降低置信度。

---

## 1. 场景过滤表（编码类型 → 各漏洞场景是否适用）

| 编码类型 | xss | sql | cmdi | log4j | upload |
|---------|:---:|:---:|:----:|:-----:|:-----:|
| `url` / `url_fullwidth` / `url_unicode` / `jetty_url` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `html_dec` | ✓ | ✓ | ✗ | ✗ | ✗ |
| `html_hex` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `js_octal` | ✓ | ✗ | ✓ | ✗ | ✗ |
| `js_hex` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `js_unicode` | ✓ | ✗ | ✗ | ✓ | ✗ |
| `hex` | ✓ | ✓ | ✓ | ✓ | ✗ |
| `binary` | ✓ | ✓ | ✓ | ✗ | ✗ |
| `base64` | ✓ | ✗ | ✓ | ✓ | ✗ |
| `base64_datauri` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `quoted_printable` | ✓ | ✗ | ✗ | ✓ | ✗ |
| `utf7` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `cp037` | ✗ | ✗ | ✗ | ✓ | ✗ |
| `utf16be` | ✓ | ✗ | ✗ | ✓ | ✓ |
| `json` | ✓ | ✗ | ✗ | ✓ | ✗ |
| `xml` / `xml_entity` | ✓ | ✗ | ✗ | ✓ | ✓ |
| `graphql` | ✓ | ✗ | ✗ | ✓ | ✗ |
| `ghostbits` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `comment_sql` | ✗ | ✓ | ✗ | ✗ | ✗ |
| `comment_html` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `space_morph` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `case_morph` | ✓ | ✓ | ✗ | ✗ | ✗ |
| `gzip` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `php_serialize` | ✗ | ✗ | ✓ | ✗ | ✓ |

**双层 / 三层链校验**：链中所有编码都必须适用于当前场景，任一不满足则整体丢弃。后端会同时提供 `vulnerability` 与 `allowed_encodings` 白名单，二者都要满足。

## 2. 投递方式对编码的约束

| 投递方式 | 传输层自动解码 | 推荐编码 | 不推荐编码 | 原因 |
|----------|-------------|---------|-----------|------|
| **URL 查询参数** | URL 解码（HTTP 标准） | `url` | — | GET 参数自动 URL 解码，是最可靠的编码目标 |
| **POST 表单字段** | URL 解码（`application/x-www-form-urlencoded`） | `url` | — | 同 URL 参数 |
| **HTTP Header** | **无自动解码** | — | `url` | Header 值不被 Web 服务器自动 URL 解码 |
| **JSON Body** | JSON 解析（`\uXXXX` → Unicode） | `json` / `js_unicode` | `url` | JSON 解析器自动解码 `\uXXXX` |
| **Multipart** | **无自动解码** | — | `url` | Multipart 字段不被自动 URL 解码 |

## 3. 靶场解码器画像

### DVWA (PHP + MySQL)
- **传输层:** PHP `$_GET` / `$_POST` 自动 URL 解码 ✅
- **渲染层:** 手动 `echo` 输出到 HTML，浏览器正常 HTML 解析 ✅
- **应用层:** 默认无 Base64/Hex 自动解码 ❌
- **关键特征:** Low 无过滤；Medium 使用 `str_replace` 黑名单；High 使用正则/白名单

### Pikachu (PHP + MySQL)
- **传输层:** 同 DVWA，PHP 自动 URL 解码 ✅
- **渲染层:** 浏览器正常 HTML 解析 ✅
- **应用层:** 无自动 Base64/Hex 解码 ❌
- **关键特征:** 部分关卡使用 `addslashes()` 转义；GBK 字符集可能存在宽字节注入

## 4. 难度等级含义

| 难度 | 过滤特征 | 编码策略建议 |
|------|---------|------------|
| **Low** | 无过滤或极简过滤 | 部分编码（特殊字符子模式）优先，保持可读性 |
| **Medium** | 黑名单字面量匹配（`str_replace`） | 整句 `url` 编码；关键字编码 + 关键字内断点编码绕过关键字检测 |
| **High** | 正则/白名单/输入验证 | 双层嵌套（如 `url→base64`）；部分编码混合；降低置信度 |

## 5. 上下文推断

从 `base_payload` 结构推断编码优先级：
- 含 `;` `|` `&&` `$()` → 命令注入上下文 → 优先 `url`（传输层）
- 含 `'` `OR` `UNION` `SELECT` → SQL 注入上下文 → 优先 `url`（传输层）+ `comment_sql`
- 含 `<script>` `<img` `onerror=` → XSS 上下文 → 优先 `html_hex`（渲染层）+ `ghostbits`/`comment_html`
- 含 `${` `jndi:` → Log4j/表达式注入 → 优先 `js_unicode`/`url`，注意仅 `log4j` 场景适用编码

## 6. 部分编码适用性

部分编码只对字符级编码适用：A 组 4 种 + B 组 5 种 + C 组 `hex`/`binary` + F 组 `xml`/`xml_entity`，共 12 种。G 组有损编码、算法编码（`base64` 等）、压缩/序列化不参与部分编码。

## 7. 关键约束

- **不得臆造解码器:** 声称目标会 Base64/Hex 解码时，必须有上下文证据（如代码可见 `base64_decode()`，或 payload 来自已知有此逻辑的靶场）。
- **投递不可变:** delivery 字段确定后，编码必须与该传输方式兼容。
- **保守优先:** 不确定解码器是否存在时，降低 confidence 而非删除候选——让人工测试者决定。
- **场景过滤优先:** 先按场景表剔除不适用的编码，再按白名单选择。
