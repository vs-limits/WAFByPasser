# 上下文感知 Skill（生产级）

## 核心任务

识别 Payload 运行的**环境上下文**，确保变异操作不破坏注入有效性。理解投递方式、靶场特性和解释器限制。

## 投递上下文

### URL 查询参数投递（?key=value）
```
限制：
- 空格会被浏览器编码为 + 或 %20
- & 和 = 是参数分隔符和键值分隔符，需要编码
- # 及之后的内容是 URL 片段，不会发送到服务器
- URL 总长度有限制（通常 2048-8192 字符）
- 换行符 %0a 可能被 HTTP 代理/负载均衡器截断

语义 Agent 输出原始文本；传输层的 URL 编码由发送器处理。
你不需要在 payload 中写入 %20 等编码——发送器会自动处理。
```

### URL 路径投递（/path/{injection}）
```
限制：
- / 是路径分隔符，不能出现在注入内容中
- ? 会终止路径并开始查询字符串
- 路径中的空格保持原样（不编码）
- . 和 .. 有特殊含义（当前目录和父目录）
```

### 不在语义迭代范围内的投递方式
```
表单 POST → 不在 URL 中，WAF 检测规则不同
JSON body → Content-Type 为 application/json
Header/Cookie → 不同的编码和传输约束
Multipart → 文件上传场景
这些投递方式 base_parts 解析会拒绝（status=unsupported）。
```

## 靶场特性

### DVWA (Damn Vulnerable Web Application)
```
难度分级：
- Low：无过滤，直接 passthru()/shell_exec()
- Medium：过滤 ; 和 &&（用 str_replace 移除）
- High：过滤 ; | & $ ( ) ` \n，使用更多的 str_replace
- Impossible：使用白名单 + CSRF token + 严格输入验证

DVWA 特性：
- 命令注入通过 POST 表单 field=IP 提交（后端 shell_exec("ping -c 4 " . $IP)）
- escapeshellcmd() 在某些级别被使用
- PHP 的 escapeshellcmd 盲区：%0a 换行、反引号在某些版本中有绕过可能
- SQL 注入：Medium/High 使用 mysqli_real_escape_string
- XSS：Medium 过滤 <script>，High 过滤更多标签

建议：
- Medium 级别优先使用 |, %0a, 反引号, $(...), || 作为分隔符
- High 级别优先使用 %0a, 花括号展开, 变量间接引用
- 如果 IP 前缀必须保留，只变异分隔符之后的内容
```

### Pikachu
```
特性：
- 多漏洞类型测试平台
- "宽字节注入" 是特色漏洞（利用 GBK 编码中 %df' 被 addslashes 转义后形成宽字节绕过）
- 命令注入通过 exec() 函数
- SQL 注入支持数字型和字符型

注意：宽字节注入是编码层面的技术，属于编码 Agent；本 Agent 不直接使用。
但可以使用 SQL 谓词重写、运算符切换等语义技术。
```

### 通用靶场（未指定具体平台）
```
假设标准 Unix/Linux 环境：
- GNU bash 4.x 或更高版本
- 标准 Unix 工具链（cat, ls, grep 等在 /bin/ 或 /usr/bin/）
- PHP 7.x/8.x（Web 应用）
- Apache 2.4 / Nginx 1.x（Web 服务器）

可用的 bash-ism：
- ${IFS}、$IFS（IFS 变量展开）
- ${var:offset:len}（子串提取）
- ${var//pattern/replacement}（模式替换）
- <<<（here-string）
- $'...'（ANSI-C 引用）
- {a,b}（花括号展开）
- $(...) 和 `...`（命令替换）
- <(...) 和 >(...)（进程替换）
```

## 依赖验证

添加可选部件前，验证其依赖是否满足：

```
添加 pipeline（管道结构）→ 依赖 injection_command 存在
添加 conditional（条件结构）→ 依赖 injection_command 存在
添加 stderr_handling → 依赖 injection_command 存在
添加 bounded_loop → 依赖 injection_command 存在
添加 argument → 依赖 injection_command 存在
添加 var_indirection → 不依赖（在命令前插入变量定义）
添加 brace_expansion → 可以应用在 injection_command 或 argument 上
添加 wildcard → 依赖 argument 或 injection_command 存在
```

缺少依赖时，不能添加该部件。这在 `dependencies` 字段中声明。

## 兼容性注意

不同 shell 支持的特性不同：

```
特性              bash  dash  sh   zsh  ksh  busybox
${IFS}           ✅    ✅    ✅   ✅   ✅   ✅
{cat,head}       ✅    ❌    ❌   ✅   ✅   ❌
<<< here-string  ✅    ❌    ❌   ✅   ✅   ❌
$'...'           ✅    ❌    ❌   ✅   ✅   ❌
${var:0:1}       ✅    ❌    ❌   ✅   ✅   ❌
$(< file)        ✅    ❌    ❌   ✅   ✅   ❌
<(...) process   ✅    ❌    ❌   ✅   ✅   ❌

原则：优先使用 POSIX 兼容语法（${IFS}, $(...), | 管道）。
只有在 available_directions 明确指示时使用 bash-ism。
如果在通用靶场中使用 bash-ism，在 explanation 中说明兼容性限制。
```

## 部件之间不可破坏的关系

有些部件关系如果被破坏，Payload 会完全失效：

```
破坏性操作                        原因
─────────────────────────────────────────────────────
删除 quote_context（闭合引号）    注入不再逃离字符串上下文
删除 separator（命令分隔符）      命令无法与合法前缀分离
替换 separator 为非分隔符文本     注入成为合法参数的一部分
改变 injection_command 为无关命令  验证目标丢失
删除必需的闭合结构（SQL/XSS）     语法错误，注入不执行
添加语法错误的依赖结构            整个 Payload 解析失败
```
