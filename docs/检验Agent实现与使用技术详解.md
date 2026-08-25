# WAFByPasser 检验 Agent 实现与使用技术详解

> 本文基于当前仓库源码整理，面向授权 WAF 测试、隔离靶场验证和防御研究。它解释检验 Agent 如何接收候选、真实发起验证、收集硬证据、限制 LLM 权限，以及最终如何归档和回写知识库。

## 一、一句话定义

检验 Agent 不是“把响应交给大模型猜成功与否”的聊天机器人，而是一套由确定性程序主导的验证流水线：

```text
SQLite 持久化任务队列
        +
固定数量的常驻 Worker
        +
五类漏洞靶场适配器
        +
服务端权威验证规则
        +
受限的 LLM 辅助分析
        +
结果归档与知识库反馈
```

其中最重要的设计原则是：

```text
最终成功或失败由实际 HTTP/浏览器/OOB 证据和确定性真值表决定；
LLM 只解释证据、给出置信度和下一次路由建议，不能修改最终裁决。
```

---

## 二、检验 Agent 在整个项目中的位置

项目先由语义 Agent、编码 Agent 或交叉迭代流程产生候选，检验 Agent 负责后半段的“真实环境闭环”。

```text
基础 Payload
    ↓
语义迭代 / 编码迭代 / 交叉迭代
    ↓
候选进入 candidates 表
    ↓ AUTO_VERIFY=true
verification_jobs 持久化队列
    ↓
Worker 原子认领任务
    ↓
按漏洞类型选择靶场适配器
    ↓
向授权靶场和 WAF 发出真实请求
    ↓
收集 HTTP、浏览器、回显、文件访问或 OOB 证据
    ↓
确定性规则裁决，必要时让 LLM 辅助解释
    ↓
bypass 库 / block 库 / unverified 库
    ↓
统计特征、技法成功率、转正和淘汰
```

主要源码位置：

- `backend/src/app/main.py`：入队、Worker、任务处理、事务落库、人工复核。
- `backend/src/app/verification_agent/adapters.py`：CMDI、XSS、SQLi、Log4j、文件上传适配器。
- `backend/src/app/verification_agent/judge.py`：LLM 调用、输出约束和确定性真值表。
- `backend/src/app/verification_agent/oob_listener.py`：OOB HTTP 回连监听。
- `backend/src/app/waf_testing.py`：WAF 拦截页识别。
- `backend/src/app/execution_goals.py`：服务端执行目标目录及权威验证规则。
- `backend/src/app/verification_agent/prompt/verification_judge.md`：检验 LLM 提示词。
- `config/.env.example`：并发、队列、LLM、靶场和 OOB 配置示例。

---

## 三、一个任务从开始到结束怎样运行

### 第 1 步：候选进入持久化检验队列

当 `AUTO_VERIFY=true` 时，语义候选、编码候选和交叉候选生成后，会写入 SQLite 的 `verification_jobs` 表。

任务状态依次变化：

```text
waiting → queued → running → completed
                          └→ failed
```

- `waiting`：已经登记，但受队列容量限制，暂未投递。
- `queued`：已经进入可消费队列。
- `running`：某个 Worker 已经认领。
- `completed`：检验流程完成，不代表一定绕过成功。
- `failed`：任务处理本身异常。

`VERIFY_QUEUE_CAPACITY` 限制 `queued + running` 的总量，示例配置默认为 5。超过容量的任务保留为 `waiting`，已有任务完成后再补入队列。它实现的是背压，防止瞬间创建大量真实网络请求。

任务记录还保存候选来源、漏洞类型、基础 Payload、候选 Payload、候选类型、执行目标、验证规则和技法 ID 等上下文，使任务可以在进程重启后继续执行。

### 第 2 步：常驻 Worker 并发消费

服务启动时创建固定数量的 daemon 线程，数量由 `VERIFY_CONCURRENCY` 控制，示例默认值为 3。

Worker 的工作方式是：

1. 从 SQLite 查找最早的 `queued` 任务。
2. 使用独立数据库连接和 `BEGIN IMMEDIATE` 开启事务。
3. 在事务内把目标任务从 `queued` 改为 `running`。
4. 提交事务，完成原子认领。
5. 在数据库锁之外执行真实网络验证。
6. 最后重新开启事务，保存裁决和全部证据。

原子认领避免两个线程消费同一个任务。网络访问不占用全局数据库锁，避免慢请求拖住其他 API 和 Worker。

没有任务时，Worker 使用 `threading.Condition` 等待通知，并设置约 2 秒的兜底唤醒。服务异常退出后，启动恢复逻辑会把遗留的 `running` 任务改回 `queued`，避免任务永久卡死。

### 第 3 步：解析任务并选择适配器

任务处理函数解析：

- 基础 Payload 与候选 Payload；
- 漏洞类型；
- 候选属于 semantic、encoding 还是 cross；
- 编码链及其层数；
- `execution_goal_id`；
- 服务端可接受的 `verification_spec`；
- 是否属于盲注、OOB 或无法用普通响应自动闭环的场景。

然后 `resolve_adapter` 按漏洞类型选择 CMDI、XSS、SQLi、Log4j 或 Upload 适配器。

### 第 4 步：建立服务端权威验证规则

检验成功不能由候选自行声明。系统通过 `execution_goal_id` 到服务端的执行目标目录中查找权威规则。

支持三种验证方式：

- `marker`：响应必须包含指定标记。
- `regex`：响应必须匹配指定正则。
- `combo`：按服务端定义组合多个条件。

候选携带的自由格式 `verification_spec` 不能单独制造成功结果。`execution_goal_id` 还只允许做非常有限的尾字符修复：最多缺少 1～2 个字符，并且必须能够唯一匹配。

这能防止模型或输入数据用“自报成功标志”的方式污染验证结果。

### 第 5 步：向真实靶场发出请求

适配器会根据靶场配置组装 URL、请求方法、参数、Cookie、Host、上传文件或浏览器页面，然后使用 `httpx` 或 Playwright 发起真实请求。

请求后统一生成 `TargetEvidence` 证据对象，主要包含：

- 靶场键和漏洞类型；
- 脱敏后的请求摘要；
- HTTP 状态码；
- 响应头；
- 截断后的响应正文；
- 实际发送的正文；
- 基线响应；
- 适配器给出的 outcome；
- 漏洞执行证据；
- 请求 SHA-256 摘要。

正文通常最多保留 4000 字符，响应头最多保留 2000 字符，既保留审计依据，又限制数据库和 LLM 上下文的大小。

### 第 6 步：先判定是否被 WAF 拦截

WAF 判定不只看状态码：

- HTTP 403、406、429：直接视为 `waf_blocked`。
- 响应正文出现 SafeLine、Access Denied、Request Blocked 等拦截特征：视为 `waf_blocked`。
- 腾讯云 WAF 可能用 HTTP 200 返回拦截页面，所以额外检查“腾讯云 WAF”“访问拦截”“Web 应用防护”“block-pages”等特征。
- 其他 HTTP 4xx/5xx：一般记为 `request_error`。
- 没有拦截迹象：记为 `application_response`，表示请求已到达应用层。

注意：`application_response` 只等于“WAF 看起来放行了”，不自动等于“漏洞执行成功”。

### 第 7 步：确认漏洞是否真实执行

不同漏洞需要不同的硬证据：

- 命令注入：服务端响应中出现权威 marker、regex 或组合证据。
- XSS：真实 Chromium 页面触发 JavaScript dialog 事件。
- SQL 注入：应使用内容差异、时间差或明确 marker；当前实现对普通 SQLi 响应的自动确认能力有限。
- Log4j：OOB 监听器收到唯一 token 对应的回连。
- 文件上传：上传成功后再次访问文件，访问结果命中权威验证规则。

适配器只有取得这些硬证据时，才返回 `execution_confirmed`。

### 第 8 步：编码链可逆性检查

对 encoding 和 cross 候选，系统还会倒序应用解码器，检查候选能否还原为基础 Payload。该检查证明：

```text
候选的编码链是可逆的，并且编码前后的语义载荷一致。
```

当前实现还有一条特殊规则：当 WAF 已放行、适配器返回 `application_response`、编码链为 1～3 层且能够还原基础 Payload 时，系统会把结果升级为 `execution_confirmed`。

这是一项重要的实现取舍。它实际上确认的是“编码表示可逆且穿过了 WAF”，不一定证明目标应用已经执行漏洞。因此阅读结果时应区分：

```text
真实执行证据：浏览器 dialog / OOB 回连 / 权威回显 / 上传后访问证据
编码代理证据：可逆编码链 + WAF 放行
```

若项目用于高可信安全评估，建议在报告层给这两类结果使用不同标签。

### 第 9 步：必要时调用受限 LLM

硬结果会短路：已经明确拦截、请求错误或确认执行时，不需要 LLM 猜测。

只有证据存在解释空间时，检验 Agent 才调用 OpenAI-compatible Chat Completions。它可使用独立的 `VERIFY_LLM_*` 配置，没有时回退到通用 `LLM_*` 配置。

LLM 只能输出：

- `analysis`：受白名单约束的分析字段；
- `rationale`：判读理由；
- `confidence`：被程序夹到 0～1；
- `route_suggestion`：下一次可尝试的正整数靶场关卡。

`analysis` 只接受：

- `bypass_assessment`；
- `execution_assessment`；
- `notable_signals`。

每个字段还有长度限制。响应正文在提示词中被明确声明为不可信数据，用于降低靶场返回内容对 LLM 的提示注入影响。

即使模型输出 verdict，程序也会忽略它。最终的 `bypass_verdict`、`execution_verdict` 和 `failure_stage` 仍由确定性真值表生成。

如果没有配置 LLM，系统保守地使用确定性规则继续运行。不过当前代码中，如果已发起 LLM 请求但请求失败或 JSON 无法解析，可能把本来已经得到的 `application_response` 转成 `check_error`；这是一个可用性与保守判定之间的取舍。

### 第 10 步：归一化裁决

核心真值表如下：

| 适配器结果 | WAF 裁决 | 执行裁决 | 失败阶段 | 含义 |
|---|---|---|---|---|
| `waf_blocked` | `block` | `not_confirmed` | `bypass_failed` | 请求被 WAF 拦截 |
| `request_error` | `error` | `not_confirmed` | `check_error` | 网络、靶场或请求异常 |
| `unsupported_context` | `error` | `not_confirmed` | `check_error` | 当前上下文无法检验 |
| `execution_confirmed` | `bypass` | `confirmed` | 空 | 放行且取得硬执行证据 |
| `application_response` + 确定性验证器但未命中 | `bypass` | `not_confirmed` | `verify_failed` | WAF 放行，但执行验证失败 |
| `application_response` 且没有验证器 | `bypass` | `unverified` | 空 | 已放行，但没有足够证据判断执行 |

程序还拒绝逻辑矛盾的组合，例如：

- `block + confirmed`；
- `block + unverified`；
- `error + confirmed`。

### 第 11 步：事务落库和知识反馈

任务完成后，系统在事务中保存：

- 原始 Payload 的 SHA-256；
- 实际发送内容；
- `payload_fidelity`，区分 exact 与 template-expanded；
- 最终请求摘要；
- 响应状态、响应头和正文证据；
- 基线响应；
- 权威 `verification_spec`；
- LLM 分析、理由和置信度；
- 使用的 technique IDs。

结果进入三个互斥结果库：

- bypass 库：WAF 放行且执行已确认。
- block 库：WAF 拦截、执行验证失败或检验异常。
- unverified 库：WAF 放行，但缺少硬执行证据。

同时写入不可变的 `kb_observations`，并更新：

- WAF 特征的 `n_200`、`n_403` 和通过率；
- 精确 technique ID 的尝试数和绕过数；
- 首次有效绕过后的技法转正；
- 达到足够不同原语样本、仍然零绕过的生成技法淘汰状态。

因此检验结果不仅用于展示，还会影响后续候选生成和技法选择。

---

## 四、五类漏洞适配器怎样实现

### 1. 命令注入适配器

目标通常为 DVWA：`/vulnerabilities/exec/`，使用 POST 表单字段 `ip`。

实现要点：

- 普通通道先登录 DVWA，并把安全级别设为 Low。
- WAF 直连通道使用源站 IP、自定义 Host 和静态 Cookie，跳过登录跳转。
- 语义候选会剥离可能重复的前导命令分隔符，避免默认前缀和候选拼成无意义的双分隔符。
- encoding/cross 候选使用一次性表单编码函数，保留候选中已有的 `%HH`，防止框架再次 URL 编码。
- WAF 放行后，响应必须命中服务端 marker、regex、combo 或兼容的旧式 `*_OK` 回显，才确认执行。

结果：可以同时证明“请求穿过 WAF”和“命令注入目标产生了预期回显”。

### 2. XSS 适配器

目标通常为 DVWA 反射型 XSS：`/vulnerabilities/xss_r/?name=<payload>`。

核心技术是 Playwright + headless Chromium：

1. 先用 `httpx` 快速请求，判断是否明显被 WAF 拦截。
2. 放行后再启动浏览器，降低每个任务的资源成本。
3. 注册浏览器 `dialog` 事件监听器。
4. 页面脚本触发对话框后自动接收，并记录为执行硬证据。

WAF 直连浏览器场景使用 Chromium 的：

```text
--host-resolver-rules=MAP <域名> <源站IP>
```

这样浏览器仍以原域名构造 Host 和页面上下文，但 TCP 连接直接指向源站 IP。

如果 Playwright 不可用，代码会降级为 `httpx`。降级模式只能判断 WAF 是否放行，不能证明 JavaScript 真正执行，因此应进入未验证状态，而不是成功状态。

### 3. SQL 注入适配器

目标为 sqli-labs。系统用正则大致识别候选类别并选择关卡：

- UNION 型：Less-1；
- 时间型：Less-9；
- 堆叠型：Less-38；
- 布尔型：Less-8。

二次检验时可以接受 LLM 的正整数 `route_suggestion`，切换到其他 Less 关卡。但建议只把它理解为“下一站去哪试”，不能理解为“模型宣布本次成功”。

适配器会发送 `id=1` 基线请求和候选请求，并保存两份响应。不过当前 `run_sqli()` 主要用它们完成 WAF 放行判断，没有完整利用响应差异直接产生 `execution_confirmed`。

这意味着当前 SQLi 自动验证仍有改进空间：

- 布尔型应比较真假分支的稳定差异；
- 时间型应多次测量并使用统计阈值；
- UNION 型应要求唯一 marker；
- 错误型应匹配特定数据库错误并排除基线已有错误。

### 4. Log4j 适配器

目标为 Solr：`/solr/admin/info/system?action=<payload>`。代码选择该路径，是因为某些环境中 `/solr/admin/cores` 的基线请求也会被 WAF 拦截。

普通 HTTP 响应只能说明 WAF 是否放行，无法证明 JNDI 查找是否在服务端发生。因此系统把这类场景视为 OOB 验证：

1. Payload 必须显式包含 `{{OOB_CALLBACK_URL}}`。
2. 系统生成唯一 token。
3. 只替换这个占位符，不擅自修改外部 URL，也不追加执行脚本。
4. 发送请求后轮询 OOB 监听服务。
5. 收到对应 token 的回连后，才返回 `execution_confirmed`。

默认轮询约 8 秒，每秒请求一次 `/api/oob/check?token=<token>`。

OOB 监听器使用 Python 标准库 `HTTPServer`，以内存字典保存首次回调，并用 `threading.Lock` 保护并发访问。当前实现没有持久化、鉴权和 token 过期清理，更适合单机隔离实验环境，不适合直接作为互联网暴露的生产监听服务。

### 5. 文件上传适配器

适配器通过内容特征区分 PHP 和 JSP：

- PHP 路由到 Upload-Labs 1～20；
- JSP 路由到 Upload-Labs 1～10。

流程是：

1. 使用 `multipart/form-data` 上传文件。
2. 检查响应中是否出现“上传成功”、`uploads/`、`/upload/` 等迹象。
3. 提取或构造上传后的访问地址。
4. 再次 GET 访问上传文件。
5. 访问响应命中服务端 marker、regex 或 combo 后，确认执行。

LLM 的 `route_suggestion` 可以让重验切换到不同的 passNN 关卡。

文件上传默认被视为较难自动闭环的类型，但只要适配器已经拿到上传后访问的明确硬证据，`execution_confirmed` 仍会优先短路。

---

## 五、LLM 到底参与了什么，没有参与什么

| 能力 | LLM 是否负责 | 实际负责人 |
|---|---:|---|
| 发送真实请求 | 否 | 漏洞适配器、httpx、Playwright |
| 判断典型 WAF 拦截页 | 否 | 状态码和特征规则 |
| 验证 marker/regex/combo | 否 | 服务端确定性验证器 |
| 确认浏览器 dialog | 否 | Playwright 事件 |
| 确认 OOB 回连 | 否 | OOB listener + token |
| 解释模糊证据 | 是 | 受限检验 LLM |
| 给出下一关卡建议 | 是 | `route_suggestion` |
| 决定最终 bypass verdict | 否 | `normalize_verdict` 真值表 |
| 决定最终 execution verdict | 否 | `normalize_verdict` 真值表 |

这种分工的目标是让 LLM 提供语义理解能力，同时不把安全验证的最终裁决交给不可重复的模型输出。

---

## 六、编码绕过中有没有“混淆处理”

有，但应准确称为“受约束、可逆的编码表示变换”，而不是任意混淆。

它包含的混淆表现主要有：

- 整句编码；
- 只编码关键片段；
- 一层、双层和三层嵌套编码；
- 多种兼容编码技法的组合；
- 语义变体之后再编码的 cross 候选；
- 保留已有 `%HH`，避免传输层意外二次编码；
- 通过逆向解码验证最终仍能恢复基础 Payload。

因此从 WAF 视角看，它确实起到了混淆特征、改变表面字节序列和影响规范化链的效果；但项目对它施加了三个边界：

1. 变换必须来自允许的编码技法。
2. 编码链长度受限，当前自动升级规则只接受 1～3 层。
3. 必须能逆向恢复基础 Payload，不能在过程中随意改变语义。

它不等同于：

- 随机插入垃圾字符；
- 不可逆加密；
- 任意改写攻击语义；
- 由 LLM 自由生成未知载荷；
- 只因字符串“看起来复杂”就宣布绕过成功。

更精确的关系是：

```text
混淆是外在效果
编码是实现手段
可逆性是正确性约束
WAF 放行是网络侧结果
漏洞执行证据才是应用侧结果
```

---

## 七、失败恢复、重验和人工复核

### 自动恢复

- 服务重启时，遗留的 `running` 任务恢复为 `queued`。
- `waiting` 任务会在队列出现容量后继续补入。
- Worker 的异常会落为任务失败或检验错误，不会把异常伪装成绕过成功。

### 手动重验

接口：

```text
POST /api/verification-jobs/{id}/reverify
```

它可以重新投递任务，并在 SQLi、Upload 等适配器中利用先前的 `route_suggestion` 尝试其他靶场关卡。

### 人工处理未验证结果

接口：

```text
POST /api/unverified-library/{id}/resolve
```

- `confirmed`：从 unverified 移动到 bypass 库。
- `failed`：从 unverified 移动到 block 库，并标记 `verify_failed`。

当前人工确认路径会更新结果库和 verification job，但没有完整调用自动验证路径中的 observation 记录与 technique promotion，因此人工裁决不会完整反映到全部知识学习统计。这是当前实现边界之一。

---

## 八、使用到的主要技术

| 技术 | 在检验 Agent 中的用途 |
|---|---|
| Python 3 | 后端及验证器主要实现语言 |
| FastAPI | 验证任务、重验、人工复核和 OOB 检查 API |
| SQLite + WAL | 持久化任务队列、证据和结果库 |
| `threading.Thread` | 固定数量的并发 Worker |
| `Condition` / `Event` / `Lock` | 任务唤醒、停止控制和 OOB 状态并发保护 |
| `BEGIN IMMEDIATE` | SQLite 任务原子认领 |
| httpx | 表单、查询参数、基线、上传和回连检查请求 |
| Playwright + Chromium | XSS 的真实浏览器执行验证 |
| Python `HTTPServer` | 轻量 OOB 回连监听器 |
| SHA-256 | Payload 和请求证据摘要 |
| 正则表达式 | WAF 页面、漏洞类别、响应 marker 和上传路径识别 |
| multipart/form-data | 文件上传靶场检验 |
| Host Header + 源站 IP | 模拟经过 WAF 的域名或直接访问源站 |
| OpenAI-compatible Chat Completions | 对不确定证据做受限解释和路由建议 |
| python-dotenv | 从 `.env` 加载靶场、并发和模型配置 |
| DVWA | CMDI、反射型 XSS 靶场 |
| sqli-labs | 多关卡 SQL 注入靶场 |
| Apache Solr | Log4j/JNDI 验证目标 |
| Upload-Labs | PHP/JSP 文件上传靶场 |

---

## 九、当前实现的优点

1. **最终裁决确定性较强**：LLM 不能直接宣布成功。
2. **证据来源多样**：支持 HTTP、浏览器事件、回显、二次文件访问和 OOB 回连。
3. **任务可恢复**：SQLite 持久化和启动恢复避免内存队列丢任务。
4. **并发边界清楚**：固定 Worker 数量和队列容量保护靶场及本机资源。
5. **验证规则由服务端控制**：候选不能伪造自己的成功条件。
6. **结果能反哺生成过程**：检验不是孤立步骤，而是知识学习闭环的一部分。
7. **保留实际发送内容**：能区分原始候选和模板展开后的请求，便于审计。
8. **对编码候选做可逆检查**：减少编码链破坏语义却被误当作有效候选的情况。

---

## 十、阅读结果时必须注意的边界

1. **WAF 放行不等于漏洞执行。** `application_response` 只说明未识别出拦截。
2. **编码可逆不等于应用执行。** 当前 encoding/cross 的自动升级规则是一种代理判定，可信度弱于硬回显、浏览器事件和 OOB 回连。
3. **SQLi 基线尚未充分利用。** 已采集基线，但当前适配器没有完整实现差分或统计验证。
4. **XSS 降级模式不能确认执行。** 没有 Chromium 时，httpx 只能看到服务器响应。
5. **OOB listener 是实验级实现。** 内存存储、无鉴权、无持久化、无自动过期。
6. **LLM 调用失败可能扩大为 check_error。** 即便已有应用响应，也可能因分析器异常被保守归类。
7. **人工复核没有完整回写知识统计。** 人工结果和自动学习链目前并非完全对称。
8. **执行目标目录包含高影响验证动作。** 只能在授权、隔离、可回滚的靶场中使用。

---

## 十一、完整结果理解示例

假设一个双层 URL 编码的 XSS 候选进入检验：

```text
候选入队
→ Worker 原子认领
→ 识别为 encoding + XSS
→ 反向解码两层，确认可恢复基础 Payload
→ httpx 请求未命中 WAF 拦截特征
→ Chromium 打开页面
→ 若捕获 dialog：bypass + confirmed
→ 若浏览器不可用或未捕获且没有其他验证器：bypass + unverified
→ 若响应是 WAF 拦截页：block + not_confirmed
→ 证据和技法统计写回数据库
```

这个例子体现了检验 Agent 的三层判断：

```text
表示层：编码链是否正确、可逆
网络层：WAF 是否放行
应用层：漏洞是否真正执行
```

只有把这三层分别记录，才能避免把“编码成功”“请求成功”和“漏洞成功”混为一谈。

---

## 十二、总结

检验 Agent 的本质是一套证据驱动的安全测试执行器。它用 SQLite 队列和线程 Worker 调度真实任务，用五类适配器连接不同靶场，用状态码、特征规则、浏览器事件、权威回显、文件二次访问和 OOB token 收集证据，再用固定真值表生成最终裁决。LLM 被限制在解释和路由建议层，不能覆盖硬证据。

编码绕过中确实包含“混淆效果”，但实现上强调的是确定性、可逆性、去重和语义保持。项目当前最需要谨慎理解的地方，是 encoding/cross 候选的“可逆 + 放行”会被升级为执行确认；在高可信报告中，最好将这种代理证据与真正的应用执行硬证据分开展示。
