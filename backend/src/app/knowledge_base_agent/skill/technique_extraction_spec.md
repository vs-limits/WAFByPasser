# 技巧提取规范

从教材文章中提炼「纯绕过层」的 WAF 绕过技巧。本规范补充主提示词的提取约束，帮助稳定产出高质量、可被后端直接入库的技巧对象。

## 1. 提取边界

- **只提取绕过手法**，剥离攻击原语（如具体的注入点、目标 URL、测试靶场 IP）与具体攻击目标。
- 每条技巧必须「原子化」：一个技巧只描述一种绕过机制，不要把多种手法合并成一条。
- 若文章只讲漏洞原理、攻击后果，而没有可复用的绕过手法，返回空列表 `{"techniques": []}`。

## 2. 技法维度（dimension）

`dimension` 是 `technique_id` 的第二段，决定技巧归属于语义层还是编码层。选择与手法本质最贴切的一个：

**编码层**（改变表示/传输形式，不改语义）：`obfuscation`、`charset`、`encoding`、`mime`、`carrier`、`format`、`config`、`filename`、`content`、`protocol`、`ext`、`hash`、`lexical`。

**语义层**（改变表达方式/结构/控制流，不改编码）：`semantic`、`mutation`、`context`、`syntactic`、`parser`、`shell`、`oracle`、`dialect`、`token`、`ast`、`dom`、`csp`、`intent`、`alias`、`argv0`、`fd`、`history`、`indirect`、`redirect`、`lookup`、`mssql`、`win`、`type`、`param`、`xslt`、`server`、`misc`、`extension`。

典型示例：

- `sqli:lexical:case_flip`（大小写混用）→ 编码层（仅改变字母大小写表示）。
- `sqli:semantic:predicate_rewrite`（谓词改写）→ 语义层（改变表达式结构）。
- `xss:obfuscation:unicode`（Unicode 混淆）→ 编码层。

## 3. 稳定 ID

- `technique_id` 三段式：`<漏洞前缀>:<技法维度>:<名称slug>`。
- 名称 slug 用 `snake_case`，可读、稳定、不与已有 ID 重复。
- 同一手法在不同文章中出现时，应复用同一个 ID（由后端 `ON CONFLICT` 去重合并）。

## 4. 字段质量

- `name`：简短中文名，直指手法（如「大小写混用」「谓词改写」）。
- `principle`：一段话说明绕过机制，说明「为什么能绕过 WAF」。
- `template`：可复用的模板/示例 payload，多个用顿号或换行分隔；不写具体靶场 IP 或目标。

## 5. 输出纪律

- 只输出一个 JSON 对象：`{"techniques": [...]}`，不输出任何 Markdown 代码围栏或解释文字。
- 无法提取时输出 `{"techniques": []}`，不要编造。
