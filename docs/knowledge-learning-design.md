# 知识库自学习系统 —— 设计文档（定稿 v1）

> 基于 `indexed-meandering-octopus(3)` 的两大要求（学习自我扩充 / 量大穷举剪枝），
> 以 WAFByPasser 仓库为主体改造落地。本文档是定稿，实现前以它为准。

---

## 一、定位（先立边界，避免过度设计）

- **主力军**：约 300 条社区偏官方技法，`protected=1`，**永不淘汰**。这是知识库的支柱。
- **学习系统**：放大器，不是支柱。它在主力军之上**按需扩充**技法，删了无后果。
- **不做自治 driver**：学习不常驻后台空转。它挂在「一轮穷举验证跑完」之后，作为收尾衔接，**不单设触发按钮**。

---

## 二、穷举 + 剪枝模式（回归，解决「量大」）

### 2.1 原则

- 一条原语（403 后）把「剪枝后剩下的」技法**全部套一遍，命中 200 不停**。
- **剪枝前置**：穷举前先做 P1/P2/P3 三道语法兼容性剪枝，再对剩下的技法穷举。
- **铁律**：脚本只产出「穷举清单」（剪枝后剩哪些技法），**payload 变体仍由 LLM 现生成**，脚本绝不硬编码 payload。

### 2.2 剪枝清单（纯元数据过滤，判据是"死的"语法兼容性）

| # | 剪枝 | 依据 | 强度 |
|---|------|------|------|
| P1 | 场景剪枝 | sqli 原语只套 sqli 技法 | 一定剪 |
| P2 | 后端剪枝 | MySQL 原语砍 Oracle/MSSQL 专属技法；跨后端通用（case_flip/comment_split 等）不剪 | 一定剪 |
| P3 | 版本剪枝 | 硬版本门槛不满足（MySQL8+/PHP<5.3.4/仅IE） | 一定剪 |

### 2.3 穷举的两个天然副产品

- **硬特征判定**：剪枝后全部试完 0 个 200 → 该原语是硬特征，403 归档 `hard_fails` 不评分。
- **特征统计**：见 §六，只做倾向，不删除。

---

## 三、学习来源（70% 挖深 / 30% 拓新）

> **唯一的生产者是 LLM**。以下来源都是喂给 LLM 的「燃料」，不是另一个生成器。

| 占比 | 方向 | 燃料 | 产出 |
|------|------|------|------|
| 70% 挖深 | 同族泛化 / 组合 / 跨场景迁移 | KB 已有技法 + 样本数据（waf_features） | 有据可依的变体 |
| 30% 拓新 | 教材文章引入 + 结合现有 | 教材库文章 + KB 现有技法 | 全新机制方向的技法 |

- **同族泛化**：以已有技法为底座，同机制下挖新写法（如 `separator-change` → 挖出 `;$(IFS)` 等库里没有的具体写法）。
- **组合**：两个不同族的已验证技法组合成链技法（成分都验证过，最安全）。
- **跨场景迁移**：把 A 场景的原理迁移到 B 场景（cmdi 的 IFS → sqli 的非标准空白）。
- **教材拓新**：教材只当「打开新方向」的种子，提取的技法同样标 `frontier`、同样过验证闸门，**绝不直接当 KB 条目**。

---

## 四、状态机（进出都真跑）

```
seed(protected=1，永不删)
        ── 用户批量导入 ──
frontier(生成/教材提取，protected=0)
        ── 1 次真绕过(200+后端执行) ──▶ promoted(转正)
promoted
        ── 采样≥10 原语 且 0 绕过 且 protected=0 ──▶ retired(软删除，可回滚)
```

四个状态：`seed` / `frontier` / `promoted` / `retired`（软删除，非物理删除）。

| 动作 | 标准 | 说明 |
|------|------|------|
| **进** | 批量导入 → seed；泛化/教材 → frontier | origin 字段区分 community/generated/textbook |
| **转正** | `bypass_count >= 1` | 成功一条即有价值 → promoted |
| **淘汰** | `distinct_primitive_count >= 10` 且 `bypass_count == 0` 且 `protected == 0` | 只删非主力，删了无后果，可回滚 |

**关键**：转正/淘汰都按 `technique_id`（技法 ID）**精确关联**，不再用现在的「同漏洞同层全 +1」伪关联。candidate 的 `rule_labels` 必须记 KB 技法 ID（seed 阶段把 `part:*` 灌进 KB 统一命名空间）。

---

## 五、去重（只去「真别名」，不去「相似」）

- 哲学：`double_write` 和 `quote_split` 看似相似，但 WAF 反应可能不同——这正是要测的信息，不去重。
- **L1 签名去重（现在做）**：规范化签名 = `(机制, 族, 规范化模板)`，撞车 = 别名，直接拒收，**零 LLM 成本**。
- **L2 语义去重（先不做）**：等真观察到 KB 膨胀再加。

---

## 六、特征统计（waf_features）——方向倾向，不删除

- 穷举天然打全 200/403 分布，直接统计每个特征片段的 `pass_rate = n_200 / (n_200 + n_403)`。
- **喂给 LLM 的用法是「倾向」，不是「规避禁令」**：`%0a` 通过率 0.09 → 提示「历史上易拦，优先试别的；若要用，考虑组合」。**即使 0 绕过也不禁**，因为它可能跟别的技法组合后绕过。
- **特征统计永不触发删除**，与淘汰是两条独立线。
- 门槛：片段采样 ≥N 次（默认 3）且 pass_rate 明显偏离 0.5（阈值 0.2）才采信。

---

## 七、防污染主闸（不真绕过不进库）

- 生成器允许乱，但**只有「WAF 200 + 后端真实执行」的技法才转正进库**。
- 污染的本质 = 「没真绕过的技法混进库」，验证闸门从根上杜绝。
- **闸门只挡「进库/转正」，不挡「被尝试」**：未转正的 `frontier` 技法同样参与穷举尝试（穷举读所有活跃状态 seed+frontier+promoted，只排除 retired），只是不转正、不计入主力，直到 1 次真绕过才 promoted。
- 可度量判据（两条同时成立才算真学到）：
  1. KB 技法数增长（有新转正）
  2. 盲测绕过率提升（eval_bench，隔离于日常训练，最后补）

---

## 八、学习触发点（挂在穷举验证一轮之后）

```
一轮穷举验证跑完
    → 回写计数（每个技法 bypass/attempt/distinct_primitive）
    → 转正（bypass>=1 → promoted）
    → 淘汰（采样>=10 且 0 绕过 且 非 protected → retired）
    → 泛化（70% 挖深 + 30% 拓新 → 生成下轮 frontier）
下一轮穷举读「所有活跃技法」（seed + frontier + promoted，排除 retired）
```

不单设「学习」按钮，不常驻后台。人肉触发一轮穷举，学习收尾自动衔接。

---

## 九、数据模型增量（在现有 SQLite 上）

### 9.1 现有 `kb_techniques` 加列

```sql
ALTER TABLE kb_techniques ADD COLUMN origin TEXT DEFAULT 'generated';          -- community/generated/textbook
ALTER TABLE kb_techniques ADD COLUMN protected INTEGER DEFAULT 0;              -- 1=主力永不删
ALTER TABLE kb_techniques ADD COLUMN mechanism_id TEXT;                        -- 指向 mechanisms
ALTER TABLE kb_techniques ADD COLUMN family_id TEXT;                           -- 指向 families
ALTER TABLE kb_techniques ADD COLUMN backend TEXT DEFAULT 'generic';           -- mysql/oracle/mssql/pg/sqlite/generic
ALTER TABLE kb_techniques ADD COLUMN version_gate TEXT DEFAULT '';             -- 硬版本门槛
ALTER TABLE kb_techniques ADD COLUMN composable INTEGER DEFAULT 0;             -- 可组合
ALTER TABLE kb_techniques ADD COLUMN priority INTEGER DEFAULT 3;
ALTER TABLE kb_techniques ADD COLUMN bypass_count INTEGER DEFAULT 0;           -- 绕过成功次数
ALTER TABLE kb_techniques ADD COLUMN attempt_count INTEGER DEFAULT 0;          -- 总验证次数
ALTER TABLE kb_techniques ADD COLUMN distinct_primitive_count INTEGER DEFAULT 0; -- 套到的不同原语数
ALTER TABLE kb_techniques ADD COLUMN retired_at TEXT;                          -- 淘汰时间
```

> 现有 `status` 值 `pending/promoted/pruned` 需迁移到 `seed/frontier/promoted/retired`（实现阶段处理）。

### 9.2 新增表

```sql
CREATE TABLE mechanisms (id TEXT PRIMARY KEY, name TEXT, desc TEXT);   -- 8 行 seed

CREATE TABLE families (
  id TEXT PRIMARY KEY,
  mechanism_id TEXT REFERENCES mechanisms(id),
  desc TEXT
);                                                                    -- 15 行

CREATE TABLE technique_templates (                                    -- 技法的 payload 样例
  technique_id TEXT,
  payload TEXT,
  note TEXT
);

CREATE TABLE technique_conflicts (                                    -- 互斥图（只串链用，不进穷举剪枝）
  technique_id TEXT,
  conflict_id TEXT,
  PRIMARY KEY (technique_id, conflict_id)
);

CREATE TABLE waf_features (                                           -- 特征统计（倾向，不删除）
  feature TEXT PRIMARY KEY,
  first_seen TEXT,
  last_seen TEXT,
  n_403 INTEGER DEFAULT 0,
  n_200 INTEGER DEFAULT 0,
  pass_rate REAL DEFAULT 0
);

CREATE TABLE kb_technique_events (                                    -- 进出审计
  id TEXT PRIMARY KEY,
  technique_id TEXT NOT NULL,
  event TEXT NOT NULL,          -- import / generate / promote / retire / reactivate
  detail TEXT,
  created_at TEXT NOT NULL
);
```

---

## 十、组件改动（增量，不推翻现有）

| 组件 | 动作 |
|------|------|
| `directions.py` | 从「唯一真源」降级为「seed」，启动时灌进 `kb_techniques`（标 protected=1） |
| 语义迭代 | `available_directions` 改从 KB 读（过滤 retired），穷举模式：LLM 按清单逐个落实变体 |
| 新增泛化 agent | 70% 挖深 + 30% 拓新，产出 frontier（标 mechanism/family/为何新颖） |
| 验证闭环 | 转正改成按 technique_id 精确关联；回写 bypass/attempt/distinct_primitive 计数 |
| 剪枝 | 元数据过滤（场景/后端/版本），落 schema |
| 淘汰 | 每轮穷举收尾自动执行（软删除 + 事件） |
| `kb_techniques/import` | 保留（教材供料入口），教材只进 notes 不直接进 KB |

---

## 十一、分阶段实施

- **P1 框架化**：seed 8 机制 15 族 → `part:*` 归并进 KB（补 family/backend 元数据，标 protected=1）→ KB 成为生成方向真源。
- **P2 穷举 + 剪枝**：剪枝元数据落库 → 穷举模式（命中 200 不停）→ 硬特征判定 → waf_features 统计。
- **P3 学习闭环**：泛化 agent（70/30）→ frontier → 1 次 bypass 转正 → 淘汰（采样≥10 且 0 绕过）→ 先单场景跑通全闭环。
- **P4 摄入质量**：教材去重 / 真实性分级 / 「教材不进 KB」铁律 / 盲测集（eval_bench）。
