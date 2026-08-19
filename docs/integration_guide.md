# 生产级 Skill 集成指南

## 集成到现有系统

本文档指导如何将生产级 XSS 和 SQL 注入 Skill 集成到现有的语义迭代 Agent 中。

## 一、集成架构

### 当前架构

```
semantic_agent/
├── parts/
│   ├── parser.py          # Payload 解析器
│   └── composer.py        # 变异候选生成器
├── skill/
│   ├── xss_mutation.md    # 原版 XSS Skill
│   └── sql_injection_mutation.md  # 原版 SQLi Skill
└── prompt/
    └── semantic_mutation_agent.md  # Agent 提示
```

### 优化后架构

```
semantic_agent/
├── parts/
│   ├── parser.py          # Payload 解析器（已增强非标签型 XSS）
│   ├── composer.py        # 变异候选生成器（需集成评分系统）
│   └── waf_analyzer.py    # 🆕 WAF 指纹识别和分析模块
├── skill/
│   ├── xss_mutation_production.md         # 🆕 生产级 XSS Skill
│   ├── sql_injection_mutation_production.md  # 🆕 生产级 SQLi Skill
│   ├── waf_bypass_strategies.md           # 🆕 WAF 策略库
│   ├── xss_mutation.md                    # 原版（备用）
│   └── sql_injection_mutation.md          # 原版（备用）
└── prompt/
    └── semantic_mutation_agent.md  # Agent 提示（需更新）
```

## 二、分步集成指南

### 步骤 1：更新 Composer 引用生产级 Skill

**文件**：`backend/src/app/semantic_agent/parts/composer.py`

**修改**：

```python
# 原代码
XSS_SKILL_PATH = "backend/src/app/semantic_agent/skill/xss_mutation.md"
SQLI_SKILL_PATH = "backend/src/app/semantic_agent/skill/sql_injection_mutation.md"

# 修改为
XSS_SKILL_PATH = "backend/src/app/semantic_agent/skill/xss_mutation_production.md"
SQLI_SKILL_PATH = "backend/src/app/semantic_agent/skill/sql_injection_mutation_production.md"

# 添加降级备份
XSS_SKILL_FALLBACK = "backend/src/app/semantic_agent/skill/xss_mutation.md"
SQLI_SKILL_FALLBACK = "backend/src/app/semantic_agent/skill/sql_injection_mutation.md"
```

### 步骤 2：创建 WAF 分析模块

**文件**：`backend/src/app/semantic_agent/parts/waf_analyzer.py`

```python
"""
WAF 指纹识别和分析模块
"""
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class WAFFingerprint:
    """WAF 指纹信息"""
    waf_type: Optional[str] = None  # cloudflare, aws_waf, modsecurity, imperva, akamai, f5
    confidence: float = 0.0  # 0-1
    strength: str = "unknown"  # weak, medium, strong, extreme
    detection_rule_type: List[str] = None  # keyword_blacklist, regex, syntax_parser, semantic, ml
    blocked_keywords: List[str] = None
    blocked_patterns: List[str] = None

class WAFAnalyzer:
    """WAF 分析器"""
    
    # WAF 特征库
    WAF_SIGNATURES = {
        "cloudflare": {
            "headers": ["cf-ray", "cf-request-id"],
            "cookies": ["__cfduid", "__cflb"],
            "status_codes": [403, 1020, 1012],
            "page_patterns": ["Attention Required", "Cloudflare"],
        },
        "aws_waf": {
            "headers": ["x-amzn-requestid", "x-amzn-waf-action"],
            "status_codes": [403],
        },
        "modsecurity": {
            "headers": ["mod_security"],
            "status_codes": [406],
            "page_patterns": ["ModSecurity", "Not Acceptable"],
        },
        "imperva": {
            "cookies": ["incap_ses_", "visid_incap_"],
            "headers": ["x-cdn"],
            "page_patterns": ["Imperva", "Incapsula"],
        },
        "akamai": {
            "headers": ["akamai-x-cache", "akamai-grn", "AkamaiGHost"],
            "page_patterns": ["Access Denied", "Akamai"],
        },
        "f5": {
            "headers": ["X-Cnection", "BigIP"],
            "cookies": ["TS", "BIGipServer"],
            "page_patterns": ["F5", "BIG-IP"],
        },
    }
    
    def __init__(self):
        self.history = []  # 历史拦截记录
    
    def analyze_response(self, response: Dict) -> WAFFingerprint:
        """
        分析单次响应，识别 WAF 类型
        
        Args:
            response: {
                "status_code": 403,
                "headers": {"cf-ray": "xxx"},
                "cookies": {"__cfduid": "xxx"},
                "body": "...",
                "payload": "' UNION SELECT 1,2,3--",
            }
        
        Returns:
            WAFFingerprint
        """
        fingerprint = WAFFingerprint()
        
        # 被动指纹识别
        for waf_type, signatures in self.WAF_SIGNATURES.items():
            confidence = 0.0
            matches = 0
            total_checks = 0
            
            # 检查响应头
            if "headers" in signatures:
                total_checks += len(signatures["headers"])
                for header in signatures["headers"]:
                    if header.lower() in [h.lower() for h in response.get("headers", {}).keys()]:
                        matches += 1
            
            # 检查 Cookie
            if "cookies" in signatures:
                total_checks += len(signatures["cookies"])
                for cookie in signatures["cookies"]:
                    for c in response.get("cookies", {}).keys():
                        if cookie.lower() in c.lower():
                            matches += 1
                            break
            
            # 检查状态码
            if "status_codes" in signatures:
                total_checks += 1
                if response.get("status_code") in signatures["status_codes"]:
                    matches += 1
            
            # 检查页面内容
            if "page_patterns" in signatures:
                total_checks += len(signatures["page_patterns"])
                body = response.get("body", "")
                for pattern in signatures["page_patterns"]:
                    if pattern.lower() in body.lower():
                        matches += 1
            
            # 计算置信度
            if total_checks > 0:
                confidence = matches / total_checks
            
            # 更新最佳匹配
            if confidence > fingerprint.confidence:
                fingerprint.waf_type = waf_type
                fingerprint.confidence = confidence
        
        return fingerprint
    
    def analyze_history(self, history: List[Dict]) -> WAFFingerprint:
        """
        分析历史拦截记录，推断 WAF 规则类型
        
        Args:
            history: [
                {
                    "payload": "' UNION SELECT 1,2,3--",
                    "blocked": True,
                    "response": {...}
                },
                ...
            ]
        
        Returns:
            WAFFingerprint
        """
        self.history = history
        
        # 基础 WAF 类型识别（从最新的响应）
        if history:
            latest = history[-1]
            fingerprint = self.analyze_response(latest.get("response", {}))
        else:
            fingerprint = WAFFingerprint()
        
        # 推断检测规则类型
        detection_types = []
        blocked_keywords = set()
        
        for record in history:
            if not record.get("blocked"):
                continue
            
            payload = record.get("payload", "")
            
            # 检测关键字黑名单
            if self._detect_keyword_blacklist(history):
                detection_types.append("keyword_blacklist")
            
            # 检测正则表达式
            if self._detect_regex_matching(history):
                detection_types.append("regex")
            
            # 检测语法解析
            if self._detect_syntax_parser(history):
                detection_types.append("syntax_parser")
            
            # 检测语义分析
            if self._detect_semantic_analysis(history):
                detection_types.append("semantic")
        
        fingerprint.detection_rule_type = list(set(detection_types))
        
        # 推断 WAF 强度
        fingerprint.strength = self._infer_strength(fingerprint)
        
        return fingerprint
    
    def _detect_keyword_blacklist(self, history: List[Dict]) -> bool:
        """检测是否为关键字黑名单型 WAF"""
        # 如果替换关键字后绕过，说明是关键字黑名单
        for i in range(len(history) - 1):
            if history[i].get("blocked") and not history[i+1].get("blocked"):
                # 检查是否只是关键字替换
                payload1 = history[i].get("payload", "").lower()
                payload2 = history[i+1].get("payload", "").lower()
                
                # 简单检测：如果 UNION 变成 UnIoN 后绕过
                if "union" in payload1 and "union" not in payload2.lower():
                    return True
        
        return False
    
    def _detect_regex_matching(self, history: List[Dict]) -> bool:
        """检测是否为正则匹配型 WAF"""
        # 如果空格变化导致绕过/拦截，说明是正则匹配
        for i in range(len(history) - 1):
            payload1 = history[i].get("payload", "")
            payload2 = history[i+1].get("payload", "")
            
            # 检测是否为空白符变化
            if payload1.replace(" ", "") == payload2.replace("/**/", "").replace(" ", ""):
                if history[i].get("blocked") != history[i+1].get("blocked"):
                    return True
        
        return False
    
    def _detect_syntax_parser(self, history: List[Dict]) -> bool:
        """检测是否为语法解析型 WAF"""
        # 如果语法正确的变种被拦截，说明有语法解析
        # 这个需要更复杂的检测逻辑
        return False
    
    def _detect_semantic_analysis(self, history: List[Dict]) -> bool:
        """检测是否为语义分析型 WAF"""
        # 如果逻辑等价的 Payload 也被拦截，说明有语义分析
        return False
    
    def _infer_strength(self, fingerprint: WAFFingerprint) -> str:
        """推断 WAF 强度"""
        if not fingerprint.waf_type:
            return "unknown"
        
        # 基于 WAF 类型和检测规则类型推断
        if "ml" in fingerprint.detection_rule_type or "semantic" in fingerprint.detection_rule_type:
            return "extreme"
        elif "syntax_parser" in fingerprint.detection_rule_type:
            return "strong"
        elif "regex" in fingerprint.detection_rule_type:
            return "medium"
        else:
            return "weak"
    
    def get_recommended_techniques(self, fingerprint: WAFFingerprint, attack_type: str) -> List[str]:
        """
        根据 WAF 指纹推荐变异技术
        
        Args:
            fingerprint: WAF 指纹
            attack_type: "xss" 或 "sqli"
        
        Returns:
            推荐技术列表（按优先级排序）
        """
        recommendations = []
        
        # 基于 WAF 类型的推荐
        if fingerprint.waf_type == "cloudflare":
            if attack_type == "xss":
                recommendations = [
                    "冷门标签+事件组合",
                    "Unicode 混淆",
                    "HTML5 新特性",
                ]
            else:  # sqli
                recommendations = [
                    "注释插入+大小写混淆",
                    "运算符替换",
                    "换行符插入",
                ]
        
        elif fingerprint.waf_type == "modsecurity":
            if attack_type == "xss":
                recommendations = [
                    "标签嵌套",
                    "HTML 实体编码",
                    "自闭合标签",
                ]
            else:  # sqli
                recommendations = [
                    "子查询包装",
                    "函数嵌套",
                    "CASE 表达式",
                ]
        
        elif fingerprint.waf_type == "imperva":
            if attack_type == "xss":
                recommendations = [
                    "延迟触发",
                    "用户交互触发",
                    "DOM 动态构造",
                ]
            else:  # sqli
                recommendations = [
                    "笛卡尔积延时",
                    "条件包装",
                    "多阶段注入",
                ]
        
        # 基于 WAF 强度的补充推荐
        if fingerprint.strength in ["strong", "extreme"]:
            if attack_type == "xss":
                recommendations.extend([
                    "浏览器特性深度利用",
                    "多维度组合变异",
                ])
            else:  # sqli
                recommendations.extend([
                    "数据库特性利用",
                    "HTTP 层面绕过",
                ])
        
        return recommendations
```

### 步骤 3：更新 Composer 集成评分系统

**文件**：`backend/src/app/semantic_agent/parts/composer.py`

在现有代码中添加：

```python
from typing import Dict, List
from .waf_analyzer import WAFAnalyzer, WAFFingerprint

class MutationComposer:
    """变异候选生成器"""
    
    def __init__(self):
        self.waf_analyzer = WAFAnalyzer()
    
    def calculate_mutation_score(
        self,
        candidate: Dict,
        waf_fingerprint: WAFFingerprint,
        attack_type: str
    ) -> float:
        """
        计算变异强度评分
        
        Args:
            candidate: 候选 Payload 信息
            waf_fingerprint: WAF 指纹
            attack_type: "xss" 或 "sqli"
        
        Returns:
            评分（0-100）
        """
        # 语义距离分（0-30）
        semantic_distance = self._calculate_semantic_distance(candidate)
        
        # WAF 规避分（0-40）
        waf_evasion = self._calculate_waf_evasion(candidate, waf_fingerprint)
        
        # 隐蔽性分（0-20）- XSS 使用
        # 攻击效果分（0-25）- SQLi 使用
        if attack_type == "xss":
            stealth = self._calculate_stealth(candidate)
            stability = self._calculate_stability(candidate)
            total = semantic_distance + waf_evasion + stealth + stability * 0.5
        else:  # sqli
            attack_effect = self._calculate_attack_effect(candidate)
            stability = self._calculate_stability(candidate)
            total = semantic_distance + waf_evasion + attack_effect + stability
        
        return total
    
    def _calculate_semantic_distance(self, candidate: Dict) -> float:
        """计算语义距离分（0-30）"""
        level = candidate.get("mutation_level", 1)
        
        level_scores = {
            1: 5,   # L1: 同义替换
            2: 10,  # L2: 结构重组
            3: 15,  # L3: 编码混淆
            4: 20,  # L4: 间接引用/子查询
            5: 25,  # L5: 逻辑等价/浏览器特性
            6: 30,  # L6: 数据库特性
        }
        
        return level_scores.get(level, 5)
    
    def _calculate_waf_evasion(
        self,
        candidate: Dict,
        waf_fingerprint: WAFFingerprint
    ) -> float:
        """计算 WAF 规避分（0-40）"""
        score = 0
        
        # 基础分：通用技术
        score += 10
        
        # 如果使用了针对该 WAF 的专项技术，额外加分
        techniques = candidate.get("techniques", [])
        recommended = self.waf_analyzer.get_recommended_techniques(
            waf_fingerprint,
            candidate.get("attack_type", "xss")
        )
        
        for tech in techniques:
            if tech in recommended:
                score += 10  # 每个推荐技术 +10 分
        
        # 如果是组合技术（多层次），额外加分
        if len(techniques) >= 2:
            score += 5
        if len(techniques) >= 3:
            score += 5
        
        # 限制最高 40 分
        return min(score, 40)
    
    def _calculate_stealth(self, candidate: Dict) -> float:
        """计算隐蔽性分（0-20）- XSS"""
        # 基于技术冷门程度
        techniques = candidate.get("techniques", [])
        
        cold_techniques = [
            "DOM Clobbering",
            "Mutation XSS",
            "原型链污染",
            "Service Worker",
        ]
        
        score = 10  # 基础分
        
        for tech in techniques:
            if tech in cold_techniques:
                score += 5
        
        return min(score, 20)
    
    def _calculate_attack_effect(self, candidate: Dict) -> float:
        """计算攻击效果分（0-25）- SQLi"""
        score = 5  # 保持攻击类别基础分
        
        # 保持查询逻辑 +10
        if candidate.get("preserves_logic", True):
            score += 10
        
        # 数据完整性 +5
        if candidate.get("data_integrity", True):
            score += 5
        
        # 执行成功率预估 +5
        if candidate.get("estimated_success", 0.8) >= 0.8:
            score += 5
        
        return score
    
    def _calculate_stability(self, candidate: Dict) -> float:
        """计算稳定性分（0-10）"""
        browser_compat = candidate.get("browser_compatibility", [])
        db_compat = candidate.get("database_compatibility", [])
        
        # XSS: 浏览器兼容性
        if browser_compat:
            if len(browser_compat) >= 3:  # Chrome, Firefox, Safari
                return 10
            elif len(browser_compat) >= 2:
                return 7
            else:
                return 5
        
        # SQLi: 数据库兼容性
        if db_compat:
            if len(db_compat) >= 3:
                return 10
            elif len(db_compat) >= 2:
                return 7
            else:
                return 5
        
        return 5  # 默认分
    
    def calculate_similarity(self, candidate1: Dict, candidate2: Dict) -> float:
        """
        计算两个候选的相似度（0-1）
        
        使用编辑距离计算
        """
        payload1 = candidate1.get("payload", "")
        payload2 = candidate2.get("payload", "")
        
        # 简单的编辑距离
        distance = self._edit_distance(payload1, payload2)
        max_len = max(len(payload1), len(payload2))
        
        if max_len == 0:
            return 0
        
        similarity = 1 - (distance / max_len)
        return similarity
    
    def _edit_distance(self, s1: str, s2: str) -> int:
        """计算编辑距离"""
        m, n = len(s1), len(s2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        
        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j
        
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if s1[i-1] == s2[j-1]:
                    dp[i][j] = dp[i-1][j-1]
                else:
                    dp[i][j] = min(
                        dp[i-1][j] + 1,    # 删除
                        dp[i][j-1] + 1,    # 插入
                        dp[i-1][j-1] + 1   # 替换
                    )
        
        return dp[m][n]
    
    def deduplicate_candidates(
        self,
        candidates: List[Dict],
        similarity_threshold: float = 0.70
    ) -> List[Dict]:
        """
        候选去重
        
        Args:
            candidates: 候选列表
            similarity_threshold: 相似度阈值（XSS: 0.70, SQLi: 0.65）
        
        Returns:
            去重后的候选列表
        """
        unique_candidates = []
        
        for candidate in candidates:
            is_unique = True
            
            for existing in unique_candidates:
                similarity = self.calculate_similarity(candidate, existing)
                
                if similarity >= similarity_threshold:
                    is_unique = False
                    break
            
            if is_unique:
                unique_candidates.append(candidate)
        
        return unique_candidates
    
    def ensure_diversity(
        self,
        candidates: List[Dict],
        min_per_level: Dict[int, int] = None
    ) -> bool:
        """
        确保候选的多样性
        
        Args:
            candidates: 候选列表
            min_per_level: 每个层次的最小数量，例如 {2: 1, 3: 1, 4: 1}
        
        Returns:
            是否满足多样性要求
        """
        if min_per_level is None:
            # 默认要求：至少 1个L2 + 1个L3 + 1个L4
            min_per_level = {2: 1, 3: 1, 4: 1}
        
        level_counts = {}
        
        for candidate in candidates:
            level = candidate.get("mutation_level", 1)
            level_counts[level] = level_counts.get(level, 0) + 1
        
        for level, min_count in min_per_level.items():
            if level_counts.get(level, 0) < min_count:
                return False
        
        return True
```

### 步骤 4：更新 Agent 提示

**文件**：`backend/src/app/semantic_agent/prompt/semantic_mutation_agent.md`

在提示中添加：

```markdown
## WAF 上下文信息

你会收到 `waf_context` 参数，包含 WAF 分析结果：

```json
{
  "waf_type": "cloudflare",  // WAF 类型
  "confidence": 0.85,         // 识别置信度
  "strength": "medium",       // WAF 强度
  "detection_rule_type": ["keyword_blacklist", "regex"],  // 检测规则类型
  "recommended_techniques": [  // 推荐技术
    "冷门标签+事件组合",
    "Unicode 混淆"
  ]
}
```

## 变异策略选择

1. **根据 WAF 类型选择专项技术**：
   - 如果 `waf_type` 已识别，优先使用对应 WAF 的专项绕过策略
   - 查阅 Skill 文档中"第三步：针对主流 WAF 的专用绕过技术"章节

2. **根据 WAF 强度选择技术层次**：
   - weak → L1-L2
   - medium → L2-L3
   - strong → L3-L4
   - extreme → L4-L5 (XSS) 或 L4-L5-L6 (SQLi)

3. **使用推荐技术**：
   - `recommended_techniques` 中的技术成功率最高
   - 优先应用这些技术

## 质量保证

生成候选时确保：

1. **评分系统**：每个候选会自动计算变异强度分（0-100）
2. **去重机制**：相似度 < 70% (XSS) 或 < 65% (SQLi)
3. **多样性保证**：至少 1个L2 + 1个L3 + 1个L4
```

## 三、测试验证

### 测试用例 1：CloudFlare XSS

```python
# 测试 WAF 识别
response = {
    "status_code": 403,
    "headers": {"cf-ray": "123456"},
    "body": "Attention Required",
}

analyzer = WAFAnalyzer()
fingerprint = analyzer.analyze_response(response)

assert fingerprint.waf_type == "cloudflare"
assert fingerprint.confidence > 0.5
```

### 测试用例 2：评分系统

```python
# 测试评分计算
candidate = {
    "payload": "<details open ontoggle=alert(1)>",
    "mutation_level": 2,
    "techniques": ["冷门标签+事件组合"],
    "attack_type": "xss",
}

composer = MutationComposer()
score = composer.calculate_mutation_score(candidate, fingerprint, "xss")

assert score >= 60  # 应该是高分候选
```

### 测试用例 3：去重机制

```python
# 测试候选去重
candidates = [
    {"payload": "<details open ontoggle=alert(1)>"},
    {"payload": "<details open ontoggle=prompt(1)>"},  # 相似度高
    {"payload": "<marquee onstart=alert(1)>"},  # 相似度低
]

unique = composer.deduplicate_candidates(candidates, 0.70)

assert len(unique) == 2  # 第二个应该被去重
```

## 四、性能优化建议

### 4.1 缓存 Skill 文档

```python
import functools

@functools.lru_cache(maxsize=10)
def load_skill_document(skill_path: str) -> str:
    """缓存 Skill 文档内容"""
    with open(skill_path, 'r', encoding='utf-8') as f:
        return f.read()
```

### 4.2 并行计算评分

```python
from concurrent.futures import ThreadPoolExecutor

def score_candidates_parallel(candidates: List[Dict], waf_fingerprint: WAFFingerprint) -> List[float]:
    """并行计算多个候选的评分"""
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(composer.calculate_mutation_score, c, waf_fingerprint, "xss")
            for c in candidates
        ]
        scores = [f.result() for f in futures]
    
    return scores
```

### 4.3 减少候选数量

```python
# 如果性能是瓶颈，可以减少候选数量
MAX_CANDIDATES = 7  # 从 10 降到 7

# 或者只保留高分候选
candidates = sorted(candidates, key=lambda c: c['score'], reverse=True)[:MAX_CANDIDATES]
```

## 五、监控和日志

### 5.1 添加性能监控

```python
import time
import logging

logger = logging.getLogger(__name__)

def compose_mutations_with_monitoring(base_payload: str) -> List[Dict]:
    """带监控的变异生成"""
    start_time = time.time()
    
    # WAF 分析
    waf_start = time.time()
    waf_fingerprint = waf_analyzer.analyze_history(history)
    waf_time = time.time() - waf_start
    logger.info(f"WAF analysis took {waf_time:.2f}s")
    
    # 候选生成
    gen_start = time.time()
    candidates = generate_candidates(base_payload, waf_fingerprint)
    gen_time = time.time() - gen_start
    logger.info(f"Candidate generation took {gen_time:.2f}s, generated {len(candidates)} candidates")
    
    # 评分
    score_start = time.time()
    for candidate in candidates:
        candidate['score'] = composer.calculate_mutation_score(candidate, waf_fingerprint, "xss")
    score_time = time.time() - score_start
    logger.info(f"Scoring took {score_time:.2f}s")
    
    # 去重
    dedup_start = time.time()
    unique_candidates = composer.deduplicate_candidates(candidates)
    dedup_time = time.time() - dedup_start
    logger.info(f"Deduplication took {dedup_time:.2f}s, {len(candidates)} -> {len(unique_candidates)}")
    
    total_time = time.time() - start_time
    logger.info(f"Total composition took {total_time:.2f}s")
    
    return unique_candidates
```

### 5.2 添加成功率统计

```python
class SuccessRateTracker:
    """成功率跟踪器"""
    
    def __init__(self):
        self.stats = {}  # {waf_type: {technique: {success: N, total: N}}}
    
    def record_attempt(self, waf_type: str, technique: str, success: bool):
        """记录一次尝试"""
        if waf_type not in self.stats:
            self.stats[waf_type] = {}
        
        if technique not in self.stats[waf_type]:
            self.stats[waf_type][technique] = {"success": 0, "total": 0}
        
        self.stats[waf_type][technique]["total"] += 1
        if success:
            self.stats[waf_type][technique]["success"] += 1
    
    def get_success_rate(self, waf_type: str, technique: str) -> float:
        """获取成功率"""
        if waf_type not in self.stats or technique not in self.stats[waf_type]:
            return 0.0
        
        data = self.stats[waf_type][technique]
        if data["total"] == 0:
            return 0.0
        
        return data["success"] / data["total"]
    
    def export_stats(self, filepath: str):
        """导出统计数据"""
        import json
        with open(filepath, 'w') as f:
            json.dump(self.stats, f, indent=2)
```

## 六、回滚计划

如果新版本出现问题，快速回滚步骤：

1. **恢复 Skill 引用**：
   ```python
   # 在 composer.py 中
   XSS_SKILL_PATH = "backend/src/app/semantic_agent/skill/xss_mutation.md"
   SQLI_SKILL_PATH = "backend/src/app/semantic_agent/skill/sql_injection_mutation.md"
   ```

2. **禁用新功能**：
   ```python
   # 添加功能开关
   USE_PRODUCTION_SKILL = False
   USE_WAF_ANALYZER = False
   USE_SCORING_SYSTEM = False
   ```

3. **降级日志**：
   ```python
   if USE_PRODUCTION_SKILL:
       skill_path = XSS_SKILL_PATH
   else:
       skill_path = XSS_SKILL_FALLBACK
       logger.warning("Using fallback skill due to feature flag")
   ```

## 七、下一步计划

### 短期（1-2周）

- [ ] 完成 `waf_analyzer.py` 的完整实现
- [ ] 集成评分系统到 Composer
- [ ] 更新 Agent 提示文档
- [ ] 编写单元测试和集成测试
- [ ] 在本地 WAF 环境测试验证

### 中期（1-2月）

- [ ] 收集真实测试数据，更新成功率统计
- [ ] 优化 WAF 指纹识别准确率
- [ ] 实现自适应变异（根据历史成功/失败调整策略）
- [ ] 添加更多 WAF 支持（Cloudflare Enterprise, Fortinet 等）
- [ ] 性能优化和并行处理

### 长期（3-6月）

- [ ] 机器学习模型：预测最佳变异策略
- [ ] 对抗性训练：持续适应 WAF 更新
- [ ] 社区 Payload 库集成
- [ ] 可视化分析仪表板

---

**文档版本**：v1.0  
**创建时间**：2026-08-18  
**维护者**：WAFByPasser Team
