"""泛化引擎：从已有技法 + 绕过率（+ 教材）泛化出新的绕过技法。

plan §2.2 的落地：
- 唯一生产者是 LLM。
- 燃料：KB 已有技法（含 bypass_count 绕过率）+ 教材文章（拓新）。
- 70% 挖深（同族泛化 / 组合 / 跨场景迁移）+ 30% 拓新（教材引入 + 结合现有）。
- 产出 frontier 候选技法，标 mechanism/family/为何新颖。

本模块只产出「技法候选」（technique_id + 元数据 + 模板），不直接生成 payload 变体。
"""

from __future__ import annotations

import re
from typing import Any

# 漏洞类型短名（LLM 可能输出）→ 规范化全名（kb_techniques.vulnerability 列使用的格式）。
_VULN_ALIASES: dict[str, str] = {
    "sqli": "sql-injection",
    "cmdi": "command-injection",
    "xss": "xss",
    "upload": "file-upload",
    "log4j": "log4j",
    "log4j2": "log4j",
    "sql": "sql-injection",
    "command": "command-injection",
}


def normalize_vulnerability(value: str) -> str | None:
    """把 LLM 输出的漏洞类型归一化为 kb_techniques.vulnerability 用的全名。

    接受 `sql-injection` 全名（原样返回）或 `sqli` 等短名（映射）；无法识别返回 None。
    """
    key = (value or "").strip().lower()
    if not key:
        return None
    if key in _VULN_ALIASES:
        return _VULN_ALIASES[key]
    # 全名集合（含官方格式）直接通过
    if key in {"sql-injection", "command-injection", "xss", "file-upload", "log4j"}:
        return key
    return None

# ---------------------------------------------------------------------------
# 提示词：挖深（exploit）与拓新（pioneer）两段分离。
# ---------------------------------------------------------------------------

EXPLOIT_SYSTEM_PROMPT = """你是 WAF 绕过知识库的**挖深**维护 Agent。你的任务：基于**已有的绕过技法**（及其绕过率）和**特征统计**（哪些片段是盲区/雷区），泛化出知识库里没有的**新变体技法**。

## 挖深 = 在已有机制/族内泛化新变体（三条路径）

1. **同族泛化**：拿一个已有技法，挖出同机制下的新写法。
   - 例：已有「注释拆分 UN/**/ION」→ 泛化出「注释拆分的另一种分隔符变体」。
2. **组合**：拿两个不同族的已验证技法，组合成一条链技法。
3. **跨场景迁移**：把场景 A 的技法原理迁移到场景 B（同族）。

## 特征统计的使用（方向倾向，非禁令）

- **盲区片段（高绕过率）**：优先在这些片段上搭新变体（WAF 拦不住 = 绕过本质）。
- **雷区片段（低绕过率）**：优先避开，但如果与其它技法组合后可能绕过，仍可尝试。

## 关键约束

1. **新颖性**：产出必须与输入已有技法**实质不同**——不是改名、换大小写、换同义词。
2. **归到已有机制/族**：从输入提供的 mechanism/family 清单里选（挖深不开新机制）。
3. **保持漏洞类型**：新技法的 vulnerability 必须与目标漏洞类型一致，且用以下全名之一：`sql-injection` / `command-injection` / `xss` / `file-upload` / `log4j`。
4. **纯绕过层**：只描述「怎么躲 WAF」，不含攻击原语。
5. **安全边界**：禁止 WebShell、反弹 Shell、持久化、提权、DoS。

## 输出格式

只输出严格 JSON：{"techniques": [{technique_id, name, vulnerability, mechanism_id, family_id, principle, template, novelty_reason}]}
- technique_id 格式 `<漏洞前缀>:generalized:<slug>`。
- mechanism_id/family_id 必须来自输入的已有清单。
- mechanism_id 和 family_id 都是**单段小写连字符 slug**（如 `parser-differential`、`token-split`），绝不填路径或 `父/子` 这种多段形式。
"""

PIONEER_SYSTEM_PROMPT = """你是 WAF 绕过知识库的**拓新**维护 Agent。你的任务：从**教材文章**和**你自己的前沿安全知识**打开知识库里没有的**新方向**，产出全新的绕过技法。

## 拓新 = 打开 KB 没有的新方向（不是复现已有的）

- **KB 已有技法只作参考，不是你的学习来源**——不要往已有技法上靠、不要复现/微调它们。
- 你的学习来源是：① 教材文章（原理文章 / 前沿 PoC）② 你自己的参数知识（CVE、绕过研究、新语法特性）。
- 产出应该是「知识库里没探索过的方向」——判据是**方向新颖**，不是「family 必须新」。

## 关键约束

1. **新颖性**：必须是 KB 里没探索过的新方向，不是已有技法的变体。
2. **mechanism_id 必须从输入的「已有机制清单」里选，禁止新建机制**；family_id 优先从「已有族清单」里选，确实归不进的才新建 family，此时在 novelty_reason 里说明失配原理。**不要为了「新」硬造碎片化 mechanism/family**——同一概念换不同英文写法（如 HPP 被写成 `hpp`/`hpp-precedence`/`http-parameter-pollution`）会被当成重复。
3. **保持漏洞类型**：vulnerability 用以下全名之一：`sql-injection` / `command-injection` / `xss` / `file-upload` / `log4j`。
4. **纯绕过层**：只描述「怎么躲 WAF」，不含攻击原语。
5. **安全边界**：禁止 WebShell、反弹 Shell、持久化、提权、DoS。

## 输出格式

只输出严格 JSON：{"techniques": [{technique_id, name, vulnerability, mechanism_id, family_id, principle, template, novelty_reason}]}
- technique_id 格式 `<漏洞前缀>:pioneer:<slug>`。
- mechanism_id 必须来自输入的「已有机制清单」（禁止新建）；family_id 优先复用「已有族清单」，确实归不进的才新建。
- **mechanism_id 和 family_id 都必须是单段小写连字符 slug**（如 `protocol`、`transport-encoding-obfuscation`），绝不填 `父/子` 这种路径式多段形式。
- novelty_reason 必须说明「这个方向为什么 KB 里没有探索过」。
"""


def _template_signature(template: str) -> str:
    """规范化模板 → 用于 L1 签名去重。

    去掉大小写、空白、标点，只留字母数字骨架。同骨架视为别名。
    """
    skel = re.sub(r"[^a-z0-9]+", "", (template or "").lower())
    return skel


# ---------------------------------------------------------------------------
# 生成侧预筛：三类确定性检查（编码层 / 协议层 / 明显死方法）。
# 只做「确定性的、会导致 payload 无效或不该进语义库」的轻量拦截，
# 不取代后续的验证闸门（WAF 真绕过才转正）。
# ---------------------------------------------------------------------------

# 编码层手法词：语义库只收「改表达方式」，不收「编码表示」。
_ENCODING_MARKERS = [
    "base64", "urlencode", "url encode", "url_encode", "percent-encod",
    "percent encod", "url 编码", "百分号编码", "double encod", "双重编码",
    "html entit", "html 实体", "实体编码", "utf-7", "utf-16", "utf8", "utf-8",
    "ebcdic", "cp037", "unicode escape", "unicode 转义", "hex encode",
    "十六进制编码", "octal encod", "八进制编码", "字符集编码",
]

# 协议/传输层：改请求结构不改 payload（语义库测不了）。
_PROTOCOL_MARKERS = [
    "content-type", "content type", "content-disposition", "multipart",
    "header smuggl", "request smuggl", "请求走私", "传输层", "协议层",
    "改请求", "chunked", "http request", "http header", "头部注入",
]

# 明显死方法：模板本身无效（空、纯占位符、描述句而非 payload 形态）。
_DEAD_TEMPLATE_MARKERS = [
    "xxx", "<payload>", "payload>", "attacker.com", "example.com",
    "占位", "此处", "替换为",
]


def prefilter_generated_technique(candidate: dict[str, Any]) -> tuple[bool, str]:
    """生成侧预筛：返回 (通过?, 拒绝原因)。

    - 编码层 / 协议层 → 拒绝（不该进语义库）
    - 模板明显无效 → 拒绝（死方法，payload 无效）
    - 其余通过（交给后续 L1 去重 + 验证闸门）
    """
    principle = (candidate.get("principle") or "").lower()
    name = (candidate.get("name") or "").lower()
    template = (candidate.get("template") or "").strip()
    text = f"{principle} {name}"

    # 1. 编码层
    for m in _ENCODING_MARKERS:
        if m in text:
            return False, f"编码层手法（命中「{m}」），语义库不收编码表示"

    # 2. 协议/传输层
    for m in _PROTOCOL_MARKERS:
        if m in text:
            return False, f"协议/传输层手法（命中「{m}」），改请求结构不改 payload"

    # 3. 明显死方法：模板空或纯占位
    if not template:
        return False, "模板为空（死方法）"
    stripped = template.strip(" `。\"'")
    if not stripped:
        return False, "模板为空壳（死方法）"
    lower_tpl = stripped.lower()
    for m in _DEAD_TEMPLATE_MARKERS:
        if m in lower_tpl:
            return False, f"模板是占位/描述句而非 payload（命中「{m}」）"

    return True, ""


def build_exploit_user_message(
    vulnerability: str,
    fuel_techniques: list[dict[str, Any]],
    features: dict[str, list[dict[str, Any]]],
) -> str:
    """挖深 user message：已有技法（含绕过率）+ 特征统计（盲区/雷区）。"""
    lines: list[str] = [f"目标漏洞类型：{vulnerability}", ""]

    lines.append(f"## 已有技法（挖深底座，{len(fuel_techniques)} 条，含绕过率）")
    for t in fuel_techniques:
        rate = ""
        attempt = t.get("attempt_count") or 0
        bypass = t.get("bypass_count") or 0
        if attempt > 0:
            rate = f"（绕过率 {bypass}/{attempt}）"
        lines.append(
            f"- {t['technique_id']} [{t.get('mechanism_id','')}/{t.get('family_id','')}] "
            f"{t.get('name','')}{rate}：{t.get('source_note','')[:160]}"
        )

    blindspots = features.get("blindspots", [])
    minefields = features.get("minefields", [])
    if blindspots or minefields:
        lines.append("")
        lines.append("## 特征统计（方向倾向，非禁令）")
        if blindspots:
            lines.append("盲区片段（高绕过率，优先复用）：")
            for f in blindspots:
                lines.append(f"  - {f['feature']}（{f['n_200']}/{f['n_200']+f['n_403']}）")
        if minefields:
            lines.append("雷区片段（低绕过率，优先规避，组合后仍可试）：")
            for f in minefields:
                lines.append(f"  - {f['feature']}（{f['n_200']}/{f['n_200']+f['n_403']}）")

    lines.append("")
    lines.append("请基于上述已有技法泛化出新的变体技法（挖深，不开新机制）。")
    return "\n".join(lines)


def build_pioneer_user_message(
    vulnerability: str,
    existing_techniques: list[dict[str, Any]],
    textbook: str,
) -> str:
    """拓新 user message：教材 + LLM 知识兜底，已有技法仅作参考。"""
    lines: list[str] = [f"目标漏洞类型：{vulnerability}", ""]

    if textbook.strip():
        lines.append("## 教材文章（拓新主料）")
        lines.append(textbook.strip()[:3000])
    else:
        lines.append("## 教材文章（拓新主料）")
        lines.append("（当前无教材，请用你自己的前沿安全知识——CVE、绕过研究、新语法特性——打开新方向）")

    # 从已有技法中提取「机制/族」去重清单，作为拓新的归并约束。
    # 拓新允许打开新方向，但方向应落到已有机制上，而非无限新建碎片机制。
    mechs: list[str] = []
    _seen_mech: set[str] = set()
    fams: list[str] = []
    _seen_fam: set[str] = set()
    for t in existing_techniques:
        m = str(t.get("mechanism_id") or "").strip()
        if m and m not in _seen_mech:
            _seen_mech.add(m)
            mechs.append(m)
        f = str(t.get("family_id") or "").strip()
        if f and f not in _seen_fam:
            _seen_fam.add(f)
            fams.append(f)

    lines.append("")
    lines.append(f"## 已有机制清单（{len(mechs)} 个，mechanism_id 只能从这里选，禁止新建）")
    for m in mechs:
        lines.append(f"- {m}")
    lines.append("")
    lines.append(f"## 已有族清单（{len(fams)} 个，family_id 优先从这里选）")
    for f in fams:
        lines.append(f"- {f}")

    lines.append("")
    lines.append(f"## 已有技法（仅作参考，不要往上靠，共 {len(existing_techniques)} 条）")
    for t in existing_techniques[:30]:
        lines.append(f"- {t['technique_id']} [{t.get('mechanism_id','')}/{t.get('family_id','')}] {t.get('name','')}")

    lines.append("")
    lines.append("请打开知识库里没有的新方向，产出全新技法。mechanism_id 必须来自上方「已有机制清单」；family_id 优先复用，确实归不进的才新建。")
    return "\n".join(lines)


def signature_for_candidate(candidate: dict[str, Any]) -> tuple[str, str, str]:
    """计算候选技法的 L1 签名 = (mechanism_id, family_id, 模板骨架)。

    用于与已有技法比对，撞车 = 别名，拒收。
    """
    mech = str(candidate.get("mechanism_id") or "").strip()
    family = str(candidate.get("family_id") or "").strip()
    template = str(candidate.get("template") or "").strip()
    return (mech, family, _template_signature(template))
