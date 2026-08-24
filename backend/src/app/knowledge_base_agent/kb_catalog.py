"""知识库分类法 catalog：8 机制 × 16 族（15 绕过族 + 1 组合元族）。

职责：
- 定义机制/族的稳定 ID 与中文名（plan §4.2 八大失配机制）。
- 维护 part:* 方向 → 机制/族 的映射（P1 归并的产物）。
- 提供幂等的 seed 函数：把机制/族 + 内置 part:* 方向灌进 kb_techniques。

注意：part:* 方向是框架内置基础设施，seed 时标 origin='system'、protected=1
（永不淘汰）。用户社区技法（origin='community'）与学习生成技法
（origin='generated'，protected=0）由其它入口写入。
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# 八大失配机制（分类根）
# ---------------------------------------------------------------------------

MECHANISMS: list[dict[str, str]] = [
    {"id": "token-split", "name": "拆分重组", "desc": "WAF 匹配连续串，拆开失配；后端重组"},
    {"id": "equivalent-substitution", "name": "等价替换", "desc": "WAF 盯字面量，换等价物"},
    {"id": "parser-differential", "name": "解析器差异", "desc": "WAF 与后端解析不同"},
    {"id": "context-escape", "name": "上下文逃逸", "desc": "受限上下文逃到可执行处"},
    {"id": "indirect-execution", "name": "间接执行", "desc": "无字面命令/函数，运行时构造"},
    {"id": "noise-dilution", "name": "稀释噪声", "desc": "特征被无害内容稀释"},
    {"id": "config-injection", "name": "结构/配置注入", "desc": "改「如何被解析」而非攻击代码"},
    {"id": "lookup-composition", "name": "Lookup 组合", "desc": "Log4j ${} 求值拼关键字"},
]

# ---------------------------------------------------------------------------
# 族（跨场景迁移载体）。15 个绕过族 + 1 个组合元族。
# ---------------------------------------------------------------------------

FAMILIES: list[dict[str, str]] = [
    # ① 拆分重组
    {"id": "token-split", "mechanism_id": "token-split", "desc": "关键字/字符串拆分后重组"},
    # ② 等价替换（4 族）
    {"id": "whitespace-sub", "mechanism_id": "equivalent-substitution", "desc": "空白结构等价替换"},
    {"id": "operator-swap", "mechanism_id": "equivalent-substitution", "desc": "运算符/分隔符等价替换"},
    {"id": "function-swap", "mechanism_id": "equivalent-substitution", "desc": "函数/命令等价替换"},
    {"id": "case-mutation", "mechanism_id": "equivalent-substitution", "desc": "大小写混写"},
    # ③ 解析器差异（3 族）
    {"id": "parser-differential", "mechanism_id": "parser-differential", "desc": "解析结构差异"},
    {"id": "namespace-confusion", "mechanism_id": "parser-differential", "desc": "命名空间混淆"},
    {"id": "comment-injection", "mechanism_id": "parser-differential", "desc": "注释注入扰乱词法"},
    # ④ 上下文逃逸（2 族）
    {"id": "context-escape", "mechanism_id": "context-escape", "desc": "标签/属性上下文逃逸"},
    {"id": "protocol-scheme", "mechanism_id": "context-escape", "desc": "协议/结构逃逸"},
    # ⑤ 间接执行
    {"id": "indirect-exec", "mechanism_id": "indirect-execution", "desc": "运行时构造执行"},
    # ⑥ 稀释噪声
    {"id": "noise-dilution", "mechanism_id": "noise-dilution", "desc": "无害内容稀释特征"},
    # ⑦ 结构/配置注入（2 族）
    {"id": "config-injection", "mechanism_id": "config-injection", "desc": "配置/结构注入"},
    {"id": "filename-ext", "mechanism_id": "config-injection", "desc": "文件名/扩展名注入"},
    # ⑧ Lookup 组合
    {"id": "lookup-composition", "mechanism_id": "lookup-composition", "desc": "${} 求值组合"},
    # 组合元族（非失配机制，跨机制组合指令）
    {"id": "composite", "mechanism_id": "", "desc": "跨机制组合（元技法）"},
]

# ---------------------------------------------------------------------------
# part:* 方向 → (机制, 族) 映射。
#
# 这是 P1 归并的核心：把 directions.py 里 64 条内置方向归进「8 机制 × 16 族」。
# 组合类方向（combine-*）归 composite 元族。
# ---------------------------------------------------------------------------

# 族名 → 机制名（等价替换内部用族名区分，机制统一为 equivalent-substitution）
_E = "equivalent-substitution"  # 等价替换
_P = "parser-differential"      # 解析器差异
_C = "context-escape"           # 上下文逃逸
_I = "indirect-execution"       # 间接执行
_N = "noise-dilution"           # 稀释噪声
_T = "token-split"              # 拆分重组
_M = ""                          # composite 元族（无机制）

DIRECTION_MAP: dict[str, tuple[str, str]] = {
    # ── 命令注入 ──
    "part:command-equivalent": (_E, "function-swap"),
    "part:separator-change": (_E, "operator-swap"),
    "part:argument-change": (_E, "function-swap"),
    "part:argument-add": (_N, "noise-dilution"),
    "part:control-add": (_E, "operator-swap"),
    "part:control-remove": (_E, "operator-swap"),
    "part:path-change": (_E, "function-swap"),
    "part:ifs-change": (_E, "whitespace-sub"),
    "part:stderr-add": (_N, "noise-dilution"),
    "part:stderr-remove": (_N, "noise-dilution"),
    "part:var-indirect": (_I, "indirect-exec"),
    "part:brace-expand": (_E, "function-swap"),
    "part:wildcard": (_E, "function-swap"),
    "part:loop-add": (_I, "indirect-exec"),
    "part:loop-remove": (_I, "indirect-exec"),
    "part:subshell-add": (_I, "indirect-exec"),
    "part:subshell-remove": (_I, "indirect-exec"),
    "part:herestring-add": (_E, "operator-swap"),
    "part:herestring-remove": (_E, "operator-swap"),
    "part:combine-two": (_M, "composite"),
    "part:combine-three": (_M, "composite"),
    "part:bash-ism": (_P, "parser-differential"),
    # ── SQL 注入 ──
    "part:predicate-rewrite": (_E, "function-swap"),
    "part:predicate-bitwise": (_E, "operator-swap"),
    "part:predicate-regex": (_E, "function-swap"),
    "part:predicate-cmp-func": (_E, "function-swap"),
    "part:operator-switch": (_E, "operator-swap"),
    "part:comment-change": (_P, "comment-injection"),
    "part:comment-inline": (_P, "comment-injection"),
    "part:ws-change": (_E, "whitespace-sub"),
    "part:paren-restructure": (_P, "parser-differential"),
    "part:subquery-add": (_E, "function-swap"),
    "part:subquery-remove": (_E, "function-swap"),
    "part:value-hex": (_E, "function-swap"),
    "part:value-char": (_E, "function-swap"),
    "part:value-scientific": (_E, "function-swap"),
    "part:value-cast": (_E, "function-swap"),
    "part:union-rewrite": (_T, "token-split"),
    "part:union-columns": (_E, "function-swap"),
    "part:fn-time-swap": (_E, "function-swap"),
    "part:fn-error-swap": (_E, "function-swap"),
    "part:fn-info-swap": (_E, "function-swap"),
    "part:fn-version-wrap": (_P, "comment-injection"),
    "part:case-mix": (_E, "case-mutation"),
    "part:keyword-comment": (_T, "token-split"),
    "part:stacked-swap": (_E, "function-swap"),
    "part:clause-restructure": (_P, "parser-differential"),
    "part:sql-combine": (_M, "composite"),
    # ── XSS ──
    "part:tag-switch": (_C, "context-escape"),
    "part:event-switch": (_C, "context-escape"),
    "part:expression-rewrite": (_E, "function-swap"),
    "part:expression-data-exfil": (_I, "indirect-exec"),
    "part:closure-change": (_C, "context-escape"),
    "part:spacing-change": (_E, "whitespace-sub"),
    "part:namespace-switch": (_P, "namespace-confusion"),
    "part:nested-tags": (_C, "context-escape"),
    "part:media-events": (_C, "context-escape"),
    "part:cookie-theft": (_I, "indirect-exec"),
    "part:storage-theft": (_I, "indirect-exec"),
    "part:keylogger": (_I, "indirect-exec"),
    "part:dom-manipulation": (_I, "indirect-exec"),
    "part:phishing-injection": (_I, "indirect-exec"),
    "part:xss-combine": (_M, "composite"),
    "part:attr-boundary": (_C, "context-escape"),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def seed_kb_catalog(connection: Any) -> dict[str, int]:
    """幂等灌入机制/族 + 内置 part:* 方向（标 origin='system' protected=1）。

    在 initialize_database 的 DB_LOCK 上下文中调用。返回计数摘要。
    """
    # 1. 机制 / 族（INSERT OR IGNORE 幂等）
    for m in MECHANISMS:
        connection.execute(
            "INSERT OR IGNORE INTO mechanisms (id, name, desc) VALUES (?, ?, ?)",
            (m["id"], m["name"], m["desc"]),
        )
    for f in FAMILIES:
        connection.execute(
            "INSERT OR IGNORE INTO families (id, mechanism_id, desc) VALUES (?, ?, ?)",
            (f["id"], f["mechanism_id"], f["desc"]),
        )

    # 2. 内置 part:* 方向 → kb_techniques（受保护 seed）
    from app.semantic_agent.parts.directions import DIRECTIONS_BY_VULN  # local import

    timestamp = utc_now()
    seeded = 0
    for vulnerability, directions in DIRECTIONS_BY_VULN.items():
        for d in directions:
            direction_id = d["id"]
            mechanism_id, family_id = DIRECTION_MAP.get(direction_id, (_M, "composite"))
            connection.execute(
                """
                INSERT INTO kb_techniques (
                    id, technique_id, name, vulnerability, status, success_count,
                    labels_json, source_note, created_at, updated_at,
                    origin, protected, mechanism_id, family_id, backend,
                    version_gate, composable, priority
                ) VALUES (?, ?, ?, ?, 'seed', 0, '[]', ?, ?, ?, 'system', 1, ?, ?, 'generic', '', 0, 3)
                ON CONFLICT(technique_id) DO UPDATE SET
                    name = excluded.name,
                    vulnerability = excluded.vulnerability,
                    source_note = excluded.source_note,
                    origin = 'system',
                    protected = 1,
                    mechanism_id = excluded.mechanism_id,
                    family_id = excluded.family_id,
                    backend = excluded.backend,
                    updated_at = excluded.updated_at
                """,
                (
                    str(uuid.uuid4()),
                    direction_id,
                    d["label"],
                    vulnerability,
                    d.get("reason", ""),
                    timestamp,
                    timestamp,
                    mechanism_id,
                    family_id,
                ),
            )
            seeded += 1

    return {
        "mechanisms": len(MECHANISMS),
        "families": len(FAMILIES),
        "seed_techniques": seeded,
    }


# ---------------------------------------------------------------------------
# 社区主力技法（bypass_techniques(1).md，327 条 → 导入 315 条）
#
# 分类审核结论：
# - 12 条筛除（非绕过/编码层/传输层），见 COMMUNITY_SKIP。
# - 其余 315 条归入「8 机制 × 16 族」。
# - dimension（ID 第二段）给出默认机制/族，同 dimension 内跨机制的用
#   TECHNIQUE_OVERRIDE 逐条覆盖（主力军，逐条审过）。
# ---------------------------------------------------------------------------

# 12 条筛除清单：非绕过（信息泄露6/防御判定1/DoS1/方法论1）+ 编码层2 + 传输层1
COMMUNITY_SKIP: set[str] = {
    # 信息泄露 / 指纹探测（非「绕过 WAF」，是「读敏感数据」）
    "log4j2:lookup:info_disclosure",
    "log4j2:lookup:env_cloud_keys",
    "log4j2:lookup:docker_k8s_special",
    "log4j2:lookup:log4j_hostname_java",
    "log4j2:lookup:main_args_exfil",
    "log4j2:lookup:spring_extra",
    # 作者自标「非绕过」
    "log4j2:format:nolookups_option",   # 原文：作为防御面判定而非新绕过
    "log4j2:format:recursive_dos",      # 递归堆栈溢出 DoS
    # 方法论（非技法）
    "xss:semantic:detection_rotation",  # 原文：成功样本迭代的判定基础
    # 编码层（属于「编码线」，不在语义 8 机制内）
    "log4j2:misc:json_unicode_dollar",  # JSON 转义藏 ${}
    "xss:decode:decode_depth_mismatch", # 解码次数差异
    # 传输层（改 Content-Type 头，payload 一字不改）
    "sqli:protocol:dual_content_type_multipart_smuggle",
}

# dimension（ID 第二段）→ (机制, 族) 默认映射
DIMENSION_DEFAULT: dict[str, tuple[str, str]] = {
    # ── 间接执行（运行时构造 / 借壳 / 隐式执行点 / JS 运行时拼接）──
    "carrier": (_I, "indirect-exec"),
    "shell": (_I, "indirect-exec"),
    "alias": (_I, "indirect-exec"),
    "argv0": (_I, "indirect-exec"),
    "fd": (_I, "indirect-exec"),
    "hash": (_I, "indirect-exec"),
    "history": (_I, "indirect-exec"),
    "indirect": (_I, "indirect-exec"),
    "param": (_I, "indirect-exec"),
    "redirect": (_I, "indirect-exec"),
    "win": (_I, "indirect-exec"),
    "dom": (_I, "indirect-exec"),
    "obfuscation": (_I, "indirect-exec"),
    # ── 解析器差异（方言 / 类型折叠 / token 化 / mXSS 重解析）──
    "parser": (_P, "parser-differential"),
    "ast": (_P, "parser-differential"),
    "dialect": (_P, "parser-differential"),
    "type": (_P, "parser-differential"),
    "token": (_P, "parser-differential"),
    "charset": (_P, "parser-differential"),
    "server": (_P, "parser-differential"),
    "mutation": (_P, "parser-differential"),
    # ── 等价替换（默认 function-swap，方言专属函数替换）──
    "mssql": (_E, "function-swap"),
    "oracle": (_E, "function-swap"),
    "intent": (_E, "function-swap"),
    # ── 上下文逃逸 ──
    "context": (_C, "context-escape"),
    "csp": (_C, "context-escape"),
    # ── 结构/配置注入 ──
    "config": ("config-injection", "config-injection"),
    "ssi": ("config-injection", "config-injection"),
    "xslt": ("config-injection", "config-injection"),
    # ── 文件名 / 扩展名注入 ──
    "extension": ("config-injection", "filename-ext"),
    "ext": ("config-injection", "filename-ext"),
    "filename": ("config-injection", "filename-ext"),
    # ── 稀释噪声 ──
    "mime": (_N, "noise-dilution"),
    "content": (_N, "noise-dilution"),
    # ── Log4j Lookup 组合 ──
    "lookup": ("lookup-composition", "lookup-composition"),
    "format": ("lookup-composition", "lookup-composition"),
    # ── 拆分重组（lexical 默认）──
    "lexical": (_T, "token-split"),
    # ── 等价替换（syntactic 默认 function-swap）──
    "syntactic": (_E, "function-swap"),
    # ── 语义层（semantic 默认间接执行）──
    "semantic": (_I, "indirect-exec"),
}

# 技法级覆盖：同 dimension 内跨机制的条目逐条归族（主力军，逐条审过）。
# 键 = technique_id（三段式），值 = (机制, 族)。
TECHNIQUE_OVERRIDE: dict[str, tuple[str, str]] = {
    # ── lexical：拆分/空白/大小写/编码转义/间接展开 混排 ──
    "sqli:lexical:case_flip": (_E, "case-mutation"),
    "sqli:lexical:ascii_whitespace": (_E, "whitespace-sub"),
    "sqli:lexical:whitespace_sub": (_E, "whitespace-sub"),
    "sqli:lexical:emoji_separator": (_E, "whitespace-sub"),
    "sqli:lexical:backtick_ident": (_E, "function-swap"),
    "sqli:lexical:dollar_quote_tag": (_E, "function-swap"),
    "sqli:lexical:after_operator_chars": (_E, "operator-swap"),
    "sqli:lexical:and_or_suffix_chars": (_E, "operator-swap"),
    "sqli:lexical:nullbyte_truncate": (_P, "parser-differential"),
    "cmdi:lexical:ifs": (_E, "whitespace-sub"),
    "cmdi:lexical:ifs_variants": (_E, "whitespace-sub"),
    "cmdi:lexical:ansi_c_quoting": (_E, "function-swap"),
    "cmdi:lexical:octal_ansi": (_E, "function-swap"),
    "cmdi:lexical:printf_hex": (_E, "function-swap"),
    "cmdi:lexical:redir_space": (_E, "operator-swap"),
    "cmdi:lexical:default_value_split": (_I, "indirect-exec"),
    "cmdi:lexical:special_param_chars": (_I, "indirect-exec"),
    "cmdi:lexical:underscore_lastarg": (_I, "indirect-exec"),
    "cmdi:lexical:tr_shift": (_I, "indirect-exec"),
    "cmdi:lexical:tilde_home": (_I, "indirect-exec"),
    # ── syntactic：等价改写 / 运算符 / AST盲区 / 运行时展开 / 稀释 混排 ──
    "sqli:syntactic:operator_swap": (_E, "operator-swap"),
    "sqli:syntactic:bool_ops": (_E, "operator-swap"),
    "sqli:syntactic:bitwise_cmp": (_E, "operator-swap"),
    "sqli:syntactic:null_safe_equal": (_E, "operator-swap"),
    "sqli:syntactic:regexp_like": (_E, "operator-swap"),
    "sqli:syntactic:schema_qualified_operator": (_E, "operator-swap"),
    "sqli:syntactic:sqlite_glob_match": (_E, "operator-swap"),
    "sqli:syntactic:mysql8_table_values": (_P, "parser-differential"),
    "sqli:syntactic:odbc_brace": (_P, "parser-differential"),
    "sqli:syntactic:schemasplit": (_P, "parser-differential"),
    "sqli:syntactic:comment_before_paren": (_P, "comment-injection"),
    "cmdi:syntactic:separator_rotate": (_E, "operator-swap"),
    "cmdi:syntactic:redir_read_alt": (_E, "operator-swap"),
    "cmdi:syntactic:logical_chain": (_N, "noise-dilution"),
    "cmdi:syntactic:comment_noise": (_N, "noise-dilution"),
    "cmdi:syntactic:glob": (_I, "indirect-exec"),
    "cmdi:syntactic:glob_char_class": (_I, "indirect-exec"),
    "cmdi:syntactic:glob_full_command": (_I, "indirect-exec"),
    "cmdi:syntactic:parameter_expansion": (_I, "indirect-exec"),
    "cmdi:syntactic:arith_expansion": (_I, "indirect-exec"),
    "cmdi:syntactic:brace_expansion": (_I, "indirect-exec"),
    "cmdi:syntactic:here_string_feed": (_I, "indirect-exec"),
    "cmdi:syntactic:heredoc_doc": (_I, "indirect-exec"),
    "cmdi:syntactic:heredoc_feed": (_I, "indirect-exec"),
    "cmdi:syntactic:process_substitution": (_I, "indirect-exec"),
    "cmdi:syntactic:rev_command": (_I, "indirect-exec"),
    "cmdi:syntactic:case_tr": (_I, "indirect-exec"),
    "cmdi:syntactic:cmd_env_substring": (_I, "indirect-exec"),
    "cmdi:syntactic:powershell_obfuscation": (_I, "indirect-exec"),
    "cmdi:syntactic:builtin_force": (_I, "indirect-exec"),
    "cmdi:syntactic:shell_alias": (_I, "indirect-exec"),
    "cmdi:syntactic:windows_caret": (_T, "token-split"),
    "cmdi:syntactic:path_variants": (_E, "function-swap"),
    # ── semantic：间接执行 / 函数替换 / 解析器差异 / 上下文逃逸 混排 ──
    "sqli:semantic:error_func_family": (_E, "function-swap"),
    "sqli:semantic:json_func_predicate": (_E, "function-swap"),
    "sqli:semantic:sys_schema_meta": (_E, "function-swap"),
    "sqli:semantic:user_var_dynamic_sql": (_I, "indirect-exec"),
    "xss:semantic:chromesanitizer_ns_split": (_P, "namespace-confusion"),
    "xss:semantic:chromesanitizer_url_fastpath": (_P, "parser-differential"),
    "xss:semantic:json_unicode_mismatch": (_P, "parser-differential"),
    "xss:semantic:mismatch_context": (_P, "parser-differential"),
    "xss:semantic:parser_differential": (_P, "parser-differential"),
    "xss:semantic:polyglot": (_C, "context-escape"),
    "xss:semantic:waffled_json_dupkey": (_P, "parser-differential"),
    # ── context：上下文逃逸 / 协议逃逸 / 解析器差异 混排 ──
    "xss:context:postmessage_origin": (_C, "protocol-scheme"),
    "xss:context:url_proto": (_C, "protocol-scheme"),
    "xss:context:url_attr_whitelist_gap": (_C, "protocol-scheme"),
    "xss:context:form_vectors": (_C, "protocol-scheme"),
    "xss:context:base_href": (_C, "protocol-scheme"),
    "xss:context:meta_refresh": (_C, "protocol-scheme"),
    "xss:context:svg_xlink": (_C, "protocol-scheme"),
    "xss:context:svg_xlink_data_script": (_C, "protocol-scheme"),
    "xss:context:svg_smil_urilist": (_C, "protocol-scheme"),
    "xss:context:svg_namespace_prefix": (_P, "namespace-confusion"),
    "xss:context:svg_xhtml_namespace": (_P, "namespace-confusion"),
    "xss:context:mathml_mxss": (_P, "namespace-confusion"),
    "xss:context:svg_entity_decl": (_P, "parser-differential"),
    "xss:context:double_angle_tag": (_P, "parser-differential"),
    "xss:context:rawtext_escape": (_P, "parser-differential"),
    "xss:context:dangling_markup": (_I, "indirect-exec"),
    "xss:context:data_blob_import": (_I, "indirect-exec"),
    "xss:context:dom_sink": (_I, "indirect-exec"),
    "xss:context:framework_sandbox": (_I, "indirect-exec"),
    "xss:context:framework_sink": (_I, "indirect-exec"),
    "xss:context:import_map": (_I, "indirect-exec"),
    "xss:context:template_literal_js": (_I, "indirect-exec"),
    "xss:context:csp_jsonp_bypass": (_C, "protocol-scheme"),
    # ── content：配置注入 / 稀释噪声 混排 ──
    "upload:content:user_ini_prepend": ("config-injection", "config-injection"),
    "upload:content:phar_gif_metadata": (_N, "noise-dilution"),
    "upload:content:js_image_polyglot": (_N, "noise-dilution"),
    "upload:content:magic_bytes": (_N, "noise-dilution"),
    "upload:content:png_zip_polyglot": (_N, "noise-dilution"),
    "upload:content:svg_stored_xss": (_N, "noise-dilution"),
    "upload:content:zip_method_spoof": (_N, "noise-dilution"),
    "upload:content:dynamic_function": (_I, "indirect-exec"),
    "upload:content:exif_metadata_xss": (_N, "noise-dilution"),
    # ── filename：文件名注入 / 解析器差异（multipart 走私）混排 ──
    "upload:filename:path_traversal_name": ("config-injection", "filename-ext"),
    "upload:filename:crlf_filename": (_P, "parser-differential"),
    "upload:filename:filename_star": (_P, "parser-differential"),
    "upload:filename:newline_in_header": (_P, "parser-differential"),
    "upload:filename:unclosed_quote": (_P, "parser-differential"),
    "upload:filename:unicode_nfkc_bypass": (_P, "parser-differential"),
    # ── mutation：mXSS 重解析（parser-differential 默认已覆盖，此处置空无需列）──
}


def classify_community_technique(technique_id: str) -> tuple[str, str] | None:
    """社区技法归族。

    返回 (mechanism_id, family_id)；命中筛除清单返回 None。
    dimension 默认 + 技法级 override。
    """
    if technique_id in COMMUNITY_SKIP:
        return None
    if technique_id in TECHNIQUE_OVERRIDE:
        return TECHNIQUE_OVERRIDE[technique_id]
    parts = technique_id.split(":")
    dimension = parts[1] if len(parts) >= 2 else ""
    return DIMENSION_DEFAULT.get(dimension, (_I, "indirect-exec"))


# ---------------------------------------------------------------------------
# 后端（方言）标注：用于穷举时的「后端剪枝」（P2）。
# 一条 MySQL 原语不套 oracle/mssql 专属技法。
# ---------------------------------------------------------------------------

# 后端专属前缀 → backend 值（dimension 维度）
BACKEND_BY_DIMENSION: dict[str, str] = {
    "oracle": "oracle",
    "mssql": "mssql",
}

# 技法级 backend 覆盖（跨后端的通用技法则标 generic）
TECHNIQUE_BACKEND_OVERRIDE: dict[str, str] = {
    # PostgreSQL 专属
    "sqli:lexical:dollar_quote_tag": "postgresql",
    "sqli:syntactic:schema_qualified_operator": "postgresql",
    "sqli:type:cast_error_exfil": "postgresql",
    "sqli:type:chr_bitwise_ascii": "postgresql",
    # SQLite 专属
    "sqli:syntactic:sqlite_glob_match": "sqlite",
    # 跨后端通用（case_flip/comment_split/operator_swap 等 MySQL/Oracle/PG/MSSQL 都认）
    "sqli:lexical:case_flip": "generic",
    "sqli:lexical:comment_split": "generic",
    "sqli:lexical:quote_split": "generic",
    "sqli:syntactic:operator_swap": "generic",
    "sqli:syntactic:comment_before_paren": "generic",
}


def infer_backend(technique_id: str) -> str:
    """返回技法适用的后端：oracle / mssql / postgresql / sqlite / generic。

    - 技法级 override 优先
    - 否则按 dimension（oracle/mssql 维度专属）
    - 默认 generic（跨后端通用）
    """
    if technique_id in TECHNIQUE_BACKEND_OVERRIDE:
        return TECHNIQUE_BACKEND_OVERRIDE[technique_id]
    parts = technique_id.split(":")
    dimension = parts[1] if len(parts) >= 2 else ""
    return BACKEND_BY_DIMENSION.get(dimension, "generic")
