"""Fix the 131 request-header payloads + 1 URL-query that weren't converted."""
import sqlite3
import re
from datetime import datetime, timezone

DB = "data/waf_bypasser.db"

conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# Find all cmd-injection payloads NOT using URL delivery
rows = conn.execute("""
    SELECT * FROM payloads
    WHERE vulnerability='command-injection'
    AND is_deleted=0
    AND delivery NOT LIKE 'URL %' AND delivery NOT LIKE 'URL%'
""").fetchall()

print(f"Remaining non-URL cmd-injection payloads: {len(rows)}")

for r in rows:
    # Convert awk/system/script template to URL-compatible command
    content = r["content"]
    delivery = r["delivery"]

    # Check if it matches common patterns: awk system(), sed -e, find -exec, etc
    new_content = None

    # Pattern 1: awk system()
    sys_m = re.search(r"""system\(["']([^"']+)["']\)""", content)
    if sys_m:
        cmd = sys_m.group(1)
        # Keep the command but add separator
        new_content = f";{cmd}"

    # Pattern 2: awk getline pipe
    elif 'getline' in content.lower():
        pipe_m = re.search(r'"([^"]+)"\s*\|', content)
        if pipe_m:
            new_content = f";{pipe_m.group(1)}"
        else:
            new_content = f";echo {content.strip(chr(39))}"  # strip single quotes

    # Pattern 3: sed -e '...'  —  extract the command inside
    elif content.strip().startswith("-e"):
        # Extract what's inside the single quotes
        cmd_m = re.search(r"""['"]([^'"]*system\([^)]+\)[^'"]*)['"]""", content)
        if cmd_m:
            sys_inner = re.search(r"""system\(["']([^"']+)["']\)""", cmd_m.group(1))
            if sys_inner:
                new_content = f";{sys_inner.group(1)}"
        if not new_content:
            # Generic: just echo the marker
            marker_m = re.search(r'echo\s+(\w+_OK)', content)
            if marker_m:
                new_content = f";echo {marker_m.group(1)}"
            else:
                new_content = f";{content.strip()}"

    # Pattern 4: find -exec echo FIND_OK \;
    elif content.strip().startswith("-exec") or content.strip().startswith("-ok"):
        marker_m = re.search(r'echo\s+(\w+_OK)', content)
        if marker_m:
            new_content = f";echo {marker_m.group(1)}"
        else:
            new_content = f";{content.strip()}"

    # Pattern 5: SCP/SSH -oProxyCommand
    elif "ProxyCommand" in content or "LocalCommand" in content:
        cmd_m = re.search(r'echo\s+(\w+_OK)', content)
        if cmd_m:
            new_content = f";{cmd_m.group(0)}"
        elif "sh" in content:
            new_content = f";id"
        else:
            new_content = f";{content.strip()}"

    # Pattern 6: tar --checkpoint/--use-compress-program
    elif "--checkpoint" in content or "--use-compress-program" in content:
        cmd_m = re.search(r'echo\s+(\w+_OK)', content)
        if cmd_m:
            new_content = f";{cmd_m.group(0)}"
        else:
            new_content = f";{content.strip()}"

    # Pattern 7: curl/wget/zip/unzip etc with embedded commands
    elif any(kw in content for kw in ["$(echo", "$(a=", "$(printf", "K <(", "--output", "--use-askpass", "--post-file", "-d \"$(", "-T -TT"]):
        cmd_m = re.search(r'echo\s+(\w+_OK)', content)
        if cmd_m:
            new_content = f";{cmd_m.group(0)}"
        else:
            # Generic extraction
            new_content = f";{content.strip()}"

    # Pattern 8: perl/python/ruby/php/lua -e/-c/-r execution
    elif re.search(r"^\s*-[ecr]\s+['\"]", content.strip()):
        cmd_m = re.search(r"""system\(["']([^"']+)["']\)""", content)
        if cmd_m:
            new_content = f";{cmd_m.group(1)}"
        elif "echo" in content:
            marker_m = re.search(r'echo\s+(\w+_OK)', content)
            if marker_m:
                new_content = f";{marker_m.group(0)}"
            else:
                new_content = f";{content.strip()}"
        else:
            new_content = f";{content.strip()}"

    # Pattern 9: make --eval, env var injection, etc
    elif "shell " in content:
        cmd_m = re.search(r'echo\s+(\w+_OK)', content)
        if cmd_m:
            new_content = f";{cmd_m.group(0)}"
        else:
            new_content = f";{content.strip()}"

    # Pattern 10: screen/tmux command injection
    elif any(kw in content for kw in ["echo SCREEN_", "echo TMUX_", "stuff 'echo"]):
        cmd_m = re.search(r'echo\s+(\w+_OK)', content)
        if cmd_m:
            new_content = f";{cmd_m.group(0)}"
        else:
            new_content = f";{content.strip()}"

    # Pattern 11: Various utility injections (script, dd, printf, xargs, strace, etc.)
    elif any(kw in content for kw in ["echo SCRIPT_", "echo DD_", "PRINTF_", "echo XARGS_",
                                        "echo STRACE_", "echo NICE_", "ENV_VAR", "echo TIME_",
                                        "echo TIMEOUT_", "echo SORT_", "echo DIFF_"]):
        cmd_m = re.search(r'echo\s+(\w+_OK)', content)
        if cmd_m:
            new_content = f";{cmd_m.group(0)}"
        else:
            new_content = f";{content.strip()}"

    # Pattern 12: awk BEGIN/END blocks (no explicit system)
    elif re.search(r"^(?:'BEGIN|'END)", content.strip()):
        sys_m = re.search(r"""system\(["']([^"']+)["']\)""", content)
        if sys_m:
            new_content = f";{sys_m.group(1)}"
        elif "echo" in content:
            marker_m = re.search(r'echo\s+(\w+_OK)', content)
            if marker_m:
                new_content = f";{marker_m.group(0)}"
            else:
                new_content = f";{content.strip()}"
        else:
            new_content = f";{content.strip()}"

    # Pattern 13: base64 encoded payloads
    elif "base64" in content.lower() and ("-d" in content or "b64decode" in content):
        # Extract echo command from base64 context
        marker_m = re.search(r'echo\s+(\w+_OK)', content)
        if marker_m:
            new_content = f";{marker_m.group(0)}"
        else:
            new_content = f";{content.strip()}"

    # Pattern 14: Option chaining / hex / complex parameter injection
    elif content.strip().startswith("--"):
        if "echo" in content:
            marker_m = re.search(r'echo\s+(\w+_OK)', content)
            if marker_m:
                new_content = f";{marker_m.group(0)}"
            else:
                new_content = f";{content.strip()}"
        else:
            new_content = f";{content.strip()}"

    # Generic fallback
    else:
        # Remove surrounding quotes
        stripped = content.strip("'\"")
        new_content = f";{stripped}"

    # Update the record
    conn.execute(
        "UPDATE payloads SET content = ?, delivery = 'URL 查询参数' WHERE id = ?",
        (new_content, r["id"]),
    )

    if (len(rows) <= 20):
        print(f"  {delivery} → URL 查询参数")
        print(f"    Old: {content[:80]}")
        print(f"    New: {new_content[:80]}")
        print()

conn.commit()

# Final verification
print("\n=== Final delivery distribution ===")
for row in conn.execute("""
    SELECT delivery, COUNT(*) as cnt
    FROM payloads WHERE vulnerability='command-injection' AND is_deleted=0
    GROUP BY 1 ORDER BY 2 DESC
""").fetchall():
    print(f"  {row['delivery']:40s} → {row['cnt']}")

conn.close()
print("\nDone.")
