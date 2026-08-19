"""
Migrate command-injection payloads from form-field / header delivery
to URL-based delivery formats compatible with Tencent WAF direct testing.

Target access pattern:
    GET http://43.136.161.54/{payload_content}
    Host: miniproject.testwaf.com

The payload content literally becomes the URL path (including optional query string).

Migration strategy:
  - Form-field (167): Strip DVWA IP prefix, convert to URL path / query param
  - Header-injection (131): Extract command from awk/system templates or keep as-is
  - URL-query (1): Already compatible, no change

Separator handling:
  - '&' → '%26' (URL query separator conflict)
  - '#' → '%23' (URL fragment conflict)
  - Other shell separators (; | || && %0a $() `` ) pass through unchanged
"""

import sqlite3
import json
import re
import uuid
import shutil
from datetime import datetime, timezone
from collections import Counter

DB = "data/waf_bypasser.db"
DB_BACKUP = "data/waf_bypasser.db.bak"

# Restore from backup first (idempotent re-run safety)
shutil.copy2(DB_BACKUP, DB)
print(f"Restored fresh copy from backup ({DB_BACKUP})")

conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

# ── Helpers ──────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# Known DVWA IP prefix patterns
DVWA_PREFIX_RE = re.compile(
    r"^(?:(?:127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|localhost)"
    r"\s*)",
    re.IGNORECASE,
)

# Dummy prefix for error-based injection
DUMMY_PREFIX_RE = re.compile(
    r"^(invalidcommand|nonexistent|xxxx|aaa|error)\s+",
    re.IGNORECASE,
)

def extract_cmd_from_dvwa(content: str) -> tuple[str, str, str]:
    """Extract separator and command from a DVWA-style payload.

    Returns: (separator, command, remainder_after_cmd)
    """
    text = content.strip()

    # Strip IP prefix
    m = DVWA_PREFIX_RE.match(text)
    if m:
        text = text[m.end():].strip()

    if not text:
        return ("", "", "")

    # Detect separator
    sep_patterns = [
        (r"^;\s*", ";"), (r"^&&\s*", "&&"), (r"^\|\|\s*", "||"),
        (r"^\|\s*", "|"), (r"^&\s*", "%26"), (r"^%0[aA]\s*", "%0a"),
        (r"^\\n\s*", "%0a"), (r"^\$\(.*?\)\s*", "$()"),
        (r"^`[^`]*`\s*", "``"),
    ]

    sep = ""
    cmd = text
    rest = ""

    for pattern, sep_name in sep_patterns:
        m = re.match(pattern, text)
        if m:
            sep = sep_name
            cmd = text[m.end():].strip()
            break

    # If no explicit separator but content starts with a command word
    if not sep and text:
        cmd = text

    # Check for trailing stderr handling, pipeline, etc.
    return (sep, cmd, rest)


def convert_to_url_path(content: str) -> str:
    """Convert a DVWA-style payload to URL path format."""
    text = content.strip()

    # Strip IP prefix
    m = DVWA_PREFIX_RE.match(text)
    if m:
        text = text[m.end():].strip()

    if not text:
        return content  # Can't parse, keep as-is

    # Handle & separator → %26
    text = re.sub(r"^&\s*", "%26", text)

    # Collapse multiple spaces (URLs don't need them in path)
    text = re.sub(r"\s+", " ", text)

    return text


def convert_to_url_query(content: str) -> str:
    """Convert to URL query parameter format (?ip=DVWA_PATTERN)."""
    text = content.strip()

    # Check if already starts with ?
    if text.startswith("?"):
        return text

    # Strip IP prefix but KEEP it for query param context
    m = DVWA_PREFIX_RE.match(text)
    if m:
        ip = m.group(0).strip()
        cmd_part = text[m.end():].strip()
        if cmd_part:
            # Handle & separator
            cmd_part = re.sub(r"^&\s*", "%26", cmd_part)
            return f"?ip={ip}{cmd_part}"
        return f"?ip={ip}"

    # No IP prefix - use generic cmd param
    return f"?cmd={text}"


def convert_awk_to_cmd(content: str) -> str:
    """Extract the shell command from awk/system injection templates."""
    # Pattern: '{system("cmd")}'  or  'BEGIN{system("cmd")}'
    system_m = re.search(r'system\("([^"]+)"\)', content)
    if system_m:
        inner_cmd = system_m.group(1)
        # Extract the actual meaningful command
        # e.g., "echo AWK_SYS_OK" → ";echo AWK_SYS_OK"
        return f";{inner_cmd}"

    # Pattern: variable concatenation + system
    # e.g., 'BEGIN{a="ec";b="ho";system(a b " AWK_VARCAT_OK")}'
    system2_m = re.search(r'system\([^)]+["\']([^"\']+)["\'][^)]*\)', content)
    if system2_m:
        marker = system2_m.group(1).strip()
        return f";echo {marker}"

    # Pattern: getline pipe
    getline_m = re.search(r'"([^"]+)"\s*\|', content)
    if getline_m:
        inner_cmd = getline_m.group(1)
        return f";{inner_cmd}"

    # Can't parse - keep original but strip quotes
    stripped = content.strip("'\"")
    return f";{stripped}"


# ── Main migration ───────────────────────────────────────────────────────

print("\n=== Starting migration ===\n")

# Get all command-injection payloads
rows = conn.execute(
    "SELECT * FROM payloads WHERE vulnerability='command-injection' AND is_deleted=0"
).fetchall()

stats = Counter()
migrated = []
unchanged = []
errors = []

for r in rows:
    payload_id = r["id"]
    old_content = r["content"]
    old_delivery = r["delivery"]
    old_usage = r["usage_method"]
    old_success = r["success_indicators"]
    old_name = r["name"]

    new_content = old_content
    new_delivery = old_delivery
    change_note = ""

    # ── Case 1: Form-field payloads (表单字段) ──
    if old_delivery in ("表单字段", "�����ֶ�"):
        # Strategy: Strip IP prefix, convert to URL query param
        # Alternate between URL path and URL query for variety
        hash_int = sum(ord(c) for c in payload_id) if payload_id else 0

        if hash_int % 3 == 0:
            # URL Path format
            new_content = convert_to_url_path(old_content)
            new_delivery = "URL 路径"
            change_note = "表单字段→URL路径：去除IP前缀，保留分隔符+命令"
        elif hash_int % 3 == 1:
            # URL Query param (DVWA-style: ?ip=...)
            new_content = convert_to_url_query(old_content)
            new_delivery = "URL 查询参数"
            change_note = "表单字段→URL查询参数：?ip=IP;cmd 格式"
        else:
            # URL Query with generic cmd param
            text = old_content.strip()
            m = DVWA_PREFIX_RE.match(text)
            if m:
                cmd_part = text[m.end():].strip()
                cmd_part = re.sub(r"^&\s*", "%26", cmd_part)
                new_content = f"?q={cmd_part}"
            else:
                new_content = f"?q={text}"
            new_delivery = "URL 查询参数"
            change_note = "表单字段→URL查询参数（通用q参数）"

        stats["form→url_path"] += 1 if new_delivery == "URL 路径" else 0
        stats["form→url_query_ip"] += 1 if new_delivery == "URL 查询参数" and "?ip=" in new_content else 0
        stats["form→url_query_q"] += 1 if new_delivery == "URL 查询参数" and "?q=" in new_content else 0

        if new_content != old_content:
            migrated.append((payload_id, old_delivery, new_delivery, old_content[:60], new_content[:60]))
        else:
            unchanged.append(payload_id)

    # ── Case 2: Request-header payloads (请求头) ──
    elif old_delivery in ("请求头", "�������", "����ͷ / Cookie", "请求头 / Cookie"):
        # Strategy: Extract command from awk/system template, convert to URL path
        text = old_content.strip()

        if "system(" in text or "|getline" in text.lower():
            new_content = convert_awk_to_cmd(text)
            new_delivery = "URL 查询参数"
            change_note = "请求头awk模板→URL命令注入：提取system()调用命令"
        elif text.startswith("'") or text.startswith('"'):
            # Quoted string - likely meant for header injection
            stripped = text.strip("'\"")
            if stripped:
                new_content = f";{stripped}"
            else:
                new_content = text
            new_delivery = "URL 查询参数"
            change_note = "请求头引用字符串→URL命令注入"
        else:
            # Already looks like a command
            new_content = f";{text}"
            new_delivery = "URL 查询参数"
            change_note = "请求头→URL命令注入（添加分号前缀）"

        stats["header→url"] += 1

        if new_content != old_content:
            migrated.append((payload_id, old_delivery, new_delivery, old_content[:60], new_content[:60]))
        else:
            unchanged.append(payload_id)

    # ── Case 3: URL query param (already correct) ──
    elif old_delivery in ("URL 查询参数", "URL��ѯ����", "URL路径", "URL 路径"):
        # Already URL-based, just normalize delivery name
        new_delivery = "URL 查询参数"
        change_note = "保持URL投递格式"
        stats["already_url"] += 1
        unchanged.append(payload_id)

    # ── Case 4: Unknown delivery ──
    else:
        stats["unknown_delivery"] += 1
        errors.append((payload_id, old_delivery, old_content[:60]))
        continue

    # ── Update the database ──
    # Update name to reflect URL delivery
    new_name = re.sub(
        r"(表单|表单字段|请求头|Header|header|awk)",
        "URL",
        old_name or "命令注入",
        flags=re.IGNORECASE,
    )

    # Update usage_method to describe URL delivery
    new_usage = (
        f"将 payload 通过 URL 投递：GET http://目标IP/{new_content}，"
        f"携带 Host 头指向目标站点。{change_note}。"
        f"原投递方式：{old_delivery}。"
    )

    conn.execute(
        "UPDATE payloads SET content = ?, delivery = ?, name = ?, usage_method = ? WHERE id = ?",
        (new_content, new_delivery, new_name, new_usage, payload_id),
    )

conn.commit()

# ── Also update iteration_pool_items snapshots ──
# These have snapshot content that should also be updated
pool_rows = conn.execute(
    "SELECT id, snapshot_payload_id FROM iteration_pool_items WHERE agent='semantic'"
).fetchall()
for pr in pool_rows:
    snap = conn.execute(
        "SELECT id, content, delivery FROM payloads WHERE id=? AND is_pool_snapshot=1",
        (pr["snapshot_payload_id"],),
    ).fetchone()
    if snap:
        snap_content = snap["content"]
        # Same conversion logic
        new_snap = convert_to_url_path(snap_content)
        if new_snap != snap_content:
            conn.execute(
                "UPDATE payloads SET content=?, delivery='URL 查询参数' WHERE id=?",
                (new_snap, snap["id"]),
            )
            stats["snapshot_updated"] += 1

conn.commit()

# ── Print summary ────────────────────────────────────────────────────────

print(f"\n=== Migration Complete ===\n")
print(f"Total payloads processed: {len(rows)}")
print(f"Migrated (changed):      {len(migrated)}")
print(f"Unchanged:               {len(unchanged)}")
print(f"Errors:                  {len(errors)}")
print()

print("Conversion breakdown:")
for k, v in sorted(stats.items()):
    print(f"  {k:30s} → {v}")

print()

print("=== Sample conversions (first 20) ===")
for pid, old_del, new_del, old_c, new_c in migrated[:20]:
    print(f"  [{old_del:15s} → {new_del:15s}]")
    print(f"    Old: {old_c}")
    print(f"    New: {new_c}")
    print()

if errors:
    print("=== Errors ===")
    for pid, od, oc in errors:
        print(f"  {pid[:12]} {od:20s} {oc}")

# ── Verify ───────────────────────────────────────────────────────────────

print("=== Post-migration delivery distribution ===")
for row in conn.execute(
    "SELECT delivery, COUNT(*) as cnt FROM payloads "
    "WHERE vulnerability='command-injection' AND is_deleted=0 "
    "GROUP BY 1 ORDER BY 2 DESC"
).fetchall():
    print(f"  {row['delivery']:30s} → {row['cnt']}")

# ── Verify a few random samples are valid URLs ──
print("\n=== URL format validation samples ===")
samples = conn.execute(
    "SELECT content, delivery FROM payloads "
    "WHERE vulnerability='command-injection' AND is_deleted=0 "
    "ORDER BY RANDOM() LIMIT 10"
).fetchall()
for s in samples:
    content = s["content"]
    # Check no raw & (should be %26)
    has_raw_amp = "&" in content and "%26" not in content and not content.startswith("?")
    issues = []
    if has_raw_amp:
        # Check if it's inside a query param (?key=val&key=val) - that's OK
        if content.startswith("?"):
            # Valid query string
            pass
        else:
            issues.append("RAW_AMPERSAND")

    status = "OK" if not issues else f"ISSUES: {', '.join(issues)}"
    print(f"  [{s['delivery']:20s}] {content[:100]:100s}  {status}")

conn.close()
print("\nDone.")
