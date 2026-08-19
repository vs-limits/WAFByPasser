"""
Analyze existing command injection payloads and print a summary report.
Also produces SQL to convert form-field payloads to URL-based delivery formats
suitable for direct HTTP GET targeting (Tencent WAF / IP+Host pattern).

The Tencent WAF test mode sends:
  GET http://<TENCENT_WAF_IP>/<payload-derived-url>
  Host: <TENCENT_WAF_HOST>

So payloads must work as URL query params or URL path components.
"""

import sqlite3
import json
from collections import Counter

DB = "data/waf_bypasser.db"

conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

# ── 1. Summary statistics ──────────────────────────────────────────

rows = conn.execute(
    "SELECT * FROM payloads WHERE vulnerability='command-injection' AND is_deleted=0"
).fetchall()

print(f"=== Total command-injection payloads: {len(rows)} ===\n")

delivery_count = Counter(r["delivery"] for r in rows)
target_count = Counter(r["target"] for r in rows)
diff_count = Counter(r["difficulty"] for r in rows)

print("By delivery:")
for k, v in delivery_count.most_common():
    print(f"  {k:40s} → {v}")

print("\nBy target:")
for k, v in target_count.most_common():
    print(f"  {k:40s} → {v}")

print("\nBy difficulty:")
for k, v in diff_count.most_common():
    print(f"  {k:40s} → {v}")

# ── 2. Sample content by delivery type ─────────────────────────────

print("\n=== Sample payloads per delivery type ===\n")

for delivery in sorted(delivery_count):
    samples = [r for r in rows if r["delivery"] == delivery]
    print(f"--- {delivery} ({len(samples)} total) ---")
    for s in samples[:5]:
        print(f"  [{s['target']:12s}] {s['content'][:120]}")
    if len(samples) > 5:
        print(f"  ... and {len(samples)-5} more")
    print()

# ── 3. Categorize which payloads can work as URL-based ─────────────

print("=== URL-based delivery feasibility analysis ===\n")

# These existing payloads are designed for DVWA form injection:
#   "127.0.0.1; id"
# The DVWA app does: shell_exec("ping -c 4 " . $input)
# So the payload = IP prefix + ; + command

# For Tencent WAF direct URL mode, payload goes in the URL:
#   http://<IP>/<payload>  or  http://<IP>/?<key>=<payload>
#
# Possible URL-based delivery forms:
# A) URL Path injection: /cgi-bin/cmd;id  (app runs specific binary)
# B) URL Query param injection: ?ip=127.0.0.1;id (app echoes param)
# C) URL Query direct: ?cmd=id (app executes param directly)

# The current "表单字段" delivery payloads use the DVWA ping pattern.
# We need to convert them for URL delivery.

# Form-field payloads (DVWA-style: IP + separator + command)
form_payloads = [r for r in rows if r["delivery"] in ("表单字段", "�����ֶ�")]
print(f"Form-field payloads to convert: {len(form_payloads)}")

# Extract the command part from each
print("\nSample form-field payloads and extracted commands:")
for fp in form_payloads[:10]:
    content = fp["content"]
    # DVWA pattern: IP;command or IP|command or IP&&command
    # Extract the command after the separator
    parts = content.split(";", 1)
    if len(parts) > 1:
        cmd = parts[1].strip()
    else:
        # Try other separators
        for sep in ["|", "&&", "||"]:
            parts = content.split(sep, 1)
            if len(parts) > 1:
                cmd = parts[1].strip()
                break
        else:
            cmd = content
    print(f"  {content[:80]:80s} → cmd: {cmd[:60]}")

conn.close()
