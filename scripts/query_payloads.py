"""Query existing command injection payloads from the database."""
import sqlite3
import json

DB = "data/waf_bypasser.db"

conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

# All command-injection payloads
rows = conn.execute(
    "SELECT * FROM payloads WHERE vulnerability='command-injection' AND is_deleted=0"
).fetchall()

print(f"=== Command Injection Payloads: {len(rows)} ===\n")

for r in rows:
    print(f"ID:        {r['id']}")
    print(f"Name:      {r['name']}")
    print(f"Target:    {r['target']}  Difficulty: {r['difficulty']}")
    print(f"Delivery:  {r['delivery']}")
    print(f"Category:  {r['category']}")
    print(f"Content:   {r['content']}")
    print(f"Usage:     {r['usage_method'][:200]}")
    print(f"Success:   {r['success_indicators'][:200]}")
    metadata = json.loads(r["iteration_metadata_json"]) if r.get("iteration_metadata_json") else {}
    print(f"IterMeta:  {json.dumps(metadata, ensure_ascii=False)[:200]}")
    print("-" * 80)

# Also show all delivery types across all payloads
print("\n=== All Delivery Types ===")
for row in conn.execute(
    "SELECT DISTINCT vulnerability, delivery, COUNT(*) as cnt FROM payloads WHERE is_deleted=0 GROUP BY 1,2"
).fetchall():
    print(f"  {row['vulnerability']:20s} | {row['delivery']:30s} | count={row['cnt']}")

# Show all success samples
print("\n=== Success Samples ===")
for row in conn.execute(
    "SELECT id, name, vulnerability, delivery, content, agent FROM success_samples"
).fetchall():
    print(f"  [{row['agent']:10s}] {row['name']:30s} | {row['delivery']:25s} | {row['content'][:80]}")

conn.close()
