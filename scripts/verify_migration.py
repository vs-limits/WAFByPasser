"""Verify the migration results."""
import sqlite3

DB = "data/waf_bypasser.db"
conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

# Show sample from each delivery type
for delivery in ["URL 查询参数", "URL 路径", "URL查询参数"]:
    rows = conn.execute(
        "SELECT content, delivery, usage_method FROM payloads "
        "WHERE vulnerability='command-injection' AND is_deleted=0 AND delivery=? "
        "ORDER BY RANDOM() LIMIT 6",
        (delivery,),
    ).fetchall()

    total = conn.execute(
        "SELECT COUNT(*) FROM payloads "
        "WHERE vulnerability='command-injection' AND is_deleted=0 AND delivery=?",
        (delivery,),
    ).fetchone()[0]

    print(f"=== {delivery.strip()} ({total} total) ===")
    for r in rows:
        print(f"  {r['content'][:120]}")
    print()

# Count by delivery
print("=== Final delivery distribution ===")
for r in conn.execute(
    "SELECT delivery, COUNT(*) as cnt FROM payloads "
    "WHERE vulnerability='command-injection' AND is_deleted=0 "
    "GROUP BY 1 ORDER BY 2 DESC"
).fetchall():
    print(f"  {r['delivery']:40s} {r['cnt']}")

# Check for any remaining problematic content
print("\n=== Checking for problematic content ===")
issues = conn.execute(
    "SELECT COUNT(*) FROM payloads "
    "WHERE vulnerability='command-injection' AND is_deleted=0 "
    "AND content LIKE '%127.0.0.1%'"
).fetchone()[0]
print(f"  Still contain '127.0.0.1': {issues}")

raw_amp = conn.execute(
    "SELECT COUNT(*) FROM payloads "
    "WHERE vulnerability='command-injection' AND is_deleted=0 "
    "AND content NOT LIKE '?%' "  # Not a query string
    "AND content LIKE '%&%' "     # Contains &
    "AND content NOT LIKE '%%%26%' "  # Not encoded
    "AND content NOT LIKE '%%&&%'"    # Not &&
).fetchone()[0]
print(f"  Raw '&' in URL path (not encoded): {raw_amp}")

conn.close()
