"""Fix remaining raw ampersands in URL-migrated payloads."""
import sqlite3
import re

DB = "data/waf_bypasser.db"
conn = sqlite3.connect(DB)

# Find payloads that need ampersand fixes
rows = conn.execute("""
    SELECT id, content, delivery FROM payloads
    WHERE vulnerability='command-injection' AND is_deleted=0
""").fetchall()

fixed = 0
for pid, content, delivery in rows:
    new_content = content

    if delivery.startswith("URL"):
        # Fix 1: In URL path (not starting with ?), encode any & that isn't already %26
        # and isn't part of && (which should become %26%26)
        if not content.startswith("?"):
            # Replace && → %26%26
            if "&&" in new_content:
                new_content = new_content.replace("&&", "%26%26")
                fixed += 1
            # Replace standalone & (not %26, not && already handled)
            # & that ends the string → %26
            new_content = re.sub(r'(?<!%)&(?!&)', '%26', new_content)
            if new_content != content:
                fixed += 1

        # Fix 2: In query params, ensure & is only used as param separator
        # Not needed for ?ip=... format since content after ? is a valid query string
        if content.startswith("?") and "&" in content:
            # Check if there's an & that's NOT a query param separator
            # A valid query string looks like ?key=val&key=val
            # An invalid one has & as shell background operator
            # Count query parts
            parts = content[1:].split("&")
            if len(parts) == 1:
                # Only one param, any & inside should be encoded
                pass  # Already %26 from conversion
            # For multiple params, verify each has =
            for p in parts[1:]:  # skip first, check subsequent
                if "=" not in p and p.strip():
                    # This is probably a shell &, not a param separator
                    # Already handled by the form-field conversion
                    pass

    if new_content != content:
        conn.execute(
            "UPDATE payloads SET content = ? WHERE id = ?",
            (new_content, pid),
        )

conn.commit()

# Verify no remaining issues in URL path payloads
issues = conn.execute("""
    SELECT content FROM payloads
    WHERE vulnerability='command-injection' AND is_deleted=0
    AND delivery='URL 路径' AND content NOT LIKE '?%'
    AND (content LIKE '%&%' OR content LIKE '%&&%')
    AND content NOT LIKE '%%%26%'
""").fetchall()

print(f"Fixed: {fixed}")
print(f"Remaining URL-path payloads with raw &: {len(issues)}")
for c in issues[:5]:
    print(f"  {c[0][:100]}")

conn.close()
