#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('data/waf_bypasser.db')
cursor = conn.execute("SELECT id, name, iteration_metadata_json FROM payloads WHERE name LIKE '%find%' LIMIT 5")

print("=== Payloads with 'find' in name ===\n")
for row in cursor.fetchall():
    payload_id, name, metadata = row
    print(f"Name: {name}")
    print(f"Metadata: {metadata[:200] if metadata else 'NULL'}")
    print("-" * 80)

conn.close()
