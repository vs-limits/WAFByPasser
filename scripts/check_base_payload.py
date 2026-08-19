#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('data/waf_bypasser.db')
cursor = conn.execute("SELECT name, iteration_metadata_json FROM payloads WHERE id = '9792efd9-e915-4141-8a70-5a61257c19e4'")
row = cursor.fetchone()

if row:
    print(f'Name: {row[0]}')
    print(f'Metadata: {row[1] if row[1] else "NULL"}')
else:
    print('Payload not found')

conn.close()
