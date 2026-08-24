"""导入绕过技巧知识库（bypass_techniques.md）到 kb_techniques 表 + knowledge_base/sources。

用法（在仓库根目录运行）：
    python backend/scripts/import_techniques.py [--dry-run]
"""

from __future__ import annotations

import argparse
import shutil
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = REPO_ROOT / "data" / "waf_bypasser.db"
KB_ROOT = REPO_ROOT / "data" / "knowledge_base"
# 优先用仓库内的知识库源文件；若桌面另有最新稿，可传 --source 覆盖。
SOURCE_MD = KB_ROOT / "sources" / "bypass_techniques.md"

import sys
sys.path.insert(0, str(REPO_ROOT / "backend" / "src"))
from app.knowledge_base_agent import parse_techniques


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main(dry_run: bool) -> None:
    if not SOURCE_MD.exists():
        print(f"错误：技巧文件不存在 {SOURCE_MD}")
        return

    text = SOURCE_MD.read_text(encoding="utf-8", errors="replace")
    techniques = parse_techniques(text)
    print(f"解析到 {len(techniques)} 条技巧")

    from collections import Counter
    stat = Counter(t["vulnerability"] for t in techniques)
    for vuln, cnt in sorted(stat.items()):
        print(f"  {vuln:20} {cnt}")

    if dry_run:
        print("\n[dry-run] 未写入")
        return

    # 复制源文件到 knowledge_base/sources（源已在目标位置时跳过）
    KB_ROOT.mkdir(parents=True, exist_ok=True)
    (KB_ROOT / "sources").mkdir(parents=True, exist_ok=True)
    dest = KB_ROOT / "sources" / "bypass_techniques.md"
    if SOURCE_MD.resolve() != dest.resolve():
        shutil.copy2(SOURCE_MD, dest)

    # 确保知识库表存在（复用 initialize_database 的建表逻辑）
    import sys
    sys.path.insert(0, str(REPO_ROOT / "backend" / "src"))
    from app import main as app_main
    app_main.initialize_database()

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        inserted = 0
        for tech in techniques:
            con.execute(
                """
                INSERT INTO kb_techniques (
                    id, technique_id, name, vulnerability, status, success_count,
                    labels_json, source_note, principle, template, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'pending', 0, '[]', ?, ?, ?, ?, ?)
                ON CONFLICT(technique_id) DO UPDATE SET
                    name = excluded.name,
                    vulnerability = excluded.vulnerability,
                    source_note = excluded.source_note,
                    principle = excluded.principle,
                    template = excluded.template,
                    updated_at = excluded.updated_at
                """,
                (
                    str(uuid.uuid4()),
                    tech["technique_id"],
                    tech["name"],
                    tech["vulnerability"],
                    tech["source_note"],
                    tech["principle"],
                    tech["template"],
                    utc_now(),
                    utc_now(),
                ),
            )
            inserted += 1
        con.commit()
        print(f"\n已写入 {inserted} 条技巧到 kb_techniques")
    finally:
        con.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    main(args.dry_run)
