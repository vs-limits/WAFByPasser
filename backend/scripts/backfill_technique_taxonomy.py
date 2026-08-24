"""给历史 generated 技法补齐分类元数据（mechanism_id / family_id / backend）。

背景：branch 引入「8 机制 × 16 族」分类后，历史 imported/generated 技法
（origin='generated'）的 mechanism_id/family_id/backend 全是 NULL，导致
technique_group 的权威分组与后端剪枝对这些数据失效。

策略（幂等，可重复跑）：
- 只处理 origin='generated' 且 mechanism_id 为空的技法。
- 对 dimension 属于「编码维度」（parser.ENCODING_DIMENSIONS）的技法**跳过**，
  保持 mechanism_id=NULL，继续靠 dimension 归入 encoding 组（编码线走
  encoding.py 独立能力，不进语义 8 机制）。
- 其余（语义维度）按 kb_catalog.classify_community_technique 归类，补
  mechanism_id / family_id，并按 infer_backend 补 backend。
- 命中 COMMUNITY_SKIP（返回 None）的技法保持原样，不强制归类。

用法（仓库根目录运行）：
    .venv/Scripts/python.exe backend/scripts/backfill_technique_taxonomy.py [--dry-run]
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = REPO_ROOT / "data" / "waf_bypasser.db"
sys.path.insert(0, str(REPO_ROOT / "backend" / "src"))

from app.knowledge_base_agent.kb_catalog import (  # noqa: E402
    classify_community_technique,
    infer_backend,
)
from app.knowledge_base_agent.parser import (  # noqa: E402
    ENCODING_DIMENSIONS,
    technique_dimension,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="补齐历史 generated 技法分类元数据")
    parser.add_argument("--dry-run", action="store_true", help="只统计不写库")
    args = parser.parse_args()

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            """
            SELECT id, technique_id FROM kb_techniques
            WHERE origin = 'generated'
              AND (mechanism_id IS NULL OR mechanism_id = '')
            """
        ).fetchall()

        to_classify = []
        skipped_encoding = []
        skipped_skip_list = []
        for r in rows:
            dim = technique_dimension(r["technique_id"])
            if dim in ENCODING_DIMENSIONS:
                skipped_encoding.append(r["technique_id"])
                continue
            cls = classify_community_technique(r["technique_id"])
            if cls is None:
                skipped_skip_list.append(r["technique_id"])
                continue
            to_classify.append((r["id"], r["technique_id"], cls))

        print(f"待补元数据 generated 技法：{len(rows)}")
        print(f"  - 语义维度、将补齐 mechanism_id：{len(to_classify)}")
        print(f"  - 编码维度、跳过（保留 encoding 组）：{len(skipped_encoding)}")
        print(f"  - 命中筛除清单、跳过：{len(skipped_skip_list)}")

        if args.dry_run:
            print("\n[dry-run] 未写库")
            return

        updated = 0
        for tid, technique_id, (mech, family) in to_classify:
            backend = infer_backend(technique_id)
            con.execute(
                """
                UPDATE kb_techniques
                SET mechanism_id = ?, family_id = ?, backend = ?
                WHERE id = ?
                """,
                (mech, family, backend, tid),
            )
            updated += 1
        con.commit()
        print(f"\n已补齐 {updated} 条技法分类元数据")
    finally:
        con.close()


if __name__ == "__main__":
    main()
