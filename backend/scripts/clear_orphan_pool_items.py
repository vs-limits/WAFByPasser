"""清空「待迭代池」中前端不可见的孤儿条目。

iteration_pool_items 中所有条目均为 started 且其关联任务已结束（completed/failed），
当前 UI 只展示 pending（待迭代池）与 started+进行中（进行中任务）两种，因此这些条目
在页面上不可见、也无法操作。本脚本将其备份为 CSV 后删除，使库表与「待迭代池为空」一致。

注意：只删除 iteration_pool_items 行；快照 payload（snapshot_payload_id）仍被
generation_tasks / encoding_tasks / candidates 等引用，必须保留，否则会连带隐藏
仍可见的已归档/已拒绝候选。
"""
from __future__ import annotations

import csv
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = PROJECT_ROOT / "data" / "waf_bypasser.db"
BACKUP_DIR = Path(r"C:\Users\limit\Desktop\暑期Mini项目\旧版成果")


def main() -> int:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    rows = connection.execute(
        "SELECT * FROM iteration_pool_items ORDER BY created_at"
    ).fetchall()
    columns = [r[1] for r in connection.execute("PRAGMA table_info(iteration_pool_items)")]

    if not rows:
        connection.close()
        print("iteration_pool_items 已为空，无需处理。")
        return 0

    backup_path = BACKUP_DIR / "iteration_pool_items_backup.csv"
    with open(backup_path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle, lineterminator="\r\n")
        writer.writerow(columns)
        for record in rows:
            writer.writerow([record[column] for column in columns])

    if not backup_path.exists() or backup_path.stat().st_size == 0:
        print(f"[ABORT] 备份文件为空或不存在: {backup_path}", file=sys.stderr)
        return 1

    # 删除前再核对一次数量，防止中途被并发改动。
    recheck = connection.execute(
        "SELECT COUNT(*) AS n FROM iteration_pool_items"
    ).fetchone()["n"]
    if recheck != len(rows):
        print(f"[ABORT] 删除前数量变化（{recheck}/{len(rows)}），已停止。", file=sys.stderr)
        return 1

    connection.execute("DELETE FROM iteration_pool_items")
    connection.commit()

    remaining = connection.execute(
        "SELECT COUNT(*) AS n FROM iteration_pool_items"
    ).fetchone()["n"]
    # 快照 payload 保留确认
    snapshots = connection.execute(
        "SELECT COUNT(*) AS n FROM payloads WHERE is_pool_snapshot = 1"
    ).fetchone()["n"]
    connection.close()

    print(f"已备份并删除 iteration_pool_items：{len(rows)} 条 -> {backup_path}")
    print(f"删除后 iteration_pool_items 剩余：{remaining} 条")
    print(f"快照 payload 保留：{snapshots} 条（仍被任务/候选引用，未删除）")
    return 0 if remaining == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
