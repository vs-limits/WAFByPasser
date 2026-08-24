"""备份语义迭代 / 编码绕过 Agent 的待测试队列并清空。

将 candidates 与 encoding_candidates 中处于待测试队列状态（pending_test /
test_success / test_failed）的记录，连同其关联的 waf_test_runs 历史，导出为
CSV 到「旧版成果」目录，然后从数据库删除，使两个 Agent 页面的待测试队列变空。

导出的 CSV 采用与既有备份一致的做法：UTF-8 BOM + CRLF 换行、完整列、content 原文。
"""
from __future__ import annotations

import csv
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = PROJECT_ROOT / "data" / "waf_bypasser.db"
BACKUP_DIR = Path(r"C:\Users\limit\Desktop\暑期Mini项目\旧版成果")

QUEUE_STATUSES = ("pending_test", "test_success", "test_failed")


def export_csv(path: Path, columns: list[str], rows: list[sqlite3.Row]) -> int:
    """Write rows as CSV with BOM + CRLF, matching existing backup files."""
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle, lineterminator="\r\n")
        writer.writerow(columns)
        for record in rows:
            writer.writerow([record[column] for column in columns])
    return len(rows)


def main() -> int:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    status_ph = ", ".join("?" for _ in QUEUE_STATUSES)

    # --- 读取待清空集合 ----------------------------------------------------
    semantic_rows = connection.execute(
        f"SELECT * FROM candidates WHERE status IN ({status_ph}) ORDER BY created_at",
        QUEUE_STATUSES,
    ).fetchall()
    encoding_rows = connection.execute(
        f"SELECT * FROM encoding_candidates WHERE status IN ({status_ph}) ORDER BY created_at",
        QUEUE_STATUSES,
    ).fetchall()

    semantic_ids = [row["id"] for row in semantic_rows]
    encoding_ids = [row["id"] for row in encoding_rows]

    waf_run_rows: list[sqlite3.Row] = []
    if semantic_ids:
        ph = ", ".join("?" for _ in semantic_ids)
        waf_run_rows = connection.execute(
            f"SELECT * FROM waf_test_runs WHERE agent = 'semantic' AND candidate_id IN ({ph})",
            semantic_ids,
        ).fetchall()

    columns = {
        "candidates": [r[1] for r in connection.execute("PRAGMA table_info(candidates)")],
        "encoding_candidates": [r[1] for r in connection.execute("PRAGMA table_info(encoding_candidates)")],
        "waf_test_runs": [r[1] for r in connection.execute("PRAGMA table_info(waf_test_runs)")],
    }

    semantic_csv = BACKUP_DIR / "semantic_candidates_queue_backup.csv"
    encoding_csv = BACKUP_DIR / "encoding_candidates_queue_backup.csv"
    waf_runs_csv = BACKUP_DIR / "waf_test_runs_queue_backup.csv"

    export_csv(semantic_csv, columns["candidates"], semantic_rows)
    export_csv(encoding_csv, columns["encoding_candidates"], encoding_rows)
    export_csv(waf_runs_csv, columns["waf_test_runs"], waf_run_rows)

    # --- 导出后校验 -------------------------------------------------------
    for path in (semantic_csv, encoding_csv, waf_runs_csv):
        if not path.exists() or path.stat().st_size == 0:
            print(f"[ABORT] 备份文件为空或不存在: {path}", file=sys.stderr)
            return 1

    # 确认导出期间数据库未被改动（防止 server 干扰导致删错）。
    recheck_semantic = connection.execute(
        f"SELECT COUNT(*) AS n FROM candidates WHERE status IN ({status_ph})", QUEUE_STATUSES
    ).fetchone()["n"]
    recheck_encoding = connection.execute(
        f"SELECT COUNT(*) AS n FROM encoding_candidates WHERE status IN ({status_ph})", QUEUE_STATUSES
    ).fetchone()["n"]
    if recheck_semantic != len(semantic_rows) or recheck_encoding != len(encoding_rows):
        print(
            f"[ABORT] 导出后队列数量发生变化（semantic {recheck_semantic}/{len(semantic_rows)}, "
            f"encoding {recheck_encoding}/{len(encoding_rows)}），已停止，不执行删除。",
            file=sys.stderr,
        )
        return 1

    # --- 删除（单事务）-----------------------------------------------------
    connection.execute("PRAGMA foreign_keys = OFF")
    try:
        if semantic_ids:
            ph = ", ".join("?" for _ in semantic_ids)
            connection.execute(
                f"DELETE FROM waf_test_runs WHERE agent = 'semantic' AND candidate_id IN ({ph})",
                semantic_ids,
            )
            connection.execute(
                f"DELETE FROM candidates WHERE id IN ({ph})", semantic_ids
            )
        if encoding_ids:
            ph = ", ".join("?" for _ in encoding_ids)
            connection.execute(
                f"DELETE FROM encoding_candidates WHERE id IN ({ph})", encoding_ids
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    # --- 终检 --------------------------------------------------------------
    check = sqlite3.connect(DB_PATH)
    check.row_factory = sqlite3.Row
    remaining_semantic = check.execute(
        f"SELECT COUNT(*) AS n FROM candidates WHERE status IN ({status_ph})", QUEUE_STATUSES
    ).fetchone()["n"]
    remaining_encoding = check.execute(
        f"SELECT COUNT(*) AS n FROM encoding_candidates WHERE status IN ({status_ph})", QUEUE_STATUSES
    ).fetchone()["n"]
    check.close()

    print(f"语义迭代 Agent：备份 {len(semantic_rows)} 条候选 + {len(waf_run_rows)} 条 WAF 测试记录")
    print(f"编码绕过 Agent：备份 {len(encoding_rows)} 条候选")
    print("备份目录:", BACKUP_DIR)
    print(f"删除后队列剩余 -> 语义 {remaining_semantic} 条，编码 {remaining_encoding} 条")
    if remaining_semantic or remaining_encoding:
        print("[WARN] 队列未完全清空！", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
