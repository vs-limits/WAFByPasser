"""将本地知识库手法全量导出为可版本管理的 Markdown 和 JSON。

默认从 ``data/waf_bypasser.db`` 读取 ``kb_techniques``，输出到
``backend/seeds/knowledge_base_techniques.{md,json}``。数据库本身包含运行状态，
不应提交到 Git；导出文件用于审阅、备份和跨环境迁移。
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = REPO_ROOT / "data" / "waf_bypasser.db"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "backend" / "seeds"

VULNERABILITY_LABELS = {
    "command-injection": "命令注入",
    "sql-injection": "SQL 注入",
    "xss": "XSS",
    "file-upload": "文件上传",
    "log4j": "Log4j",
}
VULNERABILITY_ORDER = tuple(VULNERABILITY_LABELS)

EXPORT_FIELDS = (
    "technique_id",
    "name",
    "vulnerability",
    "status",
    "success_count",
    "labels_json",
    "source_note",
    "principle",
    "template",
    "origin",
    "protected",
    "mechanism_id",
    "family_id",
    "backend",
    "version_gate",
    "composable",
    "priority",
    "bypass_count",
    "attempt_count",
    "distinct_primitive_count",
    "retired_at",
    "created_at",
    "updated_at",
)


def load_techniques(database: Path) -> list[dict[str, Any]]:
    if not database.exists():
        raise FileNotFoundError(f"知识库数据库不存在：{database}")

    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(kb_techniques)")
        }
        if not columns:
            raise RuntimeError("数据库中不存在 kb_techniques 表")
        missing = set(EXPORT_FIELDS) - columns
        if missing:
            raise RuntimeError(f"kb_techniques 缺少字段：{', '.join(sorted(missing))}")

        fields = ", ".join(EXPORT_FIELDS)
        records = connection.execute(
            f"SELECT {fields} FROM kb_techniques "
            "ORDER BY vulnerability, technique_id"  # noqa: S608 - 固定字段列表
        ).fetchall()
    finally:
        connection.close()

    techniques: list[dict[str, Any]] = []
    for record in records:
        item = dict(record)
        try:
            item["labels"] = json.loads(item.pop("labels_json") or "[]")
        except json.JSONDecodeError:
            item["labels"] = []
        item["protected"] = bool(item["protected"])
        item["composable"] = bool(item["composable"])
        techniques.append(item)
    return techniques


def build_snapshot(techniques: list[dict[str, Any]]) -> dict[str, Any]:
    vulnerability_counts = Counter(item["vulnerability"] for item in techniques)
    status_counts = Counter(item["status"] for item in techniques)
    origin_counts = Counter(item["origin"] for item in techniques)
    return {
        "schema_version": 1,
        "total": len(techniques),
        "counts": {
            "vulnerability": dict(sorted(vulnerability_counts.items())),
            "status": dict(sorted(status_counts.items())),
            "origin": dict(sorted(origin_counts.items())),
        },
        "techniques": techniques,
    }


def markdown_value(value: Any) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "-"
    return str(value).replace("\r", " ").replace("\n", " ").strip() or "-"


def build_markdown(snapshot: dict[str, Any]) -> str:
    counts = snapshot["counts"]
    lines = [
        "# 知识库手法全量快照",
        "",
        "> 本文件由 `backend/scripts/export_knowledge_base.py` 从本地知识库自动生成。",
        "> 请勿手工编辑；更新知识库后重新运行导出脚本。",
        "",
        f"- 手法总数：{snapshot['total']}",
        "- 漏洞分布："
        + "、".join(
            f"{VULNERABILITY_LABELS.get(key, key)} {value}"
            for key, value in counts["vulnerability"].items()
        ),
        "- 状态分布："
        + "、".join(f"{key} {value}" for key, value in counts["status"].items()),
        "- 来源分布："
        + "、".join(f"{key} {value}" for key, value in counts["origin"].items()),
        "",
    ]

    by_vulnerability: dict[str, list[dict[str, Any]]] = {
        key: [] for key in VULNERABILITY_ORDER
    }
    for item in snapshot["techniques"]:
        by_vulnerability.setdefault(item["vulnerability"], []).append(item)

    for vulnerability in VULNERABILITY_ORDER:
        items = by_vulnerability.get(vulnerability, [])
        if not items:
            continue
        lines.extend(
            [
                f"## {VULNERABILITY_LABELS[vulnerability]}（{len(items)} 条）",
                "",
            ]
        )
        for item in sorted(items, key=lambda value: value["technique_id"]):
            lines.extend(
                [
                    f"### `{item['technique_id']}` — {markdown_value(item['name'])}",
                    "",
                    f"- **状态**：{markdown_value(item['status'])}",
                    f"- **来源**：{markdown_value(item['origin'])}",
                    f"- **机制/族**：{markdown_value(item['mechanism_id'])} / "
                    f"{markdown_value(item['family_id'])}",
                    f"- **后端/版本门槛**：{markdown_value(item['backend'])} / "
                    f"{markdown_value(item['version_gate'])}",
                    f"- **原理**：{markdown_value(item['principle'])}",
                    f"- **模板**：{markdown_value(item['template'])}",
                    f"- **来源备注**：{markdown_value(item['source_note'])}",
                    f"- **属性**：protected={markdown_value(item['protected'])}；"
                    f"composable={markdown_value(item['composable'])}；"
                    f"priority={markdown_value(item['priority'])}；"
                    f"labels={markdown_value(item['labels'])}",
                    f"- **统计**：success={item['success_count']}；"
                    f"bypass={item['bypass_count']}；attempt={item['attempt_count']}；"
                    f"distinct_primitive={item['distinct_primitive_count']}",
                    f"- **时间**：created={markdown_value(item['created_at'])}；"
                    f"updated={markdown_value(item['updated_at'])}；"
                    f"retired={markdown_value(item['retired_at'])}",
                    "",
                ]
            )
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="全量导出知识库手法")
    parser.add_argument("--database", type=Path, default=DEFAULT_DB)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    techniques = load_techniques(args.database.resolve())
    snapshot = build_snapshot(techniques)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    json_path = args.output_dir / "knowledge_base_techniques.json"
    markdown_path = args.output_dir / "knowledge_base_techniques.md"
    json_path.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(build_markdown(snapshot), encoding="utf-8")

    print(f"已导出 {snapshot['total']} 条知识库手法")
    print(f"JSON: {json_path}")
    print(f"Markdown: {markdown_path}")


if __name__ == "__main__":
    main()
