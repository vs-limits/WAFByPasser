"""导入社区主力技法（bypass_techniques.md）到 kb_techniques。

主力军：origin='community'，protected=1，status='seed'（永不淘汰）。

审核规则：
- 12 条非绕过/编码层/传输层条目筛除（见 kb_catalog.COMMUNITY_SKIP）。
- 其余归入「8 机制 × 16 族」（kb_catalog.classify_community_technique）。
- 模板写进 technique_templates（供穷举时 LLM 参考）。

用法（在仓库根目录运行）：
    # 默认读取内置 seed：backend/seeds/bypass_techniques.md
    .venv/Scripts/python.exe backend/scripts/import_community_techniques.py

    # 或指定自定义技法文件路径
    .venv/Scripts/python.exe backend/scripts/import_community_techniques.py /path/to/bypass_techniques.md [--dry-run]
"""

from __future__ import annotations

import argparse
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = REPO_ROOT / "data" / "waf_bypasser.db"
DEFAULT_SEED = REPO_ROOT / "backend" / "seeds" / "bypass_techniques.md"
sys.path.insert(0, str(REPO_ROOT / "backend" / "src"))

from app.knowledge_base_agent.kb_catalog import (  # noqa: E402
    classify_community_technique,
    infer_backend,
    COMMUNITY_SKIP,
)

# 章节标题 -> vulnerability
SECTION_VULN = {
    "SQL": "sql-injection",
    "命令注入": "command-injection",
    "XSS": "xss",
    "文件上传": "file-upload",
    "Log4j2": "log4j",
}

TECHNIQUE_RE = re.compile(r"^###\s+([a-z0-9]+):([a-z0-9]+):([a-z0-9_]+)\s+—\s+(.+)$")
SECTION_RE = re.compile(r"^##\s+(.+)")
FIELD_RE = re.compile(r"^\s*-\s*\*\*\s*(原理|模板|风险)\s*\*\*\s*[:：]\s*(.*)$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_file(text: str) -> tuple[list[dict], list[dict]]:
    """解析 md，返回 (techniques, skipped)。

    每条 technique: {technique_id, name, vulnerability, source_note, templates}
    """
    techniques: list[dict] = []
    skipped: list[dict] = []
    current_vuln = ""
    current: dict | None = None

    for line in text.splitlines():
        stripped = line.strip()

        m = SECTION_RE.match(stripped)
        if m:
            for key, vuln in SECTION_VULN.items():
                if key in m.group(1):
                    current_vuln = vuln
                    break
            continue

        m = TECHNIQUE_RE.match(stripped)
        if m:
            # 收尾上一条
            if current is not None:
                (techniques if current["_keep"] else skipped).append(current)
            prefix, dimension, slug, name = m.group(1), m.group(2), m.group(3), m.group(4)
            technique_id = f"{prefix}:{dimension}:{slug}"
            keep = technique_id not in COMMUNITY_SKIP
            current = {
                "technique_id": technique_id,
                "name": name.strip(),
                "vulnerability": current_vuln,
                "source_note": "",
                "templates": [],
                "_keep": keep,
            }
            continue

        if current is not None:
            fm = FIELD_RE.match(line)
            if fm:
                field, value = fm.group(1), fm.group(2).strip()
                if field == "模板":
                    current["templates"].extend(
                        t.strip(" `。") for t in value.split("、") if t.strip(" `。")
                    )
                elif field == "原理":
                    current["source_note"] = value
            elif current.get("_keep") and stripped.startswith("- **模板**:"):
                # 兼容旧格式（模板行可能是 - **模板**: xxx）
                pass

    if current is not None:
        (techniques if current["_keep"] else skipped).append(current)
    return techniques, skipped


def main() -> None:
    parser = argparse.ArgumentParser(description="导入社区主力技法")
    parser.add_argument(
        "source",
        nargs="?",
        default=str(DEFAULT_SEED),
        help="bypass_techniques.md 路径（默认 backend/seeds/bypass_techniques.md）",
    )
    parser.add_argument("--dry-run", action="store_true", help="只解析不写库")
    args = parser.parse_args()

    source = Path(args.source)
    if not source.exists():
        print(f"错误：文件不存在 {source}")
        sys.exit(1)

    text = source.read_text(encoding="utf-8", errors="replace")
    techniques, skipped = parse_file(text)
    print(f"解析到 {len(techniques) + len(skipped)} 条：导入 {len(techniques)}，筛除 {len(skipped)}")

    unclassified = [t for t in techniques if classify_community_technique(t["technique_id"]) is None]
    if unclassified:
        print(f"\n[警告] {len(unclassified)} 条无法分类（应已在 skip 里）：")
        for t in unclassified:
            print("  -", t["technique_id"])

    # 分布统计
    from collections import Counter
    vuln_stat = Counter(t["vulnerability"] for t in techniques)
    print("\n漏洞分布：")
    for vuln, cnt in sorted(vuln_stat.items()):
        print(f"  {vuln:20} {cnt}")
    mech_stat = Counter(classify_community_technique(t["technique_id"])[0] for t in techniques)
    print("\n机制分布：")
    for mech, cnt in sorted(mech_stat.items()):
        print(f"  {mech:25} {cnt}")

    if args.dry_run:
        print("\n[dry-run] 未写库")
        return

    # 确保 schema 存在
    from app import main as app_main  # noqa: E402
    app_main.initialize_database()

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        timestamp = utc_now()
        inserted = 0
        for t in techniques:
            mechanism_id, family_id = classify_community_technique(t["technique_id"])
            backend = infer_backend(t["technique_id"])
            con.execute(
                """
                INSERT INTO kb_techniques (
                    id, technique_id, name, vulnerability, status, success_count,
                    labels_json, source_note, created_at, updated_at,
                    origin, protected, mechanism_id, family_id, backend,
                    version_gate, composable, priority
                ) VALUES (?, ?, ?, ?, 'seed', 0, '[]', ?, ?, ?, 'community', 1, ?, ?, ?, '', 0, 3)
                ON CONFLICT(technique_id) DO UPDATE SET
                    name = excluded.name,
                    vulnerability = excluded.vulnerability,
                    source_note = excluded.source_note,
                    status = 'seed',
                    origin = 'community',
                    protected = 1,
                    mechanism_id = excluded.mechanism_id,
                    family_id = excluded.family_id,
                    backend = excluded.backend,
                    updated_at = excluded.updated_at
                """,
                (
                    str(uuid.uuid4()),
                    t["technique_id"],
                    t["name"],
                    t["vulnerability"],
                    t["source_note"],
                    timestamp,
                    timestamp,
                    mechanism_id,
                    family_id,
                    backend,
                ),
            )
            # 模板写入 technique_templates
            for payload in t["templates"]:
                if payload:
                    con.execute(
                        "INSERT INTO technique_templates (technique_id, payload, note) VALUES (?, ?, ?)",
                        (t["technique_id"], payload, t["name"]),
                    )
            inserted += 1
        con.commit()
        print(f"\n已写入 {inserted} 条（含模板）")
        print(f"筛除 {len(skipped)} 条：")
        for s in skipped:
            print(f"  - {s['technique_id']}")
    finally:
        con.close()


if __name__ == "__main__":
    main()
