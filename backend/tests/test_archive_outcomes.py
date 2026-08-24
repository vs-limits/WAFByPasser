import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app import main


SCHEMA = """
CREATE TABLE payloads (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, vulnerability TEXT NOT NULL,
    category TEXT NOT NULL, delivery TEXT NOT NULL, target TEXT NOT NULL,
    difficulty TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL,
    archived_from_candidate_id TEXT UNIQUE, source_agent TEXT,
    source_candidate_id TEXT, iteration_metadata_json TEXT,
    is_pool_snapshot INTEGER NOT NULL DEFAULT 0, usage_method TEXT NOT NULL DEFAULT '',
    success_indicators TEXT NOT NULL DEFAULT '', is_deleted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE candidates (
    id TEXT PRIMARY KEY, task_id TEXT NOT NULL, base_payload_id TEXT NOT NULL,
    content TEXT NOT NULL, delivery TEXT NOT NULL, rule_labels_json TEXT NOT NULL,
    explanation TEXT NOT NULL, confidence REAL NOT NULL, status TEXT NOT NULL,
    test_note TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    used_direction_ids_json TEXT NOT NULL DEFAULT '[]',
    next_directions_json TEXT NOT NULL DEFAULT '[]', execution_goal_id TEXT,
    semantic_dimension_ids_json TEXT NOT NULL DEFAULT '[]',
    semantic_delta_json TEXT NOT NULL DEFAULT '{}', verification_spec_json TEXT,
    base_parts_json TEXT NOT NULL DEFAULT '[]', candidate_parts_json TEXT NOT NULL DEFAULT '[]',
    part_operations_json TEXT NOT NULL DEFAULT '[]', parser_confidence TEXT NOT NULL DEFAULT '0',
    parser_status TEXT NOT NULL DEFAULT 'unsupported', unsupported_reason TEXT
);
CREATE TABLE encoding_candidates (
    id TEXT PRIMARY KEY, task_id TEXT NOT NULL, base_payload_id TEXT NOT NULL,
    content TEXT NOT NULL, delivery TEXT NOT NULL, encoding_chain_json TEXT NOT NULL,
    decode_path_json TEXT NOT NULL, rule_labels_json TEXT NOT NULL,
    explanation TEXT NOT NULL, confidence REAL NOT NULL, status TEXT NOT NULL,
    test_note TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    origin TEXT NOT NULL DEFAULT 'generated', migration_note TEXT,
    migrated_from_candidate_id TEXT, used_direction_ids_json TEXT NOT NULL DEFAULT '[]',
    next_directions_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE cross_candidates (id TEXT PRIMARY KEY, status TEXT NOT NULL);
CREATE TABLE iteration_pool_items (
    id TEXT PRIMARY KEY, agent TEXT NOT NULL, status TEXT NOT NULL
);
CREATE TABLE cross_sources (
    id TEXT PRIMARY KEY, archived_payload_id TEXT NOT NULL UNIQUE,
    semantic_candidate_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    vulnerability TEXT NOT NULL, category TEXT NOT NULL, delivery TEXT NOT NULL,
    target TEXT NOT NULL, difficulty TEXT NOT NULL, content TEXT NOT NULL,
    rule_labels_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE success_samples (
    id TEXT PRIMARY KEY, agent TEXT NOT NULL, candidate_id TEXT NOT NULL,
    archived_payload_id TEXT, name TEXT NOT NULL, vulnerability TEXT NOT NULL,
    category TEXT NOT NULL, delivery TEXT NOT NULL, target TEXT NOT NULL,
    difficulty TEXT NOT NULL, content TEXT NOT NULL, test_note TEXT,
    provenance_json TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL, UNIQUE (agent, candidate_id)
);
CREATE TABLE waf_test_runs (
    id TEXT PRIMARY KEY, agent TEXT NOT NULL, candidate_id TEXT NOT NULL,
    base_name TEXT NOT NULL, vulnerability TEXT NOT NULL, payload_snapshot TEXT NOT NULL,
    status TEXT NOT NULL, result TEXT, evidence TEXT, request_summary TEXT,
    response_excerpt TEXT, http_status INTEGER, error_message TEXT,
    created_at TEXT NOT NULL, started_at TEXT, completed_at TEXT
);
CREATE TABLE verification_jobs (
    id TEXT PRIMARY KEY, source_agent TEXT NOT NULL, source_candidate_id TEXT,
    candidate_kind TEXT, base_name TEXT, vulnerability TEXT, payload_snapshot TEXT,
    delivery TEXT, status TEXT NOT NULL, target_key TEXT, created_at TEXT
);
CREATE TABLE bypass_library (
    id TEXT PRIMARY KEY, source_agent TEXT NOT NULL, source_candidate_id TEXT,
    vulnerability TEXT, target_key TEXT, content TEXT, confidence REAL,
    rationale TEXT, provenance_json TEXT, created_at TEXT
);
CREATE TABLE block_library (
    id TEXT PRIMARY KEY, source_agent TEXT NOT NULL, source_candidate_id TEXT,
    vulnerability TEXT, target_key TEXT, content TEXT, confidence REAL,
    rationale TEXT, provenance_json TEXT, failure_stage TEXT, created_at TEXT
);
CREATE TABLE kb_techniques (
    id TEXT PRIMARY KEY, technique_id TEXT, name TEXT, vulnerability TEXT,
    status TEXT, success_count INTEGER, labels_json TEXT, source_note TEXT
);
CREATE TABLE cross_pool_items (
    id TEXT PRIMARY KEY, cross_source_id TEXT NOT NULL,
    status TEXT NOT NULL, task_id TEXT, created_at TEXT, started_at TEXT
);
"""


class ArchiveOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.original_db_path = main.DB_PATH
        self.tempdir = tempfile.TemporaryDirectory()
        main.DB_PATH = Path(self.tempdir.name) / "archive-outcomes.db"
        connection = sqlite3.connect(main.DB_PATH)
        connection.executescript(SCHEMA)
        connection.execute(
            """
            INSERT INTO payloads (
                id, name, vulnerability, category, delivery, target, difficulty,
                content, created_at, iteration_metadata_json, usage_method, success_indicators
            ) VALUES ('base', '基础 Payload', 'sql-injection', '联合查询', 'URL 查询参数',
                      'DVWA', 'Low', '1 UNION SELECT 1', '2026-01-01', '{}',
                      '仅用于授权环境', '出现预期回显')
            """
        )
        connection.commit()
        connection.close()
        self.client = TestClient(main.app)

    def tearDown(self):
        main.DB_PATH = self.original_db_path
        self.tempdir.cleanup()

    def insert_candidate(self, agent: str, candidate_id: str, status: str) -> None:
        connection = sqlite3.connect(main.DB_PATH)
        if agent == "semantic":
            connection.execute(
                """
                INSERT INTO candidates (
                    id, task_id, base_payload_id, content, delivery, rule_labels_json,
                    explanation, confidence, status, test_note, created_at, updated_at,
                    used_direction_ids_json, next_directions_json, part_operations_json
                ) VALUES (?, 'task', 'base', ?, 'URL 查询参数', '["representation"]',
                          'test', 0.9, ?, 'manual', '2026-01-02', '2026-01-02',
                          '["representation"]', '[]', '[]')
                """,
                (candidate_id, f"semantic-{candidate_id}", status),
            )
        else:
            connection.execute(
                """
                INSERT INTO encoding_candidates (
                    id, task_id, base_payload_id, content, delivery, encoding_chain_json,
                    decode_path_json, rule_labels_json, explanation, confidence, status,
                    test_note, created_at, updated_at, used_direction_ids_json,
                    next_directions_json
                ) VALUES (?, 'task', 'base', ?, 'URL 查询参数',
                          '[{"type":"url_percent","mode":"special"}]',
                          '["url_percent"]', '["encoding"]', 'test', 0.9, ?, 'manual',
                          '2026-01-02', '2026-01-02', '["encoding"]', '[]')
                """,
                (candidate_id, f"encoding-{candidate_id}", status),
            )
        connection.commit()
        connection.close()

    def table_rows(self, table: str) -> list[sqlite3.Row]:
        connection = sqlite3.connect(main.DB_PATH)
        connection.row_factory = sqlite3.Row
        rows = connection.execute(f"SELECT * FROM {table}").fetchall()
        connection.close()
        return rows

    def test_semantic_success_archive_creates_all_success_relations(self):
        self.insert_candidate("semantic", "semantic-success", "test_success")

        response = self.client.post("/api/candidates/semantic-success/archive")

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["archive_outcome"], "bypass_success")
        self.assertEqual(len(self.table_rows("cross_sources")), 1)
        # 成功样例功能已移除：归档不再写 success_samples
        self.assertEqual(len(self.table_rows("success_samples")), 0)
        metadata = json.loads(self.table_rows("payloads")[-1]["iteration_metadata_json"])
        self.assertEqual(metadata["archive_outcome"], "bypass_success")
        self.assertEqual(metadata["direction_lineage"][-1]["archive_outcome"], "bypass_success")
        self.assertEqual(
            self.client.post("/api/candidates/semantic-success/archive").status_code,
            409,
        )

    def test_semantic_failure_archive_creates_payload_only(self):
        self.insert_candidate("semantic", "semantic-failure", "test_failed")

        response = self.client.post("/api/candidates/semantic-failure/archive")

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["archive_outcome"], "bypass_failure")
        self.assertEqual(len(self.table_rows("cross_sources")), 0)
        self.assertEqual(len(self.table_rows("success_samples")), 0)
        # 仪表盘口径已改为「自动验证流水线」：bypass/block 库 + 待检验。
        # 手工归档失败候选不再计入 failed。
        semantic_summary = self.client.get("/api/dashboard-summary").json()["agents"]["semantic"]
        self.assertEqual(semantic_summary["success"], 0)
        self.assertEqual(semantic_summary["failed"], 0)

    def test_encoding_archives_keep_success_samples_success_only(self):
        self.insert_candidate("encoding", "encoding-success", "test_success")
        self.insert_candidate("encoding", "encoding-failure", "test_failed")

        success = self.client.post("/api/encoding-candidates/encoding-success/archive")
        failure = self.client.post("/api/encoding-candidates/encoding-failure/archive")

        self.assertEqual(success.json()["archive_outcome"], "bypass_success")
        self.assertEqual(failure.json()["archive_outcome"], "bypass_failure")
        # 成功样例功能已移除：归档不再写 success_samples
        self.assertEqual(len(self.table_rows("success_samples")), 0)
        self.assertEqual(len(self.table_rows("cross_sources")), 0)

    def test_pending_and_rejected_candidates_cannot_be_archived(self):
        self.insert_candidate("semantic", "pending", "pending_test")
        self.insert_candidate("semantic", "rejected", "rejected")

        self.assertEqual(self.client.post("/api/candidates/pending/archive").status_code, 409)
        self.assertEqual(self.client.post("/api/candidates/rejected/archive").status_code, 409)

    def test_legacy_archives_default_to_success_and_manual_payloads_stay_unmarked(self):
        connection = sqlite3.connect(main.DB_PATH)
        connection.execute(
            """
            INSERT INTO payloads (
                id, name, vulnerability, category, delivery, target, difficulty,
                content, created_at, archived_from_candidate_id, source_agent,
                source_candidate_id, iteration_metadata_json
            ) VALUES ('legacy', '旧归档', 'sql-injection', '联合查询', 'URL 查询参数',
                      'DVWA', 'Low', 'legacy', '2026-01-02', 'old-candidate',
                      'semantic', 'old-candidate', '{}')
            """
        )
        connection.commit()
        connection.close()

        payloads = self.client.get("/api/payloads").json()
        outcomes = {payload["id"]: payload["archive_outcome"] for payload in payloads}

        self.assertIsNone(outcomes["base"])
        self.assertEqual(outcomes["legacy"], "bypass_success")
        self.assertEqual(
            self.client.get("/api/payloads/legacy").json()["archive_outcome"],
            "bypass_success",
        )


if __name__ == "__main__":
    unittest.main()
