import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main


class PerformanceApiTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.original_db_path = main.DB_PATH
        main.DB_PATH = Path(self.tempdir.name) / "performance.db"
        self._create_schema()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.client.close()
        main.DB_PATH = self.original_db_path
        self.tempdir.cleanup()

    def _create_schema(self):
        connection = sqlite3.connect(main.DB_PATH)
        connection.executescript(
            """
            CREATE TABLE payloads (
                id TEXT PRIMARY KEY, name TEXT, vulnerability TEXT, category TEXT,
                delivery TEXT, target TEXT, difficulty TEXT, content TEXT,
                usage_method TEXT, success_indicators TEXT, iteration_metadata_json TEXT,
                source_agent TEXT, source_candidate_id TEXT, is_pool_snapshot INTEGER,
                is_deleted INTEGER, created_at TEXT
            );
            CREATE TABLE candidates (
                id TEXT PRIMARY KEY, base_payload_id TEXT, content TEXT, delivery TEXT,
                rule_labels_json TEXT, status TEXT, created_at TEXT
            );
            CREATE TABLE encoding_candidates (id TEXT PRIMARY KEY, status TEXT);
            CREATE TABLE cross_candidates (id TEXT PRIMARY KEY, status TEXT);
            CREATE TABLE iteration_pool_items (id TEXT PRIMARY KEY, agent TEXT, status TEXT);
            CREATE TABLE waf_test_runs (
                id TEXT PRIMARY KEY, agent TEXT, candidate_id TEXT, created_at TEXT, status TEXT
            );
            CREATE TABLE success_samples (
                id TEXT PRIMARY KEY, agent TEXT, vulnerability TEXT, target TEXT,
                delivery TEXT, status TEXT, provenance_json TEXT, created_at TEXT
            );
            """
        )
        connection.execute(
            "INSERT INTO payloads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("payload-1", "Base", "sql-injection", "base", "query", "DVWA", "Low", "x", "", "", "{}", None, None, 0, 0, "2026-01-01"),
        )
        for number in range(3):
            candidate_id = f"candidate-{number}"
            connection.execute(
                "INSERT INTO candidates VALUES (?, ?, ?, ?, ?, ?, ?)",
                (candidate_id, "payload-1", f"payload-{number}", "query", "[]", "pending_test", f"2026-01-0{number + 1}"),
            )
            connection.execute(
                "INSERT INTO waf_test_runs VALUES (?, ?, ?, ?, ?)",
                (f"run-{number}", "semantic", candidate_id, f"2026-01-0{number + 1}", "completed"),
            )
        connection.execute(
            "INSERT INTO success_samples VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("sample-1", "semantic", "sql-injection", "DVWA", "query", "active", "{}", "2026-01-01"),
        )
        connection.commit()
        connection.close()

    def test_candidate_page_uses_a_single_latest_waf_lookup(self):
        with patch.object(main, "latest_waf_runs", wraps=main.latest_waf_runs) as lookup:
            response = self.client.get("/api/candidates?limit=2&cursor=0")
        self.assertEqual(response.status_code, 200)
        page = response.json()
        self.assertEqual(page["total"], 3)
        self.assertEqual(len(page["items"]), 2)
        self.assertEqual(page["next_cursor"], 2)
        self.assertEqual(lookup.call_count, 1)

    def test_success_sample_page_preserves_filters(self):
        response = self.client.get("/api/success-samples?agent=semantic&limit=50&cursor=0")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total"], 1)
        self.assertEqual(response.json()["items"][0]["id"], "sample-1")

    def test_startup_creates_performance_indexes(self):
        with TestClient(main.app):
            pass
        connection = sqlite3.connect(main.DB_PATH)
        names = {row[1] for row in connection.execute("PRAGMA index_list(waf_test_runs)")}
        names.update(row[1] for row in connection.execute("PRAGMA index_list(success_samples)"))
        connection.close()
        self.assertIn("idx_waf_test_runs_candidate_latest", names)
        self.assertIn("idx_success_samples_active_created", names)


if __name__ == "__main__":
    unittest.main()
