import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main


class WafTestRunApiTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.original_db_path = main.DB_PATH
        main.DB_PATH = Path(self.tempdir.name) / "waf-test.db"
        connection = sqlite3.connect(main.DB_PATH)
        connection.executescript(
            """
            CREATE TABLE payloads (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                vulnerability TEXT NOT NULL,
                target TEXT NOT NULL
            );
            CREATE TABLE candidates (
                id TEXT PRIMARY KEY,
                base_payload_id TEXT NOT NULL,
                content TEXT NOT NULL,
                verification_spec_json TEXT
            );
            CREATE TABLE waf_test_runs (
                id TEXT PRIMARY KEY,
                agent TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                base_name TEXT NOT NULL,
                vulnerability TEXT NOT NULL,
                payload_snapshot TEXT NOT NULL,
                status TEXT NOT NULL,
                result TEXT,
                evidence TEXT,
                request_summary TEXT,
                response_excerpt TEXT,
                http_status INTEGER,
                error_message TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT
            );
            """
        )
        connection.execute(
            "INSERT INTO payloads VALUES (?, ?, ?, ?)",
            ("payload-1", "Semantic base", "sql-injection", "DVWA"),
        )
        connection.execute(
            "INSERT INTO candidates VALUES (?, ?, ?, ?)",
            ("candidate-1", "payload-1", "1' OR '1'='1", None),
        )
        connection.commit()
        connection.close()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.client.close()
        main.DB_PATH = self.original_db_path
        self.tempdir.cleanup()

    @patch("app.main.start_background_thread")
    def test_semantic_candidate_can_be_queued_for_waf_testing(self, start_thread):
        response = self.client.post(
            "/api/waf-test-runs",
            json={"agent": "semantic", "candidate_id": "candidate-1"},
        )

        self.assertEqual(response.status_code, 202)
        body = response.json()
        self.assertEqual(body["status"], "queued")
        self.assertEqual(body["agent"], "semantic")
        self.assertEqual(body["candidate_id"], "candidate-1")
        self.assertEqual(body["payload_snapshot"], "1' OR '1'='1")
        start_thread.assert_called_once_with(main.run_waf_test, body["id"])

    @patch("app.main.start_background_thread")
    def test_direct_waf_run_keeps_candidate_identity(self, start_thread):
        response = self.client.post(
            "/api/waf-test-runs/direct",
            json={
                "target": "tencent-waf",
                "content": "1' OR '1'='1",
                "name": "Semantic base",
                "agent": "semantic",
                "candidate_id": "candidate-1",
                "vulnerability": "sql-injection",
            },
        )

        self.assertEqual(response.status_code, 202)
        body = response.json()
        self.assertEqual(body["candidate_id"], "candidate-1")
        self.assertEqual(body["vulnerability"], "sql-injection")
        start_thread.assert_called_once_with(
            main.run_direct_waf_test,
            body["id"],
            "tencent-waf",
            "1' OR '1'='1",
        )

    @patch("app.main.run_waf_test")
    def test_create_response_does_not_wait_for_slow_waf_worker(self, run_waf_test):
        started = threading.Event()
        release = threading.Event()

        def slow_worker(_run_id):
            started.set()
            release.wait(1)

        run_waf_test.side_effect = slow_worker
        began = time.perf_counter()
        try:
            response = self.client.post(
                "/api/waf-test-runs",
                json={"agent": "semantic", "candidate_id": "candidate-1"},
            )
            elapsed = time.perf_counter() - began
            self.assertEqual(response.status_code, 202)
            self.assertTrue(started.wait(0.5))
            self.assertLess(elapsed, 0.5)
        finally:
            release.set()


if __name__ == "__main__":
    unittest.main()
