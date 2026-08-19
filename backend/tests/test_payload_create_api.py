import sqlite3
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app import main


class PayloadCreateApiTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.original_db_path = main.DB_PATH
        main.DB_PATH = Path(self.tempdir.name) / "payload-create.db"
        connection = sqlite3.connect(main.DB_PATH)
        connection.execute(
            """
            CREATE TABLE payloads (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                vulnerability TEXT NOT NULL,
                category TEXT NOT NULL,
                delivery TEXT NOT NULL,
                target TEXT NOT NULL,
                difficulty TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                archived_from_candidate_id TEXT,
                source_agent TEXT,
                source_candidate_id TEXT,
                iteration_metadata_json TEXT,
                is_pool_snapshot INTEGER NOT NULL DEFAULT 0,
                usage_method TEXT NOT NULL DEFAULT '',
                success_indicators TEXT NOT NULL DEFAULT '',
                is_deleted INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        connection.commit()
        connection.close()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.client.close()
        main.DB_PATH = self.original_db_path
        self.tempdir.cleanup()

    def test_create_payload_supports_schema_without_updated_at(self):
        response = self.client.post(
            "/api/payloads",
            json={
                "name": "SQLi seed",
                "vulnerability": "sql-injection",
                "category": "union",
                "delivery": "query",
                "target": "authorized-lab",
                "difficulty": "custom",
                "content": "1' UNION SELECT 1-- -",
                "usage_method": "Submit through the authorized query parameter.",
                "success_indicators": "The authorized lab returns the controlled row.",
            },
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual(body["name"], "SQLi seed")
        self.assertEqual(body["content"], "1' UNION SELECT 1-- -")
        self.assertNotIn("updated_at", body)


if __name__ == "__main__":
    unittest.main()
