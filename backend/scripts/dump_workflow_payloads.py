"""生成工作流候选并完整打印 payload 内容 + 检验判定（一次性，跑完删除）。

临时库，真实库不受影响。
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "backend" / "src"))

from app import main  # noqa: E402


def log(msg: str) -> None:
    print(msg, flush=True)


def main_run() -> None:
    real_db = REPO_ROOT / "data" / "waf_bypasser.db"
    tmpdir = tempfile.TemporaryDirectory()
    tmp_db = Path(tmpdir.name) / "waf_bypasser.db"
    shutil.copy2(real_db, tmp_db)
    main.DB_PATH = tmp_db
    main.REPORT_EVIDENCE_ROOT = Path(tmpdir.name) / "report_evidence"
    os.environ["AUTO_VERIFY"] = "true"

    main.initialize_database()
    from fastapi.testclient import TestClient
    client = TestClient(main.app)

    base = client.get("/api/payloads?vulnerability=command-injection&limit=1&cursor=0").json()["items"][0]
    log(f"=== 原语 ===\n{base['content']}\n")

    library_calls = []

    def fake_sync(connection, job, evidence, verdict, timestamp):
        library_calls.append((job["source_agent"], job["source_candidate_id"], verdict.get("bypass_verdict"), verdict.get("execution_verdict")))
        return "dry-run-skip"

    with patch.object(main, "_sync_verification_library", side_effect=fake_sync), \
         patch.object(main, "_update_payload_labels", side_effect=lambda *a, **k: None), \
         patch.object(main, "_promote_techniques", side_effect=lambda *a, **k: None):

        # 语义
        sem_resp = client.post("/api/semantic-iterations", json={"base_payload_id": base["id"], "candidate_count": 3})
        sem_detail = client.get(f"/api/semantic-iterations/{sem_resp.json()['id']}").json()
        sem_candidates = sem_detail.get("candidates", [])

        # 编码
        enc_resp = client.post("/api/encoding-iterations", json={"base_payload_id": base["id"], "candidate_count": 3})
        enc_detail = client.get(f"/api/encoding-iterations/{enc_resp.json()['id']}").json()
        enc_candidates = enc_detail.get("candidates", [])

        # 交叉
        first_sem = sem_candidates[0]
        client.patch(f"/api/candidates/{first_sem['id']}", json={"status": "test_success"})
        client.post(f"/api/candidates/{first_sem['id']}/archive")
        sources = client.get("/api/cross-sources").json()
        cross_candidates = []
        if sources:
            cr = client.post("/api/cross-iterations", json={"cross_source_id": sources[0]["id"], "candidate_count": 2})
            cross_detail = client.get(f"/api/cross-iterations/{cr.json()['id']}").json()
            cross_candidates = cross_detail.get("candidates", [])

        # 检验
        main._verification_worker_loop()

        # 打印
        log("=== 语义候选 ===")
        for i, c in enumerate(sem_candidates):
            verdict = next((v for v in library_calls if v[1] == c["id"]), None)
            log(f"[{i}] 绕过={verdict[2] if verdict else '?'} 执行={verdict[3] if verdict else '?'}")
            log(f"    payload: {c['content']}")
            log("")

        log("=== 编码候选 ===")
        for i, c in enumerate(enc_candidates):
            verdict = next((v for v in library_calls if v[1] == c["id"]), None)
            log(f"[{i}] 绕过={verdict[2] if verdict else '?'} 执行={verdict[3] if verdict else '?'}")
            log(f"    payload: {c['content']}")
            log(f"    编码链: {c.get('encoding_chain')}")
            log("")

        log("=== 交叉候选 ===")
        for i, c in enumerate(cross_candidates):
            verdict = next((v for v in library_calls if v[1] == c["id"]), None)
            log(f"[{i}] 绕过={verdict[2] if verdict else '?'} 执行={verdict[3] if verdict else '?'}")
            log(f"    payload: {c['content']}")
            log(f"    编码链: {c.get('encoding_chain')}")
            log("")

    tmpdir.cleanup()


if __name__ == "__main__":
    main_run()
