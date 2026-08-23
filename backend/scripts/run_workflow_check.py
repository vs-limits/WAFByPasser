"""完整工作流验证脚本（一次性，跑完删除）。

流程：取 payload 库第一条命令注入 → 语义迭代 → 编码迭代 → 正向交叉迭代，
每个 agent 生成的 candidate 自动路由到检验 agent，但 monkey-patch 掉三库投影，
使检验结果不计入 bypass/block/unverified 库，也不改 payload 标签、不转正技巧。

用临时 DB（复制真实库），跑完丢弃，真实库不受影响。
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

    payloads = client.get("/api/payloads?vulnerability=command-injection&limit=1&cursor=0").json()
    if not payloads["items"]:
        log("[X] payload 库没有命令注入 payload")
        return
    base = payloads["items"][0]
    log(f"[OK] 原语: {base['content']!r}")

    library_calls = []
    label_calls = []
    promote_calls = []

    def fake_sync(connection, job, evidence, verdict, timestamp):
        library_calls.append((job["source_agent"], job["source_candidate_id"], verdict.get("bypass_verdict"), verdict.get("execution_verdict")))
        return "dry-run-skip"

    def fake_update_labels(connection, payload_id, verdict):
        label_calls.append((payload_id, verdict.get("bypass_verdict"), verdict.get("execution_verdict")))

    def fake_promote(connection, job, verdict, timestamp):
        promote_calls.append((job["source_agent"], verdict.get("bypass_verdict"), verdict.get("execution_verdict")))

    with patch.object(main, "_sync_verification_library", side_effect=fake_sync), \
         patch.object(main, "_update_payload_labels", side_effect=fake_update_labels), \
         patch.object(main, "_promote_techniques", side_effect=fake_promote):

        log("\n=== 步骤1：语义迭代 ===")
        sem_resp = client.post("/api/semantic-iterations", json={"base_payload_id": base["id"], "candidate_count": 3})
        sem_task_id = sem_resp.json().get("id")
        sem_detail = client.get(f"/api/semantic-iterations/{sem_task_id}").json()
        sem_candidates = sem_detail.get("candidates", [])
        log(f"  语义任务: {sem_detail.get('status')} 候选数 {len(sem_candidates)}")
        if not sem_candidates:
            log(f"  [X] 语义失败: {sem_detail.get('error_message')}")
            return

        log("\n=== 步骤2：编码迭代 ===")
        enc_resp = client.post("/api/encoding-iterations", json={"base_payload_id": base["id"], "candidate_count": 3})
        enc_task_id = enc_resp.json().get("id")
        enc_detail = client.get(f"/api/encoding-iterations/{enc_task_id}").json()
        enc_candidates = enc_detail.get("candidates", [])
        log(f"  编码任务: {enc_detail.get('status')} 候选数 {len(enc_candidates)}")

        log("\n=== 步骤3：正向交叉迭代 ===")
        first_sem = sem_candidates[0]
        client.patch(f"/api/candidates/{first_sem['id']}", json={"status": "test_success", "test_note": "workflow-check"})
        client.post(f"/api/candidates/{first_sem['id']}/archive")
        sources = client.get("/api/cross-sources").json()
        cross_candidates = []
        if sources:
            source_id = sources[0]["id"]
            cross_resp = client.post("/api/cross-iterations", json={"cross_source_id": source_id, "candidate_count": 2})
            cross_detail = client.get(f"/api/cross-iterations/{cross_resp.json().get('id')}").json()
            cross_candidates = cross_detail.get("candidates", [])
            log(f"  交叉任务: {cross_detail.get('status')} 候选数 {len(cross_candidates)}")

        log("\n=== 步骤4：检验 agent ===")
        queued = client.get("/api/verification-jobs?status=queued").json()
        if isinstance(queued, dict):
            queued = queued["items"]
        log(f"  待检验: {len(queued)} 条")
        main._verification_worker_loop()
        completed = client.get("/api/verification-jobs").json()
        if isinstance(completed, dict):
            completed = completed["items"]
        log(f"  检验完成: {len(completed)} 条")

        log("\n=== 步骤5：三库未写入 ===")
        for lib, endpoint in [("bypass库", "/api/bypass-library"), ("block库", "/api/block-library"), ("待人工验证", "/api/unverified-library")]:
            r = client.get(endpoint).json()
            count = r.get("total", len(r) if isinstance(r, list) else 0) if isinstance(r, dict) else len(r)
            log(f"  {lib}: {count} 条")

        log("\n=== 完整性汇总 ===")
        total = len(sem_candidates) + len(enc_candidates) + len(cross_candidates)
        log(f"  生成候选总数: {total}（语义 {len(sem_candidates)} / 编码 {len(enc_candidates)} / 交叉 {len(cross_candidates)}）")
        log(f"  检验判定次数: {len(library_calls)}")
        for agent, cid, bypass, exec_ in library_calls:
            log(f"    [{agent}] {cid[:8]} bypass={bypass} execution={exec_}")

    tmpdir.cleanup()
    log("\n[OK] 工作流检查完成")


if __name__ == "__main__":
    main_run()
