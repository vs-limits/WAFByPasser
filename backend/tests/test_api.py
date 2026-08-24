import json
import os
import tempfile
import unittest
import sqlite3
from pathlib import Path
from unittest.mock import ANY, Mock, patch

from fastapi.testclient import TestClient

from app import main
from app.encoding_agent.encoding import (
    ENCODING_CATALOG,
    ENCODINGS,
    _chain_has_lossy,
    _lossy_normalize,
    allowed_encoding_catalog,
    expected_decode_path,
    replay_encoding_chain,
    reverse_encoding_chain,
    validate_encoding_candidates,
)
from app.encoding_agent.prompts import build_encoding_system_prompt
from app.semantic_agent.prompts import build_system_prompt
from app.semantic_agent.parts import parse_semantic_parts, recompose_semantic_parts


def _mock_part_ops(base_content: str, vuln: str, index: int) -> dict:
    """Generate a valid part_operations mock response for testing.

    Creates a simple replace op on a non-required part if available,
    otherwise falls back to a comment addition.
    """
    parsed = parse_semantic_parts(base_content, vuln, "URL 查询参数")
    parts = parsed["parts"]

    # Find a non-required part to replace; if none, use a required part with equivalent value
    target = None
    for p in parts:
        if not p["required"] and p["part_id"] not in ("pm",):
            target = p
            break

    ops: list[dict] = []
    if target:
        # 变异值用 `m` + 递增个 `x` 制造骨架唯一 token（避免与 base 中的
        # 数字/字母撞出相同的 alnum 骨架，被语义骨架去重条件误杀）。
        ops = [{"operation": "replace", "part_id": target["part_id"],
                "part_type": target["part_type"],
                "value": f"{target['raw']}m{'x' * (index + 1)}",
                "reason": "test mutation"}]
    else:
        # No non-required part — use the last part with an equivalent variant
        if parts:
            last = parts[-1]
            if last["part_type"] == "comment_terminator":
                variants = ["--", "#", "/**/"]
                new_val = variants[index % len(variants)]
            else:
                new_val = f"{last['raw']}m{'x' * (index + 1)}"
            ops = [{"operation": "replace", "part_id": last["part_id"],
                    "part_type": last["part_type"],
                    "value": new_val,
                    "reason": "equivalent replacement"}]

    # Pick valid directions based on vuln type, vary per index for uniqueness
    dir_pool = {
        "command-injection": ["part:argument-change", "part:separator-change", "part:command-equivalent", "part:ifs-change", "part:control-add"],
        "sql-injection": ["part:predicate-rewrite", "part:operator-switch", "part:comment-change", "part:ws-change", "part:value-rewrite"],
        "xss": ["part:tag-switch", "part:event-switch", "part:expression-rewrite", "part:closure-change", "part:spacing-change"],
    }
    pool = dir_pool.get(vuln, ["part:argument-change"])
    direction_id = pool[index % len(pool)]

    return {
        "part_operations": ops,
        "direction_ids": [direction_id],
        "rule_labels": [direction_id],
        "explanation": f"test candidate {index}",
    }


def _mock_candidates(base_content: str, vuln: str, count: int) -> list[dict]:
    """Generate N valid part_operations-based candidates for testing."""
    return [_mock_part_ops(base_content, vuln, i) for i in range(count)]


class ApiLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.original_db_path = main.DB_PATH
        self.original_report_evidence_root = main.REPORT_EVIDENCE_ROOT
        self.original_auto_verify = os.environ.get("AUTO_VERIFY")
        os.environ["AUTO_VERIFY"] = "false"  # 测试环境禁用自动检验，避免真实靶场请求
        self.tempdir = tempfile.TemporaryDirectory()
        main.DB_PATH = Path(self.tempdir.name) / "test.db"
        main.REPORT_EVIDENCE_ROOT = Path(self.tempdir.name) / "report_evidence"
        main.initialize_database()
        self._seed_payloads()
        self._seed_techniques()
        self.client = TestClient(main.app)

    def _seed_payloads(self) -> None:
        """Insert seed payloads so list-first lookups don't hit an empty DB.

        Insertion order (oldest → newest) leaves `command-injection` at the head
        of ``GET /api/payloads`` (ordered by created_at DESC), which is what most
        generation tests read via ``[0]``.
        """
        seeds = [
            ("file-upload", "表单字段", "shell.php", 1),
            ("sql-injection", "URL 查询参数", "1' UNION SELECT 1--", 2),
            ("xss", "表单字段", "<script>alert(1)</script>", 3),
            ("command-injection", "表单字段", "127.0.0.1; id", 4),
        ]
        with main.connect() as connection:
            for vulnerability, delivery, content, seq in seeds:
                connection.execute(
                    """
                    INSERT INTO payloads (
                        id, name, vulnerability, category, delivery, target,
                        difficulty, content, created_at, severity, is_executable,
                        usage_method, success_indicators, is_deleted
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '中危', 1, '', '', 0)
                    """,
                    (
                        f"seed-{vulnerability}",
                        f"Seed {vulnerability}",
                        vulnerability,
                        "",
                        delivery,
                        "authorized-lab",
                        "low",
                        content,
                        f"2026-01-0{seq}T00:00:00Z",
                    ),
                )

    def _seed_techniques(self) -> None:
        """给测试库预置学习技法（origin='generated'），让生成遍历有数据可消费。

        原先「空库回退默认 5 条」已被移除，改为「遍历知识库手法」——预置
        semantic/encoding 各若干条，使生成测试回到「有候选可走 archive/delete
        等生命周期」的状态，数量可预测。
        """
        rows = []
        # command-injection：semantic 5 条（对应原回退 5 条）+ encoding 若干。
        for i in range(5):
            rows.append(
                (
                    f"cmdi:semantic:seed_{i}",
                    "command-injection",
                    "semantic",
                    f"语义手法 {i}",
                )
            )
        for i in range(3):
            rows.append(
                (
                    f"cmdi:lexical:seed_{i}",
                    "command-injection",
                    "encoding",
                    f"编码手法 {i}",
                )
            )
        # 其余漏洞类型各预置少量，保证 sql-injection/xss 遍历也有候选。
        for vuln, prefix in (("sql-injection", "sqli"), ("xss", "xss")):
            for i in range(3):
                rows.append(
                    (
                        f"{prefix}:semantic:seed_{i}",
                        vuln,
                        "semantic",
                        f"语义手法 {i}",
                    )
                )
        timestamp = main.utc_now()
        with main.connect() as connection:
            for tid, vuln, dim, name in rows:
                connection.execute(
                    """
                    INSERT INTO kb_techniques (
                        id, technique_id, name, vulnerability, status, success_count,
                        labels_json, source_note, principle, template, created_at, updated_at,
                        origin, protected, mechanism_id, family_id, backend
                    ) VALUES (?, ?, ?, ?, 'frontier', 0, '[]', '', '', '', ?, ?, 'generated', 0, ?, ?, 'generic')
                    """,
                    (
                        f"id-{tid}",
                        tid,
                        name,
                        vuln,
                        timestamp,
                        timestamp,
                        "equivalent-substitution",
                        "function-swap",
                    ),
                )
            connection.commit()

    def tearDown(self):
        main.DB_PATH = self.original_db_path
        main.REPORT_EVIDENCE_ROOT = self.original_report_evidence_root
        if self.original_auto_verify is None:
            os.environ.pop("AUTO_VERIFY", None)
        else:
            os.environ["AUTO_VERIFY"] = self.original_auto_verify
        try:
            self.tempdir.cleanup()
        except PermissionError:
            # Windows may release SQLite's final test handle after interpreter shutdown.
            pass

    def _create_success_sample(self) -> dict:
        sample_id = "sample-" + main.uuid.uuid4().hex
        timestamp = main.now()
        with main.connect() as connection:
            connection.execute(
                """
                INSERT INTO success_samples (
                    id, agent, candidate_id, archived_payload_id, name, vulnerability,
                    category, delivery, target, difficulty, content, test_note,
                    provenance_json, status, created_at, updated_at
                ) VALUES (?, 'semantic', ?, NULL, ?, 'command-injection', ?, ?, ?, '', ?, ?, ?, 'active', ?, ?)
                """,
                (
                    sample_id, "candidate-" + sample_id, "授权验证样例", "基础命令",
                    "表单字段", "DVWA", "127.0.0.1; id", "已确认 uid= 回显",
                    json.dumps({"rule_labels": ["execution:goal"]}, ensure_ascii=False),
                    timestamp, timestamp,
                ),
            )
        return next(item for item in self.client.get("/api/success-samples").json() if item["id"] == sample_id)

    def test_waf_scene_reflects_dvwa_configuration_only(self):
        scenarios = (
            ("dvwa", True),
            ("none", False),
        )
        for name, dvwa_configured in scenarios:
            with self.subTest(name=name):
                config_path = Path(self.tempdir.name) / f"{name}.env"
                config_path.write_text(
                    "\n".join((
                        "WAF_DVWA_BASE_URL=http://127.0.0.1:81" if dvwa_configured else "",
                        "WAF_DVWA_USERNAME=admin" if dvwa_configured else "",
                        "WAF_DVWA_PASSWORD=password" if dvwa_configured else "",
                    )),
                    encoding="utf-8",
                )
                with (
                    patch.dict(os.environ, {}, clear=True),
                    patch.object(main, "CONFIG_PATH", config_path),
                ):
                    response = self.client.get("/api/waf-test-scene")
                self.assertEqual(response.status_code, 200)
                scene = response.json()
                self.assertEqual(scene["dvwa"]["configured"], dvwa_configured)
                self.assertEqual(scene["configured"], dvwa_configured)
                self.assertNotIn("tencent_waf", scene)
                self.assertNotIn("direct_targets", scene)

    def test_semantic_agent_documents_are_available(self):
        documents = self.client.get("/api/semantic-agent/documents").json()
        self.assertEqual(len(documents), 8)
        self.assertEqual(documents[-1]["kind"], "prompt")

    def test_llm_prompt_loads_all_active_skills(self):
        prompt = build_system_prompt()
        self.assertIn("部件操作", prompt)
        self.assertIn("漏洞语义理解 Skill", prompt)
        self.assertIn("命令注入语义变异 Skill", prompt)
        self.assertIn("SQL 注入语义变异 Skill", prompt)
        self.assertIn("XSS 语义变异 Skill", prompt)
        self.assertIn("过滤规则逆向 Skill", prompt)
        self.assertIn("上下文感知 Skill", prompt)
        self.assertIn("漏洞验证推理 Skill", prompt)
        self.assertIn("part_operations", prompt)

    def test_encoding_prompt_loads_all_active_skills(self):
        prompt = build_encoding_system_prompt(3)
        self.assertIn("编码上下文理解", prompt)
        self.assertIn("编码策略与组合", prompt)
        self.assertIn("规范化与解码路径推理", prompt)
        self.assertIn("语义保持与重放验证", prompt)
        self.assertIn("候选审阅与反馈迭代", prompt)
        self.assertIn("恰好 3 条编码候选", prompt)

        documents = self.client.get("/api/encoding-agent/documents").json()
        self.assertEqual(len(documents), 6)
        self.assertEqual(documents[-1]["kind"], "prompt")

    def test_all_encoding_steps_and_two_layer_chain_are_reversible(self):
        original = "A <& 中"
        for encoding_type, modes in ENCODING_CATALOG.items():
            for mode in modes:
                chain = [{"type": encoding_type, "mode": mode}]
                try:
                    encoded = replay_encoding_chain(original, chain)
                except ValueError:
                    # 某些编码（如 cp037 代码页）本质上无法表示非 ASCII 输入；
                    # 生产路径（build_cross_candidates）对无法编码的链会静默跳过。
                    self.assertTrue(encoding_type in ENCODINGS)
                    continue
                reversed_value = reverse_encoding_chain(encoded, chain)
                has_lossy, has_case = _chain_has_lossy(chain)
                if has_lossy:
                    self.assertEqual(
                        _lossy_normalize(reversed_value, has_case),
                        _lossy_normalize(original, has_case),
                        encoding_type,
                    )
                else:
                    self.assertEqual(reversed_value, original, encoding_type)

        chain = [
            {"type": "url", "mode": "full"},
            {"type": "base64", "mode": "full"},
        ]
        encoded = replay_encoding_chain(original, chain)
        self.assertEqual(reverse_encoding_chain(encoded, chain), original)

    def test_semantic_candidate_repairs_only_unambiguous_execution_goal_tail(self):
        from app.execution_goals import normalize_execution_goal_id
        # Unambiguous tail truncation (1-2 chars) is repaired
        self.assertEqual(normalize_execution_goal_id("file:passw"), "file:passwd")
        # Short truncations (3+ chars) are NOT repaired
        self.assertNotEqual(normalize_execution_goal_id("file:pas"), "file:passwd")

    def _encoding_payload(self):
        return next(
            payload
            for payload in self.client.get("/api/payloads").json()
            if payload["vulnerability"] == "command-injection"
        )

    @staticmethod
    def _encoding_candidates(base_payload, count=3):
        # 返回「编码意图」（重构后 LLM 只输出意图，后端确定性生成 content）
        intents = [
            {"intent": "full", "encoding_type": "url", "submode": None, "chain": None, "explanation": "可逆编码，仅用于人工靶场验证。", "confidence": 0.4},
            {"intent": "full", "encoding_type": "base64", "submode": None, "chain": None, "explanation": "可逆编码，仅用于人工靶场验证。", "confidence": 0.4},
            {"intent": "nested", "encoding_type": None, "submode": None, "chain": [{"type": "url", "mode": "full"}, {"type": "base64", "mode": "full"}], "explanation": "可逆编码，仅用于人工靶场验证。", "confidence": 0.4},
        ]
        return intents[:count]

    @patch("app.main.call_encoding_model")
    def test_encoding_generation_manual_archive_and_provenance(self, model_call):
        payload = self._encoding_payload()
        model_call.return_value = self._encoding_candidates(payload["content"])
        task_response = self.client.post(
            "/api/encoding-iterations",
            json={"base_payload_id": payload["id"]},
        )
        self.assertEqual(task_response.status_code, 202)
        task = self.client.get(f"/api/encoding-iterations/{task_response.json()['id']}").json()
        self.assertEqual(task["status"], "completed")
        self.assertEqual(len(task["candidates"]), 3)

        candidate = task["candidates"][0]
        self.assertEqual(
            self.client.post(f"/api/encoding-candidates/{candidate['id']}/archive").status_code,
            409,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/encoding-candidates/{candidate['id']}",
                json={"status": "test_success", "test_note": "manual local check"},
            ).status_code,
            200,
        )
        reverted = self.client.patch(
            f"/api/encoding-candidates/{candidate['id']}",
            json={"status": "pending_test", "test_note": "manual local check"},
        )
        self.assertEqual(reverted.status_code, 200)
        self.assertEqual(reverted.json()["status"], "pending_test")
        self.assertEqual(reverted.json()["test_note"], "manual local check")
        self.assertEqual(
            self.client.post(f"/api/encoding-candidates/{candidate['id']}/archive").status_code,
            409,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/encoding-candidates/{candidate['id']}",
                json={"status": "test_success", "test_note": "manual local check"},
            ).status_code,
            200,
        )
        archived = self.client.post(f"/api/encoding-candidates/{candidate['id']}/archive")
        self.assertEqual(archived.status_code, 201)
        self.assertEqual(archived.json()["source_agent"], "encoding")
        self.assertEqual(archived.json()["source_candidate_id"], candidate["id"])
        self.assertEqual(archived.json()["archive_outcome"], "bypass_success")
        failed_candidate = task["candidates"][1]
        self.assertEqual(
            self.client.patch(
                f"/api/encoding-candidates/{failed_candidate['id']}",
                json={"status": "test_failed", "test_note": "needs retest"},
            ).status_code,
            200,
        )
        failed_archived = self.client.post(
            f"/api/encoding-candidates/{failed_candidate['id']}/archive"
        )
        self.assertEqual(failed_archived.status_code, 201)
        self.assertEqual(failed_archived.json()["archive_outcome"], "bypass_failure")
        self.assertEqual(
            self.client.post(
                f"/api/encoding-candidates/{failed_candidate['id']}/archive"
            ).status_code,
            409,
        )
        rejected_candidate = task["candidates"][2]
        self.client.patch(
            f"/api/encoding-candidates/{rejected_candidate['id']}",
            json={"status": "rejected"},
        )
        self.assertEqual(
            self.client.post(
                f"/api/encoding-candidates/{rejected_candidate['id']}/archive"
            ).status_code,
            409,
        )

    def test_encoding_agent_rejects_unsupported_payload_type(self):
        payload = next(
            payload
            for payload in self.client.get("/api/payloads").json()
            if payload["vulnerability"] == "file-upload"
        )
        response = self.client.post(
            "/api/encoding-iterations",
            json={"base_payload_id": payload["id"]},
        )
        self.assertEqual(response.status_code, 422)

    def test_payload_archive_outcome_compatibility(self):
        payloads = self.client.get("/api/payloads").json()
        self.assertGreaterEqual(len(payloads), 2)
        self.assertIsNone(payloads[0]["archive_outcome"])

        legacy_archived_id = payloads[1]["id"]
        with main.connect() as connection:
            connection.execute(
                """
                UPDATE payloads
                SET archived_from_candidate_id = ?, source_agent = 'semantic',
                    source_candidate_id = ?, iteration_metadata_json = '{}'
                WHERE id = ?
                """,
                ("legacy-candidate", "legacy-candidate", legacy_archived_id),
            )

        detail = self.client.get(f"/api/payloads/{legacy_archived_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["archive_outcome"], "bypass_success")
        listed = next(
            item for item in self.client.get("/api/payloads").json()
            if item["id"] == legacy_archived_id
        )
        self.assertEqual(listed["archive_outcome"], "bypass_success")

    @patch("app.main._post_chat_completion")
    @patch("app.main.model_config", return_value={"base_url": "http://llm.test", "api_key": "key", "model": "model", "provider": "DeepSeek"})
    def test_llm_requests_exclude_display_guidance(self, _config, post):
        response = Mock()
        response.status_code = 200
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "choices": [{"message": {"content": '{"candidates": [{"content": "candidate", "rule_labels": [], "explanation": "ok", "confidence": 0.5}]}'}}]
        }
        post.return_value = response
        payload = {
            "content": "base-content",
            "vulnerability": "xss",
            "category": "反射型",
            "delivery": "表单字段",
            "target": "DVWA",
            "difficulty": "Low",
            "usage_method": "must stay out of prompts",
            "success_indicators": "must stay out of prompts",
        }
        main.call_model(payload, ["representation"], 1)
        semantic_body = json.loads(post.call_args.args[1][1]["content"])
        self.assertNotIn("usage_method", semantic_body)
        self.assertNotIn("success_indicators", semantic_body)

        response.json.return_value = {
            "choices": [{"message": {"content": '{"candidates": [{"content": "encoded", "encoding_chain": [], "decode_path": [], "explanation": "ok", "confidence": 0.5}]}'}}]
        }
        main.call_encoding_model(payload, 1)
        encoding_body = json.loads(post.call_args.args[1][1]["content"])
        self.assertNotIn("usage_method", encoding_body)
        self.assertNotIn("success_indicators", encoding_body)

    @patch("app.main.call_model")
    def test_generation_and_manual_archive(self, model_call):
        model_call.side_effect = lambda payload, hints, count, ctx, techniques=None, per_batch=None: _mock_candidates(payload["content"], payload["vulnerability"], count)
        payload = self.client.get("/api/payloads").json()[0]
        task = self.client.post("/api/semantic-iterations", json={"base_payload_id": payload["id"]}).json()
        task_view = self.client.get(f"/api/semantic-iterations/{task['id']}").json()
        self.assertEqual(task_view["status"], "completed")
        self.assertEqual(len(task_view["candidates"]), 5)

        candidate = task_view["candidates"][0]
        self.assertEqual(
            self.client.post(f"/api/candidates/{candidate['id']}/archive").status_code,
            409,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/candidates/{candidate['id']}",
                json={"status": "test_success", "test_note": "manual local check"},
            ).status_code,
            200,
        )
        reverted = self.client.patch(
            f"/api/candidates/{candidate['id']}",
            json={"status": "pending_test", "test_note": "manual local check"},
        )
        self.assertEqual(reverted.status_code, 200)
        self.assertEqual(reverted.json()["status"], "pending_test")
        self.assertEqual(reverted.json()["test_note"], "manual local check")
        self.assertEqual(
            self.client.post(f"/api/candidates/{candidate['id']}/archive").status_code,
            409,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/candidates/{candidate['id']}",
                json={"status": "test_success", "test_note": "manual local check"},
            ).status_code,
            200,
        )
        archived = self.client.post(f"/api/candidates/{candidate['id']}/archive")
        self.assertEqual(archived.status_code, 201)
        self.assertEqual(archived.json()["archive_outcome"], "bypass_success")
        failed_candidate = task_view["candidates"][1]
        self.assertEqual(
            self.client.patch(
                f"/api/candidates/{failed_candidate['id']}",
                json={"status": "test_failed", "test_note": "needs retest"},
            ).status_code,
            200,
        )
        failed_archived = self.client.post(
            f"/api/candidates/{failed_candidate['id']}/archive"
        )
        self.assertEqual(failed_archived.status_code, 201)
        self.assertEqual(failed_archived.json()["archive_outcome"], "bypass_failure")
        self.assertFalse(
            any(
                source["semantic_candidate_id"] == failed_candidate["id"]
                for source in self.client.get("/api/cross-sources").json()
            )
        )
        with main.connect() as connection:
            metadata = json.loads(
                connection.execute(
                    "SELECT iteration_metadata_json FROM payloads WHERE id = ?",
                    (failed_archived.json()["id"],),
                ).fetchone()[0]
            )
        self.assertEqual(metadata["archive_outcome"], "bypass_failure")
        self.assertEqual(
            metadata["direction_lineage"][-1]["archive_outcome"],
            "bypass_failure",
        )

    @patch("app.main.call_model")
    def test_generation_traverses_kb_techniques(self, model_call):
        model_call.side_effect = lambda payload, hints, count, ctx, techniques=None, per_batch=None: _mock_candidates(payload["content"], payload["vulnerability"], count)
        payload = self.client.get("/api/payloads").json()[0]
        # command-injection 预置 5 条 semantic 技法，遍历逻辑应产生 5 条候选
        # （不再依赖「空库回退默认条数」，数量 = 可遍历技法数）。
        response = self.client.post(
            "/api/semantic-iterations",
            json={"base_payload_id": payload["id"]},
        )
        self.assertEqual(response.status_code, 202)
        task = self.client.get(f"/api/semantic-iterations/{response.json()['id']}").json()
        self.assertEqual(task["status"], "completed")
        self.assertEqual(len(task["candidates"]), 5)

    @patch("app.main.call_model")
    def test_semantic_batch_is_persisted_before_task_completes(self, model_call):
        # 真实 call_model 会逐批调用 per_batch；mock 复现这一行为，并在第一批落库后
        # 断言候选已可见、任务仍 running，验证「逐批落库+路由」而非「全量生成完才落库」。
        def mock_incremental(payload, hints, count, ctx, techniques=None, per_batch=None):
            first = _mock_candidates(payload["content"], payload["vulnerability"], 2)
            second = [_mock_part_ops(payload["content"], payload["vulnerability"], 2)]
            if per_batch is not None:
                per_batch(0, 2, first, 1)
                with main.connect() as connection:
                    persisted = connection.execute(
                        "SELECT COUNT(*) FROM candidates WHERE base_payload_id = ?",
                        (payload["id"],),
                    ).fetchone()[0]
                    status = connection.execute(
                        "SELECT status FROM generation_tasks WHERE base_payload_id = ? ORDER BY created_at DESC LIMIT 1",
                        (payload["id"],),
                    ).fetchone()[0]
                self.assertEqual(persisted, 2, "第一批 2 条候选应在第二批生成前落库")
                self.assertEqual(status, "running", "任务应在所有 batch 完成前保持 running")
                per_batch(2, 1, second, 2)
            return first + second

        model_call.side_effect = mock_incremental
        payload = self.client.get("/api/payloads").json()[0]
        response = self.client.post(
            "/api/semantic-iterations", json={"base_payload_id": payload["id"]}
        )
        self.assertEqual(response.status_code, 202)
        task = self.client.get(f"/api/semantic-iterations/{response.json()['id']}").json()
        self.assertEqual(task["status"], "completed")
        # 两批共 3 条候选全部落库（第二批未被去重误杀，也未因回调已触发而丢失）。
        self.assertEqual(len(task["candidates"]), 3)

    @patch("app.main.call_model")
    def test_candidate_can_be_deleted_individually(self, model_call):
        model_call.side_effect = lambda payload, hints, count, ctx, techniques=None, per_batch=None: _mock_candidates(payload["content"], payload["vulnerability"], count)
        payload = self.client.get("/api/payloads").json()[0]
        task = self.client.post("/api/semantic-iterations", json={"base_payload_id": payload["id"]}).json()
        candidate = self.client.get(f"/api/semantic-iterations/{task['id']}").json()["candidates"][0]
        self.assertEqual(self.client.delete(f"/api/candidates/{candidate['id']}").status_code, 204)
        self.assertEqual(self.client.delete(f"/api/candidates/{candidate['id']}").status_code, 404)

    @patch("app.main.call_model")
    def test_deleting_payload_with_iteration_history_hides_it_from_library(self, model_call):
        model_call.side_effect = lambda payload, hints, count, ctx, techniques=None, per_batch=None: _mock_candidates(payload["content"], payload["vulnerability"], count)
        payload = self.client.get("/api/payloads").json()[0]
        self.client.post("/api/semantic-iterations", json={"base_payload_id": payload["id"]})

        self.assertEqual(self.client.delete(f"/api/payloads/{payload['id']}").status_code, 204)
        payload_ids = {item["id"] for item in self.client.get("/api/payloads").json()}
        self.assertNotIn(payload["id"], payload_ids)

        with main.connect() as connection:
            saved = main.read_payload(connection, payload["id"])
        self.assertEqual(saved["is_deleted"], 1)

    @patch("app.main.call_encoding_model")
    @patch("app.main.call_model")
    def test_semantic_archive_creates_cross_source_and_cross_success_sample(self, model_call, encoding_model_call):
        model_call.side_effect = lambda payload, hints, count, ctx, techniques=None, per_batch=None: _mock_candidates(payload["content"], payload["vulnerability"], count)
        encoding_model_call.side_effect = lambda payload, count, ctx=None, techniques=None, per_batch=None: self._encoding_candidates(payload["content"], count)
        payload = self.client.get("/api/payloads").json()[0]
        task = self.client.post("/api/semantic-iterations", json={"base_payload_id": payload["id"]}).json()
        candidate = self.client.get(f"/api/semantic-iterations/{task['id']}").json()["candidates"][0]
        self.assertEqual(
            self.client.patch(
                f"/api/candidates/{candidate['id']}",
                json={"status": "test_success", "test_note": "semantic verified"},
            ).status_code,
            200,
        )
        archived = self.client.post(f"/api/candidates/{candidate['id']}/archive")
        self.assertEqual(archived.status_code, 201)
        self.assertEqual(archived.json()["source_agent"], "semantic")
        self.assertEqual(archived.json()["archive_outcome"], "bypass_success")

        sources = self.client.get("/api/cross-sources").json()
        self.assertEqual(len(sources), 1)
        source = sources[0]
        self.assertEqual(source["archived_payload_id"], archived.json()["id"])
        self.assertEqual(source["semantic_candidate_id"], candidate["id"])
        self.assertTrue(source["rule_labels"])
        self.assertGreaterEqual(source["available_chain_count"], 5)

        cross_task = self.client.post(
            "/api/cross-iterations",
            json={"cross_source_id": source["id"]},
        )
        self.assertEqual(cross_task.status_code, 202)
        cross_detail = self.client.get(f"/api/cross-iterations/{cross_task.json()['id']}").json()
        self.assertEqual(cross_detail["status"], "completed")
        self.assertGreaterEqual(len(cross_detail["candidates"]), 1)
        first_cross = cross_detail["candidates"][0]
        self.assertNotEqual(first_cross["content"], source["content"])
        self.assertEqual(
            reverse_encoding_chain(first_cross["content"], first_cross["encoding_chain"]),
            source["content"],
        )

    @patch("app.main.call_encoding_model")
    @patch("app.main.call_model")
    def test_cross_chain_history_survives_candidate_deletion(self, model_call, encoding_model_call):
        model_call.side_effect = lambda payload, hints, count, ctx, techniques=None, per_batch=None: _mock_candidates(payload["content"], payload["vulnerability"], count)
        payload = self.client.get("/api/payloads").json()[0]
        task = self.client.post("/api/semantic-iterations", json={"base_payload_id": payload["id"]}).json()
        candidate = self.client.get(f"/api/semantic-iterations/{task['id']}").json()["candidates"][0]
        self.client.patch(f"/api/candidates/{candidate['id']}", json={"status": "test_success"})
        self.client.post(f"/api/candidates/{candidate['id']}/archive")
        source = self.client.get("/api/cross-sources").json()[0]

        # 交叉迭代现在走编码 agent（LLM）；mock 每次调用返回不同的编码意图。
        call_counter = {"n": 0}
        encodings = ["url", "base64"]
        def mock_encoding(payload, count, ctx=None, techniques=None, per_batch=None):
            idx = call_counter["n"] % len(encodings)
            call_counter["n"] += 1
            return [{
                "intent": "full",
                "encoding_type": encodings[idx],
                "submode": None,
                "chain": None,
                "explanation": "可逆编码",
                "confidence": 0.4,
            } for _ in range(count)]
        encoding_model_call.side_effect = mock_encoding

        first_task = self.client.post("/api/cross-iterations", json={"cross_source_id": source["id"]}).json()
        first_candidate = self.client.get(f"/api/cross-iterations/{first_task['id']}").json()["candidates"][0]
        self.assertEqual(self.client.delete(f"/api/cross-candidates/{first_candidate['id']}").status_code, 204)
        second_task = self.client.post("/api/cross-iterations", json={"cross_source_id": source["id"]}).json()
        second_candidate = self.client.get(f"/api/cross-iterations/{second_task['id']}").json()["candidates"][0]
        self.assertNotEqual(first_candidate["encoding_chain"], second_candidate["encoding_chain"])
        self.assertNotEqual(first_candidate["content"], second_candidate["content"])

    @patch("app.main.call_model")
    def test_semantic_iteration_pool_snapshots_and_starts_tasks(self, model_call):
        call_counter = {"n": 0}
        def mock_generation(payload, hints, count, ctx, techniques=None, per_batch=None):
            # 每次调用用递增偏移，避免跨任务去重把重复 start 的候选全拒。
            offset = call_counter["n"] * count
            call_counter["n"] += 1
            return [
                {**cand, "part_operations": [
                    {**op, "value": f"{op['value']}g{call_counter['n']}k{i}"}
                    for op in cand["part_operations"]
                ]}
                for i, cand in enumerate(_mock_candidates(payload["content"], payload["vulnerability"], count))
            ]
        model_call.side_effect = mock_generation
        payload = next(
            item for item in self.client.get("/api/payloads").json() if item["vulnerability"] == "command-injection"
        )
        added = self.client.post("/api/iteration-pools/semantic", json={"source_payload_id": payload["id"]})
        self.assertEqual(added.status_code, 201)
        item = added.json()
        self.assertEqual(item["status"], "pending")
        self.assertEqual(item["snapshot"]["content"], payload["content"])
        self.assertNotIn("usage_method", item["snapshot"])
        self.assertNotIn("success_indicators", item["snapshot"])
        with main.connect() as connection:
            snapshot = main.read_payload(connection, item["snapshot_payload_id"])
        self.assertEqual(snapshot["usage_method"], "")
        self.assertEqual(snapshot["success_indicators"], "")
        self.assertNotIn(item["snapshot_payload_id"], {entry["id"] for entry in self.client.get("/api/payloads").json()})
        self.assertEqual(
            self.client.post("/api/iteration-pools/semantic", json={"source_payload_id": payload["id"]}).status_code,
            409,
        )

        self.client.patch(f"/api/payloads/{payload['id']}", json={"content": "edited-after-queued"})
        queued = self.client.get("/api/iteration-pools/semantic").json()[0]
        self.assertEqual(queued["snapshot"]["content"], payload["content"])
        started = self.client.post(f"/api/iteration-pools/{item['id']}/start", json={})
        self.assertEqual(started.status_code, 202)
        task = self.client.get(f"/api/semantic-iterations/{started.json()['id']}").json()
        self.assertEqual(task["status"], "completed")
        self.assertEqual(len(task["candidates"]), 5)
        candidate = task["candidates"][0]
        self.assertEqual(
            self.client.patch(f"/api/candidates/{candidate['id']}", json={"status": "test_success"}).status_code,
            200,
        )
        archived = self.client.post(f"/api/candidates/{candidate['id']}/archive")
        self.assertEqual(archived.status_code, 201)
        with main.connect() as connection:
            source_row = main.read_payload(connection, payload["id"])
            archived_row = main.read_payload(connection, archived.json()["id"])
        self.assertEqual(archived_row["usage_method"], source_row["usage_method"])
        self.assertEqual(archived_row["success_indicators"], source_row["success_indicators"])
        started_item = self.client.get("/api/iteration-pools/semantic").json()[0]
        self.assertEqual(started_item["status"], "started")
        self.assertEqual(started_item["task_id"], task["id"])

        repeated = self.client.post(
            f"/api/iteration-pools/{item['id']}/start", json={}
        )
        self.assertEqual(repeated.status_code, 202)
        repeated_task = self.client.get(f"/api/semantic-iterations/{repeated.json()['id']}").json()
        self.assertEqual(repeated_task["status"], "completed")
        self.assertNotEqual(repeated.json()["id"], task["id"])
        self.assertEqual(self.client.delete(f"/api/iteration-pools/{item['id']}").status_code, 409)

        readded = self.client.post(
            "/api/iteration-pools/semantic", json={"source_payload_id": payload["id"]}
        )
        self.assertEqual(readded.status_code, 201)
        second_item = readded.json()
        self.assertNotEqual(second_item["id"], item["id"])
        self.assertNotEqual(second_item["snapshot_payload_id"], item["snapshot_payload_id"])
        self.assertEqual(second_item["status"], "pending")
        self.assertEqual(
            self.client.post(
                "/api/iteration-pools/semantic", json={"source_payload_id": payload["id"]}
            ).status_code,
            409,
        )

        pool_items = self.client.get("/api/iteration-pools/semantic").json()
        self.assertEqual(len(pool_items), 2)
        self.assertEqual({entry["status"] for entry in pool_items}, {"pending", "started"})

        second_started = self.client.post(
            f"/api/iteration-pools/{second_item['id']}/start", json={}
        )
        self.assertEqual(second_started.status_code, 202)
        self.assertNotEqual(second_started.json()["id"], task["id"])
        pool_items = self.client.get("/api/iteration-pools/semantic").json()
        self.assertEqual([entry["status"] for entry in pool_items], ["started", "started"])

    def test_iteration_pool_can_remove_pending_item_and_reject_unsupported_encoding(self):
        command = next(
            item for item in self.client.get("/api/payloads").json() if item["vulnerability"] == "command-injection"
        )
        added = self.client.post("/api/iteration-pools/encoding", json={"source_payload_id": command["id"]})
        self.assertEqual(added.status_code, 201)
        self.assertEqual(self.client.delete(f"/api/iteration-pools/{added.json()['id']}").status_code, 204)
        self.assertEqual(
            self.client.post("/api/iteration-pools/encoding", json={"source_payload_id": command["id"]}).status_code,
            201,
        )
        upload = next(
            item for item in self.client.get("/api/payloads").json() if item["vulnerability"] == "file-upload"
        )
        self.assertEqual(
            self.client.post("/api/iteration-pools/encoding", json={"source_payload_id": upload["id"]}).status_code,
            422,
        )

    @patch("app.main.call_model")
    def test_failed_pool_generation_returns_to_pending_and_can_retry(self, model_call):
        payload = next(
            item for item in self.client.get("/api/payloads").json()
            if item["vulnerability"] == "command-injection"
        )
        successful_candidates = _mock_candidates(payload["content"], payload["vulnerability"], 3)
        model_call.side_effect = [RuntimeError("The read operation timed out"), successful_candidates]

        item = self.client.post(
            "/api/iteration-pools/semantic", json={"source_payload_id": payload["id"]}
        ).json()
        failed = self.client.post(
            f"/api/iteration-pools/{item['id']}/start", json={}
        )
        self.assertEqual(failed.status_code, 202)
        failed_task = self.client.get(f"/api/semantic-iterations/{failed.json()['id']}").json()
        self.assertEqual(failed_task["status"], "failed")

        retryable = next(
            entry for entry in self.client.get("/api/iteration-pools/semantic").json()
            if entry["id"] == item["id"]
        )
        self.assertEqual(retryable["status"], "pending")
        self.assertEqual(retryable["task_status"], "failed")
        self.assertIn("timed out", retryable["task_error"])

        retried = self.client.post(
            f"/api/iteration-pools/{item['id']}/start", json={}
        )
        self.assertEqual(retried.status_code, 202)
        retried_task = self.client.get(f"/api/semantic-iterations/{retried.json()['id']}").json()
        self.assertEqual(retried_task["status"], "completed")
        self.assertNotEqual(retried.json()["id"], failed.json()["id"])

        started = next(
            entry for entry in self.client.get("/api/iteration-pools/semantic").json()
            if entry["id"] == item["id"]
        )
        self.assertEqual(started["status"], "started")
        self.assertEqual(started["task_status"], "completed")

        listed = self.client.get("/api/candidates").json()
        retried_candidate = next(entry for entry in listed if entry["task_id"] == retried.json()["id"])
        self.assertTrue(retried_candidate["base_payload_name"])
        self.assertTrue(retried_candidate["base_target"])

    def test_report_creation_update_and_source_snapshot_retention(self):
        sample = self._create_success_sample()
        created = self.client.post(f"/api/reports/from-sample/{sample['id']}")
        self.assertEqual(created.status_code, 201)
        report = created.json()
        self.assertEqual(report["success_sample_id"], sample["id"])
        self.assertEqual(report["sample_name"], sample["name"])
        self.assertEqual(report["payload_content"], sample["content"])
        self.assertEqual(report["verification_environment"], sample["target"])
        self.assertEqual(report["actual_result"], sample["test_note"])
        self.assertEqual(report["conclusion"], "验证成功")
        self.assertEqual(report["source_status"], "active")
        self.assertEqual(report["images"], [])

        repeated = self.client.post(f"/api/reports/from-sample/{sample['id']}")
        self.assertEqual(repeated.status_code, 201)
        self.assertEqual(repeated.json()["id"], report["id"])
        self.assertEqual(len(self.client.get("/api/reports").json()), 1)

        updated = self.client.patch(
            f"/api/reports/{report['id']}",
            json={
                "title": "命令注入验证报告",
                "prerequisites": "仅限授权 DVWA Low 环境",
                "verification_steps": "在命令输入框提交 Payload",
                "actual_result": "页面返回 uid=",
                "conclusion": "验证成功，WAF 未阻断",
                "tester": "local-tester",
                "verification_date": "2026-07-31",
                "notes": "人工复核完成",
            },
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["title"], "命令注入验证报告")
        self.assertEqual(updated.json()["tester"], "local-tester")
        self.assertEqual(
            self.client.patch(
                f"/api/reports/{report['id']}", json={"verification_date": "31-07-2026"}
            ).status_code,
            422,
        )

        self.assertEqual(self.client.delete(f"/api/success-samples/{sample['id']}").status_code, 204)
        retained = self.client.get(f"/api/reports/{report['id']}")
        self.assertEqual(retained.status_code, 200)
        self.assertEqual(retained.json()["source_status"], "deleted")
        self.assertEqual(retained.json()["payload_content"], sample["content"])

        self.assertEqual(self.client.delete(f"/api/reports/{report['id']}").status_code, 204)
        self.assertEqual(self.client.get(f"/api/reports/{report['id']}").status_code, 404)
        with main.connect() as connection:
            source = main.row(connection.execute(
                "SELECT * FROM success_samples WHERE id = ?", (sample["id"],)
            ).fetchone())
        self.assertIsNotNone(source)

    def test_report_image_upload_validation_order_and_cleanup(self):
        sample = self._create_success_sample()
        report = self.client.post(f"/api/reports/from-sample/{sample['id']}").json()
        png = b"\x89PNG\r\n\x1a\n" + b"authorized-evidence"
        uploaded = self.client.post(
            f"/api/reports/{report['id']}/images",
            files={"file": ("proof.png", png, "image/png")},
        )
        self.assertEqual(uploaded.status_code, 201)
        image = uploaded.json()
        self.assertEqual(image["media_type"], "image/png")
        self.assertEqual(image["size_bytes"], len(png))
        self.assertEqual(
            self.client.get(f"/api/report-images/{image['id']}/content").content,
            png,
        )
        changed = self.client.patch(
            f"/api/report-images/{image['id']}",
            json={"caption": "命令执行回显", "sort_order": 5},
        )
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(changed.json()["caption"], "命令执行回显")
        self.assertEqual(changed.json()["sort_order"], 5)

        self.assertEqual(
            self.client.post(
                f"/api/reports/{report['id']}/images",
                files={"file": ("fake.png", b"not-an-image", "image/png")},
            ).status_code,
            422,
        )
        self.assertEqual(
            self.client.post(
                f"/api/reports/{report['id']}/images",
                files={"file": ("mismatch.jpg", png, "image/jpeg")},
            ).status_code,
            422,
        )

        for index in range(9):
            response = self.client.post(
                f"/api/reports/{report['id']}/images",
                files={"file": (f"proof-{index}.png", png + bytes([index]), "image/png")},
            )
            self.assertEqual(response.status_code, 201)
        self.assertEqual(
            self.client.post(
                f"/api/reports/{report['id']}/images",
                files={"file": ("too-many.png", png, "image/png")},
            ).status_code,
            409,
        )

        with main.connect() as connection:
            connection.execute(
                "UPDATE report_images SET relative_path = '../../outside.png' WHERE id = ?",
                (image["id"],),
            )
        self.assertEqual(
            self.client.get(f"/api/report-images/{image['id']}/content").status_code,
            422,
        )
        with main.connect() as connection:
            connection.execute(
                "UPDATE report_images SET relative_path = ? WHERE id = ?",
                (f"{report['id']}/{image['id']}.png", image["id"]),
            )

        report_dir = main.REPORT_EVIDENCE_ROOT / report["id"]
        self.assertTrue(report_dir.is_dir())
        self.assertEqual(self.client.delete(f"/api/reports/{report['id']}").status_code, 204)
        self.assertFalse(report_dir.exists())
        self.assertTrue(any(item["id"] == sample["id"] for item in self.client.get("/api/success-samples").json()))


if __name__ == "__main__":
    unittest.main()
