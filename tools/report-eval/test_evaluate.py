import argparse
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("report_eval", Path(__file__).with_name("evaluate.py"))
EVAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVAL)


class ReportEvaluationTest(unittest.TestCase):
    def test_go_policy_supports_old_raw_and_current_draft_guidance(self):
        old = "const DeliveryReportWritingRules = `旧版规则`\n"
        current = (
            "const DeliveryReportRuntimeGuidance = `共享运行约定`\n\n"
            "const DeliveryReportEvidenceGuidance = `证据规则`\n\n"
            "const DeliveryReportStyleGuidance = `简短规则`\n\n"
            "const DeliveryReportWritingRules = DeliveryReportRuntimeGuidance + DeliveryReportStyleGuidance + `新版写作规则`\n"
            "const DeliveryReportDraftRules = DeliveryReportRuntimeGuidance + DeliveryReportEvidenceGuidance + DeliveryReportStyleGuidance + `JSON 草稿规则`\n"
        )
        self.assertEqual(EVAL.expand_go_policy(old), "旧版规则")
        self.assertEqual(EVAL.expand_go_policy(current), "共享运行约定证据规则简短规则JSON 草稿规则")
        for unsupported in (
            "const DeliveryReportWritingRules = unknown()\n",
            "const DeliveryReportWritingRules = `规则` + readSecret()\n",
            "const DeliveryReportWritingRules = DeliveryReportWritingRules + `规则`\n",
            'const DeliveryReportWritingRules = "转义字符串"\n',
        ):
            with self.assertRaises(ValueError):
                EVAL.expand_go_policy(unsupported)

    def prepare(self, folder, model="fixture-model"):
        policy = folder.parent / "policy.txt"
        policy.write_text("合成评测写作规则，不是真实模型输出。", encoding="utf-8")
        EVAL.prepare(argparse.Namespace(
            policy_file=str(policy), policy_source=None, output=str(folder),
            label=folder.name, model=model, temperature=0.0, seed=1, max_output_tokens=4096,
        ))

    def test_prepare_excludes_reference_and_review_from_model_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / "run"
            self.prepare(folder)
            report_input = EVAL.read_json(folder / "inputs" / "idor.json")
            material = report_input["material"]
            instruction = report_input["instruction"]
            self.assertIn("离线合成材料", instruction)
            self.assertIn("不调用工具", instruction)
            self.assertIn("遵循系统提示", instruction)
            self.assertNotIn("测试时间：未记录", instruction)
            self.assertNotIn("必须逐字出现", instruction)
            self.assertNotIn("reference_report", material)
            self.assertNotIn("review", material)
            self.assertTrue(material["evidence"])
            self.assertTrue(all("id" not in item for item in material["evidence"]))
            self.assertTrue(all(item["purpose"] for item in material["evidence"]))
            self.assertEqual(EVAL.read_json(folder / "run.json")["results"], {})
            self.assertFalse(list((folder / "outputs").iterdir()))
            self.assertTrue((folder / "drafts").is_dir())

    def test_collect_does_not_label_human_reference_as_model_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / "run"
            self.prepare(folder)
            args = argparse.Namespace(
                run=str(folder), case="idor", report=str(EVAL.CASE_DIR / "idor.reference.md"),
                model="fixture-model", source="model", input_tokens=None,
                output_tokens=None, cached_input_tokens=None, seconds=None,
            )
            with self.assertRaisesRegex(ValueError, "人工参考"):
                EVAL.collect(args)
            args.source = "manual"
            EVAL.collect(args)
            self.assertEqual(EVAL.review_run(folder)["cases"]["idor"]["source"], "manual")

    def test_model_collect_attaches_original_evidence_outside_model_body(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / "run"
            self.prepare(folder)
            draft = Path(temporary) / "draft.md"
            draft.write_text(
                "# 示例下载线索\n\n## 描述\n待核实。\n\n### 定级依据\n现有材料不足。\n\n"
                "## 修复\n先补证据。\n\n## 测试过程\n### 发现过程与攻击思路\n现有记录只有响应头。\n\n"
                "### 失败尝试与未验证项\n响应正文未取得。\n\n## 攻击链路\n```text\n用户请求\n└─ 下载接口\n```\n\n"
                "## 证据说明\n### Burp 复现\n未能重放。\n\n### 复测标准\n补齐完整响应后核实。\n",
                encoding="utf-8",
            )
            EVAL.collect(argparse.Namespace(
                run=str(folder), case="incomplete", report=str(draft), model="fixture-model",
                source="model", input_tokens=None, output_tokens=None,
                cached_input_tokens=None, seconds=None,
            ))
            final = (folder / "outputs" / "incomplete.md").read_text(encoding="utf-8")
            self.assertIn("### 原始材料", final)
            self.assertIn("GET /api/files/file-a/download HTTP/1.1", final)
            self.assertIn("Content-Length: 48", final)
            self.assertIn("响应（正文未取得）", final)
            stored_draft = (folder / "drafts" / "incomplete.md").read_text(encoding="utf-8")
            self.assertNotIn("GET /api/files/file-a/download HTTP/1.1", stored_draft)

    def test_collected_output_must_not_change_silently(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / "run"
            self.prepare(folder)
            EVAL.collect(argparse.Namespace(
                run=str(folder), case="idor", report=str(EVAL.CASE_DIR / "idor.reference.md"),
                model="fixture-model", source="manual", input_tokens=None,
                output_tokens=None, cached_input_tokens=None, seconds=None,
            ))
            (folder / "outputs" / "idor.md").write_text("报告被修改", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "收集后改变"):
                EVAL.review_run(folder)

    def test_comparison_records_different_models_and_missing_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root / "before", "fixture-model-a")
            self.prepare(root / "after", "fixture-model-b")
            EVAL.compare(argparse.Namespace(
                before=str(root / "before"), after=str(root / "after"), output=str(root / "comparison.json"),
            ))
            comparison = EVAL.read_json(root / "comparison.json")
            self.assertFalse(comparison["comparison_complete"])
            self.assertTrue(any("model 不一致" in item for item in comparison["limitations"]))
            self.assertTrue(any("缺少模型产出" in item for item in comparison["limitations"]))

    def test_report_format_metrics_do_not_claim_semantic_quality(self):
        material = EVAL.cases()[0]
        report = chr(10).join([
            "# 漏洞名称",
            "## 描述",
            "### 定级依据",
            "## 修复建议",
            "## 测试过程",
            "测试时间：2026-11-01 10:00:00（北京时间）",
            "### 发现过程与攻击思路",
            "### 失败尝试与未验证项",
            "### Burp 复现",
            "## 攻击链路",
            "## 证据说明",
            "### 复测标准",
        ])
        report = EVAL.attach_evidence(material, report)
        measured = EVAL.metrics(material, report)
        self.assertTrue(measured["required_headings_ok"])
        self.assertTrue(measured["required_subheadings_ok"])
        self.assertTrue(measured["report_structure_ok"])
        self.assertTrue(measured["narrative_within_800_characters"])
        self.assertTrue(measured["test_time_heading_present"])
        self.assertTrue(measured["test_time_matches_input"])
        self.assertFalse(measured["verbatim_material_not_found"])
        self.assertIn("未自动判定", measured["semantic_quality"])
        report_body, appendix = report.split("### 原始材料", 1)
        too_long = EVAL.metrics(material, report_body + "x" * 801 + "\n### 原始材料" + appendix)
        self.assertFalse(too_long["narrative_within_800_characters"])

        wrong_time = report.replace("2026-11-01 10:00:00", "2026-11-01 18:00:00")
        self.assertFalse(EVAL.metrics(material, wrong_time)["test_time_matches_input"])

    def test_attack_chain_request_paths_are_checked_against_raw_evidence(self):
        case = EVAL.cases_by_id()["injection"]
        draft = {
            "cvss_vector": case["facts"]["cvss_vector"],
            "description": "问题。\n### 定级依据\n测试依据。",
            "remediation": "使用参数化查询。",
            "test_process": "### 发现过程与攻击思路\n做对照测试。\n"
            "### 失败尝试与未验证项\n字段值未读取。\n"
            "### Burp 复现\n合成样本未用 Burp。",
            "attack_chain": "```text\nGET /api/products?name=alpha\n"
            "├─ GET /api/products?name=alpha' AND 1=1-- → 返回1条\n```",
            "discovery_path": "### 复测标准\n比较真假条件响应。",
        }
        report = EVAL.attach_evidence(case, EVAL.report_from_draft(case, draft))
        measured = EVAL.metrics(case, report)
        self.assertFalse(measured["attack_chain_request_paths_match_evidence"])
        self.assertIn("GET /api/products?name=alpha'", measured["attack_chain_request_paths_not_found"])

    def test_attack_chain_metrics_detect_multiple_roots(self):
        case = EVAL.cases_by_id()["idor"]
        report = EVAL.attach_evidence(case, "\n".join([
            "# 示例越权漏洞", "## 描述", "### 定级依据", "## 修复建议", "## 测试过程",
            "### 发现过程与攻击思路", "### 失败尝试与未验证项", "### Burp 复现",
            "## 攻击链路", "```text", "GET /api/jobs/job-a", "├─ 200 OK",
            "POST /api/jobs/job-a/types", "└─ 200 OK", "```", "## 证据说明", "### 复测标准",
        ]))
        measured = EVAL.metrics(case, report)
        self.assertEqual(measured["attack_chain_root_count"], 2)
        self.assertFalse(measured["attack_chain_single_root"])
        self.assertEqual(measured["attack_chain_disconnected_nodes"], ["POST /api/jobs/job-a/types"])

    def test_non_http_attack_chain_commands_must_match_exact_evidence(self):
        case = EVAL.cases_by_id()["non-http"]
        headings = [
            "# 本地文件权限问题",
            "## 描述",
            "### 定级依据",
            "## 修复建议",
            "## 测试过程",
            "测试时间：2026-11-01 10:00:00（北京时间）",
            "### 发现过程与攻击思路",
            "### 失败尝试与未验证项",
            "### Burp 复现",
            "## 攻击链路",
        ]
        commands = [item["command"] for item in case["evidence"]]
        valid_chain = "\n".join([
            "```text",
            "本地文件权限验证",
            f"├─ {commands[0]} → 当前用户信息",
            *[f"├─ {command}" for command in commands[1:]],
            "```",
            "## 证据说明",
            "### 复测标准",
        ])
        valid = EVAL.metrics(case, EVAL.attach_evidence(case, "\n".join(headings + [valid_chain])))
        self.assertTrue(valid["attack_chain_shell_commands_match_evidence"])
        self.assertFalse(valid["attack_chain_shell_commands_not_found"])
        self.assertFalse(valid["attack_chain_shell_commands_missing"])

        concise_chain = "\n".join([
            "```text",
            "本地文件权限验证",
            *[f"├─ {command}" for command in commands[1:]],
            "```",
        ])
        concise = EVAL.metrics(
            case, EVAL.attach_evidence(case, "\n".join(headings + [concise_chain]))
        )
        self.assertTrue(concise["attack_chain_shell_commands_match_evidence"])
        self.assertEqual(concise["attack_chain_shell_commands_missing"], commands[:1])

        inaccurate_chain = "\n".join([
            "```text",
            "本地文件权限验证",
            "├─ id / whoami",
            "├─ ls -l backups/customer-notes.txt",
            "├─ cat backups/customer-notes.txt",
            "└─ cat backups/private-notes.txt",
            "```",
        ])
        inaccurate = EVAL.metrics(
            case, EVAL.attach_evidence(case, "\n".join(headings + [inaccurate_chain]))
        )
        self.assertFalse(inaccurate["attack_chain_shell_commands_match_evidence"])
        self.assertEqual(
            inaccurate["attack_chain_shell_commands_not_found"],
            [
                "id / whoami",
                "ls -l backups/customer-notes.txt",
                "cat backups/customer-notes.txt",
                "cat backups/private-notes.txt",
            ],
        )
        self.assertEqual(inaccurate["attack_chain_shell_commands_missing"], commands)

    def test_http_reports_flag_missing_burp_packets_and_unclear_shorthand(self):
        case = EVAL.cases_by_id()["idor"]
        report = "\n".join([
            "# 作业权限问题",
            "## 描述",
            "观察到设置变化。",
            "### 定级依据",
            "影响已限定。",
            "## 修复建议",
            "校验资源归属。",
            "## 测试过程",
            "### 发现过程与攻击思路",
            "测试时间：2026-11-01 10:00:00（北京时间）",
            "步骤。",
            "### 失败尝试与未验证项",
            "其他影响未验证。",
            "### Burp 复现",
            "本次未在 Burp 中发送，见建议步骤。",
            "## 攻击链路",
            "```text",
            "用户入口",
            "└─ GET /api/jobs/job-a",
            "   └─ 返回 200/1382B，held=alice",
            "```",
            "## 证据说明",
            "来源为离线样本。",
            "### 复测标准",
            "请求应被拒绝。",
        ])
        measured = EVAL.metrics(case, EVAL.attach_evidence(case, report))
        self.assertTrue(measured["burp_request_packet_required"])
        self.assertFalse(measured["burp_request_packet_present"])
        self.assertFalse(measured["burp_request_packet_matches_evidence"])
        self.assertEqual(
            measured["unclear_report_shorthand_found"],
            ["状态码/响应字节数连写", "内部变量名和值连写"],
        )

        with_packet = report.replace(
            "本次未在 Burp 中发送，见建议步骤。",
            "本次未在 Burp 中发送。建议复测请求（未发送）：\n\n"
            "```http\nGET /api/jobs/job-a HTTP/1.1\n"
            "Host: report-eval.invalid\nX-Eval-Actor: user-a\n```",
        )
        with_packet = with_packet.replace("返回 200/1382B，held=alice", "作业信息可读取")
        measured_with_packet = EVAL.metrics(
            case, EVAL.attach_evidence(case, with_packet)
        )
        self.assertTrue(measured_with_packet["burp_request_packet_present"])
        self.assertTrue(measured_with_packet["burp_request_packet_matches_evidence"])
        self.assertFalse(measured_with_packet["unclear_report_shorthand_found"])

        used_packet = with_packet.replace(
            "本次未在 Burp 中发送。建议复测请求（未发送）：",
            "已在 Burp Repeater 中发送以下请求：",
        )
        measured_used_packet = EVAL.metrics(
            case, EVAL.attach_evidence(case, used_packet)
        )
        self.assertTrue(measured_used_packet["burp_request_packet_required"])
        self.assertTrue(measured_used_packet["burp_request_packet_present"])
        self.assertTrue(measured_used_packet["burp_request_packet_matches_evidence"])

        mismatched_packet = with_packet.replace(
            "GET /api/jobs/job-a HTTP/1.1", "GET /api/jobs/job-b HTTP/1.1"
        )
        measured_mismatch = EVAL.metrics(
            case, EVAL.attach_evidence(case, mismatched_packet)
        )
        self.assertFalse(measured_mismatch["burp_request_packet_matches_evidence"])

        without_request_evidence = {
            **case,
            "evidence": [
                {**item, "request": ""} for item in case["evidence"]
            ],
        }
        incomplete_report = report.replace(
            "本次未在 Burp 中发送，见建议步骤。",
            "本次未在 Burp 中发送。建议复测请求（未发送）：\n\n"
            "```http\n<METHOD> <PATH> HTTP/1.1\n"
            "Host: <需从授权环境重新捕获>\n```",
        )
        measured_incomplete = EVAL.metrics(
            without_request_evidence,
            EVAL.attach_evidence(without_request_evidence, incomplete_report),
        )
        self.assertTrue(measured_incomplete["burp_request_packet_required"])
        self.assertTrue(measured_incomplete["burp_request_packet_present"])
        self.assertIsNone(measured_incomplete["burp_request_packet_matches_evidence"])

    def test_live_evaluation_only_accepts_loopback_and_renders_cvss_header(self):
        for url in ("https://example.com", "http://127.0.0.1.evil.test:8787", "http://user:placeholder@127.0.0.1:8787"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                EVAL.local_base_url(url)
        case = EVAL.cases_by_id()["idor"]
        draft = {
            "cvss_vector": case["facts"]["cvss_vector"],
            "description": "问题说明\n### 定级依据\n评级依据。",
            "remediation": "服务端校验当前用户与作业归属。",
            "test_process": "### 发现过程与攻击思路\n复现步骤。\n### 失败尝试与未验证项\n批量编号未验证。",
            "attack_chain": "```text\n普通用户\n└─ 修改接口\n   └─ 状态变化\n```",
            "discovery_path": "### Burp 复现\n使用 Repeater。\n### 复测标准\n请求应被拒绝。",
        }
        report = EVAL.report_from_draft(case, draft)
        self.assertIn("CVSS 4.0：" + case["facts"]["cvss_vector"], report)
        self.assertIn("评分", report)
        self.assertEqual(EVAL.metrics(case, report)["headings"], EVAL.HEADINGS)

    def test_api_json_preserves_safe_server_error_message(self):
        error = EVAL.urllib.error.HTTPError(
            "http://127.0.0.1:8787/api/report-eval/idor",
            502,
            "Bad Gateway",
            {},
            io.BytesIO(
                '{"error":"模型报告字段不完整","diagnostic":{"stop_reason":"end_turn",'
                '"content_block_types":["text"],"output_tokens":17}}'.encode()
            ),
        )
        with patch.object(EVAL.urllib.request, "build_opener") as build_opener:
            build_opener.return_value.open.side_effect = error
            with self.assertRaises(EVAL.ReportEvalHTTPError) as raised:
                EVAL.api_json("http://127.0.0.1:8787", "/api/report-eval/idor")
            self.assertIn("模型报告字段不完整", str(raised.exception))
            self.assertEqual(raised.exception.diagnostic["content_block_types"], ["text"])

    def test_live_evaluation_continues_and_records_other_case_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "live"
            calls = []

            def api_json(_base, path, method="GET", payload=None, token=None):
                if path == "/api/auth/login":
                    return {"token": "secret-test-token"}
                if path == "/api/report-eval":
                    return {
                        "case_ids": sorted(EVAL.cases_by_id()),
                        "model": "fixture-model",
                        "provider_source": "fixture",
                        "format": "openai",
                        "thinking_type": "enabled",
                        "reasoning_effort": "high",
                        "max_output_tokens": 4096,
                        "system_sha256": "fixture-policy-hash",
                    }
                case_id = path.rsplit("/", 1)[-1]
                calls.append(case_id)
                if case_id == "concurrency":
                    raise EVAL.ReportEvalHTTPError(
                        502,
                        "模型未返回可解析的报告字段",
                        "not-json output",
                        {"stop_reason": "end_turn", "content_block_types": ["text"], "output_tokens": 17},
                    )
                case = EVAL.cases_by_id()[case_id]
                return {
                    "draft": {
                        "cvss_vector": case["facts"]["cvss_vector"],
                        "description": "问题说明。\n### 定级依据\n依据合成材料中的观察。",
                        "remediation": "在服务端落实对应的业务校验。",
                        "test_process": "### 发现过程与攻击思路\n按样本材料核对。\n### 失败尝试与未验证项\n未覆盖的边界仍待验证。",
                        "attack_chain": "```text\n普通用户\n└─ 请求对应接口\n   └─ 观察到样本结果\n```",
                        "discovery_path": "### Burp 复现\n将样本请求放入 Repeater。\n### 复测标准\n按修复后的预期结果核对。",
                    },
                    "usage": {"input_tokens": 10, "output_tokens": 20},
                    "duration_ms": 100,
                    "provider_source": "fixture",
                }

            args = argparse.Namespace(
                base_url="http://127.0.0.1:8787",
                label="after",
                output=str(target),
            )
            with patch.object(EVAL.getpass, "getpass", return_value="test-password"), patch.object(EVAL, "api_json", side_effect=api_json):
                with self.assertRaisesRegex(ValueError, "1 个样本生成失败"):
                    EVAL.run_live(args)

            self.assertEqual(calls, sorted(EVAL.cases_by_id()))
            evaluation = EVAL.read_json(target / "report-evaluation.json")
            run_metadata = EVAL.read_json(target / "run.json")
            self.assertEqual(evaluation["cases"]["concurrency"]["status"], "生成失败")
            self.assertEqual(run_metadata["generation_settings"]["thinking_type"], "enabled")
            self.assertEqual(run_metadata["generation_settings"]["reasoning_effort"], "high")
            self.assertEqual(len(list((target / "outputs").glob("*.md"))), 5)
            self.assertEqual((target / "raw-responses" / "concurrency.txt").read_text(), "not-json output")
            self.assertEqual(EVAL.read_json(target / "diagnostics" / "concurrency.json")["stop_reason"], "end_turn")
            saved_text = "\n".join(path.read_text(encoding="utf-8") for path in target.rglob("*") if path.is_file())
            self.assertNotIn("secret-test-token", saved_text)
            self.assertNotIn("test-password", saved_text)


if __name__ == "__main__":
    unittest.main()
