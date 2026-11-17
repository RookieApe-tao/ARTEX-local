import argparse
import importlib.util
import io
import re
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
            "const DeliveryReportTraceabilityGuidance = `原文规则`\n\n"
            "const DeliveryReportWritingRules = DeliveryReportRuntimeGuidance + DeliveryReportStyleGuidance + DeliveryReportTraceabilityGuidance + `新版写作规则`\n"
            "const DeliveryReportDraftRules = DeliveryReportRuntimeGuidance + DeliveryReportEvidenceGuidance + DeliveryReportStyleGuidance + DeliveryReportTraceabilityGuidance + `JSON 草稿规则`\n"
        )
        self.assertEqual(EVAL.expand_go_policy(old), "旧版规则")
        self.assertEqual(EVAL.expand_go_policy(current), "共享运行约定证据规则简短规则原文规则JSON 草稿规则")
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
                "# 示例下载线索\n\nCVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N 评分待复核\n\n"
                "## 描述\n待核实。\n\n## 攻击链路\n```text\n用户请求\n└─ GET /api/files/file-a/download\n```\n\n"
                "## 测试过程\n测试时间：2026-11-01 10:00:00（北京时间）\n现有记录只有响应头，响应正文未取得。\n\n"
                "## Burp 复现\n请求包供授权测试人员导入 Repeater。\n\n```http\nGET /api/files/file-a/download HTTP/1.1\nHost: report-eval.invalid\n```\n\n"
                "## 修复建议\n先补齐响应证据后再确认修复措施。\n",
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
            evaluation = EVAL.read_json(folder / "report-evaluation.json")
            self.assertEqual(evaluation["cases"]["incomplete"]["status"], "人工审阅待完成")
            stored_draft = (folder / "drafts" / "incomplete.md").read_text(encoding="utf-8")
            self.assertNotIn("Content-Length: 48", stored_draft)
            self.assertIn("Content-Length: 48", final)

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

    def test_partial_run_can_be_reviewed_but_not_counted_as_full_comparison(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            partial = root / "partial"
            self.prepare(partial, "fixture-model")
            meta = EVAL.read_json(partial / "run.json")
            meta["corpus_sha256"] = {"idor": meta["corpus_sha256"]["idor"]}
            EVAL.write_json(partial / "run.json", meta)
            reviewed = EVAL.review_run(partial)
            self.assertEqual(set(reviewed["cases"]), {"idor"})

            comparison_path = root / "comparison.json"
            EVAL.compare(argparse.Namespace(
                before=str(partial), after=str(partial), output=str(comparison_path),
            ))
            comparison = EVAL.read_json(comparison_path)
            self.assertFalse(comparison["comparison_complete"])
            self.assertTrue(any("未包含全部固定样本" in item for item in comparison["limitations"]))

    def test_report_format_metrics_do_not_claim_semantic_quality(self):
        material = EVAL.cases()[0]
        report = chr(10).join([
            "# 漏洞名称",
            "CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N 评分待复核",
            "## 描述",
            "观察结果和评分前提待复核。",
            "## 攻击链路",
            "```text", "普通用户", "└─ GET /api/test", "```",
            "## 测试过程",
            "测试时间：2026-11-01 10:00:00（北京时间）",
            "核对请求和响应。",
            "## Burp 复现",
            "```http", "GET /api/test HTTP/1.1", "Host: example.invalid", "```",
            "## 修复建议", "补齐证据后再确定修复措施。",
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
            "description": "问题。评分前提需复核。",
            "remediation": "使用参数化查询。",
            "test_process": "测试时间：2026-11-01 10:00:00（北京时间）\n做对照测试，字段值未读取。",
            "burp_reproduction": "合成样本请求供授权测试人员导入 Repeater。",
            "attack_chain": "```text\nGET /api/products?name=alpha\n"
            "├─ GET /api/products?name=alpha' AND 1=1-- → 返回1条\n```",
        }
        report = EVAL.attach_evidence(case, EVAL.report_from_draft(case, draft))
        measured = EVAL.metrics(case, report)
        self.assertFalse(measured["attack_chain_request_paths_match_evidence"])
        self.assertIn("GET /api/products?name=alpha'", measured["attack_chain_request_paths_not_found"])

    def test_attack_chain_metrics_detect_multiple_roots(self):
        case = EVAL.cases_by_id()["idor"]
        report = EVAL.attach_evidence(case, "\n".join([
            "# 示例越权漏洞",
            "CVSS 4.0：" + case["facts"]["cvss_vector"] + " 评分待复核",
            "## 描述", "越权行为待核实。",
            "## 攻击链路", "```text", "GET /api/jobs/job-a", "├─ 200 OK",
            "POST /api/jobs/job-a/types", "└─ 200 OK", "```",
            "## 测试过程", "测试时间：2026-11-01 10:00:00（北京时间）", "请求对照。",
            "## Burp 复现", "请求包供授权人员导入 Repeater。",
            "## 修复建议", "服务端校验资源归属。",
        ]))
        measured = EVAL.metrics(case, report)
        self.assertEqual(measured["attack_chain_root_count"], 2)
        self.assertFalse(measured["attack_chain_single_root"])
        self.assertEqual(measured["attack_chain_disconnected_nodes"], ["POST /api/jobs/job-a/types"])

    def test_attack_chain_request_occurrences_detect_missing_repeated_request(self):
        case = EVAL.cases_by_id()["concurrency"]
        request_lines = [
            re.search(r"(?m)^([A-Z]+)\s+(\S+)\s+HTTP/\d(?:\.\d)?\s*$", item["request"])
            for item in case["evidence"]
        ]
        nodes = [f"├─ {match.group(1)} {match.group(2)}" for match in request_lines]

        def measured_for(chain_nodes):
            report = "\n".join([
                "# 并发登记问题",
                "## 攻击链路",
                "```text",
                "验证请求组",
                *chain_nodes,
                "```",
            ])
            return EVAL.metrics(case, EVAL.attach_evidence(case, report))

        complete = measured_for(nodes)
        self.assertTrue(complete["attack_chain_request_occurrences_match_evidence"])
        missing_one_submit = measured_for(nodes[:2] + nodes[3:])
        self.assertTrue(missing_one_submit["attack_chain_request_paths_match_evidence"])
        self.assertFalse(missing_one_submit["attack_chain_request_occurrences_match_evidence"])
        self.assertEqual(
            missing_one_submit["attack_chain_request_occurrence_differences"]["POST /api/registrations"],
            {"expected": 4, "actual": 3},
        )

    def test_non_http_attack_chain_commands_must_match_exact_evidence(self):
        case = EVAL.cases_by_id()["non-http"]
        headings = [
            "# 本地文件权限问题",
            "CVSS 4.0：CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N 评分待复核",
            "## 描述",
            "离线合成场景，未测试真实目标。读取到合成记录，真实影响未验证。",
            "## 攻击链路",
        ]
        process_sections = [
            "## 测试过程",
            "测试时间：2026-11-01 10:00:00（北京时间）",
            "检查文件权限并读取样本。",
            "## Burp 复现",
            "Burp 不适用：本次证据为本地命令或终端输出。",
            "## 修复建议",
            "将文件权限收紧至授权账号范围。",
        ]
        commands = [item["command"] for item in case["evidence"]]
        valid_chain = "\n".join([
            "```text",
            "本地文件权限验证",
            f"├─ {commands[0]} → 当前用户信息",
            *[f"├─ {command}" for command in commands[1:]],
            "```",
        ])
        valid = EVAL.metrics(case, EVAL.attach_evidence(case, "\n".join(headings + [valid_chain] + process_sections)))
        self.assertTrue(valid["attack_chain_shell_commands_match_evidence"])
        self.assertFalse(valid["attack_chain_shell_commands_not_found"])
        self.assertFalse(valid["attack_chain_shell_commands_missing"])

        annotated_chain = "\n".join([
            "```text",
            "本地文件权限验证",
            f"├─ {commands[0]} （当前用户）",
            *[f"├─ {command}" for command in commands[1:]],
            "```",
        ])
        annotated = EVAL.metrics(
            case, EVAL.attach_evidence(case, "\n".join(headings + [annotated_chain] + process_sections))
        )
        self.assertTrue(annotated["attack_chain_shell_commands_match_evidence"])
        self.assertFalse(annotated["attack_chain_shell_commands_not_found"])
        self.assertFalse(annotated["attack_chain_shell_commands_missing"])

        concise_chain = "\n".join([
            "```text",
            "本地文件权限验证",
            *[f"├─ {command}" for command in commands[1:]],
            "```",
        ])
        concise = EVAL.metrics(
            case, EVAL.attach_evidence(case, "\n".join(headings + [concise_chain] + process_sections))
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
            case, EVAL.attach_evidence(case, "\n".join(headings + [inaccurate_chain] + process_sections))
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
            "CVSS 4.0：" + case["facts"]["cvss_vector"] + " 评分待复核",
            "## 描述",
            "观察到设置变化，影响已限定。",
            "## 攻击链路",
            "```text",
            "用户入口",
            "└─ GET /api/jobs/job-a",
            "   └─ 返回 200/1382B，held=alice",
            "```",
            "## 测试过程",
            "测试时间：2026-11-01 10:00:00（北京时间）",
            "核对请求和响应，其他影响未验证。",
            "## Burp 复现",
            "请求包尚未提供。",
            "## 修复建议",
            "校验资源归属。",
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
            "请求包尚未提供。",
            "以下请求包供渗透测试工程师在授权目标中导入 Burp Repeater 复现或复测；请求包本身不代表已通过 Burp 发送或验证。\n\n"
            "```http\nGET /api/jobs/job-a HTTP/1.1\n"
            "Host: report-eval.invalid\nX-Eval-Actor: user-a\n```",
        )
        with_packet = with_packet.replace("返回 200/1382B，held=alice", "作业信息可读取")
        measured_with_packet = EVAL.metrics(
            case, EVAL.attach_evidence(case, with_packet)
        )
        self.assertTrue(measured_with_packet["burp_request_packet_present"])
        self.assertTrue(measured_with_packet["burp_request_packet_matches_evidence"])
        self.assertTrue(measured_with_packet["burp_request_identity_headers_match_evidence"])
        self.assertFalse(measured_with_packet["unclear_report_shorthand_found"])

        forged_identity = with_packet.replace(
            "X-Eval-Actor: user-a", "Authorization: Bearer <ATTACKER_TOKEN>"
        )
        measured_forged_identity = EVAL.metrics(
            case, EVAL.attach_evidence(case, forged_identity)
        )
        self.assertFalse(measured_forged_identity["burp_request_identity_headers_match_evidence"])

        used_packet = with_packet.replace(
            "以下请求包供渗透测试工程师在授权目标中导入 Burp Repeater 复现或复测；请求包本身不代表已通过 Burp 发送或验证。",
            "已在 Burp Repeater 中发送以下请求：",
        )
        measured_used_packet = EVAL.metrics(
            case, EVAL.attach_evidence(case, used_packet)
        )
        self.assertTrue(measured_used_packet["burp_request_packet_required"])
        self.assertTrue(measured_used_packet["burp_request_packet_present"])
        self.assertTrue(measured_used_packet["burp_request_packet_matches_evidence"])
        self.assertTrue(measured_used_packet["burp_actual_send_claim_detected"])

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
            "请求包尚未提供。",
            "以下请求包供渗透测试工程师在授权目标中导入 Burp Repeater 复现或复测；请求包本身不代表已通过 Burp 发送或验证。\n\n"
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

    def test_redacted_sensitive_identity_headers_match_evidence(self):
        case = EVAL.cases_by_id()["session"]
        report = "\n".join([
            "# 退出后会话仍有效",
            "CVSS 4.0：" + case["facts"]["cvss_vector"] + " 评分待复核",
            "## 描述",
            "样本观察到退出后仍能访问用户接口，真实数据影响待复核。",
            "## 攻击链路",
            "```text",
            "会话访问",
            "└─ GET /api/me",
            "   └─ 返回合成用户记录",
            "```",
            "## 测试过程",
            "测试时间：2026-11-01 10:00:00（北京时间）",
            "使用同一会话请求退出前后接口，最长有效时间未验证。",
            "## Burp 复现",
            "离线合成请求样例，不能直接发送到真实目标。请求包供授权测试人员导入 Repeater，不代表已发送或验证。",
            "```http",
            "GET /api/me HTTP/1.1",
            "Host: report-eval.invalid",
            "Cookie: [REDACTED]",
            "Content-Length: 0",
            "```",
            "## 修复建议",
            "退出时使当前会话立即失效。",
        ])
        report = EVAL.attach_evidence(case, report)
        measured = EVAL.metrics(case, report)
        self.assertTrue(measured["burp_request_identity_headers_match_evidence"])

        wrong_cookie = report.replace(
            "Cookie: [REDACTED]", "Cookie: session=attacker"
        )
        self.assertFalse(
            EVAL.metrics(case, wrong_cookie)[
                "burp_request_identity_headers_match_evidence"
            ]
        )

    def test_non_http_and_remediation_guardrail_metrics(self):
        case = EVAL.cases_by_id()["non-http"]
        report = "\n".join([
            "# 本地文件权限问题",
            "CVSS 4.0：" + case["facts"]["cvss_vector"] + " 评分待复核",
            "## 描述",
            "离线合成场景，未测试真实目标。读取到固定合成记录，未验证真实数据影响；向量中的影响为评分假设。",
            "## 攻击链路",
            "```text",
            "本地终端",
            "└─ cat /tmp/report-eval/backups/customer-notes.txt",
            "   └─ 读取到合成记录",
            "```",
            "## 测试过程",
            "测试时间：2026-11-01 10:00:00（北京时间）",
            "使用本地命令检查文件权限并读取样本。其他目录未检查。",
            "## Burp 复现",
            "Burp 不适用：本次通过本地命令验证。",
            "## 修复建议",
            "将备份文件权限收紧至仅授权账号可读。",
        ])
        measured = EVAL.metrics(case, report)
        self.assertTrue(measured["non_http_burp_not_applicable"])
        self.assertFalse(measured["non_http_unexpected_http_request_packet"])
        self.assertEqual(measured["remediation_alternative_terms_found"], [])
        self.assertFalse(measured["remediation_conditional_fix_detected"])
        self.assertEqual(measured["synthetic_confidentiality_claim_terms_found"], [])
        sensitive_asset_claim = report.replace(
            "读取到固定合成记录", "低权限用户可访问敏感备份"
        )
        self.assertIn(
            "敏感备份",
            EVAL.metrics(case, sensitive_asset_claim)[
                "synthetic_confidentiality_claim_terms_found"
            ],
        )
        negated_sensitive_asset = report.replace(
            "读取到固定合成记录", "未验证敏感备份内容"
        )
        self.assertNotIn(
            "敏感备份",
            EVAL.metrics(case, negated_sensitive_asset)[
                "synthetic_confidentiality_claim_terms_found"
            ],
        )
        self.assertTrue(measured["synthetic_target_scope_present"])

        without_scope = report.replace("离线合成场景，未测试真实目标。", "")
        self.assertFalse(EVAL.metrics(case, without_scope)["synthetic_target_scope_present"])

        fabricated_packet = report.replace(
            "Burp 不适用：本次通过本地命令验证。",
            "Burp 不适用。\n\n```http\nGET /fake HTTP/1.1\nHost: example.invalid\n```",
        )
        self.assertTrue(
            EVAL.metrics(case, fabricated_packet)[
                "non_http_unexpected_http_request_packet"
            ]
        )
        alternative = report.replace(
            "将备份文件权限收紧至仅授权账号可读。",
            "若确认风险，则将权限设为 600 或 640。",
        ).replace("读取到固定合成记录", "读取到合成样本泄露和敏感数据")
        flagged = EVAL.metrics(case, alternative)
        self.assertEqual(flagged["remediation_alternative_terms_found"], ["或"])
        self.assertTrue(flagged["remediation_conditional_fix_detected"])
        self.assertIn("敏感数据", flagged["synthetic_confidentiality_claim_terms_found"])
        self.assertIn("合成样本泄露", flagged["synthetic_confidentiality_claim_terms_found"])

        low_confidentiality_claim = report.replace(
            "读取到固定合成记录", "低机密性影响"
        )
        self.assertIn(
            "低机密性影响",
            EVAL.metrics(case, low_confidentiality_claim)[
                "synthetic_confidentiality_claim_terms_found"
            ],
        )
        local_impact_claim = report.replace(
            "读取到固定合成记录", "仅证实机密性局部影响"
        )
        self.assertIn(
            "机密性局部影响",
            EVAL.metrics(case, local_impact_claim)[
                "synthetic_confidentiality_claim_terms_found"
            ],
        )
        negated_claims = report.replace(
            "读取到固定合成记录", "无实际响应内容支撑机密性受损结论"
        )
        self.assertEqual(
            EVAL.metrics(case, negated_claims)[
                "synthetic_confidentiality_claim_terms_found"
            ],
            [],
        )

    def test_live_evaluation_only_accepts_loopback_and_renders_cvss_header(self):
        for url in ("https://example.com", "http://127.0.0.1.evil.test:8787", "http://user:placeholder@127.0.0.1:8787"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                EVAL.local_base_url(url)
        case = EVAL.cases_by_id()["idor"]
        draft = {
            "cvss_vector": case["facts"]["cvss_vector"],
            "description": "问题说明，评分依据待复核。",
            "attack_chain": "```text\n普通用户\n└─ 请求接口\n   └─ 观察结果\n```",
            "test_process": "测试时间：2026-11-01 10:00:00（北京时间）\n复现步骤。批量编号未验证。",
            "burp_reproduction": "请求包供授权测试人员导入 Repeater。",
            "remediation": "服务端校验当前用户与作业归属。",
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
                if case["kind"] == "non_http":
                    burp_reproduction = "Burp 不适用：本次证据为本地命令或终端输出。"
                else:
                    request_packet = next(item["request"] for item in case["evidence"] if item.get("request"))
                    burp_reproduction = (
                        "请求包供渗透测试工程师在授权目标中导入 Burp Repeater 复现或复测；"
                        "请求包本身不代表已通过 Burp 发送或验证。\n```http\n"
                        + request_packet.strip()
                        + "\n```"
                    )
                return {
                    "draft": {
                        "cvss_vector": case["facts"]["cvss_vector"],
                        "description": "离线合成场景，未测试真实目标。问题说明，评分依据待复核。",
                        "attack_chain": "```text\n普通用户\n└─ 请求对应接口\n   └─ 观察到样本结果\n```",
                        "test_process": "测试时间：2026-11-01 10:00:00（北京时间）\n按样本材料核对，未覆盖的边界仍待验证。",
                        "burp_reproduction": burp_reproduction,
                        "remediation": "在服务端落实对应的业务校验。",
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
