#!/usr/bin/env python3
"""准备、执行及整理固定报告样本评测。"""

import argparse
import getpass
import hashlib
import json
import math
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


CASE_DIR = Path(__file__).resolve().parent / "cases"
HEADINGS = ["描述", "修复建议", "测试过程", "攻击链路", "证据说明"]
SUBHEADINGS = [
    ("描述", "定级依据"),
    ("测试过程", "发现过程与攻击思路"),
    ("测试过程", "失败尝试与未验证项"),
    ("测试过程", "Burp 复现"),
    ("证据说明", "复测标准"),
]
DIMENSIONS = ["事实准确", "容易理解", "可以复现", "影响边界", "修复具体"]
INSTRUCTION = (
    "只根据附带的离线合成材料写一份交付报告；不调用工具、不执行命令、不访问网络。"
    "遵循系统提示中的固定结构、事实来源、影响边界和攻击链顺序。先核对证据与缺口，再写短句正文。"
    "不要重复请求、响应或终端原文；评测器会在正文后附加完整材料。"
)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    Path(path).write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def cases():
    return [read_json(path) for path in sorted(CASE_DIR.glob("*.json"))]


def cases_by_id():
    return {case["id"]: case for case in cases()}


def model_input(case):
    # 参考答案和审阅标准不进入模型输入，避免参考答案影响对照结果。
    material = {
        key: value
        for key, value in case.items()
        if key not in ("reference_report", "review")
    }
    material["evidence"] = [
        {key: value for key, value in item.items() if key != "id"}
        for item in case["evidence"]
    ]
    return material


def attach_evidence(case, report):
    """模拟 ARTEX 在保存时附加原始材料，避免模型重复生成证据包。"""
    normalized_report = report.replace("\r\n", "\n")
    blocks = []
    is_http = case["kind"] == "http"
    for item in case["evidence"]:
        fields = ("request", "response") if is_http else ("command", "stdout", "stderr")
        item_blocks = []
        for field in fields:
            value = item.get(field)
            if not value:
                continue
            normalized = value.replace("\r\n", "\n")
            if normalized.strip() in normalized_report:
                continue
            if is_http:
                title = "请求" if field == "request" else (
                    "响应" if item.get("response_complete", True) else "响应（正文未取得）"
                )
                language = "http"
            else:
                title = {"command": "命令", "stdout": "标准输出", "stderr": "错误输出"}[field]
                language = "text"
            item_blocks.append(f"{title}：\n\n```{language}\n{normalized.rstrip()}\n```")
        if item_blocks:
            blocks.append(f"#### {item['purpose']}\n\n" + "\n\n".join(item_blocks))
    if not blocks:
        return report.rstrip() + "\n"
    appendix = "### 原始材料\n\n" + "\n\n".join(blocks)
    return report.rstrip() + "\n\n" + appendix + "\n"


def report_from_draft(case, draft):
    vector = draft["cvss_vector"].strip()
    score = score_cvss4_vectors([vector]).get(vector)
    if score:
        cvss_line = f"CVSS 4.0：{vector}  评分 {score['score']:.1f}（{score['severity']}）"
    else:
        cvss_line = f"CVSS 4.0：{vector}  评分待复核"
    sections = [
        f"# {case['name']}\n\n{cvss_line}",
        "## 描述\n\n" + draft["description"].strip(),
        "## 修复建议\n\n" + draft["remediation"].strip(),
        "## 测试过程\n\n" + draft["test_process"].strip(),
        "## 攻击链路\n\n" + draft["attack_chain"].strip(),
        "## 证据说明\n\n" + draft["discovery_path"].strip(),
    ]
    return "\n\n".join(sections) + "\n"


def score_cvss4_vectors(vectors):
    """Use the same frontend scorer for the numeric header, when its local dependency exists."""
    root = Path(__file__).resolve().parents[2]
    typescript = root / "web" / "node_modules" / "typescript"
    source = root / "web" / "src" / "lib" / "cvss-v4.ts"
    if not typescript.is_dir() or not source.is_file():
        return {}
    script = r"""
const fs = require('node:fs');
const ts = require('./web/node_modules/typescript');
const source = fs.readFileSync('./web/src/lib/cvss-v4.ts', 'utf8');
const output = ts.transpileModule(source, {compilerOptions: {module: ts.ModuleKind.CommonJS}}).outputText;
const loadedModule = {exports: {}};
new Function('exports', 'require', 'module', output)(loadedModule.exports, require, loadedModule);
const vectors = JSON.parse(fs.readFileSync(0, 'utf8'));
const result = {};
for (const vector of vectors) result[vector] = loadedModule.exports.scoreCVSS4Base(vector);
process.stdout.write(JSON.stringify(result));
"""
    try:
        completed = subprocess.run(
            ["node", "-e", script], cwd=root,
            input=json.dumps(vectors), text=True, capture_output=True, check=True, timeout=10,
        )
        return json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        print("未能使用前端 CVSS 4.0 评分器，报告头将标为待复核。", file=sys.stderr)
        return {}


def local_base_url(value):
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("真实模型评测只允许连接本机 ARTEX 地址")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("ARTEX 地址不能携带凭据、查询参数或片段")
    return value.rstrip("/")


def api_json(base_url, path, method="GET", payload=None, token=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(base_url + path, data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    try:
        opener = urllib.request.build_opener(NoRedirectHandler())
        with opener.open(request, timeout=300) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            error_body = json.loads(exc.read().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            error_body = {}
        if not isinstance(error_body, dict):
            error_body = {}
        message = error_body.get("error")
        raw_output = error_body.get("raw_output")
        diagnostic = error_body.get("diagnostic")
        raise ReportEvalHTTPError(
            exc.code,
            message if isinstance(message, str) else "",
            raw_output if isinstance(raw_output, str) else "",
            diagnostic,
        ) from None
    except urllib.error.URLError as exc:
        raise ValueError("无法连接本机 ARTEX；确认容器正在运行且端口正确") from exc


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class ReportEvalHTTPError(ValueError):
    def __init__(self, status, message, raw_output="", diagnostic=None):
        if message:
            message = f"ARTEX 本地接口返回 HTTP {status}：{message}"
        else:
            message = f"ARTEX 本地接口返回 HTTP {status}"
        super().__init__(message)
        self.raw_output = raw_output
        self.diagnostic = diagnostic if isinstance(diagnostic, dict) else {}


def run_live(args):
    base_url = local_base_url(args.base_url)
    target = Path(args.output)
    if target.exists():
        raise ValueError("输出目录已存在；请使用新目录，避免覆盖已有评测结果")
    password = getpass.getpass("ARTEX 本地登录密码：")
    if not password:
        raise ValueError("登录密码不能为空")
    login = api_json(base_url, "/api/auth/login", method="POST", payload={"username": "ARTEX", "password": password})
    password = ""
    token = login.get("token", "")
    if not token:
        raise ValueError("本地登录未返回会话令牌")
    info = api_json(base_url, "/api/report-eval", token=token)
    local_cases = cases()
    ids = [case["id"] for case in local_cases]
    if info.get("case_ids") != sorted(ids):
        raise ValueError("运行中的固定样本与本地评测材料不一致")
    model = info.get("model") or "未返回模型标识"
    target.mkdir(parents=True)
    for folder in ("inputs", "drafts", "outputs", "raw-responses", "diagnostics", "reviews"):
        (target / folder).mkdir()
    corpus = {}
    for case in local_cases:
        cid = case["id"]
        material = model_input(case)
        corpus[cid] = digest(json.dumps(material, ensure_ascii=False, sort_keys=True))
        write_json(target / "inputs" / f"{cid}.json", {
            "system_sha256": info.get("system_sha256"),
            "material": material,
            "tools": [],
        })
        write_json(target / "reviews" / f"{cid}.json", {
            "scenario_id": cid,
            "reviewer": "",
            "scores": dict.fromkeys(DIMENSIONS),
            "notes": "",
            "criteria": case["review"],
        })
    meta = {
        "schema_version": 1,
        "label": args.label,
        "model": model,
        "provider_source": info.get("provider_source"),
        "generation_settings": {
            "completion_passes": info.get("completion_passes"),
            "format": info.get("format"),
            "thinking_type": info.get("thinking_type"),
            "reasoning_effort": info.get("reasoning_effort"),
            "temperature": None,
            "seed": None,
            "max_output_tokens": info.get("max_output_tokens"),
            "tools": 0,
        },
        "policy_sha256": info.get("system_sha256"),
        "corpus_sha256": corpus,
        "results": {},
        "failures": {},
    }
    write_json(target / "run.json", meta)
    try:
        for case in local_cases:
            cid = case["id"]
            try:
                result = api_json(base_url, "/api/report-eval/" + urllib.parse.quote(cid, safe=""), method="POST", payload=None, token=token)
                draft = result.get("draft")
                if not isinstance(draft, dict) or not all(draft.get(key) for key in (
                    "cvss_vector", "description", "remediation", "test_process", "attack_chain", "discovery_path",
                )):
                    raise ValueError("模型返回缺少必需报告字段")
                report = report_from_draft(case, draft)
                if report.strip() == case["reference_report"].strip():
                    raise ValueError("生成内容与人工参考完全相同，拒绝记为模型产出")
                write_json(target / "drafts" / f"{cid}.json", draft)
                (target / "drafts" / f"{cid}.md").write_text(report, encoding="utf-8")
                final_report = attach_evidence(case, report)
                (target / "outputs" / f"{cid}.md").write_text(final_report, encoding="utf-8")
                usage = result.get("usage", {})
                meta["results"][cid] = {
                    "source": "model",
                    "output_file": f"outputs/{cid}.md",
                    "output_sha256": digest(final_report),
                    "draft_file": f"drafts/{cid}.md",
                    "draft_sha256": digest(report),
                    "input_tokens": usage.get("input_tokens"),
                    "output_tokens": usage.get("output_tokens"),
                    "cached_input_tokens": usage.get("cache_read_tokens"),
                    "duration_seconds": round(result.get("duration_ms", 0) / 1000, 3),
                    "provider_source": result.get("provider_source"),
                }
                meta["failures"].pop(cid, None)
                write_json(target / "run.json", meta)
                print(f"{cid} 完成：{usage.get('input_tokens', 0)} 输入 token，{usage.get('output_tokens', 0)} 输出 token，{result.get('duration_ms', 0) / 1000:.1f} 秒")
            except ValueError as exc:
                meta["failures"][cid] = str(exc)
                if isinstance(exc, ReportEvalHTTPError) and exc.raw_output:
                    (target / "raw-responses" / f"{cid}.txt").write_text(exc.raw_output, encoding="utf-8")
                if isinstance(exc, ReportEvalHTTPError) and exc.diagnostic:
                    write_json(target / "diagnostics" / f"{cid}.json", exc.diagnostic)
                write_json(target / "run.json", meta)
                print(f"{cid} 失败：{exc}")
    finally:
        token = ""
    write_json(target / "report-evaluation.json", review_run(target))
    completed = len(meta["results"])
    print(f"已生成 {completed}/{len(local_cases)} 个固定样本：{target}")
    if meta["failures"]:
        raise ValueError(f"{len(meta['failures'])} 个样本生成失败；结果和错误记录已保存")


def read_policy(args):
    path = args.policy_file or args.policy_source
    policy = Path(path).read_text(encoding="utf-8")
    if args.policy_source:
        policy = expand_go_policy(policy)
    if not policy.strip():
        raise ValueError("写作规则为空")
    return policy


def expand_go_policy(source):
    allowed = {
        "DeliveryReportWritingRules",
        "DeliveryReportDraftRules",
        "DeliveryReportRuntimeGuidance",
        "DeliveryReportHardCaseGuidance",
        "DeliveryReportStyleGuidance",
    }

    def expand(name, parents):
        if name not in allowed or name in parents:
            raise ValueError("写作规则只支持原始字符串与已知常量相加，不能包含未知或循环引用")
        definitions = list(re.finditer(r"(?m)^const\s+" + re.escape(name) + r"\s*=\s*", source))
        if len(definitions) != 1:
            raise ValueError(f"必须有且只有一个 {name} 常量声明")
        position = definitions[0].end()
        terms = []
        while True:
            while position < len(source) and source[position].isspace():
                position += 1
            if source[position:position + 1] == "`":
                end = source.find("`", position + 1)
                if end < 0:
                    raise ValueError("写作规则的 Go 原始字符串未闭合")
                terms.append(source[position + 1:end])
                position = end + 1
            else:
                identifier = re.match(r"[A-Za-z_][A-Za-z_0-9]*", source[position:])
                if not identifier:
                    raise ValueError("写作规则只支持原始字符串与已知常量相加")
                terms.append(expand(identifier.group(), parents | {name}))
                position += len(identifier.group())
            previous = position
            while position < len(source) and source[position].isspace():
                position += 1
            if source[position:position + 1] == "+":
                position += 1
                continue
            if position == len(source):
                break
            if "\n" in source[previous:position] and (source.startswith("const ", position) or source.startswith("//", position)):
                break
            raise ValueError("写作规则包含不支持的 Go 表达式，请明确导出纯文本规则")
        return "".join(terms)

    target = "DeliveryReportDraftRules"
    if not re.search(r"(?m)^const\s+" + re.escape(target) + r"\s*=", source):
        target = "DeliveryReportWritingRules"
    return expand(target, set())


def prepare(args):
    policy = read_policy(args)
    target = Path(args.output)
    if target.exists():
        raise ValueError("输出目录已存在；请使用新的评测目录，以免覆盖旧结果")
    target.mkdir(parents=True)
    for folder in ("inputs", "drafts", "outputs", "reviews"):
        (target / folder).mkdir()
    (target / "policy.txt").write_text(policy, encoding="utf-8")
    corpus = {}
    for case in cases():
        cid = case["id"]
        material = model_input(case)
        corpus[cid] = digest(json.dumps(material, ensure_ascii=False, sort_keys=True))
        write_json(
            target / "inputs" / f"{cid}.json",
            {"system": policy, "instruction": INSTRUCTION, "material": material},
        )
        write_json(
            target / "reviews" / f"{cid}.json",
            {
                "scenario_id": cid,
                "reviewer": "",
                "scores": dict.fromkeys(DIMENSIONS),
                "notes": "",
                "criteria": case["review"],
            },
        )
    write_json(
        target / "run.json",
        {
            "schema_version": 1,
            "label": args.label,
            "model": args.model,
            "generation_settings": {
                "temperature": args.temperature,
                "seed": args.seed,
                "max_output_tokens": args.max_output_tokens,
            },
            "policy_sha256": digest(policy),
            "corpus_sha256": corpus,
            "results": {},
        },
    )
    print(f"已准备 {len(corpus)} 个离线输入：{target}")
    print("尚未调用模型；outputs 目录为空，不能据此声称评测完成。")


def collect(args):
    target = Path(args.run)
    meta = read_json(target / "run.json")
    if args.case not in meta["corpus_sha256"]:
        raise ValueError("场景不属于这次评测")
    if args.model != meta["model"]:
        raise ValueError("模型名称与 run.json 不一致，应另建评测目录")
    output = target / "outputs" / f"{args.case}.md"
    if output.exists() or args.case in meta["results"]:
        raise ValueError("该场景已有结果；请另建评测目录保留原结果")
    draft = Path(args.report).read_text(encoding="utf-8")
    if not draft.strip():
        raise ValueError("报告为空")
    reference = (CASE_DIR / f"{args.case}.reference.md").read_text(encoding="utf-8")
    if args.source == "model" and draft.strip() == reference.strip():
        raise ValueError("内容与人工参考完全相同；不能将参考报告自动记为模型产出")
    draft_file = None
    draft_sha256 = None
    if args.source == "model":
        draft_path = target / "drafts" / f"{args.case}.md"
        shutil.copyfile(args.report, draft_path)
        draft_file = f"drafts/{args.case}.md"
        draft_sha256 = digest(draft)
        final_report = attach_evidence(cases_by_id()[args.case], draft)
    else:
        final_report = draft
    output.write_text(final_report, encoding="utf-8")
    meta["results"][args.case] = {
        "source": args.source,
        "output_file": f"outputs/{args.case}.md",
        "output_sha256": digest(final_report),
        "draft_file": draft_file,
        "draft_sha256": draft_sha256,
        "input_tokens": args.input_tokens,
        "output_tokens": args.output_tokens,
        "cached_input_tokens": args.cached_input_tokens,
        "duration_seconds": args.seconds,
    }
    write_json(target / "run.json", meta)
    print(f"已收集 {args.case}；来源：{args.source}。语义质量仍需人工审阅。")


def markdown_parts(report):
    narrative, code_blocks = [], []
    fence, block = None, []
    for line in report.splitlines():
        if fence:
            if re.fullmatch(re.escape(fence[0]) + "{" + str(len(fence)) + r",}\s*", line.strip()):
                code_blocks.append("\n".join(block))
                fence, block = None, []
            else:
                block.append(line)
            continue
        opened = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if opened:
            fence = opened.group(1)
        else:
            narrative.append(line)
    return "\n".join(narrative), code_blocks, fence is None


def metrics(case, report):
    narrative, blocks, closed = markdown_parts(report)
    normalized = report.replace("\r\n", "\n")
    # The platform appends raw evidence after the report body; it is outside the fixed template.
    report_body = re.split(r"(?m)^### 原始材料\s*$", normalized, maxsplit=1)[0]
    narrative = re.split(r"(?m)^### 原始材料\s*$", narrative, maxsplit=1)[0]
    length_lines = report_body.splitlines()
    if length_lines and length_lines[0].startswith("# "):
        length_lines = length_lines[1:]
    length_lines = [line for line in length_lines if not line.startswith("CVSS 4.0：")]
    narrative_characters = len("\n".join(length_lines).strip())
    heading_rows = re.findall(r"^ {0,3}(#{1,6})\s+(.+?)\s*$", narrative, re.M)
    headings = [text for marks, text in heading_rows if len(marks) == 2]
    subheadings = []
    section = ""
    for marks, text in heading_rows:
        if len(marks) == 2:
            section = text
        elif len(marks) == 3:
            subheadings.append((section, text))
    title_count = sum(1 for marks, _ in heading_rows if len(marks) == 1)
    unexpected_heading_levels = [len(marks) for marks, _ in heading_rows if len(marks) > 3]
    chain_match = re.search(
        r"(?ms)^## 攻击链路\s*\n(.*?)(?=^## |\Z)", report_body
    )
    chain_text = chain_match.group(1) if chain_match else ""
    chain_requests = []
    for block in re.findall(r"```[^\n]*\n(.*?)```", chain_text, re.S):
        for line in block.splitlines():
            node = re.sub(r"^[\s│├└─>→↓]+", "", line)
            request = re.match(
                r"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)", node
            )
            if request:
                chain_requests.append(f"{request.group(1)} {request.group(2)}")
    evidence_requests = set()
    if case["kind"] == "http":
        for item in case["evidence"]:
            request_line = re.search(
                r"(?m)^([A-Z]+)\s+(\S+)\s+HTTP/\d(?:\.\d)?\s*$",
                item.get("request", ""),
            )
            if request_line:
                evidence_requests.add(f"{request_line.group(1)} {request_line.group(2)}")
    missing_chain_requests = [item for item in chain_requests if item not in evidence_requests]
    if case["kind"] == "http" and not chain_requests:
        missing_chain_requests.append("攻击链中没有 HTTP 请求节点")
    preserved, missing = [], []
    for material in case["evidence"]:
        fields = ("request", "response") if case["kind"] == "http" else ("command", "stdout", "stderr")
        for field in fields:
            value = material.get(field)
            if not value:
                continue
            name = material["id"] + "." + field
            if value.replace("\r\n", "\n").strip() in normalized:
                preserved.append(name)
            else:
                missing.append(name)
    return {
        "total_characters": len(report),
        "narrative_characters": narrative_characters,
        "narrative_within_800_characters": narrative_characters <= 800,
        "headings": headings,
        "required_headings_ok": headings == HEADINGS,
        "subheadings": subheadings,
        "required_subheadings_ok": subheadings == SUBHEADINGS,
        "report_structure_ok": (
            title_count == 1
            and headings == HEADINGS
            and subheadings == SUBHEADINGS
            and not unexpected_heading_levels
        ),
        "unexpected_heading_levels": unexpected_heading_levels,
        "fences_closed": closed,
        "code_blocks": len(blocks),
        "verbatim_material_found": preserved,
        "verbatim_material_not_found": missing,
        "attack_chain_request_nodes": chain_requests,
        "attack_chain_request_paths_match_evidence": (
            not missing_chain_requests if case["kind"] == "http" else None
        ),
        "attack_chain_request_paths_not_found": missing_chain_requests,
        "semantic_quality": "未自动判定；原文匹配和字数不能证明结论正确或文字易读",
    }


def review_run(folder):
    target = Path(folder)
    meta = read_json(target / "run.json")
    output = {
        "label": meta["label"],
        "model": meta["model"],
        "generation_settings": meta["generation_settings"],
        "policy_sha256": meta["policy_sha256"],
        "corpus_sha256": meta["corpus_sha256"],
        "cases": {},
    }
    for case in cases():
        cid = case["id"]
        current_digest = digest(json.dumps(model_input(case), ensure_ascii=False, sort_keys=True))
        if meta["corpus_sha256"].get(cid) != current_digest:
            raise ValueError(f"{cid} 的合成材料已变化；请用相同版本的材料重新准备评测")
        result = meta["results"].get(cid)
        if result is None:
            failure = meta.get("failures", {}).get(cid)
            output["cases"][cid] = {
                "status": "生成失败" if failure else "未收集模型输出",
                "error": failure,
            }
            continue
        # 只访问固定结果目录，run.json 不能指定仓库外文件。
        report = (target / "outputs" / f"{cid}.md").read_text(encoding="utf-8")
        if digest(report) != result["output_sha256"]:
            raise ValueError(f"{cid} 的报告已在收集后改变；另建评测目录再收集")
        if result.get("draft_file"):
            draft = (target / result["draft_file"]).read_text(encoding="utf-8")
            if digest(draft) != result.get("draft_sha256"):
                raise ValueError(f"{cid} 的模型正文已在收集后改变；另建评测目录再收集")
        review = read_json(target / "reviews" / f"{cid}.json")
        scores = review.get("scores", {})
        for dimension, score in scores.items():
            if dimension not in DIMENSIONS or (score is not None and (type(score) is not int or score not in (0, 1, 2))):
                raise ValueError(f"{cid} 的人工评分无效，必须是 0、1、2 或 null")
        reviewed = bool(review.get("reviewer", "").strip()) and all(scores.get(key) is not None for key in DIMENSIONS)
        output["cases"][cid] = {
            "status": "人工审阅完成" if reviewed else "人工审阅待完成",
            "source": result["source"],
            "metrics": metrics(case, report),
            "usage": {key: result.get(key) for key in ("input_tokens", "output_tokens", "cached_input_tokens", "duration_seconds")},
            "human_review": review,
        }
    return output


def compare(args):
    before, after = review_run(args.before), review_run(args.after)
    problems = []
    for key in ("model", "generation_settings", "corpus_sha256"):
        if before[key] != after[key]:
            problems.append(f"{key} 不一致，不能作为严格对照")
    for key, value in before["generation_settings"].items():
        if value is None or after["generation_settings"].get(key) is None:
            problems.append(f"生成参数 {key} 未完整记录，对照可重复性受限")
    for label, result in (("before", before), ("after", after)):
        for cid, case in result["cases"].items():
            if case.get("source") != "model":
                problems.append(f"{label}/{cid} 缺少模型产出，不能算真实模型评测")
            if case["status"] != "人工审阅完成":
                problems.append(f"{label}/{cid} 尚未完成人工语义审阅")
    write_json(
        args.output,
        {
            "comparison_complete": not problems,
            "limitations": problems,
            "before": before,
            "after": after,
            "interpretation": "逐例核对必须保留、不得主张和证据缺口；字数减少不能替代事实完整性及可复现性。未记录的 token 或耗时保持 null，不推算为零。",
        },
    )
    print(f"对照结果已保存：{args.output}；完整：{not problems}")


def nonnegative_int(value):
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("必须为非负整数")
    return parsed


def nonnegative_float(value):
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError("必须为非负有限数值")
    return parsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_cmd = commands.add_parser("prepare", help="准备不含参考答案的模型输入及人工评分表")
    policy = prepare_cmd.add_mutually_exclusive_group(required=True)
    policy.add_argument("--policy-file", help="明确指定纯文本写作规则文件，不读取运行配置")
    policy.add_argument("--policy-source", help="提取 Go 源码中的草稿规则（旧源码回退到 DeliveryReportWritingRules）")
    prepare_cmd.add_argument("--label", required=True)
    prepare_cmd.add_argument("--model", required=True)
    prepare_cmd.add_argument("--temperature", type=nonnegative_float)
    prepare_cmd.add_argument("--seed", type=nonnegative_int)
    prepare_cmd.add_argument("--max-output-tokens", type=nonnegative_int)
    prepare_cmd.add_argument("--output", required=True)
    prepare_cmd.set_defaults(action=prepare)
    live_cmd = commands.add_parser("run-live", help="登录本机 ARTEX，对固定合成样本运行无工具报告生成")
    live_cmd.add_argument("--base-url", default="http://127.0.0.1:8787")
    live_cmd.add_argument("--label", default="after")
    live_cmd.add_argument("--output", required=True)
    live_cmd.set_defaults(action=run_live)
    collect_cmd = commands.add_parser("collect", help="显式记录已取得的输出来源及实际消耗")
    collect_cmd.add_argument("--run", required=True)
    collect_cmd.add_argument("--case", required=True)
    collect_cmd.add_argument("--report", required=True)
    collect_cmd.add_argument("--model", required=True)
    collect_cmd.add_argument("--source", choices=("model", "manual"), required=True)
    collect_cmd.add_argument("--input-tokens", type=nonnegative_int)
    collect_cmd.add_argument("--output-tokens", type=nonnegative_int)
    collect_cmd.add_argument("--cached-input-tokens", type=nonnegative_int)
    collect_cmd.add_argument("--seconds", type=nonnegative_float)
    collect_cmd.set_defaults(action=collect)
    review_cmd = commands.add_parser("review", help="输出客观指标和人工评分，不自动判断语义")
    review_cmd.add_argument("--run", required=True)
    review_cmd.add_argument("--output", required=True)
    review_cmd.set_defaults(action=lambda args: write_json(args.output, review_run(args.run)))
    compare_cmd = commands.add_parser("compare", help="核对同模型同材料对照及人工审阅完成情况")
    compare_cmd.add_argument("--before", required=True)
    compare_cmd.add_argument("--after", required=True)
    compare_cmd.add_argument("--output", required=True)
    compare_cmd.set_defaults(action=compare)
    args = parser.parse_args()
    try:
        args.action(args)
    except (ValueError, OSError, KeyError, EOFError) as exc:
        parser.exit(2, f"评测材料处理失败：{exc}\n")


if __name__ == "__main__":
    main()
