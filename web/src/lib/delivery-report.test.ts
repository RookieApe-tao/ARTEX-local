import { applyCVSSMetadata } from "./delivery-report";
import assert from "node:assert/strict";
import test from "node:test";

const vector = "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
const singleLine = `CVSS 4.0：${vector}  评分 7.3（高危）`;

test("new report headers use the calculated score without legacy duplicates", () => {
  const content = [
    "# 系统-模块 接口 缺陷：后果",
    "",
    "漏洞名称：系统-模块 接口 缺陷",
    "CVSS 4.0：model-vector  评分 1.0（低危）",
    "- **CVSS 4.0 Base 向量（CVSS-B）**：old-vector",
    "- **CVSS 4.0 评分**：1.0（CVSS-B）",
    "- **漏洞等级**：低危",
    "CVSS 4.0：duplicate",
    "",
    "## 描述",
    "记录说明。",
  ].join("\n");
  const result = applyCVSSMetadata(content, vector);
  assert.equal(result.split(singleLine).length - 1, 1);
  assert.doesNotMatch(result, /漏洞名称：|model-vector|old-vector|duplicate|CVSS-B|漏洞等级/);
  assert.equal(applyCVSSMetadata(result, vector), result);
});

test("legacy report headers collapse to one title and one calculated CVSS line", () => {
  const content = [
    "# 原报告",
    "",
    "漏洞名称：重复标题",
    "- **CVSS 4.0 Base 向量（CVSS-B）**：model-vector",
    "- **CVSS 4.0 评分**：1.0（CVSS-B）",
    "- **漏洞等级**：低危",
    "",
    "## 漏洞描述",
    "原有内容。",
  ].join("\n");
  const result = applyCVSSMetadata(content, vector);
  assert.equal(result.split(singleLine).length - 1, 1);
  assert.doesNotMatch(result, /漏洞名称：|CVSS-B|漏洞等级/);
  assert.ok(result.includes("## 漏洞描述"));
  assert.equal(applyCVSSMetadata(result, vector), result);
});

test("missing metadata is inserted in the header without changing HTTP evidence", () => {
  const evidence = [
    "## 证据说明",
    "```http",
    "HTTP/1.1 200 OK",
    "",
    "CVSS 4.0：captured-value",
    "- **CVSS 4.0 评分**：captured-value",
    "```",
  ].join("\n");
  const result = applyCVSSMetadata(`# 报告\n\n## 描述\n观察结果。\n\n${evidence}`, vector);
  assert.ok(result.includes(singleLine));
  assert.ok(result.endsWith(evidence));
});

test("metadata inside a fenced header is retained as evidence", () => {
  const code = "```text\nCVSS 4.0：captured-value\n```";
  const result = applyCVSSMetadata(`# 报告\n\n${code}\n\n## 描述\n结果。`, vector);
  assert.ok(result.includes(code));
  assert.ok(result.includes(singleLine));
});

test("Markdown headings with up to three leading spaces delimit the report header", () => {
  for (let indent = 0; indent <= 3; indent++) {
    const spaces = " ".repeat(indent);
    const title = `${spaces}# 报告`;
    const body = `${spaces}## 描述\nCVSS 4.0：captured-value\n- **漏洞等级**：captured-value`;
    const result = applyCVSSMetadata(`${title}\n\n${body}`, vector);
    assert.ok(result.startsWith(`${title}\n\n${singleLine}`));
    assert.ok(result.endsWith(body));
    assert.equal(applyCVSSMetadata(result, vector), result);
  }
});

test("an unclosed fence never receives metadata inside the captured content", () => {
  for (const fence of ["```", "~~~"]) {
    const evidence = `${fence}http\nHTTP/1.1 200 OK\n\n# captured-title\nCVSS 4.0：captured-value`;
    const result = applyCVSSMetadata(evidence, vector);
    assert.ok(result.startsWith(`${singleLine}\n`));
    assert.ok(result.endsWith(evidence));
    assert.equal(applyCVSSMetadata(result, vector), result);
  }
});

test("partial legacy metadata is replaced with a single CVSS line", () => {
  const result = applyCVSSMetadata("# 报告\n\n- **CVSS 4.0 评分**：1.0\n\n## 描述\n结果。", vector);
  assert.equal(result.split(singleLine).length - 1, 1);
  assert.doesNotMatch(result, /CVSS-B|漏洞等级/);
  assert.equal(applyCVSSMetadata(result, vector), result);
});

test("reports without an authoritative vector and empty reports stay unchanged", () => {
  assert.equal(applyCVSSMetadata("# 原报告", ""), "# 原报告");
  assert.equal(applyCVSSMetadata("", vector), "");
});

test("internal evidence marker is hidden from rendered and copied reports", () => {
  for (const marker of ["<!-- artex:bound-traffic-evidence -->", "\\<!-- artex:bound-traffic-evidence -->\\"]) {
    const content = `# 报告\n\n## 证据说明\n来源已记录。\n\n${marker}\n`;
    const result = applyCVSSMetadata(content, vector);
    assert.doesNotMatch(result, /artex:bound-traffic-evidence/);
    assert.equal(applyCVSSMetadata(content, ""), "# 报告\n\n## 证据说明\n来源已记录。\n\n");
  }
});

test("marker-like text inside captured HTTP packets remains untouched", () => {
  const packet = "```http\nGET / HTTP/1.1\n\n<!-- artex:bound-traffic-evidence -->\n```";
  const result = applyCVSSMetadata(`# 报告\n\n## 证据说明\n${packet}`, vector);
  assert.ok(result.includes(packet));
});
