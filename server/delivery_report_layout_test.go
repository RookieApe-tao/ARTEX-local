package server

import (
	"strings"
	"testing"
)

func TestDeliveryReportReadableLayoutAndLegacyCompatibility(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
	report := "# 测试系统 查询接口越权\n\nCVSS 4.0：" + vector + " 评分 待计算（待计算）\n\n" +
		"## 描述\n\n普通用户可读取其他测试账号的记录。数据敏感性未验证。\n\n### 定级依据\n当前证据仅支持已观察到的读取行为。\n\n" +
		"## 修复建议\n\n服务端读取记录前校验当前账号与记录的授权关系。修复后无权请求应被拒绝。\n\n" +
		"## 测试过程\n\n### 发现过程与攻击思路\n使用两个授权账号核对同一记录的请求和响应。\n### 失败尝试与未验证项\n数据敏感性未验证。\n### Burp 复现\nBurp Repeater 未实际使用；建议按授权账号捕获请求后复测。\n\n" +
		"## 攻击链路\n\n~~~text\n已登录用户请求查询接口\n└─ GET /records/fixture\n   └─ 返回其他测试账号的记录\n~~~\n\n" +
		"## 证据说明\n\n来源为合成样本；没有真实网络请求或响应。\n### 复测标准\n无权账号请求应被拒绝，且不得返回记录正文。"
	for _, tc := range []struct {
		name   string
		report string
		valid  bool
	}{
		{"fixed concise layout", report, true},
		{"generated fixture", deliveryReportFixture("真实业务影响未验证。", vector), true},
		{"old section name", strings.Replace(report, "## 修复建议", "## 修复", 1), false},
		{"renamed headings", strings.Replace(report, "## 描述", "## 漏洞描述", 1), false},
		{"unexpected nested heading", strings.Replace(report, "### 发现过程与攻击思路", "### 非预期栏目\n\n### 发现过程与攻击思路", 1), false},
		{"missing test time is allowed", report, true},
		{"wrong order", strings.Replace(report, "## 测试过程", "## 攻击链路", 1), false},
		{"missing evidence", strings.Split(report, "## 证据说明")[0], false},
		{"empty remediation", strings.Replace(report, "服务端读取记录前校验当前账号与记录的授权关系。修复后无权请求应被拒绝。", " \t\n", 1), false},
		{"report wording is not a template rule", strings.Replace(report, "普通用户可读取其他测试账号的记录。当前材料支持越权读取，数据敏感性未验证。", "响应中的文件所有者与测试账号不一致，影响范围仍需复核。", 1), true},
		{"Burp phrasing is reviewed as content", strings.Replace(report, "Burp Repeater", "HTTP 工具", 1), true},
		{"missing execution tool is allowed", report, true},
		{"internal jargon is reviewed as content", strings.Replace(report, "数据敏感性未验证", "W07 数据敏感性未验证", 1), true},
		{"non-http burp note", strings.Replace(report, "Burp Repeater 未实际使用；建议按授权账号捕获请求后复测。", "本地用户读取受限文件；记录命令、输出和权限判据。Burp 不适用：本地命令验证。", 1), true},
		{"hidden tree cannot satisfy format", strings.Replace(report, "~~~text\n已登录用户", "<!--\n~~~text\n已登录用户", 1) + "\n-->", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateDeliveryReportTemplate(tc.report, vector); (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}

func TestDeliveryAttackChainVisibleClosedTree(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"without final newline", "```text\n业务入口\n└─ 实际结果\n```", true},
		{"tree inside comment", "说明\n<!--\n```text\n业务入口\n└─ 实际结果\n```\n-->", false},
		{"comment then visible tree", "<!-- 内部记录 -->\n```text\n业务入口\n└─ 实际结果\n```", true},
		{"branch without root", "```text\n└─ 实际结果\n```", false},
		{"empty branch", "```text\n业务入口\n└─ \n```", false},
		{"unclosed tree", "```text\n业务入口\n└─ 实际结果", false},
		{"http packet is not a chain", "```http\n业务入口\n└─ 实际结果\n```", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := deliveryAttackChainHasTree("## 攻击链路\n" + tc.body); got != tc.want {
				t.Fatalf("got=%v want=%v", got, tc.want)
			}
		})
	}
}
