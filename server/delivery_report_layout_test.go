package server

import (
	"strings"
	"testing"
)

func TestDeliveryReportReadableLayoutAndLegacyCompatibility(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
	report := "# 测试系统 查询接口越权\n\nCVSS 4.0：" + vector + " 评分 待计算（待计算）\n\n" +
		"## 描述\n\n普通用户可读取其他测试账号的记录。当前材料支持越权读取，数据敏感性未验证。\n\n" +
		"## 修复建议\n\n服务端读取记录前校验当前账号与记录的授权关系。修复后其他账号的请求应被拒绝。\n\n" +
		"## 测试过程\n\n测试时间：未记录。\n执行工具：未记录。用两个授权测试账号复核同一记录。将文末请求放入 Burp Repeater，改为另一账号的记录编号并发送；本次 Repeater 复测未验证。记录返回状态和正文。失败尝试未取得记录；数据敏感性未验证。\n\n" +
		"## 攻击链路\n\n~~~text\n已登录用户请求查询接口\n└─ GET /records/fixture\n   └─ 返回其他测试账号的记录\n~~~\n\n" +
		"## 证据说明\n\n来源为合成样本；没有真实网络请求或响应。"
	for _, tc := range []struct {
		name   string
		report string
		valid  bool
	}{
		{"fixed concise layout", report, true},
		{"generated fixture", deliveryReportFixture("真实业务影响未验证。", vector), true},
		{"old section name", strings.Replace(report, "## 修复建议", "## 修复", 1), false},
		{"renamed headings", strings.Replace(report, "## 描述", "## 漏洞描述", 1), false},
		{"nested headings", strings.Replace(report, "## 测试过程", "### 发现过程与攻击思路\n\n## 测试过程", 1), false},
		{"missing test time", strings.Replace(report, "测试时间：未记录。", "", 1), false},
		{"wrong order", strings.Replace(report, "## 测试过程", "## 攻击链路", 1), false},
		{"missing evidence", strings.Split(report, "## 证据说明")[0], false},
		{"empty remediation", strings.Replace(report, "服务端读取记录前校验当前账号与记录的授权关系。修复后其他账号的请求应被拒绝。", " \t\n", 1), false},
		{"report wording is not a template rule", strings.Replace(report, "普通用户可读取其他测试账号的记录。当前材料支持越权读取，数据敏感性未验证。", "响应中的文件所有者与测试账号不一致，影响范围仍需复核。", 1), true},
		{"Burp mention without Repeater", strings.Replace(report, "Burp Repeater", "Burp", 1), false},
		{"missing repeater instruction", strings.ReplaceAll(report, "Repeater", "HTTP 工具"), false},
		{"missing execution tool", strings.Replace(report, "执行工具：未记录。", "", 1), false},
		{"internal jargon", strings.Replace(report, "数据敏感性未验证", "W07 数据敏感性未验证", 1), false},
		{"non-http burp note", strings.Replace(report, "用两个授权测试账号复核同一记录。将文末请求放入 Burp Repeater，改为另一账号的记录编号并发送；本次 Repeater 复测未验证。记录返回状态和正文。失败尝试未取得记录；数据敏感性未验证。", "本地用户读取受限文件；记录命令、输出和权限判据。Burp 不适用：本地命令验证。", 1), true},
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
