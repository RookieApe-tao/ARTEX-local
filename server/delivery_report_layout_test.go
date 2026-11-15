package server

import (
	"strings"
	"testing"
)

func TestDeliveryReportReadableLayoutAndLegacyCompatibility(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
	report := "# 测试系统 查询接口越权\n\nCVSS 4.0：" + vector + " 评分 待计算（待计算）\n\n" +
		"## 描述\n\n已登录用户可读取其他测试账号的记录，敏感数据影响未验证。\n\n" +
		"### 定级依据\n\n当前材料只能支持已登录条件下的记录越权，数据敏感性待复核。\n\n" +
		"## 修复\n\n查询时按当前账号校验记录权限。未取得源码，修复后应拒绝访问其他账号记录。\n\n" +
		"## 测试过程\n\n### 发现过程与攻击思路\n\n以下为 Repeater 复现步骤，尚未在 Burp 中验证。取得两个测试账号会话，复制文末查询请求，修改对象编号后发送并检查返回记录。\n\n### 失败尝试与未验证项\n\n其他账号权限和数据敏感性未验证。\n\n" +
		"## 攻击链路\n\n~~~text\n已登录用户请求查询接口\n└─ GET /records/fixture\n   └─ 返回其他测试账号的记录\n~~~\n\n" +
		"## 证据说明\n\n合成样本，未取得原始请求与响应，不能据此宣称已完成复现。\n\n### Burp 复现\n\n没有真实请求包，当前无法在 Repeater 重放。\n\n### 复测标准\n\n授权账号查询本人记录应成功；查询其他账号记录应拒绝且不返回记录内容。"
	subsectionOutOfOrder := strings.Replace(report, "### 发现过程与攻击思路", "### 暂时标题", 1)
	subsectionOutOfOrder = strings.Replace(subsectionOutOfOrder, "### 失败尝试与未验证项", "### 发现过程与攻击思路", 1)
	subsectionOutOfOrder = strings.Replace(subsectionOutOfOrder, "### 暂时标题", "### 失败尝试与未验证项", 1)
	for _, tc := range []struct {
		name   string
		report string
		valid  bool
	}{
		{"fixed layout with required subheadings", report, true},
		{"legacy layout", deliveryReportFixture("真实业务影响未验证。", vector), true},
		{"mixed layout", strings.Replace(report, "## 修复", "## 修复建议", 1), false},
		{"renamed headings", strings.Replace(report, "## 描述", "## 漏洞描述", 1), false},
		{"subsection order", subsectionOutOfOrder, false},
		{"wrong order", strings.Replace(report, "## 测试过程", "## 修复建议", 1), false},
		{"missing evidence", strings.Split(report, "## 证据说明")[0], false},
		{"empty remediation", strings.Replace(report, "查询时按当前账号校验记录权限。未取得源码，修复后应拒绝访问其他账号记录。", "", 1), false},
		{"style does not block saving", strings.Replace(report, "已登录用户可读取其他测试账号的记录，敏感数据影响未验证。", "判决项的措辞需要审阅，格式检查不能证明内容质量。", 1), true},
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
