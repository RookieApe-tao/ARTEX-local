package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestFindingWorkflowSharedAssemblyAndSwitch(t *testing.T) {
	oldPolicy, oldResolve, oldAugment := FindingTrafficBindingEnabled, ToolResolve, ToolAugment
	t.Cleanup(func() { FindingTrafficBindingEnabled, ToolResolve, ToolAugment = oldPolicy, oldResolve, oldAugment })
	ToolAugment = nil
	on := false
	FindingTrafficBindingEnabled = func() bool { return on }
	ts := NewToolSet(nil, "fixture")
	ToolResolve = func(_ context.Context, _ string, base []actool.CoreTool) []actool.CoreTool {
		out := make([]actool.CoreTool, len(base))
		for i, tool := range base {
			out[i] = DecorateTool(tool, "CUSTOM DESCRIPTION", tool.InputSchema())
		}
		return out
	}
	for _, role := range []string{"worker", "planner", "mainagent", "auto", "pentest", "custom-agent"} {
		for _, enabled := range []bool{false, true, false} {
			on = enabled
			out, def, cleanup := AugmentTools(t.Context(), role, []actool.CoreTool{ts.addFinding(), ts.addHint()})
			cleanup()
			system, _ := deferredSystem("USER CUSTOM PROMPT", def)
			if !strings.HasPrefix(system[0], "USER CUSTOM PROMPT") {
				t.Fatal("custom prompt replaced")
			}
			if strings.Contains(system[0], "traffic_refs") != on {
				t.Fatalf("%s: guidance ignored switch: %v", role, on)
			}
			if on && (!strings.Contains(system[0], "TCP") || !strings.Contains(system[0], "evidence_hint_id")) {
				t.Fatal("missing optional/handoff contract")
			}
			for _, tool := range out {
				if !strings.HasPrefix(tool.Description(), "CUSTOM DESCRIPTION") {
					t.Fatal("custom description replaced")
				}
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				json.Unmarshal(raw, &schema)
				props := schema["properties"].(map[string]any)
				if (props["traffic_refs"] != nil) != on {
					t.Fatalf("%s: binding schema ignored switch", role)
				}
				if tool.Name() == "add_hint" {
					nested := props["hints"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
					if (nested["traffic_refs"] != nil) != on {
						t.Fatal("nested hint schema ignored switch")
					}
				}
			}
		}
	}
	on = true
	ToolResolve = func(context.Context, string, []actool.CoreTool) []actool.CoreTool { return nil }
	out, def, cleanup := AugmentTools(t.Context(), "planner", []actool.CoreTool{ts.addFinding()})
	defer cleanup()
	if len(out) != 0 || def.FindingGuidance != "" {
		t.Fatal("reintroduced disabled tool or its guidance")
	}
}

func TestReportTemplateContractReachesCustomToolsWithBindingDisabled(t *testing.T) {
	old := FindingTrafficBindingEnabled
	FindingTrafficBindingEnabled = func() bool { return false }
	t.Cleanup(func() { FindingTrafficBindingEnabled = old })
	tool := actool.Build(actool.Spec{Name: "update_finding_report", Description: "USER CUSTOM DESCRIPTION", Schema: map[string]any{"type": "object"}})
	tools, guidance := findingWorkflowTools("custom-agent", []actool.CoreTool{tool})
	if len(tools) != 1 || !strings.HasPrefix(tools[0].Description(), tool.Description()) || !strings.Contains(tools[0].Description(), DeliveryReportSectionOrder) || !strings.Contains(tools[0].Description(), DeliveryReportEvidenceGuidance) {
		t.Fatal("report save contract was lost with custom descriptions or disabled binding")
	}
	if tool.Description() != "USER CUSTOM DESCRIPTION" {
		t.Fatal("runtime decoration modified the original tool")
	}
	if !strings.Contains(guidance, DeliveryReportRuntimeGuidance) || !strings.Contains(guidance, DeliveryReportChainGuidance) || !strings.Contains(guidance, DeliveryReportEvidenceGuidance) || !strings.Contains(guidance, DeliveryReportStyleGuidance) {
		t.Fatal("custom reporter lost the writing rules while traffic binding was disabled")
	}
}

func TestReportRuntimeGuidanceFollowsFinalPermissions(t *testing.T) {
	oldPolicy, oldResolve, oldAugment := FindingTrafficBindingEnabled, ToolResolve, ToolAugment
	t.Cleanup(func() { FindingTrafficBindingEnabled, ToolResolve, ToolAugment = oldPolicy, oldResolve, oldAugment })
	ToolAugment = nil
	report := actool.Build(actool.Spec{Name: "update_finding_report", Description: "CUSTOM REPORT TOOL", Schema: map[string]any{"type": "object"}})
	read := actool.Build(actool.Spec{Name: "get_finding_traffic", Description: "READ ONLY", Schema: map[string]any{"type": "object"}})
	for _, role := range []string{"reporter", "planner", "mainagent", "custom-agent"} {
		for _, binding := range []bool{false, true} {
			FindingTrafficBindingEnabled = func() bool { return binding }
			for _, permitted := range []bool{false, true} {
				ToolResolve = func(_ context.Context, _ string, tools []actool.CoreTool) []actool.CoreTool {
					if !permitted {
						return []actool.CoreTool{read}
					}
					return tools
				}
				tools, def, cleanup := AugmentTools(t.Context(), role, []actool.CoreTool{report, read})
				cleanup()
				system, _ := deferredSystem("USER CUSTOM PROMPT", def)
				if !strings.HasPrefix(system[0], "USER CUSTOM PROMPT") {
					t.Fatal("runtime guidance replaced user content")
				}
				if strings.Contains(system[0], DeliveryReportRuntimeGuidance) != permitted {
					t.Fatalf("role=%s binding=%v permitted=%v: writing guidance ignored final permissions", role, binding, permitted)
				}
				if strings.Contains(system[0], DeliveryReportStyleGuidance) != permitted {
					t.Fatalf("role=%s binding=%v permitted=%v: style guidance ignored final permissions", role, binding, permitted)
				}
				if strings.Contains(system[0], DeliveryReportChainGuidance) != permitted {
					t.Fatalf("role=%s binding=%v permitted=%v: chain guidance ignored final permissions", role, binding, permitted)
				}
				if strings.Contains(system[0], DeliveryReportEvidenceGuidance) != permitted {
					t.Fatalf("role=%s binding=%v permitted=%v: evidence guidance ignored final permissions", role, binding, permitted)
				}
				if !permitted {
					for _, tool := range tools {
						if tool.Name() == report.Name() {
							t.Fatal("runtime guidance restored a disabled report tool")
						}
					}
					continue
				}
				stock, _ := deferredSystem(ReporterDefaultPrompt, def)
				if strings.Count(stock[0], DeliveryReportRuntimeGuidance) != 1 || strings.Count(stock[0], DeliveryReportChainGuidance) != 1 || strings.Count(stock[0], DeliveryReportEvidenceGuidance) != 1 || strings.Count(stock[0], DeliveryReportStyleGuidance) != 1 || !strings.Contains(stock[0], findingIDGuidance) {
					t.Fatal("stock prompt duplicated the writing rules or lost the ID contract")
				}
			}
		}
	}
}

func TestReporterDefaultPromptUsesMarkdownRulesWithoutJSONContract(t *testing.T) {
	if strings.Count(ReporterDefaultPrompt, DeliveryReportWritingRules) != 1 {
		t.Fatal("Reporter default must include the Markdown writing rules exactly once")
	}
	if strings.Contains(ReporterDefaultPrompt, `"cvss_vector":""`) || strings.Contains(ReporterDefaultPrompt, "description 先写问题") {
		t.Fatal("Reporter default must not include the compatibility endpoint's JSON draft contract")
	}
}

func TestDeliveryReportKeepsExecutionLedgerOutOfDeliveryBody(t *testing.T) {
	for _, required := range []string{
		"仅适用于交付报告字段",
		"不改变详细报告的章节和台账",
		"动笔前先从原始请求/响应、命令输出和执行记录整理事实，不输出清单",
		"根因（只有源码、配置或日志能证明时才填写，否则记为未知）",
		"正文每项陈述都须能对应到这些事实",
		"状态码或响应头不能证明响应正文已返回",
		"合成、演示或占位",
		"跨账号访问成功、文件正文已返回或真实数据已泄露",
		"不得称为真实用户资料、敏感数据或实际泄露",
		"身份/权限证明",
		"只建议一项针对已确认行为的可观察修复结果",
		"不得建议把样本 Host、身份、认证头、Cookie 或 Token 替换成真实值",
		"首条证据请求采集时间",
		"没有可靠记录时写“测试时间：未记录”",
		"修复建议只写一项与已确认行为相符的主要措施",
		"失败尝试只写实际做过且失败的操作",
		"Repeater 串行重放不能证明并发",
		"攻击链只画一棵树。根节点写材料中实际的页面或功能入口",
		"HTTP 请求的 METHOD/path 必须逐字复制 request_line_index",
		"真假条件、有效与无效凭证等对照请求并列，不画成互相依赖",
		"回读查询放在并发组之后",
		"多条请求不等于并发",
		"正文尽量控制在 800 字以内，不硬截断",
		"发现过程写测试时间和最多四步",
		"失败与未验证项最多两句",
		"每项事实只放一个位置",
		"正文写给开发看",
		"不要把交付报告的精简要求套到详细报告",
		"保存前在本次输出中核对结论、限制、修复和链路",
	} {
		if !strings.Contains(DeliveryReportWritingRules, required) {
			t.Fatalf("delivery report guidance is missing %q", required)
		}
	}
	for _, absent := range []string{"正文以 500 字符为目标、最多 800 字符", "禁用“判决项”", "执行工具：未记录"} {
		if strings.Contains(DeliveryReportWritingRules, absent) {
			t.Fatalf("delivery report guidance retains a style blacklist or hard limit: %q", absent)
		}
	}
	if strings.Contains(DeliveryReportWritingRules, "JSON 的 description 字段") || !strings.Contains(DeliveryReportDraftRules, "description 先用两三句写问题") ||
		!strings.Contains(DeliveryReportDraftRules, "cvss_vector 优先使用输入提供的有效向量") ||
		!strings.Contains(DeliveryReportDraftRules, "attack_chain 只写一棵短树。根节点使用实际页面或功能入口") {
		t.Fatal("JSON draft format rules must stay separate from the full Markdown Reporter rules")
	}
}
