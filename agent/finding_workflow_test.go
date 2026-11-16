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
	if len(tools) != 1 || !strings.HasPrefix(tools[0].Description(), tool.Description()) || !strings.Contains(tools[0].Description(), DeliveryReportSectionOrder) {
		t.Fatal("report save contract was lost with custom descriptions or disabled binding")
	}
	if tool.Description() != "USER CUSTOM DESCRIPTION" {
		t.Fatal("runtime decoration modified the original tool")
	}
	if !strings.Contains(guidance, DeliveryReportRuntimeGuidance) || !strings.Contains(guidance, DeliveryReportStyleGuidance) {
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
				if !permitted {
					for _, tool := range tools {
						if tool.Name() == report.Name() {
							t.Fatal("runtime guidance restored a disabled report tool")
						}
					}
					continue
				}
				stock, _ := deferredSystem(ReporterDefaultPrompt, def)
				if strings.Count(stock[0], DeliveryReportRuntimeGuidance) != 1 || strings.Count(stock[0], DeliveryReportStyleGuidance) != 1 || !strings.Contains(stock[0], findingIDGuidance) {
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
		"原始请求/响应和命令输出优先于 worker 总结、漏洞摘要和旧报告",
		"来源冲突或缺项时写明未核实",
		"详细报告保留工具参数、准确时间、失败日志、哈希和证据索引",
		"交付报告只留理解、复现和修复所需内容",
		"时间使用北京时间",
		"HTTP 状态码或响应头不能证明正文已返回",
		"CVSS 向量不是影响证据",
		"评分前提需复核",
		"只有缺陷行为已由材料确认时，才给对应的代码或配置修复",
		"结果放在触发它的操作下面",
		"顺序操作逐级相连，并发操作才并列",
		"页面入口有记录才写页面",
		"失败尝试只写实际执行过的操作",
		"Repeater 串行重放不能证明并发",
		"HTTP 报告必须有 Burp Repeater 小节",
		"说明重放什么、观察什么，不重抄报文",
		"回读请求与并发组并列，放在所有并发请求之后",
		"没有找到恢复操作，不等于无法恢复",
		"交付正文以 500 字符为目标，最多 800 字符",
		"X-Eval-Actor 等合成标记不是认证字段",
		"禁用“判决项”“阴性结果”“如实交付”“零错配”",
		"平台附加的完整报文不重抄",
		"终端 id 命令只说明当前进程用户",
		"保存前由同一 Reporter 检查复现条件、观察结果、影响边界、修复依据和链路顺序",
	} {
		if !strings.Contains(DeliveryReportWritingRules, required) {
			t.Fatalf("delivery report guidance is missing %q", required)
		}
	}
	for _, forced := range []string{"测试过程必须各有一行“测试时间：”和“执行工具：”", "测试时间：未记录", "执行工具：未记录"} {
		if strings.Contains(DeliveryReportWritingRules, forced) {
			t.Fatalf("delivery report guidance still forces execution ledger fields: %q", forced)
		}
	}
	if strings.Contains(DeliveryReportWritingRules, "JSON 的 description 字段") || !strings.Contains(DeliveryReportDraftRules, "description 先写问题") ||
		!strings.Contains(DeliveryReportDraftRules, "cvss_vector 优先使用输入提供的有效向量") ||
		!strings.Contains(DeliveryReportDraftRules, "顺序操作逐级相连") {
		t.Fatal("JSON draft format rules must stay separate from the full Markdown Reporter rules")
	}
}
