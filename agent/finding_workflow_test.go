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

func TestDeliveryReportKeepsExecutionLedgerOutOfDeliveryBody(t *testing.T) {
	for _, required := range []string{
		"详细报告保留逐项工具参数、准确时间、失败记录、哈希和证据索引",
		"交付正文只保留复现必需的账号或会话、关键参数、操作顺序和判据",
		"工具版本、完整命令、逐次结果、精确时间等留在详细报告或原始材料中",
		"测试日期在测试过程中集中写一次，使用北京时间",
	} {
		if !strings.Contains(DeliveryReportWritingRules, required) {
			t.Fatalf("delivery report guidance is missing %q", required)
		}
	}
	if strings.Contains(DeliveryReportWritingRules, "实际测试的工具与参数、发送顺序、判据和结果") {
		t.Fatal("delivery report guidance still asks for a full execution ledger")
	}
}
