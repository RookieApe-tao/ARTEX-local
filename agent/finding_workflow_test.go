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
		"摘要和旧报告只用于找材料",
		"没有找到恢复操作，不等于无法恢复",
		"详细报告保留工具参数、准确时间、失败日志、哈希和证据索引",
		"交付报告只保留理解、复现和修复问题所需的信息",
		"时间使用北京时间",
		"失败尝试只写实际执行过的操作",
		"Repeater 串行重放不能验证并发",
		"不推荐或命名其他工具",
		"身份关系用“当前用户”“作业所有者”等称呼",
		"不得建议替换认证字段",
		"合成身份标记和占位 Cookie 不能证明真实登录",
		"正文不得抄这些占位值",
		"不写已读取数据",
		"不得另行给出冲突的危害等级",
		"SQL 注入的修复只写参数化查询",
		"未证明内容敏感时不写信息泄露",
		"读取到合成内容本身不能证明机密性影响",
		"重复写入只建议数据库唯一约束",
		"交付正文最多 800 字符",
		"平台附加的完整报文不重抄",
		"生成结构化草稿时，JSON 的 description 字段必须按",
		"test_process 字段必须依次包含",
		"discovery_path 字段必须包含",
		"攻击链字段只写简短的中文树形节点",
		"终端样本中，id 命令只能说明当前进程身份",
		"保存前由同一 Reporter 检查",
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
}
