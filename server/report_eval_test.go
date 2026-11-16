package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/wpsec/ARTEX-local/agent"
	"github.com/wpsec/ARTEX-local/db"
	"github.com/wpsec/ARTEX-local/tools/report-eval"
)

func TestDeliveryReportTimeHintsUseBeijingAndKeepMissingExplicit(t *testing.T) {
	if got, want := reportEvalTestTimeHint("2026-11-01T02:00:00Z"), "2026-11-01 10:00:00（北京时间）"; got != want {
		t.Fatalf("UTC evaluation time hint=%q, want %q", got, want)
	}
	if got := reportEvalTestTimeHint("not-a-time"); got != "测试时间未记录" {
		t.Fatalf("invalid evaluation time hint=%q, want missing marker", got)
	}

	bindings := []db.FindingTrafficBinding{{
		ID:   7,
		Role: "proof",
		Note: "关键请求",
		Snapshot: db.TrafficEvidenceSnapshot{
			CapturedAt: time.Date(2026, time.November, 1, 2, 0, 0, 0, time.UTC).Unix(),
		},
	}}
	index := deliveryEvidenceTimeIndex(bindings)
	if !strings.Contains(index, "2026-11-01 10:00:00（北京时间）") || !strings.Contains(index, "关键请求") {
		t.Fatalf("evidence time index omitted timestamp or purpose: %q", index)
	}
	if got, want := deliveryEvidenceTestTimeHint(bindings), "2026-11-01 10:00:00（北京时间，首条证据请求采集时间）"; got != want {
		t.Fatalf("evidence test time hint=%q, want %q", got, want)
	}
	if got := deliveryEvidenceTimeIndex(nil); !strings.Contains(got, "没有绑定流量采集时间") {
		t.Fatalf("empty evidence time index=%q, want explicit missing-time guidance", got)
	}
	if got := deliveryEvidenceTestTimeHint(nil); got != "测试时间未记录" {
		t.Fatalf("empty evidence test time hint=%q, want missing marker", got)
	}
}

type reportEvalProvider struct {
	request llm.CompletionRequest
	calls   int
	result  string
	err     error
}

func (p *reportEvalProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) {}
}

func (p *reportEvalProvider) Complete(_ context.Context, request llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.request = request
	p.calls++
	if p.err != nil {
		return llm.Message{}, "", llm.Usage{}, p.err
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(p.result)}}, "end_turn", llm.Usage{InputTokens: 17, OutputTokens: 23}, nil
}

func TestReportEvalRouteIsAuthenticatedOptInAndFixedInputOnly(t *testing.T) {
	t.Setenv("ARTEX_REPORT_EVAL_ENABLED", "false")
	modelResponseJSON := `{"cvss_vector":"CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N","description":"普通用户可修改他人作业，状态随之改变。","remediation":"服务端校验当前账号是否有权修改该作业。","test_process":"使用样本中的普通用户请求修改作业，再以所有者账号读取并检查状态。Burp Repeater 复测未验证；授权测试时可重放附加请求。","attack_chain":"FENCEtext\n普通用户\n└─ 修改接口\n   └─ 作业状态发生变化\nFENCE","discovery_path":"来源为离线合成请求与响应，未对真实目标测试。"}`
	provider := &reportEvalProvider{result: strings.ReplaceAll(modelResponseJSON, "FENCE", "```")}
	s := &Server{llmProv: provider, llmOn: true, llmCfg: agent.Config{
		Format: llm.FormatOpenAI, Model: "fixed-test-model", APIKey: "must-not-be-exposed",
		ThinkingType: "enabled", ReasoningEffort: "high",
	}, jwtKey: []byte("report-eval-test-signing-key")}
	handler := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if response := request(http.MethodPost, "/api/report-eval/idor", "", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request status=%d, want 401", response.Code)
	}
	if response := request(http.MethodPost, "/api/report-eval/idor", "", token); response.Code != http.StatusNotFound {
		t.Fatalf("disabled route status=%d, want 404", response.Code)
	}
	t.Setenv("ARTEX_REPORT_EVAL_ENABLED", "true")
	if response := request(http.MethodPost, "/api/report-eval/unknown", "", token); response.Code != http.StatusNotFound {
		t.Fatalf("unknown case status=%d, want 404", response.Code)
	}
	if response := request(http.MethodPost, "/api/report-eval/idor", `{"prompt":"custom"}`, token); response.Code != http.StatusBadRequest {
		t.Fatalf("custom input status=%d, want 400", response.Code)
	}
	if provider.calls != 0 {
		t.Fatalf("rejected requests called the model %d times", provider.calls)
	}
	info := request(http.MethodGet, "/api/report-eval", "", token)
	if info.Code != http.StatusOK || !strings.Contains(info.Body.String(), "fixed-test-model") ||
		!strings.Contains(info.Body.String(), `"thinking_type":"enabled"`) ||
		!strings.Contains(info.Body.String(), `"reasoning_effort":"high"`) ||
		!strings.Contains(info.Body.String(), `"completion_passes":1`) ||
		strings.Contains(info.Body.String(), `"review_system_sha256"`) ||
		strings.Contains(info.Body.String(), "must-not-be-exposed") {
		t.Fatalf("metadata response status=%d body=%s", info.Code, info.Body.String())
	}
	response := request(http.MethodPost, "/api/report-eval/idor", "", token)
	if response.Code != http.StatusOK {
		t.Fatalf("sample request status=%d body=%s", response.Code, response.Body.String())
	}
	if provider.calls != 1 {
		t.Fatalf("model call count=%d, want one report generation call", provider.calls)
	}
	if len(provider.request.Tools) != 0 {
		t.Fatalf("evaluation request exposed %d tools", len(provider.request.Tools))
	}
	if provider.request.Thinking != "disabled" {
		t.Fatalf("evaluation request thinking=%q, want disabled for strict JSON output", provider.request.Thinking)
	}
	if provider.request.MaxTokens != deliveryReportMaxTokens {
		t.Fatalf("evaluation max tokens=%d, want %d", provider.request.MaxTokens, deliveryReportMaxTokens)
	}
	if len(provider.request.System) != 1 || !strings.Contains(provider.request.System[0], "保存前在本次输出中核对结论、限制、修复和链路") {
		t.Fatal("report generation call did not receive the same-Reporter self-check instructions")
	}
	if strings.Count(provider.request.System[0], agent.DeliveryReportDraftRules) != 1 {
		t.Fatal("compatibility draft generation must use the dedicated JSON draft rules once")
	}
	if strings.Contains(provider.request.System[0], "# 系统或模块 功能或接口 缺陷：实际后果") {
		t.Fatal("JSON draft instructions must not also require a full Markdown report")
	}
	for _, staleRule := range []string{"并发漏洞须使用并发工具或脚本验证", "把过滤或拒绝特殊字符列为修复", "文件名、所有者名称和权限位不能单独证明文件内容敏感"} {
		if strings.Contains(provider.request.System[0], staleRule) {
			t.Fatalf("compatibility draft generation retained superseded guidance %q", staleRule)
		}
	}
	for _, rule := range []string{"不要把占位主机、身份、Cookie 或 Token 改成真实测试条件", "每个请求或命令的结果缩进在该节点下", "响应差异只证明差异", "缺项写“未验证”", "漏洞名称和 CVSS 向量也不能代替影响证据"} {
		if !strings.Contains(provider.request.System[0], rule) {
			t.Fatalf("report generation instructions omitted rule %q", rule)
		}
	}
	prompt := provider.request.Messages[0].Text()
	for _, forbidden := range []string{"reference_report", "must_preserve", "must_not_claim", `"id":"E`} {
		if strings.Contains(prompt, forbidden) {
			t.Fatalf("model input exposed internal review material %q", forbidden)
		}
	}
	if !strings.Contains(prompt, "GET /api/jobs/job-a HTTP/1.1") || !strings.Contains(prompt, "user-b") ||
		!strings.Contains(prompt, `"request_line_index":"1. GET /api/jobs/job-a`) ||
		!strings.Contains(prompt, "2. POST /api/jobs/job-a/types") {
		t.Fatal("model input omitted the fixed sample evidence")
	}
	for _, required := range []string{`"synthetic":"true"`, "离线合成报文与记录", "攻击者已登录，知道 job-a 编号", "不带身份提交修改：HTTP 401", "没有取得正式文件正文"} {
		if !strings.Contains(prompt, required) {
			t.Fatalf("model input omitted authoritative sample context %q", required)
		}
	}
	if !strings.Contains(prompt, "不对应真实系统") || !strings.Contains(prompt, "不访问网络") {
		t.Fatal("model input must mark the cases as synthetic and prohibit network activity")
	}
	var result struct {
		Model string              `json:"model"`
		Usage llm.Usage           `json:"usage"`
		Draft deliveryReportDraft `json:"draft"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Model != "fixed-test-model" || result.Usage.InputTokens != 17 || result.Usage.OutputTokens != 23 || result.Draft.RequestPacket == "" {
		t.Fatalf("incomplete evaluation response: %+v", result)
	}
}

func TestReportEvalPromptInputLabelsSyntheticMaterials(t *testing.T) {
	sample, material, err := reporteval.Load("incomplete")
	if err != nil {
		t.Fatal(err)
	}
	input, err := reportEvalPromptInput(sample, material)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(input["task_description"], "不对应真实系统") || !strings.Contains(input["task_goal"], "不访问网络") {
		t.Fatalf("synthetic boundary missing from task context: description=%q goal=%q", input["task_description"], input["task_goal"])
	}
	if input["request_packet"] == "" || input["response_packet"] == "" {
		t.Fatal("incomplete HTTP evidence must preserve both the request and the partial response")
	}
	if input["evidence_transport"] != "http" {
		t.Fatalf("evidence transport=%q, want http", input["evidence_transport"])
	}
	if strings.Contains(input["evidence"], "/api/files/file-a/download") || strings.Contains(input["evidence"], "HTTP/1.1 200 OK") {
		t.Fatal("evidence inventory must not duplicate packets already passed in dedicated fields")
	}
	if !strings.Contains(input["request_packet"], "/api/files/file-a/download") {
		t.Fatal("dedicated request packet omitted the original request")
	}
	if !strings.Contains(input["request_line_index"], "1. GET /api/files/file-a/download") {
		t.Fatalf("request line index omitted the exact path: %q", input["request_line_index"])
	}
	if input["cvss_vector_hint"] != sample.Facts.CVSSVector {
		t.Fatalf("CVSS hint=%q, want %q", input["cvss_vector_hint"], sample.Facts.CVSSVector)
	}
	if want := "2026-11-01 10:00:00（北京时间）"; input["test_time_hint"] != want {
		t.Fatalf("test time hint=%q, want %q", input["test_time_hint"], want)
	}
	concurrency, concurrencyMaterial, err := reporteval.Load("concurrency")
	if err != nil {
		t.Fatal(err)
	}
	concurrencyInput, err := reportEvalPromptInput(concurrency, concurrencyMaterial)
	if err != nil {
		t.Fatal(err)
	}
	if concurrencyInput["test_tool_hint"] != concurrency.Facts.TestTool {
		t.Fatalf("test tool hint=%q, want %q", concurrencyInput["test_tool_hint"], concurrency.Facts.TestTool)
	}
	if strings.Count(concurrencyInput["request_line_index"], "POST /api/registrations") != 4 {
		t.Fatalf("request line index omitted repeated request count: %q", concurrencyInput["request_line_index"])
	}
	nonHTTP, nonHTTPMaterial, err := reporteval.Load("non-http")
	if err != nil {
		t.Fatal(err)
	}
	nonHTTPInput, err := reportEvalPromptInput(nonHTTP, nonHTTPMaterial)
	if err != nil {
		t.Fatal(err)
	}
	if nonHTTPInput["evidence_transport"] != "non_http" {
		t.Fatalf("non-HTTP evidence transport=%q", nonHTTPInput["evidence_transport"])
	}
}

func TestReportEvalReturnsSafeCompletionFailureCategory(t *testing.T) {
	t.Setenv("ARTEX_REPORT_EVAL_ENABLED", "true")
	tests := []struct {
		name        string
		result      string
		providerErr error
		wantMessage string
		wantRaw     string
		mustHide    string
	}{
		{name: "provider error", providerErr: errors.New("upstream token=secret-value"), wantMessage: "报告模型调用失败", mustHide: "secret-value"},
		{name: "invalid JSON", result: "not JSON", wantMessage: "模型未返回可解析的报告字段", wantRaw: "not JSON"},
		{name: "missing fields", result: `{}`, wantMessage: "模型报告字段不完整", wantRaw: `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &reportEvalProvider{result: tt.result, err: tt.providerErr}
			s := &Server{llmProv: provider, llmOn: true, llmCfg: agent.Config{Model: "fixed-test-model"}, jwtKey: []byte("report-eval-test-signing-key")}
			token, err := signJWT(s.jwtKey)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/report-eval/idor", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			s.Handler().ServeHTTP(response, req)
			if response.Code != http.StatusBadGateway {
				t.Fatalf("status=%d body=%s, want 502", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), tt.wantMessage) {
				t.Fatalf("body=%s, want safe category %q", response.Body.String(), tt.wantMessage)
			}
			if tt.wantRaw != "" && !strings.Contains(response.Body.String(), tt.wantRaw) {
				t.Fatalf("body=%s, want fixed-sample model output %q", response.Body.String(), tt.wantRaw)
			}
			if tt.name == "invalid JSON" {
				for _, want := range []string{`"stop_reason":"end_turn"`, `"content_block_types":["text"]`, `"output_tokens":23`} {
					if !strings.Contains(response.Body.String(), want) {
						t.Fatalf("body=%s, missing safe model diagnostic %q", response.Body.String(), want)
					}
				}
			}
			if tt.mustHide != "" && strings.Contains(response.Body.String(), tt.mustHide) {
				t.Fatalf("response leaked provider error detail: %s", response.Body.String())
			}
		})
	}
}

func TestDeliveryReportCompletionSystemIncludesEvidenceGuardrails(t *testing.T) {
	prompt := deliveryReportCompletionSystem()
	for _, required := range []string{
		"本次只生成交付报告草稿，不调用工具",
		"平台生成标题、CVSS 行、五节标题和原始报文附件",
		"只返回这个 JSON 对象",
		"description 先用两三句写问题、成立条件和观察结果，再依次包含“### 定级依据”和一两句评分依据",
		"test_process 依次包含“### 发现过程与攻击思路”“### 失败尝试与未验证项”“### Burp 复现”",
		"discovery_path 包含“### 复测标准”和一句可判定的复测条件",
		"attack_chain 只写一棵短树。根节点使用实际页面或功能入口",
		"HTTP 节点原样复制 METHOD/path",
		"平台会添加 text 代码围栏",
		"首条证据请求采集时间",
		"不改变详细报告的章节和台账",
		"修复建议只写一项与已确认行为相符的主要措施",
		"不得让人替换 Host、认证头或样本占位值",
		"正文以 800 字以内为目标，不硬截断",
		"前后查询按时间顺序展示",
		"### 定级依据",
		"### 发现过程与攻击思路",
		"### 失败尝试与未验证项",
		"### Burp 复现",
		"### 复测标准",
	} {
		if !strings.Contains(prompt, required) {
			t.Fatalf("report completion prompt is missing %q", required)
		}
	}
	if strings.Count(prompt, agent.DeliveryReportDraftRules) != 1 || strings.Contains(prompt, agent.DeliveryReportWritingRules) {
		t.Fatal("compatibility draft generation must use only its dedicated draft rules")
	}
}

func TestDeliveryReportMarkdownFallbackParsesFullModelReport(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"
	markdown := `# 测试系统 越权修改：普通用户可修改他人配置
CVSS 4.0：` + vector + ` 评分 6.1（中）

## 描述
普通用户可修改其他用户的配置。
### 定级依据
已观察到完整性影响。

## 修复建议
服务端校验作业归属后再更新配置。

## 测试过程
### 发现过程与攻击思路
普通用户重放更新请求并回读配置。
### 失败尝试与未验证项
未测试其他作业状态。
### Burp 复现
本次未使用 Burp Repeater；复测未验证。

## 攻击链路
普通用户
└─ POST /api/jobs/job-a/types
   └─ 配置发生变化

## 证据说明
材料来自固定合成样本。
### 复测标准
非所有者请求被拒绝且配置不变。`
	input := map[string]string{"cvss_vector_hint": vector}
	draft, usage, err := completeDeliveryReportWith(context.Background(), input, 4, func(_ context.Context, request llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		if len(request.Tools) != 0 {
			t.Fatalf("fallback request exposed %d tools", len(request.Tools))
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(markdown)}}, "end_turn", llm.Usage{OutputTokens: 80}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if usage.OutputTokens != 80 || draft.CVSSVector != vector || draft.EvidenceVersion != 4 {
		t.Fatalf("metadata lost during Markdown fallback: usage=%+v draft=%+v", usage, draft)
	}
	for _, value := range []string{draft.Description, draft.Remediation, draft.TestProcess, draft.DiscoveryPath} {
		if strings.TrimSpace(value) == "" {
			t.Fatal("Markdown fallback returned an empty report field")
		}
	}
	if !strings.HasPrefix(draft.AttackChain, "```text\n") || !strings.Contains(draft.AttackChain, "POST /api/jobs/job-a/types") {
		t.Fatalf("Markdown fallback did not preserve and fence the attack chain: %s", draft.AttackChain)
	}
}

func TestDeliveryReportDraftMovesRequiredSubheadingsToOwnLines(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"
	raw, err := json.Marshal(deliveryReportDraft{
		CVSSVector:    vector,
		Description:   "普通用户可修改作业。定级依据：现有材料显示配置已变化。",
		Remediation:   "服务端校验作业归属。",
		TestProcess:   "步骤。### 发现过程与攻击思路：重放修改请求。### 失败尝试与未验证项：没有记录失败尝试。### Burp 复现：Burp 复测未验证。",
		AttackChain:   "普通用户\n└─ POST /api/jobs/job-a/types\n   └─ 配置改变",
		DiscoveryPath: "证据来自固定样本。### 复测标准：非所有者请求被拒绝，作业配置保持不变。",
	})
	if err != nil {
		t.Fatal(err)
	}
	draft, err := parseDeliveryReportDraft(llm.Message{Content: []llm.ContentBlock{llm.TextBlock(string(raw))}}, "end_turn", llm.Usage{}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{draft.Description, draft.TestProcess, draft.DiscoveryPath} {
		if strings.Contains(value, "。### ") {
			t.Fatalf("subheading remained attached to prose: %q", value)
		}
	}
	if !strings.Contains(draft.Description, "\n### 定级依据\n") {
		t.Fatalf("plain rating label was not normalized to a required subheading: %q", draft.Description)
	}
	joinedHeading := normalizeDeliveryDraftSubheadings("结果。### 定级依据影响已观察。", "定级依据")
	if !strings.Contains(joinedHeading, "\n### 定级依据\n影响已观察。") {
		t.Fatalf("heading joined directly to prose was not normalized: %q", joinedHeading)
	}
	report := strings.Join([]string{
		"# 测试系统 作业越权",
		"CVSS 4.0：" + vector + " 评分 待复核（待复核）",
		"## 描述\n\n" + draft.Description,
		"## 修复建议\n\n" + draft.Remediation,
		"## 测试过程\n\n" + draft.TestProcess,
		"## 攻击链路\n\n" + draft.AttackChain,
		"## 证据说明\n\n" + draft.DiscoveryPath,
	}, "\n\n")
	if err := validateDeliveryReportTemplate(report, vector); err != nil {
		t.Fatalf("normalized draft does not meet the report template: %v", err)
	}
}

func TestDeliveryReportCompletionUsesProvidedCVSSVectorHint(t *testing.T) {
	sample, material, err := reporteval.Load("incomplete")
	if err != nil {
		t.Fatal(err)
	}
	input, err := reportEvalPromptInput(sample, material)
	if err != nil {
		t.Fatal(err)
	}
	modelDraft := `{"cvss_vector":"not-a-cvss-vector","description":"线索待核实。\n### 定级依据\n当前证据不足。","remediation":"先补齐响应正文。","test_process":"### 发现过程与攻击思路\n复核现有请求。\n### 失败尝试与未验证项\n文件内容未取得。\n### Burp 复现\nBurp 复测未验证。","attack_chain":"用户 B 请求文件\n└─ 仅留存 HTTP 200 响应头","discovery_path":"来源为合成材料。\n### 复测标准\n取得完整响应并比对文件。"}`
	draft, _, err := completeDeliveryReportWith(context.Background(), input, 0, func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(modelDraft)}}, "end_turn", llm.Usage{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if draft.CVSSVector != sample.Facts.CVSSVector {
		t.Fatalf("CVSS vector=%q, want trusted hint %q", draft.CVSSVector, sample.Facts.CVSSVector)
	}
}

func TestStripDeliveryDraftSectionHeading(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		section string
		want    string
	}{
		{"leading duplicate", "## 描述\n\n正文。", "描述", "正文。"},
		{"remediation section heading", "## 修复建议\n\n服务端校验归属。", "修复建议", "服务端校验归属。"},
		{"repeated leading duplicate", "## 描述\n## 描述\n正文。", "描述", "正文。"},
		{"preserve different heading", "### 定级依据\n正文。", "描述", "### 定级依据\n正文。"},
		{"preserve inline occurrence", "正文中引用 ## 描述。", "描述", "正文中引用 ## 描述。"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripDeliveryDraftSectionHeading(tc.content, tc.section); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestEnsureDeliveryAttackChainTextFence(t *testing.T) {
	plain := "普通用户登录\n└─ GET /api/me\n   └─ 返回用户信息"
	if got, want := ensureDeliveryAttackChainTextFence(plain), "```text\n"+plain+"\n```"; got != want {
		t.Fatalf("plain chain=%q, want %q", got, want)
	}
	if got, want := ensureDeliveryAttackChainTextFence("text\n"+plain), "```text\n"+plain+"\n```"; got != want {
		t.Fatalf("chain with duplicated language label=%q, want %q", got, want)
	}
	arrowChain := "入口：普通用户登录 -> POST /api/jobs/job-a/types -> 作业状态发生变化"
	if got, want := ensureDeliveryAttackChainTextFence(arrowChain), "```text\n普通用户登录\n   └─ POST /api/jobs/job-a/types\n      └─ 作业状态发生变化\n```"; got != want {
		t.Fatalf("arrow chain=%q, want %q", got, want)
	}
	if got, want := ensureDeliveryAttackChainTextFence("用户持有会话\n    └─ ↓\n    └─ > GET /api/me"), "```text\n用户持有会话\n   └─ GET /api/me\n```"; got != want {
		t.Fatalf("decorated tree=%q, want %q", got, want)
	}
	arrowInText := "用户提交参数含 ↓ 字符\n   ├─ 请求 A 返回 200\n   └─ 请求 B 返回 403"
	if got := ensureDeliveryAttackChainTextFence(arrowInText); got != "```text\n"+arrowInText+"\n```" {
		t.Fatalf("down arrow in prose changed the tree: %q", got)
	}
	misaligned := "登记请求\n└─ 并发提交相同编号\n   ├─ 请求 A 返回 201\n│  └─ 回读查询得到三条记录"
	if got, want := ensureDeliveryAttackChainTextFence(misaligned), "```text\n登记请求\n└─ 并发提交相同编号\n   ├─ 请求 A 返回 201\n   └─ 回读查询得到三条记录\n```"; got != want {
		t.Fatalf("misaligned tree=%q, want %q", got, want)
	}
	decorated := "```text\n用户已登录且知晓目标作业编号\n   └─ ↓\n   └─ POST /api/jobs/job-a/types\n   └─ ↓\n   └─ 服务端未校验所有权，直接接受修改\n```"
	want := "```text\n用户已登录且知晓目标作业编号\n   └─ POST /api/jobs/job-a/types\n      └─ 服务端未校验所有权，直接接受修改\n```"
	if got := ensureDeliveryAttackChainTextFence(decorated); got != want {
		t.Fatalf("decorated model tree=%q, want %q", got, want)
	}
	flatConcurrent := "GET /api/items?key=x\n   ├─ HTTP 200 total=0\n   ├─ 并发提交 POST /api/items\n   ├─ POST /api/items\n   ├─ HTTP 201 id=1\n   ├─ POST /api/items\n   ├─ HTTP 201 id=2\n   ├─ GET /api/items?key=x\n   └─ HTTP 200 total=2"
	concurrentRequests := "POST /api/items HTTP/1.1\nContent-Length: 0\n\nPOST /api/items HTTP/1.1\nContent-Length: 0\n\n"
	concurrentWant := "```text\nGET /api/items?key=x\n   └─ HTTP 200 total=0\n      ├─ 并发提交 2 次相同请求\n      │  ├─ POST /api/items\n      │  │  └─ HTTP 201 id=1\n      │  └─ POST /api/items\n      │     └─ HTTP 201 id=2\n      └─ GET /api/items?key=x\n         └─ HTTP 200 total=2\n```"
	if got := ensureDeliveryAttackChainTextFenceWithEvidence(flatConcurrent, concurrentRequests, true); got != concurrentWant {
		t.Fatalf("flat concurrent chain=%q, want %q", got, concurrentWant)
	}
	nestedConcurrent := "GET /api/items?key=x\n   └─ HTTP 200 total=0\n      ├─ 并发提交 POST /api/items\n      │  ├─ HTTP 201 id=1\n      │  └─ HTTP 201 id=2\n      └─ GET /api/items?key=x\n         └─ HTTP 200 total=2"
	if got := ensureDeliveryAttackChainTextFenceWithEvidence(nestedConcurrent, concurrentRequests, true); got != concurrentWant {
		t.Fatalf("nested concurrent chain=%q, want %q", got, concurrentWant)
	}
	concurrentThree := "GET /api/registrations?reference=EVAL-RACE\n   └─ HTTP 200 total=0\n      └─ 并发父节点：\n         └─ POST /api/registrations\n            └─ HTTP 201 id=reg-1\n               └─ POST /api/registrations\n                  └─ HTTP 201 id=reg-2\n                     └─ POST /api/registrations\n                        └─ HTTP 201 id=reg-3\n                           └─ GET /api/registrations?reference=EVAL-RACE\n                              └─ HTTP 200 total=3"
	requestPacket := strings.Join([]string{
		"### 提交前查询 · 请求\nGET /api/registrations?reference=EVAL-RACE HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
		"### 第一次并发提交 · 请求\nPOST /api/registrations HTTP/1.1\r\nContent-Length: 25\r\n\r\n{\"reference\":\"EVAL-RACE\"}",
		"### 第二次并发提交 · 请求\nPOST /api/registrations HTTP/1.1\r\nContent-Length: 25\r\n\r\n{\"reference\":\"EVAL-RACE\"}",
		"### 第三次并发提交 · 请求\nPOST /api/registrations HTTP/1.1\r\nContent-Length: 25\r\n\r\n{\"reference\":\"EVAL-RACE\"}",
		"### 提交后查询 · 请求\nGET /api/registrations?reference=EVAL-RACE HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
		"### 缺少业务编号的提交 · 请求\nPOST /api/registrations HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
	}, "\n\n")
	if method, path, count := repeatedDeliveryRequest(requestPacket, "并发父节点"); method != http.MethodPost || path != "/api/registrations" || count != 3 {
		t.Fatalf("actual packet repetition=%s %s x%d", method, path, count)
	}
	concurrentThreeWant := "```text\nGET /api/registrations?reference=EVAL-RACE\n   └─ HTTP 200 total=0\n      ├─ 并发提交 3 次相同请求\n      │  ├─ POST /api/registrations\n      │  │  └─ HTTP 201 id=reg-1\n      │  ├─ POST /api/registrations\n      │  │  └─ HTTP 201 id=reg-2\n      │  └─ POST /api/registrations\n      │     └─ HTTP 201 id=reg-3\n      └─ GET /api/registrations?reference=EVAL-RACE\n         └─ HTTP 200 total=3\n```"
	if got := ensureDeliveryAttackChainTextFenceWithEvidence(concurrentThree, requestPacket, true); got != concurrentThreeWant {
		t.Fatalf("concurrent evidence with unrelated same-path request was normalized incorrectly:\n%s\nwant:\n%s", got, concurrentThreeWant)
	}
	ambiguous := "普通用户\n   ├─ 请求 A 返回 200\n   └─ 请求 B 返回 403"
	if got := ensureDeliveryAttackChainTextFence(ambiguous); got != "```text\n"+ambiguous+"\n```" {
		t.Fatalf("ambiguous branches were converted to a sequence: %q", got)
	}
	fenced := "```text\n" + plain + "\n```"
	if got := ensureDeliveryAttackChainTextFence(fenced); got != fenced {
		t.Fatalf("already fenced chain changed: %q", got)
	}
}

func TestEnsureDeliveryAttackChainUsesFirstEvidenceNodeWhenRootMissing(t *testing.T) {
	input := "├─ GET /api/items\n   └─ 200 OK\n└─ POST /api/items\n   └─ 201 Created"
	want := "```text\nGET /api/items\n   └─ 200 OK\n└─ POST /api/items\n   └─ 201 Created\n```"
	if got := ensureDeliveryAttackChainTextFence(input); got != want {
		t.Fatalf("rootless attack chain did not use its first request as the root: %q", got)
	}
	if got, want := ensureDeliveryAttackChainTextFence("Root\n└─ GET /api/items"), "```text\nGET /api/items\n```"; got != want {
		t.Fatalf("placeholder root did not fall back to the first request: got %q want %q", got, want)
	}
}

func TestRepeatedDeliveryRequestRequiresUnambiguousMatch(t *testing.T) {
	packet := "POST /api/a HTTP/1.1\n\nPOST /api/a HTTP/1.1\n\nPOST /api/b HTTP/1.1\n\nPOST /api/b HTTP/1.1\n\nPOST /api/b HTTP/1.1"
	if method, path, count := repeatedDeliveryRequest(packet, "并发提交相同请求"); method != "" || path != "" || count != 0 {
		t.Fatalf("ambiguous repeated requests selected %s %s x%d", method, path, count)
	}
	if method, path, count := repeatedDeliveryRequest(packet, "并发提交 POST /api/a"); method != http.MethodPost || path != "/api/a" || count != 2 {
		t.Fatalf("matched repeated request=%s %s x%d", method, path, count)
	}
	packetWithDifferentBody := strings.Join([]string{
		"### 第一次并发提交 · 请求",
		"POST /api/registrations HTTP/1.1\r\nContent-Length: 25\r\n\r\n{\"reference\":\"EVAL-RACE\"}",
		"### 第二次并发提交 · 请求",
		"POST /api/registrations HTTP/1.1\r\nContent-Length: 25\r\n\r\n{\"reference\":\"EVAL-RACE\"}",
		"### 第三次并发提交 · 请求",
		"POST /api/registrations HTTP/1.1\r\nContent-Length: 25\r\n\r\n{\"reference\":\"EVAL-RACE\"}",
		"### 缺少业务编号的提交 · 请求",
		"POST /api/registrations HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
	}, "\n\n")
	if method, path, count := repeatedDeliveryRequest(packetWithDifferentBody, "并发提交 POST /api/registrations"); method != http.MethodPost || path != "/api/registrations" || count != 3 {
		t.Fatalf("request bodies were not distinguished: %s %s x%d", method, path, count)
	}
}

func TestDeliveryReportConcurrencyEvidenceHint(t *testing.T) {
	if !hasExplicitDeliveryConcurrencyEvidence(map[string]string{"summary": "同一账号并发提交3次相同请求"}) {
		t.Fatal("explicitly tested concurrency was not recognized")
	}
	if hasExplicitDeliveryConcurrencyEvidence(map[string]string{"summary": "并发未测试"}) {
		t.Fatal("unverified concurrency was accepted as evidence")
	}
}

func TestDeliveryReportDraftDisablesConfiguredResponsesReasoning(t *testing.T) {
	modelDraft := `{"cvss_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:L/SC:N/SI:L/SA:N","description":"问题描述。\n### 定级依据\n有可复核证据。","remediation":"在服务端校验资源归属。","test_process":"### 发现过程与攻击思路\n用 Burp Repeater 重放样本请求。\n### 失败尝试与未验证项\n批量编号未验证。\n### Burp 复现\n按授权账号复测。","attack_chain":"普通用户\n└─ 修改请求\n   └─ 其他用户数据发生变化","discovery_path":"来源为合成材料。\n### 复测标准\n跨用户请求应被拒绝。"}`
	receivedCh := make(chan map[string]json.RawMessage, 1)
	providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Errorf("request path=%q, want /v1/responses", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var received map[string]json.RawMessage
		if err := json.Unmarshal(body, &received); err != nil {
			t.Errorf("decode request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		receivedCh <- received
		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{
			"status": "completed",
			"output": []map[string]any{{
				"type": "message", "role": "assistant",
				"content": []map[string]any{{"type": "output_text", "text": modelDraft}},
			}},
			"usage": map[string]int{"input_tokens": 1200, "output_tokens": 420},
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("write model response: %v", err)
		}
	}))
	defer providerServer.Close()

	provider, err := (agent.Config{
		Format: llm.FormatOpenAIResponses, BaseURL: providerServer.URL + "/v1",
		Model: "qwen3.8-flash", APIKey: "test-provider-key", ReasoningEffort: "xhigh",
	}).NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	draft, usage, err := completeDeliveryReportWith(context.Background(), map[string]string{
		"task_description": "合成评测任务", "request_packet": "GET /item/1 HTTP/1.1",
	}, 7, provider.Complete)
	if err != nil {
		t.Fatal(err)
	}
	received := <-receivedCh
	var request struct {
		Instructions string `json:"instructions"`
		Reasoning    struct {
			Effort string `json:"effort"`
		} `json:"reasoning"`
	}
	receivedJSON, err := json.Marshal(received)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(receivedJSON, &request); err != nil {
		t.Fatal(err)
	}
	if request.Reasoning.Effort != "none" {
		t.Fatalf("Responses API reasoning effort=%q, want none", request.Reasoning.Effort)
	}
	if !strings.Contains(request.Instructions, "保存前在本次输出中核对结论、限制、修复和链路") {
		t.Fatal("report request did not include the same-Reporter self-check rules")
	}
	if draft.Description == "" || usage.OutputTokens != 420 {
		t.Fatalf("draft=%+v usage=%+v", draft, usage)
	}
}
