package server

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/wpsec/ARTEX-local/agent"
	"github.com/wpsec/ARTEX-local/tools/report-eval"
)

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
	modelResponseJSON := `{"cvss_vector":"CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N","description":"描述\n### 定级依据\n依据样本中的状态变化。","remediation":"按服务端当前用户校验作业归属。","test_process":"### 发现过程与攻击思路\n按样本步骤核对。\n### 失败尝试与未验证项\n批量编号未验证。","attack_chain":"FENCEtext\n普通用户\n└─ 修改接口\n   └─ 作业状态发生变化\nFENCE","discovery_path":"### Burp 复现\n将样本请求放入 Repeater。\n### 复测标准\n其他用户修改应被拒绝。"}`
	provider := &reportEvalProvider{result: strings.ReplaceAll(modelResponseJSON, "FENCE", "```")}
	s := &Server{llmProv: provider, llmOn: true, llmCfg: agent.Config{Model: "fixed-test-model"}, jwtKey: []byte("report-eval-test-signing-key")}
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
	if info.Code != http.StatusOK || !strings.Contains(info.Body.String(), "fixed-test-model") {
		t.Fatalf("metadata response status=%d body=%s", info.Code, info.Body.String())
	}
	response := request(http.MethodPost, "/api/report-eval/idor", "", token)
	if response.Code != http.StatusOK {
		t.Fatalf("sample request status=%d body=%s", response.Code, response.Body.String())
	}
	if provider.calls != 1 {
		t.Fatalf("model call count=%d, want 1", provider.calls)
	}
	if len(provider.request.Tools) != 0 {
		t.Fatalf("evaluation request exposed %d tools", len(provider.request.Tools))
	}
	if provider.request.Thinking != "disabled" {
		t.Fatalf("evaluation request thinking=%q, want disabled for strict JSON output", provider.request.Thinking)
	}
	prompt := provider.request.Messages[0].Text()
	for _, forbidden := range []string{"reference_report", "must_preserve", "must_not_claim", `"id":"E`} {
		if strings.Contains(prompt, forbidden) {
			t.Fatalf("model input exposed internal review material %q", forbidden)
		}
	}
	if !strings.Contains(prompt, "GET /api/jobs/job-a HTTP/1.1") || !strings.Contains(prompt, "user-b") {
		t.Fatal("model input omitted the fixed sample evidence")
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
	if result.Model != "fixed-test-model" || result.Usage.InputTokens != 17 || result.Draft.RequestPacket == "" {
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
			if tt.mustHide != "" && strings.Contains(response.Body.String(), tt.mustHide) {
				t.Fatalf("response leaked provider error detail: %s", response.Body.String())
			}
		})
	}
}
