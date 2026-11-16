package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/wpsec/ARTEX-local/agent"
	"github.com/wpsec/ARTEX-local/tools/report-eval"
)

const reportEvalMaxTokens = deliveryReportMaxTokens

func reportEvalEnabled() bool {
	enabled, err := strconv.ParseBool(strings.TrimSpace(os.Getenv("ARTEX_REPORT_EVAL_ENABLED")))
	return err == nil && enabled
}

func (s *Server) reportEvalProvider() (llm.Provider, agent.Config, string, bool) {
	if s.m != nil {
		if provider, cfg, ok := s.agentBindingProvider("reporter"); ok {
			return provider, cfg, "reporter 角色绑定", true
		}
	}
	if provider, cfg, ok := s.globalProvider(); ok {
		return provider, cfg, "全局当前模型", true
	}
	return nil, agent.Config{}, "", false
}

func (s *Server) reportEvalInfo(w http.ResponseWriter, r *http.Request) {
	if !reportEvalEnabled() {
		http.NotFound(w, r)
		return
	}
	_, cfg, source, ok := s.reportEvalProvider()
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "没有可用的报告模型")
		return
	}
	systemHash := sha256.Sum256([]byte(deliveryReportCompletionSystem()))
	writeJSON(w, http.StatusOK, map[string]any{
		"model": cfg.Model, "provider_source": source, "format": cfg.Format,
		"thinking_type": cfg.ThinkingType, "reasoning_effort": cfg.ReasoningEffort,
		"case_ids": reporteval.IDs(), "max_output_tokens": reportEvalMaxTokens, "completion_passes": 1,
		"system_sha256": hex.EncodeToString(systemHash[:]),
	})
}

func (s *Server) runReportEvalCase(w http.ResponseWriter, r *http.Request) {
	if !reportEvalEnabled() {
		http.NotFound(w, r)
		return
	}
	if r.ContentLength > 0 {
		writeErr(w, http.StatusBadRequest, "评测请求不接受自定义内容")
		return
	}
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			writeErr(w, http.StatusBadRequest, "评测请求不接受自定义内容")
			return
		}
	}
	sample, material, err := reporteval.Load(r.PathValue("case_id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "评测样本不存在")
		return
	}
	provider, cfg, source, ok := s.reportEvalProvider()
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "没有可用的报告模型")
		return
	}
	input, err := reportEvalPromptInput(sample, material)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "构造固定评测材料失败")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	started := time.Now()
	draft, usage, err := completeDeliveryReportWith(ctx, input, 0, provider.Complete)
	if err != nil {
		message := "报告模型调用失败"
		status := http.StatusBadGateway
		switch {
		case errors.Is(err, errDeliveryReportInvalidJSON):
			message = "模型未返回可解析的报告字段"
		case errors.Is(err, errDeliveryReportMissingBody):
			message = "模型报告字段不完整"
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			message = "模型请求超时"
			status = http.StatusGatewayTimeout
		}
		var outputErr *deliveryReportOutputError
		if errors.As(err, &outputErr) {
			writeJSON(w, status, map[string]any{
				"error":      message,
				"raw_output": outputErr.raw,
				"diagnostic": map[string]any{
					"stop_reason":         outputErr.stopReason,
					"content_block_types": outputErr.contentBlockType,
					"output_tokens":       outputErr.outputTokens,
				},
			})
			return
		}
		writeErr(w, status, message)
		return
	}
	draft.RequestPacket = input["request_packet"]
	draft.ResponsePacket = input["response_packet"]
	draft.CVSSVector, ok = normalizeCVSS4BaseVector(draft.CVSSVector)
	if !ok {
		writeErr(w, http.StatusBadGateway, "模型返回的 CVSS 4.0 Base 向量无效")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"case_id": sample.ID, "model": cfg.Model, "provider_source": source,
		"duration_ms": time.Since(started).Milliseconds(), "usage": usage, "draft": draft,
	})
}

func reportEvalPromptInput(sample reporteval.Case, material []byte) (map[string]string, error) {
	evidenceInventory, err := materialEvidenceInventory(material)
	if err != nil {
		return nil, err
	}
	encodedFacts, err := json.Marshal(map[string]any{"evidence_inventory": evidenceInventory})
	if err != nil {
		return nil, fmt.Errorf("marshal report evaluation facts: %w", err)
	}
	var observations []string
	for _, observation := range sample.Facts.Observations {
		observations = append(observations, "- "+observation)
	}
	var failures []string
	for _, item := range sample.Evidence {
		if status := evidenceHTTPStatus(item.Response); status >= http.StatusBadRequest {
			failures = append(failures, fmt.Sprintf("%s：HTTP %d", item.Purpose, status))
			continue
		}
		if item.ExitCode != 0 {
			failure := fmt.Sprintf("%s：命令退出码 %d", item.Purpose, item.ExitCode)
			if strings.TrimSpace(item.Stderr) != "" {
				failure += "，" + strings.TrimSpace(item.Stderr)
			}
			failures = append(failures, failure)
		}
	}
	requestPacket := reportEvalPackets(sample.Evidence, true)
	return map[string]string{
		"task_description":                  "离线合成交付报告评测；不对应真实系统或真实测试。",
		"task_goal":                         "仅根据固定样本写报告，不执行命令、不调用工具、不访问网络。",
		"synthetic":                         strconv.FormatBool(sample.Synthetic),
		"evidence_transport":                sample.Kind,
		"evidence_origin":                   "离线合成报文与记录；没有访问真实目标或执行真实测试。",
		"test_conditions":                   strings.Join(sample.Facts.Conditions, "\n"),
		"recorded_failures":                 strings.Join(failures, "\n"),
		"known_limitations":                 strings.Join(sample.Facts.Limitations, "\n"),
		"test_tool_hint":                    sample.Facts.TestTool,
		"cvss_vector_hint":                  sample.Facts.CVSSVector,
		"test_time_hint":                    reportEvalTestTimeHint(sample.TestTime),
		"finding_name":                      sample.Name,
		"vulnerability_class":               "",
		"severity":                          "",
		"summary":                           strings.Join(observations, "\n"),
		"evidence":                          string(encodedFacts),
		"existing_detailed_report":          "",
		"existing_detailed_report_is_stale": "false",
		"request_packet":                    requestPacket,
		"request_line_index":                deliveryReportRequestLineIndex(requestPacket),
		"response_packet":                   reportEvalPackets(sample.Evidence, false),
	}, nil
}

func evidenceHTTPStatus(response string) int {
	line, _, _ := strings.Cut(strings.TrimSpace(response), "\n")
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return 0
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return status
}

func materialEvidenceInventory(material []byte) (json.RawMessage, error) {
	var decoded struct {
		Evidence []struct {
			Purpose          string `json:"purpose"`
			Source           string `json:"source"`
			RequestComplete  bool   `json:"request_complete"`
			ResponseComplete bool   `json:"response_complete"`
			Request          string `json:"request"`
			Response         string `json:"response"`
			Command          string `json:"command"`
			Stdout           string `json:"stdout"`
			Stderr           string `json:"stderr"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(material, &decoded); err != nil {
		return nil, fmt.Errorf("decode fixed report evaluation evidence: %w", err)
	}
	if len(decoded.Evidence) == 0 {
		return nil, fmt.Errorf("fixed report evaluation sample has no evidence")
	}
	type item struct {
		Purpose          string `json:"purpose"`
		Source           string `json:"source"`
		RequestComplete  bool   `json:"request_complete,omitempty"`
		ResponseComplete bool   `json:"response_complete,omitempty"`
		HasRequest       bool   `json:"has_request,omitempty"`
		HasResponse      bool   `json:"has_response,omitempty"`
		HasCommand       bool   `json:"has_command,omitempty"`
		HasStdout        bool   `json:"has_stdout,omitempty"`
		HasStderr        bool   `json:"has_stderr,omitempty"`
	}
	inventory := make([]item, 0, len(decoded.Evidence))
	for _, evidence := range decoded.Evidence {
		inventory = append(inventory, item{
			Purpose: evidence.Purpose, Source: evidence.Source,
			RequestComplete: evidence.RequestComplete, ResponseComplete: evidence.ResponseComplete,
			HasRequest: evidence.Request != "", HasResponse: evidence.Response != "",
			HasCommand: evidence.Command != "", HasStdout: evidence.Stdout != "", HasStderr: evidence.Stderr != "",
		})
	}
	return json.Marshal(inventory)
}

func reportEvalPackets(evidence []reporteval.Evidence, requests bool) string {
	var out strings.Builder
	for _, item := range evidence {
		packet := item.Response
		label := "响应"
		if requests {
			packet, label = item.Request, "请求"
		}
		if packet == "" {
			continue
		}
		fmt.Fprintf(&out, "### %s · %s\n%s\n\n", item.Purpose, label, packet)
	}
	return strings.TrimSpace(out.String())
}
