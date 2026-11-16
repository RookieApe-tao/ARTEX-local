package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/norma/llm"
	"github.com/wpsec/ARTEX-local/agent"
	"github.com/wpsec/ARTEX-local/db"
	"github.com/wpsec/ARTEX-local/evidence"
)

const (
	deliveryReportMaxBytes         = 8 << 20
	deliveryReportEvidenceMaxBytes = 4 << 20
	deliveryEvidenceAppendixMarker = "<!-- artex:bound-traffic-evidence -->"
)

var (
	errDeliveryReportInvalidJSON = errors.New("模型没有返回有效的报告 JSON")
	errDeliveryReportMissingBody = errors.New("报告缺少必需内容")
)

const deliveryReportMaxTokens = 4096

type deliveryReportOutputError struct {
	cause            error
	raw              string
	stopReason       string
	contentBlockType []string
	outputTokens     int
}

func (e *deliveryReportOutputError) Error() string { return e.cause.Error() }

func (e *deliveryReportOutputError) Unwrap() error { return e.cause }

type deliveryReportAccess struct {
	task      *Task
	taskID    int64
	finding   *db.DBFinding
	findingID int64
}

type deliveryReportDraft struct {
	CVSSVector      string `json:"cvss_vector"`
	Description     string `json:"description"`
	Remediation     string `json:"remediation"`
	TestProcess     string `json:"test_process"`
	AttackChain     string `json:"attack_chain"`
	DiscoveryPath   string `json:"discovery_path"`
	RequestPacket   string `json:"request_packet"`
	ResponsePacket  string `json:"response_packet"`
	EvidenceVersion int64  `json:"evidence_version"`
}

func (s *Server) deliveryReportAccess(w http.ResponseWriter, r *http.Request) (deliveryReportAccess, bool) {
	taskID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || taskID <= 0 {
		writeErr(w, http.StatusBadRequest, "任务编号无效")
		return deliveryReportAccess{}, false
	}
	task, ok := s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok || task == nil {
		writeErr(w, http.StatusNotFound, "任务不存在")
		return deliveryReportAccess{}, false
	}
	findingID, err := strconv.ParseInt(r.PathValue("finding_id"), 10, 64)
	if err != nil || findingID <= 0 {
		writeErr(w, http.StatusBadRequest, "漏洞编号无效")
		return deliveryReportAccess{}, false
	}
	finding, err := s.m.pg.GetFinding(findingID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return deliveryReportAccess{}, false
	}
	if finding == nil {
		writeErr(w, http.StatusNotFound, "漏洞不存在")
		return deliveryReportAccess{}, false
	}
	if _, _, allowed := findingProvenanceInTask(task, finding.TaskID); !allowed {
		writeErr(w, http.StatusNotFound, "漏洞不属于当前任务或其继承范围")
		return deliveryReportAccess{}, false
	}
	return deliveryReportAccess{task: task, taskID: taskID, finding: finding, findingID: findingID}, true
}

func (s *Server) getFindingDeliveryReport(w http.ResponseWriter, r *http.Request) {
	access, ok := s.deliveryReportAccess(w, r)
	if !ok {
		return
	}
	report, err := s.m.pg.GetFindingDeliveryReport(access.taskID, access.findingID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if report == nil {
		writeErr(w, http.StatusNotFound, "漏洞不存在")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) saveFindingDeliveryReport(w http.ResponseWriter, r *http.Request) {
	access, ok := s.deliveryReportAccess(w, r)
	if !ok {
		return
	}
	var input struct {
		Content         string `json:"content"`
		CVSSVector      string `json:"cvss_vector"`
		EvidenceVersion *int64 `json:"evidence_version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, deliveryReportMaxBytes)).Decode(&input); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("请求内容无效或超过 %d MiB", deliveryReportMaxBytes>>20))
		return
	}
	if strings.TrimSpace(input.Content) == "" || input.EvidenceVersion == nil {
		writeErr(w, http.StatusBadRequest, "报告正文和证据版本必填")
		return
	}
	vector, ok := normalizeCVSS4BaseVector(input.CVSSVector)
	if !ok {
		writeErr(w, http.StatusBadRequest, "CVSS 4.0 Base 向量无效")
		return
	}
	if err := validateDeliveryReportTemplate(input.Content, vector); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	content, err := s.appendDeliveryTrafficEvidence(r.Context(), access.findingID, *input.EvidenceVersion, input.Content)
	if errors.Is(err, db.ErrEvidenceConflict) {
		writeErr(w, http.StatusConflict, "漏洞证据已变化，请刷新后重新保存")
		return
	}
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "附加完整 HTTP 流量证据失败："+err.Error())
		return
	}
	err = s.m.pg.SaveFindingDeliveryReport(r.Context(), access.taskID, access.findingID, *input.EvidenceVersion, content, vector)
	if errors.Is(err, db.ErrEvidenceConflict) || errors.Is(err, db.ErrTaskArchiveState) {
		writeErr(w, http.StatusConflict, "证据已变化或任务正在归档，请刷新后重新保存")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	report, err := s.m.pg.GetFindingDeliveryReport(access.taskID, access.findingID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) generateFindingDeliveryReport(w http.ResponseWriter, r *http.Request) {
	access, ok := s.deliveryReportAccess(w, r)
	if !ok {
		return
	}
	traffic, err := s.m.pg.GetFindingTraffic(r.Context(), access.findingID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取已绑定流量失败："+err.Error())
		return
	}
	if traffic.Version != access.finding.EvidenceVersion {
		writeErr(w, http.StatusConflict, "漏洞证据刚刚发生变化，请重新生成")
		return
	}
	requestPacket, responsePacket, err := s.deliveryTrafficPackets(traffic.Bindings)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "读取已绑定的真实流量失败："+err.Error())
		return
	}
	draft, err := s.completeDeliveryReport(r.Context(), access,
		requestPacket, responsePacket, traffic.Version, len(traffic.Bindings) > 0)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "生成交付报告草稿失败："+err.Error())
		return
	}
	latestTraffic, err := s.m.pg.GetFindingTraffic(r.Context(), access.findingID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "复核漏洞证据版本失败")
		return
	}
	if latestTraffic.Version != traffic.Version {
		writeErr(w, http.StatusConflict, "生成期间漏洞证据发生变化，请重新生成")
		return
	}
	draft.RequestPacket = requestPacket
	draft.ResponsePacket = responsePacket
	draft.EvidenceVersion = traffic.Version
	draft.CVSSVector, ok = normalizeCVSS4BaseVector(draft.CVSSVector)
	if !ok {
		writeErr(w, http.StatusBadGateway, "模型返回的 CVSS 4.0 Base 向量无效，请重试")
		return
	}
	writeJSON(w, http.StatusOK, draft)
}

func (s *Server) completeDeliveryReport(ctx context.Context, access deliveryReportAccess, requestPacket, responsePacket string, evidenceVersion int64, hasHTTPBindings bool) (deliveryReportDraft, error) {
	evidenceTransport := "unknown"
	if hasHTTPBindings {
		evidenceTransport = "http"
	}
	input := map[string]string{
		"task_description":                  access.task.Description,
		"task_goal":                         access.task.Goal,
		"finding_name":                      access.finding.Name,
		"vulnerability_class":               access.finding.VulnClass,
		"severity":                          access.finding.Severity,
		"summary":                           access.finding.Summary,
		"evidence":                          access.finding.Evidence,
		"existing_detailed_report":          access.finding.Report,
		"existing_detailed_report_is_stale": strconv.FormatBool(access.finding.Report != "" && access.finding.ReportEvidenceVersion != access.finding.EvidenceVersion),
		"request_packet":                    requestPacket,
		"response_packet":                   responsePacket,
		"evidence_transport":                evidenceTransport,
	}
	runtime := &taskLLMRuntime{s: s, taskID: access.task.ID, agentKey: "reporter"}
	draft, _, err := completeDeliveryReportWith(ctx, input, evidenceVersion, runtime.Complete)
	return draft, err
}

func deliveryReportCompletionSystem() string {
	return agent.DeliveryReportDraftRules
}

func stripDeliveryDraftSectionHeading(content, section string) string {
	lines := strings.Split(strings.TrimSpace(content), "\n")
	for len(lines) > 0 {
		if strings.TrimSpace(lines[0]) == "" {
			lines = lines[1:]
			continue
		}
		if strings.TrimSpace(lines[0]) != "## "+section {
			break
		}
		lines = lines[1:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func normalizeDeliveryDraftSubheadings(content string, headings ...string) string {
	for _, heading := range headings {
		marker := "### " + heading
		position := -1
		scanDeliveryMarkdown(content, func(line string, offset int, code bool) {
			if position >= 0 || code {
				return
			}
			level, title := deliveryMarkdownHeading(line)
			if level == 3 && title == heading {
				return
			}
			index := strings.Index(line, marker)
			if index < 0 {
				return
			}
			boundary := index + len(marker)
			if boundary < len(line) && line[boundary] != ' ' && line[boundary] != '\t' {
				return
			}
			position = offset + index
		})
		if position < 0 {
			continue
		}
		if position > 0 && content[position-1] != '\n' {
			content = content[:position] + "\n\n" + content[position:]
			position += 2
		}
		afterMarker := position + len(marker)
		if afterMarker < len(content) && content[afterMarker] != '\n' && content[afterMarker] != '\r' {
			content = content[:afterMarker] + "\n" + content[afterMarker:]
		}
	}
	return strings.TrimSpace(content)
}

func ensureDeliveryAttackChainTextFence(content string) string {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```") {
		lines := strings.Split(content, "\n")
		lines = lines[1:]
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "```" {
			lines = lines[:len(lines)-1]
		}
		content = strings.TrimSpace(strings.Join(lines, "\n"))
	}
	lines := strings.Split(content, "\n")
	nodes := make([]string, 0, len(lines))
	treeLines := make([]string, 0, len(lines))
	hasTreeBranch := false
	for _, line := range lines {
		rawLine := line
		line = strings.TrimSpace(line)
		if line == "" || line == "text" {
			continue
		}
		treeLines = append(treeLines, strings.TrimRight(rawLine, "\r"))
		if strings.Contains(line, "├─") || strings.Contains(line, "└─") {
			hasTreeBranch = true
		}
		line = strings.TrimLeft(line, "-*")
		for _, part := range strings.Split(strings.ReplaceAll(line, "->", "→"), "→") {
			part = strings.TrimSpace(part)
			for _, prefix := range []string{"入口：", "入口:", "身份：", "身份:", "条件：", "条件:", "操作：", "操作:", "结果：", "结果:", "影响：", "影响:"} {
				part = strings.TrimPrefix(part, prefix)
			}
			part = strings.TrimSpace(part)
			if part != "" {
				nodes = append(nodes, part)
			}
		}
	}
	if !hasTreeBranch && len(nodes) > 1 {
		content = nodes[0]
		for _, node := range nodes[1:] {
			content += "\n   └─ " + node
		}
	} else {
		normalizedTree := make([]string, 0, len(treeLines))
		for _, line := range treeLines {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			trimmed := strings.TrimSpace(line)
			if strings.Trim(trimmed, "│ ") == "" {
				continue
			}
			if markerOffset := strings.IndexAny(trimmed, "├└"); markerOffset > 0 && strings.ContainsRune(trimmed[:markerOffset], '│') {
				indent += strings.Repeat(" ", utf8.RuneCountInString(trimmed[:markerOffset]))
				trimmed = strings.TrimLeft(trimmed[markerOffset:], " ")
			}
			marker := ""
			for _, candidate := range []string{"├─", "└─"} {
				if strings.HasPrefix(trimmed, candidate) {
					marker = candidate
					trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, candidate))
					break
				}
			}
			if marker != "" {
				trimmed = strings.TrimLeft(trimmed, " ─>→↓")
				trimmed = strings.TrimSpace(trimmed)
				if trimmed == "" {
					continue
				}
				line = indent + marker + " " + trimmed
			} else {
				line = trimmed
			}
			normalizedTree = append(normalizedTree, line)
		}
		content = strings.Join(normalizedTree, "\n")
	}
	if content == "" {
		return content
	}
	content = strings.Join(normalizeDeliveryAttackTreeBranches(strings.Split(content, "\n")), "\n")
	return "```text\n" + content + "\n```"
}

func normalizeDeliveryAttackTreeBranches(lines []string) []string {
	type branch struct {
		lineIndex int
		indent    int
		marker    string
	}
	branches := make([]branch, 0, len(lines))
	for index, line := range lines {
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		rest := line[indent:]
		for _, marker := range []string{"├─", "└─"} {
			if strings.HasPrefix(rest, marker) {
				branches = append(branches, branch{lineIndex: index, indent: indent, marker: marker})
				break
			}
		}
	}
	for index, current := range branches {
		hasFollowingSibling := false
		for _, next := range branches[index+1:] {
			if next.indent < current.indent {
				break
			}
			if next.indent == current.indent {
				hasFollowingSibling = true
				break
			}
		}
		marker := "└─"
		if hasFollowingSibling {
			marker = "├─"
		}
		line := lines[current.lineIndex]
		rest := strings.TrimLeft(line[current.indent+len(current.marker):], " ")
		lines[current.lineIndex] = line[:current.indent] + marker + " " + rest
	}
	return lines
}

func completeDeliveryReportWith(
	ctx context.Context,
	input map[string]string,
	evidenceVersion int64,
	complete func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error),
) (deliveryReportDraft, llm.Usage, error) {
	ctx = agent.WithDeliveryReportReasoningDisabled(ctx)
	return completeDeliveryReportDraft(ctx, input, evidenceVersion, complete)
}

func completeDeliveryReportDraft(
	ctx context.Context,
	input map[string]string,
	evidenceVersion int64,
	complete func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error),
) (deliveryReportDraft, llm.Usage, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return deliveryReportDraft{}, llm.Usage{}, err
	}
	message, stopReason, usage, err := complete(ctx, llm.CompletionRequest{
		System: []string{deliveryReportCompletionSystem()}, Messages: []llm.Message{llm.UserText(string(raw))}, MaxTokens: deliveryReportMaxTokens, Thinking: "disabled",
	})
	if err != nil {
		return deliveryReportDraft{}, usage, err
	}
	draft, err := parseDeliveryReportDraft(message, stopReason, usage, input, evidenceVersion)
	if err != nil {
		return deliveryReportDraft{}, usage, err
	}
	return draft, usage, nil
}

func parseDeliveryReportDraft(
	message llm.Message,
	stopReason string,
	usage llm.Usage,
	input map[string]string,
	evidenceVersion int64,
) (deliveryReportDraft, error) {
	text := strings.TrimSpace(message.Text())
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(strings.TrimSpace(text), "```")
	contentBlockTypes := make([]string, 0, len(message.Content))
	for _, block := range message.Content {
		contentBlockTypes = append(contentBlockTypes, string(block.Type))
	}
	var draft deliveryReportDraft
	if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &draft); err != nil {
		if markdownDraft, ok := parseDeliveryReportMarkdownDraft(text); ok {
			draft = markdownDraft
		} else {
			return deliveryReportDraft{}, &deliveryReportOutputError{
				cause: errDeliveryReportInvalidJSON, raw: text, stopReason: stopReason,
				contentBlockType: contentBlockTypes, outputTokens: usage.OutputTokens,
			}
		}
	}
	if hint := strings.TrimSpace(input["cvss_vector_hint"]); hint != "" {
		if vector, ok := normalizeCVSS4BaseVector(hint); ok {
			draft.CVSSVector = vector
		}
	}
	draft.Description = normalizeDeliveryDraftSubheadings(draft.Description, "定级依据")
	draft.TestProcess = normalizeDeliveryDraftSubheadings(draft.TestProcess, "发现过程与攻击思路", "失败尝试与未验证项", "Burp 复现")
	draft.DiscoveryPath = normalizeDeliveryDraftSubheadings(draft.DiscoveryPath, "复测标准")
	draft.Description = stripDeliveryDraftSectionHeading(draft.Description, "描述")
	draft.Remediation = stripDeliveryDraftSectionHeading(draft.Remediation, "修复建议")
	draft.Remediation = stripDeliveryDraftSectionHeading(draft.Remediation, "修复")
	draft.TestProcess = stripDeliveryDraftSectionHeading(draft.TestProcess, "测试过程")
	draft.AttackChain = stripDeliveryDraftSectionHeading(draft.AttackChain, "攻击链路")
	draft.AttackChain = ensureDeliveryAttackChainTextFence(draft.AttackChain)
	draft.DiscoveryPath = stripDeliveryDraftSectionHeading(draft.DiscoveryPath, "证据说明")
	if draft.Description == "" || draft.Remediation == "" || draft.TestProcess == "" ||
		draft.AttackChain == "" || draft.DiscoveryPath == "" {
		return deliveryReportDraft{}, &deliveryReportOutputError{
			cause: errDeliveryReportMissingBody, raw: text, stopReason: stopReason,
			contentBlockType: contentBlockTypes, outputTokens: usage.OutputTokens,
		}
	}
	draft.EvidenceVersion = evidenceVersion
	return draft, nil
}

func parseDeliveryReportMarkdownDraft(raw string) (deliveryReportDraft, bool) {
	text := strings.TrimSpace(raw)
	if strings.HasPrefix(text, "```") && strings.HasSuffix(text, "```") {
		lines := strings.Split(text, "\n")
		if len(lines) >= 3 {
			first := strings.TrimSpace(lines[0])
			last := strings.TrimSpace(lines[len(lines)-1])
			if strings.HasPrefix(first, "```") && last == "```" {
				lines = lines[1 : len(lines)-1]
				if strings.TrimSpace(lines[0]) == "markdown" || strings.TrimSpace(lines[0]) == "md" {
					lines = lines[1:]
				}
				text = strings.Join(lines, "\n")
			}
		}
	}

	type section struct {
		name      string
		start     int
		headingAt int
	}
	aliases := map[string]string{
		"描述": "描述", "漏洞描述": "描述",
		"修复": "修复建议", "修复建议": "修复建议",
		"测试过程": "测试过程", "攻击链路": "攻击链路", "证据说明": "证据说明",
	}
	sections := make([]section, 0, 5)
	valid := true
	closed := walkDeliveryMarkdown(text, func(line string, offset int) {
		level, heading := deliveryMarkdownHeading(line)
		if level != 2 {
			return
		}
		name, known := aliases[heading]
		if !known {
			valid = false
			return
		}
		start := offset + len(line)
		if start < len(text) && text[start] == '\r' {
			start++
		}
		if start < len(text) && text[start] == '\n' {
			start++
		}
		sections = append(sections, section{name: name, start: start, headingAt: offset})
	})
	if !valid || !closed || len(sections) != 5 {
		return deliveryReportDraft{}, false
	}
	expected := []string{"描述", "修复建议", "测试过程", "攻击链路", "证据说明"}
	for index, section := range sections {
		if section.name != expected[index] || (index > 0 && section.headingAt <= sections[index-1].headingAt) {
			return deliveryReportDraft{}, false
		}
	}
	body := func(index int) string {
		end := len(text)
		if index+1 < len(sections) {
			end = sections[index+1].headingAt
		}
		return strings.TrimSpace(text[sections[index].start:end])
	}
	draft := deliveryReportDraft{
		Description:   body(0),
		Remediation:   body(1),
		TestProcess:   body(2),
		AttackChain:   body(3),
		DiscoveryPath: body(4),
	}
	for _, line := range strings.Split(text, "\n") {
		if index := strings.Index(line, "CVSS:4.0/"); index >= 0 {
			fields := strings.Fields(line[index:])
			if len(fields) > 0 {
				candidate := strings.TrimRight(fields[0], "，,。；;`*_)")
				if vector, ok := normalizeCVSS4BaseVector(candidate); ok {
					draft.CVSSVector = vector
					break
				}
			}
		}
	}
	return draft, true
}

func (s *Server) deliveryTrafficPackets(bindings []db.FindingTrafficBinding) (string, string, error) {
	if len(bindings) == 0 {
		return missingTrafficPacket, missingTrafficPacket, nil
	}
	if err := validateDeliveryTrafficEvidenceSize(bindings); err != nil {
		return "", "", err
	}
	store := s.evidenceStore()
	requests := make([]string, 0, len(bindings))
	responses := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		requestPacket, err := deliveryHTTPPacket(store, binding.Snapshot, "request")
		if err != nil {
			return "", "", err
		}
		responsePacket, err := deliveryHTTPPacket(store, binding.Snapshot, "response")
		if err != nil {
			return "", "", err
		}
		label := fmt.Sprintf("证据绑定 %d（%s）", binding.ID, deliveryBindingRoleLabel(binding.Role))
		requests = append(requests, label+"\n"+requestPacket)
		responses = append(responses, label+"\n"+responsePacket)
	}
	return strings.Join(requests, "\n\n"), strings.Join(responses, "\n\n"), nil
}

func validateDeliveryTrafficEvidenceSize(bindings []db.FindingTrafficBinding) error {
	var totalBytes int64
	for _, binding := range bindings {
		totalBytes += int64(len(binding.Snapshot.ReqHead)+len(binding.Snapshot.RespHead)) + binding.Snapshot.ReqLen + binding.Snapshot.RespLen
		if totalBytes > deliveryReportEvidenceMaxBytes {
			return fmt.Errorf("绑定流量共 %d 字节，超过交付报告完整报文上限 %d 字节；未截断或保存报告", totalBytes, deliveryReportEvidenceMaxBytes)
		}
	}
	return nil
}

func deliveryBindingRoleLabel(role string) string {
	switch role {
	case "baseline":
		return "测试基线"
	case "proof":
		return "漏洞验证"
	case "verification":
		return "复核证据"
	case "supporting":
		return "辅助证据"
	default:
		return "流量证据"
	}
}

func (s *Server) appendDeliveryTrafficEvidence(ctx context.Context, findingID, evidenceVersion int64, report string) (string, error) {
	report = stripDeliveryTrafficEvidence(report)
	traffic, err := s.m.pg.GetFindingTraffic(ctx, findingID)
	if err != nil {
		return "", err
	}
	if traffic == nil || traffic.Version != evidenceVersion {
		return "", db.ErrEvidenceConflict
	}
	appendix, err := renderDeliveryTrafficEvidence(s.evidenceStore(), traffic.Bindings)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(report, "\n") + "\n\n" + deliveryEvidenceAppendixMarker + "\n" + appendix, nil
}

func renderDeliveryTrafficEvidence(store *evidence.Store, bindings []db.FindingTrafficBinding) (string, error) {
	if len(bindings) == 0 {
		return "### 平台 HTTP 流量证据\n\n该漏洞未绑定 ARTEX HTTP 流量。若正文引用了任务记录中的其他原始报文，应注明其实际来源；没有原始内容的部分不能推测补写。", nil
	}
	if err := validateDeliveryTrafficEvidenceSize(bindings); err != nil {
		return "", err
	}
	var out strings.Builder
	out.WriteString("### 平台留存的 HTTP 请求与响应\n\n以下内容取自本漏洞绑定的 ARTEX 流量证据。头部由平台采集时整理，协议首行、头部顺序和换行格式可能与网络原始字节不同；正文读取完整留存内容。这里不补造协议版本、缺失请求头或响应头。每个代码块仅含一条留存报文，复现时应核对目标协议、TLS 和认证状态。\n")
	for _, binding := range bindings {
		request, requestBinary, err := readDeliveryHTTPPacket(store, binding.Snapshot, "request")
		if err != nil {
			return "", err
		}
		response, responseBinary, err := readDeliveryHTTPPacket(store, binding.Snapshot, "response")
		if err != nil {
			return "", err
		}
		capturedAt := "未留存"
		if binding.Snapshot.CapturedAt > 0 {
			capturedAt = time.Unix(binding.Snapshot.CapturedAt, 0).In(time.FixedZone("UTC+08:00", 8*60*60)).Format(time.RFC3339)
		}
		fmt.Fprintf(&out, "\n#### 证据绑定 %d\n\n- 角色：%s\n- 来源：ARTEX 平台流量\n- 源流量编号：%s\n- 采集时间：%s\n- 请求地址：%s\n- 用途：%s\n",
			binding.ID, deliveryBindingRoleLabel(binding.Role), deliveryEvidenceMetadata(binding.Snapshot.SourceTrafficID),
			capturedAt, deliveryEvidenceMetadata(binding.Snapshot.URL), deliveryEvidenceMetadata(binding.Note))
		out.WriteString("\n##### 请求包\n\n")
		writeDeliveryPacketNotice(&out, binding.Snapshot.ReqHead, requestBinary)
		out.WriteString(markdownPacketBlock(request))
		out.WriteString("\n\n##### 响应包\n\n")
		writeDeliveryPacketNotice(&out, binding.Snapshot.RespHead, responseBinary)
		out.WriteString(markdownPacketBlock(response))
		out.WriteByte('\n')
	}
	return out.String(), nil
}

func deliveryEvidenceMetadata(value string) string {
	if strings.TrimSpace(value) == "" {
		return "未留存"
	}
	return strings.NewReplacer("\\", "\\\\", "\r", "\\r", "\n", "\\n", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]").Replace(html.EscapeString(value))
}

func writeDeliveryPacketNotice(out *strings.Builder, head string, binaryBody bool) {
	if strings.TrimSpace(head) == "" {
		out.WriteString("该方向报文头未留存，下面仅展示已留存正文或缺失提示，不能作为完整复现报文。\n\n")
	}
	if binaryBody {
		out.WriteString("该报文含二进制正文，以下使用 Base64 表示。重放前须解码还原原始字节，此代码块不能直接粘贴重放。\n\n")
	}
}

func stripDeliveryTrafficEvidence(report string) string {
	index := -1
	walkDeliveryMarkdown(report, func(line string, offset int) {
		if index < 0 && strings.TrimSpace(line) == deliveryEvidenceAppendixMarker {
			index = offset
		}
	})
	if index >= 0 {
		return strings.TrimRight(report[:index], "\r\n")
	}
	return report
}

func markdownPacketBlock(packet string) string {
	longest := 2
	for i := 0; i < len(packet); {
		if packet[i] != '`' {
			i++
			continue
		}
		start := i
		for i < len(packet) && packet[i] == '`' {
			i++
		}
		if run := i - start; run > longest {
			longest = run
		}
	}
	fence := strings.Repeat("`", longest+1)
	return fence + "http\n" + packet + "\n" + fence
}

const missingTrafficPacket = "未绑定 ARTEX 平台 HTTP 流量。若任务证据或执行记录中另有原始请求/响应，应从原始证据中引用并注明来源；仅凭流量未绑定不能断言未采集。"

func deliveryHTTPPacket(store *evidence.Store, snapshot db.TrafficEvidenceSnapshot, side string) (string, error) {
	packet, _, err := readDeliveryHTTPPacket(store, snapshot, side)
	return packet, err
}

func readDeliveryHTTPPacket(store *evidence.Store, snapshot db.TrafficEvidenceSnapshot, side string) (string, bool, error) {
	head := snapshot.ReqHead
	if side == "response" {
		head = snapshot.RespHead
	}
	file, total, err := store.OpenBody(snapshot, side)
	if err != nil {
		return "", false, err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return "", false, err
	}
	if int64(len(data)) != total {
		return "", false, fmt.Errorf("HTTP %s 正文不完整：证据记录 %d 字节，实际读取 %d 字节", side, total, len(data))
	}
	body := string(data)
	binaryBody := bytesContainBinary(data)
	if binaryBody {
		body = fmt.Sprintf("[二进制正文，原始长度 %d 字节；以下为原始字节的 Base64 编码]\n%s", total, base64.StdEncoding.EncodeToString(data))
	}
	packet := strings.TrimRight(head, "\r\n")
	if packet != "" {
		packet += "\r\n\r\n"
	}
	packet += body
	if packet == "" {
		packet = "[该方向的 HTTP 报文未留存]"
	}
	return packet, binaryBody, nil
}

func bytesContainBinary(raw []byte) bool {
	return bytes.IndexByte(raw, 0) >= 0 || !utf8.Valid(raw)
}

var cvss4MetricValues = map[string]map[string]bool{
	"AV": {"N": true, "A": true, "L": true, "P": true}, "AC": {"L": true, "H": true}, "AT": {"N": true, "P": true},
	"PR": {"N": true, "L": true, "H": true}, "UI": {"N": true, "P": true, "A": true},
	"VC": {"H": true, "L": true, "N": true}, "VI": {"H": true, "L": true, "N": true}, "VA": {"H": true, "L": true, "N": true},
	"SC": {"H": true, "L": true, "N": true}, "SI": {"H": true, "L": true, "N": true}, "SA": {"H": true, "L": true, "N": true},
}

func normalizeCVSS4BaseVector(raw string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(raw), "/")
	if len(parts) != 12 || parts[0] != "CVSS:4.0" {
		return "", false
	}
	metrics := strings.Split("AV AC AT PR UI VC VI VA SC SI SA", " ")
	out := []string{parts[0]}
	for i, name := range metrics {
		pair := strings.SplitN(parts[i+1], ":", 2)
		if len(pair) != 2 || pair[0] != name || !cvss4MetricValues[name][pair[1]] {
			return "", false
		}
		out = append(out, name+":"+pair[1])
	}
	return strings.Join(out, "/"), true
}
