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
	return agent.DeliveryReportWritingRules + `

平台会拼装报告标题、CVSS 信息、五个二级标题和原始证据附件。每个字段只返回对应章节的正文；不要在字段中重复标题、CVSS 信息或完整报告。除固定要求的三级标题外，不要添加其他标题。
只返回六个字符串字段组成的 JSON 对象，不改字段名、不增加字段、不输出解释文字：
{"cvss_vector":"CVSS:4.0/...","description":"问题和实际结果。\n\n### 定级依据\n评分依据。","remediation":"一项明确的修复。","test_process":"### 发现过程与攻击思路\n必要步骤和判据。\n\n### 失败尝试与未验证项\n材料中确有的失败或未验证边界。\n\n### Burp 复现\nHTTP 复现步骤；未实际使用时标注未验证。","attack_chain":"普通用户登录\n└─ 提交请求\n   └─ 观察到的结果","discovery_path":"材料来源和完整性。\n\n### 复测标准\n可观察的修复结果。"}

逐句核对结论是否能在本次材料中找到依据。原始材料和执行记录优先于摘要、旧报告和 worker 总结。输入有 cvss_vector_hint 时原样使用；输入有 test_time_hint 且时间顺序影响结论时，换算后保留北京时间。账号、权限、会话和工具只采用材料明确记载的内容；没有记录就不猜。
正文只保留开发理解问题、复现和修复所需的信息，避免在描述、测试过程和攻击链中重复同一事实。准确时间只在顺序、竞态或有效期影响结论时写入；详细参数、逐项时间、失败日志和哈希留在详细报告。失败尝试只写执行记录中确实发生的操作；输入中的 recorded_failures 用于核对实际失败。未验证边界简短说明，不补造步骤或结果。
已观察结果与潜在影响分开写。未测试的请求方式、账号或条件不得写成已知行为。SQL 注入测试若只比较恒真和恒假常量，只报告响应变化；未测试依赖字段值的条件时，不声称能读取字段值、探测数据或判断库结构。并发测试应写清客户端实际发送方式和结果；没有服务端时序证据时，不声称服务端同刻处理或串行提交也会产生相同结果。
修复建议只给一项有证据支持的主要改动。材料只能支持待核实线索时，先写明需要补取的证据，不给条件式代码修复；确认缺陷后再给针对根因的改动。重复写入优先建议数据库唯一约束，并说明冲突时的预期响应；SQL 注入只建议参数化查询，不把过滤或拒绝特殊字符列为修复。没有源码证据时不猜文件或实现。只有状态码、响应头或身份标记时，不认定越权或数据泄露。
资源授权关系使用清楚的业务称呼，例如“当前登录用户”“作业所有者”“文件所属账号”；不要用缩写代替对象关系。像 X-Eval-Actor 这样的合成标记不能证明真实登录身份，也不能作为切换账号的方法。事实材料给出账号角色时，只按材料来源陈述，不从报文标记推导认证状态。
HTTP 问题的“Burp 复现”说明实际使用状态；未使用时给简短的建议步骤并标记未验证。证据没有真实认证材料时，不猜 Cookie、Token 或请求头，也不写修改凭证的 Repeater 步骤；建议分别用获授权账号正常登录、捕获各自请求，再核对结果。Repeater 逐条发送只能检查单次或串行行为；并发漏洞须使用并发工具或脚本验证，未实际使用时写明需要并发复测。非 HTTP 问题说明 Burp 不适用。
各节只保留读者判断、复现和修复所需内容。一般用一段描述、一个修复动作和不超过四步的测试过程；非关键未验证项合并说明。攻击链的并列请求使用同一父节点和对齐分支。
攻击链只连接证据支持的入口、必要条件、请求或命令与实际结果，使用简短中文树形内容。证据说明交代来源和完整性。平台会原样附加完整绑定报文，正文引用用途，不重抄；缺少响应正文或仅有片段时说明缺口。合成样本说明未测试真实目标。
保存前由同一 Reporter 自查标题和 CVSS 不重复、五节顺序正确、每个 JSON 字段只含对应章节正文、事实和影响有依据、攻击链与附件相符。`
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
	return "```text\n" + content + "\n```"
}

func completeDeliveryReportWith(
	ctx context.Context,
	input map[string]string,
	evidenceVersion int64,
	complete func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error),
) (deliveryReportDraft, llm.Usage, error) {
	ctx = agent.WithDeliveryReportReasoningDisabled(ctx)
	draft, usage, err := completeDeliveryReportDraft(ctx, input, evidenceVersion, complete)
	if err != nil {
		return deliveryReportDraft{}, usage, err
	}

	reviewed, reviewUsage, err := reviewDeliveryReportDraft(ctx, input, draft, evidenceVersion, complete)
	usage.Add(reviewUsage)
	if err != nil {
		return deliveryReportDraft{}, usage, err
	}
	return reviewed, usage, nil
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

func reviewDeliveryReportDraft(
	ctx context.Context,
	evidence map[string]string,
	draft deliveryReportDraft,
	evidenceVersion int64,
	complete func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error),
) (deliveryReportDraft, llm.Usage, error) {
	input := map[string]any{
		"evidence": evidence,
		"draft": map[string]string{
			"cvss_vector":    draft.CVSSVector,
			"description":    draft.Description,
			"remediation":    draft.Remediation,
			"test_process":   draft.TestProcess,
			"attack_chain":   draft.AttackChain,
			"discovery_path": draft.DiscoveryPath,
		},
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return deliveryReportDraft{}, llm.Usage{}, err
	}
	message, stopReason, usage, err := complete(ctx, llm.CompletionRequest{
		System: []string{deliveryReportReviewSystem()}, Messages: []llm.Message{llm.UserText(string(raw))}, MaxTokens: deliveryReportMaxTokens, Thinking: "disabled",
	})
	if err != nil {
		return deliveryReportDraft{}, usage, err
	}
	reviewed, err := parseDeliveryReportDraft(message, stopReason, usage, evidence, evidenceVersion)
	if err != nil {
		return deliveryReportDraft{}, usage, err
	}
	if reviewed.CVSSVector == "" {
		reviewed.CVSSVector = draft.CVSSVector
	}
	return reviewed, usage, nil
}

func reviewDeliveryReportMarkdown(
	ctx context.Context,
	evidence map[string]string,
	report string,
	vector string,
	complete func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error),
) (string, error) {
	input, err := json.Marshal(map[string]any{
		"evidence":    evidence,
		"draft":       stripDeliveryTrafficEvidence(report),
		"cvss_vector": vector,
	})
	if err != nil {
		return "", err
	}
	message, _, _, err := complete(agent.WithDeliveryReportReasoningDisabled(ctx), llm.CompletionRequest{
		System: []string{deliveryReportMarkdownReviewSystem()}, Messages: []llm.Message{llm.UserText(string(input))}, MaxTokens: deliveryReportMaxTokens, Thinking: "disabled",
	})
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(message.Text())
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(strings.TrimSpace(text), "```")
	var output struct {
		Report string `json:"report"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &output); err != nil {
		return "", fmt.Errorf("报告复核未返回有效 JSON：%w", err)
	}
	reviewed := strings.TrimSpace(output.Report)
	if reviewed == "" {
		return "", errors.New("报告复核未返回正文")
	}
	if deliveryReportHeader(reviewed) != deliveryReportHeader(report) {
		return "", errors.New("报告复核修改了标题或 CVSS 报告头")
	}
	if err := validateDeliveryReportTemplate(reviewed, vector); err != nil {
		return "", fmt.Errorf("报告复核结果未通过固定模板校验：%w", err)
	}
	return reviewed, nil
}

func deliveryReportHeader(report string) string {
	end := len(report)
	walkDeliveryMarkdown(report, func(line string, offset int) {
		if end != len(report) {
			return
		}
		level, _ := deliveryMarkdownHeading(line)
		if level == 2 {
			end = offset
		}
	})
	return strings.TrimSpace(report[:end])
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
		return deliveryReportDraft{}, &deliveryReportOutputError{
			cause: errDeliveryReportInvalidJSON, raw: text, stopReason: stopReason,
			contentBlockType: contentBlockTypes, outputTokens: usage.OutputTokens,
		}
	}
	if hint := strings.TrimSpace(input["cvss_vector_hint"]); hint != "" {
		if vector, ok := normalizeCVSS4BaseVector(hint); ok {
			draft.CVSSVector = vector
		}
	}
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

func deliveryReportReviewSystem() string {
	return `你是渗透测试交付报告的证据审阅人。你会收到原始测试材料和一份待审报告。逐句核对材料，直接改正报告后返回完整 JSON。此步骤只复核并修正交付报告，不重新测试目标，不增加漏洞结论。

只返回六个字符串字段组成的 JSON 对象，字段名为 cvss_vector、description、remediation、test_process、attack_chain、discovery_path。字段内容遵守固定五节结构，子标题与生成规范一致。不要输出解释、评分表、Markdown 代码围栏或原始报文。

审阅重点：
- 删除无法由材料支持的账号身份、认证形式、接口行为、根因、影响和失败操作。合成标记不是登录凭证，正文不要抄出标记；材料没有真实认证凭证时，不猜 Cookie、Token 或请求头，也不建议修改它们。
- 只有状态码或响应头且正文、身份或基线缺失时，结论保持待核实；修复建议只说明要补取什么证据，不写条件式代码修复。
- SQL 测试只比较恒真和恒假常量时，只写观察到的响应差异；未测试字段条件时，不写数据读取、数据提取或数据库结构探测。
- 修复建议只保留一项证据支持的改动，不给备选方案，不猜源码路径或实现。报告使用常见中文短句，删除重复内容和内部术语。
- 测试过程最多四个主要步骤。Burp 建议只使用材料中的真实请求和已知账号条件。并发复现不能写 Repeater 的并发功能或虚构插件设置。
- 攻击链只保留证据支持的步骤。树形分支对齐，不混用竖线字符和空格缩进。CVSS 向量保持原报告数值，不擅自重新定级。

报告通过检查时也要原样返回全部字段；发现问题时只修正文，不删除有证据支持的事实，不改写平台稍后附加的原始证据。`
}

func deliveryReportMarkdownReviewSystem() string {
	return `你是渗透测试交付报告的证据审阅人。输入包含原始测试材料、待审报告和已确定的 CVSS 4.0 向量。逐句核对报告，直接改正不准确、超出证据或难以理解的内容。不要重新测试目标，也不要增加漏洞结论。

只返回 JSON 对象 {"report":"完整 Markdown 报告"}。保留原报告的标题、CVSS 向量和固定章节顺序：描述、修复建议、测试过程、攻击链路、证据说明。保留必需的三级标题。CVSS 向量必须与输入完全一致。报告中不要附加流量原文；平台会在保存后附加。

审阅规则：
- 原始请求、响应和执行记录优先于摘要。区分合成身份标记与真实认证；未验证账号身份、缺少响应正文或本人基线时，不写成已确认越权或数据泄露，也不猜测凭证或请求头。
- 只测恒真、恒假常量时，只陈述响应差异，不声称读取字段值、提取数据或判断数据库结构。并发请求没有服务端时序证据时，不声称服务端同刻执行或串行也可复现。
- 实际使用 Burp 的情况必须与材料一致。未使用时标为未验证，并给出基于真实授权账号请求的简短复测建议；并发漏洞不得建议用 Repeater 串行发送复现。非 HTTP 问题说明 Burp 不适用。
- 失败记录只写实际执行过的失败操作。修复建议只给有证据支持的一项改动；待核实线索只写需要补取的证据，不给条件式代码修复；没有源码证据时不猜路径、版本或实现。
- 用简短、自然的中文写给开发人员。删除重复解释、内部评测术语和无法复核的影响。攻击链只连接已知前提、实际操作和观察结果，并保持并列分支对齐。

若报告符合规则，仍返回完整报告。不要输出说明、审阅意见或代码围栏。`
}

func (s *Server) reviewFindingDeliveryReport(
	ctx context.Context,
	finding *db.DBFinding,
	findingID int64,
	report string,
	vector string,
	evidenceVersion int64,
) (string, error) {
	traffic, err := s.m.pg.GetFindingTraffic(ctx, findingID)
	if err != nil {
		return "", fmt.Errorf("读取报告复核证据失败：%w", err)
	}
	if traffic == nil || traffic.Version != evidenceVersion {
		return "", db.ErrEvidenceConflict
	}
	requestPacket, responsePacket, err := s.deliveryTrafficPackets(traffic.Bindings)
	if err != nil {
		return "", fmt.Errorf("读取报告复核流量失败：%w", err)
	}
	taskGoal := ""
	taskID := int64(0)
	if finding.TaskID != nil {
		taskID = *finding.TaskID
		task, err := s.m.pg.GetTask(taskID)
		if err != nil {
			return "", fmt.Errorf("读取报告任务背景失败：%w", err)
		}
		if task != nil {
			taskGoal = task.Goal
		}
	}
	if taskID <= 0 {
		taskID = agent.RunInfoFrom(ctx).TaskID
	}
	evidenceQuotes, err := json.Marshal(finding.EvidenceQuotes)
	if err != nil {
		return "", fmt.Errorf("编码报告引用证据失败：%w", err)
	}
	evidence := map[string]string{
		"task_description":         finding.TaskDescription,
		"task_goal":                taskGoal,
		"finding_name":             finding.Name,
		"vulnerability_class":      finding.VulnClass,
		"severity":                 finding.Severity,
		"summary":                  finding.Summary,
		"evidence":                 finding.Evidence,
		"evidence_quotes":          string(evidenceQuotes),
		"counterevidence":          finding.Counterevidence,
		"existing_detailed_report": finding.Report,
		"request_packet":           requestPacket,
		"response_packet":          responsePacket,
		"cvss_vector_hint":         vector,
		"evidence_transport":       "unknown",
	}
	if len(traffic.Bindings) > 0 {
		evidence["evidence_transport"] = "http"
	}
	var complete func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error)
	if taskID > 0 {
		runtime := &taskLLMRuntime{s: s, taskID: strconv.FormatInt(taskID, 10), agentKey: "reporter"}
		complete = runtime.Complete
	} else if provider, _, ok := s.agentBindingProvider("reporter"); ok {
		complete = provider.Complete
	} else if provider, _, ok := s.globalProvider(); ok {
		complete = provider.Complete
	} else {
		return "", errors.New("没有可用的 Reporter 模型，交付报告未保存")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	return reviewDeliveryReportMarkdown(ctx, evidence, report, vector, complete)
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
