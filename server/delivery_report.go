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

只返回下列结构的 JSON 对象。六个字段都必须是字符串；不得改字段名、增加字段或输出解释文字：
{"cvss_vector":"CVSS:4.0/...","description":"描述正文","remediation":"修复建议正文","test_process":"测试过程正文","attack_chain":"树形链路正文，不带代码围栏","discovery_path":"证据说明正文"}
各字段只写章节正文，不重复二级标题，不添加三级标题。

事实顺序：完整请求/响应和命令输出；执行记录；明确列出的限制；漏洞摘要和旧报告。只写输入材料支持的内容。输入有 cvss_vector_hint 时照抄该值；有 test_time_hint 时在“测试时间：”后按“YYYY-MM-DD HH:mm:ss（北京时间）”格式写一次；没有时间记录时写“测试时间：未记录”。输入有 test_tool_hint 时照录为执行工具，没有时写“执行工具：未记录”。输入有 recorded_failures 时须写明这些失败结果。测试过程必须各有一行“测试时间：”和“执行工具：”。账号、权限、Cookie、Token 和认证头只能使用材料明确记载的内容，不要新增 user-a/user-b 或猜测会话格式。不要推断漏洞实现、未记录的测试工具或后果。

description 用短句说明漏洞、利用条件和实际结果；不要用“定级依据为”等套句。只有状态码、响应头、身份标记或不完整响应时，不得称为未鉴权接口或数据泄露。remediation 只给一项有材料支持的最小修复；证据不足以确认问题时先要求补齐证据，不给确认漏洞后的代码修复结论。重复写入优先建议唯一约束或幂等处理，不建议分布式锁。SQL 注入优先建议参数化查询，不要建议一概拒绝特殊字符。test_process 首行写“测试时间：YYYY-MM-DD HH:mm:ss（北京时间）”或“测试时间：未记录”，再写实际使用的工具与关键参数；工具名只能来自执行记录，缺失时写“执行工具：未记录”。之后写身份、操作、结果、判据、失败尝试和未验证事项。HTTP 问题须逐字写出“Burp Repeater”及实际使用状态。没用时写“Burp Repeater 未实际使用，复测未验证”，并给一条使用附加原始请求的复测建议，不能写成已执行。不得把 X-Eval-Actor 等测试标记头写成身份凭证；复测应使用授权账号的真实会话。若漏洞依赖并发，说明 Repeater 逐条重放只能核对重复处理，不能复现或确认并发；并发复测须使用执行记录中实际用过的工具，不得编造 Repeater 的多线程功能或界面控件。非 HTTP 问题说明 Burp 不适用，并给出实际命令。attack_chain 只写简短中文树形链路，不加代码围栏、text 标签、方括号标签或英文占位词；平台会添加围栏。discovery_path 简短说明材料来源、完整性和缺口；非 HTTP 问题不能声称附加了 HTTP 请求或响应。只有真假条件响应差异时，不得称为已提取或逐位读取数据。合成/离线说明集中放在证据说明中，不在每节重复。

按 evidence_transport 字段选择写法：值为 http 时，测试过程须出现“Burp Repeater”并说明实际使用状态；未使用时写“Burp Repeater 未实际使用，复测未验证”，步骤只能标成建议。值为 non-http 时，只写“Burp 不适用”，不要提 Repeater。值为 unknown 时写“协议未确认，Burp Repeater 复测未验证”，不猜协议也不提供 Repeater 操作步骤。测试标记（包括 X-Eval-Actor）不是身份凭证；不要抄写标记名或建议替换标记，也不要猜 Cookie、Token 或认证头格式。身份未验证时写未验证；真实复测时从获授权账号正常登录后捕获请求。不得编造 Repeater 功能、选项或并发能力；Repeater 串行重放不能验证并发。SQL 注入修复只建议参数化查询，不要建议转义、过滤或拒绝特殊字符。只有真假条件响应差异时，不得声称已提取、读取或推断出数据库内容。若输入标明 synthetic=true、evidence_origin 或测试未在真实目标执行，须明确说明为合成样本，未对真实目标测试；不得声称真实账号、真实数据或工具实际运行。正文不复制原始报文。

篇幅：描述最多 3 句；修复最多 3 句；测试过程不超过 5 个步骤；攻击链不超过 5 行；证据说明最多 2 句。用常见中文写作，不要重复同一事实。`
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
		return deliveryReportDraft{}, usage, &deliveryReportOutputError{
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
		return deliveryReportDraft{}, usage, &deliveryReportOutputError{
			cause: errDeliveryReportMissingBody, raw: text, stopReason: stopReason,
			contentBlockType: contentBlockTypes, outputTokens: usage.OutputTokens,
		}
	}
	draft.EvidenceVersion = evidenceVersion
	return draft, usage, nil
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
