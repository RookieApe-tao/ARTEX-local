package server

import (
	"fmt"
	"strings"

	"github.com/wpsec/ARTEX-local/agent"
)

// Fenced packets and HTML comments can contain Markdown-looking evidence. They
// must not satisfy report headings or be mistaken for our generated appendix.
func walkDeliveryMarkdown(report string, visit func(line string, offset int)) bool {
	return scanDeliveryMarkdown(report, func(line string, offset int, code bool) {
		if !code {
			visit(line, offset)
		}
	})
}

func scanDeliveryMarkdown(report string, visit func(line string, offset int, code bool)) bool {
	var fence byte
	fenceLength := 0
	inComment := false
	for offset := 0; offset < len(report); {
		end := strings.IndexByte(report[offset:], '\n')
		next := len(report)
		if end >= 0 {
			next = offset + end + 1
			end += offset
		} else {
			end = len(report)
		}
		line := strings.TrimSuffix(report[offset:end], "\r")
		start := offset
		offset = next
		if fence != 0 {
			trimmed := strings.TrimSpace(line)
			run := 0
			for run < len(trimmed) && trimmed[run] == fence {
				run++
			}
			if !deliveryIndentedCode(line) && run >= fenceLength && strings.TrimSpace(trimmed[run:]) == "" {
				fence, fenceLength = 0, 0
			} else {
				visit(line, start, true)
			}
			continue
		}
		if deliveryIndentedCode(line) && !inComment {
			visit(line, start, true)
			continue
		}
		if !inComment {
			if marker, length := deliveryOpeningFence(line); marker != 0 {
				fence, fenceLength = marker, length
				continue
			}
		}
		if !inComment && strings.TrimSpace(line) == deliveryEvidenceAppendixMarker {
			visit(line, start, false)
			continue
		}
		line = deliveryVisibleLine(line, &inComment)
		if deliveryIndentedCode(line) {
			continue
		}
		visit(line, start, false)
	}
	return fence == 0 && !inComment
}

func deliveryOpeningFence(line string) (byte, int) {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) < 3 || (trimmed[0] != '`' && trimmed[0] != '~') {
		return 0, 0
	}
	run := 1
	for run < len(trimmed) && trimmed[run] == trimmed[0] {
		run++
	}
	if run < 3 || (trimmed[0] == '`' && strings.ContainsRune(trimmed[run:], '`')) {
		return 0, 0
	}
	return trimmed[0], run
}

func deliveryIndentedCode(line string) bool {
	left := strings.TrimLeft(line, " ")
	return len(line)-len(left) >= 4 || strings.HasPrefix(left, "\t")
}

func deliveryVisibleLine(line string, inComment *bool) string {
	if !*inComment && !strings.Contains(line, "<!--") {
		return line
	}
	visible := []byte(line)
	for i := 0; i < len(line); {
		if *inComment {
			end := strings.Index(line[i:], "-->")
			next := len(line)
			if end >= 0 {
				next = i + end + 3
				*inComment = false
			}
			for j := i; j < next; j++ {
				visible[j] = ' '
			}
			i = next
			continue
		}
		if strings.HasPrefix(line[i:], "<!--") {
			*inComment = true
			continue
		}
		if line[i] == '`' {
			run := 1
			for i+run < len(line) && line[i+run] == '`' {
				run++
			}
			end := i + run
			matched := false
			for end < len(line) {
				if line[end] != '`' {
					end++
					continue
				}
				length := 1
				for end+length < len(line) && line[end+length] == '`' {
					length++
				}
				end += length
				if length == run {
					i = end
					matched = true
					break
				}
			}
			if !matched {
				i += run
			}
			continue
		}
		i++
	}
	return string(visible)
}

func deliverySectionHasContent(body string) bool {
	hasContent := false
	scanDeliveryMarkdown(body, func(line string, _ int, code bool) {
		trimmed := strings.TrimSpace(line)
		level, _ := deliveryMarkdownHeading(line)
		if trimmed != "" && trimmed != deliveryEvidenceAppendixMarker && (code || level == 0) {
			hasContent = true
		}
	})
	return hasContent
}

func deliveryMarkdownHeading(line string) (int, string) {
	line = strings.TrimSpace(line)
	level := 0
	for level < len(line) && line[level] == '#' {
		level++
	}
	if level == 0 || level == len(line) || (line[level] != ' ' && line[level] != '\t') {
		return 0, ""
	}
	text := strings.TrimSpace(line[level:])
	if suffix := strings.TrimRight(text, "#"); len(suffix) < len(text) && strings.HasSuffix(suffix, " ") {
		text = strings.TrimSpace(suffix)
	}
	return level, text
}

func deliveryAttackChainHasTree(report string) bool {
	start, end := -1, len(report)
	inAttackChain := false
	walkDeliveryMarkdown(report, func(line string, offset int) {
		level, title := deliveryMarkdownHeading(line)
		if level != 2 {
			return
		}
		if inAttackChain && end == len(report) {
			end = offset
		}
		inAttackChain = title == "攻击链路"
		if inAttackChain {
			start = offset + len(line)
		}
	})
	if start < 0 || end < start {
		return false
	}

	body := report[start:end]
	var fence byte
	fenceLength := 0
	textFence := false
	treeRoot := false
	treeBranch := false
	inComment := false
	for offset := 0; offset < len(body); {
		next := len(body)
		lineEnd := strings.IndexByte(body[offset:], '\n')
		if lineEnd >= 0 {
			next = offset + lineEnd + 1
			lineEnd += offset
		} else {
			lineEnd = len(body)
		}
		line := strings.TrimSuffix(body[offset:lineEnd], "\r")
		offset = next
		trimmed := strings.TrimSpace(line)
		if fence != 0 {
			run := 0
			for run < len(trimmed) && trimmed[run] == fence {
				run++
			}
			if !deliveryIndentedCode(line) && run >= fenceLength && strings.TrimSpace(trimmed[run:]) == "" {
				if textFence && treeRoot && treeBranch {
					return true
				}
				fence, fenceLength, textFence = 0, 0, false
				continue
			}
			if textFence {
				node := strings.TrimLeft(trimmed, "│ \t")
				branch := strings.HasPrefix(node, "├─") || strings.HasPrefix(node, "└─")
				if branch && treeRoot && strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(node, "├─"), "└─")) != "" {
					treeBranch = true
				}
				if node != "" && !branch {
					treeRoot = true
				}
			}
			continue
		}
		if deliveryIndentedCode(line) && !inComment {
			continue
		}
		line = deliveryVisibleLine(line, &inComment)
		if deliveryIndentedCode(line) {
			continue
		}
		trimmed = strings.TrimSpace(line)
		marker, length := deliveryOpeningFence(line)
		if marker == 0 {
			continue
		}
		fence, fenceLength = marker, length
		info := strings.Fields(strings.TrimSpace(trimmed[length:]))
		textFence = len(info) > 0 && info[0] == "text"
		treeRoot, treeBranch = false, false
	}
	return false
}

func validateDeliveryReportTemplate(report, expectedVector string) error {
	report = stripDeliveryTrafficEvidence(report)
	sections := strings.Split(agent.DeliveryReportSectionOrder, "、")
	requiredSubsections := map[string][]string{
		"描述":   {"定级依据"},
		"测试过程": {"发现过程与攻击思路", "失败尝试与未验证项", "Burp 复现"},
		"证据说明": {"复测标准"},
	}
	sectionIndex, bodyStart := -1, 0
	subsectionIndex, subsectionBodyStart := 0, -1
	title, cvss := false, false
	vectorOccurrences := 0
	var problem string
	finishSubsection := func(end int) {
		if problem != "" || subsectionBodyStart < 0 {
			return
		}
		if !deliverySectionHasContent(report[subsectionBodyStart:end]) {
			problem = "三级标题下的内容不能为空"
		}
	}
	finishSection := func(end int) {
		if problem != "" || sectionIndex < 0 {
			return
		}
		if !deliverySectionHasContent(report[bodyStart:end]) {
			problem = "“" + sections[sectionIndex] + "”章节为空"
			return
		}
		if subsectionIndex != len(requiredSubsections[sections[sectionIndex]]) {
			problem = "“" + sections[sectionIndex] + "”缺少必需的三级标题"
		}
	}
	closed := walkDeliveryMarkdown(report, func(line string, offset int) {
		if problem != "" {
			return
		}
		if strings.Contains(line, expectedVector) {
			vectorOccurrences++
		}
		if sectionIndex >= 0 && strings.Contains(line, "CVSS 4.0") {
			problem = "CVSS 信息只在报告头出现，不要在正文重复"
			return
		}
		level, text := deliveryMarkdownHeading(line)
		if level == 1 {
			if title || sectionIndex >= 0 || text == "" {
				problem = "只能在报告头保留一个非空一级标题"
				return
			}
			title = true
		}
		if level == 2 {
			if sectionIndex >= 0 {
				finishSubsection(offset)
				finishSection(offset)
				if problem != "" {
					return
				}
			}
			next := sectionIndex + 1
			if next >= len(sections) || text != sections[next] {
				problem = "二级标题缺失、重复或顺序错误：“" + text + "”"
				return
			}
			sectionIndex = next
			bodyStart = offset + len(line)
			subsectionIndex = 0
			subsectionBodyStart = -1
			return
		}
		if level == 3 {
			if sectionIndex < 0 {
				problem = "必需的三级标题必须放在对应章节内"
				return
			}
			finishSubsection(offset)
			if problem != "" {
				return
			}
			required := requiredSubsections[sections[sectionIndex]]
			if subsectionIndex >= len(required) || text != required[subsectionIndex] {
				problem = "三级标题缺失、重复或位置错误：“" + text + "”"
				return
			}
			subsectionIndex++
			subsectionBodyStart = offset + len(line)
			return
		}
		if level > 3 {
			problem = "报告最多使用三级标题"
			return
		}
		if sectionIndex < 0 {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "漏洞名称：") || strings.HasPrefix(trimmed, "漏洞名称:") {
				problem = "一级标题已经是漏洞名称，不要重复输出“漏洞名称”字段"
				return
			}
			if strings.HasPrefix(trimmed, "- **CVSS 4.0") || strings.HasPrefix(trimmed, "- **漏洞等级") {
				problem = "CVSS 向量、分数和等级必须合并为一行，不要重复列出"
				return
			}
			for _, prefix := range []string{"CVSS 4.0：", "CVSS 4.0:"} {
				if strings.HasPrefix(trimmed, prefix) {
					fields := strings.Fields(strings.TrimPrefix(trimmed, prefix))
					if cvss {
						problem = "CVSS 报告头重复"
						return
					}
					if len(fields) == 0 {
						problem = "CVSS 报告头缺少完整 Base 向量"
						return
					}
					vector, valid := normalizeCVSS4BaseVector(fields[0])
					if !valid || vector != expectedVector {
						problem = "CVSS 报告头无效或与 cvss_vector 参数不一致"
						return
					}
					cvss = true
				}
			}
		}
	})
	if problem == "" {
		if sectionIndex >= 0 {
			finishSubsection(len(report))
			finishSection(len(report))
		}
	}
	if problem == "" && !closed {
		problem = "代码块或 HTML 注释未闭合"
	}
	if problem == "" && (!title || !cvss) {
		problem = "报告头须包含作为漏洞名称的一级标题及一行“CVSS 4.0：”完整 Base 向量"
	}
	if problem == "" && vectorOccurrences != 1 {
		problem = "CVSS 向量只能在报告头出现一次"
	}
	if problem == "" && sectionIndex != len(sections)-1 {
		problem = "缺少必需章节"
	}
	if problem == "" && !deliverySectionHasContent(report[bodyStart:]) {
		problem = "“证据说明”章节为空"
	}
	if problem == "" && !deliveryAttackChainHasTree(report) {
		problem = "“攻击链路”必须包含 text 代码块树形链路，且有起点和带内容的分支"
	}
	if problem != "" {
		return fmt.Errorf("交付报告格式不符合固定模板：%s；二级标题必须按顺序为：%s。请保留各节，证据不足写“未验证”，补齐后重新保存", problem, strings.Join(sections, "、"))
	}
	return nil
}
