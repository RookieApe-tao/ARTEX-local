import { scoreCVSS4Base } from "./cvss-v4";

const metadataPatterns = [
  /^漏洞名称[：:].*$/,
  /^- \*\*CVSS 4\.0 Base 向量（CVSS-B）\*\*：.*$/,
  /^- \*\*CVSS 4\.0 评分\*\*：.*$/,
  /^- \*\*漏洞等级\*\*：.*$/,
  /^CVSS 4\.0[：:].*$/,
];

export function applyCVSSMetadata(content: string, vector: string): string {
  if (!vector || !content.trim()) return content;
  const score = scoreCVSS4Base(vector);
  const scoreText = score ? score.score.toFixed(1) : "待计算";
  const severity = score ? score.severity : "待计算";
  const singleLine = `CVSS 4.0：${vector}  评分 ${scoreText}（${severity}）`;
  const lines = content.split("\n");
  const metadata = new Set<number>();
  let bodyStart = lines.length;
  let fence = "";

  // 只整理报告头，避免把代码块中的报文内容当成重复字段。
  for (const [index, line] of lines.entries()) {
    const fenceMatch = /^\s*(`{3,}|~{3,})(.*)$/.exec(line);
    if (fenceMatch) {
      const marker = fenceMatch[1];
      if (!fence) fence = marker;
      else if (marker[0] === fence[0] && marker.length >= fence.length && !fenceMatch[2].trim()) fence = "";
      continue;
    }
    if (fence) continue;
    if (/^ {0,3}##(?:\s|$)/.test(line)) {
      bodyStart = index;
      break;
    }
    if (metadataPatterns.some((pattern) => pattern.test(line.replace(/\r$/, "")))) metadata.add(index);
  }

  const header = lines.slice(0, bodyStart).filter((_, index) => !metadata.has(index));
  while (header.length && !header[0].trim()) header.shift();
  while (header.length && !header[header.length - 1].trim()) header.pop();
  const cleanedTitleIndex = header.findIndex((line) => /^ {0,3}#\s+/.test(line));
  let normalizedHeader: string[];
  if (cleanedTitleIndex >= 0) {
    const title = header.slice(0, cleanedTitleIndex + 1);
    const details = header.slice(cleanedTitleIndex + 1);
    normalizedHeader = [...title, "", singleLine];
    if (details.length) normalizedHeader.push("", ...details);
  } else {
    normalizedHeader = [singleLine, ...header];
  }
  const body = lines.slice(bodyStart);
  if (body.length) normalizedHeader.push("");
  return [...normalizedHeader, ...body].join("\n");
}
