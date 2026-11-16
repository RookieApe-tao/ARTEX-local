package agent

// The order is shared with save validation so generated and accepted reports agree.
const DeliveryReportSectionOrder = "描述、修复建议、测试过程、攻击链路、证据说明"

const DeliveryReportSaveGuidance = "以下结构和写作要求只适用于交付报告字段；详细报告仍保留原有章节和完整台账。交付报告须包含一个漏洞名称标题、一行 CVSS 4.0 信息，并按顺序使用二级标题：" + DeliveryReportSectionOrder + "。描述含“定级依据”；测试过程含“发现过程与攻击思路”“失败尝试与未验证项”“Burp 复现”；证据说明含“复测标准”。正文尽量简短，通常不超过 800 字；复杂案例可超过，不得删掉关键证据来凑长度。测试时间按记录换算为北京时间，缺失时写“未记录”。HTTP 问题说明 Burp Repeater 的实际使用情况或复测步骤。ARTEX 会附加完整原始请求和响应，不要在正文重复转述。"

// Injected for every agent that has permission to save reports, including
// agents with user-edited prompts. The tool schema and report write flow stay stable.
const DeliveryReportRuntimeGuidance = `

以下事实与写作要求仅适用于交付报告字段，不改变详细报告的章节和台账。先核对原始请求/响应、命令输出和执行记录；它们优先于摘要。只写材料支持的身份、权限、操作、次数和结果，缺项写“未验证”，不补造。
状态码或响应头不能证明响应正文已返回；没有看到实际数据，不写成已读取。漏洞名称和 CVSS 向量也不能代替影响证据。材料标明为合成或演示时，不写成真实系统或真实数据；不要把占位主机、身份、Cookie 或 Token 改成真实测试条件。
测试过程首行写测试时间并标注北京时间。优先使用执行记录；test_time_hint 若注明“首条证据请求采集时间”，必须保留这个说明，不能称为漏洞首次发现时间或完整测试时段。evidence_time_index 只用于说明对应请求的采集时间。没有可靠记录时写“测试时间：未记录”，不能用报告生成时间替代。影响顺序的时间才在对应步骤保留到秒。
修复建议只写一项与已确认行为相符的主要措施，不猜源码、版本或实现，不罗列替代方案。行为或根因未确认时不下代码修复结论，只说明需要补什么证据。
HTTP 报告必须有 Burp Repeater 小节。实际使用过才写实际操作；未使用则明确说明，并给一条简短复测方法。真实复测使用各账号实际登录后捕获的请求；不得让人替换 Host、认证头或样本占位值。合成样本不能直接重放，也不能写成已测试。Repeater 串行重放不能证明并发。非 HTTP 问题说明 Burp 不适用。失败尝试只写实际做过且失败的操作；其他未测项简短列出。
正文写给开发看，删掉内部流程词、重复解释和不影响复现的扩展分析。不要把交付报告的精简要求套到详细报告。保存前在本次输出中核对结论、限制、修复和链路，不增加模型调用。`

const DeliveryReportChainGuidance = `

攻击链只画一棵树。根节点写材料中实际的页面或功能入口；没有页面记录时，以首个请求或命令为根，不写“Root”等空泛词。HTTP 请求的 METHOD/path 必须逐字复制 request_line_index，保留百分号编码，不补造。每个请求或命令的结果缩进在该节点下。按材料区分顺序、独立操作和并发；前后查询按时间顺序展示，不能把回读塞进并发组。相同请求只有证据明确时才合并并标次数；多条请求不等于并发。响应只留状态码和关键结果，不抄完整正文。`

const DeliveryReportEvidenceGuidance = `

不能只凭漏洞名称推断根因、利用能力或影响范围。响应差异只证明差异；缺少响应正文、账号权限或前后状态时，说明缺口。合成内容不能说成真实敏感数据。没有源码、配置或服务端日志时，不把“SQL 直接拼接”“缺少唯一约束”“会话固定”等写成已查明的根因。修复只给一项主要措施，不用“或”“也可”罗列方案；证据不支持代码根因时，只说明待补证内容。`

const DeliveryReportStyleGuidance = `

用常见中文短句，正文以 800 字以内为目标，不硬截断。描述两三句，定级依据一句，修复一句。发现过程写测试时间和最多四步；失败与未验证项最多两条；Burp 复现最多两句；证据说明和复测标准各一句。攻击链只放必要入口、请求和结果。每节不重复其他章节；保留复现所需的路径、关键结果、成立条件和未验证边界。不要写证据没有记载的工具、参数、时间或操作。`
const DeliveryReportWritingRules = DeliveryReportRuntimeGuidance + DeliveryReportChainGuidance + DeliveryReportEvidenceGuidance + DeliveryReportStyleGuidance + `

报告头只保留一个一级标题和一行 CVSS 4.0 信息：
# 系统或模块 功能或接口 缺陷：实际后果
CVSS 4.0：完整 Base 向量 评分 分数（等级）
一级标题就是漏洞名称，不再另写“漏洞名称”。CVSS 向量、分数和等级须作为一组保持一致，并与保存参数一致。已有定级时，定级依据只解释材料支持的权限和影响，不得另行给出冲突的危害等级；发现向量、分数或等级互相矛盾时，标明需人工复核，不自行改分。向量不能作为影响已发生的证据。

二级标题固定为以下五节，顺序不可改变：

## 描述
用一段话写清问题、成立条件和观察结果。未验证影响明确标出。
### 定级依据
一两句说明权限条件和已观察影响，不逐项解释 CVSS 向量，不夸大影响。

## 修复建议
写一项具体修复及预期行为，不罗列备选实现。线索未确认时先补证，不给条件式代码修复。无源码证据不猜路径或代码实现。

## 测试过程
### 发现过程与攻击思路
按顺序写最短复现步骤、关键请求或命令和判据，开头第一行必须写“测试时间：”并按上述规则注明。
### 失败尝试与未验证项
只列实际失败及影响结论的未验证边界；没有失败记录时不要编造。
### Burp 复现
说明是否实际使用 Burp Repeater。未使用时明确未实际发送，并给基于平台附加请求的简短复测步骤。合成材料不能直接重放，说明需在授权目标重新登录并捕获真实请求；不得要求将样本占位值替换成真实值。并发问题说明 Repeater 串行重放不能证明并发；非 HTTP 问题说明 Burp 不适用。

## 攻击链路
只连接有证据的页面、请求、命令和结果，按统一链路规则绘制。材料没有请求行时写“请求路径未记录”，不补造。由平台添加 text 代码围栏。
## 证据说明
简短说明来源、完整性和缺口。完整绑定报文由平台原样附加；平台外材料只有完整留存时才引用。
### 复测标准
写修复后可实际观察的最小判据，不把建议步骤写成已完成结果。

保存前最后检查：身份和结论能否定位到证据；缺失内容是否写成了已观察结果；修复是否对应已确认的行为；CVSS 影响项是否有依据；攻击链是否按实际顺序连接。存在问题时在本次输出中改正，不增加模型调用。`

// Structured draft generation has a JSON contract, while Reporter writes a
// complete Markdown report. Keeping those formats separate avoids competing
// output instructions in the same system prompt.
const DeliveryReportDraftRules = DeliveryReportRuntimeGuidance + DeliveryReportChainGuidance + DeliveryReportEvidenceGuidance + DeliveryReportStyleGuidance + `

本次只生成交付报告草稿，不调用工具。平台生成标题、CVSS 行、五节标题和原始报文附件。只返回这个 JSON 对象，不加 Markdown 围栏或解释；字段值均为非空字符串：
{"cvss_vector":"","description":"","remediation":"","test_process":"","attack_chain":"","discovery_path":""}
description 先用两三句写问题、成立条件和观察结果，再依次包含“### 定级依据”和一两句评分依据。test_process 依次包含“### 发现过程与攻击思路”“### 失败尝试与未验证项”“### Burp 复现”，每节都用短句；发现过程第一行必须为“测试时间：<test_time_hint>”，test_time_hint 为“测试时间未记录”时写“测试时间：未记录”。没有失败记录时简短注明。discovery_path 包含“### 复测标准”和一句可判定的复测条件。
cvss_vector 优先使用输入提供的有效向量；若没有有效向量，则按已验证条件和影响填写。影响项与实际证据不符时，在定级依据中标明评分前提需复核，不声称潜在影响已经发生。
attack_chain 只写一棵短树。根节点使用实际页面或功能入口；没有页面记录时以首个请求或命令为根。其余每一行以 ├─ 或 └─ 开始。生成前读取 request_line_index：HTTP 节点原样复制 METHOD/path，不解码，不补造。请求或命令的结果缩进在对应节点下；顺序、独立和并发关系按材料表达。平台会添加 text 代码围栏，完整报文由平台附加。
`
