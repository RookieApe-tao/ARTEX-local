# 交付报告固定样本评测

这组材料用于检查报告写作规则，覆盖越权、注入、并发、登录会话、非 HTTP 和证据不完整六类情况。所有账号、数据、路径和报文均为合成材料；`report-eval.invalid` 不提供测试服务，也不会被访问。

`prepare`、`collect`、`review` 和 `compare` 是离线操作，不访问网络。`run-live` 只连接本机 ARTEX，将六个固定样本交给已配置的报告模型生成草稿；接口仅提交固定样本编号，不接受自定义提示词，模型请求不含工具。执行时通过终端交互输入 ARTEX 登录密码，会话令牌只保留在进程内，不写入文件或日志。

服务端评测接口需要显式设置 `ARTEX_REPORT_EVAL_ENABLED=true`，默认关闭，并继续使用 ARTEX JWT 鉴权。评测完成后应关闭此开关。每次会产生模型调用费用，输出目录包含六份模型草稿、附加的原始合成材料、token/耗时和待人工填写的评分表。

每个场景包含事实、利用条件、完整请求响应或终端材料、证据缺口、人工审阅标准和一份人工参考报告。证据不完整场景故意只留存响应头，用于检查模型是否会根据状态码补造下载成功。参考报告用于人工核对事实边界和表达方式，不进入模型输入，也不代表在真实靶场执行过 Burp 测试。CVSS 分数使用与 ARTEX 前端相同的本地算法计算。

## 使用同一模型比较改前与改后

1. 改前规则固定在 `policies/before.go`，改后规则使用 `agent/delivery_report_template.go`。`--policy-source` 只提取 Go 源码中的 `DeliveryReportWritingRules`，支持旧版原始字符串，以及新版与 `DeliveryReportRuntimeGuidance` 的常量拼接；其他表达式会被拒绝，不执行 Go 代码，不读取 ARTEX 运行配置。模型标识及生成参数必须与实际调用一致，无法确认的参数可不填，工具会标记对照可重复性受限。

   ```sh
   python3 tools/report-eval/evaluate.py prepare \
     --policy-source tools/report-eval/policies/before.go \
     --label before --model '<同一模型标识>' --temperature 0 --seed 1 --max-output-tokens 8192 \
     --output /tmp/report-eval-before
   python3 tools/report-eval/evaluate.py prepare \
     --policy-source agent/delivery_report_template.go \
     --label after --model '<同一模型标识>' --temperature 0 --seed 1 --max-output-tokens 8192 \
     --output /tmp/report-eval-after
   ```

2. 离线对照仍可在独立会话中执行 `inputs/` 的材料，并手动收集模型输出。若要用本地 ARTEX 的当前报告模型跑六例，在本地镜像已构建后，临时开启评测接口并重建容器：

   ```sh
   ARTEX_VERSION=0.3.17 ARTEX_REPORT_EVAL_ENABLED=true \
     docker compose -f docker-compose.yml -f docker-compose.local.yml up -d artex
   python3 tools/report-eval/evaluate.py run-live \
     --base-url http://127.0.0.1:8787 \
     --label after \
     --output /tmp/report-eval-after
   ```

   脚本要求输入 ARTEX 本地密码。它只连接 `localhost`、`127.0.0.1` 或 `::1`，先校验服务端和本地的固定样本编号一致，再逐例调用无工具草稿接口。模型、提示词哈希、token 和耗时会写入输出目录。单例失败会被记录，脚本继续其他样本，最后以非零状态提示未完成；`report-evaluation.json` 会标出失败项，成功样稿仍可审阅。若模型返回了无法解析的正文，原文保存在 `raw-responses/` 供排查。完成后关闭接口并重启容器：

   ```sh
   ARTEX_VERSION=0.3.17 ARTEX_REPORT_EVAL_ENABLED=false \
     docker compose -f docker-compose.yml -f docker-compose.local.yml up -d artex
   ```

   参考答案、审阅标准及证据内部编号不进入模型输入。若采用手动模型会话，则将 Markdown 输出保存后按下方步骤收集。

3. 把模型实际输出保存为 Markdown，再逐例收集。`--source model` 必须对应真实模型产出，人工整理内容使用 `--source manual`。消耗和耗时使用实际记录；未记录则省略并保持 `null`，不能填零冒充没有成本。

   ```sh
   python3 tools/report-eval/evaluate.py collect \
     --run /tmp/report-eval-after --case idor \
     --report /tmp/idor-model-output.md --model '<同一模型标识>' --source model \
     --input-tokens 3500 --output-tokens 2100 --seconds 18.2
   ```

   上述数字仅演示参数写法，实际使用时替换为真实记录。收集后会保存输出哈希；已有结果不会被覆盖。修改输出需新建评测目录，保留旧材料。

4. 按场景标准填写 `reviews/<场景>.json` 的审阅人、五项分数和具体问题。每项使用 0、1、2：0 表示存在影响交付的问题，1 表示需要修改，2 表示可直接使用。对“事实准确、容易理解、可以复现、影响边界、修复具体”逐项给出原文依据。尤其检查原始请求响应是否完整、成立条件是否保留、未验证影响是否写成事实；不能只凭报告变短给高分。

5. 输出逐例指标和对照记录：

   ```sh
   python3 tools/report-eval/evaluate.py review \
     --run /tmp/report-eval-after --output /tmp/report-eval-after-review.json
   python3 tools/report-eval/evaluate.py compare \
     --before /tmp/report-eval-before --after /tmp/report-eval-after \
     --output /tmp/report-eval-comparison.json
   ```

## 指标和验收边界

工具记录正文及全文字数、章节顺序、代码块闭合和原始材料逐字匹配结果，并展示人工评分及实际 token、耗时。原文匹配允许 CRLF 与 LF 换行差异，不会截断或重写报文。某段材料未匹配只提示需核查，不能据此自动判断漏洞结论；格式通过也不代表语言质量通过。

`compare` 检查模型、生成参数及合成材料哈希是否一致。只有两侧六例均有真实模型输出并完成人工审阅，且比较条件完整一致，才将 `comparison_complete` 标为 `true`。人工参考、空目录、未审阅输出和不同模型都不能计作完成。`run-live` 只生成改后样本，没有自动生成改前基线；这类结果可以检查改后质量，不能单独证明相对改进。

验收要求是：事实不扩大、重要条件不丢失、开发可以照步骤核对、攻击链说明业务来源与实际结果、完整材料可取得、修复针对根因。正文变短、偶尔没有内部术语或单个样本通过，都不足以证明所有报告质量稳定。评测样本随服务端二进制嵌入，接口仅在 `ARTEX_REPORT_EVAL_ENABLED=true` 时可用，不增加数据库迁移或默认 Agent 调用。

## 本地回归

```sh
python3 -m unittest discover -s tools/report-eval -p 'test_*.py'
go test ./server -run '^TestDeliveryReportScenarioCorpus$' -count=1
```

Python 回归检查参考答案隔离、输出来源、记录完整性及对照限制；Go 回归用实际保存校验检查参考报告，并核对合成 HTTP 报文长度、材料覆盖及非 HTTP 边界。两者均不调用模型，不连接真实目标，不使用运行实例凭据，不能作为真实模型效果已验证的证明。
