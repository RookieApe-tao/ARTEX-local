# 示例系统-业务登记 重复提交：同一编号生成多条记录

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N  评分 2.3（低危）

测试时间：2026年11月1日 10:00（北京时间）。

## 描述
普通用户对同一业务编号并发提交三次，三次都返回成功。提交前查询为零条，提交后为三条，记录 ID 各不相同。这会让本应只登记一次的业务产生重复数据。没有服务端处理时间，不能确认三次请求是否同时执行。

### 定级依据

三次请求均生成新记录，支持重复提交导致数据重复的结论；服务端是否并行处理未验证。

## 修复
服务端按业务编号增加唯一约束或幂等处理，并发重复请求只生成一条记录，后续请求返回已有结果。仅限制前端重复点击无法阻止直接发包。源码位置未核实；测试生成的三条记录需要清理。

## 测试过程

### 发现过程与攻击思路
用同一账号先查询业务编号 `EVAL-RACE`，再由 Python 3.12 测试脚本并发发送三次相同请求，最后按相同编号查询。三次请求均返回 201；查询结果由零条变为三条。缺少业务编号的请求返回 400。串行重复提交和更大并发量未测试。

Burp Repeater：实际测试使用 Python 并发脚本，Burp 复测未验证。复测时先查询一个新的测试编号，将三条相同请求放入 Repeater 请求组并发发送，再按该编号查询；以新增记录数和不同 ID 数量确认结果，不只看状态码。文末列有查询、三次提交和缺少编号请求的完整报文。

### 失败尝试与未验证项

缺少业务编号的请求返回 400。串行重复提交和更大并发量未测试。

## 攻击链路
```text
普通用户提交业务登记
└─ 并发发送三次相同业务编号
   └─ POST /api/registrations
      └─ 查询结果由零条变为三条
```


## 证据说明

以下报文是离线合成材料，不对应真实服务。记录 ID 只用于串起样本响应；完整包按用途列在文末。

### Burp 复现

实际测试使用 Python 并发脚本，Burp Repeater 复测未验证。重放时先查询新编号的记录数，再并发发送相同提交请求，最后按相同编号回读记录数和 ID。

### 复测标准

修复后并发发送相同编号的请求，只应新增一条记录，后续响应应返回已创建结果。

### 完整请求与响应

#### 提交前查询

请求：

```http
GET /api/registrations?reference=EVAL-RACE HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Length: 0


```

响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 22

{"total":0,"items":[]}
```

#### 第一次并发提交

请求：

```http
POST /api/registrations HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Type: application/json
Content-Length: 25

{"reference":"EVAL-RACE"}
```

响应：

```http
HTTP/1.1 201 Created
Content-Type: application/json
Content-Length: 38

{"id":"reg-1","reference":"EVAL-RACE"}
```

#### 第二次并发提交

请求：

```http
POST /api/registrations HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Type: application/json
Content-Length: 25

{"reference":"EVAL-RACE"}
```

响应：

```http
HTTP/1.1 201 Created
Content-Type: application/json
Content-Length: 38

{"id":"reg-2","reference":"EVAL-RACE"}
```

#### 第三次并发提交

请求：

```http
POST /api/registrations HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Type: application/json
Content-Length: 25

{"reference":"EVAL-RACE"}
```

响应：

```http
HTTP/1.1 201 Created
Content-Type: application/json
Content-Length: 38

{"id":"reg-3","reference":"EVAL-RACE"}
```

#### 提交后查询

请求：

```http
GET /api/registrations?reference=EVAL-RACE HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Length: 0


```

响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 138

{"total":3,"items":[{"id":"reg-1","reference":"EVAL-RACE"},{"id":"reg-2","reference":"EVAL-RACE"},{"id":"reg-3","reference":"EVAL-RACE"}]}
```

#### 缺少业务编号的提交

请求：

```http
POST /api/registrations HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Type: application/json
Content-Length: 2

{}
```

响应：

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Content-Length: 30

{"error":"reference_required"}
```
