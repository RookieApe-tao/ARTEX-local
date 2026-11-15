# 示例系统-业务登记 重复提交：同一编号生成多条记录

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N  评分 2.3（低危）

## 描述
同一普通用户对业务编号 `EVAL-RACE` 提交三次，得到三个不同记录 ID。提交前查询为零条，提交后为三条。材料没有服务端处理时间，不能确认请求同时执行。

## 修复建议
服务端对业务编号实施唯一约束或幂等处理，重复请求返回已创建记录。测试生成的三条记录应清理；源码位置未核实。

## 测试过程
测试时间：2026-11-01 10:00:00（北京时间）
执行工具：Python 3.12 测试驱动脚本。发送三次相同 POST 请求，三次均返回 201；回读数量从 0 变为 3，ID 各不相同。缺少编号的请求返回 400。Burp Repeater 未实际使用；逐条重放只能核对重复提交，不能复现并发条件。失败尝试为缺少编号的请求；串行重复和更大并发量未验证。

## 攻击链路
```text
普通用户提交业务登记
└─ 三次提交相同业务编号
   └─ POST /api/registrations
      └─ 回读记录由 0 条增至 3 条，ID 不同
```

## 证据说明
来源为离线合成报文和测试记录，没有访问真实服务。完整请求与响应按用途附在下方。

**完整请求与响应**

**提交前查询**

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

**第一次并发提交**

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

**第二次并发提交**

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

**第三次并发提交**

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

**提交后查询**

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

**缺少业务编号的提交**

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
