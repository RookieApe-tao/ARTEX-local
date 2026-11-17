# 示例系统-业务登记 重复提交：同一编号生成多条记录

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N  评分 2.3（低危）

## 描述
同一普通用户对业务编号 `EVAL-RACE` 提交三次，生成三条不同记录。提交前为零条，提交后为三条。现有材料没有服务端处理时间，不能据此说明请求在同一时刻执行。
### 定级依据
需要已登录账号，已观察到的是重复登记和记录数增加；其他影响未验证。

## 修复建议
在数据库中为业务编号建立唯一约束。重复提交返回冲突，不再生成新记录。源码位置未核实。

## 测试过程
### 发现过程与攻击思路
2026-11-01 10:00:00（北京时间）使用 Python 3.12 并发驱动，以同一账号提交三次相同 POST。三次均返回 201，回读记录从 0 条增至 3 条，ID 不同。
### 失败尝试与未验证项
缺少 `reference` 的提交返回 400。串行重复提交、其他账号和更大并发量未测；没有请求级时间，不能确认服务端同时处理。
### Burp 复现
本次未使用 Burp Repeater。它可逐条核对重复处理，不能复现并发；并发修复应使用同步并发驱动复测。以下为单次请求模板，未发送：

```http
POST /api/registrations HTTP/1.1
Host: <授权目标域名>
Authorization: <由授权账号正常登录后捕获>
Content-Type: application/json

{"reference":"EVAL-RACE"}
```

## 攻击链路
```text
提交前基线
└─ GET /api/registrations?reference=EVAL-RACE
   └─ total=0
      ├─ 并发提交 3 次相同业务编号
      │  ├─ POST /api/registrations（第一次）
      │  │  └─ HTTP 201，id=reg-1
      │  ├─ POST /api/registrations（第二次）
      │  │  └─ HTTP 201，id=reg-2
      │  └─ POST /api/registrations（第三次）
      │     └─ HTTP 201，id=reg-3
      └─ 回读 GET /api/registrations?reference=EVAL-RACE
         └─ total=3，三条记录的 ID 不同
```

## 证据说明
材料为离线合成报文和记录，未访问真实服务。完整请求和响应按用途附在下方。
### 复测标准
并发提交相同业务编号后，系统只保留一条记录，其他请求返回既有结果或明确冲突；回读数量不得增加多条。

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
