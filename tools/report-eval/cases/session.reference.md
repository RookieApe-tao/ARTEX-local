# 示例系统-登录会话退出后仍有效：原会话继续读取用户信息

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N  评分 2.3（低危）

测试时间：2026年11月1日 10:00（北京时间）。

## 描述
用户 A 退出登录后，使用原会话立即请求 `/api/me`，仍收到 A 的用户信息；不带会话的相同请求返回 401。复现条件是攻击者已经持有该会话；会话如何被取得、退出后还能使用多久均未验证。没有测试写操作，不能据此认定可接管账号。

### 定级依据

退出后原会话仍能读取用户信息，支持已观察到的会话撤销失效；写操作和账号接管未验证。

## 修复
退出时由服务端撤销当前会话，并在后续请求中检查撤销状态。若使用自包含令牌，应采用服务端会话版本或撤销记录实现即时失效。仅删除客户端 Cookie 无法阻止原会话重放。当前会话实现和代码位置未核实。

## 测试过程

### 发现过程与攻击思路
先用原会话查询 `/api/me`，再用同一会话请求退出，随后立即重放原查询；三步依次返回用户信息、退出成功和用户信息。不带会话的查询返回 401。

Burp Repeater：完整包见文末“退出前查询”“退出登录”和“退出后重放原会话”。在授权靶场取得测试账号会话后，按上述顺序发送；退出后保留原 Cookie 重发，并以是否仍返回同一用户信息判断。Burp 实际复测未验证。最长有效时间、改密、停用、跨设备和写操作未测试。

### 失败尝试与未验证项

不带会话的请求返回 401。会话最长有效时间、改密、停用、跨设备和写操作未测试。

## 攻击链路
```text
测试人员持有用户 A 的有效会话
└─ 用户 A 退出登录
   └─ POST /api/logout
      └─ 复用原会话请求 GET /api/me，仍返回用户 A 的信息
```


## 证据说明

以下报文为离线合成材料。会话占位符不能用于真实系统；完整请求和响应按用途列在文末。

### Burp 复现

实际记录来自离线合成报文，Burp Repeater 复测未验证。按文末请求依次查询、退出，再保留原 Cookie 重放查询。

### 复测标准

修复后退出请求成功后，原 Cookie 再请求用户信息接口应返回未授权；新登录会话应仍可正常访问。

以下报文是离线合成材料。会话占位符不能用于真实系统；完整请求和响应按用途列在文末。

### 完整请求与响应

#### 退出前查询

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

#### 退出登录

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

#### 退出后重放原会话

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

#### 不带会话查询

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
