# 示例系统-附件下载 访问控制待核实：缺少响应正文，无法确认越权

CVSS 4.0：CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N  评分 0.0（无）

## 描述
用户 B 请求用户 A 的文件编号，留存响应头显示 HTTP 200，但没有响应正文、A 的文件基线或账号权限证明。现有材料不能确认服务端是否返回了文件，不能据此认定越权下载。

## 修复建议
先取得完整响应、用户 A 的文件基线和账号权限证据。若确认 B 能读取 A 的文件，再修复下载接口的文件授权校验；当前没有证据支持具体源码位置。

## 测试过程
测试时间：2026-11-01 10:00:00（北京时间）
执行工具：未记录。现有记录只有 B 请求文件编号和 HTTP 200 响应头，未取得正文、文件基线或权限证明。Burp Repeater 未实际使用；补测时先以 A 下载基线，再以 B 使用各自正常登录后捕获的请求核对完整响应正文或哈希。失败尝试记录未提供；下载结果未验证。

## 攻击链路
```text
用户 B 请求用户 A 的文件编号
└─ GET /api/files/file-a/download
   └─ 只留存 HTTP 200 响应头，正文未取得
```

## 证据说明
来源为离线合成材料。下方保留完整请求和已留存响应头；响应正文缺失，不能根据长度推测内容。

**完整请求与响应**

此例响应仅留存头部，48 字节正文未取得。不能根据 Content-Length 推测正文。

**请求他人文件**

请求：

```http
GET /api/files/file-a/download HTTP/1.1
Host: report-eval.invalid
X-Eval-Actor: user-b
Content-Length: 0


```

响应头，正文未取得：

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 48


```
