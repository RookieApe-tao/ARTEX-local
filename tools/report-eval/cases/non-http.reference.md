# 示例系统-备份文件权限过宽：其他本地用户可读取测试记录

CVSS 4.0：CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N  评分 4.8（中危）

## 描述
普通本地用户 `eval-user` 可读取文件所有者为 `eval-admin`、权限为 644 的 `customer-notes.txt`，并读到一行合成记录。只检查了该文件；远程访问、写入和提权未验证。
### 定级依据
需要在同一主机拥有普通本地账号；已观察到读取一份测试文件，其他系统影响未验证。

## 修复建议
将备份文件和目录权限收紧到实际需要的服务账号或用户组，并检查新生成的备份是否沿用该权限。服务代码和部署配置未检查。

## 测试过程
### 发现过程与攻击思路
在合成终端记录中，`id` 显示当前用户为 `eval-user`，`stat` 显示 `customer-notes.txt` 权限为 644，`cat` 读到一行合成记录。
### 失败尝试与未验证项
读取相邻的 `private-notes.txt` 返回 `Permission denied`。远程访问、文件写入和提权未验证。
### Burp 复现
Burp 不适用。本地复测使用授权测试账号执行 `id`、`stat` 和 `cat`，记录文件权限及实际读取结果。

## 攻击链路
```text
普通用户登录同一主机
└─ 读取权限为 644 的其他账号备份文件
   └─ cat /tmp/report-eval/backups/customer-notes.txt
      └─ 读取到文件中的合成记录
```

## 证据说明
材料来自离线合成终端记录，没有操作真实主机。完整命令和输出按用途附在下方。
### 复测标准
普通本地用户不应读取不属于其授权范围的备份文件；获授权的服务账号仍应按业务需要访问。

**完整命令与输出**

**当前用户**

```sh
id
```

退出码：0。

标准输出：

```text
uid=1002(eval-user) gid=1002(eval-user) groups=1002(eval-user)
```

**备份文件权限**

```sh
stat -c '%a %U %G %n' /tmp/report-eval/backups/customer-notes.txt
```

退出码：0。

标准输出：

```text
644 eval-admin eval-admin /tmp/report-eval/backups/customer-notes.txt
```

**读取备份**

```sh
cat /tmp/report-eval/backups/customer-notes.txt
```

退出码：0。

标准输出：

```text
EVAL_ONLY customer-a: synthetic test note
```

**读取相邻受限文件**

```sh
cat /tmp/report-eval/backups/private-notes.txt
```

退出码：1。

错误输出：

```text
cat: /tmp/report-eval/backups/private-notes.txt: Permission denied
```
