# 示例系统-备份文件权限过宽：其他本地用户可读取测试记录

CVSS 4.0：CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N  评分 4.8（中危）

测试时间：2026年11月1日 10:00（北京时间）。

## 描述
普通本地用户 `eval-user` 可以读取所有者为 `eval-admin`、权限为 644 的 `customer-notes.txt`，并读到一行合成记录。当前只检查了这个文件；远程利用、写入和提权未验证。

### 定级依据

普通本地用户能够读取其他账号拥有的备份文件，支持本地机密性影响；远程利用和提权未验证。

## 修复
备份文件限制为必要服务账号可读，例如文件权限 600、目录权限 700，并确认新生成的备份沿用该权限。服务代码和部署版本未检查；修复后需确认备份服务仍正常工作。

## 测试过程

### 发现过程与攻击思路
在合成测试主机上依次执行 `id`、`stat` 和 `cat`，确认当前用户、文件所有者及权限，并实际读出文件内容。尝试读取相邻的 `private-notes.txt` 时收到 `Permission denied`。本问题不是 HTTP，Burp Repeater 不适用。文末列有完整命令和输出。

### 失败尝试与未验证项

读取相邻的 private-notes.txt 时返回 Permission denied。远程访问、写入和提权未测试。

## 攻击链路
```text
普通用户登录同一主机
└─ 读取权限为 644 的其他账号备份文件
   └─ cat /tmp/report-eval/backups/customer-notes.txt
      └─ 读到文件中的合成记录
```


## 证据说明

以下为离线合成终端记录，没有执行真实主机操作。完整命令和输出按用途列在文末。

### Burp 复现

Burp Repeater 不适用：本问题通过本地 shell 命令复现。完整命令与输出见文末。

### 复测标准

修复后以普通本地用户重复读取目标文件应收到 Permission denied；备份服务账号仍应能读取并正常生成文件。

### 完整命令与输出

#### 当前用户

```sh
id
```

退出码：0。

标准输出：

```text
uid=1002(eval-user) gid=1002(eval-user) groups=1002(eval-user)
```

#### 备份文件权限

```sh
stat -c '%a %U %G %n' /tmp/report-eval/backups/customer-notes.txt
```

退出码：0。

标准输出：

```text
644 eval-admin eval-admin /tmp/report-eval/backups/customer-notes.txt
```

#### 读取备份

```sh
cat /tmp/report-eval/backups/customer-notes.txt
```

退出码：0。

标准输出：

```text
EVAL_ONLY customer-a: synthetic test note
```

#### 读取相邻受限文件

```sh
cat /tmp/report-eval/backups/private-notes.txt
```

退出码：1。

错误输出：

```text
cat: /tmp/report-eval/backups/private-notes.txt: Permission denied
```
