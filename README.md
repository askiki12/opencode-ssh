# opencode-ssh

OpenCode V2 插件：在 OpenCode 中维护**持久 SSH 连接**、保存**加密的 SSH profile**，并在远端机器上执行命令（支持 sudo 提权和切换用户）。

当前实现包括：**连接与维护 + 工具 + TUI 斜杠指令**。

---

## 1. 设计思路

### 1.1 为什么使用 `ssh2`，而不是每次调用系统 `ssh.exe`

Windows 自带的 OpenSSH 不支持 `ControlMaster` / `ControlPath`（依赖 Unix socket），因此无法用“系统 ssh + 连接复用”的方式实现真正的持久连接。本插件使用纯 JS 的 [`ssh2`](https://github.com/mscdex/ssh2)：

- 一个 TCP/SSH 连接长期保持，`ssh_exec` 在该连接上按需打开新的 channel；
- 支持密码、私钥、键盘交互认证、keepalive、PTY；
- 在 Windows 的 Node/OpenCode 服务进程中可直接运行；
- 连接建立后不会为每条命令重新握手，适合连续远程操作。

代价是：它不是 OpenSSH 的完整替代品，`~/.ssh/config`、`ProxyJump`、`known_hosts` 等语义需要单独实现。当前版本实现了自己的 known-hosts（SHA256 指纹）和基础的密码/私钥认证。

### 1.2 分层结构

```text
src/index.ts                  Plugin.define + setup + 注册工具
src/config.ts                 主密钥/known_hosts 目录、超时、输出上限等配置
src/crypto.ts                 AES-256-GCM 加密（SecretBox）
src/profiles.ts               profile CRUD + SQLite storage + 加密字段
src/known-hosts.ts            TOFU 主机指纹校验
src/ssh/command.ts            远端命令拼接、shell 引号、sudo 包装
src/ssh/errors.ts             执行错误码与恢复提示
src/ssh/manager.ts            持久连接池、连接/断开/执行、取消与超时
src/ssh/files.ts              SFTP 文件读写、编辑、删除、传输
src/ssh/search.ts             远端 glob/grep 与引擎回退
src/ssh/jobs.ts               远端长任务注册表与进程组停止
src/tools/definitions.ts      工具定义与返回格式化
src/rpc.ts                    TUI 与 server 之间的 RPC 契约
src/rpc-handlers.ts           RPC 实现（连接测试、profile 测试后再保存）
src/tui.ts                    TUI 斜杠指令、选择框、输入向导
AGENTS.md                     Agent 使用约定（连接复用、profile、exec、安全）
```

连接生命周期：

1. `ssh_connect` 解析 profile 或 inline 参数；
2. 解密密码 / sudo 密码，读取本地私钥；
3. 校验主机指纹；
4. 建立 SSH 连接，返回 `ssh_id`；
5. `ssh_exec` 在已有连接上开 channel 执行，命令结束 channel 关闭，连接继续保留；
6. `ssh_disconnect` 或插件卸载时关闭连接。

> 注意：持久的是 **SSH 连接**，不是交互式 shell。每条 `ssh_exec` 都是独立 channel，`cd`、`export` 等 shell 状态不会跨命令保留。需要目录和环境变量时使用 `cwd` / `env` 参数。这样设计可以安全地并发执行多条命令。

### 1.3 数据存储

**Profile 持久化**

- 使用 OpenCode 插件的 `ctx.storage`（底层 SQLite），键名为 `profiles`；
- OpenCode 会把 key 自动加上 `plugin:<插件 id>:` 前缀，因此同一插件的不同项目/location 共享同一份 profile；
- OpenCode 负责 SQLite 的初始化和持久化，插件不再创建 `profiles.json`，也不做旧文件迁移；
- 存储内容是 profile 元数据 + AES-256-GCM 密文；
- 启动时调用 `ensureInitialized()` 检查存储；如果没有记录，写入空的 profile 文档；

**本地文件**

以下文件仍放在数据目录：

- Windows：`%APPDATA%\opencode-ssh\`
- 其他平台：`$XDG_CONFIG_HOME/opencode-ssh/` 或 `~/.config/opencode-ssh/`

可通过插件选项 `dataDir` 或环境变量 `OPENCODE_SSH_HOME` 覆盖。

| 文件 | 内容 |
| --- | --- |
| `known_hosts.json` | 主机 SHA256 指纹（TOFU） |
| `master.key` | 默认主密钥（32 字节） |
| `master.salt` | 使用环境变量口令派生密钥时的 salt |

> 活跃 SSH 连接、解密后的 sudo 密码只保存在内存中；连接断开、插件卸载或服务重启后释放。

### 1.4 密码加密

- 算法：AES-256-GCM，96 位随机 IV，认证标签独立保存；
- AAD 绑定 `profile id + 字段名`，把密文从 `password` 挪到 `sudoPassword` 会解密失败；
- `password`、`privateKeyPassphrase`、`sudoPassword` 都加密保存；
- 私钥只保存**路径**，不保存私钥内容；
- 工具输出永远不返回密码，`ssh_profile_list` 只显示 `hasPassword` / `hasSudoPassword` 等布尔值。

主密钥来源，按优先级：

1. `OPENCODE_SSH_MASTER_KEY`：当作口令，经 scrypt（N=32768, r=8, p=1）派生密钥，salt 保存在 `master.salt`；
2. `OPENCODE_SSH_KEY_FILE`：指向一个密钥文件，支持 32 字节原始内容、64 位 hex、base64；
3. 默认 `master.key`：首次使用时自动生成 32 字节随机密钥。

> 威胁模型：默认的 `master.key` 与 OpenCode 的 SQLite 数据库都在本机；能同时读取两者的本机攻击者仍然可以解密。它主要防止“数据库被单独复制 / 备份泄漏 / 误发”。如果需要更强保护，请把 `OPENCODE_SSH_MASTER_KEY` 放在系统密钥管理器中，不要写入磁盘。后续可增加 Windows DPAPI / Credential Manager 支持。

### 1.5 主机指纹校验

`ssh_connect` 使用 SHA256 指纹，策略由 `host_key_policy` 控制：

| 策略 | 行为 |
| --- | --- |
| `accept-new`（默认） | 首次连接记录指纹；之后必须匹配 |
| `strict` | 未知主机直接拒绝 |
| `insecure` | 接受任意主机指纹（不推荐） |

指纹不匹配时会拒绝连接，并在错误中同时给出“已保存指纹”和“实际指纹”。确认是服务器合法换钥后，删除 `known_hosts.json` 中对应条目再连接。

注意：本插件使用独立的 `known_hosts.json`，不读取 OpenSSH 的 `~/.ssh/known_hosts`（后者可能是 hash 过的条目，解析语义复杂）。

---

## 2. 工具

工具注册在命名空间 `ssh` 下，实际名称为 `ssh_connect`、`ssh_exec` 等。

### 2.1 `ssh_connect`

建立持久连接。二选一：

- `profile_id`：使用 `ssh_profile_add` 保存的 profile；
- inline：`user` + `host` + `password` 或 `private_key_path`。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `profile_id` | string | 已保存的 profile id |
| `name` | string | inline 连接的可选显示名 |
| `user` | string | 登录用户 |
| `host` | string | 主机名或 IP |
| `port` | integer | 默认 22 |
| `password` | string | SSH 密码（inline 时仅保存在内存） |
| `private_key_path` | string | 本地 OpenSSH 私钥路径，支持 `~` |
| `private_key_passphrase` | string | 私钥口令 |
| `sudo_password` | string | 后续 sudo 使用（inline 时仅保存在内存） |
| `host_key_policy` | string | `accept-new` / `strict` / `insecure` |
| `force_new` | boolean | 默认 false：复用同一 profile 或同一 `user@host:port` 的活跃连接；只有用户明确要求新连接时才设为 true |

默认行为是**复用**：

- 传入 `profile_id` 时，只有活跃连接的 `profile_revision` 与当前 profile 一致、认证材料指纹相同，才返回原 `ssh_id`；profile 更新后旧连接会标记 `stale`，不再复用；
- inline 连接时，如果同一 `user@host:port` 已有活跃连接，并且认证材料指纹、host key policy 和 sudo 密码兼容，也返回原 `ssh_id`；
- 复用时会标记 `reused: true`，模型不应在任务结束后断开这种共享连接。

返回 `ssh_id`，例如 `ssh_1a2b3c4d5e6f`。连接阶段会通过 `progress` 上报 `resolving` / `reading-key` / `handshake` / `ready` 状态。

```json
{ "profile_id": "prof_9f8e7d6c5b4a" }
```

```json
{
  "user": "root",
  "host": "10.0.0.15",
  "port": 22,
  "private_key_path": "~/.ssh/id_ed25519",
  "sudo_password": "..."
}
```

### 2.2 `ssh_disconnect`

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `ssh_id` | string | `ssh_connect` 返回的连接 id |

### 2.3 `ssh_list`

无参数。列出活跃连接：`ssh_id`、`user@host:port`、认证方式、连接时间、空闲时间、是否 busy、最近错误；profile 连接还会显示 `revision`，profile 更新后的旧连接显示 `stale`。不会返回任何密码。

模型在 `ssh_connect` 前应先调用 `ssh_list`，如果已有相同 `user@host:port` 的连接，直接复用其 `ssh_id`，不要重复创建。

### 2.4 `ssh_exec`

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `ssh_id` | string | 连接 id |
| `command` | string | 远端命令 |
| `sudo` | boolean | 通过 sudo 执行 |
| `as_user` | string | `sudo -u <user>` 切换用户（隐含 sudo） |
| `cwd` | string | 执行前 `cd` 到该目录 |
| `env` | object | 额外环境变量（string → string） |
| `timeout_ms` | integer | 命令超时，默认 120000 |
| `tty` | boolean | 分配远端 PTY；不提供交互 stdin，写入可选 sudo 密码后关闭 |
| `non_interactive` | boolean | 可选 pager/颜色守卫；默认 false，设为 true 才会注入 |
| `max_output_bytes` | integer | stdout / stderr 各自保留的最大字节数 |

行为说明：

- 普通命令由登录用户的 shell 执行；
- 需要 sudo 时，实际命令形如：

  ```sh
  sudo -S -p '' [-u <user> -H] -- sh -c '<script>'
  ```

  密码通过 **stdin** 写入，不出现在远端进程命令行里；
- 工具不会预先校验 sudo 密码；缺失或错误密码只在执行结果中体现，详见 2.11；
- 当 sudo 报 “no tty present / a terminal is required” 时，会自动用 PTY 重试一次；
- 所有命令在写入可选 sudo 密码后立即向 stdin 发送 EOF，包括 `tty: true`；因此 `cat`、`read` 或交互提示会收到 EOF，不会一直挂起；
- `tty: true` 只分配 PTY，不是持久交互式 shell，也没有 send-stdin 工具；它适用于需要 TTY 检测/颜色但不需要持续输入的命令，一次性输入请用 shell 重定向/管道；读 `/dev/tty` 的程序仍可能需要 `timeout_ms`；
- 不默认注入 pager/颜色环境；对可能分页的命令（`git log`、`systemctl status`、`man`、`less`）设置 `non_interactive: true`，或通过 `env` 传 `PAGER=cat`、`GIT_PAGER=cat`、`SYSTEMD_PAGER=cat`、`NO_COLOR=1`、`TERM=dumb`；`env` 中的同名变量优先；
- 命令失败（非 0 退出码）**不会**抛工具错误，而是把 `exit_code`、stdout、stderr 返回给模型，由模型自行判断；
- stdout/stderr 会先清除 ANSI/OSC 控制序列，合并 `\r` 进度条和退格覆盖；
- 输出超过 `max_output_bytes` 时保留开头和结尾、省略中间，并分别报告 stdout/stderr 的原始字节、保留字节和截断状态；这比只保留前 N 字节更容易看到末尾的构建/测试错误；
- 命令执行超过约 1 秒时，通过 `progress` 上报有界的尾部输出、耗时和已接收字节；不会把每次进度都追加到最终结果；
- 工具调用被取消时，`ssh_exec` 会尽力向远端发送 `KILL` 后关闭 channel；`ssh_glob` / `ssh_grep` / `ssh_transfer` 也会响应同一个取消信号；取消是 best-effort，副作用仍按 `executionMayHaveStarted` 判断；
- 执行失败会抛出工具错误，并在 metadata 中提供 `errorCode`、`retryable`、`hint`、`recommendedNextTool`、`executionMayHaveStarted`；错误文本也会重复这些字段，方便只看到 message 的客户端（例如 Code Mode）；
- `executionMayHaveStarted=true` 表示远端命令可能已经产生副作用（超时、断线、通道无退出状态、abort）。此时不要盲目重跑 migration、删除或部署命令，应先确认远端状态；
- 连接在命令执行期间断开时，工具会直接报错（`SSH connection ... was lost while the command was running.`），不会返回含糊的 `exit_code: unknown`；
- 通道关闭但没有收到退出状态时，同样视为异常并报错，避免模型误判为成功；
- 权限拒绝仍由 OpenCode 权限系统处理，不会被包装成普通执行结果。

常见 `errorCode`：

| errorCode | retryable | executionMayHaveStarted | 建议 |
| --- | --- | --- | --- |
| `SSH_NOT_CONNECTED` | yes | no | 调 `ssh_connect` 或复用 `ssh_list` 中的连接 |
| `SSH_COMMAND_TIMEOUT` | yes | yes | 先确认远端状态；长任务改用 `ssh_job_start` |
| `SSH_CONNECTION_LOST` | yes | yes | 重连后确认远端状态再重试 |
| `SSH_CHANNEL_NO_EXIT` | yes | yes | 视为可能已执行，先核对结果 |
| `SSH_COMMAND_ABORTED` | no | yes | 调用方主动中止；先确认远端状态 |
| `SSH_CHANNEL_ERROR` | yes | 视阶段而定 | 检查连接后重试 |
| `SSH_INVALID_INPUT` | no | no | 修正参数 |
| `SSH_INTERNAL_ERROR` | no | no | 检查连接和插件状态 |

返回示例：

```text
exit_code: 0
duration_ms: 83
stdout: 181 bytes, retained 181, truncated: no
stderr: 0 bytes, retained 0, truncated: no

[stdout]
Linux web-01 6.8.0 ...
[stderr]
(empty)
```

输出被截断时会看到类似：

```text
stdout: 1048576 bytes, retained 262144, truncated: yes

[... 786432 bytes omitted; showing beginning and end ...]
```

sudo 示例（需要 profile 或连接上保存了 `sudo_password`）：

```json
{
  "ssh_id": "ssh_1a2b3c4d5e6f",
  "command": "systemctl restart nginx",
  "sudo": true
}
```

切换用户：

```json
{
  "ssh_id": "ssh_1a2b3c4d5e6f",
  "command": "whoami",
  "as_user": "postgres"
}
```

### 2.5 `ssh_profile_add`

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `name` | string | 唯一名称 |
| `user` | string | 登录用户 |
| `host` | string | 主机名或 IP |
| `port` | integer | 默认 22 |
| `password` | string | SSH 密码（与私钥二选一） |
| `private_key_path` | string | 私钥路径（与密码二选一） |
| `private_key_passphrase` | string | 私钥口令 |
| `sudo_password` | string | sudo 密码 |
| `host_key_policy` | string | 默认继承插件配置 |

返回 `profile_id`，例如 `prof_9f8e7d6c5b4a`。

> 该工具只写存储，不连接主机、不验证 sudo。`sudo_password` 为空只表示后续不发送密码，不能据此判断免密。详见 2.11。

### 2.6 `ssh_profile_update`（额外提供）

为避免改密码必须“删除再添加”，额外提供更新工具。只更新传入的字段；删除 secret 使用 `clear_*`：

`clear_password`、`clear_private_key_path`、`clear_private_key_passphrase`、`clear_sudo_password`。

`password` 和 `private_key_path` 互斥：设置其中一个会清掉另一个的认证方式。

连接相关字段变化会递增 profile revision，并把已有连接标记为 `stale`，但不会主动断开它们；详见 2.12。

### 2.7 `ssh_profile_remove`

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `profile_id` | string | 要删除的 profile |

删除 profile 不会断开已有连接；这些连接会被标记为 `stale`，已有任务可以继续。

### 2.8 `ssh_profile_list`

无参数。列出 profile 的 id、名称、`user@host:port`、认证方式、私钥路径、是否有 sudo 密码、`revision`、主机指纹策略。不会返回密码。`sudo_password=yes` 只表示存了密码，不代表密码正确；`no` 也不代表一定免密，详见 2.11。

### 2.9 远程文件工具

| 工具 | 用途 | 关键规则 |
| --- | --- | --- |
| `ssh_read` | 读取远端文件 | 默认 256KB；`offset` 是行偏移，`byte_offset` 是字节分段；二进制只报告不输出 |
| `ssh_write` | 完整写入文件 | 原子写；自动建父目录；默认**不覆盖**；拒绝 symlink；报告 line endings |
| `ssh_edit` | 精确替换文本 | 默认要求唯一匹配；支持 `expected_sha256`；返回前后 SHA-256；拒绝 symlink |
| `ssh_glob` | 按名字找文件 | 选择一个引擎：`rg` → `find` → SFTP；零结果不回退；默认跳过 `.git`、`node_modules`、隐藏项 |
| `ssh_grep` | 按内容搜索 | 远端 `rg` → `grep`；零结果不回退；默认跳过隐藏项、`.git`、`node_modules`；**没有 SFTP 逐字节兜底** |
| `ssh_remove` | 删除文件或目录 | 目录需 `recursive: true`；建议先 `dry_run: true` |
| `ssh_transfer` | 本地 ↔ 远端传输 | `upload` / `download`；覆盖需 `overwrite: true`；拒绝符号链接 |

共同约定：

- 路径必须是绝对路径或 `~/...`；相对路径直接拒绝，因为 SFTP 和 exec 不共享工作目录。
- 写、编辑、删除、传输使用路径级权限检查，resource 为 `user@host:/path`；读、glob、grep 不额外确认。
- `ssh_read` 的 `offset` 是行偏移，只在从字节 0 读取的窗口内有效；读取大文件后半部分请用 `byte_offset`，此时行号不可用。字节截断提示会给出下一个 `byte_offset`，不会误导继续增大行偏移。
- `ssh_write` / `ssh_edit` 会拒绝 symlink，避免原子替换把链接变成普通文件；需要编辑链接目标时，先解析真实路径并重新授权。`ssh_remove` 删除 symlink 时只删除链接本身，不删除目标。
- `ssh_write` / `ssh_edit` 保留 POSIX mode，但原子替换会把 inode ownership 变为 SSH 用户，ACL/xattr 不保证保留。
- `ssh_read` 会报告 `line_endings`；读取完整文件时还返回 SHA-256，可用于 `ssh_edit` 的 `expected_sha256`。分段读取时 `sha256` 为 null。
- `ssh_edit` 支持 `expected_sha256`，并在结果中返回修改前后 SHA-256。匹配是精确的：CRLF 文件需要 `old_text` 包含 `\r\n`，工具会给出提示但不会做模糊匹配。
- `ssh_write` 按字节原样写入并报告 `line_endings`；内容含 CRLF 时会警告，因为 Linux shell 脚本和 cron 条目通常要求 LF。
- `ssh_grep` 默认跳过隐藏项、`.git`、`node_modules`；需要搜索隐藏项时设置 `include_hidden: true`。
- `ssh_grep` / `ssh_glob` 依赖远端有 `rg`、`grep` 或 `find`；都没有时 `ssh_grep` 会明确报错，并提示可以用 `ssh_exec` 安装 ripgrep。
- `ssh_glob` / `ssh_grep` 每个请求只选择一个搜索器；合法零结果不会触发下一层扫描。权限、路径或命令错误会直接返回，不会静默变成“无结果”；输出被截断时 `truncated: yes`。
- `ssh_transfer` 会通过 `progress` 上报已传输字节和文件数（约 1 秒一次），最终结果只返回一次；单个文件先写临时文件再替换，失败或取消时尽力清理临时文件，目录传输仍可能留下部分已完成的子项。
- 不建议用 `ssh_exec cat` 读大文件，也不建议把大文件传到本地再搜索。

### 2.10 长任务工具

| 工具 | 用途 |
| --- | --- |
| `ssh_job_start` | 后台启动命令，立即返回 `job_id`、pid、job 目录和日志路径 |
| `ssh_job_status` | 查询单个 job；省略 `job_id` 时列出全部 job；`log_lines` 取日志尾部 |
| `ssh_job_stop` | 先 `SIGTERM`，宽限后 `SIGKILL`，按进程组终止 |

状态：

- `starting`：已创建目录，进程尚未写入 pid；
- `running`：进程存活且命令行匹配 job 目录；
- `finished`：有 `exit_code`；
- `stopped`：被 `ssh_job_stop` 终止；
- `lost`：进程消失且没有退出码（重启、OOM、外部 kill）；
- `corrupt`：目录存在但 `meta.json` 缺失。

远端布局：

```text
~/.opencode-ssh/jobs/<job_id>/
  meta.json  job.sh  pid  started_at  exit_code  stopped_at  output.log
```

使用约定：

- 长任务应使用 job，而不是把 `ssh_exec` 的 `timeout_ms` 调到几小时；
- job 跟踪的是**前台命令**；如果命令自己 `nohup` / `&` / `docker run -d`，job 会立即结束，只记录了启动器；
- 环境变量直接写在命令里：`export FOO=bar && python train.py`；
- 任务结束后用 `ssh_remove` 删除 `job_dir` 做清理；
- 只支持 POSIX 远端；
- job 的生命周期独立于工具调用和 SSH 连接；取消 `ssh_exec` 或断开连接不会停止 job。检测用 `ssh_job_status`，停止用 `ssh_job_stop`，不需要额外的 `job_kill`；
- **只跟踪宿主机进程**：容器有独立生命周期。`docker run -d` 会立刻返回，`docker exec` 不随 job 停止，停止 job 也可能留下容器；是否继续或停止容器需另外决定（`docker ps` / `docker stop`）。

### 2.11 sudo 密码的已知限制

**插件不会在保存 profile 或建立连接时校验 sudo 密码。**

- Agent 的 `ssh_profile_add` / `ssh_profile_update` 只写存储，不连接主机；
- TUI `/ssh-profile add/edit` 只测试 SSH 登录，不测试 sudo；
- `ssh_connect` 成功只代表 SSH 认证通过，不代表 sudo 可用。

`sudo_password` 的语义：

- 填了：加密保存，后续 `ssh_exec({ sudo: true })` 通过 stdin 发送；
- 没填：后续 sudo 不发送密码。这对 NOPASSWD 用户是正确的，但插件无法区分“用户免密”和“用户漏填”。

因此：

- 保存 profile 成功、`ssh_connect` 成功，都不能推断“sudo 免密”或“sudo 密码正确”；
- 密码错误或缺失，只有在真正执行 sudo 时才会暴露；
- sudo 凭据缓存期内，错误密码也可能暂时执行成功；
- `ssh_profile_list` 的 `sudo_password=yes` 只表示存了密码，不表示密码有效；`no` 也不代表一定免密。

需要确认时：

- 免密检查：`ssh_exec({ command: "sudo -k -n true" })`，退出码 0 表示无需密码（`-k` 忽略缓存）；
- 密码是否正确：直接执行实际需要的 sudo 命令，读取 `exit_code` / stderr，或向用户确认；不要根据连接结果猜测。

不自动检测的原因：保存 profile 需要支持离线配置；探测会额外建立连接、写 known_hosts、产生远端 auth 日志；NOPASSWD 和受限 sudoers 还容易误判。

### 2.12 profile revision 与过期连接

profile 有一个 `revision` 字段，只在**影响连接**的字段变化时递增：

- `password`
- `private_key_path` / `private_key_passphrase`
- `sudo_password`
- `host_key_policy`
- `user` / `host` / `port`

仅修改 profile 名称不会递增 revision。

行为：

- 连接创建时记录当时的 `profile_revision`；
- 按 `profile_id` 复用前，要求 revision 一致，并比较认证材料指纹；
- profile 更新后，旧连接被标记为 `stale`，但**不会主动断开**，正在执行的任务可以继续；
- 再次 `ssh_connect` 会创建使用新凭据/新策略的连接；
- `ssh_list` 会显示 `stale` 和 `revision`，TUI 的 `/ssh-list` 显示 `[stale]`；
- `ssh_profile_list` 会显示当前 `revision`；
- 旧连接需要时再用 `ssh_disconnect` 关闭。

inline 连接复用也会比较认证材料指纹和 host key policy：同一 `user@host:port` 但密码/私钥不同，或策略不同，不会复用旧连接。

---

## 3. 权限集成

`ssh_exec` 在真正执行前会调用 OpenCode 的权限检查：

- action：`ssh`
- resource：`user@host:port`

写、编辑、删除、传输文件的工具使用更细的粒度：

- resource：`user@host:/absolute/path`

`ssh_job_start` 和 `ssh_job_stop` 使用主机级粒度（与 `ssh_exec` 相同），`ssh_job_status` 不额外确认。

读、glob、grep 不触发额外确认。

权限拒绝仍然作为工具错误返回，不会被包装成 `ssh_exec` 的普通结果或执行 metadata；`errorCode` 等字段只描述 SSH 执行层的失败。

可以在 `opencode.json(c)` 中配置，例如生产机器执行前询问：

```jsonc
{
  "permissions": [
    { "action": "ssh", "resource": "*@prod-*", "effect": "ask" },
    { "action": "ssh", "resource": "*", "effect": "allow" }
  ]
}
```

默认基础策略是 `* / * / allow`，因此不加规则时不会额外弹窗。拒绝时工具会收到 OpenCode 的拒绝结果。

---

## 4. 安装与配置

### 4.1 安装依赖

在插件目录执行：

```sh
npm install
```

### 4.2 加载插件

推荐在 `opencode.json(c)` 中使用绝对路径或相对路径：

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": ["C:/Users/<you>/code/opencode-ssh"]
}
```

也可以在项目内使用相对路径：

```jsonc
{
  "plugins": ["./opencode-ssh"]
}
```

保存后 OpenCode 会自动重载；必要时执行 `/reload`。

### 4.3 插件选项

```jsonc
{
  "plugins": [
    {
      "package": "C:/Users/<you>/code/opencode-ssh",
      "options": {
        "dataDir": "C:/Users/<you>/AppData/Roaming/opencode-ssh",
        "idleTimeoutMs": 1800000,
        "maxOutputBytes": 262144,
        "connectTimeoutMs": 20000,
        "execTimeoutMs": 120000,
        "keepaliveIntervalMs": 15000,
        "hostKeyPolicy": "accept-new"
      }
    }
  ]
}
```

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `dataDir` | `%APPDATA%\opencode-ssh` | 主密钥和 known_hosts 所在目录；profile 存 SQLite |
| `idleTimeoutMs` | `0`（禁用） | 空闲多久自动断开 |
| `maxOutputBytes` | `262144` | stdout/stderr 各自上限 |
| `connectTimeoutMs` | `20000` | SSH 握手超时 |
| `execTimeoutMs` | `120000` | 默认命令超时 |
| `keepaliveIntervalMs` | `15000` | keepalive 间隔，0 禁用 |
| `hostKeyPolicy` | `accept-new` | 默认主机指纹策略 |

---

## 5. 使用示例

1. 保存 profile：

   ```text
   请调用 ssh_profile_add，name=prod-web，user=root，host=10.0.0.15，
   private_key_path=~/.ssh/id_ed25519，sudo_password=...
   ```

2. 连接：

   ```text
   调用 ssh_connect，profile_id=prof_...
   ```

3. 执行命令：

   ```text
   调用 ssh_exec，ssh_id=ssh_...，command="df -h"
   ```

4. sudo：

   ```text
   调用 ssh_exec，ssh_id=ssh_...，command="systemctl status nginx"，sudo=true
   ```

5. 查看连接：

   ```text
   调用 ssh_list
   ```

6. 断开：

   ```text
   调用 ssh_disconnect，ssh_id=ssh_...
   ```

### 5.1 TUI 斜杠指令

插件包含 TUI 部分，可在 OpenCode TUI 中使用：

| 指令 | 行为 |
| --- | --- |
| `/ssh-connect` | 直接打开选择框：列出 profile 和活跃连接；已连接的 profile 标记 `[active]` 并禁用（stale 连接不算 active）；也可选择“手动输入新连接”。手动连接成功后会询问是否保存为 profile。手动输入的目标如果已有非 stale 活跃连接，会询问“复用”还是“新建”。 |
| `/ssh-disconnect` | 直接打开选择框，选择并断开活跃连接。 |
| `/ssh-list` | 显示活跃连接列表，格式为 `name  user@host:port  idle=...`，stale 连接额外显示 `[stale]`。 |
| `/ssh-profile` | 打开 Profile 管理菜单：add / remove / list / edit。选择 add 时先输入 profile 名称，再逐步输入 user / host / port / 密码或私钥 / sudo 密码 / 指纹策略；先测试连接，成功后才保存。选择 edit 时可修改名称、user、host、port、密码/私钥、sudo 密码；连接相关字段变化时先测试连接，测试成功才更新，失败不修改。仅改名时可直接更新，不要求主机在线。 |

`/ssh-connect`、`/ssh-disconnect`、`/ssh-profile` 都不接受参数，执行后直接出现选择框/菜单。

`/ssh-profile add/edit` 的测试连接始终新建独立连接，不会复用已有活跃连接；测试结束后也只断开这条测试连接，不影响正在使用的连接。更新连接相关字段后，旧连接会标记为 `stale` 并继续执行已有任务，但不会用于后续复用。

Profile 的 `prof_...` 是内部 id，只用于 RPC/存储，不在列表和选择框中展示。选择 profile 时只显示名称和 `user@host:port`。

认证方式使用二选一确认框（密码 / 私钥），主机指纹策略使用确认框逐步选择，不额外要求输入框。

私钥选择会扫描 `~/.ssh`，列出 `id_*`、`*.pem`、`*.key` 以及内容包含 `PRIVATE KEY` 的文件；也可以手动输入路径。

> “私钥口令”是加密私钥文件本身的 passphrase，不是 SSH 登录密码。私钥没有口令时留空。

指纹策略含义：

- `accept-new`：首次连接记录主机指纹，之后必须匹配（默认）。
- `strict`：未知主机直接拒绝，只允许已记录指纹的主机。
- `insecure`：接受任意主机指纹，不推荐。

为避免重复，保存 profile 时会同时检查：

- profile 名称不能重复；
- 相同 `user + host + port + 认证方式` 的 profile 不能重复；私钥认证还要求私钥路径相同（`~`、相对路径会归一化后比较）。

> TUI 的文本输入框目前是普通输入框，密码会显示在终端界面上。敏感环境建议先用工具保存 profile，再通过 `/ssh-connect` 选择 profile。

---

## 6. 安全注意事项

- 不要把密码直接写在共享会话里。优先使用 profile；inline 密码只保存在内存，但聊天记录仍可能留存。
- 生产环境建议设置 `OPENCODE_SSH_MASTER_KEY`，并放在系统密钥管理器 / 启动环境中，而不是磁盘文件。
- `host_key_policy=insecure` 只用于临时测试。
- sudo 密码通过 stdin 传递，不会出现在 `ps` 的命令行参数中，但拥有远端 root 权限的人仍可能读取进程内存。
- 当前不保存私钥内容，只保存路径；请确保私钥文件权限正确。
- 插件进程拥有本机网络和文件权限，权限规则只能约束工具调用，不能替代操作系统隔离。
- TUI 的密码输入框目前不掩码，密码会显示在终端界面上；敏感环境建议用工具保存 profile。

---

## 7. 当前限制与后续计划

当前限制：

- 远端命令按 **POSIX shell（Linux/Unix）** 设计；连接 Windows 远端时，`cwd` / `env` / `sudo` 的包装命令不可用，仅建议执行简单命令；
- 本地 Windows 完全支持：使用 `ssh2` 纯 JS 实现，不依赖 WSL 或 OpenSSH 的 ControlMaster；
- 斜杠指令只在 OpenCode TUI 中注册，Web/GUI/Discord 等客户端未接入；
- TUI 密码输入框不掩码；
- TUI 部分基于 `@opencode/plugin` 2.2.7 的类型开发，运行环境版本差异需要实际验证；
- sudo 密码脱敏只对长度 ≥ 4 的密码生效，极短密码在 PTY 回显场景仍有风险；
- 不支持 SSH agent（Pageant / ssh-agent）、ProxyJump、端口转发；SFTP 仅实现文件读取/写入/编辑/删除/传输，不是完整的 OpenSSH SFTP 客户端；
- 不支持 OTP / 2FA 的多轮 keyboard-interactive（当前把密码用于所有 prompt）；
- 不读取 OpenSSH `~/.ssh/config` 和 `known_hosts`；
- 每条 `ssh_exec` 是独立 channel，shell 状态不持久；
- 同一私钥的口令目前只能在重新选择私钥时更新；
- `known_hosts` 仍是本地 JSON 文件，未迁移到 SQLite；
- RPC 是插件内部契约，暂未做跨版本兼容保证。

后续方向：

1. profile 导出/导入（包含加密数据或重新加密）。
2. 将 `known_hosts` 也迁移到 `ctx.storage`。
3. 增加按命令内容的权限规则，而不仅是 `user@host:port`。
4. 支持 SSH agent、ProxyJump、端口转发。
5. 评估持久交互式 shell。
6. 为 TUI 增加掩码密码输入或自定义安全表单。
7. 增加密码脱敏、无 TTY 重试等边界场景的自动化测试。

---

## 8. 开发与检查

```sh
npm run typecheck
npm run test:smoke
npm run test:tui
```

- `test:smoke` 会在本机启动临时 SSH 测试服务，覆盖加密、profile 生命周期、known-hosts、连接、执行、sudo 包装、工具层，以及基于假 SFTP 的远程文件读写/编辑/删除/传输。
- `test:tui` 使用 mock 的 dialog/RPC 覆盖 TUI 指令注册、连接选择、profile 新增/改名、编辑失败、disconnect 和 remove 流程。
- 真实 OpenCode 联调还需验证：TUI 选择框、私钥列表、连接测试后再保存、RPC 跨 location 行为。
- 开发进度和待办记录在 `TODO.md`。

联调时，将插件目录加入 `opencode.json`，然后在 OpenCode 中调用工具或 TUI 指令。建议先用测试机验证：密码登录、私钥登录、sudo、切换用户、主机指纹不匹配、断线重连。
