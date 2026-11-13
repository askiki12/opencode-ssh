# TODO

开发过程记录，只用于跟踪进度和待办。功能说明见 `README.md`，Agent 约定见 `AGENTS.md`。

维护规则：

- 完成一项就移到底部“已完成”，保留简短说明和日期。
- 新增待办写清“问题现象 + 预期行为”，避免只写标题。
- 不要在这里重复 README 的工具参数和用法。

---

## 待办

### P1

- [ ] **补充真实服务器回归**
  - 现有 `scripts/smoke.ts`、`scripts/tui-smoke.ts` 都基于本地 ssh2 测试服务器。
  - 已在真实 Linux 主机（root + 私钥）手工验证：
    - 基础执行、`cwd`、`env`、非 0 退出码、大输出截断与调大上限
    - `sudo: true`（root 免密场景）、profile 复用、`force_new`
    - 失效 `ssh_id` 报 `No active SSH connection`
    - 执行中断线报 `SSH connection ... was lost while the command was running.`
    - 后台 job 模式（`nohup ... &` + `ps` + 日志）可用
    - 密码认证（同一主机的 password profile）连接和执行正常
  - 仍缺：
    - 非 root 用户的真实 sudo 密码（含密码错误提示）
    - 主机指纹不匹配 / `strict` 拒绝首次连接的真实场景
    - 长时间大流量命令（如几百 MB 输出）
  - 这些用例应沉淀成可选的真实主机测试脚本，而不是依赖手工。

### P2（低优先级）

- [ ] **`fleet_exec`：多机并发执行**
  - 价值：一次调用替代 N 次工具调用；并发上限、`stop_on_error`、rolling 分批、每台独立结果；按 tag 选择可减少提示体积。
  - 前置：profile 目前没有 tag/分组，需要扩展数据模型和 UI。
  - 最小版本：`profile_ids[] + parallel + stop_on_error`，不做 tag/rolling。
  - 只有机器数量上来（>5）或需要统一审计时才值得做；当前用现有工具循环即可。

- [ ] **profile tags 与批量文件传输**
  - 现状：`ssh_exec` / `ssh_transfer` 都是单机工具，必须逐个指定 `profile_id`；12 台以内可以用命名约定 + 循环解决。
  - tags 本身只是选择器，单独增加不会减少工具调用；需要和 `fleet_exec` / `fleet_transfer` 配套才有价值。
  - 最小路径：先做 `fleet_exec` 的 `profile_ids[]`，再做 tags；文件批量传输需要独立的 `fleet_transfer`。
  - 批量操作还需定义每台权限、部分失败、重试和清理语义；只有分组操作频繁或机器数量明显增加时才值得做。

- [ ] **`ssh_patch`（统一 diff 应用）**
  - 需要远端有 `patch` 或 `git apply`；建议先 `--dry-run` 再执行。
  - 先观察 `ssh_edit` 是否够用，再决定是否值得新增工具。

- [ ] **`ssh_transfer` 增强**
  - 断点续传、远端到远端传输、传输进度。
  - 需要新的状态存储和更多测试，暂不做。

### P3（最低）

- [ ] **SSH agent 支持**
  - 目前只能用私钥文件 + 口令，密码和私钥都由插件自己管理。
  - 预期：Windows 上支持 Pageant / OpenSSH agent，避免把私钥路径和口令交给插件。
  - 属于能力扩展，不是稳定性修复；认证失败多时再考虑。

- [ ] **ProxyJump（跳板机）**
  - 目前只能直连目标主机，内网机器必须先手工转发或登录跳板机。
  - 预期：`proxy_jump` 参数或 profile 字段，经跳板机建立隧道。
  - 只对“直连不到”的机器有意义，按需求再加。

- [ ] **端口转发 / 隧道**
  - 目前不支持本地转发、远程转发和动态转发。
  - 与“执行命令”是两类需求，优先级最低。

- [ ] **`known_hosts` 从本地 JSON 迁移到 SQLite**
  - 当前 `known_hosts.json` 由 `src/known-hosts.ts` 直接读写文件。
  - profile 已经走 `ctx.storage`，主机指纹仍是独立 JSON，换机器时两份数据要分别处理。
  - 预期：改用 `ctx.storage` 的 key（如 `knownHosts`），保留现有 TOFU 校验逻辑；需要一次性迁移读取旧 JSON，读取成功后再删除或改名备份。
  - 不做也可以：功能正常，只是数据分散在两处。

- [ ] **auth 和 host-key 选择确认框改进**
  - 现状：认证方式用一次“密码 / 私钥”确认框；host-key 策略先用“accept-new / 其他”、再用“strict / insecure”两次确认，不是一次完整单选。
  - 问题：用户需要连续确认两次，选项没有一次展示完整，容易误选，也不符合“选择只走确认框”的交互目标。
  - 预期：用一个自定义单选对话框（或一次展示完整选项的 JSX 对话框），认证方式一次选择“密码 / 私钥”，host-key 一次选择 `accept-new` / `strict` / `insecure`。
  - 原因：不能直接用现有 select，因为它带过滤输入；用户不希望选择策略还要打字。

- [ ] **`idleTimeoutMs` 默认 0 的取舍**
  - 当前空闲连接不会自动断开，直到 OpenCode 退出。
  - 需要决定：保持默认不断开，还是给一个默认值（例如 30 分钟）并写进 README 选项表。

- [ ] **profile 活跃状态是快照**
  - `/ssh-connect`、`/ssh-profile` 的 `[active]` 只在打开菜单时计算一次。
  - 菜单打开期间 agent 或其他窗口连接/断开，显示不会更新。
  - 影响仅为显示层，实际连接由 `ConnectionManager` 复用兜底。

---

## 已完成

- 2026-11：7 个工具（connect / disconnect / list / exec / profile_add / profile_update / profile_remove / profile_list）实现完毕。
- 2026-11：profile 迁移到 `ctx.storage`（SQLite），移除 `profiles.json`。
- 2026-11：密码、私钥口令、sudo 密码使用 AES-256-GCM 加密；活跃连接和 sudo 密码仅保存在内存。
- 2026-11：TOFU 主机指纹校验（`known_hosts.json`）。
- 2026-11：TUI 斜杠指令与 RPC 打通，修复 `[object Object]` 错误显示。
- 2026-11：连接默认复用（同 profile 或同 `user@host:port`），新增 `force_new`，复用结果标记 `reused: true`。
- 2026-11：工具描述补充“先 `ssh_list`、优先复用”；新增 `AGENTS.md`。
- 2026-11：删除 `/ssh-connect-list` 和 `/ssh-profile-*` 别名；精简手动连接提示和 profile 展示。
- 2026-11：`ssh_exec` 执行期间连接断开或通道无退出状态时明确报错，不再返回 `exit_code: unknown`。
- 2026-11-13：真实 Linux 主机（root）手工回归通过：私钥与密码两种认证、基础执行、`cwd`/`env`、非 0 退出码、输出截断、sudo、profile 复用、`force_new`、失效 `ssh_id`、执行中断线报错、后台 job 模式。
- 2026-11-13：新增远程文件工具 `ssh_read` / `ssh_write` / `ssh_edit` / `ssh_glob` / `ssh_grep` / `ssh_remove` / `ssh_transfer`；每条连接复用 SFTP session；写/编辑采用临时文件 + 原子替换，并处理 OpenSSH SFTP v3 不允许覆盖 rename 的问题（posix-rename 扩展 + 备份回滚兜底）。
- 2026-11-13：文件工具在真实主机验证通过：读写、唯一匹配与歧义拒绝、覆盖保护、`glob`（find 回退）、`grep`（grep 回退）、二进制检测、截断、删除 `dry_run`/实际删除、上传下载。
- 2026-11-13：新增长任务工具 `ssh_job_start` / `ssh_job_status` / `ssh_job_stop`：远端 `~/.opencode-ssh/jobs/<job_id>/` 为唯一状态源，`setsid` + 进程组终止，`stopped_at` 标记，支持列表与日志尾部。真实主机验证：启动 400ms 返回、运行/完成/停止状态、退出码、日志、清理。Docker 容器不会随 job 停止（已记录限制）。
- 2026-11：`npm run typecheck`、`npm run test:smoke`、`npm run test:tui` 通过。
- 2026-11-13：TUI 调试日志不再硬编码项目路径：`OPENCODE_SSH_TUI_DEBUG=1` 写入插件数据目录（`OPENCODE_SSH_HOME` 或平台默认目录）下的 `tui-debug.log`，设为其他值则按路径写入。
- 2026-11-13：Docker 容器级跟踪不作为工具功能：job 只跟踪宿主机进程，容器生命周期由 `docker ps` / `docker stop` 单独决定，工具描述、README、AGENTS.md 已划定职责。
- 2026-11-13：TUI 完整重启后回归验证通过：`/ssh-connect`、`/ssh-disconnect`、`/ssh-list`、`/ssh-profile` 可用；auth 和 host-key 只走确认框；手动连接重复目标可选择“复用 / 新建”；profile 只显示名称和 `user@host:port`。
- 2026-11-13：在工具描述、AGENTS.md、README 中明确 sudo 事实：保存 profile / 连接成功不校验 sudo，`sudo_password` 缺失不等于免密，密码错误只在执行 sudo 时暴露。
- 2026-11-13：`ssh_exec` 输出改为有界清洗 + 头尾保留：清除 ANSI/OSC，合并 `\r`/退格，分别报告 stdout/stderr 原始字节、保留字节和截断状态。
- 2026-11-13：`ssh_exec` 提供可选 pager/颜色守卫（`non_interactive: true` 注入 `PAGER`/`GIT_PAGER`/`SYSTEMD_PAGER=cat`、`NO_COLOR=1`、`TERM=dumb`）；默认不注入，保持原命令语义，工具描述提醒按需使用。
- 2026-11-13：`ssh_exec` 失败增加结构化 metadata：`errorCode`、`retryable`、`hint`、`recommendedNextTool`、`executionMayHaveStarted`；权限拒绝仍保持工具错误。
- 2026-11-13：`ssh_exec`、`ssh_connect`、`ssh_transfer` 增加有界进度上报（约 1 秒一次），最终结果只返回一次。
- 2026-11-13：修复 profile add/edit 和 connection test 复用活跃连接的问题：测试连接强制 `forceNew`，只断开测试连接；避免新密码未被验证却保存，以及误断正在使用的连接。
- 2026-11-13：profile 增加 `revision`：仅连接相关字段变化时递增；连接记录创建时的 revision 和认证指纹，复用前必须匹配；更新后旧连接标记 `stale` 但不中断，后续连接使用新凭据。
- 2026-11-13：修复 `ssh_read` 大文件分段语义：新增 `byte_offset` 真字节分段，返回 byte range 和 `lineNumbers`；行 offset 超出已捕获前缀时明确报错并提示下一段 `byte_offset`。
- 2026-11-13：修复 `ssh_glob` / `ssh_grep` 扫描回退：每个请求只选一个引擎，合法零结果不回退；权限/路径/命令错误直接返回；输出截断传递到 `truncated`；`find` 用 `-prune` 跳过忽略目录；rg grep 排除 `.git` / `node_modules`。
- 2026-11-13：明确 `tty` 职责并统一 EOF：`tty:true` 只分配 PTY，不提供交互 stdin；所有命令写入 sudo 密码后立即关闭 stdin，避免 `cat`/`read`/输入提示挂到超时；工具描述、AGENTS、README 已限制其使用范围。
- 2026-11-13：统一取消信号：`ssh_exec` abort 时发送远端 `KILL`；`ssh_glob` / `ssh_grep` 传递 AbortSignal；`ssh_transfer` 支持 signal、单文件临时文件 + 原子替换并在失败/取消时尽力清理。job 生命周期保持独立，不新增 `job_kill`。
- 2026-11-13：`ssh_grep` 默认跳过隐藏项、`.git`、`node_modules`，新增 `include_hidden`；`ssh_write` / `ssh_edit` 拒绝 symlink，说明 mode/ownership/ACL/xattr 限制；`ssh_edit` 增加前后 SHA-256、`expected_sha256` 和 CRLF 精确匹配提示；`ssh_write` / `ssh_edit`、`ssh_read` 报告 line endings，CRLF 时警告。
- 2026-11-13：文档与工具描述对齐：补齐 files/search/jobs/errors 分层、移除“不支持 SFTP”的过期限制、补齐 profile revision/stale、job 状态与 no job_kill、tty/pager/取消/读文件 hash/line endings 等风险提示；TUI 手动连接不再复用 stale 连接。
- 2026-11-13：连接错误归一化：`ENOTFOUND` / `ECONNREFUSED` / `ETIMEDOUT` / unreachable / reset / 认证失败带 `user@host:port` 和恢复提示；host key mismatch 和私钥读取错误保持专用提示。
