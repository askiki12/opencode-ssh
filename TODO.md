# TODO

开发过程记录，只用于跟踪进度和待办。功能说明见 `README.md`，Agent 约定见 `AGENTS.md`。

维护规则：

- 完成一项就移到底部“已完成”，保留简短说明和日期。
- 新增待办写清“问题现象 + 预期行为”，避免只写标题。
- 不要在这里重复 README 的工具参数和用法。

---

## 进行中

- [ ] **TUI 完整重启后回归验证**
  - 必须完全退出 OpenCode TUI 再启动，`/reload` 不够。
  - 验证 `/ssh-connect`、`/ssh-disconnect`、`/ssh-list`、`/ssh-profile`。
  - 重点看：auth 和 host-key 选择只走确认框、不出现文本框；手动连接重复目标时的“复用 / 新建”；profile 只显示名称和 `user@host:port`。

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

- [ ] **`idleTimeoutMs` 默认 0 的取舍**
  - 当前空闲连接不会自动断开，直到 OpenCode 退出。
  - 需要决定：保持默认不断开，还是给一个默认值（例如 30 分钟）并写进 README 选项表。

- [ ] **profile 活跃状态是快照**
  - `/ssh-connect`、`/ssh-profile` 的 `[active]` 只在打开菜单时计算一次。
  - 菜单打开期间 agent 或其他窗口连接/断开，显示不会更新。
  - 影响仅为显示层，实际连接由 `ConnectionManager` 复用兜底。

### P2（低优先级）

- [ ] **`fleet_exec`：多机并发执行**
  - 价值：一次调用替代 N 次工具调用；并发上限、`stop_on_error`、rolling 分批、每台独立结果；按 tag 选择可减少提示体积。
  - 前置：profile 目前没有 tag/分组，需要扩展数据模型和 UI。
  - 最小版本：`profile_ids[] + parallel + stop_on_error`，不做 tag/rolling。
  - 只有机器数量上来（>5）或需要统一审计时才值得做；当前用现有工具循环即可。

- [ ] **`ssh_patch`（统一 diff 应用）**
  - 需要远端有 `patch` 或 `git apply`；建议先 `--dry-run` 再执行。
  - 先观察 `ssh_edit` 是否够用，再决定是否值得新增工具。

- [ ] **`ssh_transfer` 增强**
  - 断点续传、远端到远端传输、传输进度。
  - 需要新的状态存储和更多测试，暂不做。

- [ ] **host_key_policy 仍是两步确认框**
  - 现在是“accept-new vs 其他” + “strict vs insecure” 两次确认，不是真正的三选项菜单。
  - 原因：select 对话框带过滤输入，用户不希望选择策略还要打字。
  - 预期：如果要单选，需要写自定义 JSX 对话框，一次展示 `accept-new` / `strict` / `insecure`。

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
