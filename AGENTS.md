# opencode-ssh Agent Guide

This project is an OpenCode plugin for persistent SSH connections, encrypted profiles, and remote command execution.

## Prefer tools over TUI commands

Use the `ssh_*` tools for work. The `/ssh-connect`, `/ssh-list`, `/ssh-profile` commands are user-facing TUI commands; do not invoke them as tools.

## Connection reuse

1. Before connecting, call `ssh_list` when you need to know what is already active.
2. `ssh_connect` already reuses an existing connection by default:
   - same `profile_id`, or
   - same `user@host:port` for an inline connection when authentication material, host-key policy, and sudo password are compatible.
   It returns the existing `ssh_id` with `reused: true`.
3. Do not create a duplicate connection unless the user explicitly asks for a separate one. In that case pass `force_new: true`.
4. If `ssh_connect` returns `reused: true`, do **not** call `ssh_disconnect` when your task finishes. Other work may still be using that connection.
5. Only disconnect connections you created and no longer need.
6. Profile reuse also requires the same `revision` and authentication material. After a password/key/sudo/host-key/user/host/port edit, old connections are marked `stale`: do not reuse them for new work, but do not disconnect them if they may still be running tasks.

Recommended flow:

```text
ssh_list
  -> target already active: reuse its ssh_id with ssh_exec
  -> target not active: ssh_connect({ profile_id }) or inline ssh_connect(...)
  -> ssh_exec({ ssh_id, command, ... })
```

## Profiles

- Prefer a saved profile for repeated hosts: `ssh_profile_list`, then `ssh_connect({ profile_id })`.
- Use `ssh_profile_add` when the user wants to persist a reusable configuration.
- Inline connections are for one-off work. Do not echo passwords or sudo passwords back to the user.
- Profile ids are internal. When talking to the user, use the profile name and `user@host:port`, not the `prof_...` id.
- `ssh_profile_update` and `ssh_profile_remove` do not disconnect active connections; they mark them stale. Existing work may continue, but reuse will create a fresh connection.

## Command execution

- `ssh_exec` opens a new channel on an existing connection. Shell state such as `cd` and `export` does not persist between calls.
- Use `cwd` for a working directory and `env` for per-command environment variables.
- Use `sudo: true` for sudo. Use `as_user` to switch users. Sudo uses the password stored on the connection.
- `ssh_profile_add` / `ssh_profile_update` only write storage: they do not connect, verify credentials, or test sudo. A saved profile or successful `ssh_connect` proves SSH authentication only; never infer that sudo is passwordless or that the stored sudo password is correct.
- Before using sudo without a stored sudo password, you may check passwordless access with `ssh_exec({ command: "sudo -k -n true" })` (exit code 0 means no password is needed). Otherwise run the real sudo command and read `exit_code` / stderr, or ask the user; do not guess.
- Set `timeout_ms` for long-running commands. Output is bounded by `max_output_bytes`; terminal controls are stripped, and long output keeps both the beginning and the end. Check the separate stdout/stderr truncation fields.
- Pager guards are opt-in: for commands that may page (`git log`, `systemctl status`, `man`, `less`), pass `non_interactive: true` or set `PAGER` / `GIT_PAGER` / `SYSTEMD_PAGER` to `cat`, `NO_COLOR=1`, `TERM=dumb` via `env`. By default commands keep their normal terminal behavior.
- A non-zero exit code is normal command output, not a tool failure. Read `exit_code`, stdout, and stderr.
- On a tool failure, read `metadata.errorCode`, `retryable`, `hint`, `recommendedNextTool`, and `executionMayHaveStarted`. If `executionMayHaveStarted` is true, verify remote state before retrying; never blindly re-run migrations, deletes, or deployments.
- Progress updates are bounded UI hints (tail output, elapsed time, transfer bytes); do not treat them as final output or poll for them.
- Tool cancellation is best-effort: `ssh_exec` sends a remote KILL then closes the channel; `ssh_glob` / `ssh_grep` / `ssh_transfer` honor the tool signal. Cancelling a call does not stop a detached job; use `ssh_job_stop` for that.
- `tty: true` only allocates a PTY; there is no send-stdin tool, and stdin closes immediately after an optional sudo password. Use it for TTY detection/color, not prompts or commands that read stdin. Use shell redirection/pipes for one-shot input.

## Remote file operations

Prefer the file tools over shelling out through `ssh_exec`:

- `ssh_read` instead of `cat` / `sed -n`
- `ssh_write` for whole files (atomic, creates parent directories)
- `ssh_edit` for targeted changes (exact match, must be unique unless `replace_all`)
- `ssh_glob` instead of `find` / `ls -R`
- `ssh_grep` instead of `grep -r`
- `ssh_remove` instead of `rm` (path-scoped permission, use `dry_run` first)
- `ssh_transfer` instead of scp/base64 pipes

Rules that matter:

- Paths must be absolute or start with `~/`; relative paths are rejected.
- `ssh_write` refuses to overwrite unless `overwrite: true` is passed deliberately.
- `ssh_write` / `ssh_edit` refuse symbolic links. They preserve POSIX mode, but ownership may become the SSH user and ACL/xattr are not guaranteed. `ssh_transfer` rejects symlinks in both directions; `ssh_remove` deletes a link itself, not its target.
- `ssh_write` reports `line_endings`; CRLF is written byte-for-byte and warned about. Use LF for Linux shell scripts and cron entries.
- `ssh_edit` fails when `old_text` matches more than once unless `replace_all: true`.
- `ssh_read` reports `line_endings` and, for a complete file, its SHA-256. Pass that hash as `ssh_edit`'s `expected_sha256` to prevent overwriting a file changed by another process. `ssh_edit` also returns SHA-256 before/after. Matching is exact, including CRLF.
- Before deleting a directory, call `ssh_remove` with `dry_run: true`, then repeat with `recursive: true`.
- Write, edit, remove, and transfer trigger a path-level permission prompt; read, glob, and grep do not.
- `ssh_grep` needs `rg` or `grep`; `ssh_glob` prefers `rg`/`find` and falls back to an SFTP walk. If `ssh_grep` has neither, tell the user and offer to install ripgrep via `ssh_exec` (ask before installing). Never fall back to reading every file over SFTP for grep.
- Both tools skip hidden entries, `.git`, and `node_modules` below the search root; an explicit path that is itself hidden or named `.git`/`node_modules` is searched. With ripgrep they also respect `.gitignore`/`.ignore`; use `include_hidden` / `include_ignored` to opt in. Fallback engines cannot read ignore files and warn that results may include them; `include_ignored` only suppresses that warning there.
- `ssh_glob` uses path globs: `*.ts` matches the root level only, `**/*.ts` recurses. `ssh_grep`'s `include` is a file-name glob such as `*.ts`; use `path` to scope directories.
- Do not download large files just to inspect them. Use `ssh_read` with `offset` / `limit` for small files; for later parts of a large file use `byte_offset` and `max_bytes`. `offset` is a line offset only from byte 0, and line numbers are unavailable in a byte-offset window.
- `ssh_glob` / `ssh_grep` choose one engine and do not fall back on a legitimate zero result. Treat `truncated: yes` or `incomplete: yes` as an incomplete result; read `warnings` before concluding "no matches".

## Long-running jobs

Use the job tools when a task should outlive one tool call (training, builds, migrations, long test suites):

- `ssh_job_start` returns `job_id`, `pid`, `job_dir`, and the log path. It returns immediately; it does not wait for the command.
- The job wraps a **foreground** command, including scripts that start parallel children and wait for them (`&` + `wait`). Only commands that return immediately and leave detached work behind (`nohup cmd &`, `docker run -d`) finish the job early and track only the launcher; use `ssh_exec` with stdin/stdout/stderr redirected and detached for those.
- Do **not** raise `ssh_exec`'s `timeout_ms` to hours. That holds a channel open and loses the result on disconnect.
- `ssh_job_status` with `job_id` shows state, exit code, elapsed time; add `log_lines` to tail output. Call it without `job_id` to list the 100 most recent jobs.
- States: `starting`, `running`, `finished`, `stopped`, `lost` (process gone or the pid no longer belongs to the job), `corrupt` (missing or invalid `meta.json`).
- `ssh_job_stop` sends SIGTERM, then SIGKILL to the process group. It refuses when the pid no longer belongs to the job. There is no separate `job_kill`; cancelling a tool call does not stop a job, and with setsid disconnecting does not either.
- `ssh_job_start` runs as the SSH login user. It has no `sudo` / `as_user` option and does not use the connection's stored sudo password; use NOPASSWD or `ssh_exec` for privileged work.
- Clean up finished jobs with `ssh_remove` on `job_dir` (use `dry_run` first).
- Environment variables go inline: `export FOO=bar && python train.py`.
- Jobs survive disconnect and reconnect when the remote has `setsid` (most Linux/BSD); without `setsid` (for example base macOS) detachment is best-effort. State lives under `~/.opencode-ssh/jobs/` on the remote.
- Only the **host process** is tracked. Containers keep their own lifecycle: stopping a job may leave the container running, so decide separately whether to stop or keep it (`docker ps`, `docker stop`).
- POSIX remotes only.

## Job notifications

- `ssh_job_start` registers a completion/readiness notification by default. Do not poll `ssh_job_status` just to wait; the session is woken when the job finishes, becomes ready, fails to start, or times out.
- Pass `job_notify: false` for fire-and-forget jobs. Do not create notification noise when the user does not need the result.
- For services (vLLM, backend, daemon), pass `ready_command`. The job stays running after the `ready` notification; use `ssh_job_stop` when it should be stopped.
- `ssh_exec` only sees the launcher exit. If a command self-detaches (`nohup ... &`, `docker run -d`), it is not tracked and produces no notification. Use `ssh_job_start` for long tasks.
- After reconnect or OpenCode restart, reattach with `ssh_watch({ ssh_id, job_id })`; this only re-registers notification. Never call `ssh_job_start` again for the same job, or a second job is created.
- v1 `ssh_watch` supports existing `job_id` only; generic pid/log/health watches are not implemented yet.

## Security

- Do not put passwords, private key passphrases, or sudo passwords in user-facing summaries.
- Prefer profiles or environment-based master keys over inline secrets in long conversations.
- Remote commands run with the SSH user's authority. Treat `sudo` and destructive commands carefully.
