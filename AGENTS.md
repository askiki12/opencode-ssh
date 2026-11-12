# opencode-ssh Agent Guide

This project is an OpenCode plugin for persistent SSH connections, encrypted profiles, and remote command execution.

## Prefer tools over TUI commands

Use the `ssh_*` tools for work. The `/ssh-connect`, `/ssh-list`, `/ssh-profile` commands are user-facing TUI commands; do not invoke them as tools.

## Connection reuse

1. Before connecting, call `ssh_list` when you need to know what is already active.
2. `ssh_connect` already reuses an existing connection by default:
   - same `profile_id`, or
   - same `user@host:port` for an inline connection when the sudo password is compatible.
   It returns the existing `ssh_id` with `reused: true`.
3. Do not create a duplicate connection unless the user explicitly asks for a separate one. In that case pass `force_new: true`.
4. If `ssh_connect` returns `reused: true`, do **not** call `ssh_disconnect` when your task finishes. Other work may still be using that connection.
5. Only disconnect connections you created and no longer need.

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

## Command execution

- `ssh_exec` opens a new channel on an existing connection. Shell state such as `cd` and `export` does not persist between calls.
- Use `cwd` for a working directory and `env` for per-command environment variables.
- Use `sudo: true` for sudo. Use `as_user` to switch users. Sudo uses the password stored on the connection.
- Set `timeout_ms` for long-running commands. Output is truncated by `max_output_bytes`.
- A non-zero exit code is normal command output, not a tool failure. Read `exit_code`, stdout, and stderr.
- Avoid interactive commands unless `tty: true` is required.

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
- `ssh_edit` fails when `old_text` matches more than once unless `replace_all: true`.
- Before deleting a directory, call `ssh_remove` with `dry_run: true`, then repeat with `recursive: true`.
- Write, edit, remove, and transfer trigger a path-level permission prompt; read, glob, and grep do not.
- `ssh_grep` / `ssh_glob` need `rg`, `grep`, or `find` on the remote. If both `rg` and `grep` are missing, tell the user and offer to install ripgrep via `ssh_exec` (ask before installing). Never fall back to reading every file over SFTP.
- Do not download large files just to inspect them; use `ssh_read` with `offset` / `limit`.

## Long-running jobs

Use the job tools when a task should outlive one tool call (training, builds, migrations, long test suites):

- `ssh_job_start` returns `job_id`, `pid`, `job_dir`, and the log path. It returns immediately; it does not wait for the command.
- The job wraps a **foreground** command. If the command backgrounds itself (`nohup`, `&`, `docker run -d`), the job finishes immediately and tracks only the launcher — use `ssh_exec` and manage that process yourself instead.
- Do **not** raise `ssh_exec`'s `timeout_ms` to hours. That holds a channel open and loses the result on disconnect.
- `ssh_job_status` with `job_id` shows state, exit code, elapsed time; add `log_lines` to tail output. Call it without `job_id` to list all jobs.
- States: `running`, `finished`, `stopped`, `lost` (process gone, no exit code), `corrupt`.
- `ssh_job_stop` sends SIGTERM, then SIGKILL to the process group. It refuses when the pid no longer belongs to the job.
- Clean up finished jobs with `ssh_remove` on `job_dir` (use `dry_run` first).
- Environment variables go inline: `export FOO=bar && python train.py`.
- Jobs survive disconnect and reconnect; state lives under `~/.opencode-ssh/jobs/` on the remote.
- Only the **host process** is tracked. Containers keep their own lifecycle: stopping a job may leave the container running, so decide separately whether to stop or keep it (`docker ps`, `docker stop`).
- POSIX remotes only.

## Security

- Do not put passwords, private key passphrases, or sudo passwords in user-facing summaries.
- Prefer profiles or environment-based master keys over inline secrets in long conversations.
- Remote commands run with the SSH user's authority. Treat `sudo` and destructive commands carefully.
