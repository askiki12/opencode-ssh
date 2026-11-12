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

## Security

- Do not put passwords, private key passphrases, or sudo passwords in user-facing summaries.
- Prefer profiles or environment-based master keys over inline secrets in long conversations.
- Remote commands run with the SSH user's authority. Treat `sudo` and destructive commands carefully.
