import { Error as ToolError } from "@opencode/plugin/promise/tool";
import type { ResolvedConfig } from "../config.js";
import type { ProfileStore } from "../profiles.js";
import {
  DEFAULT_READ_BYTES,
  MAX_READ_BYTES,
  editRemoteFile,
  readRemoteFile,
  removeRemotePath,
  resolveRemotePath,
  transferPath,
  writeRemoteFile,
} from "../ssh/files.js";
import type { ReadRemoteFileResult } from "../ssh/files.js";
import type {
  ConnectionInfo,
  ConnectionManager,
  ExecInput,
  ExecResult,
} from "../ssh/manager.js";
import { SshOperationError } from "../ssh/errors.js";
import type { JobInfo, JobService } from "../ssh/jobs.js";
import type { SearchService } from "../ssh/search.js";
import { errorMessage } from "../util.js";

export interface ExecuteContext {
  readonly sessionID: string;
  readonly agent: string;
  readonly messageID: string;
  readonly id: string;
  readonly signal: AbortSignal;
  readonly progress: (
    update: Readonly<Record<string, any>>,
  ) => Promise<void>;
}

export interface SshPermissionRequest {
  sessionID: string;
  agent: string;
  messageID: string;
  toolCallID: string;
  resource: string;
}

export interface ToolDependencies {
  manager: ConnectionManager;
  profiles: ProfileStore;
  config: ResolvedConfig;
  search: SearchService;
  jobs: JobService;
  assertPermission?: (request: SshPermissionRequest) => Promise<void>;
}

export interface ToolDefinition {
  name: string;
  description: string;
  input: Record<string, unknown>;
  options: { namespace: string; codemode: true };
  execute: (
    input: unknown,
    context: ExecuteContext,
  ) => Promise<{
    content: string;
    metadata?: Record<string, unknown>;
  }>;
}

const HOST_KEY_POLICY_SCHEMA = {
  type: "string",
  enum: ["accept-new", "strict", "insecure"],
  description:
    "Host key policy: accept-new records an unknown key on first use; strict rejects unknown keys; insecure accepts any key (not recommended).",
};

const CONNECT_INPUT = {
  type: "object",
  properties: {
    profile_id: {
      type: "string",
      description:
        "Saved profile id from ssh_profile_add. Use this instead of inline connection fields.",
    },
    name: {
      type: "string",
      description: "Optional display name for an inline connection.",
    },
    user: { type: "string", description: "SSH login user." },
    host: { type: "string", description: "Hostname or IP address." },
    port: {
      type: "integer",
      minimum: 1,
      maximum: 65535,
      default: 22,
      description: "SSH port, default 22.",
    },
    password: {
      type: "string",
      description:
        "SSH password. Stored encrypted when used with ssh_profile_add; kept only in memory for an inline connection.",
    },
    private_key_path: {
      type: "string",
      description:
        "Path to an OpenSSH private key on the local machine, for example ~/.ssh/id_ed25519.",
    },
    private_key_passphrase: {
      type: "string",
      description: "Passphrase for an encrypted private key.",
    },
    sudo_password: {
      type: "string",
      description:
        "Password used when ssh_exec requests sudo or switches users. Stored encrypted in a profile, or kept in memory for an inline connection. Connecting does not verify it; a wrong or missing password only shows up when sudo actually runs.",
    },
    host_key_policy: HOST_KEY_POLICY_SCHEMA,
    force_new: {
      type: "boolean",
      description:
        "Create a separate connection even if an active connection already exists for the same profile or user@host:port. Default false: reuse the existing ssh_id.",
    },
  },
  additionalProperties: false,
} as const;

const DISCONNECT_INPUT = {
  type: "object",
  properties: {
    ssh_id: {
      type: "string",
      description: "Connection id returned by ssh_connect.",
    },
  },
  required: ["ssh_id"],
  additionalProperties: false,
} as const;

const LIST_INPUT = {
  type: "object",
  properties: {},
  additionalProperties: false,
} as const;

const EXEC_INPUT = {
  type: "object",
  properties: {
    ssh_id: {
      type: "string",
      description: "Connection id returned by ssh_connect.",
    },
    command: {
      type: "string",
      description:
        "Command to run on the remote machine. It is executed by the login user's shell.",
    },
    sudo: {
      type: "boolean",
      description:
        "Run through sudo, using the connection's sudo password when one is available. If none is stored, sudo only works when the remote policy is passwordless (NOPASSWD); missing or incorrect passwords appear in exit_code/stderr.",
    },
    as_user: {
      type: "string",
      description:
        "Switch to this user with sudo -u. Implies sudo. Requires a sudo password unless the login user is root.",
    },
    cwd: {
      type: "string",
      description: "Working directory to cd into before running the command.",
    },
    env: {
      type: "object",
      additionalProperties: { type: "string" },
      description: "Extra environment variables exported before the command.",
    },
    timeout_ms: {
      type: "integer",
      minimum: 1000,
      maximum: 3600000,
      description: "Command timeout in milliseconds. Defaults to the plugin setting.",
    },
    tty: {
      type: "boolean",
      description:
        "Allocate a remote PTY for commands that require a terminal but no continuous input. stdin is closed immediately after an optional sudo password; interactive prompts or commands that read stdin will receive EOF. Use shell redirection for one-shot input; sudo is retried with a PTY automatically when needed.",
    },
    non_interactive: {
      type: "boolean",
      description:
        "Optional pager/color guard. Set true for commands that may page (git log, systemctl status, man, less): injects PAGER=cat, GIT_PAGER=cat, SYSTEMD_PAGER=cat, NO_COLOR=1, and TERM=dumb. Default false so commands keep their normal terminal behavior.",
    },
    max_output_bytes: {
      type: "integer",
      minimum: 1024,
      maximum: 16777216,
      description:
        "Maximum bytes retained from each of stdout and stderr. Terminal control sequences are stripped; when output exceeds the limit, the beginning and end are kept and the middle is omitted.",
    },
  },
  required: ["ssh_id", "command"],
  additionalProperties: false,
} as const;

const PATH_SCHEMA = {
  type: "string",
  description:
    "Absolute remote path or a path starting with ~/ . Relative paths are rejected because SFTP and exec do not share a working directory.",
} as const;

const READ_INPUT = {
  type: "object",
  properties: {
    ssh_id: {
      type: "string",
      description: "Connection id returned by ssh_connect.",
    },
    path: PATH_SCHEMA,
    offset: {
      type: "integer",
      minimum: 1,
      description:
        "First line to return, 1-based. Only valid when reading from byte 0; use byte_offset for later parts of a large file.",
    },
    byte_offset: {
      type: "integer",
      minimum: 0,
      description:
        "0-based byte offset for a true segment read. Mutually exclusive with offset; line numbers are unavailable when non-zero.",
    },
    limit: {
      type: "integer",
      minimum: 1,
      description: "Maximum number of lines to return.",
    },
    max_bytes: {
      type: "integer",
      minimum: 1024,
      maximum: MAX_READ_BYTES,
      description: `Maximum bytes to read. Defaults to ${DEFAULT_READ_BYTES}. With byte_offset this is the window size.`,
    },
  },
  required: ["ssh_id", "path"],
  additionalProperties: false,
} as const;

const WRITE_INPUT = {
  type: "object",
  properties: {
    ssh_id: {
      type: "string",
      description: "Connection id returned by ssh_connect.",
    },
    path: PATH_SCHEMA,
    content: {
      type: "string",
      description: "Full file content to write as UTF-8.",
    },
    overwrite: {
      type: "boolean",
      description:
        "Replace the file if it already exists. Default false: an existing file is an error, use ssh_edit for a targeted change.",
    },
  },
  required: ["ssh_id", "path", "content"],
  additionalProperties: false,
} as const;

const EDIT_INPUT = {
  type: "object",
  properties: {
    ssh_id: {
      type: "string",
      description: "Connection id returned by ssh_connect.",
    },
    path: PATH_SCHEMA,
    old_text: {
      type: "string",
      description:
        "Exact text to replace. Must occur exactly once unless replace_all is true.",
    },
    new_text: {
      type: "string",
      description: "Replacement text.",
    },
    replace_all: {
      type: "boolean",
      description: "Replace every occurrence instead of requiring a unique match.",
    },
    expected_sha256: {
      type: "string",
      pattern: "^[0-9a-fA-F]{64}$",
      description:
        "Optional SHA-256 of the current file. The edit is rejected if the file changed after you read it.",
    },
  },
  required: ["ssh_id", "path", "old_text", "new_text"],
  additionalProperties: false,
} as const;

const GLOB_INPUT = {
  type: "object",
  properties: {
    ssh_id: {
      type: "string",
      description: "Connection id returned by ssh_connect.",
    },
    pattern: {
      type: "string",
      description:
        "Glob pattern relative to path, for example **/*.ts or src/**/*.{js,jsx}.",
    },
    path: {
      type: "string",
      description:
        "Directory to search; absolute or ~/..., defaults to the remote home directory.",
    },
    max_results: {
      type: "integer",
      minimum: 1,
      maximum: 5000,
      description: "Maximum number of paths to return. Defaults to 2000.",
    },
    include_hidden: {
      type: "boolean",
      description: "Include dotfiles and hidden directories. Default false.",
    },
  },
  required: ["ssh_id", "pattern"],
  additionalProperties: false,
} as const;

const GREP_INPUT = {
  type: "object",
  properties: {
    ssh_id: {
      type: "string",
      description: "Connection id returned by ssh_connect.",
    },
    pattern: {
      type: "string",
      description: "Regular expression unless literal is true.",
    },
    path: {
      type: "string",
      description:
        "File or directory to search; absolute or ~/..., defaults to the remote home directory.",
    },
    include: {
      type: "string",
      description: "Only search files matching this glob, for example **/*.ts.",
    },
    literal: {
      type: "boolean",
      description: "Treat pattern as a literal string instead of a regular expression.",
    },
    case_sensitive: {
      type: "boolean",
      description: "Case-sensitive matching. Defaults to true.",
    },
    include_hidden: {
      type: "boolean",
      description:
        "Include hidden files and directories. Defaults to false; .git and node_modules are always excluded.",
    },
    max_matches: {
      type: "integer",
      minimum: 1,
      maximum: 5000,
      description: "Maximum number of matches to return. Defaults to 200.",
    },
  },
  required: ["ssh_id", "pattern"],
  additionalProperties: false,
} as const;

const REMOVE_INPUT = {
  type: "object",
  properties: {
    ssh_id: {
      type: "string",
      description: "Connection id returned by ssh_connect.",
    },
    path: PATH_SCHEMA,
    recursive: {
      type: "boolean",
      description: "Required to remove a directory. Default false.",
    },
    dry_run: {
      type: "boolean",
      description:
        "List what would be removed without deleting anything. Use this first for directories.",
    },
  },
  required: ["ssh_id", "path"],
  additionalProperties: false,
} as const;

const TRANSFER_INPUT = {
  type: "object",
  properties: {
    ssh_id: {
      type: "string",
      description: "Connection id returned by ssh_connect.",
    },
    direction: {
      type: "string",
      enum: ["upload", "download"],
      description: "upload = local to remote, download = remote to local.",
    },
    local_path: {
      type: "string",
      description: "Local file or directory path. ~ is expanded locally.",
    },
    remote_path: PATH_SCHEMA,
    overwrite: {
      type: "boolean",
      description:
        "Replace existing files on the destination. Default false: an existing file aborts the transfer.",
    },
  },
  required: ["ssh_id", "direction", "local_path", "remote_path"],
  additionalProperties: false,
} as const;

const JOB_START_INPUT = {
  type: "object",
  properties: {
    ssh_id: {
      type: "string",
      description: "Connection id returned by ssh_connect.",
    },
    command: {
      type: "string",
      description:
        "Shell command to run detached. Set environment variables inline, for example: export FOO=bar && python train.py. Docker works as a normal command (docker run / docker exec).",
    },
    name: {
      type: "string",
      description: "Optional short label shown by ssh_job_status.",
    },
    cwd: {
      type: "string",
      description:
        "Working directory for the command. Absolute or ~/...; defaults to the remote home directory.",
    },
  },
  required: ["ssh_id", "command"],
  additionalProperties: false,
} as const;

const JOB_STATUS_INPUT = {
  type: "object",
  properties: {
    ssh_id: {
      type: "string",
      description: "Connection id returned by ssh_connect.",
    },
    job_id: {
      type: "string",
      description:
        "Job to inspect. Omit to list all jobs created by this plugin for the current user.",
    },
    log_lines: {
      type: "integer",
      minimum: 1,
      maximum: 500,
      description:
        "Include the last N lines of output.log. Only used when job_id is provided.",
    },
  },
  required: ["ssh_id"],
  additionalProperties: false,
} as const;

const JOB_STOP_INPUT = {
  type: "object",
  properties: {
    ssh_id: {
      type: "string",
      description: "Connection id returned by ssh_connect.",
    },
    job_id: {
      type: "string",
      description: "Job returned by ssh_job_start.",
    },
  },
  required: ["ssh_id", "job_id"],
  additionalProperties: false,
} as const;

const PROFILE_ADD_INPUT = {
  type: "object",
  properties: {
    name: {
      type: "string",
      description: "Unique profile name, for example prod-web.",
    },
    user: { type: "string", description: "SSH login user." },
    host: { type: "string", description: "Hostname or IP address." },
    port: {
      type: "integer",
      minimum: 1,
      maximum: 65535,
      default: 22,
      description: "SSH port, default 22.",
    },
    password: {
      type: "string",
      description:
        "SSH password. Encrypted at rest with AES-256-GCM. Provide either password or private_key_path.",
    },
    private_key_path: {
      type: "string",
      description:
        "Path to a local OpenSSH private key. Provide either password or private_key_path.",
    },
    private_key_passphrase: {
      type: "string",
      description: "Passphrase for an encrypted private key. Encrypted at rest.",
    },
    sudo_password: {
      type: "string",
      description:
        "Optional password used for sudo and user switching. Encrypted at rest, but not verified when the profile is saved. If omitted, later sudo calls send no password; this works for NOPASSWD but is indistinguishable from a missing password.",
    },
    host_key_policy: HOST_KEY_POLICY_SCHEMA,
  },
  required: ["name", "user", "host"],
  additionalProperties: false,
} as const;

const PROFILE_UPDATE_INPUT = {
  type: "object",
  properties: {
    profile_id: { type: "string", description: "Profile id to update." },
    name: { type: "string" },
    user: { type: "string" },
    host: { type: "string" },
    port: { type: "integer", minimum: 1, maximum: 65535 },
    password: {
      type: "string",
      description:
        "New SSH password. Replaces private key authentication.",
    },
    private_key_path: {
      type: "string",
      description:
        "New private key path. Replaces password authentication.",
    },
    private_key_passphrase: { type: "string" },
    sudo_password: {
      type: "string",
      description:
        "New sudo password. Stored encrypted but not verified by this tool; a wrong password is only detected when sudo runs.",
    },
    host_key_policy: HOST_KEY_POLICY_SCHEMA,
    clear_password: { type: "boolean" },
    clear_private_key_path: { type: "boolean" },
    clear_private_key_passphrase: { type: "boolean" },
    clear_sudo_password: { type: "boolean" },
  },
  required: ["profile_id"],
  additionalProperties: false,
} as const;

const PROFILE_REMOVE_INPUT = {
  type: "object",
  properties: {
    profile_id: { type: "string", description: "Profile id to remove." },
  },
  required: ["profile_id"],
  additionalProperties: false,
} as const;

const PROFILE_LIST_INPUT = LIST_INPUT;

export function createSshTools(
  dependencies: ToolDependencies,
): readonly ToolDefinition[] {
  return [
    {
      name: "connect",
      description:
        "Get or create a persistent SSH connection and return an ssh_id for later ssh_exec calls. " +
        "By default this tool REUSES an active connection when the profile or inline target matches and authentication material, host-key policy, and sudo password are compatible, and returns the existing ssh_id. " +
        "Call ssh_list first if you need to inspect active connections. " +
        "Pass force_new=true only when the user explicitly wants a separate connection. " +
        "Provide either profile_id or inline user/host plus exactly one of password or private_key_path. " +
        "A successful connect verifies SSH authentication only; it does not test sudo. " +
        "A missing sudo_password does not prove passwordless sudo, and a wrong password is not detected until sudo runs. " +
        "Reuse also requires the same profile revision; after a connection-affecting profile change, a new connection is created and the old one is marked stale instead of being interrupted.",
      input: CONNECT_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw, context) => {
        const input = asRecord(raw);
        const profileId = optionalString(input.profile_id);
        const user = optionalString(input.user);
        const host = optionalString(input.host);
        const password = optionalString(input.password);
        const privateKeyPath = optionalString(input.private_key_path);
        const privateKeyPassphrase = optionalString(
          input.private_key_passphrase,
        );
        const sudoPassword = optionalString(input.sudo_password);
        const name = optionalString(input.name);

        if (profileId !== undefined) {
          const inlineFields = [
            "name",
            "user",
            "host",
            "port",
            "password",
            "private_key_path",
            "private_key_passphrase",
            "sudo_password",
            "host_key_policy",
          ];
          if (inlineFields.some((field) => input[field] !== undefined)) {
            throw new Error(
              "Use either profile_id or inline connection fields, not both.",
            );
          }
        } else if (
          user === undefined ||
          host === undefined ||
          (password === undefined) === (privateKeyPath === undefined)
        ) {
          throw new Error(
            "Inline connection requires user, host, and exactly one of password or private_key_path.",
          );
        }

        const info = await dependencies.manager.connect({
          ...(profileId !== undefined ? { profileId } : {}),
          ...(name !== undefined ? { name } : {}),
          ...(user !== undefined ? { user } : {}),
          ...(host !== undefined ? { host } : {}),
          ...(input.port !== undefined
            ? { port: requireInteger(input.port, "port") }
            : {}),
          ...(password !== undefined ? { password } : {}),
          ...(privateKeyPath !== undefined ? { privateKeyPath } : {}),
          ...(privateKeyPassphrase !== undefined
            ? { privateKeyPassphrase }
            : {}),
          ...(sudoPassword !== undefined ? { sudoPassword } : {}),
          ...(input.host_key_policy !== undefined
            ? { hostKeyPolicy: asHostKeyPolicy(input.host_key_policy) }
            : {}),
          ...(input.force_new !== undefined
            ? { forceNew: requireBoolean(input.force_new, "force_new") }
            : {}),
          onProgress: (update) => {
            void context
              .progress({
                type: "ssh.connect.progress",
                phase: update.phase,
                message: update.message,
              })
              .catch(() => undefined);
          },
        });

        return {
          content: formatConnection(
            info,
            info.reused
              ? "Reused existing SSH connection."
              : "SSH connection established.",
          ),
          metadata: connectionMetadata(info),
        };
      },
    },

    {
      name: "disconnect",
      description: "Close an active persistent SSH connection by ssh_id.",
      input: DISCONNECT_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw) => {
        const input = asRecord(raw);
        const sshId = requireString(input.ssh_id, "ssh_id");
        const info = await dependencies.manager.disconnect(sshId);
        return {
          content: [
            "SSH connection closed.",
            `ssh_id: ${info.id}`,
            `target: ${info.user}@${info.host}:${info.port}`,
          ].join("\n"),
          metadata: { sshId: info.id },
        };
      },
    },

    {
      name: "list",
      description:
        "List active persistent SSH connections and their ssh_id values. " +
        "Reuse an existing ssh_id with ssh_exec instead of creating a duplicate connection. " +
        "Secrets and passwords are never included. A listed connection does not imply that its sudo password is present or valid. Connections marked stale belong to an older profile revision: they keep running in-flight work but are not reused.",
      input: LIST_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async () => {
        const connections = dependencies.manager.list();
        if (connections.length === 0) {
          return {
            content: "No active SSH connections.",
            metadata: { count: 0 },
          };
        }
        const lines = [`Active SSH connections (${connections.length}):`];
        for (const connection of connections) {
          const bits = [
            `- ${connection.id}`,
            `${connection.user}@${connection.host}:${connection.port}`,
            `name=${connection.name}`,
            `auth=${connection.authMethod}`,
            `connected=${connection.connectedAt}`,
            `idle=${formatDuration(connection.idleMs)}`,
          ];
          if (connection.profileId) bits.push(`profile=${connection.profileId}`);
          if (connection.profileRevision !== undefined) {
            bits.push(`revision=${connection.profileRevision}`);
          }
          if (connection.stale) bits.push("stale");
          if (connection.busy) bits.push("busy");
          if (connection.lastError) bits.push(`last_error=${connection.lastError}`);
          lines.push(bits.join("  "));
        }
        return {
          content: lines.join("\n"),
          metadata: { count: connections.length },
        };
      },
    },

    {
      name: "exec",
      description:
        "Execute a command over a persistent SSH connection. Returns the exit code, stdout, and stderr. " +
        "Use an ssh_id from ssh_connect or ssh_list; prefer reusing an existing connection instead of connecting again. " +
        "Each call opens a new channel, so shell state such as cd/export does not persist; use cwd and env instead. " +
        "tty=true allocates a PTY but does not provide interactive stdin; stdin closes immediately, so use it for TTY detection/color, not for prompts. " +
        "Set sudo=true to run through sudo, or as_user to switch users. " +
        "sudo uses the sudo password stored on the connection; the password is written to sudo's stdin, never to the command line. " +
        "The tool does not pre-check sudo: a missing password may still work (NOPASSWD) or fail, and a wrong password is only visible in exit_code/stderr. " +
        "Terminal control sequences are stripped; long output keeps both the beginning and the end, with separate stdout/stderr byte and truncation counts. " +
        "Pager/color guards are not injected by default; for pager-prone commands set non_interactive=true or pass PAGER/GIT_PAGER/SYSTEMD_PAGER=cat, NO_COLOR=1, and TERM=dumb via env. " +
        "On a tool failure, metadata includes errorCode, retryable, hint, recommendedNextTool, and executionMayHaveStarted; if executionMayHaveStarted is true, verify remote state before retrying. " +
        "Caller cancellation is best-effort: the remote command may still have started, so check executionMayHaveStarted. " +
        "A non-zero exit code is normal command output, not a tool failure.",
      input: EXEC_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw, context) => {
        const input = asRecord(raw);
        let sshId: string;
        let command: string;
        let connection: ConnectionInfo;
        try {
          sshId = requireString(input.ssh_id, "ssh_id");
          command = requireString(input.command, "command");
          connection = dependencies.manager.getInfo(sshId);
        } catch (error) {
          throw toToolError(error, "SSH_INVALID_INPUT");
        }

        if (dependencies.assertPermission) {
          await dependencies.assertPermission({
            sessionID: context.sessionID,
            agent: context.agent,
            messageID: context.messageID,
            toolCallID: context.id,
            resource: `${connection.user}@${connection.host}:${connection.port}`,
          });
        }

        let execInput: ExecInput;
        try {
          execInput = {
            sshId,
            command,
            ...(input.sudo !== undefined
              ? { sudo: requireBoolean(input.sudo, "sudo") }
              : {}),
            ...(input.as_user !== undefined
              ? { asUser: requireString(input.as_user, "as_user") }
              : {}),
            ...(input.cwd !== undefined
              ? { cwd: requireString(input.cwd, "cwd") }
              : {}),
            ...(input.env !== undefined
              ? { env: asStringRecord(input.env, "env") }
              : {}),
            ...(input.timeout_ms !== undefined
              ? { timeoutMs: requireInteger(input.timeout_ms, "timeout_ms") }
              : {}),
            ...(input.tty !== undefined
              ? { tty: requireBoolean(input.tty, "tty") }
              : {}),
            nonInteractive:
              input.non_interactive === undefined
                ? false
                : requireBoolean(input.non_interactive, "non_interactive"),
            onProgress: (update) => {
              void context
                .progress({
                  type: "ssh.exec.progress",
                  elapsedMs: update.elapsedMs,
                  stdoutBytes: update.stdoutBytes,
                  stderrBytes: update.stderrBytes,
                  stdoutTail: update.stdoutTail,
                  stderrTail: update.stderrTail,
                })
                .catch(() => undefined);
            },
            ...(input.max_output_bytes !== undefined
              ? {
                  maxOutputBytes: requireInteger(
                    input.max_output_bytes,
                    "max_output_bytes",
                  ),
                }
              : {}),
          };
        } catch (error) {
          throw toToolError(error, "SSH_INVALID_INPUT");
        }

        let result: ExecResult;
        try {
          result = await dependencies.manager.exec(execInput, context.signal);
        } catch (error) {
          throw toToolError(error);
        }

        return {
          content: formatExec(result),
          metadata: {
            sshId: result.sshId,
            exitCode: result.exitCode,
            signal: result.signal,
            durationMs: result.durationMs,
            truncated: result.truncated,
            stdoutBytes: result.stdoutBytes,
            stderrBytes: result.stderrBytes,
            stdoutRetainedBytes: Buffer.byteLength(result.stdout, "utf8"),
            stderrRetainedBytes: Buffer.byteLength(result.stderr, "utf8"),
            stdoutTruncated: result.stdoutTruncated,
            stderrTruncated: result.stderrTruncated,
          },
        };
      },
    },

    {
      name: "read",
      description:
        "Read a remote file. Prefer this over ssh_exec with cat for inspecting files: it is binary-safe, caps how many bytes are returned, and reports the exact byte range. " +
        "When the whole file is read, it also returns its SHA-256 for use with ssh_edit's expected_sha256, and always reports line endings (CRLF can break Linux scripts/cron). " +
        "offset is a 1-based line offset only valid when reading from byte 0; for later parts of a large file use byte_offset (0-based), where line numbers are unavailable.",
      input: READ_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw) => {
        const input = asRecord(raw);
        const sshId = requireString(input.ssh_id, "ssh_id");
        const target = await resolveTargetPath(
          dependencies.manager,
          sshId,
          input.path,
        );
        const sftp = await dependencies.manager.sftp(sshId);
        const result = await readRemoteFile(sftp, target, {
          ...(input.offset !== undefined
            ? { offset: requireInteger(input.offset, "offset") }
            : {}),
          ...(input.byte_offset !== undefined
            ? { byteOffset: requireInteger(input.byte_offset, "byte_offset") }
            : {}),
          ...(input.limit !== undefined
            ? { limit: requireInteger(input.limit, "limit") }
            : {}),
          ...(input.max_bytes !== undefined
            ? { maxBytes: requireInteger(input.max_bytes, "max_bytes") }
            : {}),
        });

        return {
          content: formatReadResult(result),
          metadata: {
            path: result.path,
            size: result.size,
            byteStart: result.byteStart,
            byteEnd: result.byteEnd,
            lineNumbers: result.lineNumbers,
            sha256: result.sha256,
            lineEndings: result.lineEndings,
            startLine: result.startLine,
            endLine: result.endLine,
            totalLines: result.totalLines,
            truncated: result.truncated,
            binary: result.binary,
          },
        };
      },
    },

    {
      name: "write",
      description:
        "Write a complete remote file as UTF-8 using an atomic temp-file rename. " +
        "Parent directories are created automatically. " +
        "By default an existing file is an error; pass overwrite: true to replace it, " +
        "or use ssh_edit for a targeted change. Content is written byte-for-byte: line endings are preserved and reported; CRLF may break Linux scripts/cron. " +
        "POSIX mode is preserved; ownership may become the SSH user, and ACL/xattr are not guaranteed. Refuses symbolic links.",
      input: WRITE_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw, context) => {
        const input = asRecord(raw);
        const sshId = requireString(input.ssh_id, "ssh_id");
        const target = await resolveTargetPath(
          dependencies.manager,
          sshId,
          input.path,
        );
        await assertPathPermission(dependencies, context, sshId, target);

        const sftp = await dependencies.manager.sftp(sshId);
        const result = await writeRemoteFile(
          sftp,
          target,
          requireString(input.content, "content"),
          {
            ...(input.overwrite !== undefined
              ? { overwrite: requireBoolean(input.overwrite, "overwrite") }
              : {}),
          },
        );

        const lines = [
          result.created ? "Created remote file." : "Overwrote remote file.",
          `path: ${result.path}`,
          `bytes: ${result.bytes}`,
          `line_endings: ${result.lineEndings}`,
        ];
        if (result.lineEndings === "crlf" || result.lineEndings === "mixed") {
          lines.push(
            "",
            "[warning] Content contains CRLF or mixed line endings; Linux scripts and cron entries usually require LF.",
          );
        }
        return {
          content: lines.join("\n"),
          metadata: { ...result },
        };
      },
    },

    {
      name: "edit",
      description:
        "Replace exact text in a remote file and write it atomically. " +
        "old_text must occur exactly once unless replace_all is true; otherwise the edit fails " +
        "so an ambiguous change is never applied. Matching is exact, including line endings (CRLF files need \\r\\n in old_text). " +
        "Returns SHA-256 before/after; expected_sha256 rejects the edit if the file changed after reading. " +
        "POSIX mode is preserved; ownership may become the SSH user, and ACL/xattr are not guaranteed. Refuses symbolic links.",
      input: EDIT_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw, context) => {
        const input = asRecord(raw);
        const sshId = requireString(input.ssh_id, "ssh_id");
        const target = await resolveTargetPath(
          dependencies.manager,
          sshId,
          input.path,
        );
        await assertPathPermission(dependencies, context, sshId, target);

        const sftp = await dependencies.manager.sftp(sshId);
        const result = await editRemoteFile(
          sftp,
          target,
          requireString(input.old_text, "old_text"),
          requireString(input.new_text, "new_text"),
          {
            ...(input.replace_all !== undefined
              ? { replaceAll: requireBoolean(input.replace_all, "replace_all") }
              : {}),
            ...(input.expected_sha256 !== undefined
              ? {
                  expectedSha256: requireString(
                    input.expected_sha256,
                    "expected_sha256",
                  ),
                }
              : {}),
          },
        );

        const lines = [
          `Edited remote file: ${result.path}`,
          `replacements: ${result.replacements}`,
          `sha256_before: ${result.sha256Before}`,
          `sha256_after: ${result.sha256After}`,
          `line_endings: ${result.lineEndings}`,
          "",
          ...result.preview.map((line) => `${line.number}: ${line.text}`),
        ];
        if (result.lineEndings === "crlf" || result.lineEndings === "mixed") {
          lines.push(
            "",
            "[warning] File contains CRLF or mixed line endings; Linux scripts and cron entries usually require LF.",
          );
        }

        return {
          content: lines.join("\n"),
          metadata: {
            path: result.path,
            replacements: result.replacements,
            firstLine: result.firstLine,
            sha256Before: result.sha256Before,
            sha256After: result.sha256After,
            lineEndings: result.lineEndings,
          },
        };
      },
    },

    {
      name: "glob",
      description:
        "Find remote files by glob pattern relative to a directory. " +
        "Chooses one engine: ripgrep when available, otherwise find, otherwise an SFTP walk. " +
        "A legitimate zero result is returned as-is; it does not fall back to another scan. " +
        "Errors and output truncation are reported instead of being hidden as empty results. " +
        "Default skips .git, node_modules, and hidden entries. " +
        "Prefer this over shelling out to find/glob through ssh_exec.",
      input: GLOB_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw, context) => {
        const input = asRecord(raw);
        const sshId = requireString(input.ssh_id, "ssh_id");
        const root =
          input.path === undefined
            ? await dependencies.manager.homeDir(sshId)
            : await resolveTargetPath(dependencies.manager, sshId, input.path);
        const result = await dependencies.search.glob(
          sshId,
          {
            pattern: requireString(input.pattern, "pattern"),
            path: root,
            ...(input.max_results !== undefined
              ? { maxResults: requireInteger(input.max_results, "max_results") }
              : {}),
            ...(input.include_hidden !== undefined
              ? {
                  includeHidden: requireBoolean(
                    input.include_hidden,
                    "include_hidden",
                  ),
                }
              : {}),
          },
          context.signal,
        );

        const lines = [
          `engine: ${result.engine}`,
          `root: ${root}`,
          `count: ${result.paths.length}`,
          `truncated: ${result.truncated ? "yes" : "no"}`,
          "",
          ...(result.paths.length > 0 ? result.paths : ["(no matches)"]),
        ];
        return {
          content: lines.join("\n"),
          metadata: {
            engine: result.engine,
            root,
            count: result.paths.length,
            truncated: result.truncated,
          },
        };
      },
    },

    {
      name: "grep",
      description:
        "Search remote file contents. Chooses one engine: ripgrep when available, otherwise grep; " +
        "there is no line-by-line SFTP fallback because it is far slower. " +
        "A legitimate zero match is returned as-is; it does not fall back to another scan. " +
        "Errors and output truncation are reported instead of being hidden as empty results. " +
        "If the remote lacks both tools, suggest installing ripgrep via ssh_exec and ask the user first. " +
        "Skips hidden entries, .git, and node_modules by default (set include_hidden=true to opt in); returns path, line number, and matching text up to max_matches.",
      input: GREP_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw, context) => {
        const input = asRecord(raw);
        const sshId = requireString(input.ssh_id, "ssh_id");
        const target =
          input.path === undefined
            ? await dependencies.manager.homeDir(sshId)
            : await resolveTargetPath(dependencies.manager, sshId, input.path);
        const result = await dependencies.search.grep(
          sshId,
          {
            pattern: requireString(input.pattern, "pattern"),
            path: target,
            ...(input.include !== undefined
              ? { include: requireString(input.include, "include") }
              : {}),
            ...(input.literal !== undefined
              ? { literal: requireBoolean(input.literal, "literal") }
              : {}),
            ...(input.case_sensitive !== undefined
              ? {
                  caseSensitive: requireBoolean(
                    input.case_sensitive,
                    "case_sensitive",
                  ),
                }
              : {}),
            ...(input.include_hidden !== undefined
              ? {
                  includeHidden: requireBoolean(
                    input.include_hidden,
                    "include_hidden",
                  ),
                }
              : {}),
            ...(input.max_matches !== undefined
              ? { maxMatches: requireInteger(input.max_matches, "max_matches") }
              : {}),
          },
          context.signal,
        );

        const lines = [
          `engine: ${result.engine}`,
          `count: ${result.matches.length}`,
          `truncated: ${result.truncated ? "yes" : "no"}`,
          "",
          ...(result.matches.length > 0
            ? result.matches.map((match) => `${match.path}:${match.line}: ${match.text}`)
            : ["(no matches)"]),
        ];
        return {
          content: lines.join("\n"),
          metadata: {
            engine: result.engine,
            count: result.matches.length,
            truncated: result.truncated,
          },
        };
      },
    },

    {
      name: "remove",
      description:
        "Delete a remote file or directory. Removing a directory requires recursive: true. " +
        "Use dry_run: true first to see exactly what would be deleted; this tool has its own " +
        "path-scoped permission prompt instead of running rm through ssh_exec. Removing a symbolic link deletes the link itself, not its target.",
      input: REMOVE_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw, context) => {
        const input = asRecord(raw);
        const sshId = requireString(input.ssh_id, "ssh_id");
        const target = await resolveTargetPath(
          dependencies.manager,
          sshId,
          input.path,
        );
        const dryRun = input.dry_run === true;
        if (!dryRun) {
          await assertPathPermission(dependencies, context, sshId, target);
        }

        const sftp = await dependencies.manager.sftp(sshId);
        const result = await removeRemotePath(sftp, target, {
          ...(input.recursive !== undefined
            ? { recursive: requireBoolean(input.recursive, "recursive") }
            : {}),
          dryRun,
        });

        const lines = [
          `${result.dryRun ? "Would remove" : "Removed"}: ${result.path}`,
          `entries: ${result.removed}`,
          ...(result.listedTruncated
            ? [`[note] listing truncated to the first ${result.entries.length} entries`]
            : []),
          "",
          ...result.entries,
        ];
        return {
          content: lines.join("\n"),
          metadata: {
            path: result.path,
            dryRun: result.dryRun,
            removed: result.removed,
            listedTruncated: result.listedTruncated,
          },
        };
      },
    },

    {
      name: "transfer",
      description:
        "Copy files between the local machine and the remote host over SFTP. " +
        "direction is upload or download; both file and directory paths are supported. " +
        "Existing destination files abort the transfer unless overwrite: true. " +
        "Symbolic links are rejected rather than followed. Single files use a temporary file and atomic replace; a cancelled directory transfer may leave already-completed items. " +
        "Byte and file progress is reported through the UI while the transfer runs.",
      input: TRANSFER_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw, context) => {
        const input = asRecord(raw);
        const sshId = requireString(input.ssh_id, "ssh_id");
        const direction = requireString(input.direction, "direction");
        if (direction !== "upload" && direction !== "download") {
          throw new Error("direction must be upload or download.");
        }
        const target = await resolveTargetPath(
          dependencies.manager,
          sshId,
          input.remote_path,
        );
        await assertPathPermission(dependencies, context, sshId, target);

        const sftp = await dependencies.manager.sftp(sshId);
        let lastProgressAt = 0;
        const result = await transferPath(sftp, {
          direction,
          localPath: requireString(input.local_path, "local_path"),
          remotePath: target,
          ...(input.overwrite !== undefined
            ? { overwrite: requireBoolean(input.overwrite, "overwrite") }
            : {}),
          onProgress: (update) => {
            const now = Date.now();
            if (now - lastProgressAt < 1_000) return;
            lastProgressAt = now;
            void context
              .progress({
                type: "ssh.transfer.progress",
                direction: update.direction,
                files: update.files,
                bytes: update.bytes,
              })
              .catch(() => undefined);
          },
          signal: context.signal,
        });

        return {
          content: [
            `${direction === "upload" ? "Uploaded" : "Downloaded"} ${result.files} file(s).`,
            `local: ${result.localPath}`,
            `remote: ${result.remotePath}`,
            `bytes: ${result.bytes}`,
          ].join("\n"),
          metadata: { ...result },
        };
      },
    },

    {
      name: "job_start",
      description:
        "Start a long-running remote command detached from the SSH channel and return a job_id. " +
        "Use this for tasks that outlive one tool call (training, builds, migrations) instead of raising ssh_exec timeout_ms. " +
        "The process survives disconnect and OpenCode restarts. " +
        "Environment variables go inline in the command (export FOO=bar && ...). " +
        "Run a foreground command only: if the command backgrounds itself (nohup, &, docker run -d), do not use ssh_job_start; the job would finish immediately and track only the launcher. Use ssh_exec and manage that process yourself instead. " +
        "Only the host process is tracked; containers keep their own lifecycle, so decide separately whether to stop or leave them running. " +
        "Cancelling this tool call or disconnecting does not stop the job; use ssh_job_stop for that. " +
        "Inspect with ssh_job_status, terminate with ssh_job_stop, clean up with ssh_remove on job_dir. POSIX remotes only.",
      input: JOB_START_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw, context) => {
        const input = asRecord(raw);
        const sshId = requireString(input.ssh_id, "ssh_id");
        await assertHostPermission(dependencies, context, sshId);

        const result = await dependencies.jobs.start({
          sshId,
          command: requireString(input.command, "command"),
          ...(input.name !== undefined
            ? { name: requireString(input.name, "name") }
            : {}),
          ...(input.cwd !== undefined
            ? { cwd: requireString(input.cwd, "cwd") }
            : {}),
        });

        return {
          content: [
            `Job started: ${result.jobId}`,
            ...(result.name !== undefined ? [`name: ${result.name}`] : []),
            `pid: ${result.pid}`,
            `job_dir: ${result.jobDir}`,
            `log: ${result.logPath}`,
            "",
            "Use ssh_job_status to check progress and ssh_job_stop to terminate it.",
          ].join("\n"),
          metadata: { ...result },
        };
      },
    },

    {
      name: "job_status",
      description:
        "Check a job started by ssh_job_start, or list all jobs when job_id is omitted. " +
        "States: starting, running, finished (has exit_code), stopped (terminated by ssh_job_stop), lost (process gone without exit_code), corrupt. " +
        "Pass log_lines to include the tail of output.log. " +
        "Finished jobs keep their logs until you remove their job_dir with ssh_remove.",
      input: JOB_STATUS_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw) => {
        const input = asRecord(raw);
        const sshId = requireString(input.ssh_id, "ssh_id");
        const jobId = optionalString(input.job_id);
        const logLines =
          input.log_lines === undefined
            ? 0
            : requireInteger(input.log_lines, "log_lines");

        const result = await dependencies.jobs.status(sshId, jobId, logLines);
        if (Array.isArray(result)) {
          return {
            content: formatJobList(result),
            metadata: { count: result.length },
          };
        }
        return {
          content: formatJobInfo(result),
          metadata: {
            jobId: result.jobId,
            state: result.state,
            pid: result.pid,
            exitCode: result.exitCode,
            jobDir: result.jobDir,
          },
        };
      },
    },

    {
      name: "job_stop",
      description:
        "Terminate a running job with SIGTERM, then SIGKILL after a short grace period. " +
        "Kills the whole process group when available. Refuses to signal a pid whose command line " +
        "does not belong to the job, which protects against pid reuse. " +
        "Only the host process is tracked; containers keep their own lifecycle and are not stopped. " +
        "Finished jobs are reported without doing anything. This is the job termination tool; no separate job_kill is needed.",
      input: JOB_STOP_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw, context) => {
        const input = asRecord(raw);
        const sshId = requireString(input.ssh_id, "ssh_id");
        await assertHostPermission(dependencies, context, sshId);

        const result = await dependencies.jobs.stop(
          sshId,
          requireString(input.job_id, "job_id"),
        );

        const lines: string[] = [];
        switch (result.outcome) {
          case "stopped":
            lines.push(`Stopped job ${result.jobId} (pid ${result.pid}).`);
            break;
          case "already-finished":
            lines.push(
              `Job ${result.jobId} already finished with exit code ${result.exitCode}.`,
            );
            break;
          case "not-running":
            lines.push(
              `Job ${result.jobId} is no longer running and has no exit code; inspect its job_dir or remove it.`,
            );
            break;
          case "mismatch":
            lines.push(
              `Refused to stop job ${result.jobId}: pid ${result.pid} does not belong to the job directory.`,
            );
            break;
        }
        return {
          content: lines.join("\n"),
          metadata: { ...result },
        };
      },
    },

    {
      name: "profile_add",
      description:
        "Save a reusable SSH profile. Passwords and passphrases are encrypted at rest with AES-256-GCM. " +
        "Returns a profile_id for ssh_connect. " +
        "This tool only writes storage: it does not connect, verify SSH credentials, or test sudo. " +
        "An omitted sudo_password means no password will be sent later; it does not prove passwordless sudo.",
      input: PROFILE_ADD_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw) => {
        const input = asRecord(raw);
        const profile = await dependencies.profiles.add({
          name: requireString(input.name, "name"),
          user: requireString(input.user, "user"),
          host: requireString(input.host, "host"),
          ...(input.port !== undefined
            ? { port: requireInteger(input.port, "port") }
            : {}),
          ...(input.password !== undefined
            ? { password: requireString(input.password, "password") }
            : {}),
          ...(input.private_key_path !== undefined
            ? {
                privateKeyPath: requireString(
                  input.private_key_path,
                  "private_key_path",
                ),
              }
            : {}),
          ...(input.private_key_passphrase !== undefined
            ? {
                privateKeyPassphrase: requireString(
                  input.private_key_passphrase,
                  "private_key_passphrase",
                ),
              }
            : {}),
          ...(input.sudo_password !== undefined
            ? {
                sudoPassword: requireString(
                  input.sudo_password,
                  "sudo_password",
                ),
              }
            : {}),
          hostKeyPolicy:
            input.host_key_policy !== undefined
              ? asHostKeyPolicy(input.host_key_policy)
              : dependencies.config.hostKeyPolicy,
        });

        return {
          content: formatProfile(profile, "SSH profile saved."),
          metadata: { profileId: profile.id, revision: profile.revision },
        };
      },
    },

    {
      name: "profile_update",
      description:
        "Update an existing SSH profile. Only the provided fields change. Use clear_* flags to remove stored secrets. " +
        "This tool only updates storage; it does not connect or test the new credentials or sudo password. " +
        "Connection-affecting changes increment the profile revision and mark existing profile connections stale; they are not disconnected.",
      input: PROFILE_UPDATE_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw) => {
        const input = asRecord(raw);
        const profile = await dependencies.profiles.update(
          requireString(input.profile_id, "profile_id"),
          {
            ...(input.name !== undefined
              ? { name: requireString(input.name, "name") }
              : {}),
            ...(input.user !== undefined
              ? { user: requireString(input.user, "user") }
              : {}),
            ...(input.host !== undefined
              ? { host: requireString(input.host, "host") }
              : {}),
            ...(input.port !== undefined
              ? { port: requireInteger(input.port, "port") }
              : {}),
            ...(input.password !== undefined
              ? { password: requireString(input.password, "password") }
              : {}),
            ...(input.private_key_path !== undefined
              ? {
                  privateKeyPath: requireString(
                    input.private_key_path,
                    "private_key_path",
                  ),
                }
              : {}),
            ...(input.private_key_passphrase !== undefined
              ? {
                  privateKeyPassphrase: requireString(
                    input.private_key_passphrase,
                    "private_key_passphrase",
                  ),
                }
              : {}),
            ...(input.sudo_password !== undefined
              ? {
                  sudoPassword: requireString(
                    input.sudo_password,
                    "sudo_password",
                  ),
                }
              : {}),
            ...(input.host_key_policy !== undefined
              ? { hostKeyPolicy: asHostKeyPolicy(input.host_key_policy) }
              : {}),
            ...(input.clear_password !== undefined
              ? {
                  clearPassword: requireBoolean(
                    input.clear_password,
                    "clear_password",
                  ),
                }
              : {}),
            ...(input.clear_private_key_path !== undefined
              ? {
                  clearPrivateKeyPath: requireBoolean(
                    input.clear_private_key_path,
                    "clear_private_key_path",
                  ),
                }
              : {}),
            ...(input.clear_private_key_passphrase !== undefined
              ? {
                  clearPrivateKeyPassphrase: requireBoolean(
                    input.clear_private_key_passphrase,
                    "clear_private_key_passphrase",
                  ),
                }
              : {}),
            ...(input.clear_sudo_password !== undefined
              ? {
                  clearSudoPassword: requireBoolean(
                    input.clear_sudo_password,
                    "clear_sudo_password",
                  ),
                }
              : {}),
          },
        );

        dependencies.manager.markProfileStale(profile.id, profile.revision);
        return {
          content: formatProfile(profile, "SSH profile updated."),
          metadata: { profileId: profile.id, revision: profile.revision },
        };
      },
    },

    {
      name: "profile_remove",
      description:
        "Delete a saved SSH profile by profile_id. Active connections are not disconnected; they are marked stale and keep running existing work.",
      input: PROFILE_REMOVE_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw) => {
        const input = asRecord(raw);
        const profileId = requireString(input.profile_id, "profile_id");
        const removed = await dependencies.profiles.remove(profileId);
        if (!removed) {
          throw new Error(`SSH profile not found: ${profileId}`);
        }
        dependencies.manager.markProfileStale(profileId);
        return {
          content: `SSH profile removed: ${profileId}`,
          metadata: { profileId },
        };
      },
    },

    {
      name: "profile_list",
      description:
        "List saved SSH profiles, including each current revision. Passwords, passphrases, and sudo passwords are never included. " +
        "sudo_password=yes only means a secret is stored, not that it is valid; sudo_password=no does not prove passwordless sudo.",
      input: PROFILE_LIST_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async () => {
        const profiles = await dependencies.profiles.list();
        if (profiles.length === 0) {
          return {
            content: "No saved SSH profiles.",
            metadata: { count: 0 },
          };
        }
        const lines = [`Saved SSH profiles (${profiles.length}):`];
        for (const profile of profiles) {
          const bits = [
            `- ${profile.id}`,
            `name=${profile.name}`,
            `${profile.user}@${profile.host}:${profile.port}`,
            `auth=${profile.auth}`,
          ];
          if (profile.privateKeyPath) {
            bits.push(`key=${profile.privateKeyPath}`);
          }
          if (profile.hasPrivateKeyPassphrase) bits.push("key_passphrase=yes");
          if (profile.hasSudoPassword) bits.push("sudo_password=yes");
          bits.push(`revision=${profile.revision}`);
          bits.push(`host_key_policy=${profile.hostKeyPolicy}`);
          lines.push(bits.join("  "));
        }
        return {
          content: lines.join("\n"),
          metadata: { count: profiles.length },
        };
      },
    },
  ];
}

function toToolError(
  error: unknown,
  fallbackCode: "SSH_INVALID_INPUT" | "SSH_INTERNAL_ERROR" = "SSH_INTERNAL_ERROR",
): never {
  if (error instanceof SshOperationError) {
    const metadata: Record<string, unknown> = {
      errorCode: error.code,
      retryable: error.retryable,
      hint: error.hint,
      executionMayHaveStarted: error.executionMayHaveStarted,
    };
    if (error.recommendedNextTool !== undefined) {
      metadata.recommendedNextTool = error.recommendedNextTool;
    }
    // Code Mode surfaces the error message but not always the metadata, so
    // repeat the recovery fields in text as well.
    const message = [
      error.message,
      "",
      `error_code: ${error.code}`,
      `retryable: ${error.retryable ? "yes" : "no"}`,
      `execution_may_have_started: ${error.executionMayHaveStarted ? "yes" : "no"}`,
      `hint: ${error.hint}`,
      ...(error.recommendedNextTool !== undefined
        ? [`recommended_next_tool: ${error.recommendedNextTool}`]
        : []),
    ].join("\n");
    throw new ToolError({ message, metadata });
  }

  const invalid = fallbackCode === "SSH_INVALID_INPUT";
  const hint = invalid
    ? "Fix the tool input and retry."
    : "Unexpected SSH plugin error; re-check the connection and inputs.";
  throw new ToolError({
    message: [
      errorMessage(error),
      "",
      `error_code: ${fallbackCode}`,
      `retryable: ${invalid ? "no" : "yes"}`,
      "execution_may_have_started: no",
      `hint: ${hint}`,
    ].join("\n"),
    metadata: {
      errorCode: fallbackCode,
      retryable: !invalid,
      hint,
      executionMayHaveStarted: false,
    },
  });
}

function formatConnection(info: ConnectionInfo, title: string): string {
  const lines = [
    title,
    `ssh_id: ${info.id}`,
    `target: ${info.user}@${info.host}:${info.port}`,
    `name: ${info.name}`,
    `auth: ${info.authMethod}`,
  ];
  if (info.profileId) lines.push(`profile_id: ${info.profileId}`);
  if (info.profileRevision !== undefined) {
    lines.push(`profile_revision: ${info.profileRevision}`);
  }
  if (info.stale) lines.push("stale: yes");
  if (info.hostKeyFingerprint) {
    lines.push(`host_key: ${info.hostKeyFingerprint}`);
  }
  return lines.join("\n");
}

function connectionMetadata(info: ConnectionInfo): Record<string, unknown> {
  return {
    sshId: info.id,
    user: info.user,
    host: info.host,
    port: info.port,
    authMethod: info.authMethod,
    reused: info.reused === true,
    ...(info.profileId ? { profileId: info.profileId } : {}),
    ...(info.profileRevision !== undefined
      ? { profileRevision: info.profileRevision }
      : {}),
    ...(info.stale ? { stale: true } : {}),
    ...(info.hostKeyFingerprint
      ? { hostKeyFingerprint: info.hostKeyFingerprint }
      : {}),
  };
}

function formatProfile(
  profile: {
    id: string;
    name: string;
    user: string;
    host: string;
    port: number;
    auth: string;
    privateKeyPath?: string;
    hasSudoPassword: boolean;
    hostKeyPolicy: string;
    revision: number;
  },
  title: string,
): string {
  const lines = [
    title,
    `profile_id: ${profile.id}`,
    `name: ${profile.name}`,
    `target: ${profile.user}@${profile.host}:${profile.port}`,
    `auth: ${profile.auth}`,
  ];
  if (profile.privateKeyPath) lines.push(`key: ${profile.privateKeyPath}`);
  lines.push(`sudo_password: ${profile.hasSudoPassword ? "yes" : "no"}`);
  lines.push(`revision: ${profile.revision}`);
  lines.push(`host_key_policy: ${profile.hostKeyPolicy}`);
  return lines.join("\n");
}

async function resolveTargetPath(
  manager: ConnectionManager,
  sshId: string,
  value: unknown,
): Promise<string> {
  const home = await manager.homeDir(sshId);
  return resolveRemotePath(requireString(value, "path"), home);
}

async function assertPathPermission(
  dependencies: ToolDependencies,
  context: ExecuteContext,
  sshId: string,
  target: string,
): Promise<void> {
  if (!dependencies.assertPermission) return;
  const connection = dependencies.manager.getInfo(sshId);
  await dependencies.assertPermission({
    sessionID: context.sessionID,
    agent: context.agent,
    messageID: context.messageID,
    toolCallID: context.id,
    resource: `${connection.user}@${connection.host}:${target}`,
  });
}

async function assertHostPermission(
  dependencies: ToolDependencies,
  context: ExecuteContext,
  sshId: string,
): Promise<void> {
  if (!dependencies.assertPermission) return;
  const connection = dependencies.manager.getInfo(sshId);
  await dependencies.assertPermission({
    sessionID: context.sessionID,
    agent: context.agent,
    messageID: context.messageID,
    toolCallID: context.id,
    resource: `${connection.user}@${connection.host}:${connection.port}`,
  });
}

function formatJobInfo(info: JobInfo): string {
  const lines = [
    `job: ${info.jobId}`,
    ...(info.name !== undefined ? [`name: ${info.name}`] : []),
    `state: ${info.state}`,
    ...(info.pid !== undefined ? [`pid: ${info.pid}`] : []),
    `exit_code: ${info.exitCode === undefined ? "(none)" : info.exitCode}`,
    ...(info.startedAt !== undefined ? [`started_at: ${info.startedAt}`] : []),
    ...(info.elapsedMs !== undefined
      ? [`elapsed: ${formatDuration(info.elapsedMs)}`]
      : []),
    ...(info.command !== undefined ? [`command: ${info.command}`] : []),
    `job_dir: ${info.jobDir}`,
    `log: ${info.logPath}`,
  ];

  if (info.logUnavailable === true) {
    lines.push("", "[logs] unavailable");
  } else if (info.log !== undefined) {
    lines.push("", "[last lines]", info.log.length > 0 ? info.log : "(empty)");
  }
  if (info.state === "finished" || info.state === "stopped" || info.state === "lost") {
    lines.push(
      "",
      "[note] Remove the job directory with ssh_remove when the logs are no longer needed.",
    );
  }
  return lines.join("\n");
}

function formatJobList(jobs: JobInfo[]): string {
  if (jobs.length === 0) return "No jobs found.";
  const lines = [`jobs: ${jobs.length}`];
  for (const job of jobs) {
    const bits = [job.jobId, job.state];
    if (job.name !== undefined) bits.push(`name=${job.name}`);
    if (job.exitCode !== undefined) bits.push(`exit=${job.exitCode}`);
    if (job.startedAt !== undefined) bits.push(`started=${job.startedAt}`);
    bits.push(job.jobDir);
    lines.push(`- ${bits.join("  ")}`);
  }
  return lines.join("\n");
}

function formatReadResult(result: ReadRemoteFileResult): string {
  const lines = [
    `path: ${result.path}`,
    `size: ${result.size}`,
    `bytes: ${result.byteStart}-${result.byteEnd} (end exclusive)`,
    result.sha256 === null
      ? "sha256: unavailable (partial file window)"
      : `sha256: ${result.sha256}`,
    `line_endings: ${result.lineEndings}`,
    `binary: ${result.binary ? "yes" : "no"}`,
    `truncated: ${result.truncated ? "yes" : "no"}`,
    result.lineNumbers
      ? result.totalLines === null
        ? `lines: ${result.startLine}-${result.endLine} of unknown`
        : `lines: ${result.startLine}-${result.endLine} of ${result.totalLines}`
      : "line numbers: unavailable (byte-offset window)",
    "",
  ];
  if (result.binary) {
    lines.push(
      "[binary file] Content is not shown. Use ssh_exec with a dedicated tool if you need bytes.",
    );
    return lines.join("\n");
  }
  if (result.lines.length === 0) {
    lines.push("(empty)");
    return lines.join("\n");
  }
  for (const line of result.lines) {
    lines.push(
      result.lineNumbers ? `${line.number}: ${line.text}` : line.text,
    );
  }
  if (result.truncated) {
    const notes: string[] = [];
    if (result.byteEnd < result.size) {
      notes.push(
        `Read more with byte_offset=${result.byteEnd} or raise max_bytes.`,
      );
    }
    if (
      result.lineNumbers &&
      result.totalLines !== null &&
      result.endLine < result.totalLines
    ) {
      notes.push("Read more with offset/limit.");
    }
    if (notes.length === 0) {
      notes.push("Raise max_bytes or limit to read more.");
    }
    lines.push("", `[note] ${notes.join(" ")}`);
  }
  return lines.join("\n");
}

function formatExec(result: ExecResult): string {
  const stdoutBytes =
    result.stdoutBytes ?? Buffer.byteLength(result.stdout, "utf8");
  const stderrBytes =
    result.stderrBytes ?? Buffer.byteLength(result.stderr, "utf8");
  const stdoutRetained = Buffer.byteLength(result.stdout, "utf8");
  const stderrRetained = Buffer.byteLength(result.stderr, "utf8");
  const stdoutTruncated = result.stdoutTruncated ?? result.truncated;
  const stderrTruncated = result.stderrTruncated ?? result.truncated;
  const lines: Array<string | undefined> = [
    `exit_code: ${result.exitCode === null ? "unknown" : result.exitCode}`,
    `duration_ms: ${result.durationMs}`,
    `stdout: ${stdoutBytes} bytes, retained ${stdoutRetained}, truncated: ${stdoutTruncated ? "yes" : "no"}`,
    `stderr: ${stderrBytes} bytes, retained ${stderrRetained}, truncated: ${stderrTruncated ? "yes" : "no"}`,
    result.signal ? `signal: ${result.signal}` : undefined,
    "",
    "[stdout]",
    result.stdout.length > 0 ? trimTrailingNewlines(result.stdout) : "(empty)",
    "",
    "[stderr]",
    result.stderr.length > 0 ? trimTrailingNewlines(result.stderr) : "(empty)",
  ];
  if (stdoutTruncated || stderrTruncated) {
    lines.push(
      "",
      "[note] Output exceeded the capture limit. The beginning and end are shown; the middle was omitted. Raise max_output_bytes if needed.",
    );
  }
  return lines.filter(isDefined).join("\n");
}

function trimTrailingNewlines(value: string): string {
  return value.replace(/[\r\n]+$/, "");
}

function formatDuration(milliseconds: number): string {
  const seconds = Math.max(0, Math.round(milliseconds / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (minutes < 60) return `${minutes}m${remainder}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h${minutes % 60}m`;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Tool input must be an object.");
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${field} must be a non-empty string.`);
  }
  return value;
}

function optionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") {
    throw new Error("Expected a string value.");
  }
  return value.length > 0 ? value : undefined;
}

function requireInteger(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new Error(`${field} must be an integer.`);
  }
  return value;
}

function requireBoolean(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`${field} must be a boolean.`);
  }
  return value;
}

function asStringRecord(
  value: unknown,
  field: string,
): Record<string, string> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${field} must be an object of string values.`);
  }
  const result: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry !== "string") {
      throw new Error(`${field}.${key} must be a string.`);
    }
    result[key] = entry;
  }
  return result;
}

function asHostKeyPolicy(value: unknown): "accept-new" | "strict" | "insecure" {
  if (value === "accept-new" || value === "strict" || value === "insecure") {
    return value;
  }
  throw new Error("host_key_policy must be accept-new, strict, or insecure.");
}

function isDefined(value: string | undefined): value is string {
  return value !== undefined;
}
