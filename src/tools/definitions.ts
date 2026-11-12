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
  ExecResult,
} from "../ssh/manager.js";
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
        "Password used when ssh_exec requests sudo or switches users. Stored encrypted in a profile, or kept in memory for an inline connection.",
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
        "Run through sudo, using the connection's sudo password when one is available.",
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
        "Allocate a remote PTY. Use for commands that require a terminal; sudo is retried with a PTY automatically when needed.",
    },
    max_output_bytes: {
      type: "integer",
      minimum: 1024,
      maximum: 16777216,
      description:
        "Maximum bytes captured from each of stdout and stderr. Output beyond this is truncated.",
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
      description: "First line to return, 1-based. Defaults to 1.",
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
      description: `Maximum bytes to read from the file. Defaults to ${DEFAULT_READ_BYTES}.`,
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
      description: "Directory to search. Defaults to the remote home directory.",
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
      description: "File or directory to search. Defaults to the remote home directory.",
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
        "Password used for sudo and user switching. Encrypted at rest.",
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
    sudo_password: { type: "string" },
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
        "By default this tool REUSES an active connection for the same profile, or the same user@host:port when the sudo password is compatible, and returns the existing ssh_id. " +
        "Call ssh_list first if you need to inspect active connections. " +
        "Pass force_new=true only when the user explicitly wants a separate connection. " +
        "Provide either profile_id or inline user/host plus exactly one of password or private_key_path.",
      input: CONNECT_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw) => {
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
        "Secrets and passwords are never included.",
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
        "Set sudo=true to run through sudo, or as_user to switch users. " +
        "sudo uses the sudo password stored on the connection; the password is written to sudo's stdin, never to the command line.",
      input: EXEC_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw, context) => {
        const input = asRecord(raw);
        const sshId = requireString(input.ssh_id, "ssh_id");
        const command = requireString(input.command, "command");
        const connection = dependencies.manager.getInfo(sshId);

        if (dependencies.assertPermission) {
          await dependencies.assertPermission({
            sessionID: context.sessionID,
            agent: context.agent,
            messageID: context.messageID,
            toolCallID: context.id,
            resource: `${connection.user}@${connection.host}:${connection.port}`,
          });
        }

        const result = await dependencies.manager.exec(
          {
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
            ...(input.max_output_bytes !== undefined
              ? {
                  maxOutputBytes: requireInteger(
                    input.max_output_bytes,
                    "max_output_bytes",
                  ),
                }
              : {}),
          },
          context.signal,
        );

        return {
          content: formatExec(result),
          metadata: {
            sshId: result.sshId,
            exitCode: result.exitCode,
            signal: result.signal,
            durationMs: result.durationMs,
            truncated: result.truncated,
            stdoutBytes: Buffer.byteLength(result.stdout, "utf8"),
            stderrBytes: Buffer.byteLength(result.stderr, "utf8"),
          },
        };
      },
    },

    {
      name: "read",
      description:
        "Read a remote file with line numbers. Prefer this over ssh_exec cat for inspecting files: " +
        "it is binary-safe, supports offset/limit, and caps how many bytes are returned. " +
        "Paths must be absolute or start with ~/.",
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
        "or use ssh_edit for a targeted change. Paths must be absolute or start with ~/.",
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

        return {
          content: [
            result.created ? "Created remote file." : "Overwrote remote file.",
            `path: ${result.path}`,
            `bytes: ${result.bytes}`,
          ].join("\n"),
          metadata: { ...result },
        };
      },
    },

    {
      name: "edit",
      description:
        "Replace exact text in a remote file and write it atomically, preserving permissions. " +
        "old_text must occur exactly once unless replace_all is true; otherwise the edit fails " +
        "so an ambiguous change is never applied. Paths must be absolute or start with ~/.",
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
          },
        );

        return {
          content: [
            `Edited remote file: ${result.path}`,
            `replacements: ${result.replacements}`,
            "",
            ...result.preview.map((line) => `${line.number}: ${line.text}`),
          ].join("\n"),
          metadata: {
            path: result.path,
            replacements: result.replacements,
            firstLine: result.firstLine,
          },
        };
      },
    },

    {
      name: "glob",
      description:
        "Find remote files by glob pattern relative to a directory. " +
        "Uses ripgrep when available, then find, then an SFTP walk. " +
        "Default skips .git, node_modules, and hidden entries. " +
        "Prefer this over shelling out to find/glob through ssh_exec.",
      input: GLOB_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw) => {
        const input = asRecord(raw);
        const sshId = requireString(input.ssh_id, "ssh_id");
        const root =
          input.path === undefined
            ? await dependencies.manager.homeDir(sshId)
            : await resolveTargetPath(dependencies.manager, sshId, input.path);
        const result = await dependencies.search.glob(sshId, {
          pattern: requireString(input.pattern, "pattern"),
          path: root,
          ...(input.max_results !== undefined
            ? { maxResults: requireInteger(input.max_results, "max_results") }
            : {}),
          ...(input.include_hidden !== undefined
            ? { includeHidden: requireBoolean(input.include_hidden, "include_hidden") }
            : {}),
        });

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
        "Search remote file contents. Runs on the remote host with ripgrep when available, " +
        "otherwise grep; there is no line-by-line SFTP fallback because it is far slower. " +
        "If the remote lacks both tools, suggest installing ripgrep via ssh_exec and ask the user first. " +
        "Skips binary files; returns path, line number, and matching text up to max_matches.",
      input: GREP_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw) => {
        const input = asRecord(raw);
        const sshId = requireString(input.ssh_id, "ssh_id");
        const target =
          input.path === undefined
            ? await dependencies.manager.homeDir(sshId)
            : await resolveTargetPath(dependencies.manager, sshId, input.path);
        const result = await dependencies.search.grep(sshId, {
          pattern: requireString(input.pattern, "pattern"),
          path: target,
          ...(input.include !== undefined
            ? { include: requireString(input.include, "include") }
            : {}),
          ...(input.literal !== undefined
            ? { literal: requireBoolean(input.literal, "literal") }
            : {}),
          ...(input.case_sensitive !== undefined
            ? { caseSensitive: requireBoolean(input.case_sensitive, "case_sensitive") }
            : {}),
          ...(input.max_matches !== undefined
            ? { maxMatches: requireInteger(input.max_matches, "max_matches") }
            : {}),
        });

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
        "path-scoped permission prompt instead of running rm through ssh_exec.",
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
        "Symbolic links are rejected rather than followed.",
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
        const result = await transferPath(sftp, {
          direction,
          localPath: requireString(input.local_path, "local_path"),
          remotePath: target,
          ...(input.overwrite !== undefined
            ? { overwrite: requireBoolean(input.overwrite, "overwrite") }
            : {}),
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
      name: "profile_add",
      description:
        "Save a reusable SSH profile. Passwords and passphrases are encrypted at rest with AES-256-GCM. " +
        "Returns a profile_id for ssh_connect.",
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
          metadata: { profileId: profile.id },
        };
      },
    },

    {
      name: "profile_update",
      description:
        "Update an existing SSH profile. Only the provided fields change. Use clear_* flags to remove stored secrets.",
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

        return {
          content: formatProfile(profile, "SSH profile updated."),
          metadata: { profileId: profile.id },
        };
      },
    },

    {
      name: "profile_remove",
      description: "Delete a saved SSH profile by profile_id.",
      input: PROFILE_REMOVE_INPUT,
      options: { namespace: "ssh", codemode: true },
      execute: async (raw) => {
        const input = asRecord(raw);
        const profileId = requireString(input.profile_id, "profile_id");
        const removed = await dependencies.profiles.remove(profileId);
        if (!removed) {
          throw new Error(`SSH profile not found: ${profileId}`);
        }
        return {
          content: `SSH profile removed: ${profileId}`,
          metadata: { profileId },
        };
      },
    },

    {
      name: "profile_list",
      description:
        "List saved SSH profiles. Passwords, passphrases, and sudo passwords are never included.",
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

function formatConnection(info: ConnectionInfo, title: string): string {
  const lines = [
    title,
    `ssh_id: ${info.id}`,
    `target: ${info.user}@${info.host}:${info.port}`,
    `name: ${info.name}`,
    `auth: ${info.authMethod}`,
  ];
  if (info.profileId) lines.push(`profile_id: ${info.profileId}`);
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

function formatReadResult(result: ReadRemoteFileResult): string {
  const lines = [
    `path: ${result.path}`,
    `size: ${result.size}`,
    `binary: ${result.binary ? "yes" : "no"}`,
    `truncated: ${result.truncated ? "yes" : "no"}`,
    result.totalLines === null
      ? "lines: unknown"
      : `lines: ${result.startLine}-${result.endLine} of ${result.totalLines}`,
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
    lines.push(`${line.number}: ${line.text}`);
  }
  if (result.truncated) {
    lines.push(
      "",
      "[note] Output was truncated. Read again with offset/limit or raise max_bytes.",
    );
  }
  return lines.join("\n");
}

function formatExec(result: ExecResult): string {
  const lines: Array<string | undefined> = [
    `exit_code: ${result.exitCode === null ? "unknown" : result.exitCode}`,
    `duration_ms: ${result.durationMs}`,
    `truncated: ${result.truncated ? "yes" : "no"}`,
    result.signal ? `signal: ${result.signal}` : undefined,
    "",
    "[stdout]",
    result.stdout.length > 0 ? trimTrailingNewlines(result.stdout) : "(empty)",
    "",
    "[stderr]",
    result.stderr.length > 0 ? trimTrailingNewlines(result.stderr) : "(empty)",
  ];
  if (result.truncated) {
    lines.push(
      "",
      "[note] Output exceeded the capture limit and was truncated. Use max_output_bytes to raise the limit.",
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
