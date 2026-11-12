import type { ResolvedConfig } from "../config.js";
import type { ProfileStore } from "../profiles.js";
import type {
  ConnectionInfo,
  ConnectionManager,
  ExecResult,
} from "../ssh/manager.js";
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
