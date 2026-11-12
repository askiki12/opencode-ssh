import { readFile } from "node:fs/promises";
import ssh2 from "ssh2";
import type {
  Client as SshClient,
  ClientChannel,
  ConnectConfig,
  SFTPWrapper,
} from "ssh2";
import type { ResolvedConfig } from "../config.js";
import { fingerprintFromHex, KnownHostsStore } from "../known-hosts.js";
import type {
  HostKeyPolicy,
  ProfileStore,
  ResolvedProfile,
} from "../profiles.js";
import {
  asError,
  errorMessage,
  expandPath,
  newId,
  OutputCollector,
} from "../util.js";
import {
  buildRemoteCommand,
  looksLikeMissingTty,
  looksLikeSudoPasswordFailure,
} from "./command.js";

const { Client } = ssh2;

export interface ConnectInput {
  profileId?: string;
  name?: string;
  user?: string;
  host?: string;
  port?: number;
  password?: string;
  privateKeyPath?: string;
  privateKeyPassphrase?: string;
  sudoPassword?: string;
  hostKeyPolicy?: HostKeyPolicy;
  /** Create a second connection even if an equivalent active connection exists. */
  forceNew?: boolean;
}

export interface ConnectionInfo {
  id: string;
  name: string;
  profileId?: string;
  user: string;
  host: string;
  port: number;
  authMethod: "password" | "privateKey";
  hostKeyFingerprint?: string;
  connectedAt: string;
  lastUsedAt: string;
  idleMs: number;
  busy: boolean;
  /** True when ssh_connect reused an existing active connection. */
  reused?: boolean;
  lastError?: string;
}

export interface ExecInput {
  sshId: string;
  command: string;
  sudo?: boolean;
  asUser?: string;
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  tty?: boolean;
  maxOutputBytes?: number;
}

export interface ExecResult {
  sshId: string;
  exitCode: number | null;
  signal?: string;
  stdout: string;
  stderr: string;
  durationMs: number;
  truncated: boolean;
}

interface ActiveConnection {
  id: string;
  client: SshClient;
  profileId?: string;
  name: string;
  user: string;
  host: string;
  port: number;
  authMethod: "password" | "privateKey";
  sudoPassword?: string;
  hostKeyFingerprint?: string;
  connectedAt: number;
  lastUsedAt: number;
  busy: number;
  lastError?: string;
  /** Lazily created SFTP subsystem channel, reused across file operations. */
  sftp?: SFTPWrapper | undefined;
  /** Cached remote home directory, used to expand "~" paths. */
  homeDir?: string | undefined;
}

interface RawExecResult {
  exitCode: number | null;
  signal?: string;
  stdout: string;
  stderr: string;
  truncated: boolean;
}

interface ExecOnceOptions {
  tty: boolean;
  timeoutMs: number;
  maxOutputBytes: number;
  usesSudo: boolean;
  signal?: AbortSignal;
}

export class ConnectionManager {
  private readonly connections = new Map<string, ActiveConnection>();
  private sweeper: NodeJS.Timeout | undefined;

  constructor(
    private readonly config: ResolvedConfig,
    private readonly profiles: ProfileStore,
    private readonly knownHosts: KnownHostsStore,
  ) {
    if (config.idleTimeoutMs > 0) {
      const interval = Math.max(5_000, Math.min(60_000, config.idleTimeoutMs / 2));
      this.sweeper = setInterval(() => this.sweepIdle(), interval);
      this.sweeper.unref();
    }
  }

  async connect(input: ConnectInput): Promise<ConnectionInfo> {
    const target = await this.resolveTarget(input);
    if (input.forceNew !== true) {
      const reusable = this.findReusable(target, input.profileId);
      if (reusable) return publicConnection(reusable, true);
    }

    const privateKey = target.privateKeyPath
      ? await readFile(expandPath(target.privateKeyPath)).catch((error: unknown) => {
          throw new Error(
            `Unable to read private key "${target.privateKeyPath}": ${errorMessage(error)}`,
          );
        })
      : undefined;

    const client = new Client();
    const id = newId("ssh");
    let fingerprintHex: string | undefined;
    let hostKeyError: string | undefined;
    let connection: ActiveConnection | undefined;

    client.on("error", (error: Error) => {
      if (connection) connection.lastError = errorMessage(error);
    });
    client.on("close", () => {
      this.connections.delete(id);
    });

    const hostVerifier = (key: unknown): boolean => {
      const raw =
        typeof key === "string"
          ? key
          : Buffer.from(key as Uint8Array).toString("hex");
      fingerprintHex = raw;
      const accepted = this.knownHosts.verify(
        target.host,
        target.port,
        raw,
        target.hostKeyPolicy,
      );
      if (!accepted) hostKeyError = this.knownHosts.takeError();
      return accepted;
    };

    const connectConfig: ConnectConfig = {
      host: target.host,
      port: target.port,
      username: target.user,
      readyTimeout: this.config.connectTimeoutMs,
      keepaliveInterval: this.config.keepaliveIntervalMs,
      keepaliveCountMax: 3,
      hostHash: "sha256",
      hostVerifier: hostVerifier as NonNullable<ConnectConfig["hostVerifier"]>,
    };

    if (target.password !== undefined) {
      connectConfig.password = target.password;
      connectConfig.tryKeyboard = true;
      client.on(
        "keyboard-interactive",
        (
          _name: string,
          _instructions: string,
          _language: string,
          prompts: unknown[],
          finish: (responses: string[]) => void,
        ) => {
          finish(prompts.map(() => target.password ?? ""));
        },
      );
    }
    if (privateKey !== undefined) connectConfig.privateKey = privateKey;
    if (target.privateKeyPassphrase !== undefined) {
      connectConfig.passphrase = target.privateKeyPassphrase;
    }

    await new Promise<void>((resolve, reject) => {
      let settled = false;

      const cleanup = () => {
        client.off("ready", onReady);
        client.off("error", onError);
        client.off("close", onClose);
      };
      const fail = (error: Error) => {
        if (settled) return;
        settled = true;
        cleanup();
        client.destroy();
        reject(hostKeyError ? new Error(hostKeyError) : error);
      };
      const onReady = () => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve();
      };
      const onError = (error: Error) => fail(asError(error));
      const onClose = () =>
        fail(
          new Error(
            `SSH connection to ${target.user}@${target.host}:${target.port} ` +
              "closed before authentication completed.",
          ),
        );

      client.once("ready", onReady);
      client.once("error", onError);
      client.once("close", onClose);

      try {
        client.connect(connectConfig);
      } catch (error) {
        fail(asError(error));
      }
    });

    const timestamp = Date.now();
    connection = {
      id,
      client,
      name: target.name,
      user: target.user,
      host: target.host,
      port: target.port,
      authMethod: privateKey !== undefined ? "privateKey" : "password",
      connectedAt: timestamp,
      lastUsedAt: timestamp,
      busy: 0,
    };
    if (target.id.length > 0) connection.profileId = target.id;
    if (target.sudoPassword !== undefined) {
      connection.sudoPassword = target.sudoPassword;
    }
    if (fingerprintHex !== undefined) {
      connection.hostKeyFingerprint = fingerprintFromHex(fingerprintHex);
    }

    this.connections.set(id, connection);
    return publicConnection(connection);
  }

  async disconnect(sshId: string): Promise<ConnectionInfo> {
    const connection = this.connections.get(sshId);
    if (!connection) {
      throw new Error(`No active SSH connection: ${sshId}`);
    }
    this.connections.delete(sshId);
    const info = publicConnection(connection);
    connection.client.end();
    const timer = setTimeout(() => connection.client.destroy(), 1_000);
    timer.unref();
    return info;
  }

  list(): ConnectionInfo[] {
    return [...this.connections.values()]
      .sort((left, right) => left.connectedAt - right.connectedAt)
      .map((connection) => publicConnection(connection));
  }

  getInfo(sshId: string): ConnectionInfo {
    const connection = this.connections.get(sshId);
    if (!connection) {
      throw new Error(`No active SSH connection: ${sshId}`);
    }
    return publicConnection(connection);
  }

  /**
   * Return a reusable SFTP subsystem channel for the connection. The channel is
   * created on first use and dropped when it closes, so a reconnect or channel
   * failure recovers automatically on the next file operation.
   */
  async sftp(sshId: string): Promise<SFTPWrapper> {
    const connection = this.connections.get(sshId);
    if (!connection) {
      throw new Error(`No active SSH connection: ${sshId}`);
    }
    if (connection.sftp) return connection.sftp;

    const wrapper = await new Promise<SFTPWrapper>((resolve, reject) => {
      connection.client.sftp((error, sftp) => {
        if (error) {
          reject(asError(error));
          return;
        }
        resolve(sftp);
      });
    });

    connection.sftp = wrapper;
    const invalidate = () => {
      if (connection.sftp === wrapper) connection.sftp = undefined;
    };
    wrapper.once("close", invalidate);
    wrapper.once("error", invalidate);
    return wrapper;
  }

  /** Resolve and cache the remote user's home directory via SFTP. */
  async homeDir(sshId: string): Promise<string> {
    const connection = this.connections.get(sshId);
    if (!connection) {
      throw new Error(`No active SSH connection: ${sshId}`);
    }
    if (connection.homeDir) return connection.homeDir;

    const sftp = await this.sftp(sshId);
    const home = await new Promise<string>((resolve, reject) => {
      sftp.realpath(".", (error, absolutePath) => {
        if (error) {
          reject(asError(error));
          return;
        }
        resolve(absolutePath);
      });
    });
    connection.homeDir = home;
    return home;
  }

  async exec(input: ExecInput, signal?: AbortSignal): Promise<ExecResult> {
    const connection = this.connections.get(input.sshId);
    if (!connection) {
      throw new Error(`No active SSH connection: ${input.sshId}`);
    }

    const command = requireText(input.command, "command");
    const timeoutMs = clamp(
      input.timeoutMs ?? this.config.execTimeoutMs,
      1_000,
      60 * 60 * 1000,
    );
    const maxOutputBytes = clamp(
      input.maxOutputBytes ?? this.config.maxOutputBytes,
      1_024,
      16 * 1024 * 1024,
    );
    const built = buildRemoteCommand({
      command,
      loginUser: connection.user,
      ...(input.cwd !== undefined ? { cwd: input.cwd } : {}),
      ...(input.env !== undefined ? { env: input.env } : {}),
      ...(input.sudo !== undefined ? { sudo: input.sudo } : {}),
      ...(input.asUser !== undefined ? { asUser: input.asUser } : {}),
    });

    const startedAt = Date.now();
    connection.busy += 1;
    connection.lastUsedAt = startedAt;
    try {
      let raw = await this.execOnce(connection, built.command, {
        tty: input.tty === true,
        timeoutMs,
        maxOutputBytes,
        usesSudo: built.usesSudo,
        ...(signal !== undefined ? { signal } : {}),
      });

      if (
        built.usesSudo &&
        input.tty !== true &&
        raw.exitCode !== 0 &&
        looksLikeMissingTty(raw.stderr)
      ) {
        raw = await this.execOnce(connection, built.command, {
          tty: true,
          timeoutMs,
          maxOutputBytes,
          usesSudo: true,
          ...(signal !== undefined ? { signal } : {}),
        });
      }

      let stderr = raw.stderr;
      if (built.usesSudo && connection.sudoPassword !== undefined) {
        // A PTY can echo terminal input depending on the remote sudo/terminal
        // configuration. Never return the sudo password even if it is echoed.
        raw.stdout = redactSecret(raw.stdout, connection.sudoPassword);
        stderr = redactSecret(stderr, connection.sudoPassword);
      }
      if (built.usesSudo && looksLikeSudoPasswordFailure(stderr)) {
        stderr +=
          connection.sudoPassword === undefined
            ? "\n[hint] sudo was requested but this connection has no sudo password. " +
              "Add sudoPassword to the profile or pass sudo_password to ssh_connect."
            : "\n[hint] The stored sudo password appears to be incorrect.";
      }

      const result: ExecResult = {
        sshId: connection.id,
        exitCode: raw.exitCode,
        stdout: raw.stdout,
        stderr,
        durationMs: Date.now() - startedAt,
        truncated: raw.truncated,
      };
      if (raw.signal !== undefined) result.signal = raw.signal;
      return result;
    } finally {
      connection.busy -= 1;
      connection.lastUsedAt = Date.now();
    }
  }

  async dispose(): Promise<void> {
    if (this.sweeper) {
      clearInterval(this.sweeper);
      this.sweeper = undefined;
    }
    for (const connection of this.connections.values()) {
      try {
        connection.client.end();
        connection.client.destroy();
      } catch {
        // Best effort during shutdown.
      }
    }
    this.connections.clear();
  }

  private execOnce(
    connection: ActiveConnection,
    command: string,
    options: ExecOnceOptions,
  ): Promise<RawExecResult> {
    return new Promise<RawExecResult>((resolve, reject) => {
      let settled = false;
      let stream: ClientChannel | undefined;
      let timer: NodeJS.Timeout | undefined;
      let abortListener: (() => void) | undefined;
      let clientCloseListener: (() => void) | undefined;
      let exitCode: number | null = null;
      let signalName: string | undefined;
      const stdout = new OutputCollector(options.maxOutputBytes);
      const stderr = new OutputCollector(options.maxOutputBytes);

      const cleanup = () => {
        if (timer !== undefined) clearTimeout(timer);
        if (abortListener !== undefined && options.signal !== undefined) {
          options.signal.removeEventListener("abort", abortListener);
        }
        if (clientCloseListener !== undefined) {
          connection.client.removeListener("close", clientCloseListener);
        }
      };
      const finish = (callback: () => void) => {
        if (settled) return;
        settled = true;
        cleanup();
        callback();
      };
      const fail = (error: Error) => {
        finish(() => {
          try {
            stream?.close();
          } catch {
            // Ignore channel teardown failures.
          }
          reject(error);
        });
      };

      if (options.signal !== undefined) {
        abortListener = () => fail(new Error("SSH command aborted."));
        if (options.signal.aborted) {
          abortListener();
          return;
        }
        options.signal.addEventListener("abort", abortListener, { once: true });
      }

      const execOptions = options.tty
        ? { pty: { term: "xterm-256color", cols: 120, rows: 40 } }
        : {};

      // Start the timeout before exec() so a dead connection cannot leave the
      // caller waiting forever for the channel callback.
      timer = setTimeout(() => {
        if (stream !== undefined) {
          try {
            stream.signal("KILL");
          } catch {
            // Channel may already be gone.
          }
        }
        fail(new Error(`SSH command timed out after ${options.timeoutMs} ms.`));
      }, options.timeoutMs);
      timer.unref();

      // A dropped connection must fail the command explicitly. Without this,
      // ssh2 may close the channel without an exit status and the caller would
      // receive a misleading "exit_code: unknown".
      clientCloseListener = () => {
        fail(
          new Error(
            `SSH connection to ${connection.user}@${connection.host}:${connection.port} ` +
              "was lost while the command was running.",
          ),
        );
      };
      connection.client.once("close", clientCloseListener);

      try {
        connection.client.exec(command, execOptions, (error, channel) => {
          if (settled) {
            channel?.close();
            return;
          }
          if (error) {
            fail(asError(error));
            return;
          }

          stream = channel;
          channel.on("data", (chunk: Buffer) => stdout.append(chunk));
          channel.stderr.on("data", (chunk: Buffer) => stderr.append(chunk));
          channel.on("exit", (code: number | null, signal?: string) => {
            exitCode = code;
            if (signal !== undefined) signalName = signal;
          });
          channel.on("close", () =>
            finish(() => {
              if (exitCode === null && signalName === undefined) {
                reject(
                  new Error(
                    "SSH command ended without an exit status; the connection to " +
                      `${connection.user}@${connection.host}:${connection.port} ` +
                      "may have dropped.",
                  ),
                );
                return;
              }
              const result: RawExecResult = {
                exitCode,
                stdout: stdout.text(),
                stderr: stderr.text(),
                truncated: stdout.truncated || stderr.truncated,
              };
              if (signalName !== undefined) result.signal = signalName;
              resolve(result);
            }),
          );
          channel.on("error", (channelError: Error) =>
            fail(asError(channelError)),
          );

          if (options.usesSudo && connection.sudoPassword !== undefined) {
            channel.write(
              `${connection.sudoPassword.replace(/[\r\n]+$/, "")}\n`,
            );
          }
          if (
            !options.tty ||
            (options.usesSudo && connection.sudoPassword === undefined)
          ) {
            channel.end();
          }
        });
      } catch (error) {
        fail(asError(error));
      }
    });
  }

  private sweepIdle(): void {
    const now = Date.now();
    for (const [id, connection] of this.connections) {
      if (connection.busy > 0) continue;
      if (now - connection.lastUsedAt < this.config.idleTimeoutMs) continue;
      this.connections.delete(id);
      try {
        connection.client.end();
      } catch {
        // Best effort.
      }
    }
  }

  private findReusable(
    target: ResolvedProfile,
    profileId: string | undefined,
  ): ActiveConnection | undefined {
    for (const connection of this.connections.values()) {
      if (profileId !== undefined) {
        if (connection.profileId !== profileId) continue;
      } else if (
        target.sudoPassword !== undefined &&
        connection.sudoPassword !== target.sudoPassword
      ) {
        // Reusing would silently use a different sudo password.
        continue;
      }

      if (connection.user !== target.user) continue;
      if (connection.host.toLowerCase() !== target.host.toLowerCase()) continue;
      if (connection.port !== target.port) continue;
      return connection;
    }
    return undefined;
  }

  private async resolveTarget(input: ConnectInput): Promise<ResolvedProfile> {
    if (input.profileId !== undefined) {
      if (
        input.name !== undefined ||
        input.user !== undefined ||
        input.host !== undefined ||
        input.port !== undefined ||
        input.password !== undefined ||
        input.privateKeyPath !== undefined ||
        input.privateKeyPassphrase !== undefined ||
        input.sudoPassword !== undefined ||
        input.hostKeyPolicy !== undefined
      ) {
        throw new Error(
          "When profile_id is provided, do not also provide inline connection fields.",
        );
      }
      return this.profiles.resolve(input.profileId);
    }

    const user = requireText(input.user ?? "", "user");
    const host = requireText(input.host ?? "", "host");
    const port = normalizePort(input.port);
    const password = input.password;
    const privateKeyPath = input.privateKeyPath;

    if ((password === undefined) === (privateKeyPath === undefined)) {
      throw new Error(
        "Provide exactly one of password or private_key_path for SSH authentication.",
      );
    }
    if (privateKeyPath === undefined && input.privateKeyPassphrase !== undefined) {
      throw new Error(
        "private_key_passphrase can only be used with private_key_path.",
      );
    }

    const target: ResolvedProfile = {
      id: "",
      name: input.name?.trim() || `${user}@${host}`,
      user,
      host,
      port,
      hostKeyPolicy: normalizePolicy(
        input.hostKeyPolicy,
        this.config.hostKeyPolicy,
      ),
    };
    if (password !== undefined) target.password = password;
    if (privateKeyPath !== undefined) target.privateKeyPath = privateKeyPath;
    if (input.privateKeyPassphrase !== undefined) {
      target.privateKeyPassphrase = input.privateKeyPassphrase;
    }
    if (input.sudoPassword !== undefined) {
      target.sudoPassword = input.sudoPassword;
    }
    return target;
  }
}

function publicConnection(
  connection: ActiveConnection,
  reused = false,
): ConnectionInfo {
  const info: ConnectionInfo = {
    id: connection.id,
    name: connection.name,
    user: connection.user,
    host: connection.host,
    port: connection.port,
    authMethod: connection.authMethod,
    connectedAt: new Date(connection.connectedAt).toISOString(),
    lastUsedAt: new Date(connection.lastUsedAt).toISOString(),
    idleMs: Date.now() - connection.lastUsedAt,
    busy: connection.busy > 0,
  };
  if (reused) info.reused = true;
  if (connection.profileId !== undefined) info.profileId = connection.profileId;
  if (connection.hostKeyFingerprint !== undefined) {
    info.hostKeyFingerprint = connection.hostKeyFingerprint;
  }
  if (connection.lastError !== undefined) info.lastError = connection.lastError;
  return info;
}

function requireText(value: string, field: string): string {
  const result = value.trim();
  if (result.length === 0) throw new Error(`${field} must not be empty.`);
  return result;
}

function normalizePort(value: number | undefined): number {
  const port = value ?? 22;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("port must be an integer between 1 and 65535.");
  }
  return port;
}

function normalizePolicy(
  value: HostKeyPolicy | undefined,
  fallback: HostKeyPolicy,
): HostKeyPolicy {
  if (value === undefined) return fallback;
  if (value !== "accept-new" && value !== "strict" && value !== "insecure") {
    throw new Error("host_key_policy must be accept-new, strict, or insecure.");
  }
  return value;
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, Math.trunc(value)));
}

function redactSecret(text: string, secret: string | undefined): string {
  if (secret === undefined) return text;
  const trimmed = secret.replace(/[\r\n]+$/, "");
  const candidates = new Set(
    [secret, trimmed].filter((value) => value.length >= 4),
  );
  let result = text;
  for (const candidate of candidates) {
    result = result.split(candidate).join("[redacted]");
  }
  return result;
}
