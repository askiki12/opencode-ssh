import { homedir } from "node:os";
import path from "node:path";
import type { HostKeyPolicy } from "./profiles.js";

export interface SshPluginOptions {
  /** Override the directory used for profiles, keys, and known hosts. */
  dataDir?: string;
  /** Disconnect connections that have been idle for this long. 0 disables it. */
  idleTimeoutMs?: number;
  /** Maximum bytes returned from each of stdout and stderr. */
  maxOutputBytes?: number;
  /** SSH handshake timeout. */
  connectTimeoutMs?: number;
  /** Default per-command timeout. */
  execTimeoutMs?: number;
  /** SSH-level keepalive interval. */
  keepaliveIntervalMs?: number;
  /** Default policy for unknown host keys. */
  hostKeyPolicy?: HostKeyPolicy;
  /** Notify the session when a job finishes, becomes ready, or times out. */
  jobNotify?: boolean;
  /** Initial interval for job status checks. */
  jobNotifyIntervalMs?: number;
  /** Number of output.log lines included in job notifications. */
  jobNotifyLogLines?: number;
  /** Default readiness probe interval for service jobs. */
  jobReadyIntervalMs?: number;
  /** Default time allowed for a service job to become ready. */
  jobReadyTimeoutMs?: number;
  /** Time a readiness probe must stay successful before the job is ready. */
  jobReadyStableMs?: number;
  /** Default: keep watching a ready service for an unexpected exit. */
  jobWatchAfterReady?: boolean;
}

export interface ResolvedConfig {
  dataDir: string;
  idleTimeoutMs: number;
  maxOutputBytes: number;
  connectTimeoutMs: number;
  execTimeoutMs: number;
  keepaliveIntervalMs: number;
  hostKeyPolicy: HostKeyPolicy;
  jobNotify: boolean;
  jobNotifyIntervalMs: number;
  jobNotifyLogLines: number;
  jobReadyIntervalMs: number;
  jobReadyTimeoutMs: number;
  jobReadyStableMs: number;
  jobWatchAfterReady: boolean;
}

const POLICIES: ReadonlySet<string> = new Set(["accept-new", "strict", "insecure"]);

export function resolveConfig(
  options: Readonly<Record<string, unknown>>,
  baseDirectory: string,
): ResolvedConfig {
  const dataDirValue =
    stringOption(options, "dataDir") ??
    process.env.OPENCODE_SSH_HOME ??
    defaultDataDir();

  const hostKeyPolicy = stringOption(options, "hostKeyPolicy") ?? "accept-new";
  if (!POLICIES.has(hostKeyPolicy)) {
    throw new Error(
      `Invalid hostKeyPolicy "${hostKeyPolicy}". Use accept-new, strict, or insecure.`,
    );
  }

  return {
    dataDir: path.isAbsolute(dataDirValue)
      ? path.normalize(dataDirValue)
      : path.resolve(baseDirectory, expandHome(dataDirValue)),
    idleTimeoutMs: numberOption(options, "idleTimeoutMs", 0, 0, 24 * 60 * 60 * 1000),
    maxOutputBytes: numberOption(
      options,
      "maxOutputBytes",
      256 * 1024,
      1024,
      16 * 1024 * 1024,
    ),
    connectTimeoutMs: numberOption(
      options,
      "connectTimeoutMs",
      20_000,
      3_000,
      120_000,
    ),
    execTimeoutMs: numberOption(
      options,
      "execTimeoutMs",
      120_000,
      1_000,
      60 * 60 * 1000,
    ),
    keepaliveIntervalMs: numberOption(
      options,
      "keepaliveIntervalMs",
      15_000,
      0,
      10 * 60 * 1000,
    ),
    hostKeyPolicy: hostKeyPolicy as HostKeyPolicy,
    jobNotify: booleanOption(options, "jobNotify", true),
    jobNotifyIntervalMs: numberOption(
      options,
      "jobNotifyIntervalMs",
      5_000,
      500,
      5 * 60 * 1000,
    ),
    jobNotifyLogLines: numberOption(
      options,
      "jobNotifyLogLines",
      40,
      0,
      500,
    ),
    jobReadyIntervalMs: numberOption(
      options,
      "jobReadyIntervalMs",
      5_000,
      500,
      5 * 60 * 1000,
    ),
    jobReadyTimeoutMs: numberOption(
      options,
      "jobReadyTimeoutMs",
      20 * 60 * 1000,
      1_000,
      24 * 60 * 60 * 1000,
    ),
    jobReadyStableMs: numberOption(
      options,
      "jobReadyStableMs",
      5_000,
      0,
      10 * 60 * 1000,
    ),
    jobWatchAfterReady: booleanOption(options, "jobWatchAfterReady", false),
  };
}

export function defaultDataDir(): string {
  if (process.platform === "win32" && process.env.APPDATA) {
    return path.join(process.env.APPDATA, "opencode-ssh");
  }
  if (process.env.XDG_CONFIG_HOME) {
    return path.join(process.env.XDG_CONFIG_HOME, "opencode-ssh");
  }
  return path.join(homedir(), ".config", "opencode-ssh");
}

function expandHome(value: string): string {
  let result = value;
  if (result === "~") return homedir();
  if (result.startsWith("~/") || result.startsWith("~\\")) {
    result = path.join(homedir(), result.slice(2));
  }
  return result.replace(
    /%([^%]+)%/g,
    (match, name: string) => process.env[name] ?? match,
  );
}

function stringOption(
  options: Readonly<Record<string, unknown>>,
  key: string,
): string | undefined {
  const value = options[key];
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : undefined;
}

function booleanOption(
  options: Readonly<Record<string, unknown>>,
  key: string,
  fallback: boolean,
): boolean {
  const value = options[key];
  return typeof value === "boolean" ? value : fallback;
}

function numberOption(
  options: Readonly<Record<string, unknown>>,
  key: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const value = options[key];
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  return Math.min(maximum, Math.max(minimum, Math.trunc(value)));
}
