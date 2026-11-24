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
  /** Poll interval for watch targets. */
  watchIntervalMs?: number;
  /** Maximum backoff interval for a watch whose target is unreachable. */
  watchMaxIntervalMs?: number;
  /** Consecutive probe failures before a watch reports the target as lost. */
  watchMaxFailures?: number;
  /** How long detached or terminal watches are retained for inspection. */
  watchTtlMs?: number;
  /** Maximum bytes scanned from a remote log per poll. */
  watchLogScanBytes?: number;
  /** Default readiness timeout for service targets. */
  watchReadyTimeoutMs?: number;
  /** Default readiness probe interval for service targets. */
  watchReadyIntervalMs?: number;
  /** Time a readiness probe must stay successful before a target is ready. */
  watchReadyStableMs?: number;
}

export interface ResolvedConfig {
  dataDir: string;
  idleTimeoutMs: number;
  maxOutputBytes: number;
  connectTimeoutMs: number;
  execTimeoutMs: number;
  keepaliveIntervalMs: number;
  hostKeyPolicy: HostKeyPolicy;
  watchIntervalMs: number;
  watchMaxIntervalMs: number;
  watchMaxFailures: number;
  watchTtlMs: number;
  watchLogScanBytes: number;
  watchReadyTimeoutMs: number;
  watchReadyIntervalMs: number;
  watchReadyStableMs: number;
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
    watchIntervalMs: numberOption(
      options,
      "watchIntervalMs",
      5_000,
      100,
      5 * 60 * 1000,
    ),
    watchMaxIntervalMs: numberOption(
      options,
      "watchMaxIntervalMs",
      60_000,
      1_000,
      60 * 60 * 1000,
    ),
    watchMaxFailures: numberOption(options, "watchMaxFailures", 5, 1, 100),
    watchTtlMs: numberOption(
      options,
      "watchTtlMs",
      30 * 60 * 1000,
      60 * 1000,
      7 * 24 * 60 * 60 * 1000,
    ),
    watchLogScanBytes: numberOption(
      options,
      "watchLogScanBytes",
      256 * 1024,
      4 * 1024,
      8 * 1024 * 1024,
    ),
    watchReadyTimeoutMs: numberOption(
      options,
      "watchReadyTimeoutMs",
      20 * 60 * 1000,
      1_000,
      24 * 60 * 60 * 1000,
    ),
    watchReadyIntervalMs: numberOption(
      options,
      "watchReadyIntervalMs",
      5_000,
      100,
      5 * 60 * 1000,
    ),
    watchReadyStableMs: numberOption(
      options,
      "watchReadyStableMs",
      5_000,
      0,
      10 * 60 * 1000,
    ),
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
