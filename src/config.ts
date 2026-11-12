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
}

export interface ResolvedConfig {
  dataDir: string;
  idleTimeoutMs: number;
  maxOutputBytes: number;
  connectTimeoutMs: number;
  execTimeoutMs: number;
  keepaliveIntervalMs: number;
  hostKeyPolicy: HostKeyPolicy;
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
