import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import path from "node:path";

/** Generate a short, readable identifier such as `ssh_1a2b3c4d5e6f`. */
export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(6).toString("hex")}`;
}

export function nowIso(): string {
  return new Date().toISOString();
}

/**
 * Expand a leading `~` and return an absolute path.
 * Relative paths are resolved against the process working directory.
 */
export function expandPath(value: string): string {
  let result = value.trim();
  if (result === "~") return homedir();
  if (result.startsWith("~/") || result.startsWith("~\\")) {
    result = path.join(homedir(), result.slice(2));
  }
  result = result.replace(
    /%([^%]+)%/g,
    (match, name: string) => process.env[name] ?? match,
  );
  return path.resolve(result);
}

export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

export function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(errorMessage(error));
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Collects a bounded amount of process output. Extra bytes are discarded and
 * flagged so callers can tell the model that output was truncated.
 */
export class OutputCollector {
  private readonly chunks: Buffer[] = [];
  private size = 0;
  private didTruncate = false;

  constructor(private readonly limitBytes: number) {}

  append(chunk: Buffer | string): void {
    const buffer = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
    if (this.size >= this.limitBytes) {
      this.didTruncate = true;
      return;
    }
    const remaining = this.limitBytes - this.size;
    if (buffer.length > remaining) {
      this.chunks.push(buffer.subarray(0, remaining));
      this.size = this.limitBytes;
      this.didTruncate = true;
      return;
    }
    this.chunks.push(buffer);
    this.size += buffer.length;
  }

  text(): string {
    return Buffer.concat(this.chunks).toString("utf8");
  }

  get truncated(): boolean {
    return this.didTruncate;
  }
}
