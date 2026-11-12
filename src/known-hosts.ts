import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import path from "node:path";
import type { HostKeyPolicy } from "./profiles.js";
import { nowIso } from "./util.js";

interface KnownHostEntry {
  fingerprint: string;
  firstSeen: string;
  lastSeen: string;
}

interface KnownHostsDocument {
  version: 1;
  hosts: Record<string, KnownHostEntry>;
}

/**
 * A small trust-on-first-use known-hosts store. It is intentionally separate
 * from OpenSSH's known_hosts file so the plugin can report clear fingerprints
 * without parsing hashed OpenSSH entries.
 */
export class KnownHostsStore {
  private lastError: string | undefined;

  constructor(private readonly filePath: string) {}

  /**
   * @param fingerprintHex hex SHA-256 digest of the host key, as provided by ssh2
   * when `hostHash: "sha256"` is configured.
   */
  verify(
    host: string,
    port: number,
    fingerprintHex: string,
    policy: HostKeyPolicy,
  ): boolean {
    this.lastError = undefined;
    const key = hostKey(host, port);
    const fingerprint = fingerprintFromHex(fingerprintHex);

    if (policy === "insecure") return true;

    const document = this.read();
    const existing = document.hosts[key];

    if (!existing) {
      if (policy === "strict") {
        this.lastError =
          `Unknown SSH host key for ${key} (${fingerprint}). ` +
          `Add it first with host_key_policy "accept-new" or connect without strict mode.`;
        return false;
      }
      document.hosts[key] = {
        fingerprint,
        firstSeen: nowIso(),
        lastSeen: nowIso(),
      };
      this.write(document);
      return true;
    }

    if (existing.fingerprint !== fingerprint) {
      this.lastError =
        `SSH HOST KEY MISMATCH for ${key}. ` +
        `Expected ${existing.fingerprint}, received ${fingerprint}. ` +
        `This can indicate a man-in-the-middle attack or a legitimate server key change. ` +
        `Refusing to connect. Remove the entry from ${this.filePath} only after verifying the new key.`;
      return false;
    }

    existing.lastSeen = nowIso();
    try {
      this.write(document);
    } catch {
      // Updating lastSeen is advisory; do not block a verified connection.
    }
    return true;
  }

  takeError(): string | undefined {
    const error = this.lastError;
    this.lastError = undefined;
    return error;
  }

  private read(): KnownHostsDocument {
    if (!existsSync(this.filePath)) {
      return { version: 1, hosts: {} };
    }
    try {
      const parsed = JSON.parse(
        readFileSync(this.filePath, "utf8"),
      ) as KnownHostsDocument;
      if (
        parsed.version !== 1 ||
        typeof parsed.hosts !== "object" ||
        parsed.hosts === null ||
        Array.isArray(parsed.hosts)
      ) {
        throw new Error("unsupported known_hosts document");
      }
      return parsed;
    } catch (error) {
      throw new Error(
        `Unable to read SSH known hosts file ${this.filePath}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  private write(document: KnownHostsDocument): void {
    const directory = path.dirname(this.filePath);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const temporary = `${this.filePath}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
    writeFileSync(temporary, `${JSON.stringify(document, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    renameSync(temporary, this.filePath);
    try {
      chmodSync(this.filePath, 0o600);
    } catch {
      // Windows does not fully implement POSIX modes.
    }
  }
}

export function hostKey(host: string, port: number): string {
  const normalized = host.trim().toLowerCase();
  if (normalized.includes(":") && !normalized.startsWith("[")) {
    return `[${normalized}]:${port}`;
  }
  return `${normalized}:${port}`;
}

export function fingerprintFromHex(hex: string): string {
  const normalized = hex.trim();
  if (
    normalized.length > 0 &&
    normalized.length % 2 === 0 &&
    /^[0-9a-fA-F]+$/.test(normalized)
  ) {
    const base64 = Buffer.from(normalized, "hex")
      .toString("base64")
      .replace(/=+$/, "");
    return `SHA256:${base64}`;
  }
  return `SHA256:${normalized}`;
}
