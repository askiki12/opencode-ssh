import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { expandPath } from "./util.js";

/**
 * Secrets are stored as AES-256-GCM envelopes. The ciphertext is bound to the
 * profile id and field name through the AAD, so moving a ciphertext from one
 * profile field to another fails authentication.
 */
export interface SealedSecret {
  v: 1;
  iv: string;
  tag: string;
  data: string;
}

const ALGORITHM = "aes-256-gcm";
const KEY_BYTES = 32;
const IV_BYTES = 12;
const SALT_BYTES = 16;

export class SecretBox {
  private cachedKey: Buffer | undefined;

  constructor(private readonly dataDir: string) {}

  seal(plaintext: string, aad: string): SealedSecret {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(ALGORITHM, this.key(), iv);
    cipher.setAAD(Buffer.from(aad, "utf8"));
    const data = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return {
      v: 1,
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      data: data.toString("base64"),
    };
  }

  open(sealed: SealedSecret, aad: string): string {
    if (!SecretBox.isSealed(sealed)) {
      throw new Error("Stored secret is not a valid encrypted value.");
    }
    try {
      const iv = Buffer.from(sealed.iv, "base64");
      const tag = Buffer.from(sealed.tag, "base64");
      const data = Buffer.from(sealed.data, "base64");
      const decipher = createDecipheriv(ALGORITHM, this.key(), iv);
      decipher.setAAD(Buffer.from(aad, "utf8"));
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
    } catch {
      throw new Error(
        "Unable to decrypt a stored SSH secret. The master key may have changed " +
          "(for example OPENCODE_SSH_MASTER_KEY was modified). Re-add the affected profile.",
      );
    }
  }

  static isSealed(value: unknown): value is SealedSecret {
    if (typeof value !== "object" || value === null) return false;
    const record = value as Record<string, unknown>;
    return (
      record.v === 1 &&
      typeof record.iv === "string" &&
      typeof record.tag === "string" &&
      typeof record.data === "string"
    );
  }

  private key(): Buffer {
    if (this.cachedKey) return this.cachedKey;

    const masterPassphrase = process.env.OPENCODE_SSH_MASTER_KEY;
    if (masterPassphrase && masterPassphrase.length > 0) {
      this.cachedKey = this.deriveKey(masterPassphrase, this.salt());
      return this.cachedKey;
    }

    const keyFile = process.env.OPENCODE_SSH_KEY_FILE
      ? expandPath(process.env.OPENCODE_SSH_KEY_FILE)
      : path.join(this.dataDir, "master.key");

    if (existsSync(keyFile)) {
      this.cachedKey = parseKeyMaterial(readFileSync(keyFile), keyFile);
      return this.cachedKey;
    }

    mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o700 });
    const key = randomBytes(KEY_BYTES);
    try {
      writeFileSync(keyFile, `${key.toString("hex")}\n`, {
        flag: "wx",
        mode: 0o600,
      });
    } catch (error) {
      if (isEexist(error)) {
        this.cachedKey = parseKeyMaterial(readFileSync(keyFile), keyFile);
        return this.cachedKey;
      }
      throw error;
    }
    restrictPermissions(keyFile);
    this.cachedKey = key;
    return key;
  }

  private salt(): Buffer {
    const saltFile = path.join(this.dataDir, "master.salt");
    if (existsSync(saltFile)) {
      const salt = Buffer.from(readFileSync(saltFile, "utf8").trim(), "hex");
      if (salt.length !== SALT_BYTES) {
        throw new Error(`Invalid master salt file: ${saltFile}`);
      }
      return salt;
    }
    mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    const salt = randomBytes(SALT_BYTES);
    try {
      writeFileSync(saltFile, `${salt.toString("hex")}\n`, {
        flag: "wx",
        mode: 0o600,
      });
    } catch (error) {
      if (isEexist(error)) {
        const existing = Buffer.from(
          readFileSync(saltFile, "utf8").trim(),
          "hex",
        );
        if (existing.length !== SALT_BYTES) {
          throw new Error(`Invalid master salt file: ${saltFile}`);
        }
        return existing;
      }
      throw error;
    }
    restrictPermissions(saltFile);
    return salt;
  }

  private deriveKey(passphrase: string, salt: Buffer): Buffer {
    return scryptSync(passphrase.normalize("NFKC"), salt, KEY_BYTES, {
      N: 32768,
      r: 8,
      p: 1,
      maxmem: 64 * 1024 * 1024,
    });
  }
}

function parseKeyMaterial(raw: Buffer, file: string): Buffer {
  const text = raw.toString("utf8").trim();
  if (/^[0-9a-fA-F]{64}$/.test(text)) return Buffer.from(text, "hex");
  if (text.length > 0) {
    const decoded = Buffer.from(text, "base64");
    if (decoded.length === KEY_BYTES) return decoded;
  }
  if (raw.length === KEY_BYTES) return Buffer.from(raw);
  throw new Error(
    `Invalid SSH secret master key in ${file}. Expected 32 raw bytes, 64 hex characters, or base64.`,
  );
}

function restrictPermissions(file: string): void {
  try {
    chmodSync(file, 0o600);
  } catch {
    // Windows does not fully implement POSIX modes. The key file still lives
    // inside the user's private application data directory.
  }
}

function isEexist(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "EEXIST"
  );
}
