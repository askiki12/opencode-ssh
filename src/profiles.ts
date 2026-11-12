import { SecretBox, type SealedSecret } from "./crypto.js";
import { expandPath, newId, nowIso } from "./util.js";

const PROFILES_KEY = "profiles";
let mutationQueue: Promise<unknown> = Promise.resolve();

/** Minimal surface of OpenCode's plugin storage (SQLite-backed). */
export interface ProfileStorage {
  get(key: string): Promise<unknown>;
  set(key: string, value: any): Promise<void>;
  remove(key: string): Promise<void>;
}

export type HostKeyPolicy = "accept-new" | "strict" | "insecure";

export interface ProfileInput {
  name: string;
  user: string;
  host: string;
  port?: number;
  password?: string;
  privateKeyPath?: string;
  privateKeyPassphrase?: string;
  sudoPassword?: string;
  hostKeyPolicy?: HostKeyPolicy;
}

export interface ProfileUpdateInput {
  name?: string;
  user?: string;
  host?: string;
  port?: number;
  password?: string;
  privateKeyPath?: string;
  privateKeyPassphrase?: string;
  sudoPassword?: string;
  hostKeyPolicy?: HostKeyPolicy;
  clearPassword?: boolean;
  clearPrivateKeyPath?: boolean;
  clearPrivateKeyPassphrase?: boolean;
  clearSudoPassword?: boolean;
}

interface StoredProfile {
  id: string;
  name: string;
  user: string;
  host: string;
  port: number;
  password?: SealedSecret;
  privateKeyPath?: string;
  privateKeyPassphrase?: SealedSecret;
  sudoPassword?: SealedSecret;
  hostKeyPolicy: HostKeyPolicy;
  createdAt: string;
  updatedAt: string;
}

interface ProfilesDocument {
  version: 1;
  profiles: StoredProfile[];
}

export interface PublicProfile {
  id: string;
  name: string;
  user: string;
  host: string;
  port: number;
  auth: "password" | "privateKey";
  privateKeyPath?: string;
  hasPassword: boolean;
  hasPrivateKeyPassphrase: boolean;
  hasSudoPassword: boolean;
  hostKeyPolicy: HostKeyPolicy;
  createdAt: string;
  updatedAt: string;
}

/** A profile with its secrets decrypted, used only to establish a connection. */
export interface ResolvedProfile {
  id: string;
  name: string;
  user: string;
  host: string;
  port: number;
  password?: string;
  privateKeyPath?: string;
  privateKeyPassphrase?: string;
  sudoPassword?: string;
  hostKeyPolicy: HostKeyPolicy;
}

export class ProfileStore {
  constructor(
    private readonly storage: ProfileStorage,
    private readonly box: SecretBox,
  ) {}

  async list(): Promise<PublicProfile[]> {
    const document = await this.readDocument();
    return document.profiles.map(publicProfile);
  }

  /** Verify storage access at startup and create the initial document. */
  async ensureInitialized(): Promise<void> {
    const task = async () => {
      const value = await this.storage.get(PROFILES_KEY);
      if (value === undefined) {
        await this.storage.set(PROFILES_KEY, { version: 1, profiles: [] });
        return;
      }
      if (!isProfilesDocument(value)) {
        throw new Error(
          "Stored SSH profiles have an unsupported format. " +
            "Remove the plugin storage entry and add the profiles again.",
        );
      }
    };
    const next = mutationQueue.then(task, task);
    mutationQueue = next.catch(() => undefined);
    await next;
  }

  async add(input: ProfileInput): Promise<PublicProfile> {
    const name = requiredText(input.name, "name");
    const user = requiredText(input.user, "user");
    const host = requiredText(input.host, "host");
    const port = normalizePort(input.port);
    const hostKeyPolicy = normalizePolicy(input.hostKeyPolicy);
    const password = optionalSecret(input.password);
    const privateKeyPath = optionalText(input.privateKeyPath);
    const privateKeyPassphrase = optionalSecret(input.privateKeyPassphrase);
    const sudoPassword = optionalSecret(input.sudoPassword);

    assertAuth(password, privateKeyPath);
    if (privateKeyPassphrase !== undefined && privateKeyPath === undefined) {
      throw new Error(
        "privateKeyPassphrase can only be used with a private key path.",
      );
    }

    return this.mutate((document) => {
      if (
        document.profiles.some(
          (profile) => profile.name.toLowerCase() === name.toLowerCase(),
        )
      ) {
        throw new Error(`An SSH profile named "${name}" already exists.`);
      }
      const duplicate = document.profiles.find((profile) =>
        isEquivalentTarget(profile, {
          user,
          host,
          port,
          password,
          privateKeyPath,
        }),
      );
      if (duplicate) {
        throw new Error(
          `An equivalent SSH profile already exists: ${duplicate.name} ${duplicate.user}@${duplicate.host}:${duplicate.port}.`,
        );
      }

      const id = newId("prof");
      const timestamp = nowIso();
      const stored: StoredProfile = {
        id,
        name,
        user,
        host,
        port,
        hostKeyPolicy,
        createdAt: timestamp,
        updatedAt: timestamp,
      };
      if (password !== undefined) {
        stored.password = this.box.seal(password, secretAad(id, "password"));
      }
      if (privateKeyPath !== undefined) stored.privateKeyPath = privateKeyPath;
      if (privateKeyPassphrase !== undefined) {
        stored.privateKeyPassphrase = this.box.seal(
          privateKeyPassphrase,
          secretAad(id, "privateKeyPassphrase"),
        );
      }
      if (sudoPassword !== undefined) {
        stored.sudoPassword = this.box.seal(
          sudoPassword,
          secretAad(id, "sudoPassword"),
        );
      }

      document.profiles.push(stored);
      return publicProfile(stored);
    });
  }

  async update(id: string, patch: ProfileUpdateInput): Promise<PublicProfile> {
    if (patch.password !== undefined && patch.clearPassword) {
      throw new Error("Cannot set and clear the password in the same update.");
    }
    if (patch.privateKeyPath !== undefined && patch.clearPrivateKeyPath) {
      throw new Error(
        "Cannot set and clear privateKeyPath in the same update.",
      );
    }
    if (
      patch.privateKeyPassphrase !== undefined &&
      patch.clearPrivateKeyPassphrase
    ) {
      throw new Error(
        "Cannot set and clear privateKeyPassphrase in the same update.",
      );
    }
    if (patch.sudoPassword !== undefined && patch.clearSudoPassword) {
      throw new Error(
        "Cannot set and clear sudoPassword in the same update.",
      );
    }
    if (patch.password !== undefined && patch.privateKeyPath !== undefined) {
      throw new Error(
        "Provide either password or privateKeyPath, not both.",
      );
    }

    return this.mutate((document) => {
      const profile = document.profiles.find((candidate) => candidate.id === id);
      if (!profile) throw new Error(`SSH profile not found: ${id}`);

      if (patch.name !== undefined) {
        const name = requiredText(patch.name, "name");
        if (
          document.profiles.some(
            (candidate) =>
              candidate.id !== id &&
              candidate.name.toLowerCase() === name.toLowerCase(),
          )
        ) {
          throw new Error(`An SSH profile named "${name}" already exists.`);
        }
        profile.name = name;
      }
      if (patch.user !== undefined) {
        profile.user = requiredText(patch.user, "user");
      }
      if (patch.host !== undefined) {
        profile.host = requiredText(patch.host, "host");
      }
      if (patch.port !== undefined) profile.port = normalizePort(patch.port);
      if (patch.hostKeyPolicy !== undefined) {
        profile.hostKeyPolicy = normalizePolicy(patch.hostKeyPolicy);
      }

      if (patch.password !== undefined) {
        const password = optionalSecret(patch.password);
        if (password === undefined) {
          throw new Error("password cannot be empty; use clearPassword to remove it.");
        }
        profile.password = this.box.seal(
          password,
          secretAad(profile.id, "password"),
        );
        delete profile.privateKeyPath;
        delete profile.privateKeyPassphrase;
      }
      if (patch.privateKeyPath !== undefined) {
        const keyPath = optionalText(patch.privateKeyPath);
        if (keyPath === undefined) {
          throw new Error(
            "privateKeyPath cannot be empty; use clearPrivateKeyPath to remove it.",
          );
        }
        profile.privateKeyPath = keyPath;
        delete profile.password;
        // A new key usually has a different passphrase. Drop the old one unless
        // this update also supplies a replacement.
        if (patch.privateKeyPassphrase === undefined) {
          delete profile.privateKeyPassphrase;
        }
      }
      if (patch.privateKeyPassphrase !== undefined) {
        const passphrase = optionalSecret(patch.privateKeyPassphrase);
        if (passphrase === undefined) {
          throw new Error(
            "privateKeyPassphrase cannot be empty; use clearPrivateKeyPassphrase to remove it.",
          );
        }
        profile.privateKeyPassphrase = this.box.seal(
          passphrase,
          secretAad(profile.id, "privateKeyPassphrase"),
        );
      }
      if (patch.sudoPassword !== undefined) {
        const sudoPassword = optionalSecret(patch.sudoPassword);
        if (sudoPassword === undefined) {
          throw new Error(
            "sudoPassword cannot be empty; use clearSudoPassword to remove it.",
          );
        }
        profile.sudoPassword = this.box.seal(
          sudoPassword,
          secretAad(profile.id, "sudoPassword"),
        );
      }

      if (patch.clearPassword) delete profile.password;
      if (patch.clearPrivateKeyPath) delete profile.privateKeyPath;
      if (patch.clearPrivateKeyPassphrase) delete profile.privateKeyPassphrase;
      if (patch.clearSudoPassword) delete profile.sudoPassword;

      if (
        profile.privateKeyPassphrase !== undefined &&
        profile.privateKeyPath === undefined
      ) {
        throw new Error(
          "privateKeyPassphrase can only be used with a private key path.",
        );
      }

      assertAuth(profile.password, profile.privateKeyPath);
      const duplicate = document.profiles.find(
        (candidate) =>
          candidate.id !== id &&
          isEquivalentTarget(candidate, {
            user: profile.user,
            host: profile.host,
            port: profile.port,
            password: profile.password,
            privateKeyPath: profile.privateKeyPath,
          }),
      );
      if (duplicate) {
        throw new Error(
          `An equivalent SSH profile already exists: ${duplicate.name} ${duplicate.user}@${duplicate.host}:${duplicate.port}.`,
        );
      }
      profile.updatedAt = nowIso();
      return publicProfile(profile);
    });
  }

  async remove(id: string): Promise<boolean> {
    return this.mutate((document) => {
      const index = document.profiles.findIndex((profile) => profile.id === id);
      if (index < 0) return false;
      document.profiles.splice(index, 1);
      return true;
    });
  }

  async resolve(id: string): Promise<ResolvedProfile> {
    const document = await this.readDocument();
    const profile = document.profiles.find((candidate) => candidate.id === id);
    if (!profile) throw new Error(`SSH profile not found: ${id}`);

    const resolved: ResolvedProfile = {
      id: profile.id,
      name: profile.name,
      user: profile.user,
      host: profile.host,
      port: profile.port,
      hostKeyPolicy: profile.hostKeyPolicy,
    };
    if (profile.password) {
      resolved.password = this.box.open(
        profile.password,
        secretAad(profile.id, "password"),
      );
    }
    if (profile.privateKeyPath) {
      resolved.privateKeyPath = profile.privateKeyPath;
    }
    if (profile.privateKeyPassphrase) {
      resolved.privateKeyPassphrase = this.box.open(
        profile.privateKeyPassphrase,
        secretAad(profile.id, "privateKeyPassphrase"),
      );
    }
    if (profile.sudoPassword) {
      resolved.sudoPassword = this.box.open(
        profile.sudoPassword,
        secretAad(profile.id, "sudoPassword"),
      );
    }
    return resolved;
  }

  private async readDocument(): Promise<ProfilesDocument> {
    const value = await this.storage.get(PROFILES_KEY);
    if (value === undefined) return { version: 1, profiles: [] };
    if (!isProfilesDocument(value)) {
      throw new Error(
        "Stored SSH profiles have an unsupported format. " +
          "Remove the plugin storage entry and add the profiles again.",
      );
    }
    return value;
  }

  private mutate<Result>(
    update: (document: ProfilesDocument) => Result | Promise<Result>,
  ): Promise<Result> {
    const task = async () => {
      const document = structuredClone(await this.readDocument());
      const result = await update(document);
      await this.storage.set(PROFILES_KEY, document);
      return result;
    };
    const next = mutationQueue.then(task, task);
    mutationQueue = next.catch(() => undefined);
    return next;
  }
}

function isProfilesDocument(value: unknown): value is ProfilesDocument {
  if (typeof value !== "object" || value === null) return false;
  const record = value as { version?: unknown; profiles?: unknown };
  return (
    record.version === 1 &&
    Array.isArray(record.profiles) &&
    record.profiles.every(isStoredProfile)
  );
}

function isStoredProfile(value: unknown): value is StoredProfile {
  if (typeof value !== "object" || value === null) return false;
  const profile = value as Record<string, unknown>;
  return (
    typeof profile.id === "string" &&
    typeof profile.name === "string" &&
    typeof profile.user === "string" &&
    typeof profile.host === "string" &&
    typeof profile.port === "number" &&
    typeof profile.createdAt === "string" &&
    typeof profile.updatedAt === "string" &&
    (profile.hostKeyPolicy === "accept-new" ||
      profile.hostKeyPolicy === "strict" ||
      profile.hostKeyPolicy === "insecure") &&
    (profile.password === undefined || SecretBox.isSealed(profile.password)) &&
    (profile.privateKeyPath === undefined ||
      typeof profile.privateKeyPath === "string") &&
    (profile.privateKeyPassphrase === undefined ||
      SecretBox.isSealed(profile.privateKeyPassphrase)) &&
    (profile.sudoPassword === undefined ||
      SecretBox.isSealed(profile.sudoPassword))
  );
}

interface TargetIdentity {
  user: string;
  host: string;
  port: number;
  password?: unknown;
  privateKeyPath?: string | undefined;
}

function isEquivalentTarget(
  left: TargetIdentity,
  right: TargetIdentity,
): boolean {
  if (left.user !== right.user) return false;
  if (left.host.toLowerCase() !== right.host.toLowerCase()) return false;
  if (left.port !== right.port) return false;
  const leftKey = normalizeKeyPath(left.privateKeyPath);
  const rightKey = normalizeKeyPath(right.privateKeyPath);
  if (leftKey !== undefined || rightKey !== undefined) {
    return leftKey === rightKey;
  }
  return left.password !== undefined && right.password !== undefined;
}

function normalizeKeyPath(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const resolved = expandPath(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function publicProfile(profile: StoredProfile): PublicProfile {
  const result: PublicProfile = {
    id: profile.id,
    name: profile.name,
    user: profile.user,
    host: profile.host,
    port: profile.port,
    auth: profile.privateKeyPath ? "privateKey" : "password",
    hasPassword: profile.password !== undefined,
    hasPrivateKeyPassphrase: profile.privateKeyPassphrase !== undefined,
    hasSudoPassword: profile.sudoPassword !== undefined,
    hostKeyPolicy: profile.hostKeyPolicy,
    createdAt: profile.createdAt,
    updatedAt: profile.updatedAt,
  };
  if (profile.privateKeyPath) result.privateKeyPath = profile.privateKeyPath;
  return result;
}

function secretAad(
  profileId: string,
  field: "password" | "privateKeyPassphrase" | "sudoPassword",
): string {
  return `opencode-ssh/profile/${profileId}/${field}/v1`;
}

function requiredText(value: string, field: string): string {
  const result = value.trim();
  if (result.length === 0) throw new Error(`${field} must not be empty.`);
  return result;
}

function optionalText(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const result = value.trim();
  return result.length > 0 ? result : undefined;
}

function optionalSecret(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  return value.length > 0 ? value : undefined;
}

function normalizePort(value: number | undefined): number {
  const port = value ?? 22;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("port must be an integer between 1 and 65535.");
  }
  return port;
}

function normalizePolicy(value: HostKeyPolicy | undefined): HostKeyPolicy {
  if (value === undefined) return "accept-new";
  if (value !== "accept-new" && value !== "strict" && value !== "insecure") {
    throw new Error("hostKeyPolicy must be accept-new, strict, or insecure.");
  }
  return value;
}

function assertAuth(
  password: string | SealedSecret | undefined,
  privateKeyPath: string | undefined,
): void {
  const hasPassword = password !== undefined;
  const hasPrivateKey = privateKeyPath !== undefined;
  if (hasPassword && hasPrivateKey) {
    throw new Error(
      "Provide either a password or a private key path, not both.",
    );
  }
  if (!hasPassword && !hasPrivateKey) {
    throw new Error(
      "Provide either a password or a private key path for SSH authentication.",
    );
  }
}
