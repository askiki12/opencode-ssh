import { readdir, readFile, stat } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import type {
  ProfileInput,
  ProfileStore,
  ProfileUpdateInput,
  ResolvedProfile,
} from "./profiles.js";
import type {
  ConnectInput,
  ConnectionInfo,
  ConnectionManager,
} from "./ssh/manager.js";
import { errorMessage } from "./util.js";

export interface RpcHandlerDependencies {
  manager: ConnectionManager;
  profiles: ProfileStore;
}

export interface PrivateKeyInfo {
  path: string;
  name: string;
}

type RpcResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string };

export function createRpcHandlers(dependencies: RpcHandlerDependencies) {
  const { manager, profiles } = dependencies;

  return {
    connectionsList: () => safe(async () => manager.list()),

    connectionsConnect: (raw: unknown) =>
      safe(async () => manager.connect(raw as ConnectInput)),

    connectionsDisconnect: (raw: unknown) =>
      safe(async () => {
        const input = asRecord(raw);
        return manager.disconnect(requireString(input.sshId, "sshId"));
      }),

    connectionsTest: (raw: unknown) =>
      safe(async () => {
        const info = await manager.connect(raw as ConnectInput);
        try {
          return info;
        } finally {
          await manager.disconnect(info.id).catch(() => undefined);
        }
      }),

    profilesList: () => safe(async () => profiles.list()),

    profilesAdd: (raw: unknown) =>
      safe(async () => profiles.add(raw as ProfileInput)),

    profilesUpdate: (raw: unknown) =>
      safe(async () => {
        const { profileId, patch } = splitProfileUpdate(raw);
        return profiles.update(profileId, patch);
      }),

    profilesRemove: (raw: unknown) =>
      safe(async () => {
        const input = asRecord(raw);
        const removed = await profiles.remove(
          requireString(input.profileId, "profileId"),
        );
        return { removed };
      }),

    profilesTestAndAdd: (raw: unknown) =>
      safe(async () => {
        const input = raw as ProfileInput;
        const info = await manager.connect(profileToConnectInput(input));
        await manager.disconnect(info.id).catch(() => undefined);
        return profiles.add(input);
      }),

    profilesTestAndUpdate: (raw: unknown) =>
      safe(async () => {
        const { profileId, patch } = splitProfileUpdate(raw);
        const existing = await profiles.resolve(profileId);
        if (!patchAffectsConnection(existing, patch)) {
          return profiles.update(profileId, patch);
        }
        const info = await manager.connect(
          mergeProfileForTest(existing, patch),
        );
        await manager.disconnect(info.id).catch(() => undefined);
        return profiles.update(profileId, patch);
      }),

    keysList: () => safe(async () => listPrivateKeys()),
  };
}

function safe<T>(
  task: () => Promise<T> | T,
): Promise<RpcResult<T>> {
  try {
    return Promise.resolve(task()).then(
      (data) => ({ ok: true as const, data }),
      (error: unknown) => ({
        ok: false as const,
        error: errorMessage(error),
      }),
    );
  } catch (error) {
    return Promise.resolve({
      ok: false as const,
      error: errorMessage(error),
    });
  }
}

function profileToConnectInput(input: ProfileInput): ConnectInput {
  const target: ConnectInput = {
    user: input.user,
    host: input.host,
    port: input.port ?? 22,
    hostKeyPolicy: input.hostKeyPolicy ?? "accept-new",
  };
  if (input.password !== undefined) target.password = input.password;
  if (input.privateKeyPath !== undefined) {
    target.privateKeyPath = input.privateKeyPath;
  }
  if (input.privateKeyPassphrase !== undefined) {
    target.privateKeyPassphrase = input.privateKeyPassphrase;
  }
  if (input.sudoPassword !== undefined) {
    target.sudoPassword = input.sudoPassword;
  }
  return target;
}

function mergeProfileForTest(
  existing: ResolvedProfile,
  patch: ProfileUpdateInput,
): ConnectInput {
  if (patch.password !== undefined && patch.privateKeyPath !== undefined) {
    throw new Error("Provide either password or privateKeyPath, not both.");
  }

  let password = existing.password;
  let privateKeyPath = existing.privateKeyPath;
  let privateKeyPassphrase = existing.privateKeyPassphrase;

  if (patch.password !== undefined) {
    password = patch.password;
    privateKeyPath = undefined;
    privateKeyPassphrase = undefined;
  }
  if (patch.privateKeyPath !== undefined) {
    privateKeyPath = patch.privateKeyPath;
    password = undefined;
    if (patch.privateKeyPassphrase === undefined) {
      privateKeyPassphrase = undefined;
    }
  }
  if (patch.clearPassword) password = undefined;
  if (patch.clearPrivateKeyPath) {
    privateKeyPath = undefined;
    privateKeyPassphrase = undefined;
  }
  if (patch.clearPrivateKeyPassphrase) privateKeyPassphrase = undefined;
  if (patch.privateKeyPassphrase !== undefined) {
    privateKeyPassphrase = patch.privateKeyPassphrase;
  }

  const sudoPassword = patch.clearSudoPassword
    ? undefined
    : (patch.sudoPassword ?? existing.sudoPassword);

  const target: ConnectInput = {
    user: patch.user ?? existing.user,
    host: patch.host ?? existing.host,
    port: patch.port ?? existing.port,
    hostKeyPolicy: patch.hostKeyPolicy ?? existing.hostKeyPolicy,
  };
  if (password !== undefined) target.password = password;
  if (privateKeyPath !== undefined) target.privateKeyPath = privateKeyPath;
  if (privateKeyPassphrase !== undefined) {
    target.privateKeyPassphrase = privateKeyPassphrase;
  }
  if (sudoPassword !== undefined) target.sudoPassword = sudoPassword;
  return target;
}

function splitProfileUpdate(raw: unknown): {
  profileId: string;
  patch: ProfileUpdateInput;
} {
  const input = asRecord(raw);
  const profileId = requireString(input.profileId, "profileId");
  if (
    typeof input.patch === "object" &&
    input.patch !== null &&
    !Array.isArray(input.patch)
  ) {
    return { profileId, patch: input.patch as ProfileUpdateInput };
  }
  const { profileId: _ignored, ...patch } = input;
  return { profileId, patch: patch as ProfileUpdateInput };
}

function patchAffectsConnection(
  existing: ResolvedProfile,
  patch: ProfileUpdateInput,
): boolean {
  if (patch.user !== undefined && patch.user !== existing.user) return true;
  if (patch.host !== undefined && patch.host !== existing.host) return true;
  if (patch.port !== undefined && patch.port !== existing.port) return true;
  if (
    patch.hostKeyPolicy !== undefined &&
    patch.hostKeyPolicy !== existing.hostKeyPolicy
  ) {
    return true;
  }
  if (
    patch.password !== undefined ||
    patch.privateKeyPath !== undefined ||
    patch.privateKeyPassphrase !== undefined ||
    patch.sudoPassword !== undefined
  ) {
    return true;
  }
  if (
    patch.clearPassword ||
    patch.clearPrivateKeyPath ||
    patch.clearPrivateKeyPassphrase ||
    patch.clearSudoPassword
  ) {
    return true;
  }
  return false;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("RPC input must be an object.");
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${field} must be a non-empty string.`);
  }
  return value;
}

async function listPrivateKeys(): Promise<PrivateKeyInfo[]> {
  const directory = path.join(homedir(), ".ssh");
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    return [];
  }

  const keys: PrivateKeyInfo[] = [];
  for (const entry of entries) {
    if (!entry.isFile() && !entry.isSymbolicLink()) continue;
    if (entry.name.endsWith(".pub") || entry.name.startsWith(".")) continue;
    if (
      entry.name === "config" ||
      entry.name === "known_hosts" ||
      entry.name === "authorized_keys" ||
      entry.name.startsWith("known_hosts.")
    ) {
      continue;
    }

    const fullPath = path.join(directory, entry.name);
    let likelyKey = /^id_|\.(pem|key)$/i.test(entry.name);
    if (!likelyKey) {
      try {
        const info = await stat(fullPath);
        if (info.size > 512 * 1024) continue;
        const content = await readFile(fullPath, "utf8");
        likelyKey = content.includes("PRIVATE KEY");
      } catch {
        continue;
      }
    }
    if (likelyKey) keys.push({ path: fullPath, name: entry.name });
  }

  return keys.sort((left, right) => left.name.localeCompare(right.name));
}
