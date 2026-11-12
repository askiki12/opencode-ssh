import { createReadStream, createWriteStream, promises as fs } from "node:fs";
import path from "node:path";
import type { Stats } from "ssh2";
import type { SftpLike } from "../src/ssh/files.js";

/**
 * A small SFTP implementation backed by a local directory. It lets the file
 * helpers run against real filesystem semantics (atomic rename, permissions,
 * streaming) without standing up an SSH server.
 */
export function createFakeSftp(root: string): SftpLike {
  const base = path.resolve(root);

  const local = (remote: string): string => {
    const normalized = path.posix.normalize(remote);
    if (!normalized.startsWith("/")) {
      throw new Error(`fake sftp requires absolute paths: ${remote}`);
    }
    const resolved = path.resolve(base, `.${normalized}`);
    if (resolved !== base && !resolved.startsWith(`${base}${path.sep}`)) {
      throw new Error(`fake sftp path escapes root: ${remote}`);
    }
    return resolved;
  };

  const remote = (value: string): string =>
    `/${path.relative(base, value).split(path.sep).join("/")}`.replace(/\/$/, "") || "/";

  const wrap = <T>(
    run: () => Promise<T>,
    callback: (error: Error | undefined, value: T) => void,
  ): void => {
    run().then(
      (value) => callback(undefined, value),
      (error: unknown) => callback(error as Error, undefined as unknown as T),
    );
  };

  const wrapVoid = (
    run: () => Promise<void>,
    callback: (error?: Error | null) => void,
  ): void => {
    run().then(
      () => callback(),
      (error: unknown) => callback(error as Error),
    );
  };

  return {
    lstat(target, callback) {
      wrap(async () => (await fs.lstat(local(target))) as unknown as Stats, callback);
    },
    stat(target, callback) {
      wrap(async () => (await fs.stat(local(target))) as unknown as Stats, callback);
    },
    readdir(target, callback) {
      wrap(async () => {
        const directory = local(target);
        const entries = await fs.readdir(directory, { withFileTypes: true });
        return Promise.all(
          entries.map(async (entry) => {
            const stats = await fs.lstat(path.join(directory, entry.name));
            return {
              filename: entry.name,
              longname: entry.name,
              attrs: stats as unknown as Stats,
            };
          }),
        );
      }, callback);
    },
    readFile(target, callback) {
      wrap(() => fs.readFile(local(target)), callback);
    },
    writeFile(target, data, options, callback) {
      wrapVoid(
        () => fs.writeFile(local(target), data, { mode: options.mode }),
        callback,
      );
    },
    unlink(target, callback) {
      wrapVoid(() => fs.unlink(local(target)), callback);
    },
    rmdir(target, callback) {
      wrapVoid(() => fs.rmdir(local(target)), callback);
    },
    mkdir(target, callback) {
      wrapVoid(() => fs.mkdir(local(target)), callback);
    },
    rename(from, to, callback) {
      wrapVoid(() => fs.rename(local(from), local(to)), callback);
    },
    chmod(target, mode, callback) {
      wrapVoid(() => fs.chmod(local(target), mode), callback);
    },
    realpath(target, callback) {
      wrap(async () => {
        const resolved = await fs.realpath(local(target));
        return remote(resolved);
      }, callback);
    },
    createReadStream(target, options) {
      return createReadStream(local(target), options);
    },
    createWriteStream(target, options) {
      return createWriteStream(local(target), options);
    },
  };
}
