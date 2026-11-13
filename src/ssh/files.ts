import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { createReadStream as createLocalReadStream } from "node:fs";
import { createWriteStream as createLocalWriteStream } from "node:fs";
import path from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { Readable, Writable } from "node:stream";
import type { FileEntryWithStats, Stats } from "ssh2";
import { errorMessage, expandPath } from "../util.js";

/**
 * The subset of ssh2's SFTPWrapper used by the file helpers. Keeping it
 * structural makes the helpers testable with an in-memory filesystem.
 */
export interface SftpLike {
  lstat(
    target: string,
    callback: (error: Error | undefined, stats: Stats) => void,
  ): void;
  stat(
    target: string,
    callback: (error: Error | undefined, stats: Stats) => void,
  ): void;
  readdir(
    target: string,
    callback: (error: Error | undefined, list: FileEntryWithStats[]) => void,
  ): void;
  readFile(
    target: string,
    callback: (error: Error | undefined, data: Buffer) => void,
  ): void;
  writeFile(
    target: string,
    data: Buffer,
    options: { mode?: number },
    callback: (error?: Error | null) => void,
  ): void;
  unlink(target: string, callback: (error?: Error | null) => void): void;
  rmdir(target: string, callback: (error?: Error | null) => void): void;
  mkdir(target: string, callback: (error?: Error | null) => void): void;
  rename(from: string, to: string, callback: (error?: Error | null) => void): void;
  /** OpenSSH extension: rename with atomic overwrite semantics. */
  ext_openssh_rename?(
    from: string,
    to: string,
    callback: (error?: Error | null) => void,
  ): void;
  chmod(
    target: string,
    mode: number,
    callback: (error?: Error | null) => void,
  ): void;
  realpath(
    target: string,
    callback: (error: Error | undefined, absolutePath: string) => void,
  ): void;
  createReadStream(target: string, options?: { start?: number; end?: number }): Readable;
  createWriteStream(
    target: string,
    options?: { mode?: number },
  ): Writable;
}

const posix = path.posix;

export const DEFAULT_READ_BYTES = 256 * 1024;
export const MAX_READ_BYTES = 8 * 1024 * 1024;
export const MAX_EDIT_BYTES = 8 * 1024 * 1024;
const MAX_REMOVE_ENTRIES = 50_000;
const REMOVE_LIST_LIMIT = 1_000;

export interface RemotePathOptions {
  home: string;
}

/** Accept absolute paths and `~` forms only; relative paths are ambiguous. */
export function resolveRemotePath(input: string, home: string): string {
  const value = input.trim();
  if (value.length === 0) {
    throw new Error("path must not be empty.");
  }
  if (value === "~") return posix.normalize(home);
  if (value.startsWith("~/")) return posix.join(home, value.slice(2));
  if (value.startsWith("/")) return posix.normalize(value);
  throw new Error(
    `path must be absolute or start with "~/": ${input}`,
  );
}

export interface ReadRemoteFileOptions {
  /** 1-based line offset. Only valid when reading from byte 0. */
  offset?: number;
  /** 0-based byte offset. Mutually exclusive with `offset`. */
  byteOffset?: number;
  limit?: number;
  maxBytes?: number;
}

export interface ReadRemoteFileResult {
  path: string;
  size: number;
  binary: boolean;
  truncated: boolean;
  totalLines: number | null;
  startLine: number;
  endLine: number;
  /** Byte range read from the file; end is exclusive. */
  byteStart: number;
  byteEnd: number;
  /** False when the window starts mid-file and line numbers are unknown. */
  lineNumbers: boolean;
  /** Whole-file SHA-256, or null when only a partial window was read. */
  sha256: string | null;
  lineEndings: LineEndings;
  lines: Array<{ number: number; text: string }>;
}

export async function readRemoteFile(
  sftp: SftpLike,
  target: string,
  options: ReadRemoteFileOptions = {},
): Promise<ReadRemoteFileResult> {
  const stats = await call<Stats>((done) => sftp.stat(target, done));
  if (!stats.isFile()) {
    throw new Error(`Not a regular file: ${target}`);
  }

  if (options.byteOffset !== undefined && options.offset !== undefined) {
    throw new Error(
      "Use either byte_offset or offset, not both. offset is a line offset from the start; byte_offset reads a byte range.",
    );
  }

  const maxBytes = clamp(options.maxBytes ?? DEFAULT_READ_BYTES, 1_024, MAX_READ_BYTES);
  const byteStart =
    options.byteOffset === undefined
      ? 0
      : Math.max(0, Math.trunc(options.byteOffset));
  if (byteStart > stats.size) {
    throw new Error(
      `byte_offset ${byteStart} is beyond the file size (${stats.size} bytes).`,
    );
  }
  const windowBytes = Math.min(maxBytes, stats.size - byteStart);
  const truncatedByBytes = stats.size > byteStart + windowBytes;
  const buffer =
    windowBytes === 0
      ? Buffer.alloc(0)
      : byteStart === 0 && !truncatedByBytes
        ? await call<Buffer>((done) => sftp.readFile(target, done))
        : await readRange(sftp, target, byteStart, windowBytes);
  const byteEnd = byteStart + buffer.length;
  const lineNumbers = byteStart === 0;

  if (isBinary(buffer)) {
    return {
      path: target,
      size: stats.size,
      binary: true,
      truncated: truncatedByBytes,
      totalLines: null,
      startLine: lineNumbers ? 1 : 0,
      endLine: 0,
      byteStart,
      byteEnd,
      lineNumbers,
      sha256:
        byteStart === 0 && byteEnd === stats.size ? sha256(buffer) : null,
      lineEndings: "none",
      lines: [],
    };
  }

  const text = buffer.toString("utf8");
  const allLines = splitLines(text);
  const totalLines =
    truncatedByBytes || byteStart > 0 ? null : allLines.length;
  const offset = Math.max(1, Math.trunc(options.offset ?? 1));
  if (lineNumbers && truncatedByBytes && offset > allLines.length) {
    throw new Error(
      `offset ${offset} is beyond the captured prefix (${allLines.length} lines). ` +
        `Use byte_offset=${byteEnd} to continue, or raise max_bytes.`,
    );
  }
  const requestedLimit =
    options.limit === undefined ? undefined : Math.max(0, Math.trunc(options.limit));
  const startIndex = lineNumbers ? offset - 1 : 0;
  const endIndex =
    requestedLimit === undefined
      ? allLines.length
      : Math.min(allLines.length, startIndex + requestedLimit);
  const lines: Array<{ number: number; text: string }> = [];
  for (let index = startIndex; index < endIndex; index += 1) {
    lines.push({
      number: lineNumbers ? index + 1 : 0,
      text: allLines[index] ?? "",
    });
  }

  return {
    path: target,
    size: stats.size,
    binary: false,
    truncated:
      truncatedByBytes || (requestedLimit !== undefined && endIndex < allLines.length),
    totalLines,
    startLine: lineNumbers ? (lines[0]?.number ?? offset) : 0,
    endLine: lineNumbers ? (lines[lines.length - 1]?.number ?? offset - 1) : 0,
    byteStart,
    byteEnd,
    lineNumbers,
    sha256:
      byteStart === 0 && byteEnd === stats.size ? sha256(buffer) : null,
    lineEndings: detectLineEndings(text),
    lines,
  };
}

export interface WriteRemoteFileOptions {
  overwrite?: boolean;
  mode?: number;
}

export interface WriteRemoteFileResult {
  path: string;
  bytes: number;
  created: boolean;
  lineEndings: LineEndings;
}

export type LineEndings = "none" | "lf" | "crlf" | "mixed";

export async function writeRemoteFile(
  sftp: SftpLike,
  target: string,
  content: string,
  options: WriteRemoteFileOptions = {},
): Promise<WriteRemoteFileResult> {
  const existing = await lstatOrNull(sftp, target);
  if (existing?.isSymbolicLink()) {
    throw new Error(
      `Refusing to write through a symbolic link: ${target}. Resolve the real path first.`,
    );
  }
  if (existing && options.overwrite !== true) {
    throw new Error(
      `File already exists: ${target}. Pass overwrite: true to replace it, or use ssh_edit for a targeted change.`,
    );
  }
  if (existing?.isDirectory()) {
    throw new Error(`Target is a directory: ${target}`);
  }

  const data = Buffer.from(content, "utf8");
  const mode = options.mode ?? existing?.mode ?? 0o644;
  await atomicWrite(sftp, target, data, mode);
  return {
    path: target,
    bytes: data.byteLength,
    created: existing === undefined,
    lineEndings: detectLineEndings(content),
  };
}

export interface EditRemoteFileOptions {
  replaceAll?: boolean;
  expectedSha256?: string;
}

export interface EditRemoteFileResult {
  path: string;
  replacements: number;
  firstLine: number;
  preview: Array<{ number: number; text: string }>;
  sha256Before: string;
  sha256After: string;
  lineEndings: LineEndings;
}

export async function editRemoteFile(
  sftp: SftpLike,
  target: string,
  oldText: string,
  newText: string,
  options: EditRemoteFileOptions = {},
): Promise<EditRemoteFileResult> {
  if (oldText.length === 0) {
    throw new Error("old_text must not be empty.");
  }

  const stats = await call<Stats>((done) => sftp.lstat(target, done));
  if (stats.isSymbolicLink()) {
    throw new Error(
      `Refusing to edit a symbolic link: ${target}. Resolve the real path first.`,
    );
  }
  if (!stats.isFile()) {
    throw new Error(`Not a regular file: ${target}`);
  }
  if (stats.size > MAX_EDIT_BYTES) {
    throw new Error(
      `File is too large to edit safely (${stats.size} bytes, limit ${MAX_EDIT_BYTES}). Use ssh_exec with a dedicated tool instead.`,
    );
  }

  const buffer = await call<Buffer>((done) => sftp.readFile(target, done));
  if (isBinary(buffer)) {
    throw new Error(`Refusing to edit a binary file: ${target}`);
  }

  const sha256Before = sha256(buffer);
  const expected = options.expectedSha256?.trim().toLowerCase();
  if (expected !== undefined && expected !== sha256Before) {
    throw new Error(
      `SHA-256 mismatch for ${target}. Expected ${expected}, found ${sha256Before}. ` +
        "Re-read the file and retry with the current hash.",
    );
  }

  const text = buffer.toString("utf8");
  const occurrences = countOccurrences(text, oldText);
  if (occurrences === 0) {
    const crlfHint =
      oldText.includes("\n") && text.includes("\r\n")
        ? " The file uses CRLF line endings; include \\r\\n in old_text."
        : "";
    throw new Error(`Text not found in ${target}.${crlfHint}`);
  }
  if (occurrences > 1 && options.replaceAll !== true) {
    throw new Error(
      `Found ${occurrences} matches in ${target}. Provide more context or set replace_all: true.`,
    );
  }

  const updated =
    options.replaceAll === true
      ? text.split(oldText).join(newText)
      : replaceFirst(text, oldText, newText);
  const updatedBuffer = Buffer.from(updated, "utf8");
  await atomicWrite(sftp, target, updatedBuffer, stats.mode);

  const lines = splitLines(updated);
  const firstChangedIndex = lineIndexOf(updated, text.indexOf(oldText));
  const previewStart = Math.max(0, firstChangedIndex - 2);
  const previewEnd = Math.min(lines.length, firstChangedIndex + 3);
  const preview: Array<{ number: number; text: string }> = [];
  for (let index = previewStart; index < previewEnd; index += 1) {
    preview.push({ number: index + 1, text: lines[index] ?? "" });
  }

  return {
    path: target,
    replacements: options.replaceAll === true ? occurrences : 1,
    firstLine: firstChangedIndex + 1,
    preview,
    sha256Before,
    sha256After: sha256(updatedBuffer),
    lineEndings: detectLineEndings(updated),
  };
}

export interface RemoveRemotePathOptions {
  recursive?: boolean;
  dryRun?: boolean;
}

export interface RemoveRemotePathResult {
  path: string;
  dryRun: boolean;
  removed: number;
  entries: string[];
  listedTruncated: boolean;
}

export async function removeRemotePath(
  sftp: SftpLike,
  target: string,
  options: RemoveRemotePathOptions = {},
): Promise<RemoveRemotePathResult> {
  const stats = await lstatOrNull(sftp, target);
  if (!stats) {
    throw new Error(`Path does not exist: ${target}`);
  }
  if (stats.isDirectory() && options.recursive !== true) {
    throw new Error(
      `Refusing to remove a directory without recursive: true: ${target}`,
    );
  }

  const targets: string[] = [target];
  if (stats.isDirectory()) {
    const entries = await walkRemote(sftp, target, MAX_REMOVE_ENTRIES);
    if (entries.tooMany) {
      throw new Error(
        `Refusing to remove more than ${MAX_REMOVE_ENTRIES} entries: ${target}`,
      );
    }
    targets.unshift(...entries.paths);
  }

  const listed = targets.slice(0, REMOVE_LIST_LIMIT);
  if (options.dryRun === true) {
    return {
      path: target,
      dryRun: true,
      removed: 0,
      entries: listed,
      listedTruncated: targets.length > listed.length,
    };
  }

  for (const entry of targets) {
    const entryStats = await lstatOrNull(sftp, entry);
    if (!entryStats) continue;
    if (entryStats.isDirectory()) {
      await call<void>((done) => sftp.rmdir(entry, done));
    } else {
      await call<void>((done) => sftp.unlink(entry, done));
    }
  }

  return {
    path: target,
    dryRun: false,
    removed: targets.length,
    entries: listed,
    listedTruncated: targets.length > listed.length,
  };
}

export type TransferDirection = "upload" | "download";

export interface TransferProgress {
  direction: TransferDirection;
  files: number;
  bytes: number;
}

export interface TransferOptions {
  direction: TransferDirection;
  localPath: string;
  remotePath: string;
  overwrite?: boolean;
  onProgress?: (update: TransferProgress) => void;
  signal?: AbortSignal;
}

export interface TransferResult {
  direction: TransferDirection;
  localPath: string;
  remotePath: string;
  files: number;
  bytes: number;
}

export async function transferPath(
  sftp: SftpLike,
  options: TransferOptions,
): Promise<TransferResult> {
  const localPath = path.resolve(expandPath(options.localPath));
  const totals = { files: 0, bytes: 0 };

  if (options.direction === "upload") {
    await uploadEntry(sftp, localPath, options.remotePath, options, totals);
  } else {
    await downloadEntry(sftp, options.remotePath, localPath, options, totals);
  }

  return {
    direction: options.direction,
    localPath,
    remotePath: options.remotePath,
    files: totals.files,
    bytes: totals.bytes,
  };
}

async function uploadEntry(
  sftp: SftpLike,
  localPath: string,
  remotePath: string,
  options: TransferOptions,
  totals: { files: number; bytes: number },
): Promise<void> {
  const stats = await fs.lstat(localPath);
  if (stats.isSymbolicLink()) {
    throw new Error(`Refusing to upload a symbolic link: ${localPath}`);
  }

  if (stats.isDirectory()) {
    await ensureRemoteDir(sftp, remotePath);
    const children = await fs.readdir(localPath, { withFileTypes: true });
    for (const child of children) {
      await uploadEntry(
        sftp,
        path.join(localPath, child.name),
        posix.join(remotePath, child.name),
        options,
        totals,
      );
    }
    return;
  }

  if (!stats.isFile()) {
    throw new Error(`Unsupported local file type: ${localPath}`);
  }

  const existing = await lstatOrNull(sftp, remotePath);
  if (existing?.isSymbolicLink()) {
    throw new Error(
      `Refusing to upload through a symbolic link: ${remotePath}. Resolve the real path first.`,
    );
  }
  if (existing && options.overwrite !== true) {
    throw new Error(
      `Remote file already exists: ${remotePath}. Pass overwrite: true to replace it.`,
    );
  }
  if (existing?.isDirectory()) {
    throw new Error(`Remote target is a directory: ${remotePath}`);
  }

  await ensureRemoteDir(sftp, posix.dirname(remotePath));
  const mode = stats.mode & 0o777;
  const temporary = temporaryRemotePath(remotePath);
  try {
    const read = createLocalReadStream(localPath);
    const progress = progressStream("upload", totals, options.onProgress);
    const write = sftp.createWriteStream(temporary, { mode });
    if (options.signal !== undefined) {
      await pipeline(read, progress, write, { signal: options.signal });
    } else {
      await pipeline(read, progress, write);
    }
    await chmodQuietly(sftp, temporary, mode);
    if (options.overwrite !== true) {
      const appeared = await lstatOrNull(sftp, remotePath);
      if (appeared) {
        throw new Error(
          `Remote file already exists: ${remotePath}. Pass overwrite: true to replace it.`,
        );
      }
    }
    await replaceRemoteFile(sftp, temporary, remotePath);
  } catch (error) {
    await call<void>((done) => sftp.unlink(temporary, done)).catch(
      () => undefined,
    );
    throw error;
  }
  totals.files += 1;
  totals.bytes += stats.size;
}

async function downloadEntry(
  sftp: SftpLike,
  remotePath: string,
  localPath: string,
  options: TransferOptions,
  totals: { files: number; bytes: number },
): Promise<void> {
  const stats = await lstatOrNull(sftp, remotePath);
  if (!stats) {
    throw new Error(`Remote path does not exist: ${remotePath}`);
  }
  if (stats.isSymbolicLink()) {
    throw new Error(`Refusing to download a symbolic link: ${remotePath}`);
  }

  if (stats.isDirectory()) {
    await fs.mkdir(localPath, { recursive: true });
    const entries = await call<FileEntryWithStats[]>((done) =>
      sftp.readdir(remotePath, done),
    );
    for (const entry of entries) {
      await downloadEntry(
        sftp,
        posix.join(remotePath, entry.filename),
        path.join(localPath, entry.filename),
        options,
        totals,
      );
    }
    return;
  }

  if (!stats.isFile()) {
    throw new Error(`Unsupported remote file type: ${remotePath}`);
  }

  if (await existsLocally(localPath)) {
    if (options.overwrite !== true) {
      throw new Error(
        `Local file already exists: ${localPath}. Pass overwrite: true to replace it.`,
      );
    }
  }

  await fs.mkdir(path.dirname(localPath), { recursive: true });
  const temporary = temporaryLocalPath(localPath);
  try {
    const read = sftp.createReadStream(remotePath);
    const progress = progressStream("download", totals, options.onProgress);
    const write = createLocalWriteStream(temporary);
    if (options.signal !== undefined) {
      await pipeline(read, progress, write, { signal: options.signal });
    } else {
      await pipeline(read, progress, write);
    }
    await fs.chmod(temporary, stats.mode & 0o777).catch(() => undefined);
    await replaceLocalFile(temporary, localPath);
  } catch (error) {
    await fs.unlink(temporary).catch(() => undefined);
    throw error;
  }
  totals.files += 1;
  totals.bytes += stats.size;
}

function progressStream(
  direction: TransferDirection,
  totals: { files: number; bytes: number },
  onProgress: ((update: TransferProgress) => void) | undefined,
): Transform {
  return new Transform({
    transform(chunk, _encoding, callback) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totals.bytes += buffer.length;
      if (onProgress) {
        try {
          onProgress({
            direction,
            files: totals.files,
            bytes: totals.bytes,
          });
        } catch {
          // Progress reporting must never break the transfer.
        }
      }
      callback(null, buffer);
    },
  });
}

function temporaryRemotePath(target: string): string {
  return `${target}.opencode-ssh.${Date.now().toString(36)}.${Math.random()
    .toString(36)
    .slice(2, 8)}.tmp`;
}

function temporaryLocalPath(target: string): string {
  return `${target}.opencode-ssh.${Date.now().toString(36)}.${Math.random()
    .toString(36)
    .slice(2, 8)}.tmp`;
}

async function replaceLocalFile(source: string, target: string): Promise<void> {
  try {
    await fs.rename(source, target);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "EEXIST" && code !== "EPERM" && code !== "ENOTEMPTY") {
      throw error;
    }
    // Windows rename does not reliably replace an existing target.
    await fs.rm(target, { force: true });
    await fs.rename(source, target);
  }
}

async function atomicWrite(
  sftp: SftpLike,
  target: string,
  data: Buffer,
  mode: number,
): Promise<void> {
  const temporary = `${target}.opencode-ssh.${Date.now().toString(36)}.${Math.random()
    .toString(36)
    .slice(2, 8)}.tmp`;
  await ensureRemoteDir(sftp, posix.dirname(target));
  try {
    await call<void>((done) =>
      sftp.writeFile(temporary, data, { mode }, done),
    );
    await chmodQuietly(sftp, temporary, mode);
    await replaceRemoteFile(sftp, temporary, target);
  } catch (error) {
    await call<void>((done) => sftp.unlink(temporary, done)).catch(() => undefined);
    throw error;
  }
}

/**
 * SFTP v3 rename refuses to overwrite an existing destination (OpenSSH returns
 * FAILURE). Use the posix-rename extension when the server offers it; otherwise
 * move the old file aside first so a failed rename can be rolled back.
 */
async function replaceRemoteFile(
  sftp: SftpLike,
  source: string,
  target: string,
): Promise<void> {
  if (typeof sftp.ext_openssh_rename === "function") {
    try {
      await call<void>((done) => sftp.ext_openssh_rename?.(source, target, done));
      return;
    } catch {
      // Fall through to the portable path.
    }
  }

  const existing = await lstatOrNull(sftp, target);
  if (!existing) {
    await call<void>((done) => sftp.rename(source, target, done));
    return;
  }

  const backup = `${target}.opencode-ssh.${Date.now().toString(36)}.${Math.random()
    .toString(36)
    .slice(2, 8)}.bak`;
  await call<void>((done) => sftp.rename(target, backup, done));
  try {
    await call<void>((done) => sftp.rename(source, target, done));
  } catch (error) {
    await call<void>((done) => sftp.rename(backup, target, done)).catch(
      () => undefined,
    );
    throw error;
  }
  await call<void>((done) => sftp.unlink(backup, done)).catch(() => undefined);
}

async function readRange(
  sftp: SftpLike,
  target: string,
  start: number,
  length: number,
): Promise<Buffer> {
  const stream = sftp.createReadStream(target, {
    start,
    end: start + length - 1,
  });
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

async function walkRemote(
  sftp: SftpLike,
  root: string,
  limit: number,
): Promise<{ paths: string[]; tooMany: boolean }> {
  const result: { paths: string[]; tooMany: boolean } = {
    paths: [],
    tooMany: false,
  };

  const visit = async (directory: string): Promise<void> => {
    const entries = await call<FileEntryWithStats[]>((done) =>
      sftp.readdir(directory, done),
    );
    for (const entry of entries) {
      if (result.paths.length >= limit) {
        result.tooMany = true;
        return;
      }
      const child = posix.join(directory, entry.filename);
      if (entry.attrs.isDirectory()) {
        await visit(child);
        if (result.tooMany) return;
      }
      result.paths.push(child);
    }
  };

  await visit(root);
  return result;
}

export async function ensureRemoteDir(
  sftp: SftpLike,
  directory: string,
): Promise<void> {
  const normalized = posix.normalize(directory);
  if (normalized === "/" || normalized === ".") return;

  const parts = normalized.split("/").filter((part) => part.length > 0);
  let current = "";
  for (const part of parts) {
    current += `/${part}`;
    const existing = await lstatOrNull(sftp, current);
    if (existing) {
      if (!existing.isDirectory()) {
        throw new Error(`Not a directory: ${current}`);
      }
      continue;
    }
    try {
      await call<void>((done) => sftp.mkdir(current, done));
    } catch (error) {
      // Concurrent creators are fine, but a real failure must surface.
      const again = await lstatOrNull(sftp, current);
      if (!again?.isDirectory()) throw error;
    }
  }
}

async function chmodQuietly(
  sftp: SftpLike,
  target: string,
  mode: number,
): Promise<void> {
  await call<void>((done) => sftp.chmod(target, mode, done)).catch(
    () => undefined,
  );
}

async function lstatOrNull(
  sftp: SftpLike,
  target: string,
): Promise<Stats | undefined> {
  try {
    return await call<Stats>((done) => sftp.lstat(target, done));
  } catch (error) {
    if (isNotFound(error)) return undefined;
    throw error;
  }
}

async function existsLocally(target: string): Promise<boolean> {
  try {
    await fs.lstat(target);
    return true;
  } catch (error) {
    if (isNotFound(error)) return false;
    throw error;
  }
}

function call<T>(
  run: (done: (error: Error | undefined | null, value?: T) => void) => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    run((error, value) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(value as T);
    });
  });
}

function isNotFound(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  if (code === 2 || code === "ENOENT" || code === "ENOTDIR") return true;
  return /no such file|not found|cannot find/i.test(errorMessage(error));
}

function sha256(buffer: Buffer): string {
  return createHash("sha256").update(buffer).digest("hex");
}

function detectLineEndings(text: string): LineEndings {
  let crlf = 0;
  let lf = 0;
  let cr = 0;
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === "\r") {
      if (text[index + 1] === "\n") {
        crlf += 1;
        index += 1;
      } else {
        cr += 1;
      }
    } else if (text[index] === "\n") {
      lf += 1;
    }
  }
  if (crlf === 0 && lf === 0 && cr === 0) return "none";
  if (crlf > 0 && lf === 0 && cr === 0) return "crlf";
  if (crlf === 0 && cr === 0 && lf > 0) return "lf";
  return "mixed";
}

function isBinary(buffer: Buffer): boolean {
  const limit = Math.min(buffer.length, 8_192);
  for (let index = 0; index < limit; index += 1) {
    if (buffer[index] === 0) return true;
  }
  return false;
}

function splitLines(text: string): string[] {
  if (text.length === 0) return [];
  const lines = text.split(/\r?\n/);
  if (lines[lines.length - 1] === "") lines.pop();
  return lines;
}

function countOccurrences(haystack: string, needle: string): number {
  let count = 0;
  let index = haystack.indexOf(needle);
  while (index !== -1) {
    count += 1;
    index = haystack.indexOf(needle, index + needle.length);
  }
  return count;
}

function replaceFirst(haystack: string, needle: string, replacement: string): string {
  const index = haystack.indexOf(needle);
  if (index === -1) return haystack;
  return (
    haystack.slice(0, index) + replacement + haystack.slice(index + needle.length)
  );
}

function lineIndexOf(text: string, characterIndex: number): number {
  if (characterIndex <= 0) return 0;
  let line = 0;
  for (let index = 0; index < characterIndex && index < text.length; index += 1) {
    if (text[index] === "\n") line += 1;
  }
  return line;
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, Math.trunc(value)));
}
