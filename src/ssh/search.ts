import path from "node:path";
import { shellQuote } from "./command.js";
import type { ConnectionManager, ExecResult } from "./manager.js";
import type { SftpLike } from "./files.js";

const posix = path.posix;

const SEARCH_TIMEOUT_MS = 60_000;
const SEARCH_MAX_BYTES = 8 * 1024 * 1024;

export interface RemoteTools {
  rg: boolean;
  grep: boolean;
  find: boolean;
}

export interface GrepOptions {
  pattern: string;
  path: string;
  include?: string;
  literal?: boolean;
  caseSensitive?: boolean;
  maxMatches?: number;
}

export interface GrepMatch {
  path: string;
  line: number;
  text: string;
}

export interface GrepResult {
  engine: "rg" | "grep";
  matches: GrepMatch[];
  truncated: boolean;
}

export interface GlobOptions {
  pattern: string;
  path: string;
  maxResults?: number;
  includeHidden?: boolean;
}

export interface GlobResult {
  engine: "rg" | "find" | "sftp";
  paths: string[];
  truncated: boolean;
}

/**
 * Remote search runs on the server: ripping every byte over SFTP is far slower
 * than letting the remote host use ripgrep or grep. Probing is cached per
 * connection because the result only changes when the host does.
 */
export class SearchService {
  private readonly probes = new Map<string, Promise<RemoteTools>>();

  constructor(private readonly manager: ConnectionManager) {}

  async tools(sshId: string): Promise<RemoteTools> {
    const cached = this.probes.get(sshId);
    if (cached) return cached;

    const probe = this.manager
      .exec({
        sshId,
        command:
          "for tool in rg grep find; do if command -v \"$tool\" >/dev/null 2>&1; then echo \"$tool=1\"; else echo \"$tool=0\"; fi; done",
        timeoutMs: 15_000,
        maxOutputBytes: 4_096,
      })
      .then((result) => parseProbe(result.stdout));

    this.probes.set(sshId, probe);
    probe.catch(() => this.probes.delete(sshId));
    return probe;
  }

  async grep(sshId: string, options: GrepOptions): Promise<GrepResult> {
    const tools = await this.tools(sshId);
    const maxMatches = clamp(options.maxMatches ?? 200, 1, 5_000);
    if (tools.rg) {
      return this.grepWithRipgrep(sshId, options, maxMatches);
    }
    if (tools.grep) {
      return this.grepWithGrep(sshId, options, maxMatches);
    }
    throw new Error(
      "Remote host has neither ripgrep (rg) nor grep. Install ripgrep with the " +
        "remote package manager (for example: apt install ripgrep) or use ssh_exec " +
        "to inspect files directly.",
    );
  }

  async glob(sshId: string, options: GlobOptions): Promise<GlobResult> {
    const tools = await this.tools(sshId);
    const maxResults = clamp(options.maxResults ?? 2_000, 1, 5_000);
    if (tools.rg) {
      const result = await this.rgFiles(sshId, options, maxResults);
      if (result.paths.length > 0) return result;
    }
    if (tools.find) {
      const result = await this.findFiles(sshId, options, maxResults);
      if (result.paths.length > 0) return result;
    }
    return this.sftpFiles(sshId, options, maxResults);
  }

  private async grepWithRipgrep(
    sshId: string,
    options: GrepOptions,
    maxMatches: number,
  ): Promise<GrepResult> {
    const flags = [
      "--no-config",
      "--json",
      "--hidden",
      "--no-messages",
      "--max-filesize",
      "10M",
    ];
    if (options.literal === true) flags.push("-F");
    if (options.caseSensitive === false) flags.push("-i");
    if (options.include !== undefined) {
      flags.push("--glob", shellQuote(options.include));
    }

    const result = await this.run(sshId, [
      "rg",
      ...flags,
      "-e",
      shellQuote(options.pattern),
      "--",
      shellQuote(options.path),
    ]);

    if (result.exitCode === 2) {
      throw new Error(commandFailure("rg", result));
    }

    const matches: GrepMatch[] = [];
    let truncated = false;
    for (const line of result.stdout.split(/\r?\n/)) {
      if (line.length === 0) continue;
      const parsed = safeJson(line);
      if (parsed === undefined || parsed.type !== "match") continue;
      const data = parsed.data as Record<string, any> | undefined;
      if (!data) continue;
      if (matches.length >= maxMatches) {
        truncated = true;
        break;
      }
      const filePath = textOf(data.path) ?? options.path;
      const text = (textOf(data.lines) ?? "").replace(/\r?\n$/, "");
      matches.push({
        path: filePath,
        line: Number(data.line_number ?? 0),
        text,
      });
    }

    return { engine: "rg", matches, truncated };
  }

  private async grepWithGrep(
    sshId: string,
    options: GrepOptions,
    maxMatches: number,
  ): Promise<GrepResult> {
    const flags = [
      "-rIn",
      "--color=never",
      "--exclude-dir=.git",
      "--exclude-dir=node_modules",
    ];
    if (options.literal === true) flags.push("-F");
    if (options.caseSensitive === false) flags.push("-i");
    if (options.include !== undefined) {
      flags.push("--include", shellQuote(options.include));
    }

    const result = await this.run(sshId, [
      "grep",
      ...flags,
      "-e",
      shellQuote(options.pattern),
      "--",
      shellQuote(options.path),
    ]);

    if (result.exitCode === 2) {
      throw new Error(commandFailure("grep", result));
    }

    const matches: GrepMatch[] = [];
    let truncated = false;
    for (const line of result.stdout.split(/\r?\n/)) {
      if (line.length === 0) continue;
      const parsed = /^(.*?):(\d+):(.*)$/.exec(line);
      if (!parsed) continue;
      if (matches.length >= maxMatches) {
        truncated = true;
        break;
      }
      matches.push({
        path: parsed[1] ?? "",
        line: Number(parsed[2] ?? 0),
        text: parsed[3] ?? "",
      });
    }

    if (result.exitCode === 1 && matches.length === 0) {
      return { engine: "grep", matches, truncated: false };
    }
    return { engine: "grep", matches, truncated };
  }

  private async rgFiles(
    sshId: string,
    options: GlobOptions,
    maxResults: number,
  ): Promise<GlobResult> {
    const flags = ["--files", "--glob", shellQuote(options.pattern)];
    if (options.includeHidden === true) flags.push("--hidden");
    flags.push("--glob", shellQuote("!**/.git/**"));
    flags.push("--glob", shellQuote("!**/node_modules/**"));
    flags.push("-0");

    const result = await this.manager.exec({
      sshId,
      command: `rg ${flags.join(" ")}`,
      cwd: options.path,
      timeoutMs: SEARCH_TIMEOUT_MS,
      maxOutputBytes: SEARCH_MAX_BYTES,
    });
    if (result.exitCode !== 0) {
      return { engine: "rg", paths: [], truncated: false };
    }

    const paths = splitNul(result.stdout)
      .filter((entry) => entry.length > 0)
      .map((entry) => posix.join(options.path, entry))
      .sort();
    return {
      engine: "rg",
      paths: paths.slice(0, maxResults),
      truncated: paths.length > maxResults,
    };
  }

  private async findFiles(
    sshId: string,
    options: GlobOptions,
    maxResults: number,
  ): Promise<GlobResult> {
    const result = await this.run(sshId, [
      "find",
      shellQuote(options.path),
      "-type",
      "f",
      "-print0",
    ]);
    if (result.exitCode !== 0) {
      return { engine: "find", paths: [], truncated: false };
    }

    const matcher = globToRegExp(options.pattern);
    const paths: string[] = [];
    for (const entry of splitNul(result.stdout)) {
      if (entry.length === 0) continue;
      const relative = relativeTo(options.path, entry);
      if (isIgnored(relative, options.includeHidden !== true)) continue;
      if (!matcher.test(relative)) continue;
      paths.push(entry);
    }
    paths.sort();

    return {
      engine: "find",
      paths: paths.slice(0, maxResults),
      truncated: paths.length > maxResults,
    };
  }

  private async sftpFiles(
    sshId: string,
    options: GlobOptions,
    maxResults: number,
  ): Promise<GlobResult> {
    const sftp = await this.manager.sftp(sshId);
    const matcher = globToRegExp(options.pattern);
    const paths: string[] = [];
    let truncated = false;

    const visit = async (directory: string): Promise<void> => {
      const entries = await callSftp(sftp, directory);
      for (const entry of entries) {
        if (paths.length >= maxResults) {
          truncated = true;
          return;
        }
        const child = posix.join(directory, entry.filename);
        const relative = relativeTo(options.path, child);
        if (entry.attrs.isDirectory()) {
          if (isIgnored(relative, options.includeHidden !== true)) continue;
          await visit(child);
          continue;
        }
        if (!entry.attrs.isFile()) continue;
        if (isIgnored(relative, options.includeHidden !== true)) continue;
        if (!matcher.test(relative)) continue;
        paths.push(child);
      }
    };

    await visit(options.path);
    paths.sort();
    return {
      engine: "sftp",
      paths: paths.slice(0, maxResults),
      truncated: truncated || paths.length > maxResults,
    };
  }

  private run(sshId: string, argv: string[]): Promise<ExecResult> {
    return this.manager.exec({
      sshId,
      command: argv.join(" "),
      timeoutMs: SEARCH_TIMEOUT_MS,
      maxOutputBytes: SEARCH_MAX_BYTES,
    });
  }
}

export function globToRegExp(pattern: string): RegExp {
  const sources = expandBraces(pattern).map(globToSource);
  return new RegExp(`^(?:${sources.join("|")})$`);
}

function globToSource(pattern: string): string {
  let source = "";
  let index = 0;
  while (index < pattern.length) {
    const character = pattern[index] ?? "";
    if (character === "*") {
      if (pattern[index + 1] === "*") {
        index += 2;
        if (pattern[index] === "/") {
          source += "(?:.*/)?";
          index += 1;
        } else {
          source += ".*";
        }
        continue;
      }
      source += "[^/]*";
      index += 1;
      continue;
    }
    if (character === "?") {
      source += "[^/]";
      index += 1;
      continue;
    }
    if (character === "[") {
      const end = pattern.indexOf("]", index + 1);
      if (end === -1) {
        source += "\\[";
        index += 1;
        continue;
      }
      let body = pattern.slice(index + 1, end);
      if (body.startsWith("!")) body = `^${body.slice(1)}`;
      source += `[${body.replaceAll("\\", "\\\\")}]`;
      index = end + 1;
      continue;
    }
    source += escapeRegExp(character);
    index += 1;
  }
  return source;
}

function expandBraces(pattern: string): string[] {
  const open = pattern.indexOf("{");
  if (open === -1) return [pattern];
  const close = pattern.indexOf("}", open + 1);
  if (close === -1) return [pattern];

  const body = pattern.slice(open + 1, close);
  const options = splitTopLevel(body);
  if (options.length === 1) return [pattern];

  const prefix = pattern.slice(0, open);
  const suffix = pattern.slice(close + 1);
  return options.flatMap((option) => expandBraces(`${prefix}${option}${suffix}`));
}

function splitTopLevel(body: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = "";
  for (const character of body) {
    if (character === "," && depth === 0) {
      parts.push(current);
      current = "";
      continue;
    }
    if (character === "{") depth += 1;
    if (character === "}") depth -= 1;
    current += character;
  }
  parts.push(current);
  return parts;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function relativeTo(root: string, target: string): string {
  const normalizedRoot = posix.normalize(root);
  const normalizedTarget = posix.normalize(target);
  if (normalizedTarget === normalizedRoot) return ".";
  const prefix = normalizedRoot.endsWith("/")
    ? normalizedRoot
    : `${normalizedRoot}/`;
  return normalizedTarget.startsWith(prefix)
    ? normalizedTarget.slice(prefix.length)
    : normalizedTarget;
}

function isIgnored(relativePath: string, ignoreHidden: boolean): boolean {
  const segments = relativePath.split("/");
  if (segments.includes(".git")) return true;
  if (segments.includes("node_modules")) return true;
  if (ignoreHidden && segments.some((segment) => segment.startsWith("."))) {
    return true;
  }
  return false;
}

function parseProbe(stdout: string): RemoteTools {
  const tools: RemoteTools = { rg: false, grep: false, find: false };
  for (const line of stdout.split(/\r?\n/)) {
    const [name, value] = line.trim().split("=");
    if (name === "rg") tools.rg = value === "1";
    if (name === "grep") tools.grep = value === "1";
    if (name === "find") tools.find = value === "1";
  }
  return tools;
}

function textOf(value: unknown): string | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const record = value as Record<string, unknown>;
  if (typeof record.text === "string") return record.text;
  if (typeof record.bytes === "string") {
    return Buffer.from(record.bytes, "base64").toString("utf8");
  }
  return undefined;
}

function safeJson(line: string): Record<string, any> | undefined {
  try {
    return JSON.parse(line) as Record<string, any>;
  } catch {
    return undefined;
  }
}

function commandFailure(tool: string, result: ExecResult): string {
  const detail = result.stderr.trim() || result.stdout.trim() || "no output";
  return `${tool} failed with exit code ${result.exitCode}: ${detail}`;
}

function splitNul(value: string): string[] {
  return value.split("\u0000").filter((entry) => entry.length > 0);
}

function callSftp(
  sftp: SftpLike,
  directory: string,
): Promise<Array<{ filename: string; attrs: { isDirectory(): boolean; isFile(): boolean } }>> {
  return new Promise((resolve, reject) => {
    sftp.readdir(directory, (error, list) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(list);
    });
  });
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, Math.trunc(value)));
}
