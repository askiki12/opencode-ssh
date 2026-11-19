import path from "node:path";
import { InvalidGlobPatternError, compileGlob } from "./glob.js";
import type { GlobMatcher } from "./glob.js";
import { shellQuote } from "./command.js";
import { SshOperationError } from "./errors.js";
import { errorMessage } from "../util.js";
import type { ConnectionManager, ExecResult } from "./manager.js";
import type { SftpLike } from "./files.js";

const posix = path.posix;

const SEARCH_TIMEOUT_MS = 60_000;
const SEARCH_MAX_BYTES = 8 * 1024 * 1024;

export interface RemoteTools {
  rg: boolean;
  grep: boolean;
  find: boolean;
  /**
   * True when grep accepts the GNU/BSD long options we use for exclusions
   * (notably --exclude-dir). BusyBox grep does not, so the fallback has to
   * filter results after the search instead.
   */
  grepExtended: boolean;
}

export interface GrepOptions {
  pattern: string;
  path: string;
  /** Basename glob, for example *.ts. Use path to scope directories. */
  include?: string;
  literal?: boolean;
  caseSensitive?: boolean;
  includeHidden?: boolean;
  /** Include files normally excluded by .gitignore (ripgrep only). */
  includeIgnored?: boolean;
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
  /** True when the search may be missing results (errors or truncation). */
  incomplete: boolean;
  warnings: string[];
}

export interface GlobOptions {
  pattern: string;
  path: string;
  maxResults?: number;
  includeHidden?: boolean;
  /** Include files normally excluded by .gitignore (ripgrep only). */
  includeIgnored?: boolean;
}

export interface GlobResult {
  engine: "rg" | "find" | "sftp";
  paths: string[];
  truncated: boolean;
  /** True when the search may be missing results (errors or truncation). */
  incomplete: boolean;
  warnings: string[];
}

/**
 * Remote search runs on the server: ripping every byte over SFTP is far slower
 * than letting the remote host use ripgrep or grep. Probing is cached per
 * connection because the result only changes when the host does.
 */
export class SearchService {
  private readonly probes = new Map<string, Promise<RemoteTools>>();

  constructor(private readonly manager: ConnectionManager) {}

  async tools(sshId: string, signal?: AbortSignal): Promise<RemoteTools> {
    const cached = this.probes.get(sshId);
    if (cached) return cached;

    const probe = this.manager
      .exec(
        {
          sshId,
          command:
            "for tool in rg grep find; do if command -v \"$tool\" >/dev/null 2>&1; then echo \"$tool=1\"; else echo \"$tool=0\"; fi; done; " +
            "if grep --help 2>&1 | grep -q -- '--exclude-dir'; then echo grep_extended=1; else echo grep_extended=0; fi",
          timeoutMs: 15_000,
          maxOutputBytes: 4_096,
        },
        signal,
      )
      .then((result) => parseProbe(result.stdout));

    this.probes.set(sshId, probe);
    probe.catch(() => this.probes.delete(sshId));
    return probe;
  }

  async grep(
    sshId: string,
    options: GrepOptions,
    signal?: AbortSignal,
  ): Promise<GrepResult> {
    const maxMatches = clamp(options.maxMatches ?? 200, 1, 5_000);
    const include = compileInclude(options.include);
    const tools = await this.tools(sshId, signal);
    if (tools.rg) {
      return this.grepWithRipgrep(
        sshId,
        options,
        include,
        maxMatches,
        signal,
      );
    }
    if (tools.grep) {
      return this.grepWithGrep(
        sshId,
        tools.grepExtended,
        options,
        include,
        maxMatches,
        signal,
      );
    }
    throw new SshOperationError(
      "Remote host has neither ripgrep (rg) nor grep. Install ripgrep with the " +
        "remote package manager (for example: apt install ripgrep) or use ssh_exec " +
        "to inspect files directly.",
      {
        code: "SSH_INTERNAL_ERROR",
        retryable: false,
        hint: "Install ripgrep on the remote host (for example: apt install ripgrep) and ask the user before installing.",
        recommendedNextTool: "ssh_exec",
        executionMayHaveStarted: false,
      },
    );
  }

  async glob(
    sshId: string,
    options: GlobOptions,
    signal?: AbortSignal,
  ): Promise<GlobResult> {
    const matcher = compileGlob(options.pattern);
    const tools = await this.tools(sshId, signal);
    const maxResults = clamp(options.maxResults ?? 2_000, 1, 5_000);
    // Pick one engine and accept an empty result as success. Falling through
    // on zero matches would scan the tree up to three times.
    if (tools.rg) {
      return this.rgFiles(sshId, options, matcher, maxResults, signal);
    }
    if (tools.find) {
      return this.findFiles(sshId, options, matcher, maxResults, signal);
    }
    return this.sftpFiles(sshId, options, matcher, maxResults, signal);
  }

  private async grepWithRipgrep(
    sshId: string,
    options: GrepOptions,
    include: GlobMatcher | undefined,
    maxMatches: number,
    signal?: AbortSignal,
  ): Promise<GrepResult> {
    const flags = ["--no-config", "--json"];
    if (options.includeHidden === true) flags.push("--hidden");
    if (options.includeIgnored === true) flags.push("--no-ignore");
    if (options.literal === true) flags.push("-F");
    if (options.caseSensitive === false) flags.push("-i");
    // If the search root itself is .git or node_modules, do not exclude the
    // whole subtree: the exclusions are meant for descendants of a normal root.
    const rootName = posix.basename(options.path);
    if (rootName !== ".git") {
      flags.push("--glob", shellQuote("!**/.git/**"));
    }
    if (rootName !== "node_modules") {
      flags.push("--glob", shellQuote("!**/node_modules/**"));
    }

    const result = await this.run(
      sshId,
      [
        "rg",
        ...flags,
        "-e",
        shellQuote(options.pattern),
        "--",
        shellQuote(options.path),
      ],
      signal,
    );

    const command = commandWarnings("rg", result, 1);
    const matches: GrepMatch[] = [];
    let truncated = false;
    // Parse even on exit code 2: ripgrep still prints matches it found before
    // or despite file errors. Discarding them would turn an incomplete search
    // into a false "no matches".
    for (const line of result.stdout.split(/\r?\n/)) {
      if (line.length === 0) continue;
      const parsed = safeJson(line);
      if (parsed === undefined || parsed.type !== "match") continue;
      const data = parsed.data as Record<string, any> | undefined;
      if (!data) continue;
      const filePath = textOf(data.path) ?? options.path;
      if (
        !keepGrepMatch(
          filePath,
          options.path,
          options.includeHidden,
          include,
        )
      ) {
        continue;
      }
      if (matches.length >= maxMatches) {
        truncated = true;
        break;
      }
      const text = (textOf(data.lines) ?? "").replace(/\r?\n$/, "");
      matches.push({
        path: filePath,
        line: Number(data.line_number ?? 0),
        text,
      });
    }
    assertCommandInput("rg", result, matches.length);

    return {
      engine: "rg",
      matches,
      truncated: truncated || result.truncated,
      incomplete: truncated || result.truncated || command.incomplete,
      warnings: command.warnings,
    };
  }

  private async grepWithGrep(
    sshId: string,
    grepExtended: boolean,
    options: GrepOptions,
    include: GlobMatcher | undefined,
    maxMatches: number,
    signal?: AbortSignal,
  ): Promise<GrepResult> {
    const flags = [
      "-r",
      "-n",
      // Force the filename prefix. grep omits it for a single file operand,
      // which would make the path:line:text output below unparseable.
      "-H",
    ];
    // Prefer ERE so common quantifiers and alternation behave like ripgrep.
    flags.push(options.literal === true ? "-F" : "-E");
    if (options.caseSensitive === false) flags.push("-i");
    if (grepExtended) {
      flags.push("--color=never", "-I");
      const rootName = posix.basename(options.path);
      if (rootName !== ".git") flags.push("--exclude-dir=.git");
      if (rootName !== "node_modules") flags.push("--exclude-dir=node_modules");
      // Do not prune a hidden explicit root such as ~/.config.
      if (options.includeHidden !== true && !rootName.startsWith(".")) {
        flags.push("--exclude-dir=.*");
      }
    }

    // The path is absolute and the pattern is consumed by -e, so "--" is not
    // needed and omitting it keeps BusyBox grep happy.
    const result = await this.run(
      sshId,
      [
        "grep",
        ...flags,
        "-e",
        shellQuote(options.pattern),
        shellQuote(options.path),
      ],
      signal,
    );

    const command = commandWarnings("grep", result, 1);
    const warnings = [
      ...ignoredEngineWarnings("grep", options.includeIgnored),
      ...(grepExtended ? [] : [portableGrepWarning()]),
      ...command.warnings,
    ];
    const matches: GrepMatch[] = [];
    let truncated = false;
    for (const line of result.stdout.split(/\r?\n/)) {
      if (line.length === 0) continue;
      // grep has no portable NUL-delimited filename output, so a filename
      // containing ":<digits>:" is inherently ambiguous here. ripgrep uses
      // --json and does not have this limitation.
      const parsed = /^(.*?):(\d+):(.*)$/.exec(line);
      if (!parsed) continue;
      const filePath = parsed[1] ?? "";
      if (
        !keepGrepMatch(
          filePath,
          options.path,
          options.includeHidden,
          include,
        )
      ) {
        continue;
      }
      if (matches.length >= maxMatches) {
        truncated = true;
        break;
      }
      matches.push({
        path: filePath,
        line: Number(parsed[2] ?? 0),
        text: parsed[3] ?? "",
      });
    }
    assertCommandInput("grep", result, matches.length);

    return {
      engine: "grep",
      matches,
      truncated: truncated || result.truncated,
      incomplete: truncated || result.truncated || command.incomplete,
      warnings,
    };
  }

  private async rgFiles(
    sshId: string,
    options: GlobOptions,
    matcher: GlobMatcher,
    maxResults: number,
    signal?: AbortSignal,
  ): Promise<GlobResult> {
    const flags = ["--no-config", "--files"];
    if (options.includeHidden === true) flags.push("--hidden");
    if (options.includeIgnored === true) flags.push("--no-ignore");
    // Exclude only descendants of a normal root. If the root itself is .git or
    // node_modules, an exclusion glob would hide the whole explicit subtree.
    const rootName = posix.basename(options.path);
    if (rootName !== ".git") {
      flags.push("--glob", shellQuote("!**/.git/**"));
    }
    if (rootName !== "node_modules") {
      flags.push("--glob", shellQuote("!**/node_modules/**"));
    }
    flags.push("-0");

    // Pass the root as an operand instead of using cwd: a failed `cd` also
    // exits 1, which is indistinguishable from ripgrep's legitimate "no
    // files" status and would hide the real error.
    const result = await this.run(
      sshId,
      ["rg", ...flags, "--", shellQuote(options.path)],
      signal,
      // -0 output is NUL-separated; terminal sanitization would strip it.
      true,
    );

    const command = commandWarnings("rg", result, 1);
    // Do not pass the pattern as --glob: ripgrep globs override .gitignore,
    // which would silently change the documented "respect ignore" default.
    // List files under the normal ignore rules, then filter locally.
    const paths: string[] = [];
    for (const entry of splitNulOutput(result.stdout, result.truncated)) {
      if (entry.length === 0) continue;
      const absolute = listedPath(options.path, entry);
      const relative = relativeTo(options.path, absolute);
      if (isIgnored(relative, options.includeHidden !== true)) continue;
      if (!matcher(relative)) continue;
      paths.push(absolute);
    }
    paths.sort();
    const truncated = result.truncated || paths.length > maxResults;
    return {
      engine: "rg",
      paths: paths.slice(0, maxResults),
      truncated,
      incomplete: truncated || command.incomplete,
      warnings: command.warnings,
    };
  }

  private async findFiles(
    sshId: string,
    options: GlobOptions,
    matcher: GlobMatcher,
    maxResults: number,
    signal?: AbortSignal,
  ): Promise<GlobResult> {
    // Prune ignored directories during the walk instead of downloading their
    // entire contents and filtering afterwards.
    const names =
      options.includeHidden === true
        ? [".git", "node_modules"]
        : [".git", "node_modules", ".*"];
    const nameTests: string[] = [];
    for (const [index, name] of names.entries()) {
      if (index > 0) nameTests.push("-o");
      nameTests.push("-name", shellQuote(name));
    }
    const result = await this.run(
      sshId,
      [
        "find",
        shellQuote(options.path),
        "-mindepth",
        "1",
        "\\(",
        ...nameTests,
        "\\)",
        "-prune",
        "-o",
        "-type",
        "f",
        "-print0",
      ],
      signal,
      // -print0 output is NUL-separated; keep the separators intact.
      true,
    );
    const command = commandWarnings("find", result);
    const warnings = [
      ...ignoredEngineWarnings("find", options.includeIgnored),
      ...command.warnings,
    ];

    const paths: string[] = [];
    for (const entry of splitNulOutput(result.stdout, result.truncated)) {
      if (entry.length === 0) continue;
      const relative = relativeTo(options.path, entry);
      if (isIgnored(relative, options.includeHidden !== true)) continue;
      if (!matcher(relative)) continue;
      paths.push(entry);
    }
    paths.sort();

    const truncated = result.truncated || paths.length > maxResults;
    return {
      engine: "find",
      paths: paths.slice(0, maxResults),
      truncated,
      incomplete: truncated || command.incomplete,
      warnings,
    };
  }

  private async sftpFiles(
    sshId: string,
    options: GlobOptions,
    matcher: GlobMatcher,
    maxResults: number,
    signal?: AbortSignal,
  ): Promise<GlobResult> {
    const sftp = await this.manager.sftp(sshId);
    const paths: string[] = [];
    const warnings = ignoredEngineWarnings("sftp", options.includeIgnored);
    let truncated = false;
    let incomplete = false;

    const visit = async (directory: string): Promise<void> => {
      if (signal?.aborted) throw new Error("Search aborted.");
      let entries: Awaited<ReturnType<typeof callSftp>>;
      try {
        entries = await callSftp(sftp, directory);
      } catch (error) {
        warnings.push(`Cannot read ${directory}: ${errorMessage(error)}`);
        incomplete = true;
        return;
      }
      for (const entry of entries) {
        if (signal?.aborted) throw new Error("Search aborted.");
        const child = posix.join(directory, entry.filename);
        const relative = relativeTo(options.path, child);
        if (entry.attrs.isDirectory()) {
          if (isIgnored(relative, options.includeHidden !== true)) continue;
          await visit(child);
          continue;
        }
        if (!entry.attrs.isFile()) continue;
        if (isIgnored(relative, options.includeHidden !== true)) continue;
        if (!matcher(relative)) continue;
        if (paths.length >= maxResults) {
          // Only a real extra match proves the result was truncated. Checking
          // the limit before every entry produced false positives when the
          // remaining entries did not match.
          truncated = true;
          return;
        }
        paths.push(child);
      }
    };

    await visit(options.path);
    paths.sort();
    return {
      engine: "sftp",
      paths: paths.slice(0, maxResults),
      truncated,
      incomplete: truncated || incomplete,
      warnings,
    };
  }

  private run(
    sshId: string,
    argv: string[],
    signal?: AbortSignal,
    rawOutput = false,
  ): Promise<ExecResult> {
    return this.manager.exec(
      {
        sshId,
        command: argv.join(" "),
        timeoutMs: SEARCH_TIMEOUT_MS,
        maxOutputBytes: SEARCH_MAX_BYTES,
        rawOutput,
      },
      signal,
    );
  }
}

function compileInclude(pattern: string | undefined): GlobMatcher | undefined {
  if (pattern === undefined) return undefined;
  if (pattern.includes("/")) {
    throw new InvalidGlobPatternError(
      pattern,
      `Invalid include glob ${JSON.stringify(pattern)}: include matches file names only; use path to scope directories.`,
    );
  }
  return compileGlob(pattern);
}

/**
 * Apply the flags that must not be delegated to the search command. include
 * is a basename filter so it behaves like grep --include and never changes
 * ignore rules.
 */
function keepGrepMatch(
  matchPath: string,
  root: string,
  includeHidden: boolean | undefined,
  include: GlobMatcher | undefined,
): boolean {
  const relative = relativeTo(root, matchPath);
  if (isIgnored(relative, includeHidden !== true)) return false;
  if (include === undefined) return true;
  return include(posix.basename(matchPath));
}

function portableGrepWarning(): string {
  return (
    "This grep does not support --exclude-dir; hidden, .git, and node_modules " +
    "matches are filtered after the search, so large trees may be truncated."
  );
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

function ignoredEngineWarnings(
  engine: "grep" | "find" | "sftp",
  includeIgnored: boolean | undefined,
): string[] {
  if (includeIgnored === true) return [];
  return [
    `${engine} cannot read .gitignore; results may include ignored files. ` +
      "Install ripgrep for consistent ignore semantics.",
  ];
}

const INPUT_ERROR_PATTERNS: readonly RegExp[] = [
  /regex parse error/i,
  /error parsing glob/i,
  /invalid regular expression/i,
  /invalid regex/i,
  /unmatched [\[(]/i,
  /trailing backslash/i,
  /invalid character class/i,
  /invalid repetition/i,
  /invalid range/i,
  /backreferences are not supported/i,
  /look-around[^.]*not supported/i,
  /unrecognized option/i,
  /invalid option/i,
  /unknown option/i,
  /usage:/i,
];

/**
 * A command that fails before producing any matches is usually a bad pattern
 * or an unsupported option, not a "no matches" result. Surface it as an input
 * error instead of returning an empty, warning-only result.
 */
function assertCommandInput(
  label: string,
  result: ExecResult,
  matchCount: number,
): void {
  if (matchCount > 0 || result.exitCode !== 2) return;
  const detail = result.stderr.trim();
  if (detail.length === 0) return;
  if (!INPUT_ERROR_PATTERNS.some((pattern) => pattern.test(detail))) return;

  const unsupported = /unrecognized option|invalid option|unknown option|usage:/i.test(
    detail,
  );
  throw new SshOperationError(
    `${label} rejected the pattern or options: ${detail}`,
    {
      code: "SSH_INVALID_INPUT",
      retryable: false,
      hint: unsupported
        ? "The remote grep does not support the required options. Install ripgrep with ssh_exec (ask the user first) or retry with literal=true."
        : "Fix the pattern and retry. ripgrep uses Rust regex; grep uses POSIX extended regex. Use literal=true to search the text literally.",
      executionMayHaveStarted: false,
    },
  );
}

function commandWarnings(
  label: string,
  result: ExecResult,
  noMatchExitCode?: number,
): { warnings: string[]; incomplete: boolean } {
  const detail = result.stderr.trim();
  const noMatch =
    noMatchExitCode !== undefined && result.exitCode === noMatchExitCode;
  const failed = !noMatch && result.exitCode !== 0;
  const warnings: string[] = [];
  if (failed) {
    const code = result.exitCode === null ? "unknown" : result.exitCode;
    warnings.push(
      `${label} exited with code ${code}${
        detail.length > 0 ? `: ${detail}` : ""
      }; results may be incomplete.`,
    );
  } else if (detail.length > 0) {
    warnings.push(`${label} reported: ${detail}`);
  }
  return { warnings, incomplete: failed };
}

function splitNul(value: string): string[] {
  return value.split("\u0000").filter((entry) => entry.length > 0);
}

/**
 * Split NUL-separated output, discarding partial entries at a truncation
 * boundary. OutputCollector keeps the head and tail with a text marker in
 * between; without this, the last head fragment and first tail fragment would
 * be merged into one bogus path.
 */
function splitNulOutput(value: string, truncated: boolean): string[] {
  if (!truncated) return splitNul(value);
  const markerStart = value.indexOf("\n[... ");
  if (markerStart === -1) return splitNul(value);
  const markerEnd = value.indexOf("]\n", markerStart);
  if (markerEnd === -1) return [];

  const headRaw = value.slice(0, markerStart);
  const tailRaw = value.slice(markerEnd + 2);
  const head = headRaw.length === 0 ? [] : headRaw.split("\u0000");
  const tail = tailRaw.length === 0 ? [] : tailRaw.split("\u0000");
  if (head.length > 0 && !headRaw.endsWith("\u0000")) head.pop();
  if (tail.length > 0 && !tailRaw.startsWith("\u0000")) tail.shift();
  return [...head, ...tail].filter((entry) => entry.length > 0);
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

function parseProbe(stdout: string): RemoteTools {
  const tools: RemoteTools = {
    rg: false,
    grep: false,
    find: false,
    grepExtended: false,
  };
  for (const line of stdout.split(/\r?\n/)) {
    const [name, value] = line.trim().split("=");
    if (name === "rg") tools.rg = value === "1";
    if (name === "grep") tools.grep = value === "1";
    if (name === "find") tools.find = value === "1";
    if (name === "grep_extended") tools.grepExtended = value === "1";
  }
  return tools;
}

/**
 * Turn a path printed by ripgrep into an absolute remote path. ripgrep prints
 * absolute paths for an absolute operand, but older versions and tests may
 * print relative paths or a leading "./".
 */
function listedPath(root: string, entry: string): string {
  const cleaned = entry.replace(/^\.\//, "");
  return cleaned.startsWith("/")
    ? posix.normalize(cleaned)
    : posix.join(root, cleaned);
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
  // A search root that is itself a file has the relative path ".". It is an
  // explicit target, so do not filter it even when it is hidden or named .git.
  if (relativePath === "." || relativePath.length === 0) return false;
  const segments = relativePath.split("/");
  if (segments.includes(".git")) return true;
  if (segments.includes("node_modules")) return true;
  if (ignoreHidden && segments.some((segment) => segment.startsWith("."))) {
    return true;
  }
  return false;
}
