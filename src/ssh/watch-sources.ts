import type { JobInfo, JobService } from "./jobs.js";
import { shellQuote } from "./command.js";
import type {
  JobReadiness,
  WatchCheck,
  WatchCheckContext,
  WatchDescriptor,
  WatchSource,
} from "./watch-types.js";

export interface WatchExecResult {
  exitCode: number | null;
  stdout: string;
  stderr?: string;
}

export type WatchExec = (input: {
  sshId: string;
  command: string;
  cwd?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
}) => Promise<WatchExecResult>;

export interface JobSourceOptions {
  jobs: Pick<JobService, "status">;
  runProbe?: (input: {
    sshId: string;
    jobId: string;
    jobDir: string;
    command: string;
    timeoutMs: number;
  }) => Promise<boolean>;
  sshId: string;
  jobId: string;
  logLines?: number;
  initialIntervalMs?: number;
  readyCommand?: string;
  readyTimeoutMs?: number;
  readyIntervalMs?: number;
  readyStableMs?: number;
}

const MIN_READY_CHECKS = 2;

export class JobSource implements WatchSource {
  readonly kind = "job" as const;
  readonly key: string;

  private readonly logLines: number;
  private readonly initialIntervalMs: number;
  private readonly readyTimeoutMs: number;
  private readonly readyIntervalMs: number;
  private readonly readyStableMs: number;
  private startedAt?: number;
  private readinessState: JobReadiness = "pending";
  private readySuccesses = 0;
  private readySince?: number;
  private readyAtValue?: number;

  constructor(private readonly options: JobSourceOptions) {
    this.key = `${options.sshId}:${options.jobId}`;
    this.logLines = options.logLines ?? 40;
    this.initialIntervalMs = options.initialIntervalMs ?? 5_000;
    this.readyTimeoutMs = options.readyTimeoutMs ?? 1_200_000;
    this.readyIntervalMs = options.readyIntervalMs ?? 5_000;
    this.readyStableMs = options.readyStableMs ?? 5_000;
  }

  get readiness(): JobReadiness | undefined {
    return this.options.readyCommand === undefined
      ? undefined
      : this.readinessState;
  }

  get readyAt(): number | undefined {
    return this.readyAtValue;
  }

  get descriptor(): WatchDescriptor {
    return {
      kind: "job",
      jobId: this.options.jobId,
      ...(this.options.readyCommand !== undefined
        ? { readyCommand: this.options.readyCommand }
        : {}),
      readyTimeoutMs: this.options.readyTimeoutMs ?? 1_200_000,
      readyIntervalMs: this.options.readyIntervalMs ?? 5_000,
      readyStableMs: this.options.readyStableMs ?? 5_000,
    };
  }

  async check(context: WatchCheckContext): Promise<WatchCheck> {
    const startedAt =
      this.startedAt ?? (this.startedAt = context.now);

    const result = await this.options.jobs.status(
      this.options.sshId,
      this.options.jobId,
      0,
    );
    if (Array.isArray(result)) {
      throw new Error("Expected a single job status.");
    }
    const info = result;

    if (isTerminal(info.state)) {
      const detailed = await this.withLogTail(info);
      const readiness =
        this.readyAtValue !== undefined
          ? "ready"
          : this.options.readyCommand !== undefined
            ? "failed"
            : undefined;
      if (readiness !== undefined) this.readinessState = readiness;
      return {
        state: "exited",
        event:
          this.readyAtValue !== undefined ? "service-exited" : "exit",
        ...(readiness !== undefined ? { readiness } : {}),
        ...(this.readyAtValue !== undefined
          ? { readyAt: this.readyAtValue }
          : {}),
        ...(detailed.exitCode !== undefined
          ? { exitCode: detailed.exitCode }
          : {}),
        ...(detailed.pid !== undefined ? { pid: detailed.pid } : {}),
        ...(detailed.logPath !== undefined
          ? { logPath: detailed.logPath }
          : {}),
        ...(detailed.log !== undefined ? { logTail: detailed.log } : {}),
      };
    }

    if (
      this.options.readyCommand !== undefined &&
      this.readyAtValue === undefined
    ) {
      const ok = await this.probe(info);
      if (ok) {
        if (this.readySince === undefined) this.readySince = context.now;
        this.readySuccesses += 1;
        const stableFor = context.now - this.readySince;
        if (
          this.readySuccesses >= MIN_READY_CHECKS &&
          stableFor >= this.readyStableMs
        ) {
          this.readinessState = "ready";
          this.readyAtValue = context.now;
          return {
            state: "ready",
            event: "ready",
            readiness: "ready",
            readyAt: this.readyAtValue,
            ...(info.pid !== undefined ? { pid: info.pid } : {}),
            ...(info.logPath !== undefined ? { logPath: info.logPath } : {}),
            nextIntervalMs: this.readyIntervalMs,
          };
        }
      } else {
        delete this.readySince;
        this.readySuccesses = 0;
      }

      if (context.now - startedAt >= this.readyTimeoutMs) {
        const detailed = await this.withLogTail(info);
        this.readinessState = "timeout";
        return {
          state: "timeout",
          event: "timeout",
          readiness: "timeout",
          ...(detailed.pid !== undefined ? { pid: detailed.pid } : {}),
          ...(detailed.logPath !== undefined
            ? { logPath: detailed.logPath }
            : {}),
          ...(detailed.log !== undefined ? { logTail: detailed.log } : {}),
        };
      }

      return {
        state: "pending",
        nextIntervalMs: this.readyIntervalMs,
      };
    }

    return {
      state: "pending",
      nextIntervalMs: nextJobInterval(
        context.now - startedAt,
        this.initialIntervalMs,
      ),
    };
  }

  private async probe(info: JobInfo): Promise<boolean> {
    if (this.options.runProbe === undefined) {
      throw new Error("ready_command requires a readiness probe adapter.");
    }
    return this.options.runProbe({
      sshId: this.options.sshId,
      jobId: this.options.jobId,
      jobDir: info.jobDir,
      command: this.options.readyCommand ?? "",
      timeoutMs: 10_000,
    });
  }

  private async withLogTail(info: JobInfo): Promise<JobInfo> {
    if (this.logLines <= 0 || info.log !== undefined) return info;
    try {
      const result = await this.options.jobs.status(
        this.options.sshId,
        this.options.jobId,
        this.logLines,
      );
      return Array.isArray(result) ? info : result;
    } catch {
      return info;
    }
  }
}

export interface PidSourceOptions {
  exec: WatchExec;
  sshId: string;
  pid?: number;
  pidFile?: string;
  logPath?: string;
  logLines?: number;
}

export class PidSource implements WatchSource {
  readonly kind = "pid" as const;
  readonly key: string;
  private resolvedPid?: number;

  constructor(private readonly options: PidSourceOptions) {
    this.key = `pid:${options.sshId}:${options.pid ?? options.pidFile ?? "unknown"}`;
  }

  get descriptor(): WatchDescriptor {
    return {
      kind: "pid",
      ...(this.options.pid !== undefined ? { pid: this.options.pid } : {}),
      ...(this.options.pidFile !== undefined
        ? { pidFile: this.options.pidFile }
        : {}),
      ...(this.options.logPath !== undefined
        ? { logPath: this.options.logPath }
        : {}),
      ...(this.options.logLines !== undefined
        ? { logLines: this.options.logLines }
        : {}),
    };
  }

  async check(context: WatchCheckContext): Promise<WatchCheck> {
    const pid = await this.resolvePid();
    const result = await this.options.exec({
      sshId: this.options.sshId,
      command: `kill -0 ${pid} 2>/dev/null`,
      timeoutMs: 10_000,
      maxOutputBytes: 1_024,
    });
    if (result.exitCode === 0) {
      return { state: "pending", nextIntervalMs: 5_000 };
    }

    const log = await this.readLogTail();
    return {
      state: "exited",
      event: "pid-exited",
      pid,
      ...(this.options.logPath !== undefined
        ? { logPath: this.options.logPath }
        : {}),
      ...(log !== undefined ? { logTail: log } : {}),
    };
  }

  private async resolvePid(): Promise<number> {
    if (this.options.pid !== undefined) return this.options.pid;
    if (this.resolvedPid !== undefined) return this.resolvedPid;
    if (this.options.pidFile === undefined) {
      throw new Error("pid or pid_file is required.");
    }

    const result = await this.options.exec({
      sshId: this.options.sshId,
      command: `cat -- ${shellQuote(this.options.pidFile)}`,
      timeoutMs: 10_000,
      maxOutputBytes: 1_024,
    });
    const pid = Number(result.stdout.trim());
    if (result.exitCode !== 0 || !Number.isInteger(pid) || pid <= 0) {
      throw new Error(
        `Unable to read a valid pid from ${this.options.pidFile}.`,
      );
    }
    this.resolvedPid = pid;
    return pid;
  }

  private async readLogTail(): Promise<string | undefined> {
    if (this.options.logPath === undefined) return undefined;
    try {
      const result = await this.options.exec({
        sshId: this.options.sshId,
        command: `tail -n ${Math.max(this.options.logLines ?? 40, 40)} -- ${shellQuote(this.options.logPath)} 2>/dev/null`,
        timeoutMs: 10_000,
        maxOutputBytes: 256 * 1_024,
      });
      return result.exitCode === 0
        ? result.stdout.replace(/\r?\n$/, "")
        : undefined;
    } catch {
      return undefined;
    }
  }
}

export interface LogSourceOptions {
  exec: WatchExec;
  sshId: string;
  logPath: string;
  successRegex?: string;
  failureRegex?: string;
  logLines?: number;
}

export class LogSource implements WatchSource {
  readonly kind = "log" as const;
  readonly key: string;
  private readonly success: RegExp | undefined;
  private readonly failure: RegExp | undefined;

  constructor(private readonly options: LogSourceOptions) {
    this.key = `log:${options.sshId}:${options.logPath}:${options.successRegex ?? ""}:${options.failureRegex ?? ""}`;
    this.success =
      options.successRegex !== undefined
        ? new RegExp(options.successRegex)
        : undefined;
    this.failure =
      options.failureRegex !== undefined
        ? new RegExp(options.failureRegex)
        : undefined;
  }

  get descriptor(): WatchDescriptor {
    return {
      kind: "log",
      logPath: this.options.logPath,
      ...(this.options.successRegex !== undefined
        ? { successRegex: this.options.successRegex }
        : {}),
      ...(this.options.failureRegex !== undefined
        ? { failureRegex: this.options.failureRegex }
        : {}),
      ...(this.options.logLines !== undefined
        ? { logLines: this.options.logLines }
        : {}),
    };
  }

  async check(context: WatchCheckContext): Promise<WatchCheck> {
    const result = await this.options.exec({
      sshId: this.options.sshId,
      command: `tail -n ${Math.max(this.options.logLines ?? 40, 200)} -- ${shellQuote(this.options.logPath)} 2>/dev/null`,
      timeoutMs: 10_000,
      maxOutputBytes: 256 * 1_024,
    });
    if (result.exitCode !== 0) {
      throw new Error(`Unable to read log ${this.options.logPath}.`);
    }

    if (this.success?.test(result.stdout)) {
      return {
        state: "exited",
        event: "log-matched",
        outcome: "success",
        ...(this.options.successRegex !== undefined
          ? { pattern: this.options.successRegex }
          : {}),
        logPath: this.options.logPath,
        logTail: result.stdout.replace(/\r?\n$/, ""),
      };
    }
    if (this.failure?.test(result.stdout)) {
      return {
        state: "exited",
        event: "log-matched",
        outcome: "failure",
        ...(this.options.failureRegex !== undefined
          ? { pattern: this.options.failureRegex }
          : {}),
        logPath: this.options.logPath,
        logTail: result.stdout.replace(/\r?\n$/, ""),
      };
    }

    return { state: "pending", nextIntervalMs: 5_000 };
  }
}

export interface HealthSourceOptions {
  exec: WatchExec;
  sshId: string;
  readyCommand: string;
  readyTimeoutMs?: number;
  readyIntervalMs?: number;
  readyStableMs?: number;
  logPath?: string;
  logLines?: number;
}

export class HealthSource implements WatchSource {
  readonly kind = "health" as const;
  readonly key: string;
  private readonly readyTimeoutMs: number;
  private readonly readyIntervalMs: number;
  private readonly readyStableMs: number;
  private startedAt?: number;
  private readySuccesses = 0;
  private readySince?: number;
  private readyAtValue?: number;

  constructor(private readonly options: HealthSourceOptions) {
    this.key = `health:${options.sshId}:${options.readyCommand}`;
    this.readyTimeoutMs = options.readyTimeoutMs ?? 1_200_000;
    this.readyIntervalMs = options.readyIntervalMs ?? 5_000;
    this.readyStableMs = options.readyStableMs ?? 5_000;
  }

  get readiness(): JobReadiness | undefined {
    return this.readyAtValue !== undefined ? "ready" : "pending";
  }

  get readyAt(): number | undefined {
    return this.readyAtValue;
  }

  get descriptor(): WatchDescriptor {
    return {
      kind: "health",
      readyCommand: this.options.readyCommand,
      readyTimeoutMs: this.readyTimeoutMs,
      readyIntervalMs: this.readyIntervalMs,
      readyStableMs: this.readyStableMs,
      ...(this.options.logPath !== undefined
        ? { logPath: this.options.logPath }
        : {}),
      ...(this.options.logLines !== undefined
        ? { logLines: this.options.logLines }
        : {}),
    };
  }

  async check(context: WatchCheckContext): Promise<WatchCheck> {
    const startedAt =
      this.startedAt ?? (this.startedAt = context.now);

    if (this.readyAtValue !== undefined) {
      return { state: "pending", nextIntervalMs: this.readyIntervalMs };
    }

    const ok = await this.probe();
    if (ok) {
      if (this.readySince === undefined) this.readySince = context.now;
      this.readySuccesses += 1;
      const stableFor = context.now - this.readySince;
      if (
        this.readySuccesses >= MIN_READY_CHECKS &&
        stableFor >= this.readyStableMs
      ) {
        this.readyAtValue = context.now;
        return {
          state: "ready",
          event: "ready",
          readiness: "ready",
          readyAt: this.readyAtValue,
          nextIntervalMs: this.readyIntervalMs,
        };
      }
    } else {
      delete this.readySince;
      this.readySuccesses = 0;
    }

    if (context.now - startedAt >= this.readyTimeoutMs) {
      const log = await this.readLogTail();
      return {
        state: "timeout",
        event: "timeout",
        readiness: "timeout",
        ...(this.options.logPath !== undefined
          ? { logPath: this.options.logPath }
          : {}),
        ...(log !== undefined ? { logTail: log } : {}),
      };
    }

    return { state: "pending", nextIntervalMs: this.readyIntervalMs };
  }

  private async probe(): Promise<boolean> {
    const result = await this.options.exec({
      sshId: this.options.sshId,
      command: this.options.readyCommand,
      timeoutMs: 10_000,
      maxOutputBytes: 8 * 1_024,
    });
    return result.exitCode === 0;
  }

  private async readLogTail(): Promise<string | undefined> {
    if (this.options.logPath === undefined) return undefined;
    try {
      const result = await this.options.exec({
        sshId: this.options.sshId,
        command: `tail -n ${Math.max(this.options.logLines ?? 40, 40)} -- ${shellQuote(this.options.logPath)} 2>/dev/null`,
        timeoutMs: 10_000,
        maxOutputBytes: 256 * 1_024,
      });
      return result.exitCode === 0
        ? result.stdout.replace(/\r?\n$/, "")
        : undefined;
    } catch {
      return undefined;
    }
  }
}

export class TimeoutSource implements WatchSource {
  readonly kind = "timeout" as const;
  readonly key: string;
  private startedAt?: number;

  constructor(private readonly timeoutMs: number) {
    this.key = `timeout:${timeoutMs}`;
  }

  get descriptor(): WatchDescriptor {
    return { kind: "timeout", timeoutMs: this.timeoutMs };
  }

  async check(context: WatchCheckContext): Promise<WatchCheck> {
    const startedAt =
      this.startedAt ?? (this.startedAt = context.now);
    const elapsed = context.now - startedAt;
    if (elapsed >= this.timeoutMs) {
      return { state: "timeout", event: "timeout" };
    }
    return {
      state: "pending",
      nextIntervalMs: Math.min(5_000, Math.max(500, this.timeoutMs - elapsed)),
    };
  }
}

export class CompositeSource implements WatchSource {
  readonly kind = "composite" as const;
  readonly key?: string;

  constructor(private readonly sources: WatchSource[]) {
    const keys = sources
      .map((source) => source.key)
      .filter((key): key is string => key !== undefined);
    if (keys.length > 0) {
      this.key = `composite:${keys.join("|")}`;
    }
  }

  get descriptor(): WatchDescriptor {
    return {
      kind: "composite",
      sources: this.sources
        .map((source) => source.descriptor)
        .filter((descriptor): descriptor is WatchDescriptor => descriptor !== undefined),
    };
  }

  async check(context: WatchCheckContext): Promise<WatchCheck> {
    const checks = await Promise.all(
      this.sources.map((source) => source.check(context)),
    );
    const terminal = checks.find(
      (check) =>
        check.state === "exited" ||
        check.state === "timeout" ||
        check.state === "monitor-stopped",
    );
    if (terminal !== undefined) return terminal;

    const ready = checks.find((check) => check.state === "ready");
    if (ready !== undefined) return ready;

    const intervals = checks
      .map((check) => check.nextIntervalMs)
      .filter((value): value is number => value !== undefined);
    return {
      state: "pending",
      ...(intervals.length > 0
        ? { nextIntervalMs: Math.min(...intervals) }
        : {}),
    };
  }
}

function isTerminal(state: JobInfo["state"]): boolean {
  return (
    state === "finished" ||
    state === "stopped" ||
    state === "lost" ||
    state === "corrupt"
  );
}

function nextJobInterval(elapsed: number, initial: number): number {
  if (elapsed < 60_000) return initial;
  if (elapsed < 10 * 60_000) return Math.max(initial, 10_000);
  return Math.max(initial, 30_000);
}
