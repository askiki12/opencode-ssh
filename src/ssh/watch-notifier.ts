import { randomBytes } from "node:crypto";
import type { JobInfo, JobState, JobService } from "./jobs.js";

export type JobNoticeEvent =
  | "exit"
  | "ready"
  | "timeout"
  | "service-exited"
  | "monitor-stopped";

export type JobReadiness = "pending" | "ready" | "failed" | "timeout";

export interface WatchJobInput {
  sshId: string;
  jobId: string;
  sessionID: string;
  agent?: string;
  name?: string;
  hostLabel?: string;
  logLines?: number;
  /** When set, the job is treated as a service and probed until ready. */
  readyCommand?: string;
  readyTimeoutMs?: number;
  readyIntervalMs?: number;
  readyStableMs?: number;
  /** Continue watching for an exit after the service becomes ready. */
  watchAfterReady?: boolean;
}

export interface JobNotice {
  event: JobNoticeEvent;
  sshId: string;
  jobId: string;
  sessionID: string;
  agent?: string;
  name?: string;
  hostLabel?: string;
  state: JobState;
  readiness?: JobReadiness;
  readyAt?: number;
  exitCode?: number | null;
  pid?: number;
  elapsedMs?: number;
  elapsedSinceReadyMs?: number;
  logPath?: string;
  logTail?: string;
  message?: string;
}

export interface WatchNotifierOptions {
  jobs: Pick<JobService, "status">;
  notify: (notice: JobNotice) => Promise<void>;
  /** Phase 1.5: execute ready_command through the SSH connection. */
  runProbe?: (input: {
    sshId: string;
    jobId: string;
    jobDir: string;
    command: string;
    timeoutMs: number;
  }) => Promise<boolean>;
  logLines?: number;
  initialIntervalMs?: number;
  maxIntervalMs?: number;
  readyIntervalMs?: number;
  readyTimeoutMs?: number;
  readyStableMs?: number;
  watchAfterReady?: boolean;
  maxFailures?: number;
  onError?: (error: unknown) => void;
  /** Injectable clock and sleep for tests. */
  now?: () => number;
  sleep?: (milliseconds: number, signal: AbortSignal) => Promise<void>;
}

export interface WatchSummary {
  watchId: string;
  sshId: string;
  jobId: string;
  sessionID: string;
  name?: string;
  hostLabel?: string;
  /** Only present for service jobs with ready_command. */
  readiness?: JobReadiness;
  startedAt: number;
}

interface CompletedWatch {
  readiness: JobReadiness;
  readyAt?: number;
  completedAt: number;
}

interface JobWatchRecord extends Required<Pick<WatchJobInput, "sshId" | "jobId" | "sessionID">> {
  watchId: string;
  key: string;
  agent?: string;
  name?: string;
  hostLabel?: string;
  logLines: number;
  readyCommand?: string;
  readyTimeoutMs: number;
  readyIntervalMs: number;
  readyStableMs: number;
  watchAfterReady: boolean;
  startedAt: number;
  readiness: JobReadiness;
  readySuccesses: number;
  readySince?: number;
  readyAt?: number;
  notified: boolean;
  crashNotified: boolean;
  failures: number;
  intervalMs: number;
  abort: AbortController;
  lastInfo?: JobInfo;
}

const TERMINAL_STATES: ReadonlySet<JobState> = new Set([
  "finished",
  "stopped",
  "lost",
  "corrupt",
]);

const MIN_READY_CHECKS = 2;

export class WatchNotifier {
  private readonly active = new Map<string, JobWatchRecord>();
  private readonly completed = new Map<string, CompletedWatch>();

  constructor(private readonly options: WatchNotifierOptions) {}

  /**
   * Start watching a job. Passing the same sshId/jobId twice returns the
   * existing watch instead of creating a duplicate notification stream.
   */
  watchJob(input: WatchJobInput): string {
    const key = `${input.sshId}:${input.jobId}`;
    const existing = [...this.active.values()].find((record) => record.key === key);
    if (existing) return existing.watchId;

    // Reattaching with a new ssh_id must supersede the old watch for the same
    // job; otherwise the disconnected watch can emit a late "monitor stopped".
    for (const record of [...this.active.values()]) {
      if (record.jobId !== input.jobId) continue;
      record.abort.abort();
      this.active.delete(record.watchId);
    }

    const watchId = `watch_${randomBytes(6).toString("hex")}`;
    const record: JobWatchRecord = {
      watchId,
      key,
      sshId: input.sshId,
      jobId: input.jobId,
      sessionID: input.sessionID,
      ...(input.agent !== undefined ? { agent: input.agent } : {}),
      ...(input.name !== undefined ? { name: input.name } : {}),
      ...(input.hostLabel !== undefined ? { hostLabel: input.hostLabel } : {}),
      logLines: input.logLines ?? this.options.logLines ?? 40,
      ...(input.readyCommand !== undefined
        ? { readyCommand: input.readyCommand }
        : {}),
      readyTimeoutMs: input.readyTimeoutMs ?? this.options.readyTimeoutMs ?? 1_200_000,
      readyIntervalMs: input.readyIntervalMs ?? this.options.readyIntervalMs ?? 5_000,
      readyStableMs: input.readyStableMs ?? this.options.readyStableMs ?? 5_000,
      watchAfterReady:
        input.watchAfterReady ?? this.options.watchAfterReady ?? false,
      startedAt: this.now(),
      readiness: "pending",
      readySuccesses: 0,
      notified: false,
      crashNotified: false,
      failures: 0,
      intervalMs: this.options.initialIntervalMs ?? 5_000,
      abort: new AbortController(),
    };

    this.active.set(watchId, record);
    void this.run(record).catch((error) => {
      this.options.onError?.(error);
    });
    return watchId;
  }

  unwatch(watchId: string): boolean {
    const record = this.active.get(watchId);
    if (!record) return false;
    record.abort.abort();
    this.active.delete(watchId);
    return true;
  }

  list(): WatchSummary[] {
    return [...this.active.values()]
      .map((record) => ({
        watchId: record.watchId,
        sshId: record.sshId,
        jobId: record.jobId,
        sessionID: record.sessionID,
        ...(record.name !== undefined ? { name: record.name } : {}),
        ...(record.hostLabel !== undefined ? { hostLabel: record.hostLabel } : {}),
        ...(record.readyCommand !== undefined
          ? { readiness: record.readiness }
          : {}),
        startedAt: record.startedAt,
      }))
      .sort((left, right) => left.startedAt - right.startedAt);
  }

  /** Used by ssh_job_status to show readiness without reading the remote job dir. */
  describe(
    sshId: string,
    jobId: string,
  ): { readiness?: JobReadiness; readyAt?: number } | undefined {
    const key = `${sshId}:${jobId}`;
    const record = [...this.active.values()].find((item) => item.key === key);
    if (record) {
      if (!record.readyCommand && record.readyAt === undefined) return undefined;
      return {
        readiness: record.readiness,
        ...(record.readyAt !== undefined ? { readyAt: record.readyAt } : {}),
      };
    }

    const completed = this.completed.get(key);
    if (!completed) return undefined;
    return {
      readiness: completed.readiness,
      ...(completed.readyAt !== undefined ? { readyAt: completed.readyAt } : {}),
    };
  }

  dispose(): void {
    for (const record of this.active.values()) record.abort.abort();
    this.active.clear();
    this.completed.clear();
  }

  private async run(record: JobWatchRecord): Promise<void> {
    try {
      while (!record.abort.signal.aborted) {
        let info: JobInfo;
        try {
          const result = await this.options.jobs.status(
            record.sshId,
            record.jobId,
            0,
          );
          if (Array.isArray(result)) {
            throw new Error("Expected a single job status.");
          }
          info = result;
          record.lastInfo = info;
          record.failures = 0;
          if (record.abort.signal.aborted) return;
        } catch (error) {
          if (record.abort.signal.aborted) return;
          record.failures += 1;
          if (record.failures >= (this.options.maxFailures ?? 10)) {
            await this.notifyMonitorStopped(record, error);
            return;
          }
          record.intervalMs = Math.min(
            this.options.maxIntervalMs ?? 60_000,
            Math.max(
              record.intervalMs * 2,
              this.options.initialIntervalMs ?? 5_000,
            ),
          );
          await this.sleep(record.intervalMs, record.abort.signal);
          continue;
        }

        if (TERMINAL_STATES.has(info.state)) {
          const detailed = await this.withLogTail(record, info);
          if (record.readyAt !== undefined && record.watchAfterReady) {
            await this.notifyServiceExited(record, detailed);
          } else {
            await this.notifyExit(record, detailed);
          }
          return;
        }

        if (record.readyCommand !== undefined && record.readyAt === undefined) {
          const ok = await this.probe(record, info);
          if (record.abort.signal.aborted) return;
          const now = this.now();

          if (ok) {
            if (record.readySince === undefined) record.readySince = now;
            record.readySuccesses += 1;
            const stableFor = now - record.readySince;
            if (
              record.readySuccesses >= MIN_READY_CHECKS &&
              stableFor >= record.readyStableMs
            ) {
              record.readiness = "ready";
              record.readyAt = now;
              await this.notifyReady(record, info);
              if (!record.watchAfterReady) return;
            }
          } else {
            delete record.readySince;
            record.readySuccesses = 0;
          }

          if (now - record.startedAt >= record.readyTimeoutMs) {
            record.readiness = "timeout";
            await this.notifyTimeout(record, info);
            return;
          }
        }

        const elapsed = this.now() - record.startedAt;
        record.intervalMs = nextInterval(
          elapsed,
          this.options.initialIntervalMs ?? 5_000,
          this.options.maxIntervalMs ?? 60_000,
        );
        const sleepMs =
          record.readyCommand !== undefined && record.readyAt === undefined
            ? record.readyIntervalMs
            : record.intervalMs;
        await this.sleep(sleepMs, record.abort.signal);
      }
    } finally {
      this.active.delete(record.watchId);
      if (record.readyCommand !== undefined) {
        this.completed.set(record.key, {
          readiness: record.readiness,
          ...(record.readyAt !== undefined ? { readyAt: record.readyAt } : {}),
          completedAt: this.now(),
        });
      }
    }
  }

  private async withLogTail(
    record: JobWatchRecord,
    info: JobInfo,
  ): Promise<JobInfo> {
    if (record.logLines <= 0 || info.log !== undefined) return info;
    try {
      const result = await this.options.jobs.status(
        record.sshId,
        record.jobId,
        record.logLines,
      );
      return Array.isArray(result) ? info : result;
    } catch {
      return info;
    }
  }

  private async probe(record: JobWatchRecord, info: JobInfo): Promise<boolean> {
    if (this.options.runProbe === undefined || record.readyCommand === undefined) {
      return false;
    }
    try {
      return await this.options.runProbe({
        sshId: record.sshId,
        jobId: record.jobId,
        jobDir: info.jobDir,
        command: record.readyCommand,
        timeoutMs: 10_000,
      });
    } catch {
      return false;
    }
  }

  private async notifyExit(record: JobWatchRecord, info: JobInfo): Promise<void> {
    if (record.notified) return;
    record.notified = true;
    if (record.readyCommand !== undefined) record.readiness = "failed";
    await this.emit(record, info, {
      event: "exit",
      ...(record.readyCommand !== undefined ? { readiness: "failed" } : {}),
    });
  }

  private async notifyReady(record: JobWatchRecord, info: JobInfo): Promise<void> {
    if (record.notified) return;
    record.notified = true;
    record.readiness = "ready";
    await this.emit(record, info, {
      event: "ready",
      readiness: "ready",
    });
  }

  private async notifyTimeout(record: JobWatchRecord, info: JobInfo): Promise<void> {
    if (record.notified) return;
    record.notified = true;
    record.readiness = "timeout";
    await this.emit(record, info, {
      event: "timeout",
      readiness: "timeout",
    });
  }

  private async notifyServiceExited(
    record: JobWatchRecord,
    info: JobInfo,
  ): Promise<void> {
    if (record.crashNotified) return;
    record.crashNotified = true;
    await this.emit(record, info, {
      event: "service-exited",
      readiness: "ready",
      ...(record.readyAt !== undefined
        ? { elapsedSinceReadyMs: Math.max(0, this.now() - record.readyAt) }
        : {}),
    });
  }

  private async notifyMonitorStopped(
    record: JobWatchRecord,
    error: unknown,
  ): Promise<void> {
    if (record.notified) {
      if (record.crashNotified) return;
      record.crashNotified = true;
    } else {
      record.notified = true;
    }

    const info = record.lastInfo;
    if (info === undefined) {
      await this.emitNotice({
        event: "monitor-stopped",
        sshId: record.sshId,
        jobId: record.jobId,
        sessionID: record.sessionID,
        ...(record.agent !== undefined ? { agent: record.agent } : {}),
        ...(record.name !== undefined ? { name: record.name } : {}),
        ...(record.hostLabel !== undefined ? { hostLabel: record.hostLabel } : {}),
        state: "lost",
        message: errorMessage(error),
      });
      return;
    }

    await this.emit(record, info, {
      event: "monitor-stopped",
      message: errorMessage(error),
    });
  }

  private async emit(
    record: JobWatchRecord,
    info: JobInfo,
    extra: Partial<JobNotice> & Pick<JobNotice, "event">,
  ): Promise<void> {
    await this.emitNotice({
      sshId: record.sshId,
      jobId: record.jobId,
      sessionID: record.sessionID,
      ...(record.agent !== undefined ? { agent: record.agent } : {}),
      ...(record.name !== undefined ? { name: record.name } : {}),
      ...(record.hostLabel !== undefined ? { hostLabel: record.hostLabel } : {}),
      state: info.state,
      ...(record.readyCommand !== undefined || record.readyAt !== undefined
        ? { readiness: record.readiness }
        : {}),
      ...(record.readyAt !== undefined ? { readyAt: record.readyAt } : {}),
      ...(info.exitCode !== undefined ? { exitCode: info.exitCode } : {}),
      ...(info.pid !== undefined ? { pid: info.pid } : {}),
      ...(info.elapsedMs !== undefined ? { elapsedMs: info.elapsedMs } : {}),
      ...(info.logPath !== undefined ? { logPath: info.logPath } : {}),
      ...(info.log !== undefined ? { logTail: info.log } : {}),
      ...extra,
    });
  }

  private async emitNotice(notice: JobNotice): Promise<void> {
    try {
      await this.options.notify(notice);
    } catch (error) {
      this.options.onError?.(error);
    }
  }

  private now(): number {
    return this.options.now?.() ?? Date.now();
  }

  private sleep(milliseconds: number, signal: AbortSignal): Promise<void> {
    return this.options.sleep?.(milliseconds, signal) ?? delay(milliseconds, signal);
  }
}

export function formatJobNotice(notice: JobNotice): string {
  const title =
    notice.event === "ready"
      ? "[ssh service ready]"
      : notice.event === "timeout"
        ? "[ssh service timeout]"
        : notice.event === "service-exited"
          ? "[ssh service exited]"
          : notice.event === "monitor-stopped"
            ? "[ssh job monitor stopped]"
            : notice.readiness === "failed"
              ? "[ssh service failed]"
              : `[ssh job ${notice.state}]`;

  const lines = [
    title,
    `job_id: ${notice.jobId}`,
    ...(notice.name !== undefined ? [`name: ${notice.name}`] : []),
    ...(notice.hostLabel !== undefined ? [`host: ${notice.hostLabel}`] : []),
    `state: ${notice.state}`,
    ...(notice.readiness !== undefined ? [`readiness: ${notice.readiness}`] : []),
    ...(notice.readyAt !== undefined
      ? [`ready_at: ${new Date(notice.readyAt).toISOString()}`]
      : []),
    ...(notice.exitCode !== undefined ? [`exit_code: ${notice.exitCode}`] : []),
    ...(notice.pid !== undefined ? [`pid: ${notice.pid}`] : []),
    ...(notice.elapsedMs !== undefined
      ? [`elapsed: ${formatDuration(notice.elapsedMs)}`]
      : []),
    ...(notice.elapsedSinceReadyMs !== undefined
      ? [`elapsed_since_ready: ${formatDuration(notice.elapsedSinceReadyMs)}`]
      : []),
    ...(notice.logPath !== undefined ? [`log: ${notice.logPath}`] : []),
    "",
    notice.event === "ready"
      ? "服务已就绪，job 仍在运行。需要停止时调用 ssh_job_stop({ ssh_id, job_id })。"
      : notice.event === "timeout"
        ? "超过 ready_timeout_ms 仍未就绪，进程可能仍在加载或卡住。请检查日志；需要终止时调用 ssh_job_stop。"
        : notice.event === "service-exited"
          ? "服务在就绪后退出，请检查日志并向用户汇报。"
          : notice.event === "monitor-stopped"
            ? `无法继续监控该 job${notice.message !== undefined ? `：${notice.message}` : ""}。job 本身可能仍在运行，请重新连接后调用 ssh_job_status 检查。`
            : "请现在向用户汇报结果。如果需要更多上下文，调用 ssh_job_status({ ssh_id, job_id, log_lines })。",
  ];

  if (notice.logTail !== undefined && notice.logTail.length > 0) {
    lines.push("", "Tail:", notice.logTail);
  }
  return lines.join("\n");
}

function nextInterval(elapsed: number, initial: number, maximum: number): number {
  if (elapsed < 60_000) return Math.min(initial, maximum);
  if (elapsed < 10 * 60_000) return Math.min(Math.max(initial, 10_000), maximum);
  return Math.min(Math.max(initial, 30_000), maximum);
}

function delay(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, milliseconds);
    const onAbort = () => {
      clearTimeout(timer);
      resolve();
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function formatDuration(milliseconds: number): string {
  const totalSeconds = Math.max(0, Math.floor(milliseconds / 1_000));
  const seconds = totalSeconds % 60;
  const minutes = Math.floor(totalSeconds / 60);
  if (minutes < 60) return `${minutes}m${seconds}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h${minutes % 60}m`;
}
