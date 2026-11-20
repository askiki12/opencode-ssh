import { randomBytes } from "node:crypto";
import type { JobService } from "./jobs.js";
import { JobSource } from "./watch-sources.js";
import type {
  JobReadiness,
  WatchCheck,
  WatchEvent,
  WatchNotice,
  WatchSource,
  WatchState,
  WatchSummary,
} from "./watch-types.js";

export type {
  JobReadiness,
  WatchEvent,
  WatchKind,
  WatchNotice,
  WatchSource,
  WatchState,
  WatchSummary,
} from "./watch-types.js";

export type JobNotice = WatchNotice;
export type JobNoticeEvent = WatchEvent;

export interface WatchJobInput {
  sshId: string;
  jobId: string;
  sessionID: string;
  agent?: string;
  name?: string;
  hostLabel?: string;
  logLines?: number;
  readyCommand?: string;
  readyTimeoutMs?: number;
  readyIntervalMs?: number;
  readyStableMs?: number;
  watchAfterReady?: boolean;
}

export interface WatchInput {
  source: WatchSource;
  sessionID: string;
  agent?: string;
  name?: string;
  hostLabel?: string;
  logLines?: number;
  initialIntervalMs?: number;
  maxIntervalMs?: number;
  watchAfterReady?: boolean;
  sshId?: string;
  jobId?: string;
}

export interface WatchNotifierOptions {
  jobs?: Pick<JobService, "status">;
  runProbe?: (input: {
    sshId: string;
    jobId: string;
    jobDir: string;
    command: string;
    timeoutMs: number;
  }) => Promise<boolean>;
  notify: (notice: WatchNotice) => Promise<void>;
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

interface CompletedWatch {
  readiness: JobReadiness;
  readyAt?: number;
  completedAt: number;
}

interface WatchRecord {
  watchId: string;
  key: string;
  source: WatchSource;
  sessionID: string;
  agent?: string;
  name?: string;
  hostLabel?: string;
  sshId?: string;
  jobId?: string;
  logLines: number;
  watchAfterReady: boolean;
  initialIntervalMs: number;
  maxIntervalMs: number;
  startedAt: number;
  state: WatchState;
  readiness?: JobReadiness;
  readyAt?: number;
  notified: boolean;
  crashNotified: boolean;
  failures: number;
  intervalMs: number;
  abort: AbortController;
}

export class WatchNotifier {
  private readonly active = new Map<string, WatchRecord>();
  private readonly completed = new Map<string, CompletedWatch>();

  constructor(private readonly options: WatchNotifierOptions) {}

  /** Convenience entry point used by ssh_job_start. */
  watchJob(input: WatchJobInput): string {
    if (this.options.jobs === undefined) {
      throw new Error("Job notifications are not configured.");
    }

    const source = new JobSource({
      jobs: this.options.jobs,
      sshId: input.sshId,
      jobId: input.jobId,
      logLines: input.logLines ?? this.options.logLines ?? 40,
      initialIntervalMs:
        this.options.initialIntervalMs ?? 5_000,
      ...(this.options.runProbe !== undefined
        ? { runProbe: this.options.runProbe }
        : {}),
      ...(input.readyCommand !== undefined
        ? { readyCommand: input.readyCommand }
        : {}),
      readyTimeoutMs:
        input.readyTimeoutMs ?? this.options.readyTimeoutMs ?? 1_200_000,
      readyIntervalMs:
        input.readyIntervalMs ?? this.options.readyIntervalMs ?? 5_000,
      readyStableMs:
        input.readyStableMs ?? this.options.readyStableMs ?? 5_000,
    });

    return this.watch({
      source,
      sessionID: input.sessionID,
      ...(input.agent !== undefined ? { agent: input.agent } : {}),
      ...(input.name !== undefined ? { name: input.name } : {}),
      ...(input.hostLabel !== undefined ? { hostLabel: input.hostLabel } : {}),
      ...(input.logLines !== undefined ? { logLines: input.logLines } : {}),
      ...(input.watchAfterReady !== undefined
        ? { watchAfterReady: input.watchAfterReady }
        : {}),
      sshId: input.sshId,
      jobId: input.jobId,
    });
  }

  /** Register any WatchSource. This is the generic entry point for ssh_watch. */
  watch(input: WatchInput): string {
    const key =
      input.jobId !== undefined && input.sshId !== undefined
        ? `${input.sshId}:${input.jobId}`
        : `watch:${input.source.kind}:${randomBytes(6).toString("hex")}`;

    const existing = [...this.active.values()].find((record) => record.key === key);
    if (existing) return existing.watchId;

    // Reattaching with a new ssh_id must supersede the old watch for the same
    // job; otherwise the disconnected watch can emit a late "monitor stopped".
    if (input.jobId !== undefined) {
      for (const record of [...this.active.values()]) {
        if (record.jobId !== input.jobId) continue;
        record.abort.abort();
        this.active.delete(record.watchId);
      }
    }

    const record: WatchRecord = {
      watchId: `watch_${randomBytes(6).toString("hex")}`,
      key,
      source: input.source,
      sessionID: input.sessionID,
      ...(input.agent !== undefined ? { agent: input.agent } : {}),
      ...(input.name !== undefined ? { name: input.name } : {}),
      ...(input.hostLabel !== undefined ? { hostLabel: input.hostLabel } : {}),
      ...(input.sshId !== undefined ? { sshId: input.sshId } : {}),
      ...(input.jobId !== undefined ? { jobId: input.jobId } : {}),
      logLines: input.logLines ?? this.options.logLines ?? 40,
      watchAfterReady:
        input.watchAfterReady ?? this.options.watchAfterReady ?? false,
      initialIntervalMs:
        input.initialIntervalMs ?? this.options.initialIntervalMs ?? 5_000,
      maxIntervalMs:
        input.maxIntervalMs ?? this.options.maxIntervalMs ?? 60_000,
      startedAt: this.now(),
      state: "pending",
      ...(input.source.readiness !== undefined
        ? { readiness: input.source.readiness }
        : {}),
      ...(input.source.readyAt !== undefined
        ? { readyAt: input.source.readyAt }
        : {}),
      notified: false,
      crashNotified: false,
      failures: 0,
      intervalMs:
        input.initialIntervalMs ?? this.options.initialIntervalMs ?? 5_000,
      abort: new AbortController(),
    };

    this.active.set(record.watchId, record);
    void this.run(record).catch((error) => {
      this.options.onError?.(error);
    });
    return record.watchId;
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
        kind: record.source.kind,
        ...(record.jobId !== undefined ? { jobId: record.jobId } : {}),
        ...(record.sshId !== undefined ? { sshId: record.sshId } : {}),
        sessionID: record.sessionID,
        ...(record.name !== undefined ? { name: record.name } : {}),
        ...(record.hostLabel !== undefined ? { hostLabel: record.hostLabel } : {}),
        ...(record.readiness !== undefined
          ? { readiness: record.readiness }
          : {}),
        state: record.state,
        startedAt: record.startedAt,
      }))
      .sort((left, right) => left.startedAt - right.startedAt);
  }

  describe(
    sshId: string,
    jobId: string,
  ): { readiness?: JobReadiness; readyAt?: number } | undefined {
    const key = `${sshId}:${jobId}`;
    const record = [...this.active.values()].find((item) => item.key === key);
    if (record) {
      if (record.source.kind !== "job" || record.readiness === undefined) {
        return undefined;
      }
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

  private async run(record: WatchRecord): Promise<void> {
    try {
      while (!record.abort.signal.aborted) {
        let check: WatchCheck;
        try {
          check = await record.source.check({
            now: this.now(),
            signal: record.abort.signal,
          });
        } catch (error) {
          if (record.abort.signal.aborted) return;
          record.failures += 1;
          if (record.failures >= (this.options.maxFailures ?? 10)) {
            await this.notifyMonitorStopped(record, errorMessage(error));
            return;
          }
          record.intervalMs = Math.min(
            record.maxIntervalMs,
            Math.max(
              record.intervalMs * 2,
              record.initialIntervalMs,
            ),
          );
          await this.sleep(record.intervalMs, record.abort.signal);
          continue;
        }

        if (record.abort.signal.aborted) return;
        record.failures = 0;
        record.state =
          check.state === "pending" && record.readyAt !== undefined
            ? "ready"
            : check.state;
        if (check.readiness !== undefined) {
          record.readiness = check.readiness;
        }
        if (check.readyAt !== undefined) {
          record.readyAt = check.readyAt;
        }

        switch (check.state) {
          case "pending":
            record.intervalMs =
              check.nextIntervalMs ??
              nextInterval(
                this.now() - record.startedAt,
                record.initialIntervalMs,
                record.maxIntervalMs,
              );
            await this.sleep(record.intervalMs, record.abort.signal);
            break;

          case "ready":
            if (!record.notified) {
              record.notified = true;
              await this.emit(record, check, "ready");
            }
            if (!record.watchAfterReady) return;
            await this.sleep(
              check.nextIntervalMs ?? record.intervalMs,
              record.abort.signal,
            );
            break;

          case "timeout":
            if (record.notified) {
              if (record.crashNotified) return;
              record.crashNotified = true;
            } else {
              record.notified = true;
            }
            await this.emit(record, check, "timeout");
            return;

          case "monitor-stopped":
            await this.notifyMonitorStopped(record, check.message);
            return;

          case "exited":
            if (record.readyAt !== undefined) {
              if (record.crashNotified) return;
              record.crashNotified = true;
              await this.emit(record, check, "service-exited");
            } else if (!record.notified) {
              record.notified = true;
              await this.emit(record, check, check.event ?? "exit");
            }
            return;
        }
      }
    } finally {
      this.active.delete(record.watchId);
      if (
        record.jobId !== undefined &&
        record.sshId !== undefined &&
        record.readiness !== undefined
      ) {
        this.completed.set(`${record.sshId}:${record.jobId}`, {
          readiness: record.readiness,
          ...(record.readyAt !== undefined ? { readyAt: record.readyAt } : {}),
          completedAt: this.now(),
        });
      }
    }
  }

  private async notifyMonitorStopped(
    record: WatchRecord,
    message: string | undefined,
  ): Promise<void> {
    if (record.notified) {
      if (record.crashNotified) return;
      record.crashNotified = true;
    } else {
      record.notified = true;
    }

    await this.emitNotice({
      event: "monitor-stopped",
      kind: record.source.kind,
      watchId: record.watchId,
      ...(record.jobId !== undefined ? { jobId: record.jobId } : {}),
      ...(record.sshId !== undefined ? { sshId: record.sshId } : {}),
      sessionID: record.sessionID,
      ...(record.agent !== undefined ? { agent: record.agent } : {}),
      ...(record.name !== undefined ? { name: record.name } : {}),
      ...(record.hostLabel !== undefined ? { hostLabel: record.hostLabel } : {}),
      state: "lost",
      ...(record.readiness !== undefined
        ? { readiness: record.readiness }
        : {}),
      ...(record.readyAt !== undefined ? { readyAt: record.readyAt } : {}),
      ...(message !== undefined ? { message } : {}),
      elapsedMs: Math.max(0, this.now() - record.startedAt),
    });
  }

  private async emit(
    record: WatchRecord,
    check: WatchCheck,
    event: WatchEvent,
  ): Promise<void> {
    const state =
      check.state === "exited"
        ? "finished"
        : check.state === "monitor-stopped"
          ? "lost"
          : "running";
    const readiness = check.readiness ?? record.readiness;
    const readyAt = check.readyAt ?? record.readyAt;

    await this.emitNotice({
      event,
      kind: record.source.kind,
      watchId: record.watchId,
      ...(record.jobId !== undefined ? { jobId: record.jobId } : {}),
      ...(record.sshId !== undefined ? { sshId: record.sshId } : {}),
      sessionID: record.sessionID,
      ...(record.agent !== undefined ? { agent: record.agent } : {}),
      ...(record.name !== undefined ? { name: record.name } : {}),
      ...(record.hostLabel !== undefined ? { hostLabel: record.hostLabel } : {}),
      state,
      ...(readiness !== undefined ? { readiness } : {}),
      ...(readyAt !== undefined ? { readyAt } : {}),
      ...(check.exitCode !== undefined ? { exitCode: check.exitCode } : {}),
      ...(check.pid !== undefined ? { pid: check.pid } : {}),
      ...(check.logPath !== undefined ? { logPath: check.logPath } : {}),
      ...(check.logTail !== undefined ? { logTail: check.logTail } : {}),
      ...(check.message !== undefined ? { message: check.message } : {}),
      ...(check.pattern !== undefined ? { pattern: check.pattern } : {}),
      ...(check.outcome !== undefined ? { outcome: check.outcome } : {}),
      elapsedMs: Math.max(0, this.now() - record.startedAt),
      ...(readyAt !== undefined
        ? { elapsedSinceReadyMs: Math.max(0, this.now() - readyAt) }
        : {}),
    });
  }

  private async emitNotice(notice: WatchNotice): Promise<void> {
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

export function formatWatchNotice(notice: WatchNotice): string {
  const title =
    notice.event === "ready"
      ? "[ssh service ready]"
      : notice.event === "timeout"
        ? "[ssh service timeout]"
        : notice.event === "service-exited"
          ? "[ssh service exited]"
          : notice.event === "pid-exited"
            ? "[ssh watch: pid exited]"
            : notice.event === "log-matched"
              ? "[ssh watch: log matched]"
              : notice.event === "monitor-stopped"
                ? "[ssh watch monitor stopped]"
                : notice.readiness === "failed"
                  ? "[ssh service failed]"
                  : `[ssh job ${notice.state}]`;

  const lines = [
    title,
    ...(notice.jobId !== undefined ? [`job_id: ${notice.jobId}`] : []),
    `watch_id: ${notice.watchId}`,
    ...(notice.jobId === undefined ? [`kind: ${notice.kind}`] : []),
    ...(notice.name !== undefined ? [`name: ${notice.name}`] : []),
    ...(notice.hostLabel !== undefined ? [`host: ${notice.hostLabel}`] : []),
    `state: ${notice.state}`,
    ...(notice.readiness !== undefined
      ? [`readiness: ${notice.readiness}`]
      : []),
    ...(notice.readyAt !== undefined
      ? [`ready_at: ${new Date(notice.readyAt).toISOString()}`]
      : []),
    ...(notice.exitCode !== undefined
      ? [`exit_code: ${notice.exitCode}`]
      : []),
    ...(notice.pid !== undefined ? [`pid: ${notice.pid}`] : []),
    ...(notice.elapsedMs !== undefined
      ? [`elapsed: ${formatDuration(notice.elapsedMs)}`]
      : []),
    ...(notice.elapsedSinceReadyMs !== undefined
      ? [`elapsed_since_ready: ${formatDuration(notice.elapsedSinceReadyMs)}`]
      : []),
    ...(notice.logPath !== undefined ? [`log: ${notice.logPath}`] : []),
    ...(notice.outcome !== undefined ? [`outcome: ${notice.outcome}`] : []),
    ...(notice.pattern !== undefined ? [`pattern: ${notice.pattern}`] : []),
    "",
    notice.event === "ready"
      ? "服务已就绪，job 仍在运行。需要停止时调用 ssh_job_stop({ ssh_id, job_id })。"
      : notice.event === "timeout"
        ? "超过超时时间仍未就绪，进程可能仍在加载或卡住。请检查日志。"
        : notice.event === "service-exited"
          ? "服务在就绪后退出，请检查日志并向用户汇报。"
          : notice.event === "pid-exited"
            ? "后台进程已退出。请读取日志并向用户汇报。"
            : notice.event === "log-matched"
              ? `日志命中${notice.outcome === "failure" ? "失败" : "成功"}关键字，请向用户汇报。`
              : notice.event === "monitor-stopped"
                ? `无法继续监控该任务${notice.message !== undefined ? `：${notice.message}` : ""}。任务本身可能仍在运行，请重新连接后检查。`
                : "请现在向用户汇报结果。",
  ];

  if (notice.logTail !== undefined && notice.logTail.length > 0) {
    lines.push("", "Tail:", notice.logTail);
  }
  return lines.join("\n");
}

/** Backward-compatible alias for the job-focused formatter. */
export function formatJobNotice(notice: WatchNotice): string {
  return formatWatchNotice(notice);
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
