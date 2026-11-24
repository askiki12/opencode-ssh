import { randomBytes } from "node:crypto";
import { shellQuote } from "./command.js";
import { needsRemoteHome, resolveRemotePath } from "./files.js";
import type { JobInfo, JobService } from "./jobs.js";
import type { ConnectionManager } from "./manager.js";
import { errorMessage } from "../util.js";
import {
  formatTargetLabel,
  watchTargetKey,
  type CancelWatchesResult,
  type CreateNotifierInput,
  type CreateNotifierResult,
  type MatchCondition,
  type NotifierEvent,
  type NotifierMode,
  type NotifierSnapshot,
  type NotifierState,
  type UnwatchNotifierResult,
  type UnwatchWatchResult,
  type WatchLifecycle,
  type WatchListResult,
  type WatchNotice,
  type WatchNoticeTarget,
  type WatchSnapshot,
  type WatchTargetSpec,
  type WatchTargetState,
} from "./watch-types.js";

type TerminalLifecycle = "completed" | "failed" | "timeout" | "canceled";

const MIN_READY_CHECKS = 2;
const READY_TAIL_LINES = 500;
const TERMINAL_TAIL_LINES = 500;
const MAX_NOTICE_LOG_LINES = 200;
const PROBE_TIMEOUT_MS = 15_000;

export interface WatchServiceOptions {
  manager: Pick<ConnectionManager, "exec" | "homeDir">;
  jobs: Pick<JobService, "status">;
  notify: (notice: WatchNotice) => Promise<void>;
  intervalMs: number;
  maxIntervalMs: number;
  maxFailures: number;
  ttlMs: number;
  logScanBytes: number;
  readyTimeoutMs: number;
  readyIntervalMs: number;
  readyStableMs: number;
  now?: () => number;
  sleep?: (milliseconds: number, signal: AbortSignal) => Promise<void>;
}

interface CompiledConditions {
  readyRegex?: RegExp;
  successRegex?: RegExp;
  failureRegex?: RegExp;
}

interface WatchRecord {
  id: string;
  sessionID: string;
  spec: WatchTargetSpec;
  key: string;
  conditions: CompiledConditions;
  lifecycle: WatchLifecycle;
  targetState: WatchTargetState;
  refCount: number;
  notifierIds: Set<string>;
  listeners: Map<string, (event: WatchEvent) => void>;
  createdAt: number;
  lastCheckedAt?: number;
  lastEvent?: string;
  lastMessage?: string;
  lastError?: string;
  exitCode?: number | null;
  readyAt?: number;
  terminalAt?: number;
  detachedAt?: number;
  logPath?: string;
  logOffset?: number;
  initialLogOffset?: number;
  createdTerminal: boolean;
  logUnavailable?: boolean;
  jobDir?: string;
  displayName?: string;
  resolvedPid?: number;
  pidStart?: string;
  readyStartedAt?: number;
  readyOkSince?: number;
  readyChecks: number;
  readyRegexMatched: boolean;
  readyNotified: boolean;
  suppress: boolean;
  failures: number;
  intervalMs: number;
  abort?: AbortController;
  running: boolean;
}

interface WatchEvent {
  type: NotifierEvent;
  watch: WatchRecord;
  at: number;
  message?: string;
}

interface NotifierRecord {
  id: string;
  sessionID: string;
  agent?: string;
  mode: NotifierMode;
  failFast: boolean;
  watchIds: string[];
  state: NotifierState;
  createdAt: number;
  timeoutMs?: number;
  timer?: NodeJS.Timeout;
  notify: CreateNotifierInput["notify"];
  closing: boolean;
}

export class WatchService {
  private readonly watches = new Map<string, WatchRecord>();
  private readonly notifiers = new Map<string, NotifierRecord>();
  private readonly pendingCreations = new Set<string>();
  private readonly suppressedJobs = new Set<string>();
  private readonly sweepTimer: NodeJS.Timeout;
  private readonly now: () => number;
  private readonly sleep: (milliseconds: number, signal: AbortSignal) => Promise<void>;

  constructor(private readonly options: WatchServiceOptions) {
    this.now = options.now ?? Date.now;
    this.sleep = options.sleep ?? delay;
    const sweepInterval = Math.max(1_000, Math.min(60_000, options.ttlMs / 4));
    this.sweepTimer = setInterval(() => this.sweep(), sweepInterval);
    this.sweepTimer.unref?.();
  }

  async createNotifier(input: CreateNotifierInput): Promise<CreateNotifierResult> {
    const normalized = new Map<string, WatchTargetSpec>();
    for (const raw of input.targets) {
      const spec = await this.resolveSpec(normalizeConditions(raw));
      const key = watchTargetKey(spec);
      const existing = normalized.get(key);
      if (existing !== undefined) {
        if (canonicalSpec(existing) !== canonicalSpec(spec)) {
          throw new Error(
            `The same target appears twice with different watch conditions: ${key}`,
          );
        }
        continue;
      }
      normalized.set(key, spec);
    }

    const watchIds: string[] = [];
    const reusedWatchIds: string[] = [];
    const createdWatches: WatchRecord[] = [];
    let createdNotifier: NotifierRecord | undefined;

    try {
      for (const [key, spec] of normalized) {
        const existing = this.findReusableWatch(input.sessionID, key);
        if (existing !== undefined) {
          if (canonicalSpec(existing.spec) !== canonicalSpec(spec)) {
            throw new Error(
              `Target ${key} is already watched by ${existing.id} with different conditions. ` +
                `Reuse ${existing.id} with watch_ids, or call ssh_unwatch first.`,
            );
          }
          watchIds.push(existing.id);
          reusedWatchIds.push(existing.id);
          continue;
        }

        const reservation = `${input.sessionID}:${key}`;
        if (this.pendingCreations.has(reservation)) {
          throw new Error(
            `A watch for ${key} is already being created; retry after it finishes.`,
          );
        }
        this.pendingCreations.add(reservation);
        let watch: WatchRecord;
        try {
          watch = await this.createWatch(input.sessionID, spec);
        } finally {
          this.pendingCreations.delete(reservation);
        }
        createdWatches.push(watch);
        this.watches.set(watch.id, watch);
        watchIds.push(watch.id);
      }

      for (const watchId of input.watchIds) {
        const watch = this.watches.get(watchId);
        if (watch === undefined) {
          throw new Error(`Watch not found: ${watchId}`);
        }
        if (watch.sessionID !== input.sessionID) {
          throw new Error(`Watch not found: ${watchId}`);
        }
        if (isTerminal(watch)) {
          throw new Error(
            `Watch ${watchId} is terminal (${watch.lifecycle}) and cannot be reused. Create a new watch instead.`,
          );
        }
        watchIds.push(watchId);
      }

      const uniqueWatchIds = [...new Set(watchIds)];
      if (uniqueWatchIds.length === 0) {
        throw new Error("ssh_watch requires targets or watch_ids.");
      }

      const notifier: NotifierRecord = {
        id: newId("notifier"),
        sessionID: input.sessionID,
        ...(input.agent !== undefined ? { agent: input.agent } : {}),
        mode: input.mode,
        failFast: input.failFast,
        watchIds: uniqueWatchIds,
        state: "watching",
        createdAt: this.now(),
        ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
        notify: input.notify,
        closing: false,
      };
      createdNotifier = notifier;
      this.notifiers.set(notifier.id, notifier);

      for (const watchId of uniqueWatchIds) {
        const watch = this.watches.get(watchId);
        if (watch === undefined) continue;
        this.attach(notifier, watch);
      }

      if (notifier.timeoutMs !== undefined) {
        notifier.timer = setTimeout(() => {
          void this.closeNotifier(notifier, "timeout", "timeout").catch(
            () => undefined,
          );
        }, notifier.timeoutMs);
        notifier.timer.unref?.();
      }

      await this.evaluateNotifier(notifier);
      return {
        notifier: this.snapshotNotifier(notifier),
        watches: uniqueWatchIds
          .map((watchId) => this.watches.get(watchId))
          .filter((watch): watch is WatchRecord => watch !== undefined)
          .map((watch) => this.snapshotWatch(watch)),
        reusedWatchIds,
      };
    } catch (error) {
      if (
        createdNotifier !== undefined &&
        this.notifiers.has(createdNotifier.id)
      ) {
        this.closeNotifierRecord(createdNotifier);
      }
      for (const watch of createdWatches) {
        this.stopWatch(watch);
        watch.listeners.clear();
        this.watches.delete(watch.id);
      }
      throw error;
    }
  }

  unwatchNotifier(sessionID: string, notifierId: string): UnwatchNotifierResult {
    const notifier = this.notifiers.get(notifierId);
    if (notifier === undefined || notifier.sessionID !== sessionID) {
      return { removed: false, releasedWatchIds: [], detachedWatchIds: [] };
    }
    const releasedWatchIds = [...notifier.watchIds];
    const detachedWatchIds = this.closeNotifierRecord(notifier);
    return { removed: true, releasedWatchIds, detachedWatchIds };
  }

  /**
   * Silently cancel watches bound to an ssh_id, for example when the agent
   * intentionally disconnects. No notification is emitted. Notifiers that
   * also watch other connections keep running with their remaining watches.
   */
  /**
   * Suppress job watches while ssh_job_stop is in flight. This prevents a
   * transient pid death (before stopped_at is written) from becoming a lost
   * notification for a deliberate stop.
   */
  beginJobStop(sshId: string, jobId: string): void {
    this.suppressedJobs.add(jobStopKey(sshId, jobId));
    for (const watch of this.watches.values()) {
      if (
        watch.spec.kind === "job" &&
        watch.spec.sshId === sshId &&
        watch.spec.jobId === jobId &&
        !isTerminal(watch)
      ) {
        watch.suppress = true;
      }
    }
  }

  endJobStop(
    sshId: string,
    jobId: string,
    outcome: "stopped" | "already-finished" | "not-running" | "mismatch" | "aborted",
  ): CancelWatchesResult {
    const key = jobStopKey(sshId, jobId);
    if (outcome === "stopped") {
      const result = this.cancelByJob(sshId, jobId);
      this.suppressedJobs.delete(key);
      return result;
    }
    this.suppressedJobs.delete(key);
    for (const watch of this.watches.values()) {
      if (
        watch.spec.kind === "job" &&
        watch.spec.sshId === sshId &&
        watch.spec.jobId === jobId
      ) {
        watch.suppress = false;
      }
    }
    return {
      canceledWatchIds: [],
      closedNotifierIds: [],
      remainingNotifierIds: [],
    };
  }

  cancelBySshId(sshId: string): CancelWatchesResult {
    return this.cancelMatching(
      (watch) => watch.spec.sshId === sshId,
      "ssh connection was closed by ssh_disconnect",
      "lost",
    );
  }

  /**
   * Silently cancel watches for a deliberately stopped job. This is a control
   * action, not a failure, so no notification is emitted.
   */
  cancelByJob(sshId: string, jobId: string): CancelWatchesResult {
    return this.cancelMatching(
      (watch) =>
        watch.spec.kind === "job" &&
        watch.spec.sshId === sshId &&
        watch.spec.jobId === jobId,
      "job was stopped by ssh_job_stop",
      "stopped",
    );
  }

  private cancelMatching(
    predicate: (watch: WatchRecord) => boolean,
    message: string,
    targetState: WatchTargetState,
  ): CancelWatchesResult {
    const canceledWatchIds: string[] = [];
    const closedNotifierIds: string[] = [];
    const remainingNotifierIds = new Set<string>();

    for (const watch of [...this.watches.values()]) {
      if (!predicate(watch) || isTerminal(watch)) continue;
      const result = this.cancelWatch(watch, message, targetState);
      if (result === undefined) continue;
      canceledWatchIds.push(watch.id);
      for (const notifierId of result.closedNotifierIds) {
        remainingNotifierIds.delete(notifierId);
        if (!closedNotifierIds.includes(notifierId)) {
          closedNotifierIds.push(notifierId);
        }
      }
      for (const notifierId of result.remainingNotifierIds) {
        remainingNotifierIds.add(notifierId);
      }
    }

    return {
      canceledWatchIds,
      closedNotifierIds,
      remainingNotifierIds: [...remainingNotifierIds],
    };
  }

  private cancelWatch(
    watch: WatchRecord,
    message: string,
    targetState: WatchTargetState,
  ): { closedNotifierIds: string[]; remainingNotifierIds: string[] } | undefined {
    if (isTerminal(watch)) return undefined;
    const closedNotifierIds: string[] = [];
    const remainingNotifierIds: string[] = [];

    for (const notifierId of [...watch.notifierIds]) {
      const notifier = this.notifiers.get(notifierId);
      watch.listeners.delete(notifierId);
      watch.notifierIds.delete(notifierId);
      watch.refCount = Math.max(0, watch.refCount - 1);
      if (notifier === undefined) continue;
      notifier.watchIds = notifier.watchIds.filter(
        (watchId) => watchId !== watch.id,
      );
      if (notifier.watchIds.length === 0) {
        this.closeNotifierRecord(notifier);
        closedNotifierIds.push(notifierId);
      } else {
        remainingNotifierIds.push(notifierId);
      }
    }

    this.stopWatch(watch);
    watch.listeners.clear();
    watch.notifierIds.clear();
    watch.refCount = 0;
    watch.suppress = false;
    watch.lifecycle = "canceled";
    watch.targetState = targetState;
    watch.terminalAt = this.now();
    watch.lastEvent = "canceled";
    watch.lastMessage = message;
    return { closedNotifierIds, remainingNotifierIds };
  }

  destroyWatch(sessionID: string, watchId: string): UnwatchWatchResult {
    const watch = this.watches.get(watchId);
    if (watch === undefined || watch.sessionID !== sessionID) {
      return { removed: false, watchId };
    }
    if (watch.refCount > 0) {
      throw new Error(
        `Watch ${watchId} is still referenced by ${watch.refCount} notifier(s): ` +
          `${[...watch.notifierIds].join(", ")}. Close those notifiers first.`,
      );
    }
    if (watch.lifecycle === "active") {
      throw new Error(`Watch ${watchId} is still active; close its notifier first.`);
    }
    this.stopWatch(watch);
    watch.listeners.clear();
    watch.notifierIds.clear();
    this.watches.delete(watch.id);
    return { removed: true, watchId };
  }

  list(
    sessionID: string,
    options: { notifierId?: string; watchId?: string } = {},
  ): WatchListResult {
    if (options.watchId !== undefined) {
      const watch = this.watches.get(options.watchId);
      if (watch === undefined || watch.sessionID !== sessionID) {
        return { notifiers: [], watches: [] };
      }
      return { notifiers: [], watches: [this.snapshotWatch(watch)] };
    }

    if (options.notifierId !== undefined) {
      const notifier = this.notifiers.get(options.notifierId);
      if (notifier === undefined || notifier.sessionID !== sessionID) {
        return { notifiers: [], watches: [] };
      }
      return {
        notifiers: [this.snapshotNotifier(notifier)],
        watches: notifier.watchIds
          .map((watchId) => this.watches.get(watchId))
          .filter((watch): watch is WatchRecord => watch !== undefined)
          .map((watch) => this.snapshotWatch(watch)),
      };
    }

    const notifiers = [...this.notifiers.values()]
      .filter((notifier) => notifier.sessionID === sessionID)
      .sort((left, right) => left.createdAt - right.createdAt)
      .map((notifier) => this.snapshotNotifier(notifier));
    const watches = [...this.watches.values()]
      .filter((watch) => watch.sessionID === sessionID)
      .sort((left, right) => left.createdAt - right.createdAt)
      .map((watch) => this.snapshotWatch(watch));
    return { notifiers, watches };
  }

  dispose(): void {
    clearInterval(this.sweepTimer);
    for (const notifier of this.notifiers.values()) {
      if (notifier.timer !== undefined) clearTimeout(notifier.timer);
      notifier.closing = true;
    }
    for (const watch of this.watches.values()) {
      this.stopWatch(watch);
      watch.listeners.clear();
    }
    this.notifiers.clear();
    this.watches.clear();
    this.pendingCreations.clear();
    this.suppressedJobs.clear();
  }

  private async createWatch(
    sessionID: string,
    spec: WatchTargetSpec,
  ): Promise<WatchRecord> {
    const conditions = compileConditions(spec);
    const watch: WatchRecord = {
      id: newId("watch"),
      sessionID,
      spec,
      key: watchTargetKey(spec),
      conditions,
      lifecycle: "active",
      targetState: "pending",
      refCount: 0,
      notifierIds: new Set(),
      listeners: new Map(),
      createdAt: this.now(),
      createdTerminal: false,
      readyChecks: 0,
      readyRegexMatched: false,
      readyNotified: false,
      suppress: false,
      failures: 0,
      intervalMs: this.options.intervalMs,
      running: false,
    };

    if (spec.kind === "job") {
      const info = await this.options.jobs.status(spec.sshId, spec.jobId, 0);
      if (Array.isArray(info)) {
        throw new Error(`Expected a single job status for ${spec.jobId}.`);
      }
      if (info.state === "corrupt") {
        throw new Error(
          `Job ${spec.jobId} has corrupt metadata and cannot be watched.`,
        );
      }
      watch.jobDir = info.jobDir;
      watch.createdTerminal =
        info.state !== "starting" && info.state !== "running";
      watch.logPath = spec.logPath ?? info.logPath;
      const displayName = spec.name ?? info.name;
      if (displayName !== undefined) watch.displayName = displayName;
      watch.targetState = "running";
      await this.initLog(watch);
    } else {
      const pid = await this.resolvePid(watch);
      if (pid === undefined) {
        throw new Error(
          `Process target has no readable pid: ${formatTargetLabel(spec)}`,
        );
      }
      const alive = await this.isAlive(spec.sshId, pid);
      if (!alive) {
        throw new Error(
          `Process ${pid} is not running: ${formatTargetLabel(spec)}`,
        );
      }
      watch.resolvedPid = pid;
      const pidStart = await this.pidStart(spec.sshId, pid);
      if (pidStart !== undefined) watch.pidStart = pidStart;
      if (spec.logPath !== undefined) watch.logPath = spec.logPath;
      if (spec.name !== undefined) watch.displayName = spec.name;
      watch.targetState = "running";
      await this.initLog(watch);
    }

    if (hasRegexConditions(conditions) && watch.logPath === undefined) {
      throw new Error(
        `Regex conditions require a readable log_path: ${formatTargetLabel(spec)}`,
      );
    }
    if (watch.logUnavailable === true && hasRegexConditions(conditions)) {
      throw new Error(
        `Regex conditions require a readable log_path: ${watch.logPath ?? "(none)"}`,
      );
    }
    return watch;
  }

  private async resolveSpec(spec: WatchTargetSpec): Promise<WatchTargetSpec> {
    const result: WatchTargetSpec = {
      kind: spec.kind,
      sshId: spec.sshId,
      ...(spec.jobId !== undefined ? { jobId: spec.jobId } : {}),
      ...(spec.pid !== undefined ? { pid: spec.pid } : {}),
      ...(spec.pidFile !== undefined
        ? { pidFile: await this.resolveRemotePath(spec.sshId, spec.pidFile) }
        : {}),
      ...(spec.name !== undefined ? { name: spec.name } : {}),
      ...(spec.logPath !== undefined
        ? { logPath: await this.resolveRemotePath(spec.sshId, spec.logPath) }
        : {}),
      ...(spec.ready !== undefined
        ? {
            ready: {
              ...(spec.ready.command !== undefined
                ? { command: spec.ready.command }
                : {}),
              ...(spec.ready.regex !== undefined
                ? { regex: spec.ready.regex }
                : {}),
              timeoutMs: spec.ready.timeoutMs,
              intervalMs: spec.ready.intervalMs,
              stableMs: spec.ready.stableMs,
            },
          }
        : {}),
      ...(spec.success !== undefined
        ? { success: cloneMatchCondition(spec.success) }
        : {}),
      ...(spec.failure !== undefined
        ? { failure: cloneMatchCondition(spec.failure) }
        : {}),
      watchAfterReady: spec.watchAfterReady,
    };
    return result;
  }

  private async resolveRemotePath(sshId: string, value: string): Promise<string> {
    if (!needsRemoteHome(value)) return resolveRemotePath(value, "");
    const home = await this.options.manager.homeDir(sshId);
    return resolveRemotePath(value, home);
  }

  private findReusableWatch(
    sessionID: string,
    key: string,
  ): WatchRecord | undefined {
    for (const watch of this.watches.values()) {
      if (watch.sessionID !== sessionID) continue;
      if (watch.key !== key) continue;
      if (isTerminal(watch)) continue;
      return watch;
    }
    return undefined;
  }

  private attach(notifier: NotifierRecord, watch: WatchRecord): void {
    watch.refCount += 1;
    watch.notifierIds.add(notifier.id);
    const listener = (event: WatchEvent): void => {
      void this.handleWatchEvent(notifier, event).catch(() => undefined);
    };
    watch.listeners.set(notifier.id, listener);
    if (!isTerminal(watch)) this.startWatch(watch);
  }

  private startWatch(watch: WatchRecord): void {
    if (isTerminal(watch) || watch.running) return;
    if (watch.lifecycle === "detached") {
      watch.lifecycle = "active";
      delete watch.detachedAt;
      watch.failures = 0;
      watch.intervalMs = this.options.intervalMs;
      delete watch.lastError;
    }
    watch.running = true;
    if (watch.readyAt === undefined) {
      watch.readyStartedAt = this.now();
      delete watch.readyOkSince;
      watch.readyChecks = 0;
    }
    const abort = new AbortController();
    watch.abort = abort;
    void this.runWatch(watch, abort.signal);
  }

  private stopWatch(watch: WatchRecord): void {
    watch.abort?.abort();
    delete watch.abort;
    watch.running = false;
  }

  private async runWatch(
    watch: WatchRecord,
    signal: AbortSignal,
  ): Promise<void> {
    while (!signal.aborted && !isTerminal(watch)) {
      try {
        await this.checkWatch(watch);
        watch.failures = 0;
        watch.intervalMs = this.options.intervalMs;
        delete watch.lastError;
      } catch (error) {
        if (signal.aborted) return;
        watch.failures += 1;
        watch.lastError = errorMessage(error);
        if (watch.failures >= this.options.maxFailures) {
          this.settle(
            watch,
            "failed",
            "lost",
            "failed",
            `watch lost the target after ${watch.failures} consecutive probe failures: ${watch.lastError}`,
          );
          return;
        }
        watch.intervalMs = Math.min(
          Math.max(this.options.intervalMs, this.options.maxIntervalMs),
          Math.max(this.options.intervalMs, watch.intervalMs * 2),
        );
      }

      if (signal.aborted || isTerminal(watch)) return;
      const interval =
        watch.failures === 0 &&
        watch.spec.ready !== undefined &&
        watch.readyAt === undefined
          ? watch.spec.ready.intervalMs
          : watch.intervalMs;
      try {
        await this.sleep(interval, signal);
      } catch {
        return;
      }
    }
  }

  private async checkWatch(watch: WatchRecord): Promise<void> {
    if (
      isTerminal(watch) ||
      watch.suppress ||
      this.isJobSuppressed(watch)
    ) {
      return;
    }
    watch.lastCheckedAt = this.now();
    if (watch.spec.kind === "job") {
      await this.checkJob(watch);
    } else {
      await this.checkProcess(watch);
    }
  }

  private isJobSuppressed(watch: WatchRecord): boolean {
    return (
      watch.spec.kind === "job" &&
      watch.spec.jobId !== undefined &&
      this.suppressedJobs.has(jobStopKey(watch.spec.sshId, watch.spec.jobId))
    );
  }

  private async checkJob(watch: WatchRecord): Promise<void> {
    const info = await this.options.jobs.status(
      watch.spec.sshId,
      watch.spec.jobId,
      0,
    );
    if (Array.isArray(info)) {
      throw new Error(`Expected a single job status for ${watch.spec.jobId}.`);
    }
    if (
      isTerminal(watch) ||
      watch.suppress ||
      this.isJobSuppressed(watch)
    ) {
      return;
    }
    watch.jobDir = info.jobDir;
    watch.logPath = watch.logPath ?? watch.spec.logPath ?? info.logPath;
    if (watch.displayName === undefined && info.name !== undefined) watch.displayName = info.name;

    switch (info.state) {
      case "starting":
      case "running":
        watch.targetState = watch.readyAt === undefined ? "running" : "ready";
        await this.scanLog(watch);
        if (
          isTerminal(watch) ||
          watch.suppress ||
          this.isJobSuppressed(watch)
        ) {
          return;
        }
        if (watch.readyAt === undefined && watch.spec.ready !== undefined) {
          await this.handleReady(watch, info.jobDir);
        }
        return;
      case "finished":
        await this.scanLog(watch, true);
        if (
          isTerminal(watch) ||
          watch.suppress ||
          this.isJobSuppressed(watch)
        ) {
          return;
        }
        if (info.exitCode !== undefined) watch.exitCode = info.exitCode;
        this.finishJob(watch, info, "exited");
        return;
      case "stopped":
        if (info.exitCode !== undefined) watch.exitCode = info.exitCode;
        this.cancelWatch(
          watch,
          "job was stopped by ssh_job_stop",
          "stopped",
        );
        return;
      case "lost":
        await this.scanLog(watch, true);
        if (
          isTerminal(watch) ||
          watch.suppress ||
          this.isJobSuppressed(watch)
        ) {
          return;
        }
        this.settle(
          watch,
          "failed",
          "lost",
          "failed",
          "job process is no longer running and has no exit status",
        );
        return;
      case "corrupt":
        this.settle(
          watch,
          "failed",
          "failed",
          "failed",
          "job metadata is corrupt",
        );
        return;
    }
  }

  private finishJob(
    watch: WatchRecord,
    info: JobInfo,
    fallbackState: WatchTargetState,
  ): void {
    if (isTerminal(watch)) return;
    if (watch.spec.ready !== undefined && watch.readyAt === undefined) {
      this.settle(
        watch,
        "failed",
        "failed",
        "failed",
        "job exited before becoming ready",
      );
      return;
    }
    if (watch.readyAt !== undefined && watch.spec.watchAfterReady) {
      this.settle(
        watch,
        "failed",
        fallbackState,
        "failed",
        "service exited after becoming ready",
      );
      return;
    }

    const outcome = this.evaluateMatchOutcome(
      watch,
      info.exitCode,
      fallbackState,
    );
    this.settle(
      watch,
      outcome.lifecycle,
      outcome.targetState,
      outcome.event,
      outcome.message,
    );
  }

  private async checkProcess(watch: WatchRecord): Promise<void> {
    const pid = await this.resolvePid(watch);
    if (isTerminal(watch)) return;
    if (pid === undefined) {
      await this.finishProcess(watch, "process is no longer running");
      return;
    }

    if (watch.resolvedPid !== undefined && pid !== watch.resolvedPid) {
      await this.finishProcess(
        watch,
        `pid changed from ${watch.resolvedPid} to ${pid}`,
      );
      return;
    }

    if (!(await this.isAlive(watch.spec.sshId, pid))) {
      await this.finishProcess(watch, `process ${pid} is no longer running`);
      return;
    }
    if (isTerminal(watch)) return;

    const start = await this.pidStart(watch.spec.sshId, pid);
    if (isTerminal(watch)) return;
    if (
      watch.pidStart !== undefined &&
      start !== undefined &&
      start !== watch.pidStart
    ) {
      await this.finishProcess(
        watch,
        `pid ${pid} now belongs to a different process (pid reuse)`,
      );
      return;
    }

    watch.resolvedPid = pid;
    if (watch.pidStart === undefined && start !== undefined) watch.pidStart = start;
    watch.targetState = watch.readyAt === undefined ? "running" : "ready";
    await this.scanLog(watch);
    if (isTerminal(watch)) return;
    if (watch.readyAt === undefined && watch.spec.ready !== undefined) {
      await this.handleReady(watch);
    }
  }

  private async finishProcess(
    watch: WatchRecord,
    message: string,
  ): Promise<void> {
    if (isTerminal(watch)) return;
    await this.scanLog(watch, true);
    if (isTerminal(watch)) return;

    if (watch.spec.ready !== undefined && watch.readyAt === undefined) {
      this.settle(
        watch,
        "failed",
        "failed",
        "failed",
        `${message}; process exited before becoming ready`,
      );
      return;
    }
    if (watch.readyAt !== undefined && watch.spec.watchAfterReady) {
      this.settle(
        watch,
        "failed",
        "failed",
        "failed",
        `${message}; service exited after becoming ready`,
      );
      return;
    }

    const outcome = this.evaluateMatchOutcome(watch, undefined, "exited");
    this.settle(
      watch,
      outcome.lifecycle,
      outcome.targetState,
      outcome.event,
      outcome.message ?? message,
    );
  }

  private evaluateMatchOutcome(
    watch: WatchRecord,
    exitCode: number | null | undefined,
    targetState: WatchTargetState,
  ): {
    lifecycle: TerminalLifecycle;
    targetState: WatchTargetState;
    event: NotifierEvent;
    message?: string;
  } {
    const failure = watch.spec.failure;
    const success = watch.spec.success;
    const failureExit =
      failure !== undefined && matchesExitCode(failure, exitCode);
    const successExit =
      success !== undefined && matchesExitCode(success, exitCode);

    if (failureExit) {
      return {
        lifecycle: "failed",
        targetState: "failed",
        event: "failed",
        message: "matched the failure condition",
      };
    }
    if (success !== undefined) {
      if (successExit) {
        return {
          lifecycle: "completed",
          targetState,
          event: "completed",
          message: "matched the success condition",
        };
      }
      return {
        lifecycle: "failed",
        targetState: "failed",
        event: "failed",
        message: "exited without matching the success condition",
      };
    }
    if (failure !== undefined) {
      return {
        lifecycle: "completed",
        targetState,
        event: "completed",
        message: "exited without matching the failure condition",
      };
    }
    if (watch.spec.kind === "job") {
      if (exitCode === 0) {
        return {
          lifecycle: "completed",
          targetState,
          event: "completed",
          message: "exit code 0",
        };
      }
      return {
        lifecycle: "failed",
        targetState: "failed",
        event: "failed",
        message:
          exitCode === undefined || exitCode === null
            ? "exit code is unavailable"
            : `exit code ${exitCode}`,
      };
    }
    return {
      lifecycle: "completed",
      targetState,
      event: "completed",
      message: "process exited",
    };
  }

  private async handleReady(
    watch: WatchRecord,
    cwd?: string,
  ): Promise<void> {
    const ready = watch.spec.ready;
    if (ready === undefined || watch.readyAt !== undefined) return;
    const now = this.now();
    const startedAt = watch.readyStartedAt ?? watch.createdAt;
    if (now - startedAt >= ready.timeoutMs) {
      this.settle(
        watch,
        "timeout",
        "timeout",
        "timeout",
        `not ready within ${formatDuration(ready.timeoutMs)}`,
      );
      return;
    }

    if (watch.conditions.readyRegex !== undefined) {
      if (!watch.readyRegexMatched) return;
      this.markReady(watch);
      return;
    }
    if (ready.command === undefined) return;

    let ok = false;
    try {
      const remaining = Math.max(1_000, ready.timeoutMs - (now - startedAt));
      const result = await this.options.manager.exec({
        sshId: watch.spec.sshId,
        command: ready.command,
        ...(cwd !== undefined ? { cwd } : {}),
        timeoutMs: Math.min(PROBE_TIMEOUT_MS, remaining),
        maxOutputBytes: 4_096,
      });
      ok = result.exitCode === 0;
    } catch {
      ok = false;
    }
    if (isTerminal(watch)) return;

    if (!ok) {
      delete watch.readyOkSince;
      watch.readyChecks = 0;
      return;
    }
    if (watch.readyOkSince === undefined) {
      watch.readyOkSince = now;
      watch.readyChecks = 1;
      return;
    }
    watch.readyChecks += 1;
    if (
      watch.readyChecks >= MIN_READY_CHECKS &&
      now - watch.readyOkSince >= ready.stableMs
    ) {
      this.markReady(watch);
    }
  }

  private markReady(watch: WatchRecord): void {
    if (isTerminal(watch) || watch.readyAt !== undefined) return;
    watch.readyAt = this.now();
    watch.targetState = "ready";
    watch.lastEvent = "ready";
    if (watch.spec.watchAfterReady) {
      if (!watch.readyNotified) {
        watch.readyNotified = true;
        this.emit(watch, {
          type: "ready",
          watch,
          at: this.now(),
          message: "service is ready",
        });
      }
      return;
    }
    this.settle(watch, "completed", "ready", "ready", "service is ready");
  }

  private async scanLog(watch: WatchRecord, terminal = false): Promise<void> {
    if (isTerminal(watch)) return;
    if (watch.logPath === undefined) return;
    if (!hasRegexConditions(watch.conditions) && !terminal) return;

    if (terminal) {
      let chunkFailed = false;
      if (watch.logOffset !== undefined) {
        const chunk = await this.readLogChunk(watch);
        if (chunk === undefined) {
          chunkFailed = true;
        } else if (chunk.length > 0) {
          this.applyLogText(watch, chunk);
          if (isTerminal(watch)) return;
        }
      }
      if (
        chunkFailed ||
        watch.logOffset === undefined ||
        watch.logOffset === 0 ||
        (watch.createdTerminal &&
          watch.logOffset === watch.initialLogOffset)
      ) {
        const tail = await this.readLogTail(watch, TERMINAL_TAIL_LINES);
        if (tail !== undefined) this.applyLogText(watch, tail);
      }
      return;
    }

    if (watch.logOffset === undefined) {
      const size = await this.logSize(watch);
      if (size === undefined) {
        watch.logUnavailable = true;
        return;
      }
      watch.logOffset = size;
      if (
        watch.conditions.readyRegex !== undefined &&
        !watch.readyRegexMatched
      ) {
        const tail = await this.readLogTail(watch, READY_TAIL_LINES);
        if (tail !== undefined) this.applyReadyText(watch, tail);
      }
      return;
    }

    const chunk = await this.readLogChunk(watch);
    if (chunk !== undefined) this.applyLogText(watch, chunk);
  }

  private applyReadyText(watch: WatchRecord, text: string): void {
    if (text.length === 0) return;
    if (watch.conditions.readyRegex?.test(text) === true) {
      watch.readyRegexMatched = true;
    }
  }

  private applyLogText(watch: WatchRecord, text: string): void {
    if (isTerminal(watch) || text.length === 0) return;
    if (watch.conditions.failureRegex?.test(text) === true) {
      this.settle(
        watch,
        "failed",
        "failed",
        "failed",
        "log matched the failure regex",
      );
      return;
    }
    if (watch.conditions.successRegex?.test(text) === true) {
      this.settle(
        watch,
        "completed",
        watch.targetState,
        "completed",
        "log matched the success regex",
      );
      return;
    }
    if (watch.conditions.readyRegex?.test(text) === true) {
      watch.readyRegexMatched = true;
      if (watch.readyAt === undefined) this.markReady(watch);
    }
  }

  private async initLog(watch: WatchRecord): Promise<void> {
    if (watch.logPath === undefined) return;
    const size = await this.logSize(watch);
    if (size === undefined) {
      watch.logUnavailable = true;
      return;
    }
    watch.logOffset = size;
    watch.initialLogOffset = size;
    if (watch.conditions.readyRegex !== undefined) {
      const tail = await this.readLogTail(watch, READY_TAIL_LINES);
      if (tail !== undefined) this.applyReadyText(watch, tail);
    }
  }

  private async logSize(watch: WatchRecord): Promise<number | undefined> {
    const logPath = watch.logPath;
    if (logPath === undefined) return undefined;
    const result = await this.options.manager.exec({
      sshId: watch.spec.sshId,
      command: `wc -c < ${shellQuote(logPath)} 2>/dev/null`,
      timeoutMs: 15_000,
      maxOutputBytes: 4_096,
    });
    if (result.exitCode !== 0) return undefined;
    const value = Number.parseInt(result.stdout.trim(), 10);
    return Number.isFinite(value) && value >= 0 ? value : undefined;
  }

  private async readLogChunk(watch: WatchRecord): Promise<string | undefined> {
    const logPath = watch.logPath;
    const previous = watch.logOffset;
    if (logPath === undefined || previous === undefined) return undefined;
    const result = await this.options.manager.exec({
      sshId: watch.spec.sshId,
      command:
        `size=$(wc -c < ${shellQuote(logPath)} 2>/dev/null) || exit 3; ` +
        `printf '%s\\n' "$size"; ` +
        `tail -c +$(( ${previous} + 1 )) -- ${shellQuote(logPath)} 2>/dev/null | head -c ${this.options.logScanBytes}`,
      timeoutMs: 15_000,
      maxOutputBytes: this.options.logScanBytes + 4_096,
      rawOutput: true,
    });
    if (result.exitCode !== 0) {
      watch.logUnavailable = true;
      return undefined;
    }
    const newline = result.stdout.indexOf("\n");
    if (newline < 0) return undefined;
    const size = Number.parseInt(result.stdout.slice(0, newline), 10);
    const chunk = result.stdout.slice(newline + 1);
    if (!Number.isFinite(size) || size < 0) return undefined;
    watch.logUnavailable = false;
    if (size < previous) {
      watch.logOffset = 0;
      return "";
    }
    const consumed = Buffer.byteLength(chunk, "utf8");
    watch.logOffset = Math.min(size, previous + consumed);
    return chunk;
  }

  private async readLogTail(
    watch: WatchRecord,
    lines: number,
  ): Promise<string | undefined> {
    const logPath = watch.logPath;
    if (logPath === undefined) return undefined;
    const result = await this.options.manager.exec({
      sshId: watch.spec.sshId,
      command: `tail -n ${Math.max(1, lines)} -- ${shellQuote(logPath)} 2>/dev/null`,
      timeoutMs: 15_000,
      maxOutputBytes: 256 * 1024,
    });
    if (result.exitCode !== 0) return undefined;
    return result.stdout.replace(/\r?\n$/, "");
  }

  private async resolvePid(watch: WatchRecord): Promise<number | undefined> {
    if (watch.spec.pid !== undefined) return watch.spec.pid;
    const pidFile = watch.spec.pidFile;
    if (pidFile === undefined) return undefined;
    const result = await this.options.manager.exec({
      sshId: watch.spec.sshId,
      command: `cat -- ${shellQuote(pidFile)} 2>/dev/null`,
      timeoutMs: 15_000,
      maxOutputBytes: 4_096,
    });
    if (result.exitCode !== 0) return undefined;
    const text = result.stdout.trim();
    if (!/^\d+$/.test(text)) return undefined;
    const value = Number.parseInt(text, 10);
    return value > 0 ? value : undefined;
  }

  private async isAlive(sshId: string, pid: number): Promise<boolean> {
    const result = await this.options.manager.exec({
      sshId,
      command: `ps -p ${pid} -o pid= 2>/dev/null`,
      timeoutMs: 10_000,
      maxOutputBytes: 4_096,
    });
    return result.exitCode === 0 && result.stdout.trim().length > 0;
  }

  private async pidStart(
    sshId: string,
    pid: number,
  ): Promise<string | undefined> {
    const result = await this.options.manager.exec({
      sshId,
      command: `ps -p ${pid} -o lstart= 2>/dev/null`,
      timeoutMs: 10_000,
      maxOutputBytes: 4_096,
    });
    if (result.exitCode !== 0) return undefined;
    const value = result.stdout.trim();
    return value.length > 0 ? value : undefined;
  }

  private settle(
    watch: WatchRecord,
    lifecycle: TerminalLifecycle,
    targetState: WatchTargetState,
    event: NotifierEvent,
    message?: string,
  ): void {
    if (isTerminal(watch)) return;
    watch.lifecycle = lifecycle;
    watch.targetState = targetState;
    watch.terminalAt = this.now();
    watch.lastEvent = event;
    if (message !== undefined) watch.lastMessage = message;
    this.stopWatch(watch);
    this.emit(watch, {
      type: event,
      watch,
      at: this.now(),
      ...(message !== undefined ? { message } : {}),
    });
  }

  private emit(watch: WatchRecord, event: WatchEvent): void {
    for (const listener of [...watch.listeners.values()]) {
      try {
        listener(event);
      } catch {
        // A notifier must not break the watch loop.
      }
    }
  }

  private async evaluateNotifier(notifier: NotifierRecord): Promise<void> {
    if (notifier.closing) return;
    const watches = this.notifierWatches(notifier);
    const terminals = watches.filter((watch) => isTerminal(watch));
    if (terminals.length === 0) return;

    if (notifier.failFast) {
      const failure = terminals.find(
        (watch) => watch.lifecycle === "failed" || watch.lifecycle === "timeout",
      );
      if (failure !== undefined) {
        await this.closeNotifier(
          notifier,
          failure.lifecycle === "timeout" ? "timeout" : "failed",
          failure.lifecycle === "timeout" ? "timeout" : "failed",
        );
        return;
      }
    }
    if (notifier.mode === "first") {
      const first = terminals[0];
      if (first !== undefined) {
        const ready = first.lastEvent === "ready";
        await this.closeNotifier(
          notifier,
          ready ? "ready" : eventForLifecycle(first.lifecycle),
          ready ? "completed" : stateForLifecycle(first.lifecycle),
        );
        return;
      }
    }
    if (terminals.length === watches.length) {
      await this.closeNotifier(
        notifier,
        summaryEvent(watches),
        summaryState(watches),
      );
    }
  }

  private async handleWatchEvent(
    notifier: NotifierRecord,
    event: WatchEvent,
  ): Promise<void> {
    if (notifier.closing) return;
    const watch = event.watch;

    if (event.type === "ready" && watch.lifecycle === "active") {
      await this.sendNotice(notifier, "ready", "watching", [watch], []);
      return;
    }

    if (!isTerminal(watch)) return;

    if (notifier.failFast) {
      if (watch.lifecycle === "failed" || watch.lifecycle === "timeout") {
        await this.closeNotifier(
          notifier,
          event.type === "timeout" ? "timeout" : "failed",
          event.type === "timeout" ? "timeout" : "failed",
        );
        return;
      }
    }

    if (notifier.mode === "first") {
      const ready = event.type === "ready";
      await this.closeNotifier(
        notifier,
        ready ? "ready" : eventForLifecycle(watch.lifecycle),
        ready ? "completed" : stateForLifecycle(watch.lifecycle),
      );
      return;
    }

    await this.evaluateNotifier(notifier);
  }

  private async closeNotifier(
    notifier: NotifierRecord,
    event: NotifierEvent,
    state: NotifierState,
  ): Promise<void> {
    if (notifier.closing) return;
    const watches = this.notifierWatches(notifier);
    const remaining = this.remainingWatchIds(notifier);
    notifier.closing = true;
    notifier.state = state;
    this.detachNotifier(notifier);
    await this.sendNotice(notifier, event, state, watches, remaining);
  }

  private closeNotifierRecord(notifier: NotifierRecord): string[] {
    if (notifier.closing) return [];
    notifier.closing = true;
    notifier.state = "canceled";
    return this.detachNotifier(notifier);
  }

  private detachNotifier(notifier: NotifierRecord): string[] {
    if (notifier.timer !== undefined) {
      clearTimeout(notifier.timer);
      delete notifier.timer;
    }
    this.notifiers.delete(notifier.id);
    const detached: string[] = [];
    for (const watchId of notifier.watchIds) {
      const watch = this.watches.get(watchId);
      if (watch === undefined) continue;
      watch.refCount = Math.max(0, watch.refCount - 1);
      watch.notifierIds.delete(notifier.id);
      watch.listeners.delete(notifier.id);
      if (watch.refCount === 0 && !isTerminal(watch)) {
        watch.lifecycle = "detached";
        watch.detachedAt = this.now();
        this.stopWatch(watch);
        detached.push(watchId);
      }
    }
    return detached;
  }

  private remainingWatchIds(
    notifier: NotifierRecord,
    exceptWatchId?: string,
  ): string[] {
    return notifier.watchIds.filter((watchId) => {
      if (watchId === exceptWatchId) return false;
      const watch = this.watches.get(watchId);
      return watch !== undefined && !isTerminal(watch);
    });
  }

  private notifierWatches(notifier: NotifierRecord): WatchRecord[] {
    return notifier.watchIds
      .map((watchId) => this.watches.get(watchId))
      .filter((watch): watch is WatchRecord => watch !== undefined);
  }

  private async sendNotice(
    notifier: NotifierRecord,
    event: NotifierEvent,
    state: NotifierState,
    watches: WatchRecord[],
    remainingWatchIds: string[],
  ): Promise<void> {
    const includeLogs = this.logTargets(notifier, event, watches);
    let logBudget = MAX_NOTICE_LOG_LINES;
    const targets: WatchNoticeTarget[] = [];
    for (const watch of watches) {
      let logTail: string | undefined;
      if (
        notifier.notify.logLines > 0 &&
        includeLogs.has(watch.id) &&
        logBudget > 0 &&
        watch.logPath !== undefined
      ) {
        const lines = Math.min(notifier.notify.logLines, logBudget);
        try {
          logTail = await this.readLogTail(watch, lines);
        } catch {
          logTail = undefined;
        }
        if (logTail !== undefined) {
          logBudget -= Math.min(lines, logTail.split("\n").length);
        }
      }
      targets.push(this.noticeTarget(watch, logTail));
    }

    const notice: WatchNotice = {
      event,
      notifierId: notifier.id,
      sessionID: notifier.sessionID,
      ...(notifier.agent !== undefined ? { agent: notifier.agent } : {}),
      state,
      mode: notifier.mode,
      failFast: notifier.failFast,
      ...(notifier.notify.title !== undefined
        ? { title: notifier.notify.title }
        : {}),
      targets,
      remainingWatchIds,
      at: this.now(),
    };
    try {
      await this.options.notify(notice);
    } catch {
      // Notification failure must not keep a closed notifier alive.
    }
  }

  private logTargets(
    notifier: NotifierRecord,
    event: NotifierEvent,
    watches: WatchRecord[],
  ): Set<string> {
    if (notifier.notify.logScope === "none") return new Set();
    if (notifier.notify.logScope === "all") {
      return new Set(watches.map((watch) => watch.id));
    }
    const selected = new Set<string>();
    if (event === "ready" || event === "timeout") {
      for (const watch of watches) {
        if (watch.lastEvent === event) selected.add(watch.id);
      }
    }
    for (const watch of watches) {
      if (
        watch.lifecycle === "failed" ||
        watch.lifecycle === "timeout" ||
        watch.targetState === "failed" ||
        watch.targetState === "timeout" ||
        watch.targetState === "lost"
      ) {
        selected.add(watch.id);
      }
    }
    return selected;
  }

  private noticeTarget(
    watch: WatchRecord,
    logTail: string | undefined,
  ): WatchNoticeTarget {
    return {
      watchId: watch.id,
      sshId: watch.spec.sshId,
      kind: watch.spec.kind,
      ...(watch.spec.jobId !== undefined ? { jobId: watch.spec.jobId } : {}),
      ...(watch.resolvedPid !== undefined || watch.spec.pid !== undefined
        ? { pid: watch.resolvedPid ?? watch.spec.pid }
        : {}),
      ...(watch.spec.pidFile !== undefined
        ? { pidFile: watch.spec.pidFile }
        : {}),
      ...(watch.displayName !== undefined || watch.spec.name !== undefined
        ? { name: watch.displayName ?? watch.spec.name }
        : {}),
      lifecycle: watch.lifecycle,
      targetState: watch.targetState,
      ...(watch.exitCode !== undefined ? { exitCode: watch.exitCode } : {}),
      ...(watch.lastEvent !== undefined ? { lastEvent: watch.lastEvent } : {}),
      ...(watch.lastMessage !== undefined ? { message: watch.lastMessage } : {}),
      ...(watch.logPath !== undefined ? { logPath: watch.logPath } : {}),
      ...(logTail !== undefined ? { logTail } : {}),
    };
  }

  private snapshotWatch(watch: WatchRecord): WatchSnapshot {
    return {
      watchId: watch.id,
      sessionID: watch.sessionID,
      sshId: watch.spec.sshId,
      kind: watch.spec.kind,
      ...(watch.spec.jobId !== undefined ? { jobId: watch.spec.jobId } : {}),
      ...(watch.resolvedPid !== undefined || watch.spec.pid !== undefined
        ? { pid: watch.resolvedPid ?? watch.spec.pid }
        : {}),
      ...(watch.spec.pidFile !== undefined
        ? { pidFile: watch.spec.pidFile }
        : {}),
      ...(watch.displayName !== undefined || watch.spec.name !== undefined
        ? { name: watch.displayName ?? watch.spec.name }
        : {}),
      ...(watch.logPath !== undefined ? { logPath: watch.logPath } : {}),
      lifecycle: watch.lifecycle,
      targetState: watch.targetState,
      refCount: watch.refCount,
      attachedNotifierIds: [...watch.notifierIds].sort(),
      createdAt: watch.createdAt,
      ...(watch.lastCheckedAt !== undefined
        ? { lastCheckedAt: watch.lastCheckedAt }
        : {}),
      ...(watch.lastEvent !== undefined ? { lastEvent: watch.lastEvent } : {}),
      ...(watch.lastMessage !== undefined
        ? { lastMessage: watch.lastMessage }
        : {}),
      ...(watch.lastError !== undefined ? { lastError: watch.lastError } : {}),
      ...(watch.exitCode !== undefined ? { exitCode: watch.exitCode } : {}),
      ...(watch.readyAt !== undefined ? { readyAt: watch.readyAt } : {}),
      ...(watch.terminalAt !== undefined ? { terminalAt: watch.terminalAt } : {}),
      ...(watch.detachedAt !== undefined ? { detachedAt: watch.detachedAt } : {}),
    };
  }

  private snapshotNotifier(notifier: NotifierRecord): NotifierSnapshot {
    return {
      notifierId: notifier.id,
      sessionID: notifier.sessionID,
      state: notifier.state,
      mode: notifier.mode,
      failFast: notifier.failFast,
      watchIds: [...notifier.watchIds],
      createdAt: notifier.createdAt,
      ...(notifier.timeoutMs !== undefined
        ? { timeoutMs: notifier.timeoutMs }
        : {}),
      ...(notifier.notify.title !== undefined
        ? { title: notifier.notify.title }
        : {}),
    };
  }

  private sweep(): void {
    const now = this.now();
    for (const [watchId, watch] of this.watches) {
      if (watch.refCount > 0 || watch.lifecycle === "active") continue;
      const since =
        watch.terminalAt ?? watch.detachedAt ?? watch.createdAt;
      if (now - since >= this.options.ttlMs) {
        this.stopWatch(watch);
        watch.listeners.clear();
        this.watches.delete(watchId);
      }
    }
  }
}

function newId(prefix: string): string {
  return `${prefix}_${randomBytes(6).toString("hex")}`;
}

function jobStopKey(sshId: string, jobId: string): string {
  return `${sshId}\u0000${jobId}`;
}

function isTerminal(watch: WatchRecord): boolean {
  return (
    watch.lifecycle === "completed" ||
    watch.lifecycle === "failed" ||
    watch.lifecycle === "timeout" ||
    watch.lifecycle === "canceled"
  );
}

function hasRegexConditions(conditions: CompiledConditions): boolean {
  return (
    conditions.readyRegex !== undefined ||
    conditions.successRegex !== undefined ||
    conditions.failureRegex !== undefined
  );
}

function compileConditions(spec: WatchTargetSpec): CompiledConditions {
  return {
    ...(spec.ready?.regex !== undefined
      ? { readyRegex: compileRegex(spec.ready.regex, "ready.regex") }
      : {}),
    ...(spec.success?.regex !== undefined
      ? { successRegex: compileRegex(spec.success.regex, "success.regex") }
      : {}),
    ...(spec.failure?.regex !== undefined
      ? { failureRegex: compileRegex(spec.failure.regex, "failure.regex") }
      : {}),
  };
}

function compileRegex(value: string, field: string): RegExp {
  try {
    return new RegExp(value);
  } catch (error) {
    throw new Error(`Invalid ${field}: ${errorMessage(error)}`);
  }
}

function normalizeConditions(spec: WatchTargetSpec): WatchTargetSpec {
  return {
    ...spec,
    ...(spec.ready !== undefined
      ? {
          ready: {
            ...(spec.ready.command !== undefined
              ? { command: spec.ready.command }
              : {}),
            ...(spec.ready.regex !== undefined
              ? { regex: spec.ready.regex }
              : {}),
            timeoutMs: spec.ready.timeoutMs,
            intervalMs: spec.ready.intervalMs,
            stableMs: spec.ready.stableMs,
          },
        }
      : {}),
    watchAfterReady: spec.watchAfterReady === true,
  };
}

function cloneMatchCondition(condition: MatchCondition): MatchCondition {
  return {
    ...(condition.exitCodes !== undefined
      ? { exitCodes: [...condition.exitCodes] }
      : {}),
    ...(condition.regex !== undefined ? { regex: condition.regex } : {}),
  };
}

function canonicalSpec(spec: WatchTargetSpec): string {
  return JSON.stringify({
    kind: spec.kind,
    sshId: spec.sshId,
    jobId: spec.jobId,
    pid: spec.pid,
    pidFile: spec.pidFile,
    logPath: spec.logPath,
    ready: spec.ready,
    success: canonicalMatch(spec.success),
    failure: canonicalMatch(spec.failure),
    watchAfterReady: spec.watchAfterReady,
  });
}

function canonicalMatch(
  condition: MatchCondition | undefined,
): MatchCondition | undefined {
  if (condition === undefined) return undefined;
  return {
    ...(condition.exitCodes !== undefined
      ? { exitCodes: [...condition.exitCodes].sort((left, right) => left - right) }
      : {}),
    ...(condition.regex !== undefined ? { regex: condition.regex } : {}),
  };
}

function matchesExitCode(
  condition: MatchCondition,
  exitCode: number | null | undefined,
): boolean {
  if (condition.exitCodes === undefined) return false;
  if (typeof exitCode !== "number") return false;
  return condition.exitCodes.includes(exitCode);
}

function eventForLifecycle(lifecycle: WatchLifecycle): NotifierEvent {
  switch (lifecycle) {
    case "completed":
      return "completed";
    case "timeout":
      return "timeout";
    case "canceled":
      return "canceled";
    case "failed":
    case "active":
    case "detached":
      return "failed";
  }
}

function stateForLifecycle(lifecycle: WatchLifecycle): NotifierState {
  switch (lifecycle) {
    case "completed":
      return "completed";
    case "timeout":
      return "timeout";
    case "canceled":
      return "canceled";
    case "failed":
    case "active":
    case "detached":
      return "failed";
  }
}

function summaryEvent(watches: WatchRecord[]): NotifierEvent {
  if (watches.some((watch) => watch.lifecycle === "failed")) return "failed";
  if (watches.some((watch) => watch.lifecycle === "timeout")) return "timeout";
  if (watches.some((watch) => watch.lifecycle === "canceled")) return "canceled";
  if (
    watches.length > 0 &&
    watches.every((watch) => watch.lastEvent === "ready")
  ) {
    return "ready";
  }
  return "completed";
}

function summaryState(watches: WatchRecord[]): NotifierState {
  if (watches.some((watch) => watch.lifecycle === "failed")) return "failed";
  if (watches.some((watch) => watch.lifecycle === "timeout")) return "timeout";
  if (watches.some((watch) => watch.lifecycle === "canceled")) return "canceled";
  return "completed";
}

function delay(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    return Promise.reject(new Error("aborted"));
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, milliseconds);
    timer.unref?.();
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new Error("aborted"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function formatDuration(milliseconds: number): string {
  if (milliseconds < 1_000) return `${milliseconds}ms`;
  const seconds = Math.floor(milliseconds / 1_000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h${minutes % 60}m`;
}

export function formatWatchNotice(notice: WatchNotice): string {
  const heading =
    notice.event === "ready"
      ? "[ssh watch ready]"
      : notice.event === "timeout"
        ? "[ssh watch timeout]"
        : notice.event === "failed"
          ? "[ssh watch failed]"
          : notice.event === "canceled"
            ? "[ssh watch canceled]"
            : "[ssh watch completed]";
  const lines = [
    heading,
    ...(notice.title !== undefined ? [`title: ${notice.title}`] : []),
    `notifier: ${notice.notifierId}`,
    `state: ${notice.state}  mode: ${notice.mode}  fail_fast: ${notice.failFast}`,
    "",
    "targets:",
  ];
  for (const target of notice.targets) {
    const label = formatTargetLabel(target);
    const name = target.name !== undefined ? ` (${target.name})` : "";
    const exit =
      target.exitCode !== undefined ? ` exit=${target.exitCode}` : "";
    lines.push(
      `- ${label}${name}  lifecycle=${target.lifecycle}  state=${target.targetState}${exit}`,
    );
    if (target.lastEvent !== undefined) {
      lines.push(`  event: ${target.lastEvent}`);
    }
    if (target.message !== undefined) {
      lines.push(`  detail: ${target.message}`);
    }
    if (target.logPath !== undefined) {
      lines.push(`  log: ${target.logPath}`);
    }
    if (target.logTail !== undefined && target.logTail.length > 0) {
      lines.push("  [last lines]", ...target.logTail.split("\n").map((line) => `  ${line}`));
    }
  }
  if (notice.event === "timeout") {
    lines.push("", "The watch timed out; the targets were not stopped.");
  }
  if (notice.remainingWatchIds.length > 0) {
    lines.push(
      "",
      "remaining watches (released from this notifier; reuse with ssh_watch watch_ids):",
      ...notice.remainingWatchIds.map((watchId) => `- ${watchId}`),
      "The watch stopped; the targets themselves were not stopped.",
    );
  }
  return lines.join("\n");
}
