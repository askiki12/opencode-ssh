import type { JobState } from "./jobs.js";

export type WatchKind =
  | "job"
  | "pid"
  | "log"
  | "health"
  | "timeout"
  | "composite";

export type WatchState =
  | "pending"
  | "ready"
  | "timeout"
  | "exited"
  | "monitor-stopped";

export type JobReadiness = "pending" | "ready" | "failed" | "timeout";

export type WatchEvent =
  | "exit"
  | "ready"
  | "timeout"
  | "service-exited"
  | "pid-exited"
  | "log-matched"
  | "monitor-stopped";

export interface WatchCheckContext {
  now: number;
  signal: AbortSignal;
}

export interface WatchCheck {
  state: WatchState;
  event?: WatchEvent;
  readiness?: JobReadiness;
  readyAt?: number;
  exitCode?: number | null;
  pid?: number;
  logPath?: string;
  logTail?: string;
  message?: string;
  pattern?: string;
  outcome?: "success" | "failure";
  /** Suggested delay before the next check while pending. */
  nextIntervalMs?: number;
}

export interface WatchSource {
  readonly kind: WatchKind;
  /** Stable key for duplicate suppression, for example `${sshId}:${jobId}`. */
  readonly key?: string;
  /** Current readiness for service sources. */
  readonly readiness?: JobReadiness | undefined;
  readonly readyAt?: number | undefined;
  check(context: WatchCheckContext): Promise<WatchCheck>;
}

export interface WatchNotice {
  event: WatchEvent;
  kind: WatchKind;
  watchId: string;
  jobId?: string;
  sshId?: string;
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
  pattern?: string;
  outcome?: "success" | "failure";
}

export interface WatchSummary {
  watchId: string;
  kind: WatchKind;
  jobId?: string;
  sshId?: string;
  sessionID: string;
  name?: string;
  hostLabel?: string;
  readiness?: JobReadiness;
  state: WatchState;
  startedAt: number;
}
