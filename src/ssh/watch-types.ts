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
  | "monitor-stopped"
  | "suspended";

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

export interface WatchDescriptor {
  kind: WatchKind;
  jobId?: string;
  readyCommand?: string;
  readyTimeoutMs?: number;
  readyIntervalMs?: number;
  readyStableMs?: number;
  pid?: number;
  pidFile?: string;
  logPath?: string;
  successRegex?: string;
  failureRegex?: string;
  logLines?: number;
  timeoutMs?: number;
  sources?: WatchDescriptor[];
}

export interface WatchSource {
  readonly kind: WatchKind;
  /** Stable key for duplicate suppression, for example `${sshId}:${jobId}`. */
  readonly key?: string;
  /** Serializable description used to restore suspended watches. */
  readonly descriptor?: WatchDescriptor | undefined;
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

export interface PersistedWatch {
  watchId: string;
  kind: WatchKind;
  sessionID: string;
  agent?: string;
  name?: string;
  hostLabel?: string;
  sshId?: string;
  jobId?: string;
  descriptor: WatchDescriptor;
  logLines?: number;
  watchAfterReady?: boolean;
  state: WatchState;
  startedAt: number;
  suspendedAt?: number;
  readiness?: JobReadiness;
  readyAt?: number;
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
  conditions?: string;
  state: WatchState;
  suspended?: boolean;
  startedAt: number;
}
