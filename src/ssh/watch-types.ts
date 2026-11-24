export type WatchTargetKind = "job" | "process";

export type WatchLifecycle =
  | "active"
  | "detached"
  | "completed"
  | "failed"
  | "timeout"
  | "canceled";

export type WatchTargetState =
  | "pending"
  | "running"
  | "ready"
  | "exited"
  | "stopped"
  | "failed"
  | "timeout"
  | "lost";

export type NotifierState =
  | "watching"
  | "completed"
  | "failed"
  | "timeout"
  | "canceled";

export type NotifierMode = "all" | "first";

export type NotifierEvent = "ready" | "completed" | "failed" | "timeout" | "canceled";

export type LogScope = "failed" | "all" | "none";

export interface ReadyCondition {
  command?: string;
  regex?: string;
  timeoutMs: number;
  intervalMs: number;
  stableMs: number;
}

export interface MatchCondition {
  exitCodes?: number[];
  regex?: string;
}

/** A normalized target description stored by a watch. */
export interface WatchTargetSpec {
  kind: WatchTargetKind;
  sshId: string;
  jobId?: string;
  pid?: number;
  pidFile?: string;
  name?: string;
  logPath?: string;
  ready?: ReadyCondition;
  success?: MatchCondition;
  failure?: MatchCondition;
  watchAfterReady: boolean;
}

export interface WatchSnapshot {
  watchId: string;
  sessionID: string;
  sshId: string;
  kind: WatchTargetKind;
  jobId?: string;
  pid?: number;
  pidFile?: string;
  name?: string;
  logPath?: string;
  lifecycle: WatchLifecycle;
  targetState: WatchTargetState;
  refCount: number;
  attachedNotifierIds: string[];
  createdAt: number;
  lastCheckedAt?: number;
  lastEvent?: string;
  lastMessage?: string;
  lastError?: string;
  exitCode?: number | null;
  readyAt?: number;
  terminalAt?: number;
  detachedAt?: number;
}

export interface NotifierSnapshot {
  notifierId: string;
  sessionID: string;
  state: NotifierState;
  mode: NotifierMode;
  failFast: boolean;
  watchIds: string[];
  createdAt: number;
  timeoutMs?: number;
  title?: string;
  remainingWatchIds?: string[];
}

export interface WatchNoticeTarget {
  watchId: string;
  sshId: string;
  kind: WatchTargetKind;
  jobId?: string;
  pid?: number;
  pidFile?: string;
  name?: string;
  lifecycle: WatchLifecycle;
  targetState: WatchTargetState;
  exitCode?: number | null;
  lastEvent?: string;
  message?: string;
  logPath?: string;
  logTail?: string;
}

export interface WatchNotice {
  event: NotifierEvent;
  notifierId: string;
  sessionID: string;
  agent?: string;
  state: NotifierState;
  mode: NotifierMode;
  failFast: boolean;
  title?: string;
  targets: WatchNoticeTarget[];
  remainingWatchIds: string[];
  at: number;
}

export interface WatchNotifyOptions {
  title?: string;
  logLines: number;
  logScope: LogScope;
}

export interface CreateNotifierInput {
  sessionID: string;
  agent?: string;
  targets: WatchTargetSpec[];
  watchIds: string[];
  mode: NotifierMode;
  failFast: boolean;
  timeoutMs?: number;
  notify: WatchNotifyOptions;
}

export interface CreateNotifierResult {
  notifier: NotifierSnapshot;
  watches: WatchSnapshot[];
  reusedWatchIds: string[];
}

export interface UnwatchNotifierResult {
  removed: boolean;
  releasedWatchIds: string[];
  detachedWatchIds: string[];
}

export interface UnwatchWatchResult {
  removed: boolean;
  watchId: string;
}

export interface WatchListResult {
  notifiers: NotifierSnapshot[];
  watches: WatchSnapshot[];
}

export interface CancelWatchesResult {
  canceledWatchIds: string[];
  closedNotifierIds: string[];
  remainingNotifierIds: string[];
}

export function watchTargetKey(spec: WatchTargetSpec): string {
  if (spec.kind === "job") {
    return `job:${spec.sshId}:${spec.jobId ?? ""}`;
  }
  if (spec.pid !== undefined) {
    return `process:${spec.sshId}:pid:${spec.pid}`;
  }
  return `process:${spec.sshId}:file:${spec.pidFile ?? ""}`;
}

export function formatTargetLabel(spec: {
  kind: WatchTargetKind;
  sshId: string;
  jobId?: string;
  pid?: number;
  pidFile?: string;
}): string {
  if (spec.kind === "job") {
    return `${spec.sshId}/job/${spec.jobId ?? "?"}`;
  }
  const process =
    spec.pid !== undefined ? `pid ${spec.pid}` : `pid_file ${spec.pidFile ?? "?"}`;
  return `${spec.sshId}/process/${process}`;
}
