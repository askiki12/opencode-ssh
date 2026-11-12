import { randomBytes } from "node:crypto";
import path from "node:path";
import { shellQuote } from "./command.js";
import { ensureRemoteDir, resolveRemotePath, type SftpLike } from "./files.js";
import type { ExecResult } from "./manager.js";

const posix = path.posix;

const JOB_ID_PATTERN = /^job_[0-9a-f]{8,16}$/;
const JOBS_DIRECTORY = ".opencode-ssh/jobs";
const MAX_LISTED_JOBS = 100;
const MAX_LOG_LINES = 500;
const MAX_META_COMMAND = 500;
const LAUNCH_WAIT_MS = 1_000;

/** The slice of ConnectionManager the job runner depends on. */
export interface JobConnections {
  sftp(sshId: string): Promise<SftpLike>;
  homeDir(sshId: string): Promise<string>;
  exec(input: {
    sshId: string;
    command: string;
    timeoutMs?: number;
    maxOutputBytes?: number;
  }): Promise<ExecResult>;
}

export interface JobStartInput {
  sshId: string;
  command: string;
  name?: string;
  cwd?: string;
}

export interface JobStartResult {
  jobId: string;
  name?: string;
  pid: number;
  jobDir: string;
  logPath: string;
}

export type JobState =
  | "starting"
  | "running"
  | "finished"
  | "stopped"
  | "lost"
  | "corrupt";

export interface JobInfo {
  jobId: string;
  name?: string;
  state: JobState;
  pid?: number;
  exitCode?: number | null;
  startedAt?: string;
  elapsedMs?: number;
  command?: string;
  jobDir: string;
  logPath: string;
  log?: string;
  logUnavailable?: boolean;
}

export interface JobStopResult {
  jobId: string;
  outcome: "stopped" | "already-finished" | "not-running" | "mismatch";
  pid?: number;
  exitCode?: number | null;
}

export class JobService {
  constructor(private readonly connections: JobConnections) {}

  async start(input: JobStartInput): Promise<JobStartResult> {
    const home = await this.connections.homeDir(input.sshId);
    const cwd =
      input.cwd === undefined ? home : resolveRemotePath(input.cwd, home);
    const sftp = await this.connections.sftp(input.sshId);
    const jobId = `job_${randomBytes(6).toString("hex")}`;
    const jobDir = posix.join(home, JOBS_DIRECTORY, jobId);
    const logPath = posix.join(jobDir, "output.log");

    await ensureRemoteDir(sftp, jobDir);
    await writeText(sftp, posix.join(jobDir, "job.sh"), buildJobScript(input.command, jobDir, cwd), 0o700);
    await writeText(
      sftp,
      posix.join(jobDir, "meta.json"),
      `${JSON.stringify(
        {
          id: jobId,
          ...(input.name !== undefined ? { name: input.name } : {}),
          cwd,
          command:
            input.command.length > MAX_META_COMMAND
              ? `${input.command.slice(0, MAX_META_COMMAND)}...`
              : input.command,
          createdAt: new Date().toISOString(),
        },
        null,
        2,
      )}\n`,
      0o600,
    );

    // `exec` keeps the same pid through setsid, so $! is the process group
    // leader that ssh_job_stop can later signal as a group.
    await this.connections.exec({
      sshId: input.sshId,
      command: buildLaunchCommand(jobDir),
      timeoutMs: 15_000,
      maxOutputBytes: 4_096,
    });

    const pid = await waitForPid(sftp, jobDir);
    if (pid === undefined) {
      throw new Error(
        `Job directory was created at ${jobDir} but the process did not report a pid. ` +
          "Inspect the job directory, then remove it with ssh_remove if it is unusable.",
      );
    }

    return {
      jobId,
      ...(input.name !== undefined ? { name: input.name } : {}),
      pid,
      jobDir,
      logPath,
    };
  }

  async status(
    sshId: string,
    jobId: string | undefined,
    logLines: number,
  ): Promise<JobInfo | JobInfo[]> {
    const home = await this.connections.homeDir(sshId);
    const base = posix.join(home, JOBS_DIRECTORY);
    const sftp = await this.connections.sftp(sshId);

    if (jobId !== undefined) {
      const jobDir = this.jobDirectory(base, jobId);
      const info = await this.readJob(sshId, sftp, jobDir, jobId);
      if (logLines > 0 && info.state !== "corrupt") {
        const logs = await this.readLog(sshId, info.logPath, logLines);
        if (logs === undefined) {
          info.logUnavailable = true;
        } else {
          info.log = logs;
        }
      }
      return info;
    }

    const jobs = await this.listJobs(sshId, sftp, base);
    return jobs;
  }

  async stop(sshId: string, jobId: string): Promise<JobStopResult> {
    const home = await this.connections.homeDir(sshId);
    const base = posix.join(home, JOBS_DIRECTORY);
    const jobDir = this.jobDirectory(base, jobId);
    const sftp = await this.connections.sftp(sshId);
    const pid = await readNumber(sftp, posix.join(jobDir, "pid"));
    if (pid === undefined) {
      throw new Error(
        `Job ${jobId} has no recorded pid. It may never have started; inspect ${jobDir}.`,
      );
    }

    const exitCode = await readNumber(sftp, posix.join(jobDir, "exit_code"));
    if (exitCode !== undefined) {
      return { jobId, outcome: "already-finished", pid, exitCode };
    }

    const result = await this.connections.exec({
      sshId,
      command: buildStopCommand(pid, jobDir),
      timeoutMs: 20_000,
      maxOutputBytes: 8_192,
    });

    const output = result.stdout.trim();
    if (output.includes("mismatch")) {
      return { jobId, outcome: "mismatch", pid };
    }
    if (output.includes("not-running")) {
      return { jobId, outcome: "not-running", pid };
    }

    // The wrapper cannot record an exit code when its whole process group is
    // signalled, so leave an explicit marker for the status tools.
    await writeText(
      sftp,
      posix.join(jobDir, "stopped_at"),
      `${Math.floor(Date.now() / 1_000)}\n`,
      0o600,
    );
    return { jobId, outcome: "stopped", pid };
  }

  private jobDirectory(base: string, jobId: string): string {
    if (!JOB_ID_PATTERN.test(jobId)) {
      throw new Error(
        `Invalid job_id "${jobId}". Expected a value returned by ssh_job_start.`,
      );
    }
    return posix.join(base, jobId);
  }

  private async readJob(
    sshId: string,
    sftp: SftpLike,
    jobDir: string,
    jobId: string,
  ): Promise<JobInfo> {
    const metaText = await readText(sftp, posix.join(jobDir, "meta.json"));
    if (metaText === undefined) {
      return {
        jobId,
        state: "corrupt",
        jobDir,
        logPath: posix.join(jobDir, "output.log"),
      };
    }
    const meta = parseMeta(metaText);
    const info: JobInfo = {
      jobId,
      state: "starting",
      jobDir,
      logPath: posix.join(jobDir, "output.log"),
      ...(meta.name !== undefined ? { name: meta.name } : {}),
      ...(meta.command !== undefined ? { command: meta.command } : {}),
    };

    const exitCode = await readNumber(sftp, posix.join(jobDir, "exit_code"));
    const stoppedAt = await readNumber(sftp, posix.join(jobDir, "stopped_at"));
    const pid = await readNumber(sftp, posix.join(jobDir, "pid"));
    const startedAt = await readNumber(sftp, posix.join(jobDir, "started_at"));
    if (pid !== undefined) info.pid = pid;
    if (startedAt !== undefined) info.startedAt = new Date(startedAt * 1_000).toISOString();

    if (exitCode !== undefined) {
      info.state = "finished";
      info.exitCode = exitCode;
      return info;
    }
    if (stoppedAt !== undefined) {
      info.state = "stopped";
      if (startedAt !== undefined) {
        info.elapsedMs = Math.max(0, (stoppedAt - startedAt) * 1_000);
      }
      return info;
    }
    if (pid === undefined) {
      return info;
    }

    const probe = await this.probeProcesses(sshId, [pid], jobDir);
    const now = probe.now;
    if (startedAt !== undefined) info.elapsedMs = Math.max(0, now - startedAt * 1_000);
    if (!probe.alive.has(pid)) {
      info.state = "lost";
      return info;
    }
    info.state = probe.matching.has(pid) ? "running" : "lost";
    return info;
  }

  private async listJobs(
    sshId: string,
    sftp: SftpLike,
    base: string,
  ): Promise<JobInfo[]> {
    const entries = await readdir(sftp, base);
    if (entries.length === 0) return [];

    const jobIds = entries
      .filter((entry) => JOB_ID_PATTERN.test(entry) && !entry.startsWith("."))
      .sort()
      .slice(0, MAX_LISTED_JOBS);

    const infos: JobInfo[] = [];
    for (const jobId of jobIds) {
      const jobDir = posix.join(base, jobId);
      const metaText = await readText(sftp, posix.join(jobDir, "meta.json"));
      const info: JobInfo = {
        jobId,
        state: metaText === undefined ? "corrupt" : "starting",
        jobDir,
        logPath: posix.join(jobDir, "output.log"),
      };
      if (metaText !== undefined) {
        const meta = parseMeta(metaText);
        if (meta.name !== undefined) info.name = meta.name;
        if (meta.command !== undefined) info.command = meta.command;
      }

      const exitCode = await readNumber(sftp, posix.join(jobDir, "exit_code"));
      const stoppedAt = await readNumber(sftp, posix.join(jobDir, "stopped_at"));
      const pid = await readNumber(sftp, posix.join(jobDir, "pid"));
      const startedAt = await readNumber(sftp, posix.join(jobDir, "started_at"));
      if (pid !== undefined) info.pid = pid;
      if (startedAt !== undefined) {
        info.startedAt = new Date(startedAt * 1_000).toISOString();
      }
      if (exitCode !== undefined) {
        info.state = metaText === undefined ? "corrupt" : "finished";
        info.exitCode = exitCode;
      } else if (stoppedAt !== undefined && metaText !== undefined) {
        info.state = "stopped";
        if (startedAt !== undefined) {
          info.elapsedMs = Math.max(0, (stoppedAt - startedAt) * 1_000);
        }
      }
      infos.push(info);
    }

    const pids = infos
      .map((info) => info.pid)
      .filter((pid): pid is number => pid !== undefined);
    if (pids.length > 0) {
      const probe = await this.probeProcesses(sshId, pids);
      for (const info of infos) {
        if (
          info.pid === undefined ||
          info.state === "finished" ||
          info.state === "stopped" ||
          info.state === "corrupt"
        ) {
          continue;
        }
        if (!probe.alive.has(info.pid)) {
          info.state = "lost";
          continue;
        }
        info.state = probe.matching.has(info.pid) ? "running" : "lost";
        const started = info.startedAt === undefined
          ? undefined
          : Date.parse(info.startedAt);
        if (started !== undefined && !Number.isNaN(started)) {
          info.elapsedMs = Math.max(0, probe.now - started);
        }
      }
    }

    return infos.sort((left, right) =>
      (right.startedAt ?? "").localeCompare(left.startedAt ?? ""),
    );
  }

  private async probeProcesses(
    sshId: string,
    pids: number[],
    expectedDir?: string,
  ): Promise<{ now: number; alive: Set<number>; matching: Set<number> }> {
    const alive = new Set<number>();
    const matching = new Set<number>();
    const lines: string[] = [];
    for (const pid of pids) {
      lines.push(
        `if kill -0 ${pid} 2>/dev/null; then echo "${pid}=alive"; else echo "${pid}=dead"; fi;`,
      );
      if (expectedDir !== undefined) {
        lines.push(
          `case "$(ps -p ${pid} -o args= 2>/dev/null)" in *${shellQuote(expectedDir)}*) echo "${pid}=match";; esac;`,
        );
      }
    }
    const result = await this.connections.exec({
      sshId,
      command: `now=$(date +%s); echo "now=$now"; ${lines.join(" ")}`,
      timeoutMs: 15_000,
      maxOutputBytes: 64 * 1_024,
    });

    let now = Date.now();
    for (const line of result.stdout.split(/\r?\n/)) {
      if (line.startsWith("now=")) {
        const parsed = Number(line.slice(4));
        if (Number.isFinite(parsed)) now = parsed * 1_000;
        continue;
      }
      const [pidText, marker] = line.split("=");
      const pid = Number(pidText);
      if (!Number.isFinite(pid)) continue;
      if (marker === "alive") alive.add(pid);
      if (marker === "match") {
        alive.add(pid);
        matching.add(pid);
      }
    }

    // Without an expected directory we cannot check the command line; treat
    // every live pid as matching.
    if (expectedDir === undefined) {
      for (const pid of alive) matching.add(pid);
    }
    return { now, alive, matching };
  }

  private async readLog(
    sshId: string,
    logPath: string,
    lines: number,
  ): Promise<string | undefined> {
    const count = clamp(lines, 1, MAX_LOG_LINES);
    const result = await this.connections.exec({
      sshId,
      command: `tail -n ${count} -- ${shellQuote(logPath)} 2>/dev/null`,
      timeoutMs: 15_000,
      maxOutputBytes: 256 * 1_024,
    });
    if (result.exitCode !== 0) return undefined;
    return result.stdout.replace(/\r?\n$/, "");
  }
}

export function buildJobScript(
  command: string,
  jobDir: string,
  cwd: string,
): string {
  return [
    "#!/bin/sh",
    "set +e",
    `echo $$ > ${shellQuote(posix.join(jobDir, "pid"))}`,
    `date +%s > ${shellQuote(posix.join(jobDir, "started_at"))}`,
    `cd ${shellQuote(cwd)} || { echo 1 > ${shellQuote(posix.join(jobDir, "exit_code"))}; exit 1; }`,
    "(",
    command,
    ")",
    `echo $? > ${shellQuote(posix.join(jobDir, "exit_code"))}`,
    "",
  ].join("\n");
}

export function buildLaunchCommand(jobDir: string): string {
  // The whole subshell is redirected, so no process keeps the SSH channel's
  // stdout/stderr open for the lifetime of the job. Using the absolute script
  // path also lets stop verify the pid through `ps -o args=`.
  const script = shellQuote(posix.join(jobDir, "job.sh"));
  const log = shellQuote(posix.join(jobDir, "output.log"));
  return [
    `(command -v setsid >/dev/null 2>&1 && exec setsid sh ${script} || exec sh ${script})`,
    ">",
    log,
    "2>&1",
    "<",
    "/dev/null",
    "&",
    "echo $!",
  ].join(" ");
}

export function buildStopCommand(pid: number, jobDir: string): string {
  const quotedDir = shellQuote(jobDir);
  return [
    `if ! kill -0 ${pid} 2>/dev/null; then echo not-running; exit 0; fi;`,
    `case "$(ps -p ${pid} -o args= 2>/dev/null)" in`,
    `*${quotedDir}*) ;;`,
    "*) echo mismatch; exit 3 ;;",
    "esac;",
    `kill -TERM -${pid} 2>/dev/null || kill -TERM ${pid} 2>/dev/null || true;`,
    "i=0;",
    `while kill -0 ${pid} 2>/dev/null && [ $i -lt 5 ]; do sleep 1; i=$((i+1)); done;`,
    `if kill -0 ${pid} 2>/dev/null; then kill -KILL -${pid} 2>/dev/null || kill -KILL ${pid} 2>/dev/null || true; echo killed; else echo stopped; fi;`,
  ].join(" ");
}

async function waitForPid(
  sftp: SftpLike,
  jobDir: string,
): Promise<number | undefined> {
  const deadline = Date.now() + LAUNCH_WAIT_MS;
  while (Date.now() < deadline) {
    const pid = await readNumber(sftp, posix.join(jobDir, "pid"));
    if (pid !== undefined) return pid;
    await delay(50);
  }
  return readNumber(sftp, posix.join(jobDir, "pid"));
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

async function writeText(
  sftp: SftpLike,
  target: string,
  content: string,
  mode: number,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    sftp.writeFile(target, Buffer.from(content, "utf8"), { mode }, (error) =>
      error ? reject(error) : resolve(),
    );
  });
  await new Promise<void>((resolve) => {
    sftp.chmod(target, mode, () => resolve());
  });
}

async function readText(
  sftp: SftpLike,
  target: string,
): Promise<string | undefined> {
  try {
    const data = await new Promise<Buffer>((resolve, reject) => {
      sftp.readFile(target, (error, value) =>
        error ? reject(error) : resolve(value),
      );
    });
    return data.toString("utf8");
  } catch {
    return undefined;
  }
}

async function readNumber(
  sftp: SftpLike,
  target: string,
): Promise<number | undefined> {
  const text = await readText(sftp, target);
  if (text === undefined) return undefined;
  const value = Number(text.trim());
  return Number.isFinite(value) ? value : undefined;
}

async function readdir(sftp: SftpLike, directory: string): Promise<string[]> {
  try {
    const entries = await new Promise<Array<{ filename: string }>>(
      (resolve, reject) => {
        sftp.readdir(directory, (error, list) =>
          error ? reject(error) : resolve(list),
        );
      },
    );
    return entries.map((entry) => entry.filename);
  } catch {
    return [];
  }
}

function parseMeta(text: string): { name?: string; command?: string } {
  try {
    const value = JSON.parse(text) as Record<string, unknown>;
    return {
      ...(typeof value.name === "string" ? { name: value.name } : {}),
      ...(typeof value.command === "string" ? { command: value.command } : {}),
    };
  } catch {
    return {};
  }
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, Math.trunc(value)));
}
