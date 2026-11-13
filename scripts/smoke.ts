import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import ssh2 from "ssh2";
import { Error as ToolError } from "@opencode/plugin/promise/tool";
import { resolveConfig } from "../src/config.js";
import { SecretBox } from "../src/crypto.js";
import { KnownHostsStore } from "../src/known-hosts.js";
import { ProfileStore, type ProfileStorage } from "../src/profiles.js";
import { createRpcHandlers } from "../src/rpc-handlers.js";
import { buildRemoteCommand } from "../src/ssh/command.js";
import {
  editRemoteFile,
  readRemoteFile,
  removeRemotePath,
  resolveRemotePath,
  transferPath,
  writeRemoteFile,
} from "../src/ssh/files.js";
import {
  JobService,
  buildJobScript,
  buildLaunchCommand,
  type JobConnections,
  type JobInfo,
} from "../src/ssh/jobs.js";
import { SshOperationError } from "../src/ssh/errors.js";
import { ConnectionManager, type ExecResult } from "../src/ssh/manager.js";
import { globToRegExp, SearchService } from "../src/ssh/search.js";
import { createSshTools, type ToolDefinition } from "../src/tools/definitions.js";
import { OutputCollector } from "../src/util.js";
import { createFakeSftp } from "./fake-sftp.js";

const dataDir = mkdtempSync(path.join(tmpdir(), "opencode-ssh-smoke-"));
process.env.OPENCODE_SSH_HOME = dataDir;

class MemoryStorage implements ProfileStorage {
  private readonly values = new Map<string, unknown>();

  async get(key: string): Promise<unknown> {
    return this.values.get(key);
  }

  async set(key: string, value: any): Promise<void> {
    this.values.set(key, structuredClone(value));
  }

  async remove(key: string): Promise<void> {
    this.values.delete(key);
  }
}

async function main() {
  const box = new SecretBox(dataDir);
  const sealed = box.seal("hunter2\nwith-newline", "field/a");
  assert.equal(box.open(sealed, "field/a"), "hunter2\nwith-newline");
  assert.throws(() => box.open(sealed, "field/b"), /Unable to decrypt/);

  const storage = new MemoryStorage();
  const profiles = new ProfileStore(storage, box);
  await profiles.ensureInitialized();
  assert.deepEqual(await storage.get("profiles"), {
    version: 1,
    profiles: [],
  });
  const added = await profiles.add({
    name: "smoke",
    user: "root",
    host: "127.0.0.1",
    port: 2222,
    password: "ssh-password",
    sudoPassword: "sudo-password",
    hostKeyPolicy: "strict",
  });
  assert.match(added.id, /^prof_[0-9a-f]{12}$/);
  assert.equal(added.auth, "password");
  assert.equal(added.hasSudoPassword, true);
  assert.equal(added.revision, 1);

  const stored = await storage.get("profiles");
  assert.ok(stored !== undefined, "profiles document should be stored");
  const storedText = JSON.stringify(stored);
  assert.ok(!storedText.includes("ssh-password"), "password must not be stored in plaintext");
  assert.ok(!storedText.includes("sudo-password"), "sudo password must not be stored in plaintext");
  assert.ok(storedText.includes("iv"), "sealed envelope should be present");

  const resolved = await profiles.resolve(added.id);
  assert.equal(resolved.password, "ssh-password");
  assert.equal(resolved.sudoPassword, "sudo-password");
  assert.equal(resolved.revision, 1);

  const listed = await profiles.list();
  assert.equal(listed.length, 1);
  assert.equal(listed[0]?.hasPassword, true);
  assert.equal("password" in (listed[0] ?? {}), false);

  // A new ProfileStore over the same storage simulates a service restart.
  const reloaded = new ProfileStore(storage, box);
  assert.equal((await reloaded.list()).length, 1);
  assert.equal((await reloaded.resolve(added.id)).password, "ssh-password");

  const renamed = await profiles.update(added.id, { name: "smoke-renamed" });
  assert.equal(renamed.revision, 1);
  assert.ok(renamed.updatedAt >= added.updatedAt);

  const updated = await profiles.update(added.id, {
    name: "smoke-2",
    privateKeyPath: "~/.ssh/id_ed25519",
    clearSudoPassword: true,
  });
  assert.equal(updated.name, "smoke-2");
  assert.equal(updated.auth, "privateKey");
  assert.equal(updated.hasSudoPassword, false);
  assert.equal(updated.revision, 2);
  const updatedResolved = await profiles.resolve(added.id);
  assert.equal(updatedResolved.password, undefined);
  assert.equal(updatedResolved.privateKeyPath, "~/.ssh/id_ed25519");

  assert.equal(await profiles.remove(added.id), true);
  assert.equal(await profiles.remove(added.id), false);
  assert.deepEqual(await profiles.list(), []);

  // Two stores over the same storage must not lose concurrent writes.
  const concurrentA = new ProfileStore(storage, box);
  const concurrentB = new ProfileStore(storage, box);
  const [concurrentOne, concurrentTwo] = await Promise.all([
    concurrentA.add({
      name: "concurrent-one",
      user: "demo",
      host: "one.example",
      password: "one",
    }),
    concurrentB.add({
      name: "concurrent-two",
      user: "demo",
      host: "two.example",
      password: "two",
    }),
  ]);
  assert.equal(
    (await profiles.list()).filter((profile) =>
      profile.name.startsWith("concurrent-"),
    ).length,
    2,
  );
  await profiles.remove(concurrentOne.id);
  await profiles.remove(concurrentTwo.id);
  assert.deepEqual(await profiles.list(), []);

  const sanitized = new OutputCollector(1024);
  sanitized.append(Buffer.from("\u001b[31mred\u001b[0m \u001b]0;title\u0007ok\n"));
  sanitized.append("\rprogress 10%\rprogress 50%\rprogress 100%\n");
  sanitized.append("abc\b\bX");
  sanitized.end();
  assert.equal(sanitized.text(), "red ok\nprogress 100%\naX");
  assert.equal(sanitized.truncated, false);

  const bounded = new OutputCollector(1024);
  for (let index = 0; index < 200; index += 1) {
    bounded.append(`line ${index.toString().padStart(4, "0")}\n`);
  }
  bounded.end();
  assert.equal(bounded.truncated, true);
  assert.ok(bounded.rawBytes > bounded.bytes);
  assert.match(bounded.text(), /^line 0000/);
  assert.match(bounded.text(), /line 0199/);
  assert.match(bounded.text(), /bytes omitted/);
  assert.match(bounded.tailText(128), /line 0199/);

  const quoted = buildRemoteCommand({
    command: "echo 'hello world' && whoami",
    cwd: "/tmp/a b",
    env: { GREETING: "hi there" },
    sudo: true,
    asUser: "postgres",
    loginUser: "deploy",
  });
  assert.equal(quoted.usesSudo, true);
  assert.match(quoted.command, /^sudo -S -p '' -u 'postgres' -H -- sh -c /);
  assert.ok(quoted.command.includes("'\\''hello world'\\''"));

  const guarded = buildRemoteCommand({
    command: "git log",
    loginUser: "deploy",
    nonInteractive: true,
  });
  assert.match(guarded.command, /export PAGER='cat'/);
  assert.match(guarded.command, /export GIT_PAGER='cat'/);
  assert.match(guarded.command, /export SYSTEMD_PAGER='cat'/);
  assert.match(guarded.command, /export NO_COLOR='1'/);
  assert.match(guarded.command, /export TERM='dumb'/);

  const overriddenGuard = buildRemoteCommand({
    command: "git log",
    loginUser: "deploy",
    nonInteractive: true,
    env: { PAGER: "less" },
  });
  assert.match(overriddenGuard.command, /export PAGER='less'/);
  assert.doesNotMatch(overriddenGuard.command, /export PAGER='cat'/);

  const sudoGuarded = buildRemoteCommand({
    command: "systemctl status nginx",
    loginUser: "deploy",
    sudo: true,
    nonInteractive: true,
  });
  assert.match(sudoGuarded.command, /^sudo -S -p '' -- sh -c /);
  assert.match(sudoGuarded.command, /export PAGER=/);
  assert.match(sudoGuarded.command, /export TERM=/);

  const homeDirectory = buildRemoteCommand({
    command: "pwd",
    cwd: "~/work dir",
    loginUser: "deploy",
  });
  assert.equal(homeDirectory.command, `cd -- "$HOME"/'work dir' && (pwd)`);

  const root = buildRemoteCommand({
    command: "id",
    sudo: true,
    loginUser: "root",
  });
  assert.equal(root.command, "id");
  assert.equal(root.usesSudo, false);

  const knownHosts = new KnownHostsStore(path.join(dataDir, "known_hosts.json"));
  const fingerprintA = "ab".repeat(32);
  const fingerprintB = "cd".repeat(32);
  assert.equal(knownHosts.verify("Example.COM", 22, fingerprintA, "accept-new"), true);
  assert.equal(knownHosts.verify("example.com", 22, fingerprintA, "strict"), true);
  assert.equal(knownHosts.verify("other.example.com", 22, fingerprintB, "strict"), false);
  assert.match(knownHosts.takeError() ?? "", /Unknown SSH host key/);
  assert.equal(knownHosts.verify("example.com", 22, fingerprintB, "accept-new"), false);
  assert.match(knownHosts.takeError() ?? "", /HOST KEY MISMATCH/);
  assert.equal(knownHosts.verify("example.com", 22, fingerprintB, "insecure"), true);

  const relativeConfig = resolveConfig({ dataDir: "./relative-data" }, dataDir);
  assert.equal(
    relativeConfig.dataDir,
    path.resolve(dataDir, "relative-data"),
  );

  const fileRoot = mkdtempSync(path.join(tmpdir(), "opencode-ssh-files-"));
  try {
    const sftp = createFakeSftp(fileRoot);

    assert.equal(
      resolveRemotePath("~/notes/a.txt", "/home/tester"),
      "/home/tester/notes/a.txt",
    );
    assert.equal(resolveRemotePath("/var//tmp/x", "/home/tester"), "/var/tmp/x");
    assert.throws(
      () => resolveRemotePath("relative/x", "/home/tester"),
      /absolute/,
    );

    assert.equal(globToRegExp("**/*.ts").test("src/a.ts"), true);
    assert.equal(globToRegExp("**/*.ts").test("a.ts"), true);
    assert.equal(globToRegExp("src/**/*.{js,jsx}").test("src/x/y.js"), true);
    assert.equal(globToRegExp("src/**/*.{js,jsx}").test("src/x/y.ts"), false);
    assert.equal(globToRegExp("*.md").test("docs/a.md"), false);

    const zeroGlob = fakeSearchManager([
      fakeExecResult("rg=1\ngrep=1\nfind=1\n"),
      fakeExecResult(""),
    ]);
    const zeroGlobSignal = new AbortController().signal;
    const zeroGlobResult = await new SearchService(
      zeroGlob.manager,
    ).glob(
      "ssh_test",
      { pattern: "**/*.ts", path: "/work" },
      zeroGlobSignal,
    );
    assert.equal(zeroGlobResult.engine, "rg");
    assert.deepEqual(zeroGlobResult.paths, []);
    assert.equal(zeroGlob.calls.length, 2);
    assert.equal(zeroGlob.signals[1], zeroGlobSignal);

    const findGlob = fakeSearchManager([
      fakeExecResult("rg=0\ngrep=1\nfind=1\n"),
      fakeExecResult("/work/a.ts\u0000/work/sub/b.ts\u0000"),
    ]);
    const findGlobResult = await new SearchService(
      findGlob.manager,
    ).glob("ssh_test", { pattern: "**/*.ts", path: "/work" });
    assert.equal(findGlobResult.engine, "find");
    assert.deepEqual(findGlobResult.paths, [
      "/work/a.ts",
      "/work/sub/b.ts",
    ]);
    assert.match(findGlob.calls[1] ?? "", /-prune/);
    assert.equal(findGlob.calls.length, 2);

    const failedGlob = fakeSearchManager([
      fakeExecResult("rg=1\ngrep=1\nfind=1\n"),
      fakeExecResult("", 2),
    ]);
    await assert.rejects(
      new SearchService(failedGlob.manager).glob("ssh_test", {
        pattern: "**/*.ts",
        path: "/work",
      }),
      /rg failed/,
    );
    assert.equal(failedGlob.calls.length, 2);

    const zeroGrep = fakeSearchManager([
      fakeExecResult("rg=1\ngrep=1\nfind=1\n"),
      fakeExecResult("", 1),
    ]);
    const zeroGrepResult = await new SearchService(
      zeroGrep.manager,
    ).grep("ssh_test", { pattern: "needle", path: "/work" });
    assert.equal(zeroGrepResult.engine, "rg");
    assert.deepEqual(zeroGrepResult.matches, []);
    assert.match(zeroGrep.calls[1] ?? "", /\.git/);
    assert.match(zeroGrep.calls[1] ?? "", /node_modules/);
    assert.doesNotMatch(zeroGrep.calls[1] ?? "", /--hidden/);
    assert.equal(zeroGrep.calls.length, 2);

    const hiddenGrep = fakeSearchManager([
      fakeExecResult("rg=1\ngrep=1\nfind=1\n"),
      fakeExecResult("", 1),
    ]);
    const hiddenGrepResult = await new SearchService(
      hiddenGrep.manager,
    ).grep("ssh_test", {
      pattern: "needle",
      path: "/work",
      includeHidden: true,
    });
    assert.equal(hiddenGrepResult.engine, "rg");
    assert.match(hiddenGrep.calls[1] ?? "", /--hidden/);

    const truncatedGrep = fakeSearchManager([
      fakeExecResult("rg=1\ngrep=1\nfind=1\n"),
      fakeExecResult(
        `${JSON.stringify({
          type: "match",
          data: {
            path: { text: "/work/a.ts" },
            lines: { text: "needle\n" },
            line_number: 1,
          },
        })}\n`,
        0,
        true,
      ),
    ]);
    const truncatedGrepResult = await new SearchService(
      truncatedGrep.manager,
    ).grep("ssh_test", { pattern: "needle", path: "/work" });
    assert.equal(truncatedGrepResult.matches.length, 1);
    assert.equal(truncatedGrepResult.truncated, true);

    const failedFind = fakeSearchManager([
      fakeExecResult("rg=0\ngrep=1\nfind=1\n"),
      fakeExecResult("", 1),
    ]);
    await assert.rejects(
      new SearchService(failedFind.manager).glob("ssh_test", {
        pattern: "**/*.ts",
        path: "/work",
      }),
      /find failed/,
    );

    const created = await writeRemoteFile(
      sftp,
      "/project/hello.txt",
      "one\ntwo\nthree\n",
    );
    assert.equal(created.created, true);
    assert.equal(created.bytes, 14);

    const listed = readdirNames(path.join(fileRoot, "project"));
    assert.deepEqual(listed, ["hello.txt"]);

    const read = await readRemoteFile(sftp, "/project/hello.txt");
    assert.deepEqual(
      read.lines.map((line) => line.text),
      ["one", "two", "three"],
    );
    assert.equal(read.totalLines, 3);
    assert.equal(read.lineEndings, "lf");
    assert.equal(
      read.sha256,
      createHash("sha256").update("one\ntwo\nthree\n").digest("hex"),
    );
    const ranged = await readRemoteFile(sftp, "/project/hello.txt", {
      offset: 2,
      limit: 5,
    });
    assert.deepEqual(
      ranged.lines.map((line) => line.number),
      [2, 3],
    );

    await assert.rejects(
      writeRemoteFile(sftp, "/project/hello.txt", "replaced"),
      /already exists/,
    );
    const replaced = await writeRemoteFile(
      sftp,
      "/project/hello.txt",
      "one\ntwo\nthree four\n",
      { overwrite: true },
    );
    assert.equal(replaced.created, false);

    symlinkSync(
      path.join(fileRoot, "project", "hello.txt"),
      path.join(fileRoot, "project", "link.txt"),
    );
    await assert.rejects(
      writeRemoteFile(sftp, "/project/link.txt", "replaced", {
        overwrite: true,
      }),
      /symbolic link/,
    );
    await assert.rejects(
      editRemoteFile(sftp, "/project/link.txt", "one", "ONE"),
      /symbolic link/,
    );

    await assert.rejects(
      editRemoteFile(sftp, "/project/hello.txt", "t", "T"),
      /Found 2 matches/,
    );
    const edited = await editRemoteFile(
      sftp,
      "/project/hello.txt",
      "t",
      "T",
      { replaceAll: true },
    );
    assert.equal(edited.replacements, 2);
    const afterEdit = await readRemoteFile(sftp, "/project/hello.txt");
    assert.deepEqual(
      afterEdit.lines.map((line) => line.text),
      ["one", "Two", "Three four"],
    );

    const hashBefore = createHash("sha256")
      .update(readFileSync(path.join(fileRoot, "project", "hello.txt")))
      .digest("hex");
    const hashedEdit = await editRemoteFile(
      sftp,
      "/project/hello.txt",
      "one",
      "ONE",
      { expectedSha256: hashBefore },
    );
    assert.equal(hashedEdit.sha256Before, hashBefore);
    assert.notEqual(hashedEdit.sha256After, hashBefore);
    assert.equal(hashedEdit.lineEndings, "lf");
    await assert.rejects(
      editRemoteFile(sftp, "/project/hello.txt", "ONE", "one", {
        expectedSha256: "0".repeat(64),
      }),
      /SHA-256 mismatch/,
    );

    writeFileSync(
      path.join(fileRoot, "project", "crlf.txt"),
      "one\r\ntwo\r\n",
    );
    assert.equal(
      (await readRemoteFile(sftp, "/project/crlf.txt")).lineEndings,
      "crlf",
    );
    await assert.rejects(
      editRemoteFile(sftp, "/project/crlf.txt", "one\ntwo", "x"),
      /CRLF/,
    );
    const crlfWrite = await writeRemoteFile(
      sftp,
      "/project/crlf-write.txt",
      "a\r\nb\r\n",
    );
    assert.equal(crlfWrite.lineEndings, "crlf");

    const binaryPath = "/project/data.bin";
    writeFileSync(path.join(fileRoot, "project", "data.bin"), Buffer.from([1, 0, 2]));
    const binary = await readRemoteFile(sftp, binaryPath);
    assert.equal(binary.binary, true);
    assert.equal(binary.lineEndings, "none");
    assert.equal(binary.lines.length, 0);
    assert.match(
      await captureError(() => editRemoteFile(sftp, binaryPath, "a", "b")),
      /binary/,
    );

    writeFileSync(path.join(fileRoot, "big.txt"), `${"a\n".repeat(5000)}`);
    const truncated = await readRemoteFile(sftp, "/big.txt", { maxBytes: 1024 });
    assert.equal(truncated.truncated, true);
    assert.equal(truncated.totalLines, null);
    assert.equal(truncated.sha256, null);

    const tail = await readRemoteFile(sftp, "/big.txt", {
      byteOffset: 9000,
      maxBytes: 1024,
    });
    assert.equal(tail.byteStart, 9000);
    assert.equal(tail.byteEnd, 10000);
    assert.equal(tail.lineNumbers, false);
    assert.equal(tail.truncated, false);
    assert.equal(tail.sha256, null);
    assert.equal(tail.lines.length, 500);
    assert.ok(tail.lines.every((line) => line.text === "a"));

    const partialTail = await readRemoteFile(sftp, "/big.txt", {
      byteOffset: 8000,
      maxBytes: 1024,
    });
    assert.equal(partialTail.byteStart, 8000);
    assert.equal(partialTail.byteEnd, 9024);
    assert.equal(partialTail.truncated, true);
    assert.equal(partialTail.lines.length, 512);

    await assert.rejects(
      readRemoteFile(sftp, "/big.txt", { offset: 1000, maxBytes: 1024 }),
      /beyond the captured prefix/,
    );
    await assert.rejects(
      readRemoteFile(sftp, "/big.txt", {
        offset: 1,
        byteOffset: 0,
      }),
      /either byte_offset or offset/,
    );

    const nested = await writeRemoteFile(
      sftp,
      "/tree/a/b/c.txt",
      "deep\n",
    );
    assert.equal(nested.created, true);
    const dryRun = await removeRemotePath(sftp, "/tree", {
      recursive: true,
      dryRun: true,
    });
    assert.equal(dryRun.dryRun, true);
    assert.equal(dryRun.removed, 0);
    assert.ok(dryRun.entries.includes("/tree/a/b/c.txt"));
    assert.equal(existsLocally(path.join(fileRoot, "tree", "a", "b", "c.txt")), true);

    await assert.rejects(
      removeRemotePath(sftp, "/tree"),
      /recursive: true/,
    );
    const removed = await removeRemotePath(sftp, "/tree", { recursive: true });
    assert.equal(removed.removed, 4);
    assert.equal(existsLocally(path.join(fileRoot, "tree")), false);

    const localSource = path.join(fileRoot, "local-src");
    mkdirSync(localSource, { recursive: true });
    writeFileSync(path.join(localSource, "one.txt"), "upload-one\n");
    writeFileSync(path.join(localSource, "two.txt"), "upload-two\n");

    const uploadProgress: Array<{
      direction: string;
      files: number;
      bytes: number;
    }> = [];
    const upload = await transferPath(sftp, {
      direction: "upload",
      localPath: localSource,
      remotePath: "/backup/src",
      onProgress: (update) => uploadProgress.push(update),
    });
    assert.equal(upload.files, 2);
    assert.ok(uploadProgress.length > 0);
    assert.equal(uploadProgress.at(-1)?.direction, "upload");
    assert.ok((uploadProgress.at(-1)?.bytes ?? 0) > 0);
    assert.equal(readFileSync(path.join(fileRoot, "backup", "src", "one.txt"), "utf8"), "upload-one\n");

    await assert.rejects(
      transferPath(sftp, {
        direction: "upload",
        localPath: localSource,
        remotePath: "/backup/src",
      }),
      /already exists/,
    );

    const singleUpload = path.join(fileRoot, "single-upload.txt");
    writeFileSync(singleUpload, "single\n");
    symlinkSync(
      path.join(fileRoot, "backup", "src", "one.txt"),
      path.join(fileRoot, "backup", "symlink-upload.txt"),
    );
    await assert.rejects(
      transferPath(sftp, {
        direction: "upload",
        localPath: singleUpload,
        remotePath: "/backup/symlink-upload.txt",
        overwrite: true,
      }),
      /symbolic link/,
    );

    const localTarget = path.join(fileRoot, "local-dst");
    const downloadProgress: Array<{
      direction: string;
      files: number;
      bytes: number;
    }> = [];
    const download = await transferPath(sftp, {
      direction: "download",
      localPath: localTarget,
      remotePath: "/backup/src",
      overwrite: true,
      onProgress: (update) => downloadProgress.push(update),
    });
    assert.equal(download.files, 2);
    assert.ok(downloadProgress.length > 0);
    assert.equal(downloadProgress.at(-1)?.direction, "download");
    assert.ok((downloadProgress.at(-1)?.bytes ?? 0) > 0);
    assert.equal(readFileSync(path.join(localTarget, "two.txt"), "utf8"), "upload-two\n");

    const abortSource = path.join(fileRoot, "abort-upload.txt");
    writeFileSync(abortSource, "abort\n");
    const abortedController = new AbortController();
    abortedController.abort();
    await assert.rejects(
      transferPath(sftp, {
        direction: "upload",
        localPath: abortSource,
        remotePath: "/backup/aborted-upload.txt",
        signal: abortedController.signal,
      }),
      /abort/i,
    );
    assert.equal(
      existsLocally(path.join(fileRoot, "backup", "aborted-upload.txt")),
      false,
    );
    assert.ok(
      !readdirNames(path.join(fileRoot, "backup")).some((name) =>
        name.endsWith(".tmp"),
      ),
    );

    await assert.rejects(
      transferPath(sftp, {
        direction: "download",
        localPath: path.join(fileRoot, "aborted-download.txt"),
        remotePath: "/backup/src/one.txt",
        signal: abortedController.signal,
      }),
      /abort/i,
    );
    assert.equal(
      existsLocally(path.join(fileRoot, "aborted-download.txt")),
      false,
    );
    assert.ok(
      !readdirNames(fileRoot).some((name) => name.endsWith(".tmp")),
    );
  } finally {
    rmSync(fileRoot, { recursive: true, force: true });
  }

  const jobRoot = mkdtempSync(path.join(tmpdir(), "opencode-ssh-jobs-"));
  try {
    const harness = new FakeJobConnections(jobRoot);
    const jobs = new JobService(harness);

    const script = buildJobScript(
      "echo hi",
      "/home/tester/.opencode-ssh/jobs/job_ab12cd34",
      "/tmp",
    );
    assert.ok(script.includes("echo $$ >"));
    assert.ok(script.includes("echo $? >"));
    assert.ok(script.includes("date +%s >"));
    const launch = buildLaunchCommand("/home/tester/.opencode-ssh/jobs/job_ab12cd34");
    assert.ok(launch.includes("setsid"));
    assert.ok(launch.includes("echo $!"));

    const started = await jobs.start({
      sshId: "ssh_test",
      command: "sleep 100",
      name: "train",
    });
    assert.match(started.jobId, /^job_[0-9a-f]{12}$/);
    assert.equal(started.pid, 4242);
    assert.equal(started.logPath, `${started.jobDir}/output.log`);

    const running = await jobs.status("ssh_test", started.jobId, 2);
    assert.equal(Array.isArray(running), false);
    const runningInfo = running as JobInfo;
    assert.equal(runningInfo.state, "running");
    assert.equal(runningInfo.name, "train");
    assert.match(runningInfo.log ?? "", /log-1/);

    const listed = await jobs.status("ssh_test", undefined, 0);
    assert.equal(Array.isArray(listed), true);
    assert.equal((listed as JobInfo[]).length, 1);
    assert.equal((listed as JobInfo[])[0]?.state, "running");

    harness.writeExit(started.jobDir, 0);
    const finished = (await jobs.status("ssh_test", started.jobId, 0)) as JobInfo;
    assert.equal(finished.state, "finished");
    assert.equal(finished.exitCode, 0);

    const stopFinished = await jobs.stop("ssh_test", started.jobId);
    assert.equal(stopFinished.outcome, "already-finished");

    harness.clearExit(started.jobDir);
    harness.alive = false;
    const lost = (await jobs.status("ssh_test", started.jobId, 0)) as JobInfo;
    assert.equal(lost.state, "lost");
    const stopLost = await jobs.stop("ssh_test", started.jobId);
    assert.equal(stopLost.outcome, "not-running");

    harness.alive = true;
    harness.stopAnswer = "mismatch";
    const mismatch = await jobs.stop("ssh_test", started.jobId);
    assert.equal(mismatch.outcome, "mismatch");

    harness.stopAnswer = "stopped";
    const stopped = await jobs.stop("ssh_test", started.jobId);
    assert.equal(stopped.outcome, "stopped");
    const stoppedInfo = (await jobs.status("ssh_test", started.jobId, 0)) as JobInfo;
    assert.equal(stoppedInfo.state, "stopped");

    await assert.rejects(
      jobs.status("ssh_test", "job_zzzz", 0),
      /Invalid job_id/,
    );
  } finally {
    rmSync(jobRoot, { recursive: true, force: true });
  }

  const config = resolveConfig(
    { dataDir, connectTimeoutMs: 3000, execTimeoutMs: 5000 },
    dataDir,
  );
  const manager = new ConnectionManager(config, profiles, knownHosts);
  const connections = manager.list();
  assert.deepEqual(connections, []);
  await assert.rejects(
    manager.connect({ user: "nobody", host: "127.0.0.1", port: 1, password: "x" }),
    /ECONNREFUSED|connect|closed|timed out/i,
  );

  const server = await startTestSshServer();
  let strictManager: ConnectionManager | undefined;
  try {
    const connection = await manager.connect({
      user: "tester",
      host: "127.0.0.1",
      port: server.port,
      password: "secret",
      sudoPassword: "sudo-secret",
      hostKeyPolicy: "accept-new",
    });
    assert.match(connection.id, /^ssh_[0-9a-f]{12}$/);
    assert.match(connection.hostKeyFingerprint ?? "", /^SHA256:/);
    assert.equal(manager.list().length, 1);

    const plain = await manager.exec({
      sshId: connection.id,
      command: "echo hello",
    });
    assert.equal(plain.exitCode, 0);
    assert.equal(plain.stdout, "command=echo hello\n");
    assert.equal(plain.stderr, "stderr=echo hello\n");

    const wrapped = await manager.exec({
      sshId: connection.id,
      command: "whoami",
      cwd: "/tmp/x y",
      env: { GREETING: "hi there" },
    });
    assert.equal(
      wrapped.stdout,
      "command=cd -- '/tmp/x y' && (export GREETING='hi there'; whoami)\n",
    );

    const streamed = await manager.exec({
      sshId: connection.id,
      command: "__stream__",
      maxOutputBytes: 1024,
    });
    assert.equal(streamed.stdoutTruncated, true);
    assert.equal(streamed.stderrTruncated, true);
    assert.match(streamed.stdout, /^head-red\n/);
    assert.match(streamed.stdout, /line-0199/);
    assert.match(streamed.stderr, /err-0199/);
    assert.match(streamed.stdout, /bytes omitted/);
    assert.match(streamed.stdout, /progress 100%/);
    assert.doesNotMatch(streamed.stdout, /\u001b/);
    assert.doesNotMatch(streamed.stderr, /\u001b/);
    assert.ok((streamed.stdoutBytes ?? 0) > 1024);
    assert.ok((streamed.stderrBytes ?? 0) > 1024);

    const ttyEof = await manager.exec({
      sshId: connection.id,
      command: "__stdin__",
      tty: true,
      timeoutMs: 2_000,
    });
    assert.equal(ttyEof.exitCode, 0);
    assert.match(ttyEof.stdout, /stdin-eof:/);

    const abortController = new AbortController();
    const abortedPromise = manager.exec(
      { sshId: connection.id, command: "__hang__" },
      abortController.signal,
    );
    setTimeout(() => abortController.abort(), 100);
    const aborted = await abortedPromise.catch((error: unknown) => error);
    if (!(aborted instanceof SshOperationError)) {
      throw new Error("expected SSH_COMMAND_ABORTED");
    }
    assert.equal(aborted.code, "SSH_COMMAND_ABORTED");
    assert.equal(aborted.executionMayHaveStarted, true);

    const sudo = await manager.exec({
      sshId: connection.id,
      command: "id",
      sudo: true,
    });
    assert.match(
      sudo.stdout,
      /^command=sudo -S -p '' -- sh -c 'id'\n$/,
    );

    const noExit = await manager
      .exec({ sshId: connection.id, command: "__no-exit__" })
      .catch((error: unknown) => error);
    if (!(noExit instanceof SshOperationError)) {
      throw new Error("expected SSH_CHANNEL_NO_EXIT");
    }
    assert.match(noExit.message, /without an exit status/);
    assert.equal(noExit.code, "SSH_CHANNEL_NO_EXIT");
    assert.equal(noExit.executionMayHaveStarted, true);

    const progressUpdates: Array<{
      elapsedMs: number;
      stdoutTail: string;
      stderrTail: string;
    }> = [];
    const timedOut = await manager
      .exec({
        sshId: connection.id,
        command: "__hang__",
        timeoutMs: 1_200,
        onProgress: (update) => progressUpdates.push(update),
      })
      .catch((error: unknown) => error);
    if (!(timedOut instanceof SshOperationError)) {
      throw new Error("expected SSH_COMMAND_TIMEOUT");
    }
    assert.equal(timedOut.code, "SSH_COMMAND_TIMEOUT");
    assert.equal(timedOut.executionMayHaveStarted, true);
    assert.ok(progressUpdates.length > 0);
    assert.match(progressUpdates[0]?.stdoutTail ?? "", /started/);

    const dropManager = new ConnectionManager(config, profiles, knownHosts);
    try {
      const dropConnection = await dropManager.connect({
        user: "tester",
        host: "127.0.0.1",
        port: server.port,
        password: "secret",
        sudoPassword: "sudo-secret",
      });
      const pending = dropManager.exec({
        sshId: dropConnection.id,
        command: "__hang__",
      });
      // Attach a handler immediately so the rejection is never unhandled.
      pending.catch(() => undefined);
      await new Promise((resolve) => setTimeout(resolve, 150));
      await dropManager.disconnect(dropConnection.id);
      const lost = await pending.catch((error: unknown) => error);
      if (!(lost instanceof SshOperationError)) {
        throw new Error("expected SSH_CONNECTION_LOST");
      }
      assert.match(
        lost.message,
        /was lost while the command was running|without an exit status/,
      );
      assert.equal(lost.code, "SSH_CONNECTION_LOST");
      assert.equal(lost.executionMayHaveStarted, true);
    } finally {
      await dropManager.dispose();
    }

    const reuseManager = new ConnectionManager(config, profiles, knownHosts);
    try {
      const reuseFirst = await reuseManager.connect({
        user: "tester",
        host: "127.0.0.1",
        port: server.port,
        password: "secret",
        sudoPassword: "sudo-secret",
      });
      const reuseSecond = await reuseManager.connect({
        user: "tester",
        host: "127.0.0.1",
        port: server.port,
        password: "secret",
        sudoPassword: "sudo-secret",
      });
      assert.equal(reuseSecond.id, reuseFirst.id);
      assert.equal(reuseSecond.reused, true);

      const differentSudo = await reuseManager.connect({
        user: "tester",
        host: "127.0.0.1",
        port: server.port,
        password: "secret",
        sudoPassword: "other-sudo",
      });
      assert.notEqual(differentSudo.id, reuseFirst.id);

      await assert.rejects(
        reuseManager.connect({
          user: "tester",
          host: "127.0.0.1",
          port: server.port,
          password: "wrong-password",
          sudoPassword: "sudo-secret",
        }),
        /authentication|All configured|failed/i,
      );

      const stricterPolicy = await reuseManager.connect({
        user: "tester",
        host: "127.0.0.1",
        port: server.port,
        password: "secret",
        sudoPassword: "sudo-secret",
        hostKeyPolicy: "strict",
      });
      assert.notEqual(stricterPolicy.id, reuseFirst.id);

      const forced = await reuseManager.connect({
        user: "tester",
        host: "127.0.0.1",
        port: server.port,
        password: "secret",
        sudoPassword: "sudo-secret",
        forceNew: true,
      });
      assert.notEqual(forced.id, reuseFirst.id);

      const reuseProfile = await profiles.add({
        name: "reuse-profile",
        user: "tester",
        host: "127.0.0.1",
        port: server.port,
        password: "secret",
        sudoPassword: "sudo-secret",
      });
      try {
        const profileFirst = await reuseManager.connect({
          profileId: reuseProfile.id,
        });
        const profileSecond = await reuseManager.connect({
          profileId: reuseProfile.id,
        });
        assert.equal(profileSecond.id, profileFirst.id);
        assert.equal(profileSecond.reused, true);
      } finally {
        await profiles.remove(reuseProfile.id);
      }
    } finally {
      await reuseManager.dispose();
    }

    const rpcManager = new ConnectionManager(config, profiles, knownHosts);
    const testProfile = await profiles.add({
      name: "rpc-reuse-profile",
      user: "tester",
      host: "127.0.0.1",
      port: server.port,
      password: "secret",
    });
    try {
      const active = await rpcManager.connect({ profileId: testProfile.id });
      const handlers = createRpcHandlers({
        manager: rpcManager,
        profiles,
      });

      const update = await handlers.profilesTestAndUpdate({
        profileId: testProfile.id,
        patch: { password: "wrong-password" },
      });
      assert.equal(update.ok, false);
      assert.ok(rpcManager.list().some((item) => item.id === active.id));
      assert.equal(
        (await profiles.resolve(testProfile.id)).password,
        "secret",
      );

      const renamed = await handlers.profilesUpdate({
        profileId: testProfile.id,
        patch: { name: "rpc-reuse-renamed" },
      });
      assert.equal(renamed.ok, true);
      if (renamed.ok) assert.equal(renamed.data.revision, 1);
      assert.notEqual(rpcManager.getInfo(active.id).stale, true);

      const successful = await handlers.profilesTestAndUpdate({
        profileId: testProfile.id,
        patch: { password: "secret" },
      });
      assert.equal(successful.ok, true);
      if (successful.ok) assert.equal(successful.data.revision, 2);
      assert.equal(rpcManager.getInfo(active.id).stale, true);

      const replacement = await rpcManager.connect({
        profileId: testProfile.id,
      });
      assert.notEqual(replacement.id, active.id);
      assert.equal(replacement.profileRevision, 2);
      assert.notEqual(replacement.stale, true);
      await rpcManager.disconnect(replacement.id);

      const added = await handlers.profilesTestAndAdd({
        name: "rpc-reuse-add",
        user: "tester",
        host: "127.0.0.1",
        port: server.port,
        password: "wrong-password",
      });
      assert.equal(added.ok, false);
      assert.ok(rpcManager.list().some((item) => item.id === active.id));

      const tested = await handlers.connectionsTest({
        user: "tester",
        host: "127.0.0.1",
        port: server.port,
        password: "wrong-password",
      });
      assert.equal(tested.ok, false);
      assert.ok(rpcManager.list().some((item) => item.id === active.id));

      const alive = await rpcManager.exec({
        sshId: active.id,
        command: "echo alive",
      });
      assert.equal(alive.exitCode, 0);
    } finally {
      await rpcManager.dispose();
      await profiles.remove(testProfile.id);
    }

    const permissionRequests: Array<{ resource: string }> = [];
    const tools = createSshTools({
      manager,
      profiles,
      config,
      search: new SearchService(manager),
      jobs: new JobService(manager),
      assertPermission: async (request) => {
        permissionRequests.push({ resource: request.resource });
      },
    });
    const byName = new Map(tools.map((tool) => [tool.name, tool]));
    const context = {
      sessionID: "ses_smoke",
      agent: "build",
      messageID: "msg_smoke",
      id: "call_smoke",
      signal: new AbortController().signal,
      progress: async () => undefined,
    };

    const connectResult = await requiredTool(byName, "connect").execute(
      {
        name: "tool-test",
        user: "tester",
        host: "127.0.0.1",
        port: server.port,
        password: "secret",
        sudo_password: "sudo-secret",
      },
      context,
    );
    assert.match(connectResult.content, /ssh_id: ssh_/);
    assert.match(connectResult.content, /Reused existing SSH connection/);
    assert.equal(connectResult.metadata?.reused, true);
    const toolSshId = connectResult.metadata?.sshId;
    assert.equal(typeof toolSshId, "string");

    const execResult = await requiredTool(byName, "exec").execute(
      { ssh_id: toolSshId, command: "id", sudo: true },
      context,
    );
    assert.match(execResult.content, /exit_code: 0/);
    assert.match(execResult.content, /command=sudo -S -p '' -- sh -c 'id'/);
    assert.equal(permissionRequests.length, 1);
    assert.match(
      permissionRequests[0]?.resource ?? "",
      /^tester@127\.0\.0\.1:\d+$/,
    );

    const guardedExec = await requiredTool(byName, "exec").execute(
      {
        ssh_id: toolSshId,
        command: "echo guarded",
        non_interactive: true,
      },
      context,
    );
    assert.match(guardedExec.content, /export PAGER='cat'/);
    assert.match(guardedExec.content, /echo guarded\)/);

    const missingConnection = await requiredTool(byName, "exec")
      .execute(
        { ssh_id: "ssh_missing", command: "id" },
        context,
      )
      .catch((error: unknown) => error);
    if (!(missingConnection instanceof ToolError)) {
      throw new Error("expected a ToolError for a missing connection");
    }
    assert.equal(missingConnection.metadata?.errorCode, "SSH_NOT_CONNECTED");
    assert.equal(missingConnection.metadata?.retryable, true);
    assert.equal(
      missingConnection.metadata?.executionMayHaveStarted,
      false,
    );

    const timeoutToolError = await requiredTool(byName, "exec")
      .execute(
        {
          ssh_id: toolSshId,
          command: "__hang__",
          timeout_ms: 1_000,
          non_interactive: false,
        },
        context,
      )
      .catch((error: unknown) => error);
    if (!(timeoutToolError instanceof ToolError)) {
      throw new Error("expected a ToolError for a command timeout");
    }
    assert.equal(timeoutToolError.metadata?.errorCode, "SSH_COMMAND_TIMEOUT");
    assert.equal(timeoutToolError.metadata?.retryable, true);
    assert.equal(
      timeoutToolError.metadata?.executionMayHaveStarted,
      true,
    );
    assert.match(
      timeoutToolError.message,
      /error_code: SSH_COMMAND_TIMEOUT/,
    );

    const profileResult = await requiredTool(
      byName,
      "profile_add",
    ).execute(
      {
        name: "tool-profile",
        user: "deploy",
        host: "example.internal",
        password: "profile-password",
      },
      context,
    );
    assert.match(profileResult.content, /profile_id: prof_/);
    const profileList = await requiredTool(byName, "profile_list").execute(
      {},
      context,
    );
    assert.match(profileList.content, /name=tool-profile/);
    const toolProfileId = profileResult.metadata?.profileId;
    assert.equal(typeof toolProfileId, "string");
    await requiredTool(byName, "profile_remove").execute(
      { profile_id: toolProfileId },
      context,
    );
    await requiredTool(byName, "disconnect").execute(
      { ssh_id: toolSshId },
      context,
    );

    const liveProfileResult = await requiredTool(
      byName,
      "profile_add",
    ).execute(
      {
        name: "tool-live",
        user: "tester",
        host: "127.0.0.1",
        port: server.port,
        password: "secret",
        sudo_password: "sudo-secret",
      },
      context,
    );
    const liveProfileId = liveProfileResult.metadata?.profileId;
    assert.equal(typeof liveProfileId, "string");
    await assert.rejects(
      requiredTool(byName, "connect").execute(
        { profile_id: liveProfileId, user: "someone-else" },
        context,
      ),
      /either profile_id or inline/,
    );
    const profileConnect = await requiredTool(byName, "connect").execute(
      { profile_id: liveProfileId },
      context,
    );
    const profileSshId = profileConnect.metadata?.sshId;
    assert.equal(typeof profileSshId, "string");
    const profileExec = await requiredTool(byName, "exec").execute(
      { ssh_id: profileSshId, command: "whoami" },
      context,
    );
    assert.match(profileExec.content, /command=whoami/);
    await requiredTool(byName, "disconnect").execute(
      { ssh_id: profileSshId },
      context,
    );
    await requiredTool(byName, "profile_update").execute(
      { profile_id: liveProfileId, sudo_password: "new-sudo" },
      context,
    );
    await requiredTool(byName, "profile_remove").execute(
      { profile_id: liveProfileId },
      context,
    );

    const strictManagerInstance = new ConnectionManager(
      config,
      profiles,
      knownHosts,
    );
    strictManager = strictManagerInstance;
    const strict = await strictManagerInstance.connect({
      user: "tester",
      host: "127.0.0.1",
      port: server.port,
      password: "secret",
      hostKeyPolicy: "strict",
    });
    assert.match(strict.hostKeyFingerprint ?? "", /^SHA256:/);
    await strictManagerInstance.disconnect(strict.id);

    const unknownServer = await startTestSshServer();
    try {
      await assert.rejects(
        manager.connect({
          user: "tester",
          host: "127.0.0.1",
          port: unknownServer.port,
          password: "secret",
          hostKeyPolicy: "strict",
        }),
        /Unknown SSH host key/,
      );
    } finally {
      await unknownServer.close();
    }

    assert.equal(manager.list().length, 0);
    assert.throws(() => manager.getInfo(connection.id), /No active SSH connection/);
  } finally {
    await strictManager?.dispose();
    await manager.dispose();
    await server.close();
  }

  console.log("smoke tests passed");
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

function fakeExecResult(
  stdout: string,
  exitCode = 0,
  truncated = false,
): ExecResult {
  return {
    sshId: "ssh_test",
    exitCode,
    stdout,
    stderr: "",
    durationMs: 1,
    truncated,
  };
}

function fakeSearchManager(results: ExecResult[]): {
  manager: ConnectionManager;
  calls: string[];
  signals: Array<AbortSignal | undefined>;
} {
  const calls: string[] = [];
  const signals: Array<AbortSignal | undefined> = [];
  const manager = {
    exec: async (input: { command: string }, signal?: AbortSignal) => {
      calls.push(input.command);
      signals.push(signal);
      const next = results.shift();
      if (next === undefined) {
        throw new Error(`unexpected search exec: ${input.command}`);
      }
      return next;
    },
    sftp: async () => {
      throw new Error("unexpected search SFTP fallback");
    },
  };
  return {
    manager: manager as unknown as ConnectionManager,
    calls,
    signals,
  };
}

function requiredTool(
  tools: Map<string, ToolDefinition>,
  name: string,
): ToolDefinition {
  const tool = tools.get(name);
  assert.ok(tool, `missing tool: ${name}`);
  return tool;
}

async function startTestSshServer(): Promise<{
  port: number;
  close: () => Promise<void>;
}> {
  const { Server } = ssh2;
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const hostKey = privateKey
    .export({ type: "pkcs1", format: "pem" })
    .toString();

  const server = new Server({ hostKeys: [hostKey] }, (client) => {
    client.on("error", () => undefined);
    client.on("authentication", (context) => {
      if (
        context.method === "password" &&
        context.username === "tester" &&
        context.password === "secret"
      ) {
        context.accept();
        return;
      }
      context.reject(["password"]);
    });
    client.on("ready", () => {
      client.on("session", (accept) => {
        const session = accept();
        session.on("pty", (acceptPty) => acceptPty());
        session.on("exec", (acceptExec, _reject, info) => {
          const stream = acceptExec();
          if (info.command === "__hang__") {
            // Leave the channel open so a test can drop the connection mid-exec.
            stream.write("started\n");
            return;
          }
          if (info.command === "__no-exit__") {
            // Close the channel without sending an exit status.
            stream.write("no-exit\n");
            stream.end();
            return;
          }
          if (info.command === "__stdin__") {
            let received = "";
            stream.on("data", (chunk: Buffer) => {
              received += chunk.toString("utf8");
            });
            stream.on("end", () => {
              stream.write(`stdin-eof:${received.trim()}\n`);
              stream.exit(0);
              stream.end();
              stream.close();
            });
            return;
          }
          if (info.command === "__stream__") {
            stream.write("\u001b[31mhead-red\u001b[0m\n");
            stream.stderr.write("\u001b[32mstderr-start\u001b[0m\n");
            for (let index = 0; index < 200; index += 1) {
              const label = `line-${index.toString().padStart(4, "0")}`;
              stream.write(`${label}\n`);
              stream.stderr.write(`err-${index.toString().padStart(4, "0")}\n`);
            }
            stream.write("\rprogress 10%\rprogress 100%\n");
            stream.exit(0);
            stream.end();
            stream.close();
            return;
          }
          stream.write(`command=${info.command}\n`);
          stream.stderr.write(`stderr=${info.command}\n`);
          stream.exit(0);
          stream.end();
          stream.close();
        });
      });
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address();
  if (typeof address !== "object" || address === null) {
    server.close();
    throw new Error("Test SSH server did not expose a TCP address.");
  }

  return {
    port: address.port,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

function readdirNames(directory: string): string[] {
  return readdirSync(directory).sort();
}

function existsLocally(target: string): boolean {
  return existsSync(target);
}

async function captureError(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
    return "";
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

/**
 * Simulates the remote side of a job: the launch command writes pid/started_at,
 * probes report liveness, and stop returns a scripted outcome.
 */
class FakeJobConnections implements JobConnections {
  private readonly sftpStore;
  alive = true;
  stopAnswer: "stopped" | "not-running" | "mismatch" = "stopped";
  readonly now = Math.floor(Date.now() / 1_000);

  constructor(private readonly root: string) {
    this.sftpStore = createFakeSftp(root);
  }

  sftp() {
    return Promise.resolve(this.sftpStore);
  }

  homeDir() {
    return Promise.resolve("/home/tester");
  }

  exec(input: {
    sshId: string;
    command: string;
    timeoutMs?: number;
    maxOutputBytes?: number;
  }): Promise<ExecResult> {
    const result = (stdout: string, exitCode = 0): ExecResult => ({
      sshId: input.sshId,
      exitCode,
      stdout,
      stderr: "",
      durationMs: 1,
      truncated: false,
    });

    const command = input.command;
    if (command.startsWith("(command -v setsid")) {
      const match = /sh '([^']+)'/.exec(command);
      const script = match?.[1] ?? "";
      const local = this.toLocal(path.posix.dirname(script));
      writeFileSync(path.join(local, "pid"), "4242\n");
      writeFileSync(path.join(local, "started_at"), `${this.now}\n`);
      return Promise.resolve(result("4242\n"));
    }
    if (command.includes("tail -n")) {
      return Promise.resolve(result("log-1\nlog-2\n"));
    }
    if (command.includes('echo "now=')) {
      return Promise.resolve(
        result(
          this.alive
            ? `now=${this.now}\n4242=alive\n4242=match\n`
            : `now=${this.now}\n4242=dead\n`,
        ),
      );
    }
    if (command.includes("kill -TERM")) {
      return Promise.resolve(
        result(this.alive ? `${this.stopAnswer}\n` : "not-running\n"),
      );
    }
    return Promise.resolve(result(""));
  }

  writeExit(jobDir: string, code: number): void {
    writeFileSync(path.join(this.toLocal(jobDir), "exit_code"), `${code}\n`);
  }

  clearExit(jobDir: string): void {
    rmSync(path.join(this.toLocal(jobDir), "exit_code"), { force: true });
  }

  private toLocal(remote: string): string {
    return path.join(this.root, `.${remote}`);
  }
}
