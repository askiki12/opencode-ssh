import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import ssh2 from "ssh2";
import { resolveConfig } from "../src/config.js";
import { SecretBox } from "../src/crypto.js";
import { KnownHostsStore } from "../src/known-hosts.js";
import { ProfileStore, type ProfileStorage } from "../src/profiles.js";
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
import { ConnectionManager, type ExecResult } from "../src/ssh/manager.js";
import { globToRegExp, SearchService } from "../src/ssh/search.js";
import { createSshTools, type ToolDefinition } from "../src/tools/definitions.js";
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

  const stored = await storage.get("profiles");
  assert.ok(stored !== undefined, "profiles document should be stored");
  const storedText = JSON.stringify(stored);
  assert.ok(!storedText.includes("ssh-password"), "password must not be stored in plaintext");
  assert.ok(!storedText.includes("sudo-password"), "sudo password must not be stored in plaintext");
  assert.ok(storedText.includes("iv"), "sealed envelope should be present");

  const resolved = await profiles.resolve(added.id);
  assert.equal(resolved.password, "ssh-password");
  assert.equal(resolved.sudoPassword, "sudo-password");

  const listed = await profiles.list();
  assert.equal(listed.length, 1);
  assert.equal(listed[0]?.hasPassword, true);
  assert.equal("password" in (listed[0] ?? {}), false);

  // A new ProfileStore over the same storage simulates a service restart.
  const reloaded = new ProfileStore(storage, box);
  assert.equal((await reloaded.list()).length, 1);
  assert.equal((await reloaded.resolve(added.id)).password, "ssh-password");

  const updated = await profiles.update(added.id, {
    name: "smoke-2",
    privateKeyPath: "~/.ssh/id_ed25519",
    clearSudoPassword: true,
  });
  assert.equal(updated.name, "smoke-2");
  assert.equal(updated.auth, "privateKey");
  assert.equal(updated.hasSudoPassword, false);
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

    const binaryPath = "/project/data.bin";
    writeFileSync(path.join(fileRoot, "project", "data.bin"), Buffer.from([1, 0, 2]));
    const binary = await readRemoteFile(sftp, binaryPath);
    assert.equal(binary.binary, true);
    assert.equal(binary.lines.length, 0);
    assert.match(
      await captureError(() => editRemoteFile(sftp, binaryPath, "a", "b")),
      /binary/,
    );

    writeFileSync(path.join(fileRoot, "big.txt"), `${"a\n".repeat(5000)}`);
    const truncated = await readRemoteFile(sftp, "/big.txt", { maxBytes: 1024 });
    assert.equal(truncated.truncated, true);
    assert.equal(truncated.totalLines, null);

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

    const upload = await transferPath(sftp, {
      direction: "upload",
      localPath: localSource,
      remotePath: "/backup/src",
    });
    assert.equal(upload.files, 2);
    assert.equal(readFileSync(path.join(fileRoot, "backup", "src", "one.txt"), "utf8"), "upload-one\n");

    await assert.rejects(
      transferPath(sftp, {
        direction: "upload",
        localPath: localSource,
        remotePath: "/backup/src",
      }),
      /already exists/,
    );

    const localTarget = path.join(fileRoot, "local-dst");
    const download = await transferPath(sftp, {
      direction: "download",
      localPath: localTarget,
      remotePath: "/backup/src",
      overwrite: true,
    });
    assert.equal(download.files, 2);
    assert.equal(readFileSync(path.join(localTarget, "two.txt"), "utf8"), "upload-two\n");
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

    const sudo = await manager.exec({
      sshId: connection.id,
      command: "id",
      sudo: true,
    });
    assert.match(
      sudo.stdout,
      /^command=sudo -S -p '' -- sh -c 'id'\n$/,
    );

    await assert.rejects(
      manager.exec({ sshId: connection.id, command: "__no-exit__" }),
      /without an exit status/,
    );

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
      await assert.rejects(
        pending,
        /was lost while the command was running|without an exit status/,
      );
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
