import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import ssh2 from "ssh2";
import { resolveConfig } from "../src/config.js";
import { SecretBox } from "../src/crypto.js";
import { KnownHostsStore } from "../src/known-hosts.js";
import { ProfileStore, type ProfileStorage } from "../src/profiles.js";
import { buildRemoteCommand } from "../src/ssh/command.js";
import { ConnectionManager } from "../src/ssh/manager.js";
import { createSshTools, type ToolDefinition } from "../src/tools/definitions.js";

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
