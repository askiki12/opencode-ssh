import assert from "node:assert/strict";
import tui from "../src/tui.js";

interface Command {
  run: (input?: string) => void | false | Promise<void>;
}

const commands = new Map<string, Command>();
const alerts: string[] = [];
const toasts: string[] = [];
let selectAnswers: Array<string | undefined> = [];
let promptAnswers: Array<string | undefined> = [];
let confirmAnswers: Array<boolean | undefined> = [];
let rawRpc: Record<string, (input: any, options?: any) => Promise<any>> = {};
let lastTestUpdateInput: any;
let lastRpcOptions: any;
let lastSelectOptions: any;
let lastConnectInput: any;

const context = {
  location: { directory: "C:/work/opencode-ssh" },
  keymap: {
    layer: (factory: () => { commands: Command[] }) => {
      for (const command of factory().commands) {
        // id is not in the local Command type, but the layer includes it.
        const id = (command as unknown as { id: string }).id;
        commands.set(id, command);
      }
    },
  },
  client: {
    rpc: () => rawRpc,
  },
  ui: {
    dialog: {
      select: async (options: any) => {
        lastSelectOptions = options;
        return selectAnswers.shift();
      },
      prompt: async () => promptAnswers.shift(),
      confirm: async () => confirmAnswers.shift(),
      alert: async (options: { message: string }) => {
        alerts.push(options.message);
      },
    },
    toast: {
      show: (options: { message: string }) => {
        toasts.push(options.message);
      },
    },
  },
};

type TuiContext = Parameters<typeof tui.setup>[0];
tui.setup(context as unknown as TuiContext);

assert.ok(commands.has("opencode-ssh.connect"));
assert.ok(commands.has("opencode-ssh.disconnect"));
assert.ok(commands.has("opencode-ssh.list"));
assert.ok(commands.has("opencode-ssh.profile"));
assert.ok(!commands.has("opencode-ssh.profile.add"));
assert.ok(!commands.has("opencode-ssh.profile.remove"));
assert.ok(!commands.has("opencode-ssh.profile.list"));
assert.ok(!commands.has("opencode-ssh.profile.edit"));

function reset(): void {
  alerts.length = 0;
  toasts.length = 0;
  selectAnswers = [];
  promptAnswers = [];
  confirmAnswers = [];
  rawRpc = {};
  lastTestUpdateInput = undefined;
  lastRpcOptions = undefined;
  lastSelectOptions = undefined;
  lastConnectInput = undefined;
}

async function run(id: string, input?: string): Promise<void> {
  const command = commands.get(id);
  assert.ok(command, `missing command ${id}`);
  await command.run(input);
}

const profile = {
  id: "prof_test",
  name: "test",
  user: "tester",
  host: "127.0.0.1",
  port: 2222,
  auth: "password",
  hasPassword: true,
  hasPrivateKeyPassphrase: false,
  hasSudoPassword: false,
  hostKeyPolicy: "accept-new",
  createdAt: "",
  updatedAt: "",
};

const connection = {
  id: "ssh_test",
  name: "test",
  user: "tester",
  host: "127.0.0.1",
  port: 2222,
  authMethod: "password",
  connectedAt: "",
  lastUsedAt: "",
  idleMs: 0,
  busy: false,
};

async function main() {
  reset();
  rawRpc = {
    connectionsList: async (_input, options) => {
      lastRpcOptions = options;
      return { ok: true, data: [] };
    },
  };
  await run("opencode-ssh.list");
  assert.ok(alerts.includes("没有活跃连接。"));
  assert.equal(
    lastRpcOptions?.location?.directory,
    "C:/work/opencode-ssh",
  );

  reset();
  rawRpc = {
    connectionsList: async () => {
      throw { type: "rpc.unavailable", message: "RPC is unavailable" };
    },
  };
  await run("opencode-ssh.list");
  assert.ok(alerts.some((message) => message.includes("RPC is unavailable")));

  reset();
  rawRpc = {
    profilesList: async () => ({ ok: true, data: [profile] }),
    connectionsList: async () => ({ ok: true, data: [] }),
    connectionsConnect: async () => ({ ok: true, data: connection }),
  };
  selectAnswers = ["prof_test"];
  await run("opencode-ssh.connect");
  assert.ok(toasts.some((message) => message.includes("已连接")));
  assert.equal(lastSelectOptions?.options?.[0]?.title, "test");
  assert.equal(
    lastSelectOptions?.options?.[0]?.description,
    "tester@127.0.0.1:2222",
  );

  reset();
  rawRpc = {
    profilesList: async () => ({ ok: true, data: [] }),
    connectionsList: async () => ({ ok: true, data: [connection] }),
  };
  selectAnswers = ["__manual__"];
  promptAnswers = ["tester", "127.0.0.1", "2222", "secret", ""];
  confirmAnswers = [true, true, true];
  await run("opencode-ssh.connect");
  assert.ok(toasts.some((message) => message.includes("复用已有连接")));

  reset();
  rawRpc = {
    profilesList: async () => ({ ok: true, data: [] }),
    connectionsList: async () => ({ ok: true, data: [connection] }),
    connectionsConnect: async (input: any) => {
      lastConnectInput = input;
      return { ok: true, data: connection };
    },
  };
  selectAnswers = ["__manual__"];
  promptAnswers = ["tester", "127.0.0.1", "2222", "secret", ""];
  confirmAnswers = [true, true, false];
  await run("opencode-ssh.connect");
  assert.equal(lastConnectInput?.forceNew, true);

  reset();
  rawRpc = {
    profilesList: async () => ({ ok: true, data: [] }),
    connectionsList: async () => ({ ok: true, data: [] }),
  };
  selectAnswers = ["list"];
  await run("opencode-ssh.profile");
  assert.ok(alerts.includes("没有已保存的 profile。"));

  reset();
  rawRpc = {
    profilesList: async () => ({ ok: true, data: [profile] }),
    connectionsList: async () => ({ ok: true, data: [] }),
  };
  selectAnswers = ["list"];
  await run("opencode-ssh.profile");
  assert.ok(alerts[0]?.includes("test  tester@127.0.0.1:2222"));
  assert.ok(!alerts[0]?.includes("prof_test"));
  assert.ok(!alerts[0]?.includes("auth="));

  reset();
  rawRpc = {
    connectionsList: async () => ({ ok: true, data: [connection] }),
  };
  await run("opencode-ssh.list");
  assert.ok(alerts[0]?.includes("test  tester@127.0.0.1:2222  idle=0s"));
  assert.ok(!alerts[0]?.includes("ssh_test"));
  assert.ok(!alerts[0]?.includes("auth="));

  reset();
  rawRpc = {
    profilesList: async () => ({ ok: true, data: [] }),
    profilesTestAndAdd: async () => ({ ok: true, data: profile }),
  };
  promptAnswers = [
    "new-profile",
    "tester",
    "127.0.0.1",
    "2222",
    "secret",
    "sudo-secret",
  ];
  confirmAnswers = [true, true];
  selectAnswers = ["add"];
  await run("opencode-ssh.profile");
  assert.ok(toasts.some((message) => message.includes("Profile 已保存")));

  reset();
  rawRpc = {
    profilesList: async () => ({ ok: true, data: [profile] }),
    connectionsList: async () => ({ ok: true, data: [] }),
    profilesTestAndUpdate: async (input: any) => {
      lastTestUpdateInput = input;
      return {
        ok: false,
        error: "All configured authentication methods failed",
      };
    },
  };
  selectAnswers = ["edit", "prof_test"];
  promptAnswers = ["test-renamed", "tester", "127.0.0.1", "2222", "", ""];
  confirmAnswers = [true, true];
  await run("opencode-ssh.profile");
  assert.ok(
    alerts.some((message) =>
      message.includes("All configured authentication methods failed"),
    ),
  );
  assert.equal(lastTestUpdateInput?.patch?.name, "test-renamed");

  reset();
  rawRpc = {
    connectionsList: async () => ({ ok: true, data: [connection] }),
    connectionsDisconnect: async () => ({ ok: true, data: connection }),
  };
  selectAnswers = ["ssh_test"];
  await run("opencode-ssh.disconnect");
  assert.ok(toasts.some((message) => message.includes("已断开")));

  reset();
  rawRpc = {
    profilesList: async () => ({ ok: true, data: [profile] }),
    connectionsList: async () => ({ ok: true, data: [] }),
    profilesRemove: async () => ({ ok: true, data: { removed: true } }),
  };
  selectAnswers = ["remove", "prof_test"];
  confirmAnswers = [true];
  await run("opencode-ssh.profile");
  assert.ok(toasts.some((message) => message.includes("已删除")));

  console.log("tui smoke tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
