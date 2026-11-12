import { appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Plugin } from "@opencode/plugin/tui";
import type { PublicProfile } from "./profiles.js";
import { SshRpc } from "./rpc.js";
import type { ConnectionInfo } from "./ssh/manager.js";

function debugLog(message: string): void {
  const target = process.env.OPENCODE_SSH_TUI_DEBUG;
  if (!target) return;
  const file =
    target === "1" ? path.join(tmpdir(), "opencode-ssh-tui.log") : target;
  try {
    appendFileSync(file, `${new Date().toISOString()} ${message}\n`);
  } catch {
    // Debug logging must never break the TUI.
  }
}

function withLog(
  label: string,
  run: (input?: string) => void | false | Promise<void>,
): (input?: string) => void | false | Promise<void> {
  return (input) => {
    debugLog(
      `${label} input.type=${typeof input} input=${
        typeof input === "string" ? JSON.stringify(input) : String(input)
      }`,
    );
    return run(input);
  };
}

type HostKeyPolicy = "accept-new" | "strict" | "insecure";
type AuthMethod = "password" | "privateKey";

interface ConnectFormInput {
  user: string;
  host: string;
  port: number;
  password?: string;
  privateKeyPath?: string;
  privateKeyPassphrase?: string;
  sudoPassword?: string;
  hostKeyPolicy: HostKeyPolicy;
  forceNew?: boolean;
}

interface ProfileAddInput extends ConnectFormInput {
  name: string;
}

interface ProfilePatch {
  name?: string;
  user?: string;
  host?: string;
  port?: number;
  password?: string;
  privateKeyPath?: string;
  privateKeyPassphrase?: string;
  sudoPassword?: string;
  hostKeyPolicy?: HostKeyPolicy;
  clearPassword?: boolean;
  clearPrivateKeyPath?: boolean;
  clearPrivateKeyPassphrase?: boolean;
  clearSudoPassword?: boolean;
}

interface PrivateKeyInfo {
  path: string;
  name: string;
}

interface SshRpcClient {
  connectionsList(input: Record<string, never>): Promise<ConnectionInfo[]>;
  connectionsConnect(
    input: ConnectFormInput | { profileId: string },
  ): Promise<ConnectionInfo>;
  connectionsDisconnect(input: { sshId: string }): Promise<ConnectionInfo>;
  connectionsTest(input: ConnectFormInput): Promise<ConnectionInfo>;
  profilesList(input: Record<string, never>): Promise<PublicProfile[]>;
  profilesAdd(input: ProfileAddInput): Promise<PublicProfile>;
  profilesUpdate(
    input: { profileId: string } & ProfilePatch,
  ): Promise<PublicProfile>;
  profilesRemove(input: { profileId: string }): Promise<{ removed: boolean }>;
  profilesTestAndAdd(input: ProfileAddInput): Promise<PublicProfile>;
  profilesTestAndUpdate(input: {
    profileId: string;
    patch: ProfilePatch;
  }): Promise<PublicProfile>;
  keysList(input: Record<string, never>): Promise<PrivateKeyInfo[]>;
}

type RpcResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string };

interface RpcOptions {
  location?: unknown;
}

interface RawRpcClient {
  connectionsList(
    input: Record<string, never>,
    options?: RpcOptions,
  ): Promise<RpcResult<ConnectionInfo[]>>;
  connectionsConnect(
    input: ConnectFormInput | { profileId: string },
    options?: RpcOptions,
  ): Promise<RpcResult<ConnectionInfo>>;
  connectionsDisconnect(
    input: { sshId: string },
    options?: RpcOptions,
  ): Promise<RpcResult<ConnectionInfo>>;
  connectionsTest(
    input: ConnectFormInput,
    options?: RpcOptions,
  ): Promise<RpcResult<ConnectionInfo>>;
  profilesList(
    input: Record<string, never>,
    options?: RpcOptions,
  ): Promise<RpcResult<PublicProfile[]>>;
  profilesAdd(
    input: ProfileAddInput,
    options?: RpcOptions,
  ): Promise<RpcResult<PublicProfile>>;
  profilesUpdate(
    input: { profileId: string } & ProfilePatch,
    options?: RpcOptions,
  ): Promise<RpcResult<PublicProfile>>;
  profilesRemove(
    input: { profileId: string },
    options?: RpcOptions,
  ): Promise<RpcResult<{ removed: boolean }>>;
  profilesTestAndAdd(
    input: ProfileAddInput,
    options?: RpcOptions,
  ): Promise<RpcResult<PublicProfile>>;
  profilesTestAndUpdate(
    input: { profileId: string; patch: ProfilePatch },
    options?: RpcOptions,
  ): Promise<RpcResult<PublicProfile>>;
  keysList(
    input: Record<string, never>,
    options?: RpcOptions,
  ): Promise<RpcResult<PrivateKeyInfo[]>>;
}

interface SelectOption {
  title: string;
  value: string;
  description?: string;
  disabled?: boolean;
}

export default Plugin.define({
  id: "opencode-ssh.tui",
  setup(context) {
    debugLog(
      `setup dialog.prompt=${typeof context.ui?.dialog?.prompt} dialog.select=${typeof context.ui?.dialog?.select} dialog.alert=${typeof context.ui?.dialog?.alert} toast=${typeof context.ui?.toast?.show} dispatch=${typeof context.keymap?.dispatch}`,
    );
    context.keymap.layer(() => ({
      mode: "global",
      commands: [
        {
          id: "opencode-ssh.connect",
          title: "SSH: 连接",
          group: "SSH",
          palette: true,
          slash: { name: "ssh-connect" },
          run: withLog("connect", (input) =>
            guard(context, () =>
              runConnect(
                context,
                getRpc(context),
                commandArguments(input, "ssh-connect"),
              ),
            ),
          ),
        },
        {
          id: "opencode-ssh.disconnect",
          title: "SSH: 断开连接",
          group: "SSH",
          palette: true,
          slash: { name: "ssh-disconnect" },
          run: withLog("disconnect", (input) =>
            guard(context, () =>
              runDisconnect(
                context,
                getRpc(context),
                commandArguments(input, "ssh-disconnect"),
              ),
            ),
          ),
        },
        {
          id: "opencode-ssh.list",
          title: "SSH: 活跃连接",
          group: "SSH",
          palette: true,
          slash: { name: "ssh-list" },
          run: withLog("list", () =>
            guard(context, () => runList(context, getRpc(context))),
          ),
        },
        {
          id: "opencode-ssh.profile",
          title: "SSH: Profile 管理",
          group: "SSH",
          palette: true,
          slash: { name: "ssh-profile" },
          run: withLog("profile", (input) =>
            guard(context, () =>
              runProfileCommand(
                context,
                getRpc(context),
                commandArguments(input, "ssh-profile"),
              ),
            ),
          ),
        },
      ],
    }));
  },
});

function getRpc(context: Plugin.Context): SshRpcClient {
  const location = context.location ?? context.data.location.default();
  const options = { location };
  const raw = context.client.rpc(SshRpc) as unknown as RawRpcClient;
  return {
    connectionsList: (input) => unwrap(raw.connectionsList(input, options)),
    connectionsConnect: (input) =>
      unwrap(raw.connectionsConnect(input, options)),
    connectionsDisconnect: (input) =>
      unwrap(raw.connectionsDisconnect(input, options)),
    connectionsTest: (input) => unwrap(raw.connectionsTest(input, options)),
    profilesList: (input) => unwrap(raw.profilesList(input, options)),
    profilesAdd: (input) => unwrap(raw.profilesAdd(input, options)),
    profilesUpdate: (input) => unwrap(raw.profilesUpdate(input, options)),
    profilesRemove: (input) => unwrap(raw.profilesRemove(input, options)),
    profilesTestAndAdd: (input) =>
      unwrap(raw.profilesTestAndAdd(input, options)),
    profilesTestAndUpdate: (input) =>
      unwrap(raw.profilesTestAndUpdate(input, options)),
    keysList: (input) => unwrap(raw.keysList(input, options)),
  };
}

async function unwrap<T>(result: Promise<RpcResult<T>>): Promise<T> {
  const settled = await result;
  if (!settled.ok) throw new Error(settled.error);
  return settled.data;
}

function errorText(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  if (typeof error === "object" && error !== null) {
    const record = error as { type?: unknown; message?: unknown };
    if (typeof record.message === "string") {
      return typeof record.type === "string"
        ? `${record.type}: ${record.message}`
        : record.message;
    }
    try {
      return JSON.stringify(error);
    } catch {
      // Fall through to String().
    }
  }
  return String(error);
}

async function guard(
  context: Plugin.Context,
  task: () => Promise<void>,
): Promise<void> {
  try {
    await task();
  } catch (error) {
    debugLog(
      `command error ${error instanceof Error ? (error.stack ?? error.message) : errorText(error)}`,
    );
    await context.ui.dialog.alert({
      title: "SSH",
      message: errorText(error),
    });
  }
}

async function runConnect(
  context: Plugin.Context,
  rpc: SshRpcClient,
  argument: string,
): Promise<void> {
  const [profiles, connections] = await Promise.all([
    rpc.profilesList({}),
    rpc.connectionsList({}),
  ]);
  const active = new Set(connections.map(connectionTarget));

  if (argument.length > 0) {
    const profile = findProfile(profiles, argument);
    if (!profile) {
      await context.ui.dialog.alert({
        title: "SSH",
        message: `未找到 profile: ${argument}`,
      });
      return;
    }
    await connectProfile(context, rpc, profile, active);
    return;
  }

  const options: SelectOption[] = profiles.map((profile) => {
    const isActive = active.has(profileTarget(profile));
    return {
      title: `${isActive ? "[active] " : ""}${profile.name}`,
      value: profile.id,
      description: `${profile.user}@${profile.host}:${profile.port}`,
      disabled: isActive,
    };
  });
  options.push({
    title: "手动输入新连接",
    value: "__manual__",
  });

  const choice = await context.ui.dialog.select({
    title: "SSH 连接",
    placeholder: "选择 profile，或手动输入新连接",
    options,
  });
  if (choice === undefined) return;

  if (choice === "__manual__") {
    const input = await promptNewConnection(context, rpc);
    if (!input) return;
    const existing = connections.find(
      (candidate) => connectionTarget(candidate) === inputTarget(input),
    );
    if (existing) {
      const reuse = await context.ui.dialog.confirm({
        title: "已有活跃连接",
        message: `${existing.name}  ${existing.user}@${existing.host}:${existing.port} 已经连接。\n\n选择“复用”使用现有连接；选择“新建”创建另一个 SSH 连接。`,
        label: { confirm: "复用", cancel: "新建" },
      });
      if (reuse === undefined) return;
      if (reuse) {
        context.ui.toast.show({
          title: "SSH",
          message: `复用已有连接: ${existing.name}  ${existing.user}@${existing.host}:${existing.port}`,
          variant: "info",
        });
        return;
      }
    }
    const info = await rpc.connectionsConnect(
      existing ? { ...input, forceNew: true } : input,
    );
    context.ui.toast.show({
      title: "SSH",
      message: `已连接: ${info.user}@${info.host}:${info.port}`,
      variant: "success",
    });
    await maybeSaveProfile(context, rpc, input, profiles);
    return;
  }

  const profile = profiles.find((candidate) => candidate.id === choice);
  if (!profile) return;
  await connectProfile(context, rpc, profile, active);
}

async function connectProfile(
  context: Plugin.Context,
  rpc: SshRpcClient,
  profile: PublicProfile,
  active: Set<string>,
): Promise<void> {
  if (active.has(profileTarget(profile))) {
    await context.ui.dialog.alert({
      title: "SSH",
      message: `${profile.name} 已经处于 active 状态。`,
    });
    return;
  }
  const info = await rpc.connectionsConnect({ profileId: profile.id });
  context.ui.toast.show({
    title: "SSH",
    message: `已连接 ${profile.name}  ${profile.user}@${profile.host}:${profile.port}`,
    variant: "success",
  });
}

async function maybeSaveProfile(
  context: Plugin.Context,
  rpc: SshRpcClient,
  input: ConnectFormInput,
  profiles: PublicProfile[],
): Promise<void> {
  const save = await context.ui.dialog.confirm({
    title: "保存 Profile",
    message: "连接成功。是否把这次连接保存为 profile？",
    label: { confirm: "保存", cancel: "不保存" },
  });
  if (save !== true) return;

  const equivalent = profiles.find((profile) => sameTarget(profile, input));
  if (equivalent) {
    await context.ui.dialog.alert({
      title: "已存在等价 Profile",
      message: `${equivalent.name}  ${equivalent.user}@${equivalent.host}:${equivalent.port} 已经保存了相同的 user/host/port/认证信息。`,
    });
    return;
  }

  const name = await promptProfileName(
    context,
    profiles,
    `${input.user}@${input.host}`,
  );
  if (!name) return;

  try {
    const saved = await rpc.profilesAdd({ ...input, name });
    context.ui.toast.show({
      title: "SSH",
      message: `Profile 已保存: ${saved.name}`,
      variant: "success",
    });
  } catch (error) {
    await context.ui.dialog.alert({
      title: "保存失败",
      message: errorText(error),
    });
  }
}

async function promptNewConnection(
  context: Plugin.Context,
  rpc: SshRpcClient,
): Promise<ConnectFormInput | undefined> {
  const user = await askRequired(context, "SSH 用户", "例如 root / deploy");
  if (user === undefined) return undefined;
  const host = await askRequired(context, "SSH 主机", "主机名或 IP");
  if (host === undefined) return undefined;
  const port = await askPort(context, 22);
  if (port === undefined) return undefined;

  const auth = await selectAuth(context, "password");
  if (auth === undefined) return undefined;

  let password: string | undefined;
  let privateKeyPath: string | undefined;
  let privateKeyPassphrase: string | undefined;

  if (auth === "password") {
    password = await askRequiredSecret(context, "SSH 密码");
    if (password === undefined) return undefined;
  } else {
    const selected = await selectKeyPath(context, rpc, undefined, false);
    if (selected === undefined || selected === "keep") return undefined;
    privateKeyPath = selected;
    privateKeyPassphrase = await askSecret(
      context,
      "私钥口令",
      "私钥没有口令时留空",
    );
  }

  const sudoPassword =
    user === "root"
      ? undefined
      : await askSecret(
          context,
          "sudo 密码",
          "非 root 用户选填；留空表示不使用 sudo 密码",
        );
  const hostKeyPolicy = await selectHostKeyPolicy(context, "accept-new");
  if (hostKeyPolicy === undefined) return undefined;

  return {
    user,
    host,
    port,
    hostKeyPolicy,
    ...(password !== undefined ? { password } : {}),
    ...(privateKeyPath !== undefined ? { privateKeyPath } : {}),
    ...(privateKeyPassphrase !== undefined ? { privateKeyPassphrase } : {}),
    ...(sudoPassword !== undefined ? { sudoPassword } : {}),
  };
}

async function runDisconnect(
  context: Plugin.Context,
  rpc: SshRpcClient,
  argument: string,
): Promise<void> {
  const connections = await rpc.connectionsList({});
  if (connections.length === 0) {
    await context.ui.dialog.alert({
      title: "SSH",
      message: "当前没有活跃连接。",
    });
    return;
  }

  let connection: ConnectionInfo | undefined;
  if (argument.length > 0) {
    connection = connections.find(
      (candidate) =>
        candidate.id === argument ||
        candidate.name.toLowerCase() === argument.toLowerCase(),
    );
    if (!connection) {
      await context.ui.dialog.alert({
        title: "SSH",
        message: `未找到活跃连接: ${argument}`,
      });
      return;
    }
  } else {
    const choice = await context.ui.dialog.select({
      title: "断开 SSH 连接",
      options: connections.map((candidate) => ({
        title: `${candidate.name}  ${candidate.user}@${candidate.host}:${candidate.port}`,
        value: candidate.id,
      })),
    });
    if (choice === undefined) return;
    connection = connections.find((candidate) => candidate.id === choice);
  }

  if (!connection) return;
  await rpc.connectionsDisconnect({ sshId: connection.id });
  context.ui.toast.show({
    title: "SSH",
    message: `已断开: ${connection.name}  ${connection.user}@${connection.host}:${connection.port}`,
    variant: "success",
  });
}

async function runList(
  context: Plugin.Context,
  rpc: SshRpcClient,
): Promise<void> {
  const connections = await rpc.connectionsList({});
  if (connections.length === 0) {
    await context.ui.dialog.alert({
      title: "SSH 活跃连接",
      message: "没有活跃连接。",
    });
    return;
  }
  await context.ui.dialog.alert({
    title: `SSH 活跃连接 (${connections.length})`,
    message: connections.map(formatConnection).join("\n"),
  });
}

async function runProfileCommand(
  context: Plugin.Context,
  rpc: SshRpcClient,
  argument: string,
): Promise<void> {
  const action = argument.split(/\s+/)[0]?.toLowerCase() ?? "";
  if (action === "add") return runProfileAdd(context, rpc);
  if (action === "remove") return runProfileRemove(context, rpc);
  if (action === "list") return runProfileList(context, rpc);
  if (action === "edit") return runProfileEdit(context, rpc);

  const choice = await context.ui.dialog.select({
    title: "SSH Profile",
    options: [
      { title: "add", value: "add", description: "新增 profile 并测试连接" },
      { title: "remove", value: "remove", description: "删除 profile" },
      { title: "list", value: "list", description: "查看所有 profile" },
      { title: "edit", value: "edit", description: "编辑 profile 并测试连接" },
    ],
  });
  if (choice === undefined) return;
  if (choice === "add") return runProfileAdd(context, rpc);
  if (choice === "remove") return runProfileRemove(context, rpc);
  if (choice === "list") return runProfileList(context, rpc);
  if (choice === "edit") return runProfileEdit(context, rpc);
}

async function runProfileAdd(
  context: Plugin.Context,
  rpc: SshRpcClient,
): Promise<void> {
  const profiles = await rpc.profilesList({});
  const name = await promptProfileName(context, profiles, "");
  if (!name) return;

  const input = await promptNewConnection(context, rpc);
  if (!input) return;

  const equivalent = profiles.find((profile) => sameTarget(profile, input));
  if (equivalent) {
    await context.ui.dialog.alert({
      title: "已存在等价 Profile",
      message: `${equivalent.name}  ${equivalent.user}@${equivalent.host}:${equivalent.port} 已经保存了相同的 user/host/port/认证信息。`,
    });
    return;
  }

  const saved = await rpc.profilesTestAndAdd({ ...input, name });
  context.ui.toast.show({
    title: "SSH",
    message: `连接测试成功，Profile 已保存: ${saved.name}`,
    variant: "success",
  });
}

async function runProfileRemove(
  context: Plugin.Context,
  rpc: SshRpcClient,
): Promise<void> {
  const [profiles, connections] = await Promise.all([
    rpc.profilesList({}),
    rpc.connectionsList({}),
  ]);
  if (profiles.length === 0) {
    await context.ui.dialog.alert({
      title: "SSH Profile",
      message: "没有已保存的 profile。",
    });
    return;
  }
  const active = new Set(connections.map(connectionTarget));
  const choice = await context.ui.dialog.select({
    title: "删除 SSH Profile",
    options: profiles.map((profile) => ({
      title: `${profile.name}${
        active.has(profileTarget(profile)) ? " [active]" : ""
      }`,
      value: profile.id,
      description: `${profile.user}@${profile.host}:${profile.port}`,
    })),
  });
  if (choice === undefined) return;
  const profile = profiles.find((candidate) => candidate.id === choice);
  if (!profile) return;

  const isActive = active.has(profileTarget(profile));
  const confirmed = await context.ui.dialog.confirm({
    title: "删除 Profile",
    message: isActive
      ? `确认删除 ${profile.name}  ${profile.user}@${profile.host}:${profile.port}？\n\n该 profile 当前有活跃连接；删除 profile 不会断开已有连接。`
      : `确认删除 ${profile.name}  ${profile.user}@${profile.host}:${profile.port}？`,
    label: { confirm: "删除", cancel: "取消" },
  });
  if (confirmed !== true) return;

  const result = await rpc.profilesRemove({ profileId: profile.id });
  context.ui.toast.show({
    title: "SSH",
    message: result.removed
      ? `已删除: ${profile.name}`
      : `未找到: ${profile.name}`,
    variant: result.removed ? "success" : "warning",
  });
}

async function runProfileList(
  context: Plugin.Context,
  rpc: SshRpcClient,
): Promise<void> {
  const [profiles, connections] = await Promise.all([
    rpc.profilesList({}),
    rpc.connectionsList({}),
  ]);
  if (profiles.length === 0) {
    await context.ui.dialog.alert({
      title: "SSH Profile",
      message: "没有已保存的 profile。",
    });
    return;
  }
  const active = new Set(connections.map(connectionTarget));
  await context.ui.dialog.alert({
    title: `SSH Profile (${profiles.length})`,
    message: profiles
      .map((profile) =>
        formatProfile(profile, active.has(profileTarget(profile))),
      )
      .join("\n"),
  });
}

async function runProfileEdit(
  context: Plugin.Context,
  rpc: SshRpcClient,
): Promise<void> {
  const [profiles, connections] = await Promise.all([
    rpc.profilesList({}),
    rpc.connectionsList({}),
  ]);
  if (profiles.length === 0) {
    await context.ui.dialog.alert({
      title: "SSH Profile",
      message: "没有已保存的 profile。",
    });
    return;
  }
  const active = new Set(connections.map(connectionTarget));
  const choice = await context.ui.dialog.select({
    title: "编辑 SSH Profile",
    options: profiles.map((profile) => ({
      title: `${profile.name}${
        active.has(profileTarget(profile)) ? " [active]" : ""
      }`,
      value: profile.id,
      description: `${profile.user}@${profile.host}:${profile.port}`,
    })),
  });
  if (choice === undefined) return;
  const profile = profiles.find((candidate) => candidate.id === choice);
  if (!profile) return;

  const patch = await promptEditPatch(context, rpc, profile);
  if (!patch) return;

  const saved = await rpc.profilesTestAndUpdate({
    profileId: profile.id,
    patch,
  });
  context.ui.toast.show({
    title: "SSH",
    message: `连接测试成功，Profile 已更新: ${saved.name}`,
    variant: "success",
  });
}

async function promptEditPatch(
  context: Plugin.Context,
  rpc: SshRpcClient,
  profile: PublicProfile,
): Promise<ProfilePatch | undefined> {
  const name = await askRequired(
    context,
    "Profile 名称",
    "名称必须唯一",
    profile.name,
  );
  if (name === undefined) return undefined;
  const user = await askRequired(context, "SSH 用户", undefined, profile.user);
  if (user === undefined) return undefined;
  const host = await askRequired(context, "SSH 主机", undefined, profile.host);
  if (host === undefined) return undefined;
  const port = await askPort(context, profile.port);
  if (port === undefined) return undefined;

  const auth = await selectAuth(context, profile.auth);
  if (auth === undefined) return undefined;

  const patch: ProfilePatch = {
    name,
    user,
    host,
    port,
  };

  if (auth === "password") {
    const password =
      profile.auth === "password"
        ? await askSecret(context, "新 SSH 密码", "留空保持当前密码")
        : await askRequiredSecret(context, "SSH 密码");
    if (password === undefined && profile.auth !== "password") return undefined;
    if (password !== undefined) patch.password = password;
  } else {
    const selected = await selectKeyPath(
      context,
      rpc,
      profile.privateKeyPath,
      true,
    );
    if (selected === undefined) return undefined;
    if (selected !== "keep") {
      patch.privateKeyPath = selected;
      const passphrase = await askSecret(
        context,
        "私钥口令",
        "留空表示私钥没有口令",
      );
      if (passphrase !== undefined) patch.privateKeyPassphrase = passphrase;
    } else if (profile.auth !== "privateKey") {
      return undefined;
    }
  }

  if (user === "root") {
    if (profile.hasSudoPassword) {
      const clear = await context.ui.dialog.confirm({
        title: "sudo 密码",
        message: "已切换为 root 用户，是否清除已保存的 sudo 密码？",
        label: { confirm: "清除", cancel: "保留" },
      });
      if (clear === true) patch.clearSudoPassword = true;
    }
  } else {
    const sudoPassword = await askSecret(
      context,
      "新 sudo 密码",
      "留空保持当前设置",
    );
    if (sudoPassword !== undefined) {
      patch.sudoPassword = sudoPassword;
    } else if (profile.hasSudoPassword) {
      const clear = await context.ui.dialog.confirm({
        title: "sudo 密码",
        message: "是否清除已保存的 sudo 密码？",
        label: { confirm: "清除", cancel: "保留" },
      });
      if (clear === true) patch.clearSudoPassword = true;
    }
  }

  const hostKeyPolicy = await selectHostKeyPolicy(
    context,
    profile.hostKeyPolicy,
  );
  if (hostKeyPolicy === undefined) return undefined;
  patch.hostKeyPolicy = hostKeyPolicy;
  return patch;
}

async function promptProfileName(
  context: Plugin.Context,
  profiles: PublicProfile[],
  suggested: string,
): Promise<string | undefined> {
  let value = suggested;
  while (true) {
    const name = await askRequired(
      context,
      "Profile 名称",
      "用于 /ssh-connect 选择；名称必须唯一",
      value,
    );
    if (name === undefined) return undefined;
    if (
      profiles.some(
        (profile) => profile.name.toLowerCase() === name.toLowerCase(),
      )
    ) {
      await context.ui.dialog.alert({
        title: "名称重复",
        message: `已存在名为 "${name}" 的 profile，请换一个名称。`,
      });
      value = name;
      continue;
    }
    return name;
  }
}

async function selectAuth(
  context: Plugin.Context,
  current: AuthMethod,
): Promise<AuthMethod | undefined> {
  const usePassword = await context.ui.dialog.confirm({
    title: "认证方式",
    message: `当前：${current === "password" ? "密码" : "私钥"}\n\n选择“密码”使用 SSH 密码；选择“私钥”使用本地私钥文件。`,
    label: { confirm: "密码", cancel: "私钥" },
  });
  if (usePassword === undefined) return undefined;
  return usePassword ? "password" : "privateKey";
}

async function selectHostKeyPolicy(
  context: Plugin.Context,
  current: HostKeyPolicy,
): Promise<HostKeyPolicy | undefined> {
  const acceptNew = await context.ui.dialog.confirm({
    title: "主机指纹策略",
    message: `当前：${current}\n\n使用 accept-new？\n首次连接记录主机指纹，之后必须匹配。`,
    label: { confirm: "accept-new", cancel: "其他" },
  });
  if (acceptNew === undefined) return undefined;
  if (acceptNew) return "accept-new";

  const strict = await context.ui.dialog.confirm({
    title: "主机指纹策略",
    message:
      "使用 strict？\n未知主机直接拒绝，只允许已记录指纹的主机。\n\n选择“insecure”接受任意主机指纹（不推荐）。",
    label: { confirm: "strict", cancel: "insecure" },
  });
  if (strict === undefined) return undefined;
  return strict ? "strict" : "insecure";
}

async function selectKeyPath(
  context: Plugin.Context,
  rpc: SshRpcClient,
  current: string | undefined,
  allowKeep: boolean,
): Promise<string | "keep" | undefined> {
  const keys = await rpc.keysList({});
  const options: SelectOption[] = [];
  if (allowKeep && current) {
    options.push({
      title: "保持当前私钥",
      value: "__keep__",
      description: current,
    });
  }
  for (const key of keys) {
    options.push({
      title: key.name,
      value: key.path,
      description: key.path,
    });
  }
  options.push({
    title: "手动输入路径",
    value: "__manual__",
    description: "输入其他私钥文件路径",
  });

  const choice = await context.ui.dialog.select({
    title: "选择私钥",
    options,
    placeholder: "从 ~/.ssh 检测到的私钥中选择",
  });
  if (choice === undefined) return undefined;
  if (choice === "__keep__") return "keep";
  if (choice === "__manual__") {
    return askRequired(
      context,
      "私钥路径",
      "支持 ~ 和 %VAR%",
      current,
    );
  }
  return choice;
}

async function askRequired(
  context: Plugin.Context,
  title: string,
  description?: string,
  value?: string,
): Promise<string | undefined> {
  while (true) {
    const entered = await context.ui.dialog.prompt({
      title,
      ...(description !== undefined ? { description } : {}),
      ...(value !== undefined && value.length > 0 ? { value } : {}),
    });
    if (entered === undefined) return undefined;
    const trimmed = entered.trim();
    if (trimmed.length > 0) return trimmed;
    await context.ui.dialog.alert({
      title,
      message: "不能为空，请重新输入。",
    });
  }
}

async function askRequiredSecret(
  context: Plugin.Context,
  title: string,
  description?: string,
): Promise<string | undefined> {
  while (true) {
    const entered = await promptSecret(context, title, description);
    if (entered === undefined) return undefined;
    if (entered.length > 0) return entered;
    await context.ui.dialog.alert({
      title,
      message: "密码不能为空，请重新输入。",
    });
  }
}

async function askSecret(
  context: Plugin.Context,
  title: string,
  description?: string,
): Promise<string | undefined> {
  const entered = await promptSecret(context, title, description);
  if (entered === undefined) return undefined;
  return entered.length > 0 ? entered : undefined;
}

async function promptSecret(
  context: Plugin.Context,
  title: string,
  description?: string,
): Promise<string | undefined> {
  return context.ui.dialog.prompt({
    title,
    ...(description !== undefined ? { description } : {}),
  });
}

async function askPort(
  context: Plugin.Context,
  current: number,
): Promise<number | undefined> {
  while (true) {
    const entered = await askRequired(
      context,
      "SSH 端口",
      "默认 22",
      String(current),
    );
    if (entered === undefined) return undefined;
    const port = Number(entered);
    if (Number.isInteger(port) && port >= 1 && port <= 65535) return port;
    await context.ui.dialog.alert({
      title: "SSH 端口",
      message: "端口必须是 1-65535 的整数。",
    });
  }
}

function commandArguments(
  input: string | undefined,
  commandName: string,
): string {
  const text = (input ?? "").trim();
  if (text.length === 0) return "";
  const lower = text.toLowerCase();
  const slash = `/${commandName.toLowerCase()}`;
  if (lower === slash) return "";
  if (lower.startsWith(`${slash} `)) {
    return text.slice(slash.length).trim();
  }
  return text;
}

function findProfile(
  profiles: PublicProfile[],
  value: string,
): PublicProfile | undefined {
  const normalized = value.toLowerCase();
  return profiles.find(
    (profile) =>
      profile.id === value || profile.name.toLowerCase() === normalized,
  );
}

function sameTarget(profile: PublicProfile, input: ConnectFormInput): boolean {
  if (profile.user !== input.user) return false;
  if (profile.host.toLowerCase() !== input.host.toLowerCase()) return false;
  if (profile.port !== input.port) return false;
  if (input.privateKeyPath !== undefined) {
    return (
      profile.auth === "privateKey" &&
      profile.privateKeyPath === input.privateKeyPath
    );
  }
  return profile.auth === "password" && input.password !== undefined;
}

function profileTarget(profile: PublicProfile): string {
  return `${profile.user}@${profile.host.toLowerCase()}:${profile.port}`;
}

function connectionTarget(connection: ConnectionInfo): string {
  return `${connection.user}@${connection.host.toLowerCase()}:${connection.port}`;
}

function inputTarget(input: ConnectFormInput): string {
  return `${input.user}@${input.host.toLowerCase()}:${input.port}`;
}

function formatConnection(connection: ConnectionInfo): string {
  return `${connection.name}  ${connection.user}@${connection.host}:${connection.port}  idle=${formatDuration(connection.idleMs)}`;
}

function formatProfile(profile: PublicProfile, active: boolean): string {
  return `${active ? "[active] " : ""}${profile.name}  ${profile.user}@${profile.host}:${profile.port}`;
}

function formatDuration(milliseconds: number): string {
  const seconds = Math.max(0, Math.round(milliseconds / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (minutes < 60) return `${minutes}m${remainder}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h${minutes % 60}m`;
}
