import { Plugin } from "@opencode/plugin";
import path from "node:path";
import { resolveConfig } from "./config.js";
import { SecretBox } from "./crypto.js";
import { KnownHostsStore } from "./known-hosts.js";
import { ProfileStore } from "./profiles.js";
import { SshRpc } from "./rpc.js";
import { createRpcHandlers } from "./rpc-handlers.js";
import { ConnectionManager } from "./ssh/manager.js";
import { JobService } from "./ssh/jobs.js";
import { SearchService } from "./ssh/search.js";
import {
  formatJobNotice,
  WatchNotifier,
  type PersistedWatch,
} from "./ssh/watch-notifier.js";
import { createSshTools } from "./tools/definitions.js";

export default Plugin.define({
  id: "opencode-ssh",
  async setup(ctx) {
    const config = resolveConfig(ctx.options, ctx.location.directory);
    const secretBox = new SecretBox(config.dataDir);
    // ctx.storage is SQLite-backed and managed by OpenCode. ProfileStore
    // lazily creates the "profiles" entry on first write.
    const profiles = new ProfileStore(ctx.storage, secretBox);
    await profiles.ensureInitialized();
    const knownHosts = new KnownHostsStore(
      path.join(config.dataDir, "known_hosts.json"),
    );
    const manager = new ConnectionManager(config, profiles, knownHosts);
    const search = new SearchService(manager);
    const jobs = new JobService(manager);
    const watchNotifier = new WatchNotifier({
      jobs,
      logLines: config.jobNotifyLogLines,
      initialIntervalMs: config.jobNotifyIntervalMs,
      readyIntervalMs: config.jobReadyIntervalMs,
      readyTimeoutMs: config.jobReadyTimeoutMs,
      readyStableMs: config.jobReadyStableMs,
      watchAfterReady: config.jobWatchAfterReady,
      runProbe: async ({ sshId, jobDir, command, timeoutMs }) => {
        try {
          const result = await manager.exec({
            sshId,
            command,
            cwd: jobDir,
            timeoutMs,
            maxOutputBytes: 8 * 1024,
          });
          return result.exitCode === 0;
        } catch {
          return false;
        }
      },
      storage: {
        load: async () => {
          const stored = await ctx.storage.get("watchSubscriptions");
          return Array.isArray(stored)
            ? (stored as PersistedWatch[])
            : undefined;
        },
        save: async (watches) => {
          await ctx.storage.set("watchSubscriptions", watches as never);
        },
      },
      notify: async (notice) => {
        await ctx.session.synthetic({
          sessionID: notice.sessionID as never,
          text: formatJobNotice(notice),
          description:
            notice.event === "ready"
              ? "SSH service ready"
              : notice.event === "timeout"
                ? "SSH service timeout"
                : notice.event === "service-exited"
                  ? "SSH service exited"
                  : notice.event === "monitor-stopped"
                    ? "SSH job monitor stopped"
                    : "SSH job finished",
          resume: true,
          delivery: "queue",
          metadata: {
            source: "opencode-ssh",
            ...(notice.jobId !== undefined ? { jobId: notice.jobId } : {}),
            watchId: notice.watchId,
            kind: notice.kind,
            state: notice.state,
            event: notice.event,
            ...(notice.readiness !== undefined
              ? { readiness: notice.readiness }
              : {}),
          },
        });
      },
    });
    await watchNotifier.initialize();
    const rpcRegistration = await ctx.rpc.register(
      SshRpc,
      createRpcHandlers({ manager, profiles }),
    );
    const tools = createSshTools({
      manager,
      profiles,
      config,
      search,
      jobs,
      watchNotifier,
      assertPermission: async (request) => {
        await ctx.permission.assert({
          // The plugin tool context carries branded ids. They are strings at
          // runtime; the casts keep this adapter independent of OpenCode's
          // internal schema package.
          sessionID: request.sessionID as never,
          agent: request.agent as never,
          source: {
            type: "tool",
            messageID: request.messageID as never,
            id: request.toolCallID as never,
          },
          action: "ssh",
          resources: [request.resource],
          save: [request.resource],
        });
      },
    });

    const registration = await ctx.tool.transform((editor) => {
      editor.namespace({
        name: "ssh",
        description:
          "Persistent SSH connections, encrypted profiles, and remote command execution.",
      });
      for (const tool of tools) editor.add(tool);
    });

    return async () => {
      try {
        await watchNotifier.dispose();
        await registration.dispose();
      } finally {
        try {
          await rpcRegistration.dispose();
        } finally {
          await manager.dispose();
        }
      }
    };
  },
});
