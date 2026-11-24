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
import { formatWatchNotice, WatchService } from "./ssh/watch.js";
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
    const watches = new WatchService({
      manager,
      jobs,
      intervalMs: config.watchIntervalMs,
      maxIntervalMs: config.watchMaxIntervalMs,
      maxFailures: config.watchMaxFailures,
      ttlMs: config.watchTtlMs,
      logScanBytes: config.watchLogScanBytes,
      readyTimeoutMs: config.watchReadyTimeoutMs,
      readyIntervalMs: config.watchReadyIntervalMs,
      readyStableMs: config.watchReadyStableMs,
      notify: async (notice) => {
        await ctx.session.synthetic({
          sessionID: notice.sessionID as never,
          text: formatWatchNotice(notice),
          description:
            notice.event === "ready"
              ? "SSH watch ready"
              : notice.event === "timeout"
                ? "SSH watch timeout"
                : notice.event === "failed"
                  ? "SSH watch failed"
                  : notice.event === "canceled"
                    ? "SSH watch canceled"
                    : "SSH watch completed",
          resume: true,
          delivery: "queue",
          metadata: {
            source: "opencode-ssh",
            notifierId: notice.notifierId,
            watchIds: notice.targets.map((target) => target.watchId),
            remainingWatchIds: notice.remainingWatchIds,
            state: notice.state,
            event: notice.event,
          },
        });
      },
    });
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
      watches,
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
        watches.dispose();
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
