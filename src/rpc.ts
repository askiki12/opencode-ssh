import { Rpc } from "@opencode/plugin/rpc";

const HOST_KEY_POLICY = {
  type: "string",
  enum: ["accept-new", "strict", "insecure"],
} as const;

const CONNECT_INPUT = {
  type: "object",
  properties: {
    profileId: { type: "string" },
    name: { type: "string" },
    user: { type: "string" },
    host: { type: "string" },
    port: { type: "integer", minimum: 1, maximum: 65535 },
    password: { type: "string" },
    privateKeyPath: { type: "string" },
    privateKeyPassphrase: { type: "string" },
    sudoPassword: { type: "string" },
    hostKeyPolicy: HOST_KEY_POLICY,
    forceNew: { type: "boolean" },
  },
  additionalProperties: false,
} as const;

const PROFILE_PATCH_PROPERTIES = {
  name: { type: "string" },
  user: { type: "string" },
  host: { type: "string" },
  port: { type: "integer", minimum: 1, maximum: 65535 },
  password: { type: "string" },
  privateKeyPath: { type: "string" },
  privateKeyPassphrase: { type: "string" },
  sudoPassword: { type: "string" },
  hostKeyPolicy: HOST_KEY_POLICY,
  clearPassword: { type: "boolean" },
  clearPrivateKeyPath: { type: "boolean" },
  clearPrivateKeyPassphrase: { type: "boolean" },
  clearSudoPassword: { type: "boolean" },
} as const;

const PROFILE_ADD_INPUT = {
  type: "object",
  properties: {
    name: { type: "string" },
    user: { type: "string" },
    host: { type: "string" },
    port: { type: "integer", minimum: 1, maximum: 65535 },
    password: { type: "string" },
    privateKeyPath: { type: "string" },
    privateKeyPassphrase: { type: "string" },
    sudoPassword: { type: "string" },
    hostKeyPolicy: HOST_KEY_POLICY,
  },
  required: ["name", "user", "host"],
  additionalProperties: false,
} as const;

const PROFILE_UPDATE_INPUT = {
  type: "object",
  properties: {
    profileId: { type: "string" },
    ...PROFILE_PATCH_PROPERTIES,
  },
  required: ["profileId"],
  additionalProperties: false,
} as const;

const PROFILE_TEST_UPDATE_INPUT = {
  type: "object",
  properties: {
    profileId: { type: "string" },
    patch: {
      type: "object",
      properties: PROFILE_PATCH_PROPERTIES,
      additionalProperties: false,
    },
  },
  required: ["profileId", "patch"],
  additionalProperties: false,
} as const;

const PROFILE_ID_INPUT = {
  type: "object",
  properties: {
    profileId: { type: "string" },
  },
  required: ["profileId"],
  additionalProperties: false,
} as const;

const EMPTY_OBJECT = {
  type: "object",
  properties: {},
  additionalProperties: false,
} as const;

const ANY_OBJECT = {
  type: "object",
  additionalProperties: true,
} as const;

export const SshRpc = Rpc.define({
  id: "opencode-ssh",
  methods: {
    connectionsList: {
      input: EMPTY_OBJECT,
      output: ANY_OBJECT,
    },
    connectionsConnect: {
      input: CONNECT_INPUT,
      output: ANY_OBJECT,
    },
    connectionsDisconnect: {
      input: {
        type: "object",
        properties: { sshId: { type: "string" } },
        required: ["sshId"],
        additionalProperties: false,
      },
      output: ANY_OBJECT,
    },
    connectionsTest: {
      input: CONNECT_INPUT,
      output: ANY_OBJECT,
    },
    profilesList: {
      input: EMPTY_OBJECT,
      output: ANY_OBJECT,
    },
    profilesAdd: {
      input: PROFILE_ADD_INPUT,
      output: ANY_OBJECT,
    },
    profilesUpdate: {
      input: PROFILE_UPDATE_INPUT,
      output: ANY_OBJECT,
    },
    profilesRemove: {
      input: PROFILE_ID_INPUT,
      output: ANY_OBJECT,
    },
    profilesTestAndAdd: {
      input: PROFILE_ADD_INPUT,
      output: ANY_OBJECT,
    },
    profilesTestAndUpdate: {
      input: PROFILE_TEST_UPDATE_INPUT,
      output: ANY_OBJECT,
    },
    keysList: {
      input: EMPTY_OBJECT,
      output: ANY_OBJECT,
    },
  },
  events: {},
});

export type SshRpcDefinition = typeof SshRpc;
