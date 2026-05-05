import assert from "node:assert/strict";
import test from "node:test";
import {
  type GetVariablesResponse,
  type Group,
  type GroupAccess,
  type GroupGetParams,
  type GroupVaultAccess,
  type Item,
  type ItemCreateParams,
  type ItemOverview,
  type Vault,
  type VaultCreateParams,
  type VaultGetParams,
  type VaultListParams,
  type VaultOverview,
  type VaultUpdateParams,
  ItemCategory,
  ItemFieldType,
  ItemState,
  VaultAccessorType,
  VaultType,
} from "@1password/sdk";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { MemoryAuditLogger } from "./audit.js";
import type { ServerConfig } from "./config.js";
import {
  DESTRUCTIVE_ACTION_ACK,
  GENERATED_SECRET_ACK,
  PERMISSION_MUTATION_ACK,
  SECRET_REVEAL_ACK,
} from "./constants.js";
import type {
  OpScriptRunOptions,
  OpScriptRunner,
  OpSessionStatus,
  ScriptAllowlistReloadResult,
  ScriptAllowlist,
} from "./op-runner.js";
import { createOnePasswordMcpServer } from "./server.js";
import type { OnePasswordService } from "./service.js";

class FakeOnePasswordService implements OnePasswordService {
  public item: Item = {
    id: "item-1",
    title: "Root Login",
    category: ItemCategory.Login,
    vaultId: "vault-1",
    fields: [
      {
        id: "username",
        title: "username",
        fieldType: ItemFieldType.Text,
        value: "alice",
      },
      {
        id: "password",
        title: "password",
        fieldType: ItemFieldType.Concealed,
        value: "super-secret",
      },
    ],
    sections: [],
    notes: "internal note",
    tags: ["prod"],
    websites: [],
    version: 1,
    files: [],
    createdAt: new Date("2026-04-21T00:00:00.000Z"),
    updatedAt: new Date("2026-04-21T00:00:00.000Z"),
  };

  public async vaultList(_params?: VaultListParams): Promise<VaultOverview[]> {
    return [
      {
        id: "vault-1",
        title: "Primary",
        description: "Main vault",
        vaultType: VaultType.UserCreated,
        activeItemCount: 1,
        contentVersion: 1,
        attributeVersion: 1,
        createdAt: new Date("2026-04-21T00:00:00.000Z"),
        updatedAt: new Date("2026-04-21T00:00:00.000Z"),
      },
    ];
  }

  public async vaultGetOverview(_vaultId: string): Promise<VaultOverview> {
    return (await this.vaultList())[0]!;
  }

  public async vaultGet(_vaultId: string, _params: VaultGetParams): Promise<Vault> {
    return {
      id: "vault-1",
      title: "Primary",
      description: "Main vault",
      vaultType: VaultType.UserCreated,
      activeItemCount: 1,
      contentVersion: 1,
      attributeVersion: 1,
      access: [
        {
          vaultUuid: "vault-1",
          accessorType: VaultAccessorType.Group,
          accessorUuid: "group-1",
          permissions: 96,
        },
      ],
    };
  }

  public async vaultCreate(params: VaultCreateParams): Promise<Vault> {
    return {
      ...(await this.vaultGet("vault-created", {})),
      id: "vault-created",
      title: params.title,
      description: params.description ?? "",
    };
  }

  public async vaultUpdate(_vaultId: string, params: VaultUpdateParams): Promise<Vault> {
    return {
      ...(await this.vaultGet("vault-1", {})),
      title: params.title ?? "Primary",
      description: params.description ?? "Main vault",
    };
  }

  public async vaultDelete(_vaultId: string): Promise<void> {}

  public async groupGet(_groupId: string, _params: GroupGetParams): Promise<Group> {
    return {
      id: "group-1",
      title: "Operators",
      description: "Ops team",
      groupType: "userDefined",
      state: "active",
      vaultAccess: [
        {
          vaultUuid: "vault-1",
          accessorType: VaultAccessorType.Group,
          accessorUuid: "group-1",
          permissions: 96,
        },
      ],
    } as Group;
  }

  public async vaultGrantGroupPermissions(
    _vaultId: string,
    _permissions: GroupAccess[],
  ): Promise<void> {}

  public async vaultUpdateGroupPermissions(
    _permissions: GroupVaultAccess[],
  ): Promise<void> {}

  public async vaultRevokeGroupPermissions(
    _vaultId: string,
    _groupId: string,
  ): Promise<void> {}

  public async itemList(_vaultId: string): Promise<ItemOverview[]> {
    return [
      {
        id: this.item.id,
        title: this.item.title,
        category: this.item.category,
        vaultId: this.item.vaultId,
        websites: [],
        tags: ["prod"],
        createdAt: this.item.createdAt,
        updatedAt: this.item.updatedAt,
        state: ItemState.Active,
      },
    ];
  }

  public async itemGet(_vaultId: string, _itemId: string): Promise<Item> {
    return this.item;
  }

  public async itemCreate(params: ItemCreateParams): Promise<Item> {
    this.item = {
      ...this.item,
      id: "item-created",
      title: params.title,
      vaultId: params.vaultId,
      category: params.category,
      notes: params.notes ?? "",
      tags: params.tags ?? [],
      fields: params.fields ?? [],
      sections: params.sections ?? [],
      websites: params.websites ?? [],
    };
    return this.item;
  }

  public async itemPut(item: Item): Promise<Item> {
    this.item = item;
    return this.item;
  }

  public async itemDelete(_vaultId: string, _itemId: string): Promise<void> {}

  public async itemArchive(_vaultId: string, _itemId: string): Promise<void> {}

  public async environmentGetVariables(
    _environmentId: string,
  ): Promise<GetVariablesResponse> {
    return {
      variables: [
        {
          name: "API_KEY",
          value: "secret",
          masked: true,
        },
        {
          name: "SERVICE_URL",
          value: "https://example.test",
          masked: false,
        },
      ],
    };
  }

  public readonly secretResolveCalls: string[] = [];

  public async secretResolve(reference: string): Promise<string> {
    this.secretResolveCalls.push(reference);
    if (reference.includes("supabase-db-password")) {
      return "supabase-db-password-secret";
    }
    return "resolved-secret";
  }
}

class FakeOpScriptRunner implements OpScriptRunner {
  public resetCalls = 0;
  public reloadCalls = 0;
  public lastRunOptions?: OpScriptRunOptions;
  public nextStdout = "done\n";
  public nextStderr = "";
  public nextErrorMessage: string | undefined;
  public nextReloadError: Error | undefined;
  public reloadResult: ScriptAllowlistReloadResult = {
    previousAllowlistCount: 1,
    allowlistCount: 1,
    commandCount: 2,
  };
  public readonly allowlist: ScriptAllowlist = {
    path: "/workspace/.onepassword-mcp.json",
    workspaceRoot: "/workspace",
    commands: [
      {
        id: "deploy",
        description: "Deploy test command",
        command: "npm",
        args: ["run", "deploy"],
        cwd: ".",
        timeoutMs: 60_000,
        sensitiveOutput: false,
      },
      {
        id: "print-secret",
        description: "Print a sensitive value",
        command: "npm",
        args: ["run", "secret"],
        cwd: ".",
        timeoutMs: 60_000,
        sensitiveOutput: true,
      },
    ],
  };

  public async list(_workspaceRoot: string): Promise<ScriptAllowlist> {
    return this.allowlist;
  }

  public async run(
    workspaceRoot: string,
    commandId: string,
    options: OpScriptRunOptions = {},
  ) {
    if (!this.allowlist.commands.some((command) => command.id === commandId)) {
      throw new Error(`Allowlisted command ${commandId} not found.`);
    }
    this.lastRunOptions = options;
    const redact = (text: string) =>
      (options.secretRedactionValues ?? []).reduce(
        (redacted, secret) => redacted.replaceAll(secret, "[REDACTED]"),
        text,
      );

    return {
      commandId,
      workspaceRoot,
      cwd: workspaceRoot,
      command: "npm",
      args: ["run", commandId],
      sensitiveOutput: commandId === "print-secret",
      authMode: "manual-session" as const,
      refreshedAuth: false,
      stdout: redact(this.nextStdout),
      stderr: redact(this.nextStderr),
      errorMessage: this.nextErrorMessage ? redact(this.nextErrorMessage) : undefined,
      exitCode: 0,
      signal: null,
      timedOut: false,
      outputTruncated: false,
      durationMs: 12,
    };
  }

  public status(): OpSessionStatus {
    return {
      enabled: true,
      authMode: "manual-session",
      configuredAuthMode: "auto",
      accountConfigured: true,
      opCliPathConfigured: true,
      hasCachedSession: true,
      manualSessionKnownValid: true,
      manualSessionMarkedInvalid: false,
      desktopValidated: false,
    };
  }

  public reload(): ScriptAllowlistReloadResult {
    this.reloadCalls += 1;
    if (this.nextReloadError) {
      throw this.nextReloadError;
    }
    return this.reloadResult;
  }

  public reset(): void {
    this.resetCalls += 1;
  }
}

async function createClientAndServer(
  enableSecretReveal = false,
  options: {
    enableScriptRunner?: boolean;
    enableWrites?: boolean;
    enableDestructiveActions?: boolean;
    enablePermissionMutation?: boolean;
    scriptRunner?: OpScriptRunner;
  } = {},
) {
  const config: ServerConfig = {
    authMode: "desktop",
    account: "TestAccount",
    enableSecretReveal,
    enableWrites: options.enableWrites ?? false,
    enableDestructiveActions: options.enableDestructiveActions ?? false,
    enablePermissionMutation: options.enablePermissionMutation ?? false,
    enableScriptRunner: options.enableScriptRunner ?? false,
    scriptRunnerRoots: ["/workspace"],
    scriptRunnerAllowlistPaths: ["/workspace/.onepassword-mcp.json"],
    opCliPath: "op",
    opCliAuthMode: "auto",
    transport: "stdio",
    httpHost: "127.0.0.1",
    httpPort: 17337,
    httpPath: "/mcp",
    httpRequireBearer: false,
    httpAllowedOrigins: [],
    httpMaxSessions: 64,
    httpSessionIdleMs: 15 * 60_000,
    httpRequestTimeoutMs: 30_000,
    auditLogPath: "/tmp/onepassword-mcp-test-audit.jsonl",
    logLevel: "info",
    integrationName: "Test",
    integrationVersion: "0.1.0",
  };
  const auditLogger = new MemoryAuditLogger();
  const service = new FakeOnePasswordService();
  const server = createOnePasswordMcpServer(
    config,
    service,
    auditLogger,
    options.scriptRunner,
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({
    name: "test-client",
    version: "1.0.0",
  });

  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { auditLogger, client, service };
}

function readTextResource(
  entry:
    | { uri: string; text: string; mimeType?: string; _meta?: Record<string, unknown> }
    | { uri: string; blob: string; mimeType?: string; _meta?: Record<string, unknown> }
    | undefined,
): string {
  return entry && "text" in entry ? entry.text : "";
}

test("registers expected tools", async () => {
  const { client } = await createClientAndServer();
  const tools = await client.listTools();
  const passwordReadTool = tools.tools.find((tool) => tool.name === "password_read");
  const secretRevealTool = tools.tools.find((tool) => tool.name === "secret_reveal");
  const passwordReadProperties =
    (passwordReadTool?.inputSchema as { properties?: Record<string, unknown> })
      .properties ?? {};
  const secretRevealProperties =
    (secretRevealTool?.inputSchema as { properties?: Record<string, unknown> })
      .properties ?? {};
  const passwordReadDescription = passwordReadTool?.description ?? "";
  const secretRevealDescription = secretRevealTool?.description ?? "";

  assert(tools.tools.some((tool) => tool.name === "sdk_capabilities"));
  assert(tools.tools.some((tool) => tool.name === "secret_reveal"));
  assert(tools.tools.some((tool) => tool.name === "vault_permissions_get"));
  assert(tools.tools.some((tool) => tool.name === "password_generate"));
  assert(tools.tools.some((tool) => tool.name === "password_read"));
  assert(tools.tools.some((tool) => tool.name === "op_session_status"));
  assert("secretReference" in passwordReadProperties);
  assert("vaultId" in passwordReadProperties);
  assert("reference" in secretRevealProperties);
  assert("fieldId" in secretRevealProperties);
  assert.match(passwordReadDescription, /reveal=true will fail/);
  assert.match(passwordReadDescription, /op_script_run/);
  assert.match(secretRevealDescription, /Plaintext reveal is disabled/);
  assert.match(secretRevealDescription, /op_script_run/);
  assert(!tools.tools.some((tool) => tool.name === "password_update"));
  assert(!tools.tools.some((tool) => tool.name === "op_script_run"));
  assert(!tools.tools.some((tool) => tool.name === "op_script_reload_allowlists"));
});

test("registers write tools only when enabled", async () => {
  const { client } = await createClientAndServer(false, { enableWrites: true });
  const tools = await client.listTools();

  assert(tools.tools.some((tool) => tool.name === "password_create"));
  assert(tools.tools.some((tool) => tool.name === "password_update"));
  assert(tools.tools.some((tool) => tool.name === "vault_create"));
  assert(tools.tools.some((tool) => tool.name === "item_update"));
  assert(!tools.tools.some((tool) => tool.name === "item_delete"));
});

test("registers script runner tools when enabled", async () => {
  const { client } = await createClientAndServer(false, {
    enableScriptRunner: true,
    scriptRunner: new FakeOpScriptRunner(),
  });
  const tools = await client.listTools();

  assert(tools.tools.some((tool) => tool.name === "op_script_list"));
  assert(tools.tools.some((tool) => tool.name === "op_script_reload_allowlists"));
  assert(tools.tools.some((tool) => tool.name === "op_script_run"));
  assert(tools.tools.some((tool) => tool.name === "op_session_status"));
  assert(tools.tools.some((tool) => tool.name === "op_session_reset"));

  const secretRevealTool = tools.tools.find((tool) => tool.name === "secret_reveal");
  assert.match(secretRevealTool?.description ?? "", /Plaintext reveal is disabled/);
  assert.match(secretRevealTool?.description ?? "", /op_script_list/);
  assert.match(secretRevealTool?.description ?? "", /envSecretRefs/);
});

test("plaintext reveal tool descriptions reflect enabled runtime gates", async () => {
  const { client } = await createClientAndServer(true, {
    enableScriptRunner: true,
    scriptRunner: new FakeOpScriptRunner(),
  });
  const tools = await client.listTools();
  const passwordReadTool = tools.tools.find((tool) => tool.name === "password_read");
  const secretRevealTool = tools.tools.find((tool) => tool.name === "secret_reveal");

  assert.match(passwordReadTool?.description ?? "", /Plaintext reveal is enabled/);
  assert.doesNotMatch(passwordReadTool?.description ?? "", /will fail/);
  assert.match(secretRevealTool?.description ?? "", /Return a secret in plaintext/);
  assert.doesNotMatch(secretRevealTool?.description ?? "", /Plaintext reveal is disabled/);
  assert.match(secretRevealTool?.description ?? "", /op_script_run/);
});

test("op_session_status exposes runtime gates when script runner is disabled", async () => {
  const { client } = await createClientAndServer(false);
  const status = await client.callTool({
    name: "op_session_status",
    arguments: {},
  });
  const payload = status.structuredContent as {
    secretRevealEnabled: boolean;
    writesEnabled: boolean;
    destructiveActionsEnabled: boolean;
    permissionMutationEnabled: boolean;
    scriptRunnerEnabled: boolean;
    scriptRunnerAllowlistCount: number;
  };

  assert.equal(payload.secretRevealEnabled, false);
  assert.equal(payload.writesEnabled, false);
  assert.equal(payload.destructiveActionsEnabled, false);
  assert.equal(payload.permissionMutationEnabled, false);
  assert.equal(payload.scriptRunnerEnabled, false);
  assert.equal(payload.scriptRunnerAllowlistCount, 1);
});

test("registers prompts and resources", async () => {
  const { client } = await createClientAndServer();
  const prompts = await client.listPrompts();
  const resources = await client.listResources();
  const templates = await client.listResourceTemplates();

  assert(prompts.prompts.some((prompt) => prompt.name === "credential-rotation"));
  assert(prompts.prompts.some((prompt) => prompt.name === "vault-audit"));
  assert(resources.resources.some((resource) => resource.uri === "onepassword://config"));
  assert(resources.resources.some((resource) => resource.uri === "onepassword://vaults"));
  assert(
    templates.resourceTemplates.some((template) =>
      template.uriTemplate.includes("onepassword://vaults/{vaultId}/items"),
    ),
  );
});

test("can read fixed and templated resources", async () => {
  const { client } = await createClientAndServer();
  const configResource = await client.readResource({ uri: "onepassword://config" });
  const vaultItemsResource = await client.readResource({
    uri: "onepassword://vaults/vault-1/items",
  });

  const configText = readTextResource(configResource.contents[0]);
  const vaultItemsText = readTextResource(vaultItemsResource.contents[0]);
  assert.match(configText, /supportedTools/);
  assert.match(vaultItemsText, /Root Login/);
});

test("getPrompt returns actionable prompt text", async () => {
  const { client } = await createClientAndServer();
  const prompt = await client.getPrompt({
    name: "environment-inspection",
    arguments: {
      environmentId: "env-1",
      variableName: "API_KEY",
    },
  });

  assert.equal(prompt.messages[0]?.role, "user");
  assert.match((prompt.messages[0]?.content as { text?: string }).text ?? "", /env-1/);
  assert.match(
    (prompt.messages[0]?.content as { text?: string }).text ?? "",
    /environment_get_variable/,
  );
});

test("item metadata redacts field values", async () => {
  const { client } = await createClientAndServer();
  const result = await client.callTool({
    name: "item_get_metadata",
    arguments: {
      vaultId: "vault-1",
      itemId: "item-1",
    },
  });
  const payload = result.structuredContent as {
    item: {
      notesState: string;
      fields: Array<{ id: string; valueState: string }>;
    };
  };

  assert.equal(payload.item.notesState, "redacted");
  assert.equal(payload.item.fields[0]?.valueState, "redacted");
  assert.equal(payload.item.fields[1]?.valueState, "redacted");
});

test("secret reveal is blocked when disabled", async () => {
  const { client } = await createClientAndServer(false);
  const result = await client.callTool({
    name: "secret_reveal",
    arguments: {
      reason: "Need to test",
      acknowledgePlaintext: "I_UNDERSTAND_THIS_RETURNS_SECRET_PLAINTEXT",
      reference: "op://vault/item/password",
    },
  });

  assert.equal(result.isError, true);
  const textContent = result.content as Array<{ type: string; text?: string }>;
  assert.match(textContent[0]?.text ?? "", /OP_MCP_ENABLE_SECRET_REVEAL=true/);
  assert.match(textContent[0]?.text ?? "", /--enable-secret-reveal=true/);
  assert.match(textContent[0]?.text ?? "", /op_script_run/);
  assert.match(textContent[0]?.text ?? "", /envSecretRefs/);
});

test("password read stays redacted by default", async () => {
  const { client } = await createClientAndServer();
  const result = await client.callTool({
    name: "password_read",
    arguments: {
      vaultId: "vault-1",
      itemId: "item-1",
    },
  });

  const payload = result.structuredContent as {
    mode: string;
    valueState: string;
    field: string;
    secretConsumptionGuidance: {
      preferredPath: string;
      plaintextRevealEnabled: boolean;
      scriptRunnerEnabled: boolean;
    };
  };

  assert.equal(payload.mode, "item-field");
  assert.equal(payload.valueState, "redacted");
  assert.equal(payload.field, "password");
  assert.equal(payload.secretConsumptionGuidance.preferredPath, "op_script_run");
  assert.equal(payload.secretConsumptionGuidance.plaintextRevealEnabled, false);
});

test("password read reveal is blocked when disabled", async () => {
  const { client } = await createClientAndServer(false);
  const result = await client.callTool({
    name: "password_read",
    arguments: {
      vaultId: "vault-1",
      itemId: "item-1",
      reveal: true,
      reason: "Need local debugging",
      acknowledgePlaintext: "I_UNDERSTAND_THIS_RETURNS_SECRET_PLAINTEXT",
    },
  });

  assert.equal(result.isError, true);
  const textContent = result.content as Array<{ type: string; text?: string }>;
  assert.match(textContent[0]?.text ?? "", /op_script_run/);
  assert.match(textContent[0]?.text ?? "", /envSecretRefs/);
});

test("password read reveal succeeds and audits when enabled", async () => {
  const { client, auditLogger } = await createClientAndServer(true);
  const result = await client.callTool({
    name: "password_read",
    arguments: {
      vaultId: "vault-1",
      itemId: "item-1",
      reveal: true,
      reason: "Need local debugging",
      acknowledgePlaintext: "I_UNDERSTAND_THIS_RETURNS_SECRET_PLAINTEXT",
    },
  });

  const textContent = result.content as Array<{ type: string; text?: string }>;
  assert.equal(textContent[0]?.text, "super-secret");
  assert.equal(auditLogger.events.at(-1)?.action, "password_read");
  assert.equal(auditLogger.events.at(-1)?.outcome, "success");
});

test("password generators return plaintext values", async () => {
  const { client, auditLogger } = await createClientAndServer();
  const missingAck = await client.callTool({
    name: "password_generate",
    arguments: {
      length: 20,
      includeSymbols: false,
    },
  });
  assert.equal(missingAck.isError, true);

  const randomResult = await client.callTool({
    name: "password_generate",
    arguments: {
      length: 20,
      includeSymbols: false,
      reason: "Need a generated password for a test item",
      acknowledgePlaintext: GENERATED_SECRET_ACK,
    },
  });
  const memorableResult = await client.callTool({
    name: "password_generate_memorable",
    arguments: {
      words: 4,
      separator: ".",
      includeNumber: false,
      reason: "Need a memorable generated password for a test item",
      acknowledgePlaintext: GENERATED_SECRET_ACK,
    },
  });

  const randomText = (randomResult.content as Array<{ text?: string }>)[0]?.text ?? "";
  const memorableText =
    (memorableResult.content as Array<{ text?: string }>)[0]?.text ?? "";
  assert.equal(randomText.length, 20);
  assert.match(memorableText, /\./);
  assert.equal(auditLogger.events.at(-2)?.action, "password_generate");
  assert.equal(auditLogger.events.at(-1)?.action, "password_generate_memorable");
});

test("password create stores a generated secret and returns redacted metadata", async () => {
  const { client, auditLogger, service } = await createClientAndServer(false, {
    enableWrites: true,
  });
  const result = await client.callTool({
    name: "password_create",
    arguments: {
      vaultId: "vault-1",
      title: "Generated Login",
      username: "alice",
      mode: "random",
      randomLength: 18,
    },
  });

  const payload = result.structuredContent as {
    item: {
      title: string;
      fields: Array<{ valueState: string }>;
    };
    generatedSecret: boolean;
    secretLength: number;
  };

  assert.equal(payload.item.title, "Generated Login");
  assert.equal(payload.item.fields[1]?.valueState, "redacted");
  assert.equal(payload.generatedSecret, true);
  assert.equal(payload.secretLength, 18);
  assert.equal(service.item.title, "Generated Login");
  assert.equal(auditLogger.events.at(-1)?.action, "password_create");
});

test("password update can replace a field with a provided password", async () => {
  const { client, auditLogger, service } = await createClientAndServer(false, {
    enableWrites: true,
  });
  const result = await client.callTool({
    name: "password_update",
    arguments: {
      vaultId: "vault-1",
      itemId: "item-1",
      password: "rotated-secret",
      mode: "provided",
    },
  });

  const payload = result.structuredContent as {
    item: {
      fields: Array<{ valueState: string }>;
    };
    generatedSecret: boolean;
    passwordSource: string;
  };

  assert.equal(payload.item.fields[1]?.valueState, "redacted");
  assert.equal(payload.generatedSecret, false);
  assert.equal(payload.passwordSource, "provided");
  assert.equal(findPasswordValue(service.item, "password"), "rotated-secret");
  assert.equal(auditLogger.events.at(-1)?.action, "password_update");
});

test("destructive tools require per-call acknowledgement and audit accepted calls", async () => {
  const { client, auditLogger } = await createClientAndServer(false, {
    enableDestructiveActions: true,
  });

  const missingAck = await client.callTool({
    name: "item_delete",
    arguments: {
      vaultId: "vault-1",
      itemId: "item-1",
      reason: "Remove a duplicate test item",
    },
  });
  assert.equal(missingAck.isError, true);

  const deleted = await client.callTool({
    name: "item_delete",
    arguments: {
      vaultId: "vault-1",
      itemId: "item-1",
      reason: "Remove a duplicate test item",
      acknowledgeDestructive: DESTRUCTIVE_ACTION_ACK,
    },
  });

  assert.notEqual(deleted.isError, true);
  assert.equal(auditLogger.events.at(-1)?.action, "item_delete");
  assert.equal(auditLogger.events.at(-1)?.metadata.reason, "Remove a duplicate test item");
});

test("permission mutation tools require per-call acknowledgement and audit accepted calls", async () => {
  const { client, auditLogger } = await createClientAndServer(false, {
    enablePermissionMutation: true,
  });

  const missingAck = await client.callTool({
    name: "vault_permissions_grant_group",
    arguments: {
      vaultId: "vault-1",
      groupId: "group-1",
      permissions: ["READ_ITEMS"],
      reason: "Grant read access for support coverage",
    },
  });
  assert.equal(missingAck.isError, true);

  const granted = await client.callTool({
    name: "vault_permissions_grant_group",
    arguments: {
      vaultId: "vault-1",
      groupId: "group-1",
      permissions: ["READ_ITEMS"],
      reason: "Grant read access for support coverage",
      acknowledgePermissionMutation: PERMISSION_MUTATION_ACK,
    },
  });

  assert.notEqual(granted.isError, true);
  assert.equal(auditLogger.events.at(-1)?.action, "vault_permissions_grant_group");
  assert.equal(
    auditLogger.events.at(-1)?.metadata.reason,
    "Grant read access for support coverage",
  );
});

test("environment variable listing supports filtering and stays redacted", async () => {
  const { client } = await createClientAndServer();
  const result = await client.callTool({
    name: "environment_get_variables",
    arguments: {
      environmentId: "env-1",
      query: "api",
    },
  });

  const payload = result.structuredContent as {
    totalMatched: number;
    variables: Array<{ name: string; valueState: string }>;
  };

  assert.equal(payload.totalMatched, 1);
  assert.equal(payload.variables[0]?.name, "API_KEY");
  assert.equal(payload.variables[0]?.valueState, "redacted");
});

test("environment variable reveal is blocked when disabled", async () => {
  const { client } = await createClientAndServer(false);
  const result = await client.callTool({
    name: "environment_reveal_variable",
    arguments: {
      environmentId: "env-1",
      name: "API_KEY",
      reason: "Need to test a deployment locally",
      acknowledgePlaintext: "I_UNDERSTAND_THIS_RETURNS_SECRET_PLAINTEXT",
    },
  });

  assert.equal(result.isError, true);
});

test("environment variable reveal succeeds and audits when enabled", async () => {
  const { client, auditLogger } = await createClientAndServer(true);
  const result = await client.callTool({
    name: "environment_reveal_variable",
    arguments: {
      environmentId: "env-1",
      name: "API_KEY",
      reason: "Need the value for a manual recovery flow",
      acknowledgePlaintext: "I_UNDERSTAND_THIS_RETURNS_SECRET_PLAINTEXT",
    },
  });

  const textContent = result.content as Array<{ type: string; text?: string }>;
  assert.equal(textContent[0]?.type, "text");
  assert.equal(textContent[0]?.text, "secret");
  assert.equal(auditLogger.events.at(-1)?.action, "environment_reveal_variable");
  assert.equal(auditLogger.events.at(-1)?.outcome, "success");
});

test("secret reveal succeeds and audits when enabled", async () => {
  const { client, auditLogger } = await createClientAndServer(true);
  const result = await client.callTool({
    name: "secret_reveal",
    arguments: {
      reason: "Need to rotate the credential",
      acknowledgePlaintext: "I_UNDERSTAND_THIS_RETURNS_SECRET_PLAINTEXT",
      reference: "op://vault/item/password",
    },
  });

  assert.notEqual(result.isError, true);
  const textContent = result.content as Array<{ type: string; text?: string }>;
  assert.equal(textContent[0]?.type, "text");
  assert.equal(textContent[0]?.text, "resolved-secret");
  assert.equal(auditLogger.events.length, 1);
  assert.equal(auditLogger.events[0]?.action, "secret_reveal");
  assert.equal(auditLogger.events[0]?.outcome, "success");
});

test("script runner lists and runs allowlisted commands with audit", async () => {
  const scriptRunner = new FakeOpScriptRunner();
  const { client, auditLogger } = await createClientAndServer(false, {
    enableScriptRunner: true,
    scriptRunner,
  });

  const listed = await client.callTool({
    name: "op_script_list",
    arguments: {
      workspaceRoot: "/workspace",
    },
  });
  const listPayload = listed.structuredContent as {
    commands: Array<{ id: string; sensitiveOutput: boolean }>;
  };
  assert.equal(listPayload.commands[0]?.id, "deploy");

  const run = await client.callTool({
    name: "op_script_run",
    arguments: {
      workspaceRoot: "/workspace",
      commandId: "deploy",
      reason: "Need to run deploy from an MCP client",
    },
  });
  const textContent = run.content as Array<{ type: string; text?: string }>;
  const payload = run.structuredContent as {
    exitCode: number;
    authMode: string;
    outputReturned: boolean;
    outputState: string;
  };

  assert.equal(run.isError, false);
  assert.match(textContent[0]?.text ?? "", /withheld/);
  assert.equal(payload.exitCode, 0);
  assert.equal(payload.authMode, "manual-session");
  assert.equal(payload.outputReturned, false);
  assert.equal(payload.outputState, "withheld");
  assert.equal(auditLogger.events.at(-1)?.action, "op_script_run");
  assert.equal(auditLogger.events.at(-1)?.outcome, "success");
});

test("script runner reloads allowlists with audit", async () => {
  const scriptRunner = new FakeOpScriptRunner();
  const { client, auditLogger } = await createClientAndServer(false, {
    enableScriptRunner: true,
    scriptRunner,
  });

  const result = await client.callTool({
    name: "op_script_reload_allowlists",
    arguments: {
      reason: "Need to pick up an edited allowlist file",
    },
  });
  const payload = result.structuredContent as {
    reloaded: boolean;
    configuredAllowlistPathCount: number;
    previousAllowlistCount: number;
    allowlistCount: number;
    commandCount: number;
  };
  const auditEvent = auditLogger.events.at(-1);

  assert.notEqual(result.isError, true);
  assert.equal(scriptRunner.reloadCalls, 1);
  assert.equal(payload.reloaded, true);
  assert.equal(payload.configuredAllowlistPathCount, 1);
  assert.equal(payload.previousAllowlistCount, 1);
  assert.equal(payload.allowlistCount, 1);
  assert.equal(payload.commandCount, 2);
  assert.equal(auditEvent?.action, "op_script_reload_allowlists");
  assert.equal(auditEvent?.outcome, "success");
  assert.equal(
    auditEvent?.metadata.reason,
    "Need to pick up an edited allowlist file",
  );
});

test("script runner audits failed allowlist reloads", async () => {
  const scriptRunner = new FakeOpScriptRunner();
  scriptRunner.nextReloadError = new Error("invalid allowlist");
  const { client, auditLogger } = await createClientAndServer(false, {
    enableScriptRunner: true,
    scriptRunner,
  });

  const result = await client.callTool({
    name: "op_script_reload_allowlists",
    arguments: {
      reason: "Need to validate a changed allowlist file",
    },
  });
  const auditEvent = auditLogger.events.at(-1);

  assert.equal(result.isError, true);
  assert.equal(scriptRunner.reloadCalls, 1);
  assert.equal(auditEvent?.action, "op_script_reload_allowlists");
  assert.equal(auditEvent?.outcome, "error");
  assert.match(auditEvent?.errorMessage ?? "", /invalid allowlist/);
});

test("script runner injects 1Password secrets without returning plaintext", async () => {
  const scriptRunner = new FakeOpScriptRunner();
  scriptRunner.nextStdout = "connected with supabase-db-password-secret\n";
  const { client, auditLogger, service } = await createClientAndServer(false, {
    enableScriptRunner: true,
    scriptRunner,
  });

  const result = await client.callTool({
    name: "op_script_run",
    arguments: {
      workspaceRoot: "/workspace",
      commandId: "deploy",
      reason: "Need Supabase migration secrets",
      envSecretRefs: {
        SUPABASE_DB_PASSWORD: "op://vault/supabase-db-password/password",
      },
      returnOutput: true,
      acknowledgePlaintext: SECRET_REVEAL_ACK,
    },
  });
  const payload = result.structuredContent as {
    stdout: string;
    envSecretRefCount: number;
    injectedSecretEnvVars: string[];
  };
  const auditPayload = JSON.stringify(auditLogger.events.at(-1));

  assert.equal(result.isError, false);
  assert.equal(service.secretResolveCalls[0], "op://vault/supabase-db-password/password");
  assert.equal(
    scriptRunner.lastRunOptions?.extraEnv?.SUPABASE_DB_PASSWORD,
    "supabase-db-password-secret",
  );
  assert.deepEqual(scriptRunner.lastRunOptions?.secretRedactionValues, [
    "supabase-db-password-secret",
  ]);
  assert.equal(payload.stdout, "connected with [REDACTED]\n");
  assert.equal(payload.envSecretRefCount, 1);
  assert.deepEqual(payload.injectedSecretEnvVars, ["SUPABASE_DB_PASSWORD"]);
  assert.match(auditPayload, /"referenceScheme":"op"/);
  assert.match(auditPayload, /"referenceHash":"[a-f0-9]{64}"/);
  assert(!auditPayload.includes("op://vault/supabase-db-password/password"));
  assert(!auditPayload.includes("supabase-db-password-secret"));
});

test("script runner refuses output for injected secrets without acknowledgement", async () => {
  const scriptRunner = new FakeOpScriptRunner();
  const { client, service } = await createClientAndServer(false, {
    enableScriptRunner: true,
    scriptRunner,
  });

  const result = await client.callTool({
    name: "op_script_run",
    arguments: {
      workspaceRoot: "/workspace",
      commandId: "deploy",
      reason: "Need Supabase migration secrets",
      envSecretRefs: {
        SUPABASE_DB_PASSWORD: "op://vault/supabase-db-password/password",
      },
      returnOutput: true,
    },
  });

  assert.equal(result.isError, true);
  assert.equal(service.secretResolveCalls.length, 0);
  assert.equal(scriptRunner.lastRunOptions, undefined);
});

test("script runner refuses non-allowlisted commands", async () => {
  const { client, service } = await createClientAndServer(false, {
    enableScriptRunner: true,
    scriptRunner: new FakeOpScriptRunner(),
  });

  const result = await client.callTool({
    name: "op_script_run",
    arguments: {
      workspaceRoot: "/workspace",
      commandId: "missing",
      reason: "Need to verify allowlist refusal",
      envSecretRefs: {
        SUPABASE_DB_PASSWORD: "op://vault/supabase-db-password/password",
      },
    },
  });

  assert.equal(result.isError, true);
  assert.equal(service.secretResolveCalls.length, 0);
});

test("script runner only returns command output with reveal acknowledgement", async () => {
  const scriptRunner = new FakeOpScriptRunner();
  const { client } = await createClientAndServer(true, {
    enableScriptRunner: true,
    scriptRunner,
  });

  const run = await client.callTool({
    name: "op_script_run",
    arguments: {
      workspaceRoot: "/workspace",
      commandId: "deploy",
      reason: "Need to inspect command output",
      returnOutput: true,
      acknowledgePlaintext: "I_UNDERSTAND_THIS_RETURNS_SECRET_PLAINTEXT",
    },
  });
  const payload = run.structuredContent as {
    stdout: string;
    outputReturned: boolean;
  };

  assert.equal(run.isError, false);
  assert.equal(payload.outputReturned, true);
  assert.equal(payload.stdout, "done\n");
});

test("script runner blocks output return without reveal acknowledgement", async () => {
  const { client } = await createClientAndServer(false, {
    enableScriptRunner: true,
    scriptRunner: new FakeOpScriptRunner(),
  });

  const result = await client.callTool({
    name: "op_script_run",
    arguments: {
      workspaceRoot: "/workspace",
      commandId: "print-secret",
      reason: "Need to inspect sensitive command output",
      returnOutput: true,
    },
  });

  assert.equal(result.isError, true);
});

test("script runner exposes and resets non-secret session status", async () => {
  const scriptRunner = new FakeOpScriptRunner();
  const { client } = await createClientAndServer(false, {
    enableScriptRunner: true,
    scriptRunner,
  });

  const status = await client.callTool({
    name: "op_session_status",
    arguments: {},
  });
  const statusPayload = status.structuredContent as {
    hasCachedSession: boolean;
    secretRevealEnabled: boolean;
    scriptRunnerEnabled: boolean;
    scriptRunnerAllowlistCount: number;
    secretConsumptionGuidance: {
      preferredPath: string;
      scriptRunnerEnabled: boolean;
    };
  };
  assert.equal(statusPayload.hasCachedSession, true);
  assert.equal(statusPayload.secretRevealEnabled, false);
  assert.equal(statusPayload.scriptRunnerEnabled, true);
  assert.equal(statusPayload.scriptRunnerAllowlistCount, 1);
  assert.equal(statusPayload.secretConsumptionGuidance.preferredPath, "op_script_run");
  assert.equal(statusPayload.secretConsumptionGuidance.scriptRunnerEnabled, true);

  await client.callTool({
    name: "op_session_reset",
    arguments: {},
  });
  assert.equal(scriptRunner.resetCalls, 1);
});

function findPasswordValue(item: Item, fieldId: string): string | undefined {
  return item.fields.find((field) => field.id === fieldId)?.value;
}
