import assert from "node:assert/strict";
import { tmpdir } from "node:os";
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
  UNRESTRICTED_RUNNER_ACK,
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
import type {
  UnrestrictedAuthorizationRequired,
  UnrestrictedRunResult,
  UnrestrictedRunner,
  UnrestrictedRunnerStatus,
} from "./unrestricted-runner.js";
import { UnrestrictedApprovalManager } from "./unrestricted-runner.js";

class FakeOnePasswordService implements OnePasswordService {
  public vaultListCalls = 0;

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
    this.vaultListCalls += 1;
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

  public async runCommand(
    workspaceRoot: string,
    command: string,
    options: OpScriptRunOptions = {},
  ) {
    this.lastRunOptions = options;
    const redact = (text: string) =>
      (options.secretRedactionValues ?? []).reduce(
        (redacted, secret) => redacted.replaceAll(secret, "[REDACTED]"),
        text,
      );

    return {
      workspaceRoot,
      cwd: workspaceRoot,
      command,
      shell: "/bin/sh",
      shellArgs: ["-c", command],
      sensitiveOutput: true as const,
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
      loadedAllowlistCount: this.reloadResult.allowlistCount,
      loadedAllowlistCommandCount: this.reloadResult.commandCount,
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

class FakeUnrestrictedRunner implements UnrestrictedRunner {
  public nextAuthorization?: UnrestrictedAuthorizationRequired;
  public lastCommand?: string;
  public nextStdout = "unrestricted done\n";
  public nextStderr = "";
  public nextErrorMessage: string | undefined;
  public nextExitCode: number | null = 0;

  public async authorization(
    _workspaceRoot: string,
  ): Promise<UnrestrictedAuthorizationRequired | undefined> {
    return this.nextAuthorization;
  }

  public async run(workspaceRoot: string, command: string): Promise<UnrestrictedRunResult> {
    this.lastCommand = command;
    return {
      workspaceRoot,
      configuredRoot: "/workspace",
      cwd: workspaceRoot,
      command,
      shell: "/bin/sh",
      shellArgs: ["-c", command],
      sensitiveOutput: true,
      stdout: this.nextStdout,
      stderr: this.nextStderr,
      errorMessage: this.nextErrorMessage,
      exitCode: this.nextExitCode,
      signal: null,
      timedOut: false,
      outputTruncated: false,
      durationMs: 21,
    };
  }

  public status(): UnrestrictedRunnerStatus {
    return {
      enabled: true,
      configuredRootCount: 1,
      requireSessionApproval: true,
      approvalServerAvailable: true,
      approvedRootCount: this.nextAuthorization ? 0 : 1,
      approvalTtlMs: 12 * 60 * 60_000,
      commandTimeoutMs: 600_000,
    };
  }
}

async function createClientAndServer(
  enableSecretReveal = false,
  options: {
    authMode?: ServerConfig["authMode"];
    enableScriptRunner?: boolean;
    enableUnrestrictedRunner?: boolean;
    enableWrites?: boolean;
    enableDestructiveActions?: boolean;
    enablePermissionMutation?: boolean;
    enableUnrestrictedScriptRunner?: boolean;
    enableDiagnostics?: boolean;
    scriptRunner?: OpScriptRunner;
    unrestrictedRunner?: UnrestrictedRunner;
    approvalManager?: UnrestrictedApprovalManager;
    unrestrictedRunnerRequireSessionApproval?: boolean;
    unrestrictedRunnerRoots?: string[];
  } = {},
) {
  const config: ServerConfig = {
    authMode: options.authMode ?? "desktop",
    account: options.authMode === "connect" ? undefined : "TestAccount",
    connectHost:
      options.authMode === "connect" ? "http://127.0.0.1:8080" : undefined,
    connectToken: options.authMode === "connect" ? "connect-token" : undefined,
    connectTimeoutMs: options.authMode === "connect" ? 30_000 : undefined,
    enableSecretReveal,
    enableWrites: options.enableWrites ?? false,
    enableDestructiveActions: options.enableDestructiveActions ?? false,
    enablePermissionMutation: options.enablePermissionMutation ?? false,
    enableScriptRunner:
      options.enableUnrestrictedScriptRunner || (options.enableScriptRunner ?? false),
    enableUnrestrictedScriptRunner: options.enableUnrestrictedScriptRunner ?? false,
    scriptRunnerRoots: ["/workspace"],
    scriptRunnerAllowlistPaths: ["/workspace/.onepassword-mcp.json"],
    scriptRunnerAllowlistManifestPaths: [],
    enableUnrestrictedRunner: options.enableUnrestrictedRunner ?? false,
    unrestrictedRunnerRoots: options.unrestrictedRunnerRoots ?? ["/workspace"],
    unrestrictedRunnerRequireSessionApproval:
      options.unrestrictedRunnerRequireSessionApproval ?? true,
    unrestrictedRunnerApprovalHost: "127.0.0.1",
    unrestrictedRunnerApprovalPort: 0,
    unrestrictedRunnerApprovalTtlMs: 12 * 60 * 60_000,
    unrestrictedRunnerCommandTimeoutMs: 600_000,
    approvalRememberStorePath: "/tmp/onepassword-mcp-test-approvals.enc.json",
    approvalRememberKeyPath: "/tmp/onepassword-mcp-test-approvals.key",
    approvalRememberTtlMs: 24 * 60 * 60_000,
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
    enableDiagnostics: options.enableDiagnostics ?? false,
    logLevel: "info",
    integrationName: "Test",
    integrationVersion: "0.1.0",
  };
  const auditLogger = new MemoryAuditLogger();
  const service = new FakeOnePasswordService();
  const approvalManager =
    options.approvalManager ?? new UnrestrictedApprovalManager(12 * 60 * 60_000);
  const server = createOnePasswordMcpServer(
    config,
    service,
    auditLogger,
    options.scriptRunner,
    options.unrestrictedRunner,
    approvalManager,
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
  const capabilities = await client.callTool({
    name: "sdk_capabilities",
    arguments: {},
  });
  const passwordReadTool = tools.tools.find((tool) => tool.name === "password_read");
  const secretRevealTool = tools.tools.find((tool) => tool.name === "secret_reveal");
  const capabilityPayload = capabilities.structuredContent as {
    effectiveSupportedTools: string[];
  };
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
  assert(!tools.tools.some((tool) => tool.name === "op_unrestricted_run"));
  assert.deepEqual(
    [...capabilityPayload.effectiveSupportedTools].sort(),
    tools.tools.map((tool) => tool.name).sort(),
  );
});

test("diagnostics audit records MCP requests without raw arguments", async () => {
  const { auditLogger, client } = await createClientAndServer(false, {
    enableDiagnostics: true,
  });

  await client.listTools();
  await client.callTool({
    name: "secret_reveal",
    arguments: {
      reference: "op://vault/item/password",
      reason: "diagnostic test",
      acknowledgePlaintext: SECRET_REVEAL_ACK,
    },
  });

  assert(
    auditLogger.events.some(
      (event) =>
        event.action === "mcp_request" &&
        event.outcome === "success" &&
        event.metadata.method === "tools/list",
    ),
  );
  assert(
    auditLogger.events.some(
      (event) =>
        event.action === "mcp_request" &&
        event.metadata.method === "tools/call" &&
        event.metadata.toolName === "secret_reveal",
    ),
  );
  assert.doesNotMatch(JSON.stringify(auditLogger.events), /op:\/\/vault\/item\/password/);
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

test("connect mode registers only Connect-supported backend tools", async () => {
  const { client } = await createClientAndServer(false, {
    authMode: "connect",
    enableWrites: true,
    enableDestructiveActions: true,
    enablePermissionMutation: true,
  });
  const tools = await client.listTools();
  const names = new Set(tools.tools.map((tool) => tool.name));

  assert(names.has("vault_list"));
  assert(names.has("vault_get"));
  assert(names.has("item_search"));
  assert(names.has("item_get_metadata"));
  assert(names.has("password_create"));
  assert(names.has("password_update"));
  assert(names.has("item_create"));
  assert(names.has("item_update"));
  assert(names.has("item_delete"));
  assert(names.has("password_read"));
  assert(names.has("secret_reveal"));

  assert(!names.has("vault_create"));
  assert(!names.has("vault_update"));
  assert(!names.has("vault_delete"));
  assert(!names.has("group_get"));
  assert(!names.has("vault_permissions_get"));
  assert(!names.has("vault_permissions_grant_group"));
  assert(!names.has("vault_permissions_update_group"));
  assert(!names.has("vault_permissions_revoke_group"));
  assert(!names.has("item_archive"));
  assert(!names.has("environment_get_variables"));
  assert(!names.has("environment_get_variable"));
  assert(!names.has("environment_reveal_variable"));

  const capabilities = await client.callTool({
    name: "sdk_capabilities",
    arguments: {},
  });
  const capabilityPayload = capabilities.structuredContent as {
    effectiveSupportedTools: string[];
  };
  assert.deepEqual([...capabilityPayload.effectiveSupportedTools].sort(), [...names].sort());
});

test("item_search returns partial results when one visible vault fails", async () => {
  const { client, service } = await createClientAndServer();
  service.vaultList = async () => [
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
    {
      id: "vault-denied",
      title: "Denied",
      description: "No access",
      vaultType: VaultType.UserCreated,
      activeItemCount: 1,
      contentVersion: 1,
      attributeVersion: 1,
      createdAt: new Date("2026-04-21T00:00:00.000Z"),
      updatedAt: new Date("2026-04-21T00:00:00.000Z"),
    },
  ];
  service.itemList = async (vaultId: string) => {
    if (vaultId === "vault-denied") {
      throw { message: "vault access denied", code: "OP_FORBIDDEN" };
    }
    return [
      {
        id: "item-1",
        title: "Root Login",
        category: ItemCategory.Login,
        vaultId,
        websites: [],
        tags: ["prod"],
        createdAt: new Date("2026-04-21T00:00:00.000Z"),
        updatedAt: new Date("2026-04-21T00:00:00.000Z"),
        state: ItemState.Active,
      },
    ];
  };

  const result = await client.callTool({
    name: "item_search",
    arguments: { query: "Root" },
  });
  const payload = result.structuredContent as {
    items: Array<{ id: string }>;
    searchedVaultCount: number;
    failedVaultCount: number;
    partialFailure: boolean;
    failures: Array<{ vaultId: string; errorMessage: string }>;
  };

  assert.notEqual(result.isError, true);
  assert.equal(payload.items.length, 1);
  assert.equal(payload.searchedVaultCount, 2);
  assert.equal(payload.failedVaultCount, 1);
  assert.equal(payload.partialFailure, true);
  assert.deepEqual(payload.failures, [
    {
      vaultId: "vault-denied",
      errorMessage: "vault access denied (code=OP_FORBIDDEN)",
    },
  ]);
});

test("item_search with an explicit vault reports structured failures clearly", async () => {
  const { client, service } = await createClientAndServer();
  service.itemList = async () => {
    throw { message: "explicit vault access denied", code: "OP_FORBIDDEN" };
  };

  const result = await client.callTool({
    name: "item_search",
    arguments: { vaultId: "vault-denied" },
  });
  const text = (result.content as Array<{ text?: string }>)[0]?.text ?? "";

  assert.equal(result.isError, true);
  assert.match(text, /explicit vault access denied/);
  assert.match(text, /OP_FORBIDDEN/);
  assert.notEqual(text, "[object Object]");
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

test("registers unrestricted runner tool only when enabled", async () => {
  const { client } = await createClientAndServer(false, {
    enableUnrestrictedRunner: true,
    unrestrictedRunner: new FakeUnrestrictedRunner(),
  });
  const tools = await client.listTools();
  const tool = tools.tools.find((entry) => entry.name === "op_unrestricted_run");

  assert(tool);
  assert.match(tool.description ?? "", /free-form local shell command/);
  assert.match(tool.description ?? "", /not an operating-system sandbox/);
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
    scriptRunnerConfiguredAllowlistPathCount: number;
    scriptRunnerAllowlistManifestCount: number;
    unrestrictedRunner: {
      enabled: boolean;
      configuredRootCount: number;
    };
  };

  assert.equal(payload.secretRevealEnabled, false);
  assert.equal(payload.writesEnabled, false);
  assert.equal(payload.destructiveActionsEnabled, false);
  assert.equal(payload.permissionMutationEnabled, false);
  assert.equal(payload.scriptRunnerEnabled, false);
  assert.equal(payload.scriptRunnerAllowlistCount, 0);
  assert.equal(payload.scriptRunnerConfiguredAllowlistPathCount, 1);
  assert.equal(payload.scriptRunnerAllowlistManifestCount, 0);
  assert.equal(payload.unrestrictedRunner.enabled, false);
  assert.equal(payload.unrestrictedRunner.configuredRootCount, 0);
});

test("op_session_status reports active Connect backend", async () => {
  const { client } = await createClientAndServer(false, { authMode: "connect" });
  const status = await client.callTool({
    name: "op_session_status",
    arguments: {},
  });
  const payload = status.structuredContent as {
    backend: string;
    diagnostics: { backend: string };
  };

  assert.equal(payload.backend, "connect");
  assert.equal(payload.diagnostics.backend, "connect");
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

test("resources/list does not touch the 1Password SDK", async () => {
  const { client, service } = await createClientAndServer();

  await client.listResources();

  assert.equal(service.vaultListCalls, 0);
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

test("write tools return useful messages for structured SDK errors", async () => {
  const { client, auditLogger, service } = await createClientAndServer(false, {
    enableWrites: true,
  });
  service.itemCreate = async () => {
    throw { message: "structured SDK create failure", code: "OP_CREATE_FAILED" };
  };

  const passwordCreate = await client.callTool({
    name: "password_create",
    arguments: {
      vaultId: "vault-1",
      title: "Broken Login",
      mode: "random",
    },
  });
  const passwordCreateText =
    (passwordCreate.content as Array<{ text?: string }>)[0]?.text ?? "";

  assert.equal(passwordCreate.isError, true);
  assert.match(passwordCreateText, /structured SDK create failure/);
  assert.match(passwordCreateText, /OP_CREATE_FAILED/);
  assert.notEqual(passwordCreateText, "[object Object]");
  assert.equal(
    auditLogger.events.at(-1)?.errorMessage,
    "structured SDK create failure (code=OP_CREATE_FAILED)",
  );

  const itemCreate = await client.callTool({
    name: "item_create",
    arguments: {
      vaultId: "vault-1",
      category: ItemCategory.Login,
      title: "Broken Item",
    },
  });
  const itemCreateText = (itemCreate.content as Array<{ text?: string }>)[0]?.text ?? "";

  assert.equal(itemCreate.isError, true);
  assert.match(itemCreateText, /structured SDK create failure/);
  assert.match(itemCreateText, /OP_CREATE_FAILED/);
  assert.notEqual(itemCreateText, "[object Object]");
  assert.equal(
    auditLogger.events.at(-1)?.errorMessage,
    "structured SDK create failure (code=OP_CREATE_FAILED)",
  );
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
    configuredAllowlistManifestCount: number;
    previousAllowlistCount: number;
    allowlistCount: number;
    commandCount: number;
  };
  const auditEvent = auditLogger.events.at(-1);

  assert.notEqual(result.isError, true);
  assert.equal(scriptRunner.reloadCalls, 1);
  assert.equal(payload.reloaded, true);
  assert.equal(payload.configuredAllowlistPathCount, 1);
  assert.equal(payload.configuredAllowlistManifestCount, 0);
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

test("unrestricted script runner ignores allowlists and gates free commands once per session", async () => {
  const scriptRunner = new FakeOpScriptRunner();
  scriptRunner.nextStdout = "connected with supabase-db-password-secret\n";
  const approvalManager = new UnrestrictedApprovalManager(60_000);
  approvalManager.setApprovalBaseUrl("http://127.0.0.1:19000");
  const { client, auditLogger, service } = await createClientAndServer(false, {
    enableUnrestrictedScriptRunner: true,
    scriptRunner,
    approvalManager,
  });

  const listed = await client.callTool({
    name: "op_script_list",
    arguments: {
      workspaceRoot: "/workspace",
    },
  });
  const listPayload = listed.structuredContent as {
    unrestrictedScriptRunner: boolean;
    commands: unknown[];
  };
  assert.equal(listPayload.unrestrictedScriptRunner, true);
  assert.deepEqual(listPayload.commands, []);

  const reload = await client.callTool({
    name: "op_script_reload_allowlists",
    arguments: {
      reason: "Need to verify allowlists are ignored",
    },
  });
  assert.equal((reload.structuredContent as { ignored: boolean }).ignored, true);
  assert.equal(scriptRunner.reloadCalls, 0);

  const authorization = await client.callTool({
    name: "op_script_run",
    arguments: {
      workspaceRoot: "/workspace",
      command: "node scripts/deploy.mjs",
      reason: "Need free command execution with injected secrets",
      envSecretRefs: {
        SUPABASE_DB_PASSWORD: "op://vault/supabase-db-password/password",
      },
    },
  });
  const authorizationPayload = authorization.structuredContent as {
    authorizationRequired: boolean;
    approvalUrl: string;
    acknowledgement: string;
  };
  const token = new URL(authorizationPayload.approvalUrl).searchParams.get("token") ?? "";

  assert.equal(authorizationPayload.authorizationRequired, true);
  assert.match(authorizationPayload.approvalUrl, /^http:\/\/127\.0\.0\.1:19000\/approve/);
  assert.equal(authorizationPayload.acknowledgement, UNRESTRICTED_RUNNER_ACK);
  assert.equal(service.secretResolveCalls.length, 0);
  assert.equal(auditLogger.events.at(-1)?.action, "op_script_run_authorization_required");

  approvalManager.approveToken(token, true, UNRESTRICTED_RUNNER_ACK);

  const status = await client.callTool({
    name: "op_session_status",
    arguments: {},
  });
  const statusPayload = status.structuredContent as {
    unrestrictedScriptRunnerEnabled: boolean;
    unrestrictedRunner: {
      enabled: boolean;
      mode: string;
      configuredRoot: string;
      requireSessionApproval: boolean;
      approvedRootCount: number;
      rememberTtlMs: number;
    };
  };
  assert.equal(statusPayload.unrestrictedScriptRunnerEnabled, true);
  assert.equal(statusPayload.unrestrictedRunner.enabled, true);
  assert.equal(statusPayload.unrestrictedRunner.mode, "op_script_run");
  assert.equal(
    statusPayload.unrestrictedRunner.configuredRoot,
    "unrestricted-script-runner-session",
  );
  assert.equal(statusPayload.unrestrictedRunner.requireSessionApproval, true);
  assert.equal(statusPayload.unrestrictedRunner.approvedRootCount, 1);
  assert.equal(statusPayload.unrestrictedRunner.rememberTtlMs, 24 * 60 * 60_000);

  const missingOutputAck = await client.callTool({
    name: "op_script_run",
    arguments: {
      workspaceRoot: "/workspace",
      command: "node scripts/deploy.mjs",
      reason: "Need free command execution with injected secrets",
      envSecretRefs: {
        SUPABASE_DB_PASSWORD: "op://vault/supabase-db-password/password",
      },
      returnOutput: true,
    },
  });
  const missingAckPayload = missingOutputAck.structuredContent as {
    executionSkipped: boolean;
    outputState: string;
    requiredAcknowledgement: string;
  };

  assert.equal(missingAckPayload.executionSkipped, true);
  assert.equal(missingAckPayload.outputState, "skipped_ack_missing");
  assert.equal(missingAckPayload.requiredAcknowledgement, SECRET_REVEAL_ACK);
  assert.equal(scriptRunner.lastRunOptions, undefined);
  assert.equal(service.secretResolveCalls.length, 0);

  const result = await client.callTool({
    name: "op_script_run",
    arguments: {
      workspaceRoot: "/workspace",
      command: "node scripts/deploy.mjs",
      reason: "Need free command execution with injected secrets",
      envSecretRefs: {
        SUPABASE_DB_PASSWORD: "op://vault/supabase-db-password/password",
      },
      returnOutput: true,
      acknowledgePlaintext: SECRET_REVEAL_ACK,
    },
  });
  const payload = result.structuredContent as {
    mode: string;
    stdout: string;
    commandHash: string;
    outputReturned: boolean;
    envSecretRefCount: number;
    injectedSecretEnvVars: string[];
  };
  const auditPayload = JSON.stringify(auditLogger.events.at(-1));

  assert.equal(result.isError, false);
  assert.equal(payload.mode, "unrestricted");
  assert.equal(payload.outputReturned, true);
  assert.equal(payload.stdout, "connected with [REDACTED]\n");
  assert.match(payload.commandHash, /^[a-f0-9]{64}$/);
  assert.equal(payload.envSecretRefCount, 1);
  assert.deepEqual(payload.injectedSecretEnvVars, ["SUPABASE_DB_PASSWORD"]);
  assert.equal(scriptRunner.lastRunOptions?.extraEnv?.SUPABASE_DB_PASSWORD, "supabase-db-password-secret");
  assert(!auditPayload.includes("node scripts/deploy.mjs"));
  assert(!auditPayload.includes("supabase-db-password-secret"));
});

test("unrestricted script runner skips approval when session approval is disabled", async () => {
  const scriptRunner = new FakeOpScriptRunner();
  scriptRunner.nextStdout = "ran without session approval\n";
  const { client, auditLogger } = await createClientAndServer(false, {
    enableUnrestrictedScriptRunner: true,
    unrestrictedRunnerRequireSessionApproval: false,
    scriptRunner,
  });

  const result = await client.callTool({
    name: "op_script_run",
    arguments: {
      workspaceRoot: "/workspace",
      command: "node scripts/deploy.mjs",
      reason: "Need free command execution without session approval",
      returnOutput: true,
      acknowledgePlaintext: SECRET_REVEAL_ACK,
    },
  });
  const payload = result.structuredContent as {
    mode: string;
    stdout: string;
    outputReturned: boolean;
  };

  assert.equal(result.isError, false);
  assert.equal(payload.mode, "unrestricted");
  assert.equal(payload.stdout, "ran without session approval\n");
  assert.equal(payload.outputReturned, true);
  assert.equal(auditLogger.events.at(-1)?.action, "op_script_run");

  const status = await client.callTool({
    name: "op_session_status",
    arguments: {},
  });
  const statusPayload = status.structuredContent as {
    unrestrictedRunner: {
      requireSessionApproval: boolean;
      approvalServerAvailable: boolean;
    };
  };
  assert.equal(statusPayload.unrestrictedRunner.requireSessionApproval, false);
  assert.equal(statusPayload.unrestrictedRunner.approvalServerAvailable, false);
  await client.close();
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

test("script runner rejects reserved secret env vars case-insensitively", async () => {
  const { client, service } = await createClientAndServer(false, {
    enableScriptRunner: true,
    scriptRunner: new FakeOpScriptRunner(),
  });

  const result = await client.callTool({
    name: "op_script_run",
    arguments: {
      workspaceRoot: "/workspace",
      commandId: "deploy",
      reason: "Need to verify reserved env var validation",
      envSecretRefs: {
        op_service_account_token: "op://vault/item/password",
      },
    },
  });
  const textContent = result.content as Array<{ type: string; text?: string }>;

  assert.equal(result.isError, true);
  assert.match(textContent[0]?.text ?? "", /reserved and cannot be injected/);
  assert.equal(service.secretResolveCalls.length, 0);
});

test("script runner accepts case-insensitive secret reference schemes", async () => {
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
      reason: "Need to verify secret reference scheme handling",
      envSecretRefs: {
        SERVICE_PASSWORD: "OP://vault/item/password",
      },
    },
  });

  assert.notEqual(result.isError, true);
  assert.equal(service.secretResolveCalls[0], "OP://vault/item/password");
  assert.equal(scriptRunner.lastRunOptions?.extraEnv?.SERVICE_PASSWORD, "resolved-secret");
});

test("script runner requires acknowledgement before executing injected-secret output", async () => {
  const scriptRunner = new FakeOpScriptRunner();
  scriptRunner.nextStdout = "connected with supabase-db-password-secret\n";
  scriptRunner.nextErrorMessage = "failed with supabase-db-password-secret";
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
  const textContent = result.content as Array<{ type: string; text?: string }>;
  const payload = result.structuredContent as {
    executionSkipped: boolean;
    outputRequested: boolean;
    outputReturned: boolean;
    outputState: string;
    requiredAcknowledgement: string;
    stdout?: string;
    errorMessage?: string;
    envSecretRefCount: number;
    injectedSecretEnvVars: string[];
  };

  assert.notEqual(result.isError, true);
  assert.equal(service.secretResolveCalls.length, 0);
  assert.equal(scriptRunner.lastRunOptions, undefined);
  assert.match(textContent[0]?.text ?? "", /was not executed/);
  assert.equal(payload.executionSkipped, true);
  assert.equal(payload.outputRequested, true);
  assert.equal(payload.outputReturned, false);
  assert.equal(payload.outputState, "skipped_ack_missing");
  assert.equal(payload.requiredAcknowledgement, SECRET_REVEAL_ACK);
  assert.equal(payload.stdout, undefined);
  assert.equal(payload.errorMessage, undefined);
  assert.equal(payload.envSecretRefCount, 1);
  assert.deepEqual(payload.injectedSecretEnvVars, ["SUPABASE_DB_PASSWORD"]);
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

test("script runner requires acknowledgement before executing sensitive output", async () => {
  const scriptRunner = new FakeOpScriptRunner();
  scriptRunner.nextStdout = "secret output\n";
  scriptRunner.nextErrorMessage = "secret error";
  const { client } = await createClientAndServer(false, {
    enableScriptRunner: true,
    scriptRunner,
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
  const payload = result.structuredContent as {
    executionSkipped: boolean;
    outputRequested: boolean;
    outputReturned: boolean;
    outputState: string;
    requiredAcknowledgement: string;
    stdout?: string;
    errorMessage?: string;
  };

  assert.notEqual(result.isError, true);
  assert.equal(scriptRunner.lastRunOptions, undefined);
  assert.equal(payload.executionSkipped, true);
  assert.equal(payload.outputRequested, true);
  assert.equal(payload.outputReturned, false);
  assert.equal(payload.outputState, "skipped_ack_missing");
  assert.equal(payload.requiredAcknowledgement, SECRET_REVEAL_ACK);
  assert.equal(payload.stdout, undefined);
  assert.equal(payload.errorMessage, undefined);
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

test("unrestricted runner returns local approval URL before running", async () => {
  const unrestrictedRunner = new FakeUnrestrictedRunner();
  unrestrictedRunner.nextAuthorization = {
    authorizationRequired: true,
    approvalUrl: "http://127.0.0.1:19000/approve?token=test-token",
    workspaceRoot: "/workspace",
    configuredRoot: "/workspace",
    acknowledgement: UNRESTRICTED_RUNNER_ACK,
    warning: "Approval permits arbitrary local command execution.",
    expiresAt: "2026-05-06T00:00:00.000Z",
  };
  const { client, auditLogger } = await createClientAndServer(false, {
    enableUnrestrictedRunner: true,
    unrestrictedRunner,
  });

  const result = await client.callTool({
    name: "op_unrestricted_run",
    arguments: {
      workspaceRoot: "/workspace",
      command: "npm test",
      reason: "Need broad command execution in this worktree",
    },
  });
  const payload = result.structuredContent as {
    authorizationRequired: boolean;
    approvalUrl: string;
    acknowledgement: string;
  };

  assert.notEqual(result.isError, true);
  assert.equal(payload.authorizationRequired, true);
  assert.equal(payload.approvalUrl, "http://127.0.0.1:19000/approve?token=test-token");
  assert.equal(payload.acknowledgement, UNRESTRICTED_RUNNER_ACK);
  assert.equal(unrestrictedRunner.lastCommand, undefined);
  assert.equal(
    auditLogger.events.at(-1)?.action,
    "op_unrestricted_run_authorization_required",
  );
});

test("default unrestricted runner reuses the supplied approval manager", async () => {
  const workspaceRoot = tmpdir();
  const approvalManager = new UnrestrictedApprovalManager(60_000);
  approvalManager.setApprovalBaseUrl("http://127.0.0.1:19000");
  const { client } = await createClientAndServer(false, {
    enableUnrestrictedRunner: true,
    approvalManager,
    unrestrictedRunnerRoots: [workspaceRoot],
  });

  const result = await client.callTool({
    name: "op_unrestricted_run",
    arguments: {
      workspaceRoot,
      command: "printf ok",
      reason: "Need broad command execution in this worktree",
    },
  });
  const payload = result.structuredContent as {
    authorizationRequired: boolean;
    approvalUrl: string;
  };

  assert.notEqual(result.isError, true);
  assert.equal(payload.authorizationRequired, true);
  assert.match(payload.approvalUrl, /^http:\/\/127\.0\.0\.1:19000\/approve/);
});

test("unrestricted runner requires acknowledgement before execution when output is requested", async () => {
  const unrestrictedRunner = new FakeUnrestrictedRunner();
  unrestrictedRunner.nextStdout = "token-like output\n";
  unrestrictedRunner.nextErrorMessage = "sensitive error";
  const { client, auditLogger } = await createClientAndServer(false, {
    enableUnrestrictedRunner: true,
    unrestrictedRunner,
  });

  const result = await client.callTool({
    name: "op_unrestricted_run",
    arguments: {
      workspaceRoot: "/workspace",
      command: "printf token-like-output",
      reason: "Need broad command execution in this worktree",
      returnOutput: true,
    },
  });
  const textContent = result.content as Array<{ type: string; text?: string }>;
  const payload = result.structuredContent as {
    executionSkipped: boolean;
    outputRequested: boolean;
    outputReturned: boolean;
    outputState: string;
    requiredAcknowledgement: string;
    stdout?: string;
    errorMessage?: string;
    commandHash: string;
  };
  const auditPayload = auditLogger.events.at(-1)?.metadata ?? {};

  assert.notEqual(result.isError, true);
  assert.equal(unrestrictedRunner.lastCommand, undefined);
  assert.match(textContent[0]?.text ?? "", /was not executed/);
  assert.equal(payload.executionSkipped, true);
  assert.equal(payload.outputRequested, true);
  assert.equal(payload.outputReturned, false);
  assert.equal(payload.outputState, "skipped_ack_missing");
  assert.equal(payload.requiredAcknowledgement, SECRET_REVEAL_ACK);
  assert.equal(payload.stdout, undefined);
  assert.equal(payload.errorMessage, undefined);
  assert.match(payload.commandHash, /^[a-f0-9]{64}$/);
  assert.equal(auditPayload.commandLength, "printf token-like-output".length);
  assert(!JSON.stringify(auditPayload).includes("printf token-like-output"));
});

test("unrestricted runner returns output with plaintext acknowledgement", async () => {
  const unrestrictedRunner = new FakeUnrestrictedRunner();
  const { client } = await createClientAndServer(false, {
    enableUnrestrictedRunner: true,
    unrestrictedRunner,
  });

  const result = await client.callTool({
    name: "op_unrestricted_run",
    arguments: {
      workspaceRoot: "/workspace",
      command: "echo unrestricted",
      reason: "Need broad command execution in this worktree",
      returnOutput: true,
      acknowledgePlaintext: SECRET_REVEAL_ACK,
    },
  });
  const payload = result.structuredContent as {
    stdout: string;
    outputReturned: boolean;
  };

  assert.equal(result.isError, false);
  assert.equal(payload.outputReturned, true);
  assert.equal(payload.stdout, "unrestricted done\n");
});

function findPasswordValue(item: Item, fieldId: string): string | undefined {
  return item.fields.find((field) => field.id === fieldId)?.value;
}
