import assert from "node:assert/strict";
import test from "node:test";
import {
  ItemCategory,
  ItemFieldType,
  VaultType,
  type Item,
  type ItemCreateParams,
} from "@1password/sdk";
import { MemoryAuditLogger } from "./audit.js";
import type { ServerConfig } from "./config.js";
import { ConnectOnePasswordService, type ConnectClient } from "./connect-service.js";

function createConfig(): ServerConfig {
  return {
    authMode: "connect",
    connectHost: "http://127.0.0.1:8080",
    connectToken: "connect-token",
    connectTimeoutMs: 30_000,
    enableSecretReveal: false,
    enableWrites: true,
    enableDestructiveActions: true,
    enablePermissionMutation: false,
    enableScriptRunner: false,
    enableUnrestrictedScriptRunner: false,
    scriptRunnerRoots: [],
    scriptRunnerAllowlistPaths: [],
    scriptRunnerAllowlistManifestPaths: [],
    enableUnrestrictedRunner: false,
    unrestrictedRunnerRoots: [],
    unrestrictedRunnerRequireSessionApproval: true,
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
    enableDiagnostics: false,
    logLevel: "info",
    integrationName: "Test",
    integrationVersion: "0.1.0",
  };
}

class FakeConnectClient implements ConnectClient {
  public createdItem?: unknown;
  public updatedItem?: unknown;
  public deletedItem?: { vaultId: string; itemId: string };

  private readonly vault = {
    id: "vault-1",
    name: "Engineering",
    description: "Team secrets",
    type: "USER_CREATED",
    items: 1,
    contentVersion: 7,
    attributeVersion: 3,
    createdAt: new Date("2026-05-01T10:00:00.000Z"),
    updatedAt: new Date("2026-05-02T10:00:00.000Z"),
  };

  private readonly item = {
    id: "item-1",
    title: "Database",
    category: "LOGIN",
    vault: { id: "vault-1" },
    tags: ["prod"],
    urls: [{ href: "https://db.example.test", label: "login", primary: true }],
    version: 4,
    createdAt: new Date("2026-05-01T10:00:00.000Z"),
    updatedAt: new Date("2026-05-02T10:00:00.000Z"),
    sections: [{ id: "section-1", label: "Credentials" }],
    fields: [
      { id: "username", purpose: "USERNAME", value: "alice" },
      { id: "password", purpose: "PASSWORD", value: "secret" },
      {
        id: "token",
        section: { id: "section-1" },
        type: "CONCEALED",
        label: "api-token",
        value: "token-secret",
      },
      { id: "otp", type: "OTP", label: "one-time password", otp: "123456" },
    ],
  };

  public async listVaults(): Promise<unknown[]> {
    return [this.vault];
  }

  public async getVault(_vaultQuery: string): Promise<unknown> {
    return this.vault;
  }

  public async listItems(_vaultId: string): Promise<unknown[]> {
    return [this.item];
  }

  public async getItem(_vaultId: string, _itemQuery: string): Promise<unknown> {
    return this.item;
  }

  public async createItem(vaultId: string, item: unknown): Promise<unknown> {
    this.createdItem = item;
    return {
      ...(item as Record<string, unknown>),
      id: "item-created",
      vault: { id: vaultId },
      version: 1,
      createdAt: new Date("2026-05-03T10:00:00.000Z"),
      updatedAt: new Date("2026-05-03T10:00:00.000Z"),
    };
  }

  public async updateItem(vaultId: string, item: unknown): Promise<unknown> {
    this.updatedItem = item;
    return {
      ...(item as Record<string, unknown>),
      vault: { id: vaultId },
      updatedAt: new Date("2026-05-04T10:00:00.000Z"),
    };
  }

  public async deleteItem(vaultId: string, itemId: string): Promise<void> {
    this.deletedItem = { vaultId, itemId };
  }
}

test("ConnectOnePasswordService maps vault and item CRUD through the Connect client", async () => {
  const fakeClient = new FakeConnectClient();
  const service = new ConnectOnePasswordService(createConfig(), async () => fakeClient);

  const vaults = await service.vaultList();
  assert.equal(vaults[0]?.title, "Engineering");
  assert.equal(vaults[0]?.vaultType, VaultType.UserCreated);

  const items = await service.itemList("vault-1");
  assert.equal(items[0]?.title, "Database");
  assert.equal(items[0]?.category, ItemCategory.Login);

  const item = await service.itemGet("vault-1", "item-1");
  assert.equal(item.fields.find((field) => field.id === "password")?.value, "secret");

  const createParams: ItemCreateParams = {
    vaultId: "vault-1",
    category: ItemCategory.Login,
    title: "Created Database",
    fields: [
      {
        id: "password",
        title: "password",
        fieldType: ItemFieldType.Concealed,
        value: "created-secret",
      },
    ],
  };
  const created = await service.itemCreate(createParams);
  assert.equal(created.id, "item-created");
  assert.deepEqual(fakeClient.createdItem, {
    title: "Created Database",
    vault: { id: "vault-1" },
    category: "LOGIN",
    tags: [],
    sections: [],
    fields: [{ id: "password", purpose: "PASSWORD", value: "created-secret" }],
    urls: [],
  });

  const updatedInput: Item = {
    ...item,
    title: "Updated Database",
    fields: [
      {
        id: "password",
        title: "password",
        fieldType: ItemFieldType.Concealed,
        value: "updated-secret",
      },
    ],
  };
  const updated = await service.itemPut(updatedInput);
  assert.equal(updated.title, "Updated Database");
  assert.deepEqual(fakeClient.updatedItem, {
    id: "item-1",
    title: "Updated Database",
    vault: { id: "vault-1" },
    category: "LOGIN",
    tags: ["prod"],
    sections: [{ id: "section-1", label: "Credentials" }],
    fields: [{ id: "password", purpose: "PASSWORD", value: "updated-secret" }],
    version: 4,
    urls: [{ href: "https://db.example.test", label: "login", primary: true }],
  });

  await service.itemDelete("vault-1", "item-1");
  assert.deepEqual(fakeClient.deletedItem, { vaultId: "vault-1", itemId: "item-1" });
});

test("ConnectOnePasswordService deletes items with the public Connect SDK delete API", async () => {
  let deletedItem: { vaultId: string; itemId: string } | undefined;
  const service = new ConnectOnePasswordService(
    createConfig(),
    async () =>
      ({
        deleteItem: async (vaultId: string, itemId: string) => {
          deletedItem = { vaultId, itemId };
        },
      }) as unknown as ConnectClient,
  );

  await service.itemDelete("vault-1", "item-1");

  assert.deepEqual(deletedItem, { vaultId: "vault-1", itemId: "item-1" });
});

test("ConnectOnePasswordService resolves op references without the Desktop SDK", async () => {
  const fakeClient = new FakeConnectClient();
  const auditLogger = new MemoryAuditLogger();
  const service = new ConnectOnePasswordService(
    { ...createConfig(), enableDiagnostics: true },
    async () => fakeClient,
    auditLogger,
  );

  assert.equal(await service.secretResolve("op://Engineering/Database/password"), "secret");
  assert.equal(
    await service.secretResolve("op://Engineering/Database/Credentials/api-token"),
    "token-secret",
  );
  assert.equal(
    await service.secretResolve("op://Engineering/Database/Credentials/api-token?attribute=id"),
    "token",
  );
  assert.equal(
    await service.secretResolve("op://Engineering/Database/Credentials/api-token?attribute=title"),
    "api-token",
  );
  assert.equal(
    await service.secretResolve("op://Engineering/Database/Credentials/api-token?attribute=type"),
    "CONCEALED",
  );
  assert.equal(
    await service.secretResolve("op://Engineering/Database/password?attribute=purpose"),
    "PASSWORD",
  );
  assert.equal(
    await service.secretResolve("op://Engineering/Database/one-time password?attribute=otp"),
    "123456",
  );

  assert(
    auditLogger.events.some(
      (event) =>
        event.action === "op_connect_client_create_start" &&
        event.metadata.triggerOperation === "secret_resolve",
    ),
  );
});

test("ConnectOnePasswordService rejects operations outside the Connect POC surface", async () => {
  const service = new ConnectOnePasswordService(
    createConfig(),
    async () => new FakeConnectClient(),
  );

  await assert.rejects(
    () => service.vaultCreate({ title: "New Vault" }),
    /not supported in Connect mode/,
  );
  await assert.rejects(
    () => service.itemArchive("vault-1", "item-1"),
    /not supported in Connect mode/,
  );
  await assert.rejects(
    () => service.environmentGetVariables("env-1"),
    /not supported in Connect mode/,
  );
});
