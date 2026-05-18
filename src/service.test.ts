import assert from "node:assert/strict";
import test from "node:test";
import type { Client, VaultOverview } from "@1password/sdk";
import { MemoryAuditLogger } from "./audit.js";
import type { ServerConfig } from "./config.js";
import { SdkOnePasswordService } from "./service.js";

function createConfig(): ServerConfig {
  return {
    authMode: "desktop",
    account: "TestAccount",
    enableSecretReveal: false,
    enableWrites: false,
    enableDestructiveActions: false,
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

test("SdkOnePasswordService refreshes the SDK client when 1Password returns invalid client id", async () => {
  const expectedVaults = [{ id: "vault-2", title: "Infra" }] as unknown as VaultOverview[];
  let factoryCalls = 0;

  const staleClient = {
    vaults: {
      list: async () => {
        throw new Error("invalid client id");
      },
    },
  } as unknown as Client;
  const freshClient = {
    vaults: {
      list: async () => expectedVaults,
    },
  } as unknown as Client;

  const service = new SdkOnePasswordService(createConfig(), async () => {
    factoryCalls += 1;
    return factoryCalls === 1 ? staleClient : freshClient;
  });

  const vaults = await service.vaultList();

  assert.equal(factoryCalls, 2);
  assert.deepEqual(vaults, expectedVaults);
});

test("SdkOnePasswordService keeps the original error for non-retryable failures", async () => {
  let factoryCalls = 0;
  const service = new SdkOnePasswordService(createConfig(), async () => {
    factoryCalls += 1;
    return {
      vaults: {
        list: async () => {
          throw new Error("permission denied");
        },
      },
    } as unknown as Client;
  });

  await assert.rejects(() => service.vaultList(), /permission denied/);
  assert.equal(factoryCalls, 1);
});

test("SdkOnePasswordService diagnostics record client creation and triggering operation", async () => {
  const auditLogger = new MemoryAuditLogger();
  const config = { ...createConfig(), enableDiagnostics: true };
  const expectedVaults = [{ id: "vault-1", title: "Primary" }] as unknown as VaultOverview[];

  const service = new SdkOnePasswordService(
    config,
    async () =>
      ({
        vaults: {
          list: async () => expectedVaults,
        },
      }) as unknown as Client,
    auditLogger,
  );

  await service.vaultList();

  assert(
    auditLogger.events.some(
      (event) =>
        event.action === "op_sdk_client_create_start" &&
        event.metadata.triggerOperation === "vault_list",
    ),
  );
  assert(
    auditLogger.events.some(
      (event) =>
        event.action === "op_sdk_operation" &&
        event.outcome === "success" &&
        event.metadata.operation === "vault_list",
    ),
  );
});
