import assert from "node:assert/strict";
import test from "node:test";
import type { Client, VaultOverview } from "@1password/sdk";
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
    scriptRunnerRoots: [],
    scriptRunnerAllowlistPaths: [],
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
