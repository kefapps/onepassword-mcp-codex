#!/usr/bin/env node

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  DESTRUCTIVE_ACTION_ACK,
  GENERATED_SECRET_ACK,
  PERMISSION_MUTATION_ACK,
  SECRET_REVEAL_ACK,
} from "../dist/constants.js";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const distIndex = join(repoRoot, "dist", "index.js");
const auditLogPath =
  process.env.OP_MCP_SMOKE_AUDIT_LOG_PATH ?? "/tmp/mcp-1password-smoke-audit.jsonl";

function envFlag(name) {
  const value = process.env[name];
  return value === "1" || value === "true" || value === "yes" || value === "on";
}

function optionalEnv(name) {
  const value = process.env[name];
  return value && value.trim() ? value.trim() : undefined;
}

function requiredEnv(name) {
  const value = optionalEnv(name);
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function authMode() {
  const mode = optionalEnv("OP_MCP_SMOKE_AUTH_MODE") ?? "desktop";
  if (mode !== "desktop" && mode !== "service-account") {
    throw new Error("OP_MCP_SMOKE_AUTH_MODE must be desktop or service-account.");
  }
  return mode;
}

function serverArgs(extraArgs = []) {
  const mode = authMode();
  const args = [distIndex, `--auth-mode=${mode}`, `--audit-log-path=${auditLogPath}`];

  if (mode === "desktop") {
    args.push(`--account=${optionalEnv("OP_MCP_SMOKE_ACCOUNT") ?? requiredEnv("OP_MCP_ACCOUNT")}`);
  }

  if (envFlag("OP_MCP_SMOKE_ENABLE_REVEAL")) {
    args.push("--enable-secret-reveal=true");
  }
  if (envFlag("OP_MCP_SMOKE_ENABLE_WRITES")) {
    args.push("--enable-writes=true");
  }
  if (envFlag("OP_MCP_SMOKE_ENABLE_DESTRUCTIVE")) {
    args.push("--enable-destructive-actions=true");
  }
  if (envFlag("OP_MCP_SMOKE_ENABLE_PERMISSION_MUTATION")) {
    args.push("--enable-permission-mutation=true");
  }

  if (optionalEnv("OP_MCP_SMOKE_SCRIPT_ALLOWLIST")) {
    args.push("--enable-script-runner=true");
    args.push(`--script-runner-allowlist=${requiredEnv("OP_MCP_SMOKE_SCRIPT_ALLOWLIST")}`);
    args.push(`--script-runner-root=${requiredEnv("OP_MCP_SMOKE_SCRIPT_ROOT")}`);
    args.push(`--op-cli-path=${requiredEnv("OP_MCP_SMOKE_OP_CLI_PATH")}`);
  }

  return [...args, ...extraArgs];
}

function childEnv(extra = {}) {
  const env = {
    ...process.env,
    OP_MCP_AUDIT_LOG_PATH: auditLogPath,
    ...extra,
  };

  if (authMode() === "service-account") {
    env.OP_SERVICE_ACCOUNT_TOKEN =
      optionalEnv("OP_MCP_SMOKE_SERVICE_ACCOUNT_TOKEN") ??
      optionalEnv("OP_SERVICE_ACCOUNT_TOKEN") ??
      requiredEnv("OP_MCP_SERVICE_ACCOUNT_TOKEN");
  }

  return env;
}

function textContent(result) {
  return (result.content ?? [])
    .filter((entry) => entry.type === "text")
    .map((entry) => entry.text ?? "")
    .join("\n");
}

function assertToolOk(result, name) {
  if (result.isError) {
    throw new Error(`${name} returned an MCP error: ${textContent(result)}`);
  }
}

async function runStep(name, fn) {
  process.stdout.write(`- ${name} ... `);
  await fn();
  process.stdout.write("ok\n");
}

async function withStdioClient(fn) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: serverArgs(),
    cwd: repoRoot,
    env: childEnv(),
    stderr: envFlag("OP_MCP_SMOKE_DEBUG") ? "inherit" : "pipe",
  });
  const client = new Client({ name: "mcp-1password-smoke", version: "1.0.0" });
  try {
    await client.connect(transport, { timeout: 120_000 });
    await fn(client);
  } finally {
    await transport.close();
  }
}

async function getFreePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : undefined;
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  if (!port) {
    throw new Error("Could not allocate a local HTTP port.");
  }
  return port;
}

async function waitForHealthz(port) {
  const url = `http://127.0.0.1:${port}/healthz`;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      // Server not ready yet.
    }
    await delay(250);
  }
  throw new Error(`HTTP server did not become ready at ${url}`);
}

async function withHttpClient(fn) {
  const port = await getFreePort();
  const token = randomBytes(32).toString("base64url");
  const child = spawn(
    process.execPath,
    serverArgs([
      "--transport=http",
      "--http-host=127.0.0.1",
      `--http-port=${port}`,
      "--http-path=/mcp",
    ]),
    {
      cwd: repoRoot,
      env: childEnv({ OP_MCP_HTTP_BEARER_TOKEN: token }),
      stdio: envFlag("OP_MCP_SMOKE_DEBUG") ? ["ignore", "inherit", "inherit"] : "ignore",
    },
  );

  try {
    await waitForHealthz(port);

    const invalidOrigin = await fetch(`http://127.0.0.1:${port}/healthz`, {
      headers: { origin: "http://invalid.example" },
    });
    if (invalidOrigin.status !== 403) {
      throw new Error(`Expected invalid Origin to return 403, got ${invalidOrigin.status}.`);
    }

    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${port}/mcp`),
      {
        requestInit: {
          headers: {
            authorization: `Bearer ${token}`,
          },
        },
      },
    );
    const client = new Client({ name: "mcp-1password-http-smoke", version: "1.0.0" });
    try {
      await client.connect(transport, { timeout: 120_000 });
      await fn(client);
      await transport.terminateSession().catch(() => undefined);
    } finally {
      await transport.close();
    }
  } finally {
    child.kill("SIGTERM");
  }
}

async function runReadOnlyChecks(client) {
  await runStep("list tools includes core tools", async () => {
    const tools = await client.listTools();
    const names = new Set(tools.tools.map((tool) => tool.name));
    for (const name of ["sdk_capabilities", "vault_list", "item_search", "password_generate"]) {
      if (!names.has(name)) {
        throw new Error(`Missing expected tool: ${name}`);
      }
    }
  });

  await runStep("read redacted config resource", async () => {
    const resource = await client.readResource({ uri: "onepassword://config" });
    const payload = JSON.parse(resource.contents[0]?.text ?? "{}");
    for (const forbiddenKey of ["account", "opCliPath", "scriptRunnerRoots"]) {
      if (Object.hasOwn(payload, forbiddenKey)) {
        throw new Error(`Config resource leaked ${forbiddenKey}.`);
      }
    }
  });

  await runStep("call sdk_capabilities", async () => {
    const result = await client.callTool({ name: "sdk_capabilities", arguments: {} });
    assertToolOk(result, "sdk_capabilities");
  });

  await runStep("list real vaults", async () => {
    const result = await client.callTool({ name: "vault_list", arguments: {} });
    assertToolOk(result, "vault_list");
    const vaults = result.structuredContent?.vaults ?? [];
    if (!Array.isArray(vaults) || vaults.length === 0) {
      throw new Error("vault_list returned no vaults.");
    }
  });

  const vaultId = optionalEnv("OP_MCP_SMOKE_VAULT_ID");
  const itemId = optionalEnv("OP_MCP_SMOKE_ITEM_ID");
  if (vaultId) {
    await runStep("search items in the smoke vault", async () => {
      const result = await client.callTool({
        name: "item_search",
        arguments: {
          vaultId,
          query: optionalEnv("OP_MCP_SMOKE_ITEM_QUERY"),
          limit: 10,
        },
      });
      assertToolOk(result, "item_search");
    });
  }

  if (vaultId && itemId) {
    await runStep("read item metadata without plaintext", async () => {
      const result = await client.callTool({
        name: "item_get_metadata",
        arguments: { vaultId, itemId },
      });
      assertToolOk(result, "item_get_metadata");
      const fields = result.structuredContent?.item?.fields ?? [];
      if (!Array.isArray(fields) || fields.some((field) => field.valueState !== "redacted")) {
        throw new Error("item_get_metadata did not keep all fields redacted.");
      }
    });

    await runStep("password_read stays redacted by default", async () => {
      const result = await client.callTool({
        name: "password_read",
        arguments: { vaultId, itemId },
      });
      assertToolOk(result, "password_read");
      if (result.structuredContent?.valueState !== "redacted") {
        throw new Error("password_read did not return redacted metadata by default.");
      }
    });
  }

  await runStep("generate password with plaintext acknowledgement", async () => {
    const result = await client.callTool({
      name: "password_generate",
      arguments: {
        length: 24,
        includeSymbols: false,
        reason: "Smoke test generated secret handling",
        acknowledgePlaintext: GENERATED_SECRET_ACK,
      },
    });
    assertToolOk(result, "password_generate");
    if (textContent(result).length !== 24) {
      throw new Error("Generated password did not have the expected length.");
    }
  });
}

async function runRevealChecks(client) {
  if (!envFlag("OP_MCP_SMOKE_ENABLE_REVEAL")) {
    return;
  }

  const reference = optionalEnv("OP_MCP_SMOKE_SECRET_REFERENCE");
  const vaultId = optionalEnv("OP_MCP_SMOKE_VAULT_ID");
  const itemId = optionalEnv("OP_MCP_SMOKE_ITEM_ID");

  if (reference) {
    await runStep("reveal one explicit secret reference", async () => {
      const result = await client.callTool({
        name: "secret_reveal",
        arguments: {
          reference,
          reason: "Smoke test explicit reveal path",
          acknowledgePlaintext: SECRET_REVEAL_ACK,
        },
      });
      assertToolOk(result, "secret_reveal");
      if (!textContent(result)) {
        throw new Error("secret_reveal returned an empty value.");
      }
    });
    return;
  }

  if (vaultId && itemId) {
    await runStep("reveal one explicit item password field", async () => {
      const result = await client.callTool({
        name: "password_read",
        arguments: {
          vaultId,
          itemId,
          field: optionalEnv("OP_MCP_SMOKE_PASSWORD_FIELD"),
          reveal: true,
          reason: "Smoke test explicit password reveal path",
          acknowledgePlaintext: SECRET_REVEAL_ACK,
        },
      });
      assertToolOk(result, "password_read reveal");
      if (!textContent(result)) {
        throw new Error("password_read reveal returned an empty value.");
      }
    });
  }
}

async function runWriteChecks(client) {
  if (!envFlag("OP_MCP_SMOKE_ENABLE_WRITES")) {
    return undefined;
  }

  const vaultId = requiredEnv("OP_MCP_SMOKE_VAULT_ID");
  const title = `mcp-smoke-${new Date().toISOString()}`;
  let createdItemId;

  await runStep("create disposable password item", async () => {
    const result = await client.callTool({
      name: "password_create",
      arguments: {
        vaultId,
        title,
        username: "mcp-smoke",
        mode: "random",
        randomLength: 24,
        tags: ["mcp-smoke-test"],
      },
    });
    assertToolOk(result, "password_create");
    createdItemId = result.structuredContent?.item?.id;
    if (!createdItemId) {
      throw new Error("password_create did not return the created item id.");
    }
  });

  await runStep("update disposable password item", async () => {
    const result = await client.callTool({
      name: "password_update",
      arguments: {
        vaultId,
        itemId: createdItemId,
        mode: "provided",
        password: `smoke-rotated-${randomBytes(12).toString("hex")}`,
      },
    });
    assertToolOk(result, "password_update");
  });

  return { vaultId, itemId: createdItemId };
}

async function runDestructiveChecks(client, createdItem) {
  if (!envFlag("OP_MCP_SMOKE_ENABLE_DESTRUCTIVE")) {
    return;
  }
  if (!createdItem) {
    throw new Error("Destructive smoke checks require OP_MCP_SMOKE_ENABLE_WRITES=true.");
  }

  await runStep("archive disposable item with destructive acknowledgement", async () => {
    const result = await client.callTool({
      name: "item_archive",
      arguments: {
        vaultId: createdItem.vaultId,
        itemId: createdItem.itemId,
        reason: "Smoke test cleanup of disposable item",
        acknowledgeDestructive: DESTRUCTIVE_ACTION_ACK,
      },
    });
    assertToolOk(result, "item_archive");
  });
}

async function runPermissionMutationChecks(client) {
  if (!envFlag("OP_MCP_SMOKE_ENABLE_PERMISSION_MUTATION")) {
    return;
  }
  if (optionalEnv("OP_MCP_SMOKE_CONFIRM_PERMISSION_MUTATION") !== PERMISSION_MUTATION_ACK) {
    throw new Error(
      `Set OP_MCP_SMOKE_CONFIRM_PERMISSION_MUTATION=${PERMISSION_MUTATION_ACK} to run permission mutation smoke checks.`,
    );
  }

  const vaultId = requiredEnv("OP_MCP_SMOKE_VAULT_ID");
  const groupId = requiredEnv("OP_MCP_SMOKE_GROUP_ID");
  const permissions = (optionalEnv("OP_MCP_SMOKE_PERMISSION_NAMES") ?? "READ_ITEMS")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);

  await runStep("grant test group permissions with acknowledgement", async () => {
    const result = await client.callTool({
      name: "vault_permissions_grant_group",
      arguments: {
        vaultId,
        groupId,
        permissions,
        reason: "Smoke test permission mutation path on a disposable vault/group",
        acknowledgePermissionMutation: PERMISSION_MUTATION_ACK,
      },
    });
    assertToolOk(result, "vault_permissions_grant_group");
  });

  await runStep("revoke test group permissions with acknowledgement", async () => {
    const result = await client.callTool({
      name: "vault_permissions_revoke_group",
      arguments: {
        vaultId,
        groupId,
        reason: "Smoke test permission mutation cleanup",
        acknowledgePermissionMutation: PERMISSION_MUTATION_ACK,
      },
    });
    assertToolOk(result, "vault_permissions_revoke_group");
  });
}

async function runScriptRunnerChecks(client) {
  const workspaceRoot = optionalEnv("OP_MCP_SMOKE_SCRIPT_ROOT");
  const commandId = optionalEnv("OP_MCP_SMOKE_SCRIPT_COMMAND_ID");
  if (!workspaceRoot || !commandId) {
    return;
  }

  await runStep("list allowlisted script commands", async () => {
    const result = await client.callTool({
      name: "op_script_list",
      arguments: { workspaceRoot },
    });
    assertToolOk(result, "op_script_list");
  });

  await runStep("run allowlisted script command without returning output", async () => {
    const result = await client.callTool({
      name: "op_script_run",
      arguments: {
        workspaceRoot,
        commandId,
        reason: "Smoke test allowlisted script runner path",
      },
    });
    assertToolOk(result, "op_script_run");
  });
}

async function main() {
  console.log("mcp-1password real smoke test");
  console.log(`auth mode: ${authMode()}`);
  console.log(`audit log: ${auditLogPath}`);

  await withStdioClient(async (client) => {
    await runReadOnlyChecks(client);
    await runRevealChecks(client);
    const createdItem = await runWriteChecks(client);
    await runDestructiveChecks(client, createdItem);
    await runPermissionMutationChecks(client);
    await runScriptRunnerChecks(client);
  });

  await runStep("HTTP transport health, Origin rejection, and MCP connection", async () => {
    await withHttpClient(async (client) => {
      const result = await client.callTool({ name: "sdk_capabilities", arguments: {} });
      assertToolOk(result, "sdk_capabilities over HTTP");
    });
  });

  console.log("Smoke test completed successfully.");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
