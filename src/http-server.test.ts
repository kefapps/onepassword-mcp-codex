import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { MemoryAuditLogger } from "./audit.js";
import type { ServerConfig } from "./config.js";
import { startOnePasswordHttpServer } from "./http-server.js";
import { DefaultOpScriptRunner } from "./op-runner.js";
import type { OnePasswordService } from "./service.js";

function createConfig(overrides: Partial<ServerConfig> = {}): ServerConfig {
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
    transport: "http",
    httpHost: "127.0.0.1",
    httpPort: 0,
    httpPath: "/mcp",
    httpRequireBearer: true,
    httpBearerToken: "local-token",
    auditLogPath: "/tmp/onepassword-mcp-test-audit.jsonl",
    logLevel: "info",
    integrationName: "Test",
    integrationVersion: "0.1.0",
    ...overrides,
  };
}

test("HTTP server exposes unauthenticated health status", async () => {
  const config = createConfig();
  const handle = await startOnePasswordHttpServer(
    config,
    {} as OnePasswordService,
    new MemoryAuditLogger(),
    new DefaultOpScriptRunner(config),
  );

  try {
    const response = await fetch(handle.url.replace("/mcp", "/healthz"));
    const payload = (await response.json()) as {
      ok: boolean;
    };

    assert.equal(response.status, 200);
    assert.equal(payload.ok, true);
  } finally {
    await handle.close();
  }
});

test("HTTP MCP endpoint rejects missing bearer token", async () => {
  const config = createConfig();
  const handle = await startOnePasswordHttpServer(
    config,
    {} as OnePasswordService,
    new MemoryAuditLogger(),
    new DefaultOpScriptRunner(config),
  );

  try {
    const response = await fetch(handle.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "test", version: "1.0.0" },
        },
      }),
    });

    assert.equal(response.status, 401);
  } finally {
    await handle.close();
  }
});

test("HTTP MCP initialize responds with JSON, not SSE", async () => {
  const config = createConfig();
  const handle = await startOnePasswordHttpServer(
    config,
    {} as OnePasswordService,
    new MemoryAuditLogger(),
    new DefaultOpScriptRunner(config),
  );

  try {
    const response = await fetch(handle.url, {
      method: "POST",
      headers: {
        accept: "application/json, text/event-stream",
        authorization: "Bearer local-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "test", version: "1.0.0" },
        },
      }),
    });

    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type") ?? "", /^application\/json\b/);
    assert.notEqual(response.headers.get("content-type"), "text/event-stream");

    const payload = (await response.json()) as {
      jsonrpc: string;
      id: number;
      result?: {
        serverInfo?: {
          name?: string;
        };
      };
    };
    assert.equal(payload.jsonrpc, "2.0");
    assert.equal(payload.id, 1);
    assert.equal(payload.result?.serverInfo?.name, "mcp-1password");
  } finally {
    await handle.close();
  }
});

test("HTTP MCP endpoint accepts bearer-authenticated clients", async () => {
  const config = createConfig();
  const handle = await startOnePasswordHttpServer(
    config,
    {} as OnePasswordService,
    new MemoryAuditLogger(),
    new DefaultOpScriptRunner(config),
  );
  const transport = new StreamableHTTPClientTransport(new URL(handle.url), {
    requestInit: {
      headers: {
        authorization: "Bearer local-token",
      },
    },
  });
  const client = new Client({ name: "test-client", version: "1.0.0" });

  try {
    await client.connect(transport);
    const tools = await client.listTools();

    assert(tools.tools.some((tool) => tool.name === "sdk_capabilities"));
    assert(!tools.tools.some((tool) => tool.name === "op_script_run"));
  } finally {
    await client.close();
    await handle.close();
  }
});
