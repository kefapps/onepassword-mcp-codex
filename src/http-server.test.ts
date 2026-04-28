import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { MemoryAuditLogger } from "./audit.js";
import type { ServerConfig } from "./config.js";
import { startOnePasswordHttpServer } from "./http-server.js";
import { DefaultOpScriptRunner } from "./op-runner.js";
import type { OnePasswordService } from "./service.js";

const HTTP_TOKEN = "local-token-123456";

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
    httpBearerToken: HTTP_TOKEN,
    httpAllowedOrigins: [],
    httpMaxSessions: 64,
    httpSessionIdleMs: 15 * 60_000,
    httpRequestTimeoutMs: 30_000,
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

test("HTTP server rejects invalid browser origins", async () => {
  const config = createConfig();
  const handle = await startOnePasswordHttpServer(
    config,
    {} as OnePasswordService,
    new MemoryAuditLogger(),
    new DefaultOpScriptRunner(config),
  );

  try {
    const response = await fetch(handle.url.replace("/mcp", "/healthz"), {
      headers: {
        origin: "http://evil.test",
      },
    });

    assert.equal(response.status, 403);
  } finally {
    await handle.close();
  }
});

test("HTTP server allows configured origins", async () => {
  const config = createConfig({
    httpAllowedOrigins: ["http://trusted.test"],
  });
  const handle = await startOnePasswordHttpServer(
    config,
    {} as OnePasswordService,
    new MemoryAuditLogger(),
    new DefaultOpScriptRunner(config),
  );

  try {
    const response = await fetch(handle.url.replace("/mcp", "/healthz"), {
      headers: {
        origin: "http://trusted.test",
      },
    });

    assert.equal(response.status, 200);
  } finally {
    await handle.close();
  }
});

test("HTTP MCP endpoint returns 400 on malformed JSON", async () => {
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
        authorization: `Bearer ${HTTP_TOKEN}`,
        "content-type": "application/json",
      },
      body: "{",
    });
    const payload = (await response.json()) as {
      error?: { message?: string };
    };

    assert.equal(response.status, 400);
    assert.equal(payload.error?.message, "Malformed JSON request body.");
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
        authorization: `Bearer ${HTTP_TOKEN}`,
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

test("HTTP MCP endpoint enforces max session count", async () => {
  const config = createConfig({ httpMaxSessions: 1 });
  const handle = await startOnePasswordHttpServer(
    config,
    {} as OnePasswordService,
    new MemoryAuditLogger(),
    new DefaultOpScriptRunner(config),
  );
  const initializeBody = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "test", version: "1.0.0" },
    },
  };

  try {
    const first = await fetch(handle.url, {
      method: "POST",
      headers: {
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${HTTP_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(initializeBody),
    });
    const second = await fetch(handle.url, {
      method: "POST",
      headers: {
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${HTTP_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ ...initializeBody, id: 2 }),
    });

    assert.equal(first.status, 200);
    assert.equal(second.status, 503);
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
        authorization: `Bearer ${HTTP_TOKEN}`,
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
