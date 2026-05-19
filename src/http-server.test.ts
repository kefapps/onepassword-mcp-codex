import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { MemoryAuditLogger } from "./audit.js";
import type { ServerConfig } from "./config.js";
import { startOnePasswordHttpServer } from "./http-server.js";
import { DefaultOpScriptRunner } from "./op-runner.js";
import type { OnePasswordService } from "./service.js";
import { UnrestrictedApprovalManager } from "./unrestricted-runner.js";

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
    enableDiagnostics: false,
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
    assert.equal(response.headers.get("access-control-allow-origin"), "http://trusted.test");
  } finally {
    await handle.close();
  }
});

test("HTTP MCP endpoint handles CORS preflight for configured origins", async () => {
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
    const response = await fetch(handle.url, {
      method: "OPTIONS",
      headers: {
        origin: "http://trusted.test",
        "access-control-request-method": "POST",
        "access-control-request-headers": "authorization, content-type, mcp-session-id",
      },
    });

    assert.equal(response.status, 204);
    assert.equal(response.headers.get("access-control-allow-origin"), "http://trusted.test");
    assert.match(response.headers.get("access-control-allow-methods") ?? "", /POST/);
    assert.match(response.headers.get("access-control-allow-headers") ?? "", /authorization/);
    assert.match(response.headers.get("access-control-expose-headers") ?? "", /mcp-session-id/);
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

test("HTTP default unrestricted runner reuses the supplied approval manager", async () => {
  const workspaceRoot = tmpdir();
  const config = createConfig({
    enableUnrestrictedRunner: true,
    unrestrictedRunnerRoots: [workspaceRoot],
  });
  const approvalManager = new UnrestrictedApprovalManager(60_000);
  approvalManager.setApprovalBaseUrl("http://127.0.0.1:19000");
  const handle = await startOnePasswordHttpServer(
    config,
    {} as OnePasswordService,
    new MemoryAuditLogger(),
    new DefaultOpScriptRunner(config),
    undefined,
    approvalManager,
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
  } finally {
    await client.close();
    await handle.close();
  }
});

function rawHealthGet(
  url: string,
  hostHeader: string,
): Promise<{ status: number }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const request = httpRequest(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname + parsed.search,
        method: "GET",
        // Force the Host header before Node fills it from hostname:port — fetch
        // forbids setting Host, so we drop down to http.request for this test.
        headers: { host: hostHeader },
      },
      (response) => {
        response.resume();
        response.on("end", () => resolve({ status: response.statusCode ?? 0 }));
      },
    );
    request.on("error", reject);
    request.end();
  });
}

test("HTTP server rejects requests with mismatched Host header", async () => {
  // Defense-in-depth against DNS rebinding: a malicious local process can omit
  // Origin (which the existing check only enforces when present) and reach the
  // socket on 127.0.0.1 via a rebound DNS name. The Host header reveals which
  // name was used and must match the configured listen host:port.
  const config = createConfig();
  const handle = await startOnePasswordHttpServer(
    config,
    {} as OnePasswordService,
    new MemoryAuditLogger(),
    new DefaultOpScriptRunner(config),
  );

  try {
    const { status } = await rawHealthGet(
      handle.url.replace("/mcp", "/healthz"),
      "evil.test",
    );
    assert.equal(status, 403);
  } finally {
    await handle.close();
  }
});

test("HTTP server accepts requests with localhost Host header", async () => {
  // Sanity check: clients addressing the server as `localhost:<port>` (the
  // common case for fetch from a local dev tool) must still pass the Host
  // whitelist after the rebind-protection lands.
  const config = createConfig();
  const handle = await startOnePasswordHttpServer(
    config,
    {} as OnePasswordService,
    new MemoryAuditLogger(),
    new DefaultOpScriptRunner(config),
  );

  try {
    const port = new URL(handle.url).port;
    const { status } = await rawHealthGet(
      handle.url.replace("/mcp", "/healthz"),
      `localhost:${port}`,
    );
    assert.equal(status, 200);
  } finally {
    await handle.close();
  }
});
