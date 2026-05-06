import { timingSafeEqual, randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { AuditLogger } from "./audit.js";
import type { ServerConfig } from "./config.js";
import type { OpScriptRunner } from "./op-runner.js";
import { createOnePasswordMcpServer } from "./server.js";
import type { OnePasswordService } from "./service.js";
import {
  DefaultUnrestrictedRunner,
  UnrestrictedApprovalManager,
  type UnrestrictedRunner,
} from "./unrestricted-runner.js";

const MAX_HTTP_BODY_BYTES = 1024 * 1024;

export interface OnePasswordHttpServerHandle {
  server: Server;
  url: string;
  close(): Promise<void>;
}

class HttpRequestError extends Error {
  public constructor(
    public readonly statusCode: number,
    message: string,
  ) {
    super(message);
  }
}

interface SessionEntry {
  transport: StreamableHTTPServerTransport;
  idleTimer: NodeJS.Timeout;
}

function sendJson(
  response: ServerResponse,
  statusCode: number,
  payload: Record<string, unknown>,
  headers: Record<string, string> = {},
): void {
  response.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    ...headers,
  });
  response.end(`${JSON.stringify(payload)}\n`);
}

function jsonRpcErrorResponse(
  response: ServerResponse,
  statusCode: number,
  code: number,
  message: string,
  headers: Record<string, string> = {},
): void {
  sendJson(
    response,
    statusCode,
    {
      jsonrpc: "2.0",
      error: {
        code,
        message,
      },
      id: null,
    },
    headers,
  );
}

function unauthorizedResponse(response: ServerResponse): void {
  jsonRpcErrorResponse(response, 401, -32001, "Unauthorized", {
    "www-authenticate": "Bearer",
  });
}

function forbiddenResponse(response: ServerResponse): void {
  jsonRpcErrorResponse(response, 403, -32003, "Forbidden");
}

function notFoundResponse(response: ServerResponse): void {
  sendJson(response, 404, { error: "not_found" });
}

function methodNotAllowedResponse(response: ServerResponse): void {
  sendJson(response, 405, { error: "method_not_allowed" }, { allow: "GET, POST, DELETE" });
}

function isExpectedBearerToken(header: string | string[] | undefined, token: string): boolean {
  if (!header || Array.isArray(header)) {
    return false;
  }

  const [scheme, value] = header.split(/\s+/, 2);
  if (scheme?.toLowerCase() !== "bearer" || !value) {
    return false;
  }

  const expected = Buffer.from(token);
  const actual = Buffer.from(value);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let bytesRead = 0;

  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytesRead += buffer.length;
    if (bytesRead > MAX_HTTP_BODY_BYTES) {
      throw new HttpRequestError(413, "HTTP request body too large.");
    }
    chunks.push(buffer);
  }

  if (chunks.length === 0) {
    return undefined;
  }

  const body = Buffer.concat(chunks).toString("utf8").trim();
  try {
    return body ? JSON.parse(body) : undefined;
  } catch {
    throw new HttpRequestError(400, "Malformed JSON request body.");
  }
}

function assertAuthorized(config: ServerConfig, request: IncomingMessage): boolean {
  if (!config.httpRequireBearer) {
    return true;
  }
  return isExpectedBearerToken(request.headers.authorization, config.httpBearerToken ?? "");
}

function localDefaultOrigins(port: number): Set<string> {
  return new Set([
    `http://127.0.0.1:${port}`,
    `http://localhost:${port}`,
    `http://[::1]:${port}`,
  ]);
}

function isLocalHost(host: string): boolean {
  return host === "127.0.0.1" || host === "localhost" || host === "::1";
}

function allowedOrigins(config: ServerConfig, port: number): Set<string> {
  if (config.httpAllowedOrigins.length > 0) {
    return new Set(config.httpAllowedOrigins);
  }
  return isLocalHost(config.httpHost) ? localDefaultOrigins(port) : new Set();
}

function assertOriginAllowed(
  config: ServerConfig,
  request: IncomingMessage,
  port: number,
): boolean {
  const origin = request.headers.origin;
  if (!origin) {
    return true;
  }
  if (Array.isArray(origin)) {
    return false;
  }
  return allowedOrigins(config, port).has(origin);
}

function listen(server: Server, host: string, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

export async function startOnePasswordHttpServer(
  config: ServerConfig,
  service: OnePasswordService,
  auditLogger: AuditLogger,
  scriptRunner: OpScriptRunner,
  unrestrictedRunner: UnrestrictedRunner = new DefaultUnrestrictedRunner(
    config,
    new UnrestrictedApprovalManager(config.unrestrictedRunnerApprovalTtlMs),
  ),
): Promise<OnePasswordHttpServerHandle> {
  const transports = new Map<string, SessionEntry>();
  const clearSession = (sessionId: string): void => {
    const entry = transports.get(sessionId);
    if (!entry) {
      return;
    }
    clearTimeout(entry.idleTimer);
    transports.delete(sessionId);
  };
  const refreshSession = (sessionId: string, transport: StreamableHTTPServerTransport): void => {
    const existing = transports.get(sessionId);
    if (existing) {
      clearTimeout(existing.idleTimer);
    }
    const idleTimer = setTimeout(() => {
      clearSession(sessionId);
      void transport.close();
    }, config.httpSessionIdleMs);
    idleTimer.unref();
    transports.set(sessionId, { transport, idleTimer });
  };

  const httpServer = createServer(async (request, response) => {
    try {
      const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
      const address = httpServer.address();
      const port = typeof address === "object" && address ? address.port : config.httpPort;

      if (!assertOriginAllowed(config, request, port)) {
        forbiddenResponse(response);
        return;
      }

      if (path === "/healthz") {
        sendJson(response, 200, { ok: true });
        return;
      }

      if (path !== config.httpPath) {
        notFoundResponse(response);
        return;
      }

      if (!assertAuthorized(config, request)) {
        unauthorizedResponse(response);
        return;
      }

      if (request.method !== "GET" && request.method !== "POST" && request.method !== "DELETE") {
        methodNotAllowedResponse(response);
        return;
      }

      const body = request.method === "POST" ? await readJsonBody(request) : undefined;
      const sessionId = request.headers["mcp-session-id"];
      const existingSessionId = Array.isArray(sessionId) ? undefined : sessionId;
      const sessionEntry = existingSessionId ? transports.get(existingSessionId) : undefined;
      let transport = sessionEntry?.transport;
      if (existingSessionId && transport) {
        refreshSession(existingSessionId, transport);
      }

      if (
        !transport &&
        !existingSessionId &&
        request.method === "POST" &&
        isInitializeRequest(body)
      ) {
        if (transports.size >= config.httpMaxSessions) {
          jsonRpcErrorResponse(response, 503, -32004, "Too many active MCP sessions.");
          return;
        }
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          enableJsonResponse: true,
          onsessioninitialized: (initializedSessionId) => {
            if (transport) {
              refreshSession(initializedSessionId, transport);
            }
          },
        });
        transport.onclose = () => {
          if (transport?.sessionId) {
            clearSession(transport.sessionId);
          }
        };

        const mcpServer = createOnePasswordMcpServer(
          config,
          service,
          auditLogger,
          scriptRunner,
          unrestrictedRunner,
        );
        await mcpServer.connect(transport);
      }

      if (!transport) {
        jsonRpcErrorResponse(response, 400, -32000, "Bad Request: No valid MCP session.");
        return;
      }

      await transport.handleRequest(request, response, body);
    } catch (error) {
      if (!response.headersSent) {
        if (error instanceof HttpRequestError) {
          jsonRpcErrorResponse(response, error.statusCode, -32000, error.message);
          return;
        }
        jsonRpcErrorResponse(response, 500, -32603, "Internal server error");
      } else {
        response.end();
      }
    }
  });
  httpServer.requestTimeout = config.httpRequestTimeoutMs;
  httpServer.headersTimeout = Math.max(1_000, config.httpRequestTimeoutMs + 1_000);

  await listen(httpServer, config.httpHost, config.httpPort);
  const address = httpServer.address();
  const port = typeof address === "object" && address ? address.port : config.httpPort;

  return {
    server: httpServer,
    url: `http://${config.httpHost}:${port}${config.httpPath}`,
    async close() {
      await Promise.all(
        Array.from(transports.values()).map(async (entry) => {
          clearTimeout(entry.idleTimer);
          await entry.transport.close();
        }),
      );
      transports.clear();
      await closeServer(httpServer);
    },
  };
}
