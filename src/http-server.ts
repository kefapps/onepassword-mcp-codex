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
  createUnrestrictedApprovalManager,
  type UnrestrictedRunner,
} from "./unrestricted-runner.js";

const MAX_HTTP_BODY_BYTES = 1024 * 1024;
const HTTP_METHODS = "GET, POST, DELETE, OPTIONS";
const CORS_ALLOWED_HEADERS =
  "authorization, content-type, mcp-session-id, mcp-protocol-version";

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

function unauthorizedResponse(
  response: ServerResponse,
  headers: Record<string, string> = {},
): void {
  jsonRpcErrorResponse(response, 401, -32001, "Unauthorized", {
    ...headers,
    "www-authenticate": "Bearer",
  });
}

function forbiddenResponse(
  response: ServerResponse,
  headers: Record<string, string> = {},
): void {
  jsonRpcErrorResponse(response, 403, -32003, "Forbidden", headers);
}

function notFoundResponse(
  response: ServerResponse,
  headers: Record<string, string> = {},
): void {
  sendJson(response, 404, { error: "not_found" }, headers);
}

function methodNotAllowedResponse(
  response: ServerResponse,
  headers: Record<string, string> = {},
): void {
  sendJson(response, 405, { error: "method_not_allowed" }, {
    ...headers,
    allow: HTTP_METHODS,
  });
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

function isWildcardBind(host: string): boolean {
  // Listening on a wildcard address means the configured host name is just
  // "any interface" — it is never what clients put in the Host header. They
  // reach us via the service's real DNS name or one of the machine's IPs.
  return host === "" || host === "0.0.0.0" || host === "::" || host === "::0" || host === "*";
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

function localDefaultHosts(port: number): Set<string> {
  return new Set([
    `127.0.0.1:${port}`,
    `localhost:${port}`,
    `[::1]:${port}`,
  ]);
}

function originHostname(origin: string): string | undefined {
  try {
    return new URL(origin).host;
  } catch {
    return undefined;
  }
}

function allowedHosts(config: ServerConfig, port: number): Set<string> {
  // The Host header reflects which name the client used to reach us, not
  // which Origin a browser was running on. Always include the configured
  // listen address; httpAllowedOrigins adds CORS-trusted hostnames on top.
  // Wildcard binds (0.0.0.0, ::) are skipped here — the wildcard literal is
  // never what a real client sends; see assertHostAllowed for that path.
  const hosts = new Set<string>();
  if (isLocalHost(config.httpHost)) {
    for (const host of localDefaultHosts(port)) {
      hosts.add(host);
    }
  } else if (!isWildcardBind(config.httpHost)) {
    hosts.add(`${config.httpHost}:${port}`.toLowerCase());
  }
  for (const origin of config.httpAllowedOrigins) {
    const host = originHostname(origin);
    if (host) {
      hosts.add(host.toLowerCase());
    }
  }
  return hosts;
}

function assertHostAllowed(
  config: ServerConfig,
  request: IncomingMessage,
  port: number,
): boolean {
  // Defense-in-depth against DNS rebinding: the Origin check above only fires
  // when a browser sets the header. A non-browser client (curl, scripted
  // attacker) can omit Origin entirely; the Host header is required by
  // HTTP/1.1 and reflects which name the client used to resolve us.
  const host = request.headers.host;
  if (!host || Array.isArray(host)) {
    return false;
  }
  // Wildcard binds (0.0.0.0, ::) carry no hint about what hostname clients
  // should use; with no operator-supplied allowlist we cannot tell legitimate
  // traffic from a rebind. Fall back to "accept any Host" so the standard
  // HTTP transport behaviour stays intact; operators who want strict Host
  // pinning under a wildcard bind enumerate hostnames via httpAllowedOrigins.
  if (isWildcardBind(config.httpHost) && config.httpAllowedOrigins.length === 0) {
    return true;
  }
  return allowedHosts(config, port).has(host.toLowerCase());
}

function corsHeaders(
  config: ServerConfig,
  request: IncomingMessage,
  port: number,
): Record<string, string> {
  const origin = request.headers.origin;
  if (!origin || Array.isArray(origin) || !allowedOrigins(config, port).has(origin)) {
    return {};
  }

  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": HTTP_METHODS,
    "access-control-allow-headers": CORS_ALLOWED_HEADERS,
    "access-control-expose-headers": "mcp-session-id",
    "access-control-max-age": "600",
    vary: "Origin",
  };
}

function noContentResponse(
  response: ServerResponse,
  headers: Record<string, string> = {},
): void {
  response.writeHead(204, headers);
  response.end();
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
  providedUnrestrictedRunner?: UnrestrictedRunner,
  providedApprovalManager?: UnrestrictedApprovalManager,
): Promise<OnePasswordHttpServerHandle> {
  const approvalManager =
    providedApprovalManager ?? createUnrestrictedApprovalManager(config);
  const unrestrictedRunner =
    providedUnrestrictedRunner ??
    new DefaultUnrestrictedRunner(config, approvalManager);
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
    let responseHeaders: Record<string, string> = {};
    try {
      const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
      const address = httpServer.address();
      const port = typeof address === "object" && address ? address.port : config.httpPort;

      if (!assertOriginAllowed(config, request, port)) {
        forbiddenResponse(response);
        return;
      }
      if (!assertHostAllowed(config, request, port)) {
        forbiddenResponse(response);
        return;
      }
      responseHeaders = corsHeaders(config, request, port);

      if (path === "/healthz") {
        if (request.method === "OPTIONS") {
          noContentResponse(response, responseHeaders);
          return;
        }
        sendJson(response, 200, { ok: true }, responseHeaders);
        return;
      }

      if (path !== config.httpPath) {
        notFoundResponse(response, responseHeaders);
        return;
      }

      if (request.method === "OPTIONS") {
        noContentResponse(response, responseHeaders);
        return;
      }

      if (!assertAuthorized(config, request)) {
        unauthorizedResponse(response, responseHeaders);
        return;
      }

      if (request.method !== "GET" && request.method !== "POST" && request.method !== "DELETE") {
        methodNotAllowedResponse(response, responseHeaders);
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
          jsonRpcErrorResponse(
            response,
            503,
            -32004,
            "Too many active MCP sessions.",
            responseHeaders,
          );
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
          approvalManager,
        );
        await mcpServer.connect(transport);
      }

      if (!transport) {
        jsonRpcErrorResponse(
          response,
          400,
          -32000,
          "Bad Request: No valid MCP session.",
          responseHeaders,
        );
        return;
      }

      for (const [header, value] of Object.entries(responseHeaders)) {
        response.setHeader(header, value);
      }
      await transport.handleRequest(request, response, body);
    } catch (error) {
      if (!response.headersSent) {
        if (error instanceof HttpRequestError) {
          jsonRpcErrorResponse(
            response,
            error.statusCode,
            -32000,
            error.message,
            responseHeaders,
          );
          return;
        }
        jsonRpcErrorResponse(
          response,
          500,
          -32603,
          "Internal server error",
          responseHeaders,
        );
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
