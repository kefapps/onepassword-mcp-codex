import { timingSafeEqual, randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { AuditLogger } from "./audit.js";
import type { ServerConfig } from "./config.js";
import type { OpScriptRunner } from "./op-runner.js";
import { createOnePasswordMcpServer } from "./server.js";
import type { OnePasswordService } from "./service.js";

const MAX_HTTP_BODY_BYTES = 1024 * 1024;

export interface OnePasswordHttpServerHandle {
  server: Server;
  url: string;
  close(): Promise<void>;
}

function sendJson(
  response: ServerResponse,
  statusCode: number,
  payload: Record<string, unknown>,
): void {
  response.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
  });
  response.end(`${JSON.stringify(payload)}\n`);
}

function forbiddenResponse(response: ServerResponse): void {
  response.writeHead(401, {
    "content-type": "application/json; charset=utf-8",
    "www-authenticate": "Bearer",
  });
  response.end(
    `${JSON.stringify({
      jsonrpc: "2.0",
      error: {
        code: -32001,
        message: "Unauthorized",
      },
      id: null,
    })}\n`,
  );
}

function notFoundResponse(response: ServerResponse): void {
  sendJson(response, 404, { error: "not_found" });
}

function methodNotAllowedResponse(response: ServerResponse): void {
  sendJson(response, 405, { error: "method_not_allowed" });
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
      throw new Error("HTTP request body too large.");
    }
    chunks.push(buffer);
  }

  if (chunks.length === 0) {
    return undefined;
  }

  const body = Buffer.concat(chunks).toString("utf8").trim();
  return body ? JSON.parse(body) : undefined;
}

function assertAuthorized(config: ServerConfig, request: IncomingMessage): boolean {
  if (!config.httpRequireBearer) {
    return true;
  }
  return isExpectedBearerToken(request.headers.authorization, config.httpBearerToken ?? "");
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
): Promise<OnePasswordHttpServerHandle> {
  const transports = new Map<string, StreamableHTTPServerTransport>();

  const httpServer = createServer(async (request, response) => {
    try {
      const path = new URL(request.url ?? "/", `http://${request.headers.host ?? "127.0.0.1"}`).pathname;

      if (path === "/healthz") {
        sendJson(response, 200, { ok: true });
        return;
      }

      if (path !== config.httpPath) {
        notFoundResponse(response);
        return;
      }

      if (!assertAuthorized(config, request)) {
        forbiddenResponse(response);
        return;
      }

      if (request.method !== "GET" && request.method !== "POST" && request.method !== "DELETE") {
        methodNotAllowedResponse(response);
        return;
      }

      const body = request.method === "POST" ? await readJsonBody(request) : undefined;
      const sessionId = request.headers["mcp-session-id"];
      const existingSessionId = Array.isArray(sessionId) ? undefined : sessionId;
      let transport = existingSessionId ? transports.get(existingSessionId) : undefined;

      if (
        !transport &&
        !existingSessionId &&
        request.method === "POST" &&
        isInitializeRequest(body)
      ) {
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          enableJsonResponse: true,
          onsessioninitialized: (initializedSessionId) => {
            if (transport) {
              transports.set(initializedSessionId, transport);
            }
          },
        });
        transport.onclose = () => {
          if (transport?.sessionId) {
            transports.delete(transport.sessionId);
          }
        };

        const mcpServer = createOnePasswordMcpServer(
          config,
          service,
          auditLogger,
          scriptRunner,
        );
        await mcpServer.connect(transport);
      }

      if (!transport) {
        sendJson(response, 400, {
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: "Bad Request: No valid MCP session.",
          },
          id: null,
        });
        return;
      }

      await transport.handleRequest(request, response, body);
    } catch (error) {
      if (!response.headersSent) {
        sendJson(response, 500, {
          jsonrpc: "2.0",
          error: {
            code: -32603,
            message: error instanceof Error ? error.message : "Internal server error",
          },
          id: null,
        });
      } else {
        response.end();
      }
    }
  });

  await listen(httpServer, config.httpHost, config.httpPort);
  const address = httpServer.address();
  const port = typeof address === "object" && address ? address.port : config.httpPort;

  return {
    server: httpServer,
    url: `http://${config.httpHost}:${port}${config.httpPath}`,
    async close() {
      await Promise.all(
        Array.from(transports.values()).map(async (transport) => {
          await transport.close();
        }),
      );
      transports.clear();
      await closeServer(httpServer);
    },
  };
}
