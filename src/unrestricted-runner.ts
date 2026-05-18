import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { realpath } from "node:fs/promises";
import { dirname, isAbsolute, relative, sep } from "node:path";
import type { AuditLogger } from "./audit.js";
import type { ServerConfig } from "./config.js";
import { UNRESTRICTED_RUNNER_ACK } from "./constants.js";
import {
  DEFAULT_OUTPUT_LIMIT_BYTES,
  NodeProcessRunner,
  type ProcessRunResult,
  type ProcessRunner,
} from "./op-runner.js";

const PENDING_APPROVAL_TTL_MS = 10 * 60_000;
const APPROVAL_FORM_MAX_BYTES = 16 * 1024;
const REMEMBER_APPROVAL_TTL_MS = 24 * 60 * 60_000;
const APPROVAL_STORE_ALGORITHM = "aes-256-gcm";

export interface UnrestrictedRunnerStatus {
  enabled: boolean;
  configuredRootCount: number;
  requireSessionApproval: boolean;
  approvalServerAvailable: boolean;
  approvedRootCount: number;
  approvalTtlMs: number;
  commandTimeoutMs: number;
}

export interface UnrestrictedAuthorizationRequired {
  authorizationRequired: true;
  approvalUrl: string;
  workspaceRoot: string;
  configuredRoot: string;
  acknowledgement: typeof UNRESTRICTED_RUNNER_ACK;
  warning: string;
  expiresAt: string;
}

export interface UnrestrictedRunResult extends ProcessRunResult {
  workspaceRoot: string;
  configuredRoot: string;
  cwd: string;
  command: string;
  shell: string;
  shellArgs: string[];
  sensitiveOutput: true;
}

export interface UnrestrictedRunner {
  authorization(workspaceRoot: string): Promise<UnrestrictedAuthorizationRequired | undefined>;
  run(workspaceRoot: string, command: string): Promise<UnrestrictedRunResult>;
  status(): UnrestrictedRunnerStatus;
}

interface PendingApproval {
  token: string;
  configuredRoot: string;
  workspaceRoot: string;
  expiresAtMs: number;
}

interface ApprovalGrant {
  expiresAtMs: number;
}

interface ApprovalPersistenceConfig {
  storePath: string;
  keyPath: string;
  rememberTtlMs?: number;
}

interface PersistentApprovalGrant {
  configuredRoot: string;
  expiresAtMs: number;
}

interface ResolvedWorkspace {
  workspaceRoot: string;
  configuredRoot: string;
}

export interface UnrestrictedApprovalResult {
  configuredRoot: string;
  expiresAt: string;
  remembered: boolean;
}

export class UnrestrictedApprovalManager {
  private approvalBaseUrl?: string;
  private readonly pendingApprovals = new Map<string, PendingApproval>();
  private readonly grants = new Map<string, ApprovalGrant>();
  private readonly persistentGrantScopes = new Set<string>();

  public constructor(
    private readonly approvalTtlMs: number,
    private readonly persistence?: ApprovalPersistenceConfig,
  ) {
    this.loadPersistentGrants();
  }

  public setApprovalBaseUrl(url: string): void {
    this.approvalBaseUrl = url.replace(/\/$/, "");
  }

  public get approvalServerAvailable(): boolean {
    return Boolean(this.approvalBaseUrl);
  }

  public get approvedRootCount(): number {
    this.pruneExpired();
    return this.grants.size;
  }

  public isApproved(configuredRoot: string): boolean {
    this.pruneExpired();
    return this.grants.has(configuredRoot);
  }

  public createAuthorizationRequest(
    workspaceRoot: string,
    configuredRoot: string,
  ): UnrestrictedAuthorizationRequired {
    this.pruneExpired();
    if (!this.approvalBaseUrl) {
      throw new Error("Unrestricted runner approval server is not available.");
    }

    const token = randomBytes(32).toString("base64url");
    const expiresAtMs = Date.now() + PENDING_APPROVAL_TTL_MS;
    this.pendingApprovals.set(token, {
      token,
      configuredRoot,
      workspaceRoot,
      expiresAtMs,
    });

    const sessionWide = configuredRoot === "unrestricted-script-runner-session";
    return {
      authorizationRequired: true,
      approvalUrl: `${this.approvalBaseUrl}/approve?token=${encodeURIComponent(token)}`,
      workspaceRoot,
      configuredRoot,
      acknowledgement: UNRESTRICTED_RUNNER_ACK,
      warning: sessionWide
        ? "Approval permits arbitrary local op_script_run command execution for this MCP process. This is an approval scope, not an operating-system sandbox."
        : "Approval permits arbitrary local command execution for this configured root in the current MCP process. The path is an approval scope, not an operating-system sandbox.",
      expiresAt: new Date(expiresAtMs).toISOString(),
    };
  }

  public getPendingApproval(token: string): PendingApproval | undefined {
    this.pruneExpired();
    return this.pendingApprovals.get(token);
  }

  public approveToken(
    token: string,
    acceptedRisk: boolean,
    acknowledgement: string | undefined,
    rememberFor24h = false,
  ): UnrestrictedApprovalResult {
    this.pruneExpired();
    const pending = this.pendingApprovals.get(token);
    if (!pending) {
      throw new Error("Approval request was not found or has expired.");
    }
    if (!acceptedRisk || acknowledgement !== UNRESTRICTED_RUNNER_ACK) {
      throw new Error("Approval requires the risk checkbox and exact acknowledgement phrase.");
    }

    const remembered = rememberFor24h && Boolean(this.persistence);
    const expiresAtMs =
      Date.now() +
      (rememberFor24h
        ? (this.persistence?.rememberTtlMs ?? REMEMBER_APPROVAL_TTL_MS)
        : this.approvalTtlMs);
    this.pendingApprovals.delete(token);
    this.grants.set(pending.configuredRoot, { expiresAtMs });
    if (remembered) {
      this.persistentGrantScopes.add(pending.configuredRoot);
      this.writePersistentGrants();
    }
    return {
      configuredRoot: pending.configuredRoot,
      expiresAt: new Date(expiresAtMs).toISOString(),
      remembered,
    };
  }

  private pruneExpired(): void {
    const now = Date.now();
    let persistentGrantsChanged = false;
    for (const [token, pending] of this.pendingApprovals) {
      if (pending.expiresAtMs <= now) {
        this.pendingApprovals.delete(token);
      }
    }
    for (const [root, grant] of this.grants) {
      if (grant.expiresAtMs <= now) {
        this.grants.delete(root);
        if (this.persistentGrantScopes.delete(root)) {
          persistentGrantsChanged = true;
        }
      }
    }
    if (persistentGrantsChanged) {
      this.writePersistentGrants();
    }
  }

  private loadPersistentGrants(): void {
    if (!this.persistence || !existsSync(this.persistence.storePath)) {
      return;
    }

    try {
      const encrypted = JSON.parse(readFileSync(this.persistence.storePath, "utf8")) as {
        version?: number;
        algorithm?: string;
        iv?: string;
        tag?: string;
        ciphertext?: string;
      };
      if (
        encrypted.version !== 1 ||
        encrypted.algorithm !== APPROVAL_STORE_ALGORITHM ||
        !encrypted.iv ||
        !encrypted.tag ||
        !encrypted.ciphertext
      ) {
        return;
      }

      const key = readOrCreateApprovalStoreKey(this.persistence.keyPath);
      const decipher = createDecipheriv(
        APPROVAL_STORE_ALGORITHM,
        key,
        Buffer.from(encrypted.iv, "base64"),
      );
      decipher.setAuthTag(Buffer.from(encrypted.tag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(encrypted.ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
      const payload = JSON.parse(plaintext) as {
        version?: number;
        grants?: PersistentApprovalGrant[];
      };
      if (payload.version !== 1 || !Array.isArray(payload.grants)) {
        return;
      }

      const now = Date.now();
      for (const grant of payload.grants) {
        if (
          typeof grant.configuredRoot === "string" &&
          Number.isFinite(grant.expiresAtMs) &&
          grant.expiresAtMs > now
        ) {
          this.grants.set(grant.configuredRoot, {
            expiresAtMs: grant.expiresAtMs,
          });
          this.persistentGrantScopes.add(grant.configuredRoot);
        }
      }
    } catch {
      return;
    }
  }

  private writePersistentGrants(): void {
    if (!this.persistence) {
      return;
    }

    const grants = [...this.persistentGrantScopes]
      .map((configuredRoot) => ({
        configuredRoot,
        expiresAtMs: this.grants.get(configuredRoot)?.expiresAtMs,
      }))
      .filter(
        (grant): grant is PersistentApprovalGrant =>
          typeof grant.expiresAtMs === "number" && grant.expiresAtMs > Date.now(),
      );
    const key = readOrCreateApprovalStoreKey(this.persistence.keyPath);
    const iv = randomBytes(12);
    const cipher = createCipheriv(APPROVAL_STORE_ALGORITHM, key, iv);
    const plaintext = Buffer.from(
      JSON.stringify({
        version: 1,
        grants,
      }),
      "utf8",
    );
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const payload = {
      version: 1,
      algorithm: APPROVAL_STORE_ALGORITHM,
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };

    mkdirSync(dirname(this.persistence.storePath), { recursive: true, mode: 0o700 });
    writeFileSync(this.persistence.storePath, `${JSON.stringify(payload, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    chmodSync(this.persistence.storePath, 0o600);
  }
}

export interface UnrestrictedApprovalServerHandle {
  server: Server;
  url: string;
  close(): Promise<void>;
}

class ApprovalRequestError extends Error {
  public constructor(
    public readonly statusCode: number,
    message: string,
  ) {
    super(message);
  }
}

function readOrCreateApprovalStoreKey(keyPath: string): Buffer {
  mkdirSync(dirname(keyPath), { recursive: true, mode: 0o700 });
  if (existsSync(keyPath)) {
    const key = Buffer.from(readFileSync(keyPath, "utf8").trim(), "base64");
    if (key.length === 32) {
      return key;
    }
  }

  const key = randomBytes(32);
  writeFileSync(keyPath, `${key.toString("base64")}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  chmodSync(keyPath, 0o600);
  return key;
}

export class DefaultUnrestrictedRunner implements UnrestrictedRunner {
  private readonly configuredRoots: string[];

  public constructor(
    private readonly config: ServerConfig,
    private readonly approvalManager: UnrestrictedApprovalManager,
    private readonly processRunner: ProcessRunner = new NodeProcessRunner(),
  ) {
    this.configuredRoots = config.enableUnrestrictedRunner
      ? config.unrestrictedRunnerRoots
          .map((root) => realpathSync(root))
          .sort((left, right) => right.length - left.length)
      : [];
  }

  public status(): UnrestrictedRunnerStatus {
    return {
      enabled: this.config.enableUnrestrictedRunner,
      configuredRootCount: this.configuredRoots.length,
      requireSessionApproval: this.config.unrestrictedRunnerRequireSessionApproval,
      approvalServerAvailable: this.approvalManager.approvalServerAvailable,
      approvedRootCount: this.approvalManager.approvedRootCount,
      approvalTtlMs: this.config.unrestrictedRunnerApprovalTtlMs,
      commandTimeoutMs: this.config.unrestrictedRunnerCommandTimeoutMs,
    };
  }

  public async authorization(
    workspaceRoot: string,
  ): Promise<UnrestrictedAuthorizationRequired | undefined> {
    const resolved = await this.resolveWorkspace(workspaceRoot);
    if (
      this.config.unrestrictedRunnerRequireSessionApproval &&
      !this.approvalManager.isApproved(resolved.configuredRoot)
    ) {
      return this.approvalManager.createAuthorizationRequest(
        resolved.workspaceRoot,
        resolved.configuredRoot,
      );
    }
    return undefined;
  }

  public async run(workspaceRoot: string, command: string): Promise<UnrestrictedRunResult> {
    const resolved = await this.resolveWorkspace(workspaceRoot);
    if (
      this.config.unrestrictedRunnerRequireSessionApproval &&
      !this.approvalManager.isApproved(resolved.configuredRoot)
    ) {
      throw new Error("Unrestricted runner approval is required for this workspace root.");
    }

    const { shell, shellArgs } = shellCommand(command);
    const result = await this.processRunner.run(shell, shellArgs, {
      cwd: resolved.workspaceRoot,
      env: createUnrestrictedChildEnvironment(),
      timeoutMs: this.config.unrestrictedRunnerCommandTimeoutMs,
      maxOutputBytes: DEFAULT_OUTPUT_LIMIT_BYTES,
    });

    return {
      ...result,
      workspaceRoot: resolved.workspaceRoot,
      configuredRoot: resolved.configuredRoot,
      cwd: resolved.workspaceRoot,
      command,
      shell,
      shellArgs,
      sensitiveOutput: true,
    };
  }

  private async resolveWorkspace(workspaceRoot: string): Promise<ResolvedWorkspace> {
    if (!this.config.enableUnrestrictedRunner) {
      throw new Error(
        "The unrestricted runner is disabled. Restart the server with --enable-unrestricted-runner=true to allow this tool.",
      );
    }

    const resolvedWorkspaceRoot = await realpath(workspaceRoot);
    const configuredRoot = this.configuredRoots.find((root) =>
      isPathInside(root, resolvedWorkspaceRoot),
    );
    if (!configuredRoot) {
      throw new Error(
        `Workspace ${resolvedWorkspaceRoot} is outside the configured unrestricted runner roots.`,
      );
    }

    return {
      workspaceRoot: resolvedWorkspaceRoot,
      configuredRoot,
    };
  }
}

export async function startUnrestrictedApprovalServer(
  config: ServerConfig,
  approvalManager: UnrestrictedApprovalManager,
  auditLogger: AuditLogger,
): Promise<UnrestrictedApprovalServerHandle | undefined> {
  if (
    (!config.enableUnrestrictedRunner && !config.enableUnrestrictedScriptRunner) ||
    !config.unrestrictedRunnerRequireSessionApproval
  ) {
    return undefined;
  }

  const httpServer = createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (url.pathname === "/healthz") {
        sendText(response, 200, "ok\n", "text/plain; charset=utf-8");
        return;
      }

      if (url.pathname !== "/approve") {
        sendText(response, 404, "Not found\n", "text/plain; charset=utf-8");
        return;
      }

      if (request.method === "GET") {
        const token = url.searchParams.get("token") ?? "";
        const pending = approvalManager.getPendingApproval(token);
        if (!pending) {
          sendApprovalPage(response, 404, "Approval Expired", expiredBody());
          return;
        }
        sendApprovalPage(response, 200, "Approve Unrestricted Runner", approvalForm(pending));
        return;
      }

      if (request.method !== "POST") {
        response.writeHead(405, {
          allow: "GET, POST",
          "content-type": "text/plain; charset=utf-8",
        });
        response.end("Method not allowed\n");
        return;
      }

      const form = await readFormBody(request);
      const token = form.get("token") ?? "";
      const pending = approvalManager.getPendingApproval(token);
      const result = approvalManager.approveToken(
        token,
        form.get("acceptedRisk") === "on",
        form.get("acknowledgement") ?? undefined,
        form.get("rememberFor24h") === "on",
      );
      auditLogger.record({
        action: "op_unrestricted_runner_approve",
        outcome: "success",
        metadata: {
          configuredRoot: result.configuredRoot,
          workspaceRoot: pending?.workspaceRoot,
          expiresAt: result.expiresAt,
          remembered: result.remembered,
        },
      });
      sendApprovalPage(response, 200, "Unrestricted Runner Approved", successBody(result));
    } catch (error) {
      auditLogger.record({
        action: "op_unrestricted_runner_approve",
        outcome: "error",
        metadata: {},
        errorMessage: String(error),
      });
      const statusCode = error instanceof ApprovalRequestError ? error.statusCode : 400;
      sendApprovalPage(
        response,
        statusCode,
        "Approval Failed",
        failureBody(error instanceof Error ? error.message : String(error)),
      );
    }
  });

  await listen(httpServer, config.unrestrictedRunnerApprovalHost, config.unrestrictedRunnerApprovalPort);
  const address = httpServer.address();
  const port =
    typeof address === "object" && address
      ? address.port
      : config.unrestrictedRunnerApprovalPort;
  const url = `http://${hostForUrl(config.unrestrictedRunnerApprovalHost)}:${port}`;
  approvalManager.setApprovalBaseUrl(url);

  return {
    server: httpServer,
    url,
    close: () => closeServer(httpServer),
  };
}

function shellCommand(command: string): { shell: string; shellArgs: string[] } {
  if (process.platform === "win32") {
    return {
      shell: process.env.ComSpec ?? "cmd.exe",
      shellArgs: ["/d", "/s", "/c", command],
    };
  }

  return {
    shell: "/bin/sh",
    shellArgs: ["-c", command],
  };
}

function createUnrestrictedChildEnvironment(): NodeJS.ProcessEnv {
  const childEnv: NodeJS.ProcessEnv = {};
  for (const key of ["PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TEMP", "TMP"]) {
    if (process.env[key]) {
      childEnv[key] = process.env[key];
    }
  }
  for (const [key, value] of Object.entries(process.env)) {
    if ((key === "LANG" || key.startsWith("LC_")) && value) {
      childEnv[key] = value;
    }
  }
  return childEnv;
}

function isPathInside(parentPath: string, childPath: string): boolean {
  const pathRelative = relative(parentPath, childPath);
  return (
    pathRelative === "" ||
    (!pathRelative.startsWith(`..${sep}`) &&
      pathRelative !== ".." &&
      !isAbsolute(pathRelative))
  );
}

function listen(server: Server, host: string, port: number): Promise<void> {
  return new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolveListen();
    });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolveClose, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolveClose();
    });
  });
}

async function readFormBody(request: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  let bytesRead = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytesRead += buffer.length;
    if (bytesRead > APPROVAL_FORM_MAX_BYTES) {
      throw new ApprovalRequestError(413, "Approval form body is too large.");
    }
    chunks.push(buffer);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

function sendText(
  response: ServerResponse,
  statusCode: number,
  body: string,
  contentType: string,
): void {
  response.writeHead(statusCode, {
    "content-type": contentType,
    "cache-control": "no-store",
  });
  response.end(body);
}

function sendApprovalPage(
  response: ServerResponse,
  statusCode: number,
  title: string,
  body: string,
): void {
  response.writeHead(statusCode, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
    "x-content-type-options": "nosniff",
  });
  response.end(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    body { color: #151515; font: 16px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; padding: 32px; background: #fafafa; }
    main { max-width: 760px; margin: 0 auto; }
    h1 { font-size: 24px; line-height: 1.2; margin: 0 0 20px; }
    p { margin: 0 0 16px; }
    code { background: #f0f0f0; border: 1px solid #ddd; border-radius: 4px; padding: 2px 4px; word-break: break-all; }
    .warning { border-left: 4px solid #b42318; background: #fff5f5; padding: 14px 16px; margin: 0 0 20px; }
    label { display: block; margin: 16px 0; }
    input[type="text"] { box-sizing: border-box; display: block; width: 100%; margin-top: 6px; padding: 10px; border: 1px solid #bbb; border-radius: 4px; font: inherit; }
    button { background: #151515; border: 0; border-radius: 4px; color: white; cursor: pointer; font: inherit; padding: 10px 14px; }
  </style>
</head>
<body>
  <main>${body}</main>
</body>
</html>`);
}

function approvalForm(pending: PendingApproval): string {
  const sessionWide = pending.configuredRoot === "unrestricted-script-runner-session";
  const scopeLabel = sessionWide
    ? "Session approval scope"
    : "Configured root";
  const scopeValue = sessionWide
    ? "All op_script_run commands for this MCP process"
    : pending.configuredRoot;
  return `
    <h1>Approve Unrestricted Command Execution</h1>
    <div class="warning">
      <p>This grants the current MCP process permission to run arbitrary local shell commands for the scope below.</p>
      <p>The scope is an approval boundary, not an operating-system sandbox. A command can still read, write, or execute outside the requested workspace if your OS permissions allow it.</p>
    </div>
    <p><strong>${scopeLabel}:</strong><br><code>${escapeHtml(scopeValue)}</code></p>
    <p><strong>Requested workspace:</strong><br><code>${escapeHtml(pending.workspaceRoot)}</code></p>
    <form method="post" action="/approve">
      <input type="hidden" name="token" value="${escapeHtml(pending.token)}">
      <label>
        <input type="checkbox" name="acceptedRisk">
        I understand and accept the local command execution risk for this MCP process.
      </label>
      <label>
        <input type="checkbox" name="rememberFor24h">
        Remember this approval for 24 hours on this machine.
      </label>
      <label>
        Type the exact acknowledgement phrase:
        <input type="text" name="acknowledgement" autocomplete="off" spellcheck="false" value="">
      </label>
      <p><code>${UNRESTRICTED_RUNNER_ACK}</code></p>
      <button type="submit">Approve</button>
    </form>
  `;
}

function expiredBody(): string {
  return `
    <h1>Approval Link Expired</h1>
    <p>Ask the MCP client to call <code>op_script_run</code> or <code>op_unrestricted_run</code> again to generate a fresh local approval link.</p>
  `;
}

function successBody(result: UnrestrictedApprovalResult): string {
  return `
    <h1>Approved</h1>
    <p>Unrestricted command execution is now approved for:</p>
    <p><code>${escapeHtml(result.configuredRoot)}</code></p>
    <p>This in-memory approval expires at <code>${escapeHtml(result.expiresAt)}</code>.</p>
    ${
      result.remembered
        ? "<p>This approval was remembered locally for future MCP sessions until that expiration time.</p>"
        : ""
    }
  `;
}

function failureBody(message: string): string {
  return `
    <h1>Approval Failed</h1>
    <p>${escapeHtml(message)}</p>
  `;
}

function hostForUrl(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
