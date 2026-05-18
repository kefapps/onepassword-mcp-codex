import { createHash } from "node:crypto";
import type { AuditLogger } from "./audit.js";
import type { ServerConfig } from "./config.js";

type AuditOutcome = "success" | "error";

export interface RuntimeDiagnostics {
  backend?: string;
  sdkClientCreated?: boolean;
  lastSdkAuthAttemptAt?: string;
  lastSdkAuthOutcome?: AuditOutcome;
  lastSdkOperation?: string;
  connectClientCreated?: boolean;
  lastConnectAuthAttemptAt?: string;
  lastConnectAuthOutcome?: AuditOutcome;
  lastConnectOperation?: string;
}

function sha256Hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeErrorMessage(error: unknown): string | undefined {
  if (!(error instanceof Error)) {
    return undefined;
  }
  return sanitizeDiagnosticString(error.message);
}

function sanitizeDiagnosticString(value: string): string {
  if (/op:\/\//i.test(value) || value.length > 200) {
    return `[sha256:${sha256Hash(value)}]`;
  }
  return value;
}

function sanitizeDiagnosticValue(value: unknown): unknown {
  if (typeof value === "string") {
    return sanitizeDiagnosticString(value);
  }
  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeDiagnosticValue(entry));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key,
        sanitizeDiagnosticValue(entry),
      ]),
    );
  }
  return value;
}

export function recordDiagnosticAudit(
  config: ServerConfig,
  auditLogger: AuditLogger,
  action: string,
  outcome: AuditOutcome,
  metadata: Record<string, unknown>,
  error?: unknown,
): void {
  if (!config.enableDiagnostics) {
    return;
  }

  auditLogger.record({
    action,
    outcome,
    metadata: sanitizeDiagnosticValue(metadata) as Record<string, unknown>,
    errorMessage: safeErrorMessage(error),
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function stringParam(value: unknown): string | undefined {
  return typeof value === "string" ? sanitizeDiagnosticString(value) : undefined;
}

function hashParam(value: unknown): string | undefined {
  return typeof value === "string" ? sha256Hash(value) : undefined;
}

export function mcpRequestMetadata(request: unknown): Record<string, unknown> {
  if (!isRecord(request)) {
    return { method: "unknown" };
  }

  const method = stringParam(request.method) ?? "unknown";
  const params = isRecord(request.params) ? request.params : {};
  const metadata: Record<string, unknown> = { method };

  if (method === "tools/call") {
    metadata.toolName = stringParam(params.name);
  }
  if (method === "prompts/get") {
    metadata.promptName = stringParam(params.name);
  }
  if (method === "resources/read") {
    metadata.resourceUriHash = hashParam(params.uri);
  }
  if (method === "completion/complete" && isRecord(params.ref)) {
    metadata.refType = stringParam(params.ref.type);
    metadata.refName = stringParam(params.ref.name);
    metadata.refUriHash = hashParam(params.ref.uri);
  }
  if (method === "completion/complete" && isRecord(params.argument)) {
    metadata.argumentName = stringParam(params.argument.name);
  }

  return metadata;
}

export function processMetadata(config: ServerConfig): Record<string, unknown> {
  return {
    pid: process.pid,
    ppid: process.ppid,
    transport: config.transport,
    authMode: config.authMode,
    opCliAuthMode: config.opCliAuthMode,
    secretRevealEnabled: config.enableSecretReveal,
    writesEnabled: config.enableWrites,
    destructiveActionsEnabled: config.enableDestructiveActions,
    permissionMutationEnabled: config.enablePermissionMutation,
    scriptRunnerEnabled: config.enableScriptRunner,
    unrestrictedScriptRunnerEnabled: config.enableUnrestrictedScriptRunner,
    unrestrictedRunnerEnabled: config.enableUnrestrictedRunner,
  };
}
