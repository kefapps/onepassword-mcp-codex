import {
  type EnvironmentVariable,
  type Group,
  type GroupAccess,
  type GroupVaultAccess,
  type Item,
  type ItemCreateParams,
  type ItemField,
  type ItemListFilter,
  type ItemSection,
  type Website,
  AutofillBehavior,
  ItemCategory,
  ItemFieldType,
} from "@1password/sdk";
import { createHash } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AuditLogger } from "./audit.js";
import {
  SDK_CAPABILITIES,
  backendCapabilities,
  effectiveSupportedTools,
} from "./capabilities.js";
import type { ServerConfig } from "./config.js";
import {
  mcpRequestMetadata,
  recordDiagnosticAudit,
  type RuntimeDiagnostics,
} from "./diagnostics.js";
import { errorMessage, normalizeError } from "./errors.js";
import {
  DESTRUCTIVE_ACTION_ACK,
  GENERATED_SECRET_ACK,
  PERMISSION_MUTATION_ACK,
  SECRET_REVEAL_ACK,
  UNRESTRICTED_RUNNER_ACK,
} from "./constants.js";
import { registerOnePasswordPrompts } from "./mcp-prompts.js";
import { registerOnePasswordResources } from "./mcp-resources.js";
import {
  DefaultOpScriptRunner,
  type AllowlistedCommand,
  type OpScriptCommandRunResult,
  type OpScriptRunner,
} from "./op-runner.js";
import {
  type PasswordMode,
  findPasswordField,
  generateMemorablePassword,
  generateRandomPassword,
  upsertPasswordField,
} from "./passwords.js";
import {
  PERMISSION_NAMES,
  type PermissionName,
  decodePermissions,
  encodePermissions,
} from "./permissions.js";
import { redactItem, redactItemOverview, redactVault } from "./redaction.js";
import type { OnePasswordService } from "./service.js";
import {
  DefaultUnrestrictedRunner,
  UnrestrictedApprovalManager,
  createUnrestrictedApprovalManager,
  type UnrestrictedRunner,
  type UnrestrictedRunnerStatus,
} from "./unrestricted-runner.js";

const websiteSchema = z.object({
  url: z.string().min(1),
  label: z.string().min(1),
  autofillBehavior: z.nativeEnum(AutofillBehavior),
});

const sectionSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(1),
});

const fieldSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(1),
  sectionId: z.string().min(1).optional(),
  fieldType: z.nativeEnum(ItemFieldType),
  value: z.string(),
});

const permissionNameSchema = z.enum(PERMISSION_NAMES as [PermissionName, ...PermissionName[]]);
const passwordModeSchema = z.enum(["provided", "random", "memorable"]);
const envVariableNamePattern = /^[A-Za-z_][A-Za-z0-9_]*$/;
const reservedScriptEnvKeys = new Set([
  "PATH",
  "HOME",
  "OP_ACCOUNT",
  "OP_SESSION",
  "OP_SERVICE_ACCOUNT_TOKEN",
]);
const SCRIPT_RUNNER_SECRET_HINT =
  "When a secret is needed only by a command or local script, prefer op_script_run with envSecretRefs so the secret is injected into the child process and never returned in plaintext.";
const UNRESTRICTED_SCRIPT_RUNNER_SCOPE = "unrestricted-script-runner-session";

const envSecretRefsSchema = z.record(z.string().min(1), z.string().min(1));
const passwordReadInputShape = {
  secretReference: z.string().min(1).optional(),
  vaultId: z.string().min(1).optional(),
  itemId: z.string().min(1).optional(),
  field: z.string().min(1).optional(),
  reveal: z.boolean().optional(),
  reason: z.string().optional(),
  acknowledgePlaintext: z.string().optional(),
} satisfies z.ZodRawShape;
const passwordReadInputSchema = z
  .object(passwordReadInputShape)
  .superRefine((value, context) => {
    const byReference = value.secretReference !== undefined;
    const byItem = value.vaultId !== undefined && value.itemId !== undefined;

    if (!byReference && !byItem) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Provide secretReference or both vaultId and itemId.",
      });
    }

    if (byReference && (value.vaultId !== undefined || value.itemId !== undefined)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Choose either secretReference mode or vaultId+itemId mode.",
      });
    }

    if (value.reveal) {
      if (!value.reason || value.reason.length < 3) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: "reveal=true requires a reason of at least 3 characters.",
        });
      }
      if (value.acknowledgePlaintext !== SECRET_REVEAL_ACK) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: "reveal=true requires the exact plaintext acknowledgement string.",
        });
      }
    }
  });
const secretRevealInputShape = {
  reason: z.string().min(3),
  acknowledgePlaintext: z.literal(SECRET_REVEAL_ACK),
  reference: z.string().min(1).optional(),
  vaultId: z.string().min(1).optional(),
  itemId: z.string().min(1).optional(),
  fieldId: z.string().min(1).optional(),
} satisfies z.ZodRawShape;
const secretRevealInputSchema = z
  .object(secretRevealInputShape)
  .superRefine((value, context) => {
    const byReference = value.reference !== undefined;
    const byField =
      value.vaultId !== undefined &&
      value.itemId !== undefined &&
      value.fieldId !== undefined;

    if (!byReference && !byField) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Provide either reference or vaultId+itemId+fieldId.",
      });
    }

    if (byReference && byField) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Choose either reference mode or field mode, not both.",
      });
    }
  });

function jsonResult(data: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(data, null, 2),
      },
    ],
    structuredContent: data as Record<string, unknown>,
  };
}

function textResult(text: string, structuredContent?: Record<string, unknown>) {
  return {
    content: [
      {
        type: "text" as const,
        text,
      },
    ],
    structuredContent,
  };
}

function toItemFields(fields?: z.infer<typeof fieldSchema>[]): ItemField[] | undefined {
  return fields?.map((field) => ({ ...field }));
}

function toItemSections(
  sections?: z.infer<typeof sectionSchema>[],
): ItemSection[] | undefined {
  return sections?.map((section) => ({ ...section }));
}

function toWebsites(websites?: z.infer<typeof websiteSchema>[]): Website[] | undefined {
  return websites?.map((website) => ({ ...website }));
}

function sanitizeGroup(group: Group) {
  return {
    ...group,
    vaultAccess: group.vaultAccess?.map((access) => ({
      ...access,
      permissionsMask: access.permissions,
      permissions: decodePermissions(access.permissions),
    })),
  };
}

function createItemFilters(includeArchived: boolean): ItemListFilter[] {
  return [
    {
      type: "ByState",
      content: {
        active: true,
        archived: includeArchived,
      },
    },
  ];
}

function findEnvironmentVariable(
  variables: EnvironmentVariable[],
  name: string,
): EnvironmentVariable {
  const wanted = name.trim().toLowerCase();
  const match = variables.find((variable) => variable.name.toLowerCase() === wanted);
  if (!match) {
    throw new Error(`Environment variable ${name} not found.`);
  }
  return match;
}

function redactEnvironmentVariable(variable: EnvironmentVariable) {
  return {
    name: variable.name,
    masked: variable.masked,
    valueState: "redacted" as const,
  };
}

function filterEnvironmentVariables(
  variables: EnvironmentVariable[],
  query?: string,
): EnvironmentVariable[] {
  if (!query) {
    return variables;
  }

  const normalizedQuery = query.trim().toLowerCase();
  return variables.filter((variable) =>
    variable.name.toLowerCase().includes(normalizedQuery),
  );
}

function matchesQuery(item: object, query?: string) {
  if (!query) {
    return true;
  }

  return JSON.stringify(item).toLowerCase().includes(query.toLowerCase());
}

function assertSecretRevealEnabled(config: ServerConfig): void {
  if (!config.enableSecretReveal) {
    throw new Error(
      `Plaintext secret reveal is disabled. ${SCRIPT_RUNNER_SECRET_HINT} ` +
        "If plaintext is truly required, restart the server with OP_MCP_ENABLE_SECRET_REVEAL=true or --enable-secret-reveal=true.",
    );
  }
}

function assertScriptRunnerEnabled(config: ServerConfig): void {
  if (!config.enableScriptRunner) {
    throw new Error(
      "The 1Password script runner is disabled. Restart the server with --enable-script-runner=true to allow this tool.",
    );
  }
}

function assertUnrestrictedRunnerEnabled(config: ServerConfig): void {
  if (!config.enableUnrestrictedRunner) {
    throw new Error(
      "The unrestricted runner is disabled. Restart the server with --enable-unrestricted-runner=true to allow this tool.",
    );
  }
}

function assertWritesEnabled(config: ServerConfig): void {
  if (!config.enableWrites) {
    throw new Error(
      "1Password write tools are disabled. Restart the server with --enable-writes=true to allow this tool.",
    );
  }
}

function assertDestructiveActionsEnabled(config: ServerConfig): void {
  if (!config.enableDestructiveActions) {
    throw new Error(
      "1Password destructive tools are disabled. Restart the server with --enable-destructive-actions=true to allow this tool.",
    );
  }
}

function assertPermissionMutationEnabled(config: ServerConfig): void {
  if (!config.enablePermissionMutation) {
    throw new Error(
      "1Password permission mutation tools are disabled. Restart the server with --enable-permission-mutation=true to allow this tool.",
    );
  }
}

function secretConsumptionGuidance(config: ServerConfig): Record<string, unknown> {
  const unrestrictedScriptRunner = config.enableUnrestrictedScriptRunner;
  return {
    preferredPath: "op_script_run",
    reason: unrestrictedScriptRunner
      ? "Use this path when the user needs a secret consumed by a local command, not displayed to the model. This server accepts free-form commands after local session approval."
      : "Use this path when the user needs a secret consumed by an allowlisted command, not displayed to the model.",
    plaintextRevealEnabled: config.enableSecretReveal,
    scriptRunnerEnabled: config.enableScriptRunner,
    unrestrictedScriptRunnerEnabled: unrestrictedScriptRunner,
    nextStep: config.enableScriptRunner
      ? unrestrictedScriptRunner
        ? "Call op_script_run with workspaceRoot, command, reason, and envSecretRefs mapping env var names to op:// references. If authorizationRequired is returned, open approvalUrl locally once for this MCP process and retry."
        : "Call op_script_list for the workspaceRoot, then op_script_run with commandId and envSecretRefs mapping env var names to op:// references."
      : "Restart the server with --enable-script-runner=true plus startup --script-runner-root and --script-runner-allowlist or --script-runner-allowlist-manifest entries to enable secret injection into scripts.",
  };
}

function sessionUnrestrictedRunnerStatus(
  config: ServerConfig,
  approvalManager: UnrestrictedApprovalManager,
  legacyStatus: UnrestrictedRunnerStatus,
): UnrestrictedRunnerStatus & Record<string, unknown> {
  if (!config.enableUnrestrictedScriptRunner) {
    return {
      mode: "op_unrestricted_run",
      ...legacyStatus,
    };
  }

  return {
    ...legacyStatus,
    mode: "op_script_run",
    enabled: true,
    configuredRoot: UNRESTRICTED_SCRIPT_RUNNER_SCOPE,
    configuredRootCount: 1,
    requireSessionApproval: config.unrestrictedRunnerRequireSessionApproval,
    approvalServerAvailable: approvalManager.approvalServerAvailable,
    approvedRootCount: approvalManager.approvedRootCount,
    approvalTtlMs: config.unrestrictedRunnerApprovalTtlMs,
    commandTimeoutMs: config.unrestrictedRunnerCommandTimeoutMs,
    rememberTtlMs: config.approvalRememberTtlMs,
  };
}

function scriptRunnerSecretInstruction(config: ServerConfig): string {
  return config.enableScriptRunner
    ? config.enableUnrestrictedScriptRunner
      ? "Call op_script_run with workspaceRoot, command, reason, and envSecretRefs mapping environment variable names to op:// references; if authorizationRequired is returned, open approvalUrl locally once for this MCP process and retry."
      : "Call op_script_list for the workspaceRoot, then op_script_run with commandId and envSecretRefs mapping environment variable names to op:// references."
    : "op_script_run is not available because the script runner is also disabled here; restart the server with --enable-script-runner=true plus startup --script-runner-root and --script-runner-allowlist or --script-runner-allowlist-manifest entries to allow no-plaintext secret consumption by scripts.";
}

function plaintextRevealDescription(
  config: ServerConfig,
  enabledDescription: string,
): string {
  if (config.enableSecretReveal) {
    return `${enabledDescription} ${SCRIPT_RUNNER_SECRET_HINT}`;
  }

  return (
    "Plaintext reveal is disabled in this server; this tool will fail until the server is restarted with OP_MCP_ENABLE_SECRET_REVEAL=true or --enable-secret-reveal=true. " +
    `If the secret only needs to be consumed by a command or local script, do not call this tool. ${scriptRunnerSecretInstruction(config)}`
  );
}

function passwordReadDescription(config: ServerConfig): string {
  const base = "Read one password field or secret reference. Returns redacted metadata by default.";
  if (config.enableSecretReveal) {
    return `${base} Plaintext reveal is enabled with reveal=true plus reason and acknowledgement. ${SCRIPT_RUNNER_SECRET_HINT}`;
  }

  return (
    `${base} Plaintext reveal is disabled in this server; reveal=true will fail. ` +
    `If the secret only needs to be consumed by a command or local script, do not request reveal. ${scriptRunnerSecretInstruction(config)}`
  );
}

type ScriptOutputState = "returned" | "withheld" | "skipped_ack_missing";

interface ScriptOutputPolicy {
  requested: boolean;
  returned: boolean;
  state: ScriptOutputState;
  requiredAcknowledgement?: string;
}

function resolveScriptOutputPolicy(
  returnOutput: boolean | undefined,
  requiresAcknowledgement: boolean,
  acknowledgePlaintext?: string,
): ScriptOutputPolicy {
  const requested = returnOutput ?? false;
  if (!requested) {
    return {
      requested,
      returned: false,
      state: "withheld",
    };
  }

  if (
    requiresAcknowledgement &&
    acknowledgePlaintext !== SECRET_REVEAL_ACK
  ) {
    return {
      requested,
      returned: false,
      state: "skipped_ack_missing",
      requiredAcknowledgement: SECRET_REVEAL_ACK,
    };
  }

  return {
    requested,
    returned: true,
    state: "returned",
  };
}

function shouldSkipForMissingOutputAcknowledgement(outputPolicy: ScriptOutputPolicy): boolean {
  return outputPolicy.state === "skipped_ack_missing";
}

function outputAcknowledgementRequiredText(): string {
  return (
    "Command was not executed because returnOutput=true with secret injection or sensitive output " +
    `requires acknowledgePlaintext=${SECRET_REVEAL_ACK}. Retry with that acknowledgement to execute the command and return stdout/stderr.`
  );
}

function outputAcknowledgementRequiredContent(
  outputPolicy: ScriptOutputPolicy,
  extra: Record<string, unknown>,
): Record<string, unknown> {
  return {
    ...extra,
    executionSkipped: true,
    outputRequested: outputPolicy.requested,
    outputReturned: false,
    outputState: outputPolicy.state,
    ...(outputPolicy.requiredAcknowledgement
      ? { requiredAcknowledgement: outputPolicy.requiredAcknowledgement }
      : {}),
  };
}

function validateEnvSecretRefs(
  envSecretRefs: Record<string, string> | undefined,
): Record<string, string> {
  const validated: Record<string, string> = {};

  for (const [envVar, reference] of Object.entries(envSecretRefs ?? {})) {
    if (!envVariableNamePattern.test(envVar)) {
      throw new Error(`Invalid environment variable name for secret injection: ${envVar}.`);
    }
    if (reservedScriptEnvKeys.has(envVar)) {
      throw new Error(`Environment variable ${envVar} is reserved and cannot be injected.`);
    }

    const trimmedReference = reference.trim();
    if (!trimmedReference.startsWith("op://")) {
      throw new Error(
        `Secret reference for ${envVar} must be an op:// reference.`,
      );
    }
    validated[envVar] = trimmedReference;
  }

  return validated;
}

function secretReferenceScheme(reference: string): string {
  const schemeEnd = reference.indexOf("://");
  return schemeEnd > 0 ? reference.slice(0, schemeEnd) : "unknown";
}

function secretReferenceHash(reference: string): string {
  return sha256Hash(reference);
}

function sha256Hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function summarizeEnvSecretRefs(envSecretRefs: Record<string, string>) {
  return Object.entries(envSecretRefs)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([envVar, reference]) => ({
      envVar,
      referenceScheme: secretReferenceScheme(reference),
      referenceHash: secretReferenceHash(reference),
    }));
}

async function resolveEnvSecretRefs(
  service: OnePasswordService,
  envSecretRefs: Record<string, string>,
): Promise<{
  extraEnv: Record<string, string>;
  secretRedactionValues: string[];
}> {
  const resolved = await Promise.all(
    Object.entries(envSecretRefs).map(async ([envVar, reference]) => {
      const value = await service.secretResolve(reference);
      return [envVar, value] as const;
    }),
  );

  return {
    extraEnv: Object.fromEntries(resolved),
    secretRedactionValues: resolved.map(([, value]) => value),
  };
}

async function getAllowlistedCommand(
  scriptRunner: OpScriptRunner,
  workspaceRoot: string,
  commandId: string,
): Promise<AllowlistedCommand> {
  const allowlist = await scriptRunner.list(workspaceRoot);
  const command = allowlist.commands.find((candidate) => candidate.id === commandId);
  if (!command) {
    throw new Error(`Allowlisted command ${commandId} not found.`);
  }
  return command;
}

function sanitizeAuditString(value: string): string {
  return value
    .replace(/op:\/\/[^\s"']+/g, "[REDACTED_REFERENCE]")
    .replace(/OP_SESSION(?:_[A-Z0-9_]+)?=[^\s"']+/gi, "OP_SESSION=[REDACTED]")
    .replace(/OP_SERVICE_ACCOUNT_TOKEN=[^\s"']+/gi, "OP_SERVICE_ACCOUNT_TOKEN=[REDACTED]");
}

function sanitizeAuditValue(value: unknown): unknown {
  if (typeof value === "string") {
    return sanitizeAuditString(value);
  }
  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeAuditValue(entry));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, sanitizeAuditValue(entry)]),
    );
  }
  return value;
}

function recordAudit(
  auditLogger: AuditLogger,
  action: string,
  outcome: "success" | "error",
  metadata: Record<string, unknown>,
  error?: unknown,
): void {
  auditLogger.record({
    action,
    outcome,
    metadata: sanitizeAuditValue(metadata) as Record<string, unknown>,
    errorMessage: error === undefined ? undefined : sanitizeAuditString(errorMessage(error)),
  });
}

function instrumentMcpRequests(
  server: McpServer,
  config: ServerConfig,
  auditLogger: AuditLogger,
): void {
  if (!config.enableDiagnostics) {
    return;
  }

  const originalSetRequestHandler = server.server.setRequestHandler.bind(
    server.server,
  );
  type SetRequestHandler = typeof server.server.setRequestHandler;
  server.server.setRequestHandler = ((
    requestSchema: Parameters<SetRequestHandler>[0],
    handler: Parameters<SetRequestHandler>[1],
  ) =>
    originalSetRequestHandler(requestSchema, async (request, extra) => {
      const metadata = mcpRequestMetadata(request);
      const startedAt = Date.now();
      recordDiagnosticAudit(config, auditLogger, "mcp_request_start", "success", {
        ...metadata,
        ppid: process.ppid,
      });

      try {
        const result = await handler(request, extra);
        recordDiagnosticAudit(config, auditLogger, "mcp_request", "success", {
          ...metadata,
          ppid: process.ppid,
          durationMs: Date.now() - startedAt,
        });
        return result;
      } catch (error) {
        recordDiagnosticAudit(config, auditLogger, "mcp_request", "error", {
          ...metadata,
          ppid: process.ppid,
          durationMs: Date.now() - startedAt,
        }, error);
        throw normalizeError(error);
      }
    })) as SetRequestHandler;
}

function serviceRuntimeDiagnostics(
  service: OnePasswordService,
): RuntimeDiagnostics | undefined {
  if (
    "runtimeDiagnostics" in service &&
    typeof service.runtimeDiagnostics === "function"
  ) {
    return service.runtimeDiagnostics();
  }
  return undefined;
}

function resolvePasswordMode(mode: PasswordMode | undefined, password?: string): PasswordMode {
  return mode ?? (password ? "provided" : "random");
}

function resolvePasswordValue(input: {
  mode?: PasswordMode;
  password?: string;
  randomLength?: number;
  includeLowercase?: boolean;
  includeUppercase?: boolean;
  includeDigits?: boolean;
  includeSymbols?: boolean;
  excludeSimilar?: boolean;
  symbols?: string;
  memorableWords?: number;
  memorableSeparator?: string;
  memorableCapitalize?: boolean;
  memorableIncludeNumber?: boolean;
}) {
  const mode = resolvePasswordMode(input.mode, input.password);

  if (mode === "provided") {
    if (!input.password) {
      throw new Error("mode=provided requires a password value.");
    }
    return {
      mode,
      value: input.password,
      generated: false,
    };
  }

  if (input.password) {
    throw new Error("password must be omitted unless mode=provided.");
  }

  if (mode === "random") {
    return {
      mode,
      value: generateRandomPassword({
        length: input.randomLength,
        includeLowercase: input.includeLowercase,
        includeUppercase: input.includeUppercase,
        includeDigits: input.includeDigits,
        includeSymbols: input.includeSymbols,
        excludeSimilar: input.excludeSimilar,
        symbols: input.symbols,
      }),
      generated: true,
    };
  }

  return {
    mode,
    value: generateMemorablePassword({
      words: input.memorableWords,
      separator: input.memorableSeparator,
      capitalize: input.memorableCapitalize,
      includeNumber: input.memorableIncludeNumber,
    }),
    generated: true,
  };
}

function commandOutputText(result: {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
  outputTruncated: boolean;
  sensitiveOutput: boolean;
  errorMessage?: string;
}, outputPolicy: ScriptOutputPolicy): string {
  const sections: string[] = [];

  if (outputPolicy.returned && result.stdout) {
    sections.push(result.stdout.trimEnd());
  }
  if (outputPolicy.returned && result.stderr) {
    sections.push(result.stderr.trimEnd());
  }
  if (
    result.errorMessage &&
    (outputPolicy.returned ||
      (!result.sensitiveOutput && outputPolicy.state !== "skipped_ack_missing"))
  ) {
    sections.push(result.errorMessage);
  }
  if (sections.length === 0) {
    sections.push(`Command completed with exit code ${result.exitCode ?? "unknown"}.`);
  }
  if (!outputPolicy.returned) {
    sections.push(
      outputPolicy.state === "skipped_ack_missing"
        ? outputAcknowledgementRequiredText()
        : "Command stdout/stderr withheld by default.",
    );
  }
  if (result.timedOut) {
    sections.push("Command timed out.");
  }
  if (result.outputTruncated) {
    sections.push("Command output was truncated.");
  }

  return sections.join("\n");
}

function scriptRunStructuredContent(
  result: {
    commandId: string;
    workspaceRoot: string;
    cwd: string;
    authMode: string;
    exitCode: number | null;
    signal: NodeJS.Signals | null;
    timedOut: boolean;
    outputTruncated: boolean;
    durationMs: number;
    refreshedAuth: boolean;
    sensitiveOutput: boolean;
    stdout: string;
    stderr: string;
    errorMessage?: string;
  },
  outputPolicy: ScriptOutputPolicy,
): Record<string, unknown> {
  const includeWithheldErrorMessage =
    result.errorMessage &&
    !result.sensitiveOutput &&
    outputPolicy.state !== "skipped_ack_missing";

  return {
    commandId: result.commandId,
    workspaceRoot: result.workspaceRoot,
    cwd: result.cwd,
    authMode: result.authMode,
    exitCode: result.exitCode,
    signal: result.signal,
    timedOut: result.timedOut,
    outputTruncated: result.outputTruncated,
    durationMs: result.durationMs,
    refreshedAuth: result.refreshedAuth,
    sensitiveOutput: result.sensitiveOutput,
    outputRequested: outputPolicy.requested,
    outputReturned: outputPolicy.returned,
    ...(outputPolicy.returned
      ? {
          stdout: result.stdout,
          stderr: result.stderr,
          errorMessage: result.errorMessage,
        }
      : {
          outputState: outputPolicy.state,
          ...(outputPolicy.requiredAcknowledgement
            ? { requiredAcknowledgement: outputPolicy.requiredAcknowledgement }
            : {}),
          ...(includeWithheldErrorMessage
            ? { errorMessage: result.errorMessage }
            : {}),
        }),
  };
}

function unrestrictedScriptRunStructuredContent(
  result: OpScriptCommandRunResult,
  outputPolicy: ScriptOutputPolicy,
): Record<string, unknown> {
  return {
    mode: "unrestricted",
    workspaceRoot: result.workspaceRoot,
    cwd: result.cwd,
    authMode: result.authMode,
    commandHash: sha256Hash(result.command),
    commandLength: result.command.length,
    shell: result.shell,
    exitCode: result.exitCode,
    signal: result.signal,
    timedOut: result.timedOut,
    outputTruncated: result.outputTruncated,
    durationMs: result.durationMs,
    refreshedAuth: result.refreshedAuth,
    sensitiveOutput: result.sensitiveOutput,
    outputRequested: outputPolicy.requested,
    outputReturned: outputPolicy.returned,
    ...(outputPolicy.returned
      ? {
          stdout: result.stdout,
          stderr: result.stderr,
          errorMessage: result.errorMessage,
        }
      : {
          outputState: outputPolicy.state,
          ...(outputPolicy.requiredAcknowledgement
            ? { requiredAcknowledgement: outputPolicy.requiredAcknowledgement }
            : {}),
        }),
  };
}

function unrestrictedRunStructuredContent(
  result: {
    workspaceRoot: string;
    configuredRoot: string;
    cwd: string;
    command: string;
    shell: string;
    exitCode: number | null;
    signal: NodeJS.Signals | null;
    timedOut: boolean;
    outputTruncated: boolean;
    durationMs: number;
    sensitiveOutput: boolean;
    stdout: string;
    stderr: string;
    errorMessage?: string;
  },
  outputPolicy: ScriptOutputPolicy,
): Record<string, unknown> {
  return {
    workspaceRoot: result.workspaceRoot,
    configuredRoot: result.configuredRoot,
    cwd: result.cwd,
    commandHash: sha256Hash(result.command),
    commandLength: result.command.length,
    shell: result.shell,
    exitCode: result.exitCode,
    signal: result.signal,
    timedOut: result.timedOut,
    outputTruncated: result.outputTruncated,
    durationMs: result.durationMs,
    sensitiveOutput: result.sensitiveOutput,
    outputRequested: outputPolicy.requested,
    outputReturned: outputPolicy.returned,
    ...(outputPolicy.returned
      ? {
          stdout: result.stdout,
          stderr: result.stderr,
          errorMessage: result.errorMessage,
        }
      : {
          outputState: outputPolicy.state,
          ...(outputPolicy.requiredAcknowledgement
            ? { requiredAcknowledgement: outputPolicy.requiredAcknowledgement }
            : {}),
        }),
  };
}

export function createOnePasswordMcpServer(
  config: ServerConfig,
  service: OnePasswordService,
  auditLogger: AuditLogger,
  scriptRunner: OpScriptRunner = new DefaultOpScriptRunner(config),
  providedUnrestrictedRunner?: UnrestrictedRunner,
  providedApprovalManager?: UnrestrictedApprovalManager,
): McpServer {
  const approvalManager =
    providedApprovalManager ?? createUnrestrictedApprovalManager(config);
  const unrestrictedRunner =
    providedUnrestrictedRunner ??
    new DefaultUnrestrictedRunner(config, approvalManager);
  const capabilities = backendCapabilities(config);
  const supportedTools = effectiveSupportedTools(config);
  const server = new McpServer({
    name: "mcp-1password",
    version: config.integrationVersion,
  });
  instrumentMcpRequests(server, config, auditLogger);

  registerOnePasswordResources(server, config, service);
  registerOnePasswordPrompts(server);

  server.registerTool(
    "sdk_capabilities",
    {
      description:
        "Describe the capability surface exposed by this server, including the preferred no-plaintext path for consuming secrets in scripts.",
    },
    async () =>
      jsonResult({
        authMode: config.authMode,
        backend: config.authMode,
        secretRevealEnabled: config.enableSecretReveal,
        writesEnabled: config.enableWrites,
        destructiveActionsEnabled: config.enableDestructiveActions,
        permissionMutationEnabled: config.enablePermissionMutation,
        scriptRunnerEnabled: config.enableScriptRunner,
        unrestrictedScriptRunnerEnabled: config.enableUnrestrictedScriptRunner,
        scriptRunnerAllowlistManifestCount:
          config.scriptRunnerAllowlistManifestPaths.length,
        unrestrictedRunnerEnabled: config.enableUnrestrictedRunner,
        unrestrictedRunnerRootCount: config.unrestrictedRunnerRoots.length,
        unrestrictedRunnerRequireSessionApproval:
          config.unrestrictedRunnerRequireSessionApproval,
        unrestrictedRunnerApprovalTtlMs: config.unrestrictedRunnerApprovalTtlMs,
        unrestrictedRunnerCommandTimeoutMs:
          config.unrestrictedRunnerCommandTimeoutMs,
        approvalRememberTtlMs: config.approvalRememberTtlMs,
        transport: config.transport,
        httpPath: config.httpPath,
        httpRequireBearer: config.httpRequireBearer,
        httpAllowedOriginCount: config.httpAllowedOrigins.length,
        httpMaxSessions: config.httpMaxSessions,
        httpSessionIdleMs: config.httpSessionIdleMs,
        httpRequestTimeoutMs: config.httpRequestTimeoutMs,
        diagnosticsEnabled: config.enableDiagnostics,
        backendCapabilities: capabilities,
        effectiveSupportedTools: supportedTools,
        secretConsumptionGuidance: secretConsumptionGuidance(config),
        ...SDK_CAPABILITIES,
      }),
  );

  server.registerTool(
    "op_session_status",
    {
      description:
        "Show non-secret 1Password CLI session state and runtime capability gates held by this MCP process.",
    },
    async () => {
      const status = scriptRunner.status();
      const unrestrictedStatus = unrestrictedRunner.status();
      return jsonResult({
        backend: config.authMode,
        ...status,
        secretRevealEnabled: config.enableSecretReveal,
        writesEnabled: config.enableWrites,
        destructiveActionsEnabled: config.enableDestructiveActions,
        permissionMutationEnabled: config.enablePermissionMutation,
        scriptRunnerEnabled: config.enableScriptRunner,
        unrestrictedScriptRunnerEnabled: config.enableUnrestrictedScriptRunner,
        scriptRunnerAllowlistCount:
          status.loadedAllowlistCount ?? config.scriptRunnerAllowlistPaths.length,
        scriptRunnerConfiguredAllowlistPathCount:
          config.scriptRunnerAllowlistPaths.length,
        scriptRunnerAllowlistManifestCount:
          config.scriptRunnerAllowlistManifestPaths.length,
        approvalRememberTtlMs: config.approvalRememberTtlMs,
        unrestrictedRunner: sessionUnrestrictedRunnerStatus(
          config,
          approvalManager,
          unrestrictedStatus,
        ),
        diagnostics: {
          backend: config.authMode,
          enabled: config.enableDiagnostics,
          pid: process.pid,
          ppid: process.ppid,
          ...serviceRuntimeDiagnostics(service),
        },
        secretConsumptionGuidance: secretConsumptionGuidance(config),
      });
    },
  );

  if (config.enableScriptRunner) {
    server.registerTool(
      "op_script_list",
      {
        description:
          `List currently loaded startup-configured allowlisted scripts. ${SCRIPT_RUNNER_SECRET_HINT}`,
        inputSchema: {
          workspaceRoot: z.string().min(1),
        },
      },
      async ({ workspaceRoot }) => {
        assertScriptRunnerEnabled(config);
        if (config.enableUnrestrictedScriptRunner) {
          return jsonResult({
            unrestrictedScriptRunner: true,
            workspaceRoot,
            commands: [],
            message:
              "Unrestricted script runner is enabled; startup allowlists are ignored and op_script_run accepts a free-form command after one local approval per MCP process.",
          });
        }
        const allowlist = await scriptRunner.list(workspaceRoot);
        return jsonResult({
          path: allowlist.path,
          workspaceRoot: allowlist.workspaceRoot,
          commands: allowlist.commands,
        });
      },
    );

    server.registerTool(
      "op_script_reload_allowlists",
      {
        description:
          "Reload the startup-configured script allowlist files into this MCP process. " +
          "Only direct allowlist paths, manifest trust anchors, and trusted roots configured at server startup are used; invalid reloads fail without replacing the active allowlists.",
        inputSchema: {
          reason: z.string().min(3),
        },
      },
      async ({ reason }) => {
        assertScriptRunnerEnabled(config);
        if (config.enableUnrestrictedScriptRunner) {
          const result = {
            reloaded: false,
            ignored: true,
            unrestrictedScriptRunner: true,
            configuredAllowlistPathCount: config.scriptRunnerAllowlistPaths.length,
            configuredAllowlistManifestCount:
              config.scriptRunnerAllowlistManifestPaths.length,
            previousAllowlistCount: 0,
            allowlistCount: 0,
            commandCount: 0,
          };
          recordAudit(auditLogger, "op_script_reload_allowlists", "success", {
            reason,
            ...result,
          });
          return jsonResult(result);
        }

        try {
          const reload = scriptRunner.reload();
          const result = {
            reloaded: true,
            configuredAllowlistPathCount: config.scriptRunnerAllowlistPaths.length,
            configuredAllowlistManifestCount:
              config.scriptRunnerAllowlistManifestPaths.length,
            ...reload,
          };
          recordAudit(auditLogger, "op_script_reload_allowlists", "success", {
            reason,
            ...result,
          });
          return jsonResult(result);
        } catch (error) {
          recordAudit(
            auditLogger,
            "op_script_reload_allowlists",
            "error",
            {
              reason,
              configuredAllowlistPathCount: config.scriptRunnerAllowlistPaths.length,
              configuredAllowlistManifestCount:
                config.scriptRunnerAllowlistManifestPaths.length,
            },
            error,
          );
          throw normalizeError(error);
        }
      },
    );

    server.registerTool(
      "op_script_run",
      {
        description:
          `Run one script with 1Password CLI auth injected by the MCP process. In normal mode this runs a startup-configured allowlisted commandId. When --enable-unrestricted-script-runner=true is set, startup allowlists are ignored and this accepts a free-form command after one local browser approval per MCP process. ${SCRIPT_RUNNER_SECRET_HINT} Use this instead of password_read reveal or secret_reveal when the secret only needs to be passed to a script. If returnOutput=true is requested for secret-injected or sensitive output without plaintext acknowledgement, execution is skipped and the required acknowledgement is returned.`,
        inputSchema: {
          workspaceRoot: z.string().min(1),
          commandId: z.string().min(1).optional(),
          command: z.string().min(1).optional(),
          reason: z.string().min(3),
          envSecretRefs: envSecretRefsSchema.optional(),
          returnOutput: z.boolean().optional(),
          acknowledgePlaintext: z.string().optional(),
        },
      },
      async ({
        workspaceRoot,
        commandId,
        command,
        reason,
        envSecretRefs,
        returnOutput,
        acknowledgePlaintext,
      }) => {
        assertScriptRunnerEnabled(config);

        let envSecretReferences: ReturnType<typeof summarizeEnvSecretRefs> = [];
        let injectedSecretEnvVars: string[] = [];

        try {
          const validatedEnvSecretRefs = validateEnvSecretRefs(envSecretRefs);
          envSecretReferences = summarizeEnvSecretRefs(validatedEnvSecretRefs);
          injectedSecretEnvVars = envSecretReferences.map((entry) => entry.envVar);

          if (config.enableUnrestrictedScriptRunner) {
            if (!command) {
              throw new Error(
                "command is required when unrestricted script runner mode is enabled.",
              );
            }

            if (
              config.unrestrictedRunnerRequireSessionApproval &&
              !approvalManager.isApproved(UNRESTRICTED_SCRIPT_RUNNER_SCOPE)
            ) {
              const authorization = approvalManager.createAuthorizationRequest(
                workspaceRoot,
                UNRESTRICTED_SCRIPT_RUNNER_SCOPE,
              );
              recordAudit(
                auditLogger,
                "op_script_run_authorization_required",
                "success",
                {
                  workspaceRoot,
                  configuredRoot: UNRESTRICTED_SCRIPT_RUNNER_SCOPE,
                  commandHash: sha256Hash(command),
                  commandLength: command.length,
                  reason,
                  requiredAcknowledgement: UNRESTRICTED_RUNNER_ACK,
                  envSecretRefCount: envSecretReferences.length,
                  injectedSecretEnvVars,
                  envSecretReferences,
                },
              );
              return jsonResult(authorization);
            }

            const outputPolicy = resolveScriptOutputPolicy(
              returnOutput,
              true,
              acknowledgePlaintext,
            );
            if (shouldSkipForMissingOutputAcknowledgement(outputPolicy)) {
              recordAudit(auditLogger, "op_script_run_output_ack_required", "success", {
                mode: "unrestricted",
                workspaceRoot,
                commandHash: sha256Hash(command),
                commandLength: command.length,
                reason,
                sensitiveOutput: true,
                outputRequested: outputPolicy.requested,
                outputReturned: outputPolicy.returned,
                outputState: outputPolicy.state,
                requiredAcknowledgement: outputPolicy.requiredAcknowledgement,
                envSecretRefCount: envSecretReferences.length,
                injectedSecretEnvVars,
                envSecretReferences,
              });

              return textResult(
                outputAcknowledgementRequiredText(),
                outputAcknowledgementRequiredContent(outputPolicy, {
                  mode: "unrestricted",
                  workspaceRoot,
                  commandHash: sha256Hash(command),
                  commandLength: command.length,
                  sensitiveOutput: true,
                  envSecretRefCount: envSecretReferences.length,
                  injectedSecretEnvVars,
                }),
              );
            }
            const { extraEnv, secretRedactionValues } = await resolveEnvSecretRefs(
              service,
              validatedEnvSecretRefs,
            );
            const result = await scriptRunner.runCommand(workspaceRoot, command, {
              extraEnv,
              secretRedactionValues,
            });
            const outcome =
              result.exitCode === 0 && !result.timedOut ? "success" : "error";
            recordAudit(auditLogger, "op_script_run", outcome, {
              mode: "unrestricted",
              workspaceRoot: result.workspaceRoot,
              cwd: result.cwd,
              commandHash: sha256Hash(command),
              commandLength: command.length,
              shell: result.shell,
              authMode: result.authMode,
              reason,
              durationMs: result.durationMs,
              exitCode: result.exitCode,
              signal: result.signal,
              timedOut: result.timedOut,
              outputTruncated: result.outputTruncated,
              refreshedAuth: result.refreshedAuth,
              sensitiveOutput: result.sensitiveOutput,
              outputRequested: outputPolicy.requested,
              outputReturned: outputPolicy.returned,
              outputState: outputPolicy.state,
              envSecretRefCount: envSecretReferences.length,
              injectedSecretEnvVars,
              envSecretReferences,
              ...(outputPolicy.requiredAcknowledgement
                ? { requiredAcknowledgement: outputPolicy.requiredAcknowledgement }
                : {}),
            }, result.errorMessage);

            return {
              ...textResult(
                commandOutputText(result, outputPolicy),
                {
                  ...unrestrictedScriptRunStructuredContent(result, outputPolicy),
                  envSecretRefCount: envSecretReferences.length,
                  injectedSecretEnvVars,
                },
              ),
              isError: outcome === "error",
            };
          }

          if (!commandId) {
            throw new Error("commandId is required unless unrestricted script runner mode is enabled.");
          }
          const allowlistedCommand = await getAllowlistedCommand(
            scriptRunner,
            workspaceRoot,
            commandId,
          );
          const outputPolicy = resolveScriptOutputPolicy(
            returnOutput,
            envSecretReferences.length > 0 || allowlistedCommand.sensitiveOutput === true,
            acknowledgePlaintext,
          );
          if (shouldSkipForMissingOutputAcknowledgement(outputPolicy)) {
            recordAudit(auditLogger, "op_script_run_output_ack_required", "success", {
              workspaceRoot,
              commandId,
              command: allowlistedCommand.command,
              args: allowlistedCommand.args,
              reason,
              sensitiveOutput: allowlistedCommand.sensitiveOutput,
              outputRequested: outputPolicy.requested,
              outputReturned: outputPolicy.returned,
              outputState: outputPolicy.state,
              requiredAcknowledgement: outputPolicy.requiredAcknowledgement,
              envSecretRefCount: envSecretReferences.length,
              injectedSecretEnvVars,
              envSecretReferences,
            });

            return textResult(
              outputAcknowledgementRequiredText(),
              outputAcknowledgementRequiredContent(outputPolicy, {
                workspaceRoot,
                commandId,
                sensitiveOutput: allowlistedCommand.sensitiveOutput,
                envSecretRefCount: envSecretReferences.length,
                injectedSecretEnvVars,
              }),
            );
          }

          const { extraEnv, secretRedactionValues } = await resolveEnvSecretRefs(
            service,
            validatedEnvSecretRefs,
          );

          const result = await scriptRunner.run(workspaceRoot, commandId, {
            extraEnv,
            secretRedactionValues,
          });
          const outcome =
            result.exitCode === 0 && !result.timedOut ? "success" : "error";
          recordAudit(auditLogger, "op_script_run", outcome, {
            workspaceRoot: result.workspaceRoot,
            commandId: result.commandId,
            command: result.command,
            args: result.args,
            cwd: result.cwd,
            authMode: result.authMode,
            reason,
            durationMs: result.durationMs,
            exitCode: result.exitCode,
            signal: result.signal,
            timedOut: result.timedOut,
            outputTruncated: result.outputTruncated,
            refreshedAuth: result.refreshedAuth,
            sensitiveOutput: result.sensitiveOutput,
            outputRequested: outputPolicy.requested,
            outputReturned: outputPolicy.returned,
            outputState: outputPolicy.state,
            envSecretRefCount: envSecretReferences.length,
            injectedSecretEnvVars,
            envSecretReferences,
            ...(outputPolicy.requiredAcknowledgement
              ? { requiredAcknowledgement: outputPolicy.requiredAcknowledgement }
              : {}),
          }, result.errorMessage);

          return {
            ...textResult(
              commandOutputText(result, outputPolicy),
              {
                ...scriptRunStructuredContent(result, outputPolicy),
                envSecretRefCount: envSecretReferences.length,
                injectedSecretEnvVars,
              },
            ),
            isError: outcome === "error",
          };
        } catch (error) {
          recordAudit(
            auditLogger,
            "op_script_run",
            "error",
            {
              workspaceRoot,
              commandId,
              commandHash: command ? sha256Hash(command) : undefined,
              commandLength: command?.length,
              reason,
              envSecretRefCount: envSecretReferences.length,
              injectedSecretEnvVars,
              envSecretReferences,
            },
            error,
          );
          throw normalizeError(error);
        }
      },
    );

    server.registerTool(
      "op_session_reset",
      {
        description:
          "Clear cached 1Password CLI session state held by this MCP process.",
      },
      async () => {
        assertScriptRunnerEnabled(config);
        scriptRunner.reset();
        return jsonResult({
          reset: true,
          status: scriptRunner.status(),
        });
      },
    );
  }

  if (config.enableUnrestrictedRunner) {
    server.registerTool(
      "op_unrestricted_run",
      {
        description:
          "Run a free-form local shell command from a startup-configured unrestricted runner root after explicit local session approval. This is intentionally dangerous: the configured path is an approval scope, not an operating-system sandbox, and commands are not allowlisted. 1Password secrets are not injected; prefer op_script_run for secret-consuming commands. If returnOutput=true is requested without plaintext acknowledgement, execution is skipped and the required acknowledgement is returned.",
        inputSchema: {
          workspaceRoot: z.string().min(1),
          command: z.string().min(1),
          reason: z.string().min(3),
          returnOutput: z.boolean().optional(),
          acknowledgePlaintext: z.string().optional(),
        },
      },
      async ({
        workspaceRoot,
        command,
        reason,
        returnOutput,
        acknowledgePlaintext,
      }) => {
        assertUnrestrictedRunnerEnabled(config);

        try {
          const authorization = await unrestrictedRunner.authorization(workspaceRoot);
          if (authorization) {
            recordAudit(
              auditLogger,
              "op_unrestricted_run_authorization_required",
              "success",
              {
                workspaceRoot: authorization.workspaceRoot,
                configuredRoot: authorization.configuredRoot,
                commandHash: sha256Hash(command),
                commandLength: command.length,
                reason,
                requiredAcknowledgement: UNRESTRICTED_RUNNER_ACK,
              },
            );
            return jsonResult(authorization);
          }

          const outputPolicy = resolveScriptOutputPolicy(
            returnOutput,
            true,
            acknowledgePlaintext,
          );
          if (shouldSkipForMissingOutputAcknowledgement(outputPolicy)) {
            recordAudit(auditLogger, "op_unrestricted_run_output_ack_required", "success", {
              workspaceRoot,
              commandHash: sha256Hash(command),
              commandLength: command.length,
              reason,
              sensitiveOutput: true,
              outputRequested: outputPolicy.requested,
              outputReturned: outputPolicy.returned,
              outputState: outputPolicy.state,
              requiredAcknowledgement: outputPolicy.requiredAcknowledgement,
            });

            return textResult(
              outputAcknowledgementRequiredText(),
              outputAcknowledgementRequiredContent(outputPolicy, {
                workspaceRoot,
                commandHash: sha256Hash(command),
                commandLength: command.length,
                sensitiveOutput: true,
              }),
            );
          }
          const result = await unrestrictedRunner.run(workspaceRoot, command);
          const outcome =
            result.exitCode === 0 && !result.timedOut ? "success" : "error";
          recordAudit(auditLogger, "op_unrestricted_run", outcome, {
            workspaceRoot: result.workspaceRoot,
            configuredRoot: result.configuredRoot,
            cwd: result.cwd,
            commandHash: sha256Hash(command),
            commandLength: command.length,
            shell: result.shell,
            reason,
            durationMs: result.durationMs,
            exitCode: result.exitCode,
            signal: result.signal,
            timedOut: result.timedOut,
            outputTruncated: result.outputTruncated,
            sensitiveOutput: result.sensitiveOutput,
            outputRequested: outputPolicy.requested,
            outputReturned: outputPolicy.returned,
            outputState: outputPolicy.state,
            ...(outputPolicy.requiredAcknowledgement
              ? { requiredAcknowledgement: outputPolicy.requiredAcknowledgement }
              : {}),
          }, result.errorMessage);

          return {
            ...textResult(
              commandOutputText(result, outputPolicy),
              unrestrictedRunStructuredContent(result, outputPolicy),
            ),
            isError: outcome === "error",
          };
        } catch (error) {
          recordAudit(
            auditLogger,
            "op_unrestricted_run",
            "error",
            {
              workspaceRoot,
              commandHash: sha256Hash(command),
              commandLength: command.length,
              reason,
            },
            error,
          );
          throw normalizeError(error);
        }
      },
    );
  }

  server.registerTool(
    "password_generate",
    {
      description:
        "Generate a strong random password and return it in plaintext for immediate use. Requires a reason and generated-secret acknowledgement.",
      inputSchema: {
        length: z.number().int().min(8).max(256).optional(),
        includeLowercase: z.boolean().optional(),
        includeUppercase: z.boolean().optional(),
        includeDigits: z.boolean().optional(),
        includeSymbols: z.boolean().optional(),
        excludeSimilar: z.boolean().optional(),
        symbols: z.string().min(1).optional(),
        reason: z.string().min(3),
        acknowledgePlaintext: z.literal(GENERATED_SECRET_ACK),
      },
    },
    async (args) => {
      try {
        const password = generateRandomPassword(args);
        recordAudit(auditLogger, "password_generate", "success", {
          kind: "random-password",
          valueLength: password.length,
          reason: args.reason,
        });
        return textResult(password, {
          generated: true,
          kind: "random-password",
          valueLength: password.length,
        });
      } catch (error) {
        recordAudit(
          auditLogger,
          "password_generate",
          "error",
          { kind: "random-password", reason: args.reason },
          error,
        );
        throw normalizeError(error);
      }
    },
  );

  server.registerTool(
    "password_generate_memorable",
    {
      description:
        "Generate a memorable passphrase-like password and return it in plaintext for immediate use. Requires a reason and generated-secret acknowledgement.",
      inputSchema: {
        words: z.number().int().min(3).max(12).optional(),
        separator: z.string().max(8).optional(),
        capitalize: z.boolean().optional(),
        includeNumber: z.boolean().optional(),
        reason: z.string().min(3),
        acknowledgePlaintext: z.literal(GENERATED_SECRET_ACK),
      },
    },
    async ({ words, separator, capitalize, includeNumber, reason }) => {
      try {
        const password = generateMemorablePassword({
          words,
          separator,
          capitalize,
          includeNumber,
        });
        recordAudit(auditLogger, "password_generate_memorable", "success", {
          kind: "memorable-password",
          valueLength: password.length,
          reason,
        });
        return textResult(password, {
          generated: true,
          kind: "memorable-password",
          valueLength: password.length,
        });
      } catch (error) {
        recordAudit(
          auditLogger,
          "password_generate_memorable",
          "error",
          { kind: "memorable-password", reason },
          error,
        );
        throw normalizeError(error);
      }
    },
  );

  server.registerTool(
    "password_read",
      {
        description: passwordReadDescription(config),
        inputSchema: passwordReadInputShape,
      },
      async (rawArgs) => {
        const { secretReference, vaultId, itemId, field, reveal, reason } =
          passwordReadInputSchema.parse(rawArgs);

        if (!reveal) {
          if (secretReference) {
            return jsonResult({
            mode: "reference",
            reference: secretReference,
            valueState: "redacted",
            secretConsumptionGuidance: secretConsumptionGuidance(config),
          });
        }

        const item = await service.itemGet(vaultId!, itemId!);
        const passwordField = findPasswordField(item, field);
        return jsonResult({
          mode: "item-field",
          vaultId,
          itemId,
          title: item.title,
          field: passwordField.id,
          fieldType: passwordField.fieldType,
          valueState: "redacted",
          secretConsumptionGuidance: secretConsumptionGuidance(config),
        });
      }

      assertSecretRevealEnabled(config);

      try {
        if (secretReference) {
          const secret = await service.secretResolve(secretReference);
          recordAudit(auditLogger, "password_read", "success", {
            revealMode: "reference",
            secretReference,
            reason,
          });
          return textResult(secret, {
            revealed: true,
            revealMode: "reference",
            reference: secretReference,
            valueLength: secret.length,
          });
        }

        const item = await service.itemGet(vaultId!, itemId!);
        const passwordField = findPasswordField(item, field);
        const secret = passwordField.value;
        if (typeof secret !== "string") {
          throw new Error(`Field ${passwordField.id} is not a string secret.`);
        }

        recordAudit(auditLogger, "password_read", "success", {
          revealMode: "item-field",
          vaultId,
          itemId,
          field: passwordField.id,
          reason,
        });
        return textResult(secret, {
          revealed: true,
          revealMode: "item-field",
          vaultId,
          itemId,
          field: passwordField.id,
          valueLength: secret.length,
        });
      } catch (error) {
        recordAudit(
          auditLogger,
          "password_read",
          "error",
          { secretReference, vaultId, itemId, field, reason, reveal: true },
          error,
        );
        throw normalizeError(error);
      }
    },
  );

  if (config.enableWrites) {
    server.registerTool(
      "password_create",
    {
      description:
        "Create a login/password item with either a provided password or a generated one. Returns redacted item metadata only.",
      inputSchema: {
        vaultId: z.string().min(1),
        title: z.string().min(1),
        username: z.string().optional(),
        password: z.string().optional(),
        mode: passwordModeSchema.optional(),
        category: z.enum(["Login", "Password"]).optional(),
        tags: z.array(z.string()).optional(),
        notes: z.string().optional(),
        url: z.string().url().optional(),
        field: z.string().min(1).optional(),
        randomLength: z.number().int().min(8).max(256).optional(),
        includeLowercase: z.boolean().optional(),
        includeUppercase: z.boolean().optional(),
        includeDigits: z.boolean().optional(),
        includeSymbols: z.boolean().optional(),
        excludeSimilar: z.boolean().optional(),
        symbols: z.string().min(1).optional(),
        memorableWords: z.number().int().min(3).max(12).optional(),
        memorableSeparator: z.string().max(8).optional(),
        memorableCapitalize: z.boolean().optional(),
        memorableIncludeNumber: z.boolean().optional(),
      },
    },
    async (args) => {
      const passwordFieldId = args.field ?? "password";
      const passwordState = resolvePasswordValue(args);
      const fields: ItemField[] = [];

      if (args.username) {
        fields.push({
          id: "username",
          title: "username",
          fieldType: ItemFieldType.Text,
          value: args.username,
        });
      }

      fields.push({
        id: passwordFieldId,
        title: passwordFieldId,
        fieldType: ItemFieldType.Concealed,
        value: passwordState.value,
      });

      const category =
        (args.category ?? "Login") === "Password"
          ? ItemCategory.Password
          : ItemCategory.Login;
      const websites = args.url
        ? [
            {
              url: args.url,
              label: args.title,
              autofillBehavior: AutofillBehavior.ExactDomain,
            },
          ]
        : undefined;

      try {
        const item = await service.itemCreate({
          vaultId: args.vaultId,
          title: args.title,
          category,
          notes: args.notes,
          tags: args.tags,
          fields,
          websites,
        });
        recordAudit(auditLogger, "password_create", "success", {
          vaultId: args.vaultId,
          title: args.title,
          mode: passwordState.mode,
        });
        return jsonResult({
          item: redactItem(item),
          passwordField: passwordFieldId,
          passwordSource: passwordState.mode,
          generatedSecret: passwordState.generated,
          secretLength: passwordState.value.length,
        });
      } catch (error) {
        recordAudit(
          auditLogger,
          "password_create",
          "error",
          {
            vaultId: args.vaultId,
            title: args.title,
            mode: passwordState.mode,
          },
          error,
        );
        throw normalizeError(error);
      }
    },
  );

    server.registerTool(
      "password_update",
    {
      description:
        "Update or insert one concealed password field on an existing item. Returns redacted item metadata only.",
      inputSchema: {
        vaultId: z.string().min(1),
        itemId: z.string().min(1),
        password: z.string().optional(),
        mode: passwordModeSchema.optional(),
        field: z.string().min(1).optional(),
        randomLength: z.number().int().min(8).max(256).optional(),
        includeLowercase: z.boolean().optional(),
        includeUppercase: z.boolean().optional(),
        includeDigits: z.boolean().optional(),
        includeSymbols: z.boolean().optional(),
        excludeSimilar: z.boolean().optional(),
        symbols: z.string().min(1).optional(),
        memorableWords: z.number().int().min(3).max(12).optional(),
        memorableSeparator: z.string().max(8).optional(),
        memorableCapitalize: z.boolean().optional(),
        memorableIncludeNumber: z.boolean().optional(),
      },
    },
    async (args) => {
      const passwordFieldId = args.field ?? "password";
      const passwordState = resolvePasswordValue(args);

      try {
        const existing = await service.itemGet(args.vaultId, args.itemId);
        const nextItem = upsertPasswordField(existing, passwordState.value, passwordFieldId);
        const item = await service.itemPut(nextItem);
        recordAudit(auditLogger, "password_update", "success", {
          vaultId: args.vaultId,
          itemId: args.itemId,
          field: passwordFieldId,
          mode: passwordState.mode,
        });
        return jsonResult({
          item: redactItem(item),
          passwordField: passwordFieldId,
          passwordSource: passwordState.mode,
          generatedSecret: passwordState.generated,
          secretLength: passwordState.value.length,
        });
      } catch (error) {
        recordAudit(
          auditLogger,
          "password_update",
          "error",
          {
            vaultId: args.vaultId,
            itemId: args.itemId,
            field: passwordFieldId,
            mode: passwordState.mode,
          },
          error,
        );
        throw normalizeError(error);
      }
    },
    );
  }

  server.registerTool(
    "vault_list",
    {
      description: "List vaults visible to the authenticated 1Password integration.",
      inputSchema: {
        decryptDetails: z.boolean().optional(),
      },
    },
    async ({ decryptDetails }) => {
      const vaults = await service.vaultList({ decryptDetails });
      return jsonResult({
        vaults: vaults.map((vault) => ({
          ...vault,
          createdAt: vault.createdAt.toISOString(),
          updatedAt: vault.updatedAt.toISOString(),
        })),
      });
    },
  );

  server.registerTool(
    "vault_get",
    {
      description: "Get vault details and, optionally, accessor permissions for one vault.",
      inputSchema: {
        vaultId: z.string().min(1),
        includeAccessors: z.boolean().optional(),
      },
    },
    async ({ vaultId, includeAccessors }) => {
      const vault = await service.vaultGet(vaultId, { accessors: includeAccessors });
      return jsonResult({ vault: redactVault(vault) });
    },
  );

  if (config.enableWrites && capabilities.vaultMutation) {
    server.registerTool(
      "vault_create",
    {
      description: "Create a new vault.",
      inputSchema: {
        title: z.string().min(1),
        description: z.string().optional(),
        allowAdminsAccess: z.boolean().optional(),
      },
    },
    async ({ title, description, allowAdminsAccess }) => {
      try {
        const vault = await service.vaultCreate({
          title,
          description,
          allowAdminsAccess,
        });
        recordAudit(auditLogger, "vault_create", "success", { title });
        return jsonResult({ vault: redactVault(vault) });
      } catch (error) {
        recordAudit(auditLogger, "vault_create", "error", { title }, error);
        throw normalizeError(error);
      }
    },
  );

    server.registerTool(
      "vault_update",
    {
      description: "Update a vault title and/or description.",
      inputSchema: {
        vaultId: z.string().min(1),
        title: z.string().optional(),
        description: z.string().optional(),
      },
    },
    async ({ vaultId, title, description }) => {
      try {
        const vault = await service.vaultUpdate(vaultId, { title, description });
        recordAudit(auditLogger, "vault_update", "success", { vaultId });
        return jsonResult({ vault: redactVault(vault) });
      } catch (error) {
        recordAudit(auditLogger, "vault_update", "error", { vaultId }, error);
        throw normalizeError(error);
      }
    },
  );

  }

  if (config.enableDestructiveActions && capabilities.vaultDestructive) {
    server.registerTool(
      "vault_delete",
    {
      description: "Delete a vault by ID. Requires a reason and destructive-action acknowledgement.",
      inputSchema: {
        vaultId: z.string().min(1),
        reason: z.string().min(3),
        acknowledgeDestructive: z.literal(DESTRUCTIVE_ACTION_ACK),
      },
    },
    async ({ vaultId, reason }) => {
      try {
        await service.vaultDelete(vaultId);
        recordAudit(auditLogger, "vault_delete", "success", { vaultId, reason });
        return jsonResult({ deleted: true, vaultId });
      } catch (error) {
        recordAudit(auditLogger, "vault_delete", "error", { vaultId, reason }, error);
        throw normalizeError(error);
      }
    },
    );
  }

  if (capabilities.permissionRead) {
    server.registerTool(
    "group_get",
    {
      description:
        "Get one group by ID. This is the only group read endpoint exposed by the official JS SDK beta today.",
      inputSchema: {
        groupId: z.string().min(1),
        includeVaultPermissions: z.boolean().optional(),
      },
    },
    async ({ groupId, includeVaultPermissions }) => {
      const group = await service.groupGet(groupId, {
        vaultPermissions: includeVaultPermissions,
      });
      return jsonResult({ group: sanitizeGroup(group) });
    },
  );

    server.registerTool(
    "vault_permissions_get",
    {
      description:
        "Get vault accessor permissions. The JS SDK beta exposes this through vault accessors.",
      inputSchema: {
        vaultId: z.string().min(1),
      },
    },
    async ({ vaultId }) => {
      const vault = await service.vaultGet(vaultId, { accessors: true });
      return jsonResult({
        vaultId,
        accessors: redactVault(vault).access ?? [],
      });
    },
    );
  }

  if (config.enablePermissionMutation && capabilities.permissionMutation) {
    server.registerTool(
      "vault_permissions_grant_group",
    {
      description: "Grant group permissions on a vault. Requires a reason and permission-mutation acknowledgement.",
      inputSchema: {
        vaultId: z.string().min(1),
        groupId: z.string().min(1),
        permissions: z.array(permissionNameSchema).min(1),
        reason: z.string().min(3),
        acknowledgePermissionMutation: z.literal(PERMISSION_MUTATION_ACK),
      },
    },
    async ({ vaultId, groupId, permissions, reason }) => {
      const payload: GroupAccess[] = [
        {
          groupId,
          permissions: encodePermissions(permissions),
        },
      ];

      try {
        await service.vaultGrantGroupPermissions(vaultId, payload);
        recordAudit(auditLogger, "vault_permissions_grant_group", "success", {
          vaultId,
          groupId,
          permissions,
          reason,
        });
        return jsonResult({
          granted: true,
          vaultId,
          groupId,
          permissions,
        });
      } catch (error) {
        recordAudit(
          auditLogger,
          "vault_permissions_grant_group",
          "error",
          { vaultId, groupId, permissions, reason },
          error,
        );
        throw normalizeError(error);
      }
    },
  );

    server.registerTool(
      "vault_permissions_update_group",
    {
      description: "Replace a group's permissions on a vault. Requires a reason and permission-mutation acknowledgement.",
      inputSchema: {
        vaultId: z.string().min(1),
        groupId: z.string().min(1),
        permissions: z.array(permissionNameSchema).min(1),
        reason: z.string().min(3),
        acknowledgePermissionMutation: z.literal(PERMISSION_MUTATION_ACK),
      },
    },
    async ({ vaultId, groupId, permissions, reason }) => {
      const payload: GroupVaultAccess[] = [
        {
          vaultId,
          groupId,
          permissions: encodePermissions(permissions),
        },
      ];

      try {
        await service.vaultUpdateGroupPermissions(payload);
        recordAudit(auditLogger, "vault_permissions_update_group", "success", {
          vaultId,
          groupId,
          permissions,
          reason,
        });
        return jsonResult({
          updated: true,
          vaultId,
          groupId,
          permissions,
        });
      } catch (error) {
        recordAudit(
          auditLogger,
          "vault_permissions_update_group",
          "error",
          { vaultId, groupId, permissions, reason },
          error,
        );
        throw normalizeError(error);
      }
    },
  );

    server.registerTool(
      "vault_permissions_revoke_group",
    {
      description: "Revoke all group permissions from a vault. Requires a reason and permission-mutation acknowledgement.",
      inputSchema: {
        vaultId: z.string().min(1),
        groupId: z.string().min(1),
        reason: z.string().min(3),
        acknowledgePermissionMutation: z.literal(PERMISSION_MUTATION_ACK),
      },
    },
    async ({ vaultId, groupId, reason }) => {
      try {
        await service.vaultRevokeGroupPermissions(vaultId, groupId);
        recordAudit(auditLogger, "vault_permissions_revoke_group", "success", {
          vaultId,
          groupId,
          reason,
        });
        return jsonResult({
          revoked: true,
          vaultId,
          groupId,
        });
      } catch (error) {
        recordAudit(
          auditLogger,
          "vault_permissions_revoke_group",
          "error",
          { vaultId, groupId, reason },
          error,
        );
        throw normalizeError(error);
      }
    },
    );
  }

  server.registerTool(
    "item_search",
    {
      description:
        "Search item overviews by title/tags/category. If no vault is provided, the server searches every visible vault client-side.",
      inputSchema: {
        query: z.string().optional(),
        vaultId: z.string().optional(),
        includeArchived: z.boolean().optional(),
        limit: z.number().int().positive().max(200).optional(),
      },
    },
    async ({ query, vaultId, includeArchived, limit }) => {
      const targetVaults =
        vaultId !== undefined
          ? [{ id: vaultId }]
          : await service.vaultList({ decryptDetails: false });

      const itemFilters = createItemFilters(includeArchived ?? false);
      const results: ReturnType<typeof redactItemOverview>[] = [];
      const failures: Array<{ vaultId: string; errorMessage: string }> = [];

      for (const vault of targetVaults) {
        try {
          const items = await service.itemList(vault.id, ...itemFilters);
          for (const item of items) {
            const redacted = redactItemOverview(item);
            if (matchesQuery(redacted, query)) {
              results.push(redacted);
            }
          }
        } catch (error) {
          if (vaultId !== undefined) {
            throw normalizeError(error);
          }
          failures.push({
            vaultId: vault.id,
            errorMessage: errorMessage(error),
          });
        }
      }

      return jsonResult({
        items: results.slice(0, limit ?? 50),
        totalMatched: results.length,
        searchedVaultCount: targetVaults.length,
        failedVaultCount: failures.length,
        partialFailure: failures.length > 0,
        failures,
      });
    },
  );

  server.registerTool(
    "item_get_metadata",
    {
      description:
        "Get item metadata with every field value redacted. Use secret_reveal only when plaintext is explicitly required.",
      inputSchema: {
        vaultId: z.string().min(1),
        itemId: z.string().min(1),
      },
    },
    async ({ vaultId, itemId }) => {
      const item = await service.itemGet(vaultId, itemId);
      return jsonResult({ item: redactItem(item) });
    },
  );

  if (config.enableWrites) {
    server.registerTool(
      "item_create",
    {
      description: "Create an item in a vault.",
      inputSchema: {
        vaultId: z.string().min(1),
        category: z.nativeEnum(ItemCategory),
        title: z.string().min(1),
        notes: z.string().optional(),
        tags: z.array(z.string()).optional(),
        fields: z.array(fieldSchema).optional(),
        sections: z.array(sectionSchema).optional(),
        websites: z.array(websiteSchema).optional(),
      },
    },
    async ({ vaultId, category, title, notes, tags, fields, sections, websites }) => {
      const params: ItemCreateParams = {
        vaultId,
        category,
        title,
        notes,
        tags,
        fields: toItemFields(fields),
        sections: toItemSections(sections),
        websites: toWebsites(websites),
      };

      try {
        const item = await service.itemCreate(params);
        recordAudit(auditLogger, "item_create", "success", {
          vaultId,
          category,
          title,
        });
        return jsonResult({ item: redactItem(item) });
      } catch (error) {
        recordAudit(
          auditLogger,
          "item_create",
          "error",
          { vaultId, category, title },
          error,
        );
        throw normalizeError(error);
      }
    },
  );

    server.registerTool(
      "item_update",
    {
      description:
        "Update an item. Provided arrays replace the existing arrays on the item.",
      inputSchema: {
        vaultId: z.string().min(1),
        itemId: z.string().min(1),
        title: z.string().optional(),
        notes: z.string().optional(),
        tags: z.array(z.string()).optional(),
        fields: z.array(fieldSchema).optional(),
        sections: z.array(sectionSchema).optional(),
        websites: z.array(websiteSchema).optional(),
      },
    },
    async ({ vaultId, itemId, title, notes, tags, fields, sections, websites }) => {
      const existing = await service.itemGet(vaultId, itemId);
      const nextItem: Item = {
        ...existing,
        title: title ?? existing.title,
        notes: notes ?? existing.notes,
        tags: tags ?? existing.tags,
        fields: toItemFields(fields) ?? existing.fields,
        sections: toItemSections(sections) ?? existing.sections,
        websites: toWebsites(websites) ?? existing.websites,
      };

      try {
        const item = await service.itemPut(nextItem);
        recordAudit(auditLogger, "item_update", "success", { vaultId, itemId });
        return jsonResult({ item: redactItem(item) });
      } catch (error) {
        recordAudit(
          auditLogger,
          "item_update",
          "error",
          { vaultId, itemId },
          error,
        );
        throw normalizeError(error);
      }
    },
  );

  }

  if (config.enableDestructiveActions) {
    if (capabilities.itemArchive) {
      server.registerTool(
      "item_archive",
    {
      description: "Archive an item. Requires a reason and destructive-action acknowledgement.",
      inputSchema: {
        vaultId: z.string().min(1),
        itemId: z.string().min(1),
        reason: z.string().min(3),
        acknowledgeDestructive: z.literal(DESTRUCTIVE_ACTION_ACK),
      },
    },
    async ({ vaultId, itemId, reason }) => {
      try {
        await service.itemArchive(vaultId, itemId);
        recordAudit(auditLogger, "item_archive", "success", { vaultId, itemId, reason });
        return jsonResult({ archived: true, vaultId, itemId });
      } catch (error) {
        recordAudit(
          auditLogger,
          "item_archive",
          "error",
          { vaultId, itemId, reason },
          error,
        );
        throw normalizeError(error);
      }
    },
      );
    }

    if (capabilities.itemDelete) {
      server.registerTool(
      "item_delete",
    {
      description: "Delete an item. Requires a reason and destructive-action acknowledgement.",
      inputSchema: {
        vaultId: z.string().min(1),
        itemId: z.string().min(1),
        reason: z.string().min(3),
        acknowledgeDestructive: z.literal(DESTRUCTIVE_ACTION_ACK),
      },
    },
    async ({ vaultId, itemId, reason }) => {
      try {
        await service.itemDelete(vaultId, itemId);
        recordAudit(auditLogger, "item_delete", "success", { vaultId, itemId, reason });
        return jsonResult({ deleted: true, vaultId, itemId });
      } catch (error) {
        recordAudit(
          auditLogger,
          "item_delete",
          "error",
          { vaultId, itemId, reason },
          error,
        );
        throw normalizeError(error);
      }
    },
      );
    }
  }

  if (capabilities.environments) {
    server.registerTool(
    "environment_get_variables",
    {
      description:
        `Get 1Password Environment variables with values redacted. Supports simple client-side filtering by variable name. ${SCRIPT_RUNNER_SECRET_HINT}`,
      inputSchema: {
        environmentId: z.string().min(1),
        query: z.string().optional(),
        limit: z.number().int().positive().max(500).optional(),
      },
    },
    async ({ environmentId, query, limit }) => {
      const environment = await service.environmentGetVariables(environmentId);
      const filtered = filterEnvironmentVariables(environment.variables, query);
      return jsonResult({
        environmentId,
        query,
        totalMatched: filtered.length,
        variables: filtered
          .slice(0, limit ?? 100)
          .map((variable) => redactEnvironmentVariable(variable)),
        secretConsumptionGuidance: secretConsumptionGuidance(config),
      });
    },
  );

    server.registerTool(
    "environment_get_variable",
    {
      description:
        `Get one 1Password Environment variable by exact name, with the value redacted. ${SCRIPT_RUNNER_SECRET_HINT}`,
      inputSchema: {
        environmentId: z.string().min(1),
        name: z.string().min(1),
      },
    },
    async ({ environmentId, name }) => {
      const environment = await service.environmentGetVariables(environmentId);
      const variable = findEnvironmentVariable(environment.variables, name);
      return jsonResult({
        environmentId,
        variable: redactEnvironmentVariable(variable),
        secretConsumptionGuidance: secretConsumptionGuidance(config),
      });
    },
  );

    server.registerTool(
    "environment_reveal_variable",
    {
      description: plaintextRevealDescription(
        config,
        "Reveal one 1Password Environment variable in plaintext. Requires secret reveal to be enabled and writes an audit entry.",
      ),
      inputSchema: {
        environmentId: z.string().min(1),
        name: z.string().min(1),
        reason: z.string().min(3),
        acknowledgePlaintext: z.literal(SECRET_REVEAL_ACK),
      },
    },
    async ({ environmentId, name, reason }) => {
      assertSecretRevealEnabled(config);

      try {
        const environment = await service.environmentGetVariables(environmentId);
        const variable = findEnvironmentVariable(environment.variables, name);

        recordAudit(auditLogger, "environment_reveal_variable", "success", {
          environmentId,
          name,
          reason,
        });
        return textResult(variable.value, {
          revealed: true,
          revealMode: "environment-variable",
          environmentId,
          name: variable.name,
          valueLength: variable.value.length,
          masked: variable.masked,
        });
      } catch (error) {
        recordAudit(
          auditLogger,
          "environment_reveal_variable",
          "error",
          { environmentId, name, reason },
          error,
        );
        throw normalizeError(error);
      }
    },
    );
  }

  server.registerTool(
    "secret_reveal",
      {
        description: plaintextRevealDescription(
          config,
          "Return a secret in plaintext. This tool writes an audit entry.",
        ),
        inputSchema: secretRevealInputShape,
      },
      async (rawArgs) => {
        const { reason, reference, vaultId, itemId, fieldId } =
          secretRevealInputSchema.parse(rawArgs);

        assertSecretRevealEnabled(config);

        try {
        let secret: string;
        let revealMode: "reference" | "field";

        if (reference) {
          secret = await service.secretResolve(reference);
          revealMode = "reference";
        } else {
          const item = await service.itemGet(vaultId!, itemId!);
          const field = item.fields.find((candidate) => candidate.id === fieldId);
          if (!field) {
            throw new Error(`Field ${fieldId} not found on item ${itemId}.`);
          }
          secret = field.value;
          revealMode = "field";
        }

        recordAudit(auditLogger, "secret_reveal", "success", {
          revealMode,
          reference,
          vaultId,
          itemId,
          fieldId,
          reason,
        });
        return textResult(secret, {
          revealed: true,
          revealMode,
          reference,
          vaultId,
          itemId,
          fieldId,
          valueLength: secret.length,
        });
      } catch (error) {
        recordAudit(
          auditLogger,
          "secret_reveal",
          "error",
          { reference, vaultId, itemId, fieldId, reason },
          error,
        );
        throw normalizeError(error);
      }
    },
  );

  return server;
}
