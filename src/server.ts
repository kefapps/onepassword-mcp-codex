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
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AuditLogger } from "./audit.js";
import { SDK_CAPABILITIES } from "./capabilities.js";
import type { ServerConfig } from "./config.js";
import { SECRET_REVEAL_ACK } from "./constants.js";
import { registerOnePasswordPrompts } from "./mcp-prompts.js";
import { registerOnePasswordResources } from "./mcp-resources.js";
import { DefaultOpScriptRunner, type OpScriptRunner } from "./op-runner.js";
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
      "Plaintext secret reveal is disabled. Restart the server with --enable-secret-reveal=true to allow this tool.",
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
  errorMessage?: string,
): void {
  auditLogger.record({
    action,
    outcome,
    metadata: sanitizeAuditValue(metadata) as Record<string, unknown>,
    errorMessage: errorMessage ? sanitizeAuditString(errorMessage) : undefined,
  });
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
  errorMessage?: string;
}, includeOutput: boolean): string {
  const sections: string[] = [];

  if (includeOutput && result.stdout) {
    sections.push(result.stdout.trimEnd());
  }
  if (includeOutput && result.stderr) {
    sections.push(result.stderr.trimEnd());
  }
  if (result.errorMessage) {
    sections.push(result.errorMessage);
  }
  if (sections.length === 0) {
    sections.push(`Command completed with exit code ${result.exitCode ?? "unknown"}.`);
  }
  if (!includeOutput) {
    sections.push("Command stdout/stderr withheld by default.");
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
  includeOutput: boolean,
): Record<string, unknown> {
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
    outputReturned: includeOutput,
    ...(includeOutput
      ? {
          stdout: result.stdout,
          stderr: result.stderr,
          errorMessage: result.errorMessage,
        }
      : {
          outputState: "withheld",
          errorMessage: result.errorMessage,
        }),
  };
}

export function createOnePasswordMcpServer(
  config: ServerConfig,
  service: OnePasswordService,
  auditLogger: AuditLogger,
  scriptRunner: OpScriptRunner = new DefaultOpScriptRunner(config),
): McpServer {
  const server = new McpServer({
    name: "onepassword-mcp-codex",
    version: config.integrationVersion,
  });

  registerOnePasswordResources(server, config, service);
  registerOnePasswordPrompts(server);

  server.registerTool(
    "sdk_capabilities",
    {
      description:
        "Describe the capability surface exposed by this server and the official JS SDK gaps still blocking some admin flows.",
    },
    async () =>
      jsonResult({
        authMode: config.authMode,
        secretRevealEnabled: config.enableSecretReveal,
        writesEnabled: config.enableWrites,
        destructiveActionsEnabled: config.enableDestructiveActions,
        permissionMutationEnabled: config.enablePermissionMutation,
        scriptRunnerEnabled: config.enableScriptRunner,
        ...SDK_CAPABILITIES,
      }),
  );

  if (config.enableScriptRunner) {
    server.registerTool(
      "op_script_list",
      {
        description:
          "List startup-configured allowlisted scripts that can run with persistent 1Password CLI authentication managed by the MCP process.",
        inputSchema: {
          workspaceRoot: z.string().min(1),
        },
      },
      async ({ workspaceRoot }) => {
        assertScriptRunnerEnabled(config);
        const allowlist = await scriptRunner.list(workspaceRoot);
        return jsonResult({
          path: allowlist.path,
          workspaceRoot: allowlist.workspaceRoot,
          commands: allowlist.commands,
        });
      },
    );

    server.registerTool(
      "op_script_run",
      {
        description:
          "Run one startup-configured allowlisted script with 1Password CLI auth injected by the MCP process. No free-form shell commands are accepted.",
        inputSchema: {
          workspaceRoot: z.string().min(1),
          commandId: z.string().min(1),
          reason: z.string().min(3),
          returnOutput: z.boolean().optional(),
          acknowledgePlaintext: z.string().optional(),
        },
      },
      async ({ workspaceRoot, commandId, reason, returnOutput, acknowledgePlaintext }) => {
        assertScriptRunnerEnabled(config);

        try {
          const includeOutput = returnOutput ?? false;
          if (includeOutput) {
            assertSecretRevealEnabled(config);
            if (acknowledgePlaintext !== SECRET_REVEAL_ACK) {
              throw new Error(
                `returnOutput=true requires acknowledgePlaintext=${SECRET_REVEAL_ACK}.`,
              );
            }
          }

          const result = await scriptRunner.run(workspaceRoot, commandId);
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
            outputReturned: includeOutput,
          }, result.errorMessage);

          return {
            ...textResult(
              commandOutputText(result, includeOutput),
              scriptRunStructuredContent(result, includeOutput),
            ),
            isError: outcome === "error",
          };
        } catch (error) {
          recordAudit(
            auditLogger,
            "op_script_run",
            "error",
            { workspaceRoot, commandId, reason },
            String(error),
          );
          throw error;
        }
      },
    );

    server.registerTool(
      "op_session_status",
      {
        description:
          "Show non-secret 1Password CLI session state held by this MCP process.",
      },
      async () => {
        assertScriptRunnerEnabled(config);
        return jsonResult(scriptRunner.status());
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

  server.registerTool(
    "password_generate",
    {
      description:
        "Generate a strong random password and return it in plaintext for immediate use.",
      inputSchema: {
        length: z.number().int().min(8).max(256).optional(),
        includeLowercase: z.boolean().optional(),
        includeUppercase: z.boolean().optional(),
        includeDigits: z.boolean().optional(),
        includeSymbols: z.boolean().optional(),
        excludeSimilar: z.boolean().optional(),
        symbols: z.string().min(1).optional(),
      },
    },
    async (args) => {
      const password = generateRandomPassword(args);
      return textResult(password, {
        generated: true,
        kind: "random-password",
        valueLength: password.length,
      });
    },
  );

  server.registerTool(
    "password_generate_memorable",
    {
      description:
        "Generate a memorable passphrase-like password and return it in plaintext for immediate use.",
      inputSchema: {
        words: z.number().int().min(3).max(12).optional(),
        separator: z.string().max(8).optional(),
        capitalize: z.boolean().optional(),
        includeNumber: z.boolean().optional(),
      },
    },
    async ({ words, separator, capitalize, includeNumber }) => {
      const password = generateMemorablePassword({
        words,
        separator,
        capitalize,
        includeNumber,
      });
      return textResult(password, {
        generated: true,
        kind: "memorable-password",
        valueLength: password.length,
      });
    },
  );

  server.registerTool(
    "password_read",
    {
      description:
        "Read one password field or secret reference. Returns redacted metadata by default; plaintext requires reveal=true plus reason and acknowledgement.",
      inputSchema: z
        .object({
          secretReference: z.string().optional(),
          vaultId: z.string().optional(),
          itemId: z.string().optional(),
          field: z.string().optional(),
          reveal: z.boolean().optional(),
          reason: z.string().optional(),
          acknowledgePlaintext: z.string().optional(),
        })
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
        }),
    },
    async ({ secretReference, vaultId, itemId, field, reveal, reason }) => {
      if (!reveal) {
        if (secretReference) {
          return jsonResult({
            mode: "reference",
            reference: secretReference,
            valueState: "redacted",
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
          String(error),
        );
        throw error;
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
          String(error),
        );
        throw error;
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
          String(error),
        );
        throw error;
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

  if (config.enableWrites) {
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
        recordAudit(auditLogger, "vault_create", "error", { title }, String(error));
        throw error;
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
        recordAudit(auditLogger, "vault_update", "error", { vaultId }, String(error));
        throw error;
      }
    },
  );

  }

  if (config.enableDestructiveActions) {
    server.registerTool(
      "vault_delete",
    {
      description: "Delete a vault by ID.",
      inputSchema: {
        vaultId: z.string().min(1),
      },
    },
    async ({ vaultId }) => {
      try {
        await service.vaultDelete(vaultId);
        recordAudit(auditLogger, "vault_delete", "success", { vaultId });
        return jsonResult({ deleted: true, vaultId });
      } catch (error) {
        recordAudit(auditLogger, "vault_delete", "error", { vaultId }, String(error));
        throw error;
      }
    },
    );
  }

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

  if (config.enablePermissionMutation) {
    server.registerTool(
      "vault_permissions_grant_group",
    {
      description: "Grant group permissions on a vault.",
      inputSchema: {
        vaultId: z.string().min(1),
        groupId: z.string().min(1),
        permissions: z.array(permissionNameSchema).min(1),
      },
    },
    async ({ vaultId, groupId, permissions }) => {
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
          { vaultId, groupId, permissions },
          String(error),
        );
        throw error;
      }
    },
  );

    server.registerTool(
      "vault_permissions_update_group",
    {
      description: "Replace a group's permissions on a vault.",
      inputSchema: {
        vaultId: z.string().min(1),
        groupId: z.string().min(1),
        permissions: z.array(permissionNameSchema).min(1),
      },
    },
    async ({ vaultId, groupId, permissions }) => {
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
          { vaultId, groupId, permissions },
          String(error),
        );
        throw error;
      }
    },
  );

    server.registerTool(
      "vault_permissions_revoke_group",
    {
      description: "Revoke all group permissions from a vault.",
      inputSchema: {
        vaultId: z.string().min(1),
        groupId: z.string().min(1),
      },
    },
    async ({ vaultId, groupId }) => {
      try {
        await service.vaultRevokeGroupPermissions(vaultId, groupId);
        recordAudit(auditLogger, "vault_permissions_revoke_group", "success", {
          vaultId,
          groupId,
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
          { vaultId, groupId },
          String(error),
        );
        throw error;
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
      const results = [];

      for (const vault of targetVaults) {
        const items = await service.itemList(vault.id, ...itemFilters);
        for (const item of items) {
          const redacted = redactItemOverview(item);
          if (matchesQuery(redacted, query)) {
            results.push(redacted);
          }
        }
      }

      return jsonResult({
        items: results.slice(0, limit ?? 50),
        totalMatched: results.length,
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
          String(error),
        );
        throw error;
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
          String(error),
        );
        throw error;
      }
    },
  );

  }

  if (config.enableDestructiveActions) {
    server.registerTool(
      "item_archive",
    {
      description: "Archive an item.",
      inputSchema: {
        vaultId: z.string().min(1),
        itemId: z.string().min(1),
      },
    },
    async ({ vaultId, itemId }) => {
      try {
        await service.itemArchive(vaultId, itemId);
        recordAudit(auditLogger, "item_archive", "success", { vaultId, itemId });
        return jsonResult({ archived: true, vaultId, itemId });
      } catch (error) {
        recordAudit(
          auditLogger,
          "item_archive",
          "error",
          { vaultId, itemId },
          String(error),
        );
        throw error;
      }
    },
  );

    server.registerTool(
      "item_delete",
    {
      description: "Delete an item.",
      inputSchema: {
        vaultId: z.string().min(1),
        itemId: z.string().min(1),
      },
    },
    async ({ vaultId, itemId }) => {
      try {
        await service.itemDelete(vaultId, itemId);
        recordAudit(auditLogger, "item_delete", "success", { vaultId, itemId });
        return jsonResult({ deleted: true, vaultId, itemId });
      } catch (error) {
        recordAudit(
          auditLogger,
          "item_delete",
          "error",
          { vaultId, itemId },
          String(error),
        );
        throw error;
      }
    },
    );
  }

  server.registerTool(
    "environment_get_variables",
    {
      description:
        "Get 1Password Environment variables with values redacted. Supports simple client-side filtering by variable name.",
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
      });
    },
  );

  server.registerTool(
    "environment_get_variable",
    {
      description:
        "Get one 1Password Environment variable by exact name, with the value redacted.",
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
      });
    },
  );

  server.registerTool(
    "environment_reveal_variable",
    {
      description:
        "Reveal one 1Password Environment variable in plaintext. Requires secret reveal to be enabled and writes an audit entry.",
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
          String(error),
        );
        throw error;
      }
    },
  );

  server.registerTool(
    "secret_reveal",
    {
      description:
        "Return a secret in plaintext only when the server was explicitly started with secret reveal enabled. This tool writes an audit entry.",
      inputSchema: z
        .object({
          reason: z.string().min(3),
          acknowledgePlaintext: z.literal(SECRET_REVEAL_ACK),
          reference: z.string().optional(),
          vaultId: z.string().optional(),
          itemId: z.string().optional(),
          fieldId: z.string().optional(),
        })
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
        }),
    },
    async ({ reason, reference, vaultId, itemId, fieldId }) => {
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
          String(error),
        );
        throw error;
      }
    },
  );

  return server;
}
