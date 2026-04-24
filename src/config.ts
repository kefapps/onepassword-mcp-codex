import { mkdirSync } from "node:fs";
import { delimiter, dirname, isAbsolute, join } from "node:path";
import { homedir } from "node:os";

export type AuthMode = "desktop" | "service-account";
export type LogLevel = "debug" | "info" | "warn" | "error";
export type OpCliAuthMode = "auto" | "desktop" | "manual-session" | "service-account";

export interface ServerConfig {
  authMode: AuthMode;
  account?: string;
  serviceAccountToken?: string;
  enableSecretReveal: boolean;
  enableWrites: boolean;
  enableDestructiveActions: boolean;
  enablePermissionMutation: boolean;
  enableScriptRunner: boolean;
  scriptRunnerRoots: string[];
  scriptRunnerAllowlistPaths: string[];
  opCliPath: string;
  opCliAuthMode: OpCliAuthMode;
  auditLogPath: string;
  logLevel: LogLevel;
  integrationName: string;
  integrationVersion: string;
}

export class HelpError extends Error {}

const DEFAULT_AUDIT_LOG_PATH = join(
  homedir(),
  ".onepassword-mcp-codex",
  "audit.jsonl",
);

function validateFlagValue(name: string, value: string | undefined): string {
  if (!value || value.startsWith("--")) {
    throw new Error(
      `Missing value for --${name}. Use --${name}=<value> or --${name} <value>.`,
    );
  }

  return value;
}

function readFlagValue(args: string[], name: string): string | undefined {
  const prefix = `--${name}=`;
  const prefixed = args.find((arg) => arg.startsWith(prefix));
  if (prefixed) {
    return validateFlagValue(name, prefixed.slice(prefix.length));
  }

  const index = args.indexOf(`--${name}`);
  if (index >= 0) {
    return validateFlagValue(name, args[index + 1]);
  }

  return undefined;
}

function readFlagValues(args: string[], name: string): string[] {
  const values: string[] = [];
  const prefix = `--${name}=`;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg.startsWith(prefix)) {
      values.push(validateFlagValue(name, arg.slice(prefix.length)));
      continue;
    }
    if (arg === `--${name}`) {
      values.push(validateFlagValue(name, args[index + 1]));
      index += 1;
    }
  }

  return values;
}

function hasFlag(args: string[], name: string): boolean {
  return (
    args.includes(`--${name}`) || args.some((arg) => arg.startsWith(`--${name}=`))
  );
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }

  switch (value.toLowerCase()) {
    case "1":
    case "true":
    case "yes":
    case "on":
      return true;
    case "0":
    case "false":
    case "no":
    case "off":
      return false;
    default:
      throw new Error(`Invalid boolean value: ${value}`);
  }
}

function parseLogLevel(value: string | undefined): LogLevel {
  if (!value) {
    return "info";
  }

  if (value === "debug" || value === "info" || value === "warn" || value === "error") {
    return value;
  }

  throw new Error(`Invalid log level: ${value}`);
}

function parseOpCliAuthMode(value: string | undefined): OpCliAuthMode {
  if (!value) {
    return "auto";
  }

  if (
    value === "auto" ||
    value === "desktop" ||
    value === "manual-session" ||
    value === "service-account"
  ) {
    return value;
  }

  throw new Error(`Unsupported op CLI auth mode: ${value}`);
}

function resolveScriptRunnerAuthMode(
  authMode: AuthMode,
  opCliAuthMode: OpCliAuthMode,
): Exclude<OpCliAuthMode, "auto"> {
  if (opCliAuthMode === "auto") {
    return authMode === "service-account" ? "service-account" : "manual-session";
  }

  return opCliAuthMode;
}

function parsePathList(value: string | undefined): string[] {
  if (!value) {
    return [];
  }

  return value
    .split(delimiter)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function parseConfig(argv: string[], packageVersion: string): ServerConfig {
  if (argv.includes("-h") || hasFlag(argv, "help")) {
    throw new HelpError(
      [
        "Usage: onepassword-mcp-codex [options]",
        "",
        "Options:",
        "  --auth-mode=desktop|service-account",
        "  --account=<1password account name or UUID>",
        "  --service-account-token=<token>",
        "  --enable-secret-reveal=true|false",
        "  --enable-writes=true|false",
        "  --enable-destructive-actions=true|false",
        "  --enable-permission-mutation=true|false",
        "  --enable-script-runner=true|false",
        "  --script-runner-root=<absolute trusted root> (repeatable)",
        "  --script-runner-allowlist=<absolute allowlist file> (repeatable)",
        "  --op-cli-path=<path>",
        "  --op-cli-auth-mode=auto|desktop|manual-session|service-account",
        "  --audit-log-path=<path>",
        "  --log-level=debug|info|warn|error",
      ].join("\n"),
    );
  }

  const authMode = (readFlagValue(argv, "auth-mode") ??
    process.env.OP_MCP_AUTH_MODE ??
    "desktop") as AuthMode;

  if (authMode !== "desktop" && authMode !== "service-account") {
    throw new Error(`Unsupported auth mode: ${authMode}`);
  }

  const account = readFlagValue(argv, "account") ?? process.env.OP_MCP_ACCOUNT;
  const serviceAccountToken =
    readFlagValue(argv, "service-account-token") ??
    process.env.OP_SERVICE_ACCOUNT_TOKEN ??
    process.env.OP_MCP_SERVICE_ACCOUNT_TOKEN;

  if (authMode === "desktop" && !account) {
    throw new Error(
      "Desktop auth requires --account or OP_MCP_ACCOUNT with the 1Password account name/UUID.",
    );
  }

  if (authMode === "service-account" && !serviceAccountToken) {
    throw new Error(
      "Service-account auth requires --service-account-token or OP_SERVICE_ACCOUNT_TOKEN.",
    );
  }

  const enableSecretReveal = parseBoolean(
    readFlagValue(argv, "enable-secret-reveal") ??
      process.env.OP_MCP_ENABLE_SECRET_REVEAL,
    false,
  );
  const enableWrites = parseBoolean(
    readFlagValue(argv, "enable-writes") ?? process.env.OP_MCP_ENABLE_WRITES,
    false,
  );
  const enableDestructiveActions = parseBoolean(
    readFlagValue(argv, "enable-destructive-actions") ??
      process.env.OP_MCP_ENABLE_DESTRUCTIVE_ACTIONS,
    false,
  );
  const enablePermissionMutation = parseBoolean(
    readFlagValue(argv, "enable-permission-mutation") ??
      process.env.OP_MCP_ENABLE_PERMISSION_MUTATION,
    false,
  );
  const enableScriptRunner = parseBoolean(
    readFlagValue(argv, "enable-script-runner") ??
      process.env.OP_MCP_ENABLE_SCRIPT_RUNNER,
    false,
  );
  const scriptRunnerRoots = [
    ...readFlagValues(argv, "script-runner-root"),
    ...parsePathList(
      readFlagValue(argv, "script-runner-roots") ??
        process.env.OP_MCP_SCRIPT_RUNNER_ROOTS,
    ),
  ];
  const scriptRunnerAllowlistPaths = [
    ...readFlagValues(argv, "script-runner-allowlist"),
    ...parsePathList(
      readFlagValue(argv, "script-runner-allowlists") ??
        process.env.OP_MCP_SCRIPT_RUNNER_ALLOWLISTS,
    ),
  ];
  const opCliPath = readFlagValue(argv, "op-cli-path") ?? process.env.OP_MCP_OP_CLI_PATH ?? "op";
  const opCliAuthMode = parseOpCliAuthMode(
    readFlagValue(argv, "op-cli-auth-mode") ?? process.env.OP_MCP_OP_CLI_AUTH_MODE,
  );

  if (enableScriptRunner) {
    if (scriptRunnerAllowlistPaths.length === 0) {
      throw new Error(
        "Script runner requires at least one --script-runner-allowlist absolute allowlist file.",
      );
    }
    for (const root of scriptRunnerRoots) {
      if (!isAbsolute(root)) {
        throw new Error(`Script runner root must be absolute: ${root}`);
      }
    }
    for (const allowlistPath of scriptRunnerAllowlistPaths) {
      if (!isAbsolute(allowlistPath)) {
        throw new Error(`Script runner allowlist path must be absolute: ${allowlistPath}`);
      }
    }
    if (!isAbsolute(opCliPath)) {
      throw new Error(
        "Script runner requires --op-cli-path to be an absolute path.",
      );
    }
    const scriptRunnerAuthMode = resolveScriptRunnerAuthMode(authMode, opCliAuthMode);
    if (
      (scriptRunnerAuthMode === "desktop" ||
        scriptRunnerAuthMode === "manual-session") &&
      !account
    ) {
      throw new Error(
        "Script runner op CLI auth requires --account or OP_MCP_ACCOUNT for desktop/manual-session mode.",
      );
    }
    if (scriptRunnerAuthMode === "service-account" && !serviceAccountToken) {
      throw new Error(
        "Script runner op CLI service-account mode requires --service-account-token or OP_SERVICE_ACCOUNT_TOKEN.",
      );
    }
  }

  const auditLogPath =
    readFlagValue(argv, "audit-log-path") ??
    process.env.OP_MCP_AUDIT_LOG_PATH ??
    DEFAULT_AUDIT_LOG_PATH;
  mkdirSync(dirname(auditLogPath), { recursive: true, mode: 0o700 });

  return {
    authMode,
    account,
    serviceAccountToken,
    enableSecretReveal,
    enableWrites,
    enableDestructiveActions,
    enablePermissionMutation,
    enableScriptRunner,
    scriptRunnerRoots,
    scriptRunnerAllowlistPaths,
    opCliPath,
    opCliAuthMode,
    auditLogPath,
    logLevel: parseLogLevel(
      readFlagValue(argv, "log-level") ?? process.env.OP_MCP_LOG_LEVEL,
    ),
    integrationName: "Codex 1Password MCP",
    integrationVersion: packageVersion,
  };
}
