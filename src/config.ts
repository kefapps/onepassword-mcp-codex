import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

export type AuthMode = "desktop" | "service-account";
export type LogLevel = "debug" | "info" | "warn" | "error";
export type OpCliAuthMode = "auto" | "desktop" | "manual-session" | "service-account";

export interface ServerConfig {
  authMode: AuthMode;
  account?: string;
  serviceAccountToken?: string;
  enableSecretReveal: boolean;
  enableScriptRunner: boolean;
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

function readFlagValue(args: string[], name: string): string | undefined {
  const prefix = `--${name}=`;
  const prefixed = args.find((arg) => arg.startsWith(prefix));
  if (prefixed) {
    return prefixed.slice(prefix.length);
  }

  const index = args.indexOf(`--${name}`);
  if (index >= 0) {
    return args[index + 1];
  }

  return undefined;
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
        "  --enable-script-runner=true|false",
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
  const enableScriptRunner = parseBoolean(
    readFlagValue(argv, "enable-script-runner") ??
      process.env.OP_MCP_ENABLE_SCRIPT_RUNNER,
    false,
  );
  const opCliPath = readFlagValue(argv, "op-cli-path") ?? process.env.OP_MCP_OP_CLI_PATH ?? "op";
  const opCliAuthMode = parseOpCliAuthMode(
    readFlagValue(argv, "op-cli-auth-mode") ?? process.env.OP_MCP_OP_CLI_AUTH_MODE,
  );

  const auditLogPath =
    readFlagValue(argv, "audit-log-path") ??
    process.env.OP_MCP_AUDIT_LOG_PATH ??
    DEFAULT_AUDIT_LOG_PATH;
  mkdirSync(dirname(auditLogPath), { recursive: true });

  return {
    authMode,
    account,
    serviceAccountToken,
    enableSecretReveal,
    enableScriptRunner,
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
