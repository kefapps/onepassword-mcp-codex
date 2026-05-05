import { mkdirSync } from "node:fs";
import { delimiter, dirname, isAbsolute, join } from "node:path";
import { homedir } from "node:os";

export type AuthMode = "desktop" | "service-account";
export type LogLevel = "debug" | "info" | "warn" | "error";
export type OpCliAuthMode = "auto" | "desktop" | "manual-session" | "service-account";
export type TransportMode = "stdio" | "http";

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
  scriptRunnerAllowlistManifestPaths: string[];
  opCliPath: string;
  opCliAuthMode: OpCliAuthMode;
  transport: TransportMode;
  httpHost: string;
  httpPort: number;
  httpPath: string;
  httpRequireBearer: boolean;
  httpBearerToken?: string;
  httpAllowedOrigins: string[];
  httpMaxSessions: number;
  httpSessionIdleMs: number;
  httpRequestTimeoutMs: number;
  auditLogPath: string;
  logLevel: LogLevel;
  integrationName: string;
  integrationVersion: string;
}

export class HelpError extends Error {}

const DEFAULT_AUDIT_LOG_PATH = join(
  homedir(),
  ".onepassword-mcp",
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

function parseTransportMode(value: string | undefined): TransportMode {
  if (!value) {
    return "stdio";
  }

  if (value === "stdio" || value === "http") {
    return value;
  }

  throw new Error(`Unsupported transport: ${value}`);
}

function parseHttpPort(value: string | undefined): number {
  if (!value) {
    return 17337;
  }

  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new Error(`Invalid HTTP port: ${value}`);
  }
  return port;
}

function parseHttpPath(value: string | undefined): string {
  if (!value) {
    return "/mcp";
  }
  if (!value.startsWith("/")) {
    throw new Error(`HTTP path must start with /: ${value}`);
  }
  return value;
}

function parseIntegerOption(
  name: string,
  value: string | undefined,
  fallback: number,
  min: number,
  max: number,
): number {
  if (!value) {
    return fallback;
  }

  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`Invalid ${name}: ${value}`);
  }
  return parsed;
}

function parseCommaList(value: string | undefined): string[] {
  if (!value) {
    return [];
  }

  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function isLocalHttpHost(host: string): boolean {
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
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
        "Usage: mcp-1password [options]",
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
        "  --script-runner-allowlist-manifest=<absolute manifest file> (repeatable)",
        "  --op-cli-path=<path>",
        "  --op-cli-auth-mode=auto|desktop|manual-session|service-account",
        "  --transport=stdio|http",
        "  --http-host=<host>",
        "  --http-port=<port>",
        "  --http-path=<path>",
        "  --http-require-bearer=true|false",
        "  --http-allowed-origin=<origin> (repeatable)",
        "  --http-max-sessions=<count>",
        "  --http-session-idle-ms=<milliseconds>",
        "  --http-request-timeout-ms=<milliseconds>",
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
  const scriptRunnerAllowlistManifestPaths = [
    ...readFlagValues(argv, "script-runner-allowlist-manifest"),
    ...parsePathList(
      readFlagValue(argv, "script-runner-allowlist-manifests") ??
        process.env.OP_MCP_SCRIPT_RUNNER_ALLOWLIST_MANIFESTS,
    ),
  ];
  const opCliPath = readFlagValue(argv, "op-cli-path") ?? process.env.OP_MCP_OP_CLI_PATH ?? "op";
  const opCliAuthMode = parseOpCliAuthMode(
    readFlagValue(argv, "op-cli-auth-mode") ?? process.env.OP_MCP_OP_CLI_AUTH_MODE,
  );
  const transport = parseTransportMode(
    readFlagValue(argv, "transport") ?? process.env.OP_MCP_TRANSPORT,
  );
  const httpHost =
    readFlagValue(argv, "http-host") ?? process.env.OP_MCP_HTTP_HOST ?? "127.0.0.1";
  const httpPort = parseHttpPort(
    readFlagValue(argv, "http-port") ?? process.env.OP_MCP_HTTP_PORT,
  );
  const httpPath = parseHttpPath(
    readFlagValue(argv, "http-path") ?? process.env.OP_MCP_HTTP_PATH,
  );
  const httpRequireBearer = parseBoolean(
    readFlagValue(argv, "http-require-bearer") ??
      process.env.OP_MCP_HTTP_REQUIRE_BEARER,
    transport === "http",
  );
  const httpBearerToken = process.env.OP_MCP_HTTP_BEARER_TOKEN;
  const httpAllowedOrigins = [
    ...readFlagValues(argv, "http-allowed-origin"),
    ...parseCommaList(process.env.OP_MCP_HTTP_ALLOWED_ORIGINS),
  ];
  const httpMaxSessions = parseIntegerOption(
    "HTTP max sessions",
    readFlagValue(argv, "http-max-sessions") ?? process.env.OP_MCP_HTTP_MAX_SESSIONS,
    64,
    1,
    10_000,
  );
  const httpSessionIdleMs = parseIntegerOption(
    "HTTP session idle timeout",
    readFlagValue(argv, "http-session-idle-ms") ??
      process.env.OP_MCP_HTTP_SESSION_IDLE_MS,
    15 * 60_000,
    1_000,
    24 * 60 * 60_000,
  );
  const httpRequestTimeoutMs = parseIntegerOption(
    "HTTP request timeout",
    readFlagValue(argv, "http-request-timeout-ms") ??
      process.env.OP_MCP_HTTP_REQUEST_TIMEOUT_MS,
    30_000,
    1_000,
    10 * 60_000,
  );

  if (transport === "http" && httpRequireBearer && !httpBearerToken) {
    throw new Error(
      "HTTP transport requires OP_MCP_HTTP_BEARER_TOKEN unless --http-require-bearer=false is set.",
    );
  }
  if (transport === "http" && httpRequireBearer && httpBearerToken && httpBearerToken.length < 16) {
    throw new Error("OP_MCP_HTTP_BEARER_TOKEN must be at least 16 characters long.");
  }
  if (transport === "http" && !httpRequireBearer && !isLocalHttpHost(httpHost)) {
    throw new Error(
      "Disabling HTTP bearer auth is only allowed when binding to localhost.",
    );
  }

  if (enableScriptRunner) {
    if (
      scriptRunnerAllowlistPaths.length === 0 &&
      scriptRunnerAllowlistManifestPaths.length === 0
    ) {
      throw new Error(
        "Script runner requires at least one --script-runner-allowlist or --script-runner-allowlist-manifest absolute file.",
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
    for (const manifestPath of scriptRunnerAllowlistManifestPaths) {
      if (!isAbsolute(manifestPath)) {
        throw new Error(
          `Script runner allowlist manifest path must be absolute: ${manifestPath}`,
        );
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
    scriptRunnerAllowlistManifestPaths,
    opCliPath,
    opCliAuthMode,
    transport,
    httpHost,
    httpPort,
    httpPath,
    httpRequireBearer,
    httpBearerToken,
    httpAllowedOrigins,
    httpMaxSessions,
    httpSessionIdleMs,
    httpRequestTimeoutMs,
    auditLogPath,
    logLevel: parseLogLevel(
      readFlagValue(argv, "log-level") ?? process.env.OP_MCP_LOG_LEVEL,
    ),
    integrationName: "1Password MCP",
    integrationVersion: packageVersion,
  };
}
