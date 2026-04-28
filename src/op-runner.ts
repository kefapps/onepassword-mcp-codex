import { spawn } from "node:child_process";
import { constants, readFileSync, realpathSync } from "node:fs";
import { access, realpath } from "node:fs/promises";
import { delimiter, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { z } from "zod";
import type { ServerConfig } from "./config.js";

export const SCRIPT_ALLOWLIST_FILENAME = ".onepassword-mcp.json";
export const DEFAULT_SCRIPT_TIMEOUT_MS = 600_000;
export const DEFAULT_PROCESS_TIMEOUT_MS = 30_000;
export const DEFAULT_OUTPUT_LIMIT_BYTES = 64 * 1024;
const FORCE_KILL_GRACE_MS = 1_000;

export type ResolvedOpCliAuthMode =
  | "desktop"
  | "manual-session"
  | "service-account";

export interface AllowlistedCommand {
  id: string;
  description?: string;
  command: string;
  args: string[];
  cwd: string;
  timeoutMs: number;
  sensitiveOutput: boolean;
}

export interface ScriptAllowlist {
  path: string;
  workspaceRoot: string;
  commands: AllowlistedCommand[];
}

export interface ProcessRunResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  outputTruncated: boolean;
  durationMs: number;
  errorMessage?: string;
}

export interface ProcessRunner {
  run(
    command: string,
    args: string[],
    options: {
      cwd?: string;
      env?: NodeJS.ProcessEnv;
      timeoutMs: number;
      maxOutputBytes: number;
    },
  ): Promise<ProcessRunResult>;
}

interface OpCliEnvironment {
  mode: ResolvedOpCliAuthMode;
  env: NodeJS.ProcessEnv;
  refreshedAuth: boolean;
}

export interface OpSessionStatus {
  enabled: boolean;
  authMode: ResolvedOpCliAuthMode;
  configuredAuthMode: ServerConfig["opCliAuthMode"];
  account?: string;
  opCliPath: string;
  hasCachedSession: boolean;
  desktopValidated: boolean;
}

export interface OpScriptRunResult extends ProcessRunResult {
  commandId: string;
  workspaceRoot: string;
  cwd: string;
  command: string;
  args: string[];
  sensitiveOutput: boolean;
  authMode: ResolvedOpCliAuthMode;
  refreshedAuth: boolean;
}

export interface OpScriptRunner {
  list(workspaceRoot: string): Promise<ScriptAllowlist>;
  run(workspaceRoot: string, commandId: string): Promise<OpScriptRunResult>;
  status(): OpSessionStatus;
  reset(): void;
}

const commandSchema = z.object({
  description: z.string().min(1).optional(),
  command: z.string().min(1),
  args: z.array(z.string()).optional(),
  cwd: z.string().min(1).optional(),
  timeoutMs: z.number().int().positive().max(3_600_000).optional(),
  sensitiveOutput: z.boolean().optional(),
});

const allowlistSchema = z.object({
  version: z.literal(1),
  workspaceRoot: z.string().min(1).optional(),
  workspaceRoots: z.array(z.string().min(1)).optional(),
  commands: z.record(commandSchema),
});

const BASE_CHILD_ENV_KEYS = [
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "TMPDIR",
  "TEMP",
  "TMP",
] as const;

function isPathInside(parentPath: string, childPath: string): boolean {
  const pathRelative = relative(parentPath, childPath);
  return (
    pathRelative === "" ||
    (!pathRelative.startsWith(`..${sep}`) &&
      pathRelative !== ".." &&
      !isAbsolute(pathRelative))
  );
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function redactExactValue(text: string, value: string | undefined): string {
  if (!value) {
    return text;
  }
  return text.replace(new RegExp(escapeRegExp(value), "g"), "[REDACTED]");
}

function redactAuthText(text: string, sessionToken?: string, serviceToken?: string): string {
  return redactExactValue(redactExactValue(text, sessionToken), serviceToken)
    .replace(/OP_SESSION(?:_[A-Z0-9_]+)?=[^\s"']+/gi, "OP_SESSION=[REDACTED]")
    .replace(/OP_SERVICE_ACCOUNT_TOKEN=[^\s"']+/gi, "OP_SERVICE_ACCOUNT_TOKEN=[REDACTED]");
}

function appendOutput(
  chunks: Buffer[],
  sharedState: { length: number; truncated: boolean },
  data: Buffer,
  maxBytes: number,
): void {
  if (sharedState.length >= maxBytes) {
    sharedState.truncated = true;
    return;
  }

  const remaining = maxBytes - sharedState.length;
  if (data.length > remaining) {
    chunks.push(data.subarray(0, remaining));
    sharedState.length += remaining;
    sharedState.truncated = true;
    return;
  }

  chunks.push(data);
  sharedState.length += data.length;
}

function resolveAuthMode(config: ServerConfig): ResolvedOpCliAuthMode {
  if (config.opCliAuthMode === "auto") {
    return config.authMode === "service-account" ? "service-account" : "manual-session";
  }

  return config.opCliAuthMode;
}

function isDeterministicOpAuthFailure(result: ProcessRunResult): boolean {
  if (result.exitCode === 0) {
    return false;
  }

  const output = `${result.stdout}\n${result.stderr}\n${result.errorMessage ?? ""}`;
  return output
    .split(/\r?\n/)
    .some((line) =>
      [
        /\bnot (?:currently )?signed in\b/i,
        /\brun [`'"]?op signin\b/i,
        /\bOP_SESSION(?:_[A-Z0-9_]+)?\b.*\b(?:expired|invalid)\b/i,
        /\b(?:expired|invalid)\b.*\bOP_SESSION(?:_[A-Z0-9_]+)?\b/i,
        /\bsession\b.*\b(?:expired|invalid)\b/i,
        /\b(?:expired|invalid)\b.*\bsession\b/i,
      ].some((pattern) => pattern.test(line)),
    );
}

function processFailureDetails(result: ProcessRunResult): string {
  return (
    result.stderr ||
    result.stdout ||
    result.errorMessage ||
    `exitCode=${result.exitCode ?? "unknown"} signal=${result.signal ?? "none"} timedOut=${result.timedOut}`
  );
}

function forceKillGraceMs(timeoutMs: number): number {
  return Math.min(FORCE_KILL_GRACE_MS, Math.max(50, Math.floor(timeoutMs / 2)));
}

function createChildEnvironment(
  authMode: ResolvedOpCliAuthMode,
  env: Record<string, string>,
): NodeJS.ProcessEnv {
  const childEnv: NodeJS.ProcessEnv = {};
  for (const key of BASE_CHILD_ENV_KEYS) {
    if (process.env[key]) {
      childEnv[key] = process.env[key];
    }
  }
  for (const [key, value] of Object.entries(process.env)) {
    if ((key === "LANG" || key.startsWith("LC_")) && value) {
      childEnv[key] = value;
    }
  }

  return {
    ...childEnv,
    ...env,
  };
}

function prependPathEntries(
  env: NodeJS.ProcessEnv,
  entries: string[],
): NodeJS.ProcessEnv {
  const normalizedEntries = entries.filter(Boolean);
  const pathEntries =
    env.PATH
      ?.split(delimiter)
      .filter((entry) => entry && !normalizedEntries.includes(entry)) ?? [];

  for (const entry of normalizedEntries.slice().reverse()) {
    if (pathEntries.includes(entry)) {
      continue;
    }
    pathEntries.unshift(entry);
  }

  return {
    ...env,
    PATH: pathEntries.join(delimiter),
  };
}

function createScriptEnvironment(
  env: NodeJS.ProcessEnv,
  commandPath: string,
  opCliPath: string,
): NodeJS.ProcessEnv {
  return prependPathEntries(env, [
    dirname(commandPath),
    ...(isAbsolute(opCliPath) ? [dirname(opCliPath)] : []),
  ]);
}

export class NodeProcessRunner implements ProcessRunner {
  public run(
    command: string,
    args: string[],
    options: {
      cwd?: string;
      env?: NodeJS.ProcessEnv;
      timeoutMs: number;
      maxOutputBytes: number;
    },
  ): Promise<ProcessRunResult> {
    const startedAt = Date.now();

    return new Promise((resolveResult) => {
      let settled = false;
      let timedOut = false;
      let outputTruncated = false;
      let forceKillTimeout: NodeJS.Timeout | undefined;
      let forceSettleTimeout: NodeJS.Timeout | undefined;
      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];
      const outputState = { length: 0, truncated: false };
      const child = spawn(command, args, {
        cwd: options.cwd,
        env: options.env,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      });

      const timeout = setTimeout(() => {
        timedOut = true;
        child.kill("SIGTERM");
        forceKillTimeout = setTimeout(() => {
          if (settled) {
            return;
          }
          child.kill("SIGKILL");
          forceSettleTimeout = setTimeout(() => {
            settle({
              exitCode: null,
              signal: "SIGKILL",
              errorMessage: "Process timed out and did not close after SIGKILL.",
            });
          }, forceKillGraceMs(options.timeoutMs));
        }, forceKillGraceMs(options.timeoutMs));
      }, options.timeoutMs);

      const settle = (
        result: Pick<ProcessRunResult, "exitCode" | "signal"> & {
          errorMessage?: string;
        },
      ) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timeout);
        if (forceKillTimeout) {
          clearTimeout(forceKillTimeout);
        }
        if (forceSettleTimeout) {
          clearTimeout(forceSettleTimeout);
        }
        outputTruncated = outputTruncated || outputState.truncated;
        resolveResult({
          stdout: Buffer.concat(stdoutChunks).toString("utf8"),
          stderr: Buffer.concat(stderrChunks).toString("utf8"),
          exitCode: result.exitCode,
          signal: result.signal,
          timedOut,
          outputTruncated,
          durationMs: Date.now() - startedAt,
          errorMessage: result.errorMessage,
        });
      };

      child.stdout?.on("data", (data: Buffer) => {
        appendOutput(stdoutChunks, outputState, data, options.maxOutputBytes);
      });
      child.stderr?.on("data", (data: Buffer) => {
        appendOutput(stderrChunks, outputState, data, options.maxOutputBytes);
      });
      child.once("error", (error) => {
        settle({
          exitCode: 127,
          signal: null,
          errorMessage: error.message,
        });
      });
      child.once("close", (exitCode, signal) => {
        settle({ exitCode, signal });
      });
    });
  }
}

export class OpCliSessionManager {
  private cachedSessionToken?: string;
  private desktopValidated = false;
  private manualSessionTokenPromise?: Promise<{
    token: string;
    refreshedAuth: boolean;
  }>;

  public constructor(
    private readonly config: ServerConfig,
    private readonly processRunner: ProcessRunner = new NodeProcessRunner(),
  ) {}

  public get resolvedAuthMode(): ResolvedOpCliAuthMode {
    return resolveAuthMode(this.config);
  }

  public status(): OpSessionStatus {
    return {
      enabled: this.config.enableScriptRunner,
      authMode: this.resolvedAuthMode,
      configuredAuthMode: this.config.opCliAuthMode,
      account: this.config.account,
      opCliPath: this.config.opCliPath,
      hasCachedSession: Boolean(this.cachedSessionToken),
      desktopValidated: this.desktopValidated,
    };
  }

  public reset(): void {
    this.cachedSessionToken = undefined;
    this.desktopValidated = false;
    this.manualSessionTokenPromise = undefined;
  }

  public redact(text: string): string {
    return redactAuthText(
      text,
      this.cachedSessionToken,
      this.config.serviceAccountToken,
    );
  }

  public async getEnvironment(): Promise<OpCliEnvironment> {
    const mode = this.resolvedAuthMode;

    if (mode === "service-account") {
      if (!this.config.serviceAccountToken) {
        throw new Error(
          "op CLI service-account mode requires --service-account-token or OP_SERVICE_ACCOUNT_TOKEN.",
        );
      }
      return {
        mode,
        env: createChildEnvironment(mode, {
          OP_SERVICE_ACCOUNT_TOKEN: this.config.serviceAccountToken,
          ...(this.config.account ? { OP_ACCOUNT: this.config.account } : {}),
        }),
        refreshedAuth: false,
      };
    }

    if (!this.config.account) {
      throw new Error("op CLI auth requires --account or OP_MCP_ACCOUNT.");
    }

    if (mode === "desktop") {
      await this.ensureDesktopValidated();
      return {
        mode,
        env: createChildEnvironment(mode, {
          OP_ACCOUNT: this.config.account,
        }),
        refreshedAuth: false,
      };
    }

    const session = await this.ensureManualSessionTokenLocked();
    return {
      mode,
      env: createChildEnvironment(mode, {
        OP_ACCOUNT: this.config.account,
        OP_SESSION: session.token,
      }),
      refreshedAuth: session.refreshedAuth,
    };
  }

  public async isCurrentManualSessionInvalid(): Promise<boolean> {
    if (this.resolvedAuthMode !== "manual-session") {
      return false;
    }
    if (!this.config.account || !this.cachedSessionToken) {
      return true;
    }

    const result = await this.processRunner.run(
      this.config.opCliPath,
      ["whoami", "--account", this.config.account],
      {
        env: createChildEnvironment("manual-session", {
          OP_ACCOUNT: this.config.account,
          OP_SESSION: this.cachedSessionToken,
        }),
        timeoutMs: DEFAULT_PROCESS_TIMEOUT_MS,
        maxOutputBytes: DEFAULT_OUTPUT_LIMIT_BYTES,
      },
    );

    return isDeterministicOpAuthFailure(result);
  }

  private async ensureDesktopValidated(): Promise<void> {
    if (this.desktopValidated) {
      return;
    }

    const result = await this.processRunner.run(
      this.config.opCliPath,
      ["account", "get", "--account", this.config.account!, "--format", "json"],
      {
        env: createChildEnvironment("desktop", {
          OP_ACCOUNT: this.config.account!,
        }),
        timeoutMs: DEFAULT_PROCESS_TIMEOUT_MS,
        maxOutputBytes: DEFAULT_OUTPUT_LIMIT_BYTES,
      },
    );

    if (result.exitCode !== 0) {
      throw new Error(
        `op account get failed: ${this.redact(processFailureDetails(result))}`,
      );
    }

    this.desktopValidated = true;
  }

  private async ensureManualSessionToken(): Promise<{
    token: string;
    refreshedAuth: boolean;
  }> {
    const hadCachedSession = Boolean(this.cachedSessionToken);
    if (this.cachedSessionToken) {
      if (!(await this.isCurrentManualSessionInvalid())) {
        return { token: this.cachedSessionToken, refreshedAuth: false };
      }
      this.cachedSessionToken = undefined;
    }

    const result = await this.processRunner.run(
      this.config.opCliPath,
      ["signin", "--account", this.config.account!, "--raw"],
      {
        env: createChildEnvironment("manual-session", {
          OP_ACCOUNT: this.config.account!,
        }),
        timeoutMs: DEFAULT_PROCESS_TIMEOUT_MS,
        maxOutputBytes: DEFAULT_OUTPUT_LIMIT_BYTES,
      },
    );

    const token = result.stdout.trim();
    if (result.exitCode !== 0 || !token) {
      throw new Error(
        `op signin --raw failed: ${this.redact(result.stderr || result.stdout || result.errorMessage || "unknown error")}`,
      );
    }

    this.cachedSessionToken = token;
    return { token, refreshedAuth: hadCachedSession };
  }

  private async ensureManualSessionTokenLocked(): Promise<{
    token: string;
    refreshedAuth: boolean;
  }> {
    if (!this.manualSessionTokenPromise) {
      this.manualSessionTokenPromise = this.ensureManualSessionToken().finally(() => {
        this.manualSessionTokenPromise = undefined;
      });
    }
    return this.manualSessionTokenPromise;
  }
}

export class DefaultOpScriptRunner implements OpScriptRunner {
  private readonly allowlistsByWorkspaceRoot: ScriptAllowlist[];

  public constructor(
    private readonly config: ServerConfig,
    private readonly sessionManager = new OpCliSessionManager(config),
    private readonly processRunner: ProcessRunner = new NodeProcessRunner(),
  ) {
    this.allowlistsByWorkspaceRoot = (config.enableScriptRunner ? loadConfiguredScriptAllowlists(config) : []).sort(
      (left, right) => right.workspaceRoot.length - left.workspaceRoot.length,
    );
  }

  public status(): OpSessionStatus {
    return this.sessionManager.status();
  }

  public reset(): void {
    this.sessionManager.reset();
  }

  public async list(workspaceRoot: string): Promise<ScriptAllowlist> {
    const resolvedWorkspaceRoot = await realpath(workspaceRoot);
    const allowlist = this.allowlistsByWorkspaceRoot.find((candidate) =>
      isPathInside(candidate.workspaceRoot, resolvedWorkspaceRoot),
    );
    if (!allowlist) {
      throw new Error(
        `Workspace ${resolvedWorkspaceRoot} does not have a startup-configured script allowlist.`,
      );
    }

    return allowlist;
  }

  public async run(
    workspaceRoot: string,
    commandId: string,
  ): Promise<OpScriptRunResult> {
    const allowlist = await this.list(workspaceRoot);
    const command = allowlist.commands.find((candidate) => candidate.id === commandId);
    if (!command) {
      throw new Error(`Allowlisted command ${commandId} not found.`);
    }

    const cwd = await resolveWorkspacePath(allowlist.workspaceRoot, command.cwd);
    await validateCommandExecutable(command.command);

    const auth = await this.sessionManager.getEnvironment();
    const result = await this.processRunner.run(command.command, command.args, {
      cwd,
      env: createScriptEnvironment(auth.env, command.command, this.config.opCliPath),
      timeoutMs: command.timeoutMs,
      maxOutputBytes: DEFAULT_OUTPUT_LIMIT_BYTES,
    });

    return {
      ...result,
      stdout: this.sessionManager.redact(result.stdout),
      stderr: this.sessionManager.redact(result.stderr),
      errorMessage: result.errorMessage
        ? this.sessionManager.redact(result.errorMessage)
        : undefined,
      commandId,
      workspaceRoot: allowlist.workspaceRoot,
      cwd,
      command: command.command,
      args: command.args,
      sensitiveOutput: command.sensitiveOutput,
      authMode: auth.mode,
      refreshedAuth: auth.refreshedAuth,
    };
  }
}

function resolveWorkspaceRootsFromParsed(
  allowlistPath: string,
  parsed: z.infer<typeof allowlistSchema>,
): string[] {
  const entries = parsed.workspaceRoots?.length
    ? parsed.workspaceRoots
    : parsed.workspaceRoot
      ? [parsed.workspaceRoot]
      : ["."];

  const base = dirname(allowlistPath);
  return entries.map((root) => realpathSync(resolve(base, root)));
}

function scriptAllowlistFromParsed(
  allowlistPath: string,
  workspaceRoot: string,
  parsed: z.infer<typeof allowlistSchema>,
): ScriptAllowlist {
  return {
    path: allowlistPath,
    workspaceRoot,
    commands: Object.entries(parsed.commands).map(([id, command]) => ({
      id,
      description: command.description,
      command: command.command,
      args: command.args ?? [],
      cwd: command.cwd ?? ".",
      timeoutMs: command.timeoutMs ?? DEFAULT_SCRIPT_TIMEOUT_MS,
      sensitiveOutput: command.sensitiveOutput ?? false,
    })),
  };
}

function assertWorkspaceRootAllowed(
  workspaceRoot: string,
  allowedRoots: string[],
): void {
  const withinAllowedRoot = allowedRoots.some((root) =>
    isPathInside(root, workspaceRoot),
  );
  if (!withinAllowedRoot) {
    throw new Error(
      `Workspace ${workspaceRoot} is outside the configured script runner roots.`,
    );
  }
}

export function loadConfiguredScriptAllowlists(
  config: Pick<ServerConfig, "scriptRunnerAllowlistPaths" | "scriptRunnerRoots">,
): ScriptAllowlist[] {
  const resolvedAllowedRoots = config.scriptRunnerRoots.map((root) =>
    realpathSync(root),
  );

  return config.scriptRunnerAllowlistPaths.flatMap((allowlistPath) => {
    const resolvedAllowlistPath = realpathSync(allowlistPath);
    const raw = readFileSync(resolvedAllowlistPath, "utf8");
    const parsed = allowlistSchema.parse(JSON.parse(raw));
    const workspaceRoots = resolveWorkspaceRootsFromParsed(
      resolvedAllowlistPath,
      parsed,
    );

    return workspaceRoots.flatMap((workspaceRoot) => {
      if (resolvedAllowedRoots.length > 0) {
        assertWorkspaceRootAllowed(workspaceRoot, resolvedAllowedRoots);
      }

      return [scriptAllowlistFromParsed(resolvedAllowlistPath, workspaceRoot, parsed)];
    });
  });
}

async function resolveWorkspacePath(
  workspaceRoot: string,
  candidatePath: string,
): Promise<string> {
  const resolved = await realpath(resolve(workspaceRoot, candidatePath));
  if (!isPathInside(workspaceRoot, resolved)) {
    throw new Error(`Path ${candidatePath} resolves outside workspace ${workspaceRoot}.`);
  }
  return resolved;
}

async function validateCommandExecutable(command: string): Promise<void> {
  if (!isAbsolute(command)) {
    throw new Error(
      "Allowlisted command must be an absolute executable path.",
    );
  }

  await access(await realpath(command), constants.X_OK);
}
