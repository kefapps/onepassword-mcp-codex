import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { access, readFile, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { z } from "zod";
import type { ServerConfig } from "./config.js";

export const SCRIPT_ALLOWLIST_FILENAME = ".onepassword-mcp-codex.json";
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

function hasPathSeparator(value: string): boolean {
  return value.includes("/") || value.includes("\\");
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

function isAuthenticationFailure(result: ProcessRunResult): boolean {
  if (result.exitCode === 0) {
    return false;
  }

  const output = `${result.stdout}\n${result.stderr}\n${result.errorMessage ?? ""}`;
  return output
    .split(/\r?\n/)
    .some((line) =>
      [
        /\b(?:op|1password)\b.*\bnot (?:currently )?signed in\b/i,
        /\bnot (?:currently )?signed in\b.*\b(?:op|1password)\b/i,
        /\b(?:op|1password)\b.*\bsign in\b/i,
        /\bsign in\b.*\b(?:op|1password)\b/i,
        /\brun [`'"]?op signin\b/i,
        /\bOP_SESSION(?:_[A-Z0-9_]+)?\b.*\b(?:expired|invalid)\b/i,
        /\b(?:expired|invalid)\b.*\bOP_SESSION(?:_[A-Z0-9_]+)?\b/i,
        /\b(?:op|1password)\b.*\bsession\b.*\b(?:expired|invalid)\b/i,
        /\bsession\b.*\b(?:expired|invalid)\b.*\b(?:op|1password)\b/i,
      ].some((pattern) => pattern.test(line)),
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
  }

  public redact(text: string): string {
    return redactAuthText(
      text,
      this.cachedSessionToken,
      this.config.serviceAccountToken,
    );
  }

  public async getEnvironment(): Promise<{
    mode: ResolvedOpCliAuthMode;
    env: NodeJS.ProcessEnv;
  }> {
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
      };
    }

    return {
      mode,
      env: createChildEnvironment(mode, {
        OP_ACCOUNT: this.config.account,
        OP_SESSION: await this.ensureManualSessionToken(),
      }),
    };
  }

  private async ensureDesktopValidated(): Promise<void> {
    if (this.desktopValidated) {
      return;
    }

    const result = await this.processRunner.run(
      this.config.opCliPath,
      ["whoami", "--account", this.config.account!],
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
        `op whoami failed: ${this.redact(result.stderr || result.stdout || result.errorMessage || "unknown error")}`,
      );
    }

    this.desktopValidated = true;
  }

  private async ensureManualSessionToken(): Promise<string> {
    if (this.cachedSessionToken) {
      return this.cachedSessionToken;
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
    return token;
  }
}

export class DefaultOpScriptRunner implements OpScriptRunner {
  public constructor(
    private readonly config: ServerConfig,
    private readonly sessionManager = new OpCliSessionManager(config),
    private readonly processRunner: ProcessRunner = new NodeProcessRunner(),
  ) {}

  public status(): OpSessionStatus {
    return this.sessionManager.status();
  }

  public reset(): void {
    this.sessionManager.reset();
  }

  public async list(workspaceRoot: string): Promise<ScriptAllowlist> {
    return loadScriptAllowlist(workspaceRoot, this.config.scriptRunnerRoots);
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
    await validateCommandExecutable(command.command, allowlist.workspaceRoot);

    const runOnce = async (): Promise<OpScriptRunResult> => {
      const auth = await this.sessionManager.getEnvironment();
      const result = await this.processRunner.run(command.command, command.args, {
        cwd,
        env: auth.env,
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
        refreshedAuth: false,
      };
    };

    const firstResult = await runOnce();
    if (!isAuthenticationFailure(firstResult)) {
      return firstResult;
    }
    if (firstResult.authMode !== "manual-session") {
      return firstResult;
    }

    this.sessionManager.reset();
    const refreshedResult = await runOnce();
    return {
      ...refreshedResult,
      refreshedAuth: true,
    };
  }
}

export async function loadScriptAllowlist(
  workspaceRoot: string,
  allowedRoots: string[] = [],
): Promise<ScriptAllowlist> {
  const resolvedWorkspaceRoot = await realpath(workspaceRoot);
  if (allowedRoots.length > 0) {
    const resolvedAllowedRoots = await Promise.all(
      allowedRoots.map((root) => realpath(root)),
    );
    const withinAllowedRoot = resolvedAllowedRoots.some((root) =>
      isPathInside(root, resolvedWorkspaceRoot),
    );
    if (!withinAllowedRoot) {
      throw new Error(
        `Workspace ${resolvedWorkspaceRoot} is outside the configured script runner roots.`,
      );
    }
  }
  const allowlistPath = join(resolvedWorkspaceRoot, SCRIPT_ALLOWLIST_FILENAME);
  const raw = await readFile(allowlistPath, "utf8");
  const parsed = allowlistSchema.parse(JSON.parse(raw));

  return {
    path: allowlistPath,
    workspaceRoot: resolvedWorkspaceRoot,
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

async function validateCommandExecutable(
  command: string,
  workspaceRoot: string,
): Promise<void> {
  if (!hasPathSeparator(command)) {
    return;
  }

  if (!isAbsolute(command)) {
    throw new Error(
      "Allowlisted command must be a PATH executable name or an absolute path inside the workspace.",
    );
  }

  const commandPath = await realpath(command);
  if (!isPathInside(workspaceRoot, commandPath)) {
    throw new Error(`Command ${command} resolves outside workspace ${workspaceRoot}.`);
  }

  await access(commandPath, constants.X_OK);
  const commandDirectory = await realpath(dirname(commandPath));
  if (!isPathInside(workspaceRoot, commandDirectory)) {
    throw new Error(`Command ${command} resolves outside workspace ${workspaceRoot}.`);
  }
}
