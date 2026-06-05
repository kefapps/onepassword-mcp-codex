import { constants, realpathSync } from "node:fs";
import { access, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { SCRIPT_ALLOWLIST_FILENAME } from "./op-runner.js";

export const DEFAULT_WORKSPACE_TRUST_MANIFEST_PATH = join(
  homedir(),
  ".onepassword-mcp",
  "workspace-trust.json",
);

export type WorkspaceTrustScope = "exact" | "prefix";

export interface WorkspaceTrustOptions {
  workspacePath?: string;
  manifestPath?: string;
  trustFileName?: string;
  scope?: WorkspaceTrustScope;
}

export interface WorkspaceTrustResult {
  workspaceRoot: string;
  trustFilePath: string;
  manifestPath: string;
  scope: WorkspaceTrustScope;
  trustFileCreated: boolean;
  trustFileUpdated: boolean;
  manifestCreated: boolean;
  manifestUpdated: boolean;
}

export class WorkspaceTrustHelpError extends Error {}

type JsonObject = Record<string, unknown>;

interface WorkspaceTrustFile extends JsonObject {
  version: 1;
  workspaceRoot?: string;
  workspaceRoots?: string[];
  workspaceRootPrefixes?: string[];
  allowWorkspaceCommands?: boolean;
  commands?: JsonObject;
}

interface WorkspaceTrustManifest extends JsonObject {
  version: 1;
  allowlists: string[];
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function stringifyJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readJsonFile(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

function workspaceTrustFileFromUnknown(value: unknown): WorkspaceTrustFile {
  if (!isJsonObject(value)) {
    throw new Error("Workspace trust file must contain a JSON object.");
  }
  if (value.version !== 1) {
    throw new Error("Workspace trust file must use version 1.");
  }
  if (value.commands !== undefined && !isJsonObject(value.commands)) {
    throw new Error("Workspace trust file commands must be a JSON object.");
  }
  if (
    value.workspaceRootPrefixes !== undefined &&
    (!Array.isArray(value.workspaceRootPrefixes) ||
      !value.workspaceRootPrefixes.every((entry) => typeof entry === "string"))
  ) {
    throw new Error("Workspace trust file workspaceRootPrefixes must be strings.");
  }
  if (
    value.workspaceRoots !== undefined &&
    (!Array.isArray(value.workspaceRoots) ||
      !value.workspaceRoots.every((entry) => typeof entry === "string"))
  ) {
    throw new Error("Workspace trust file workspaceRoots must be strings.");
  }

  return value as WorkspaceTrustFile;
}

function manifestFromUnknown(value: unknown): WorkspaceTrustManifest {
  if (!isJsonObject(value)) {
    throw new Error("Workspace trust manifest must contain a JSON object.");
  }
  if (value.version !== 1) {
    throw new Error("Workspace trust manifest must use version 1.");
  }
  if (
    !Array.isArray(value.allowlists) ||
    !value.allowlists.every((entry) => typeof entry === "string")
  ) {
    throw new Error("Workspace trust manifest entries must be strings.");
  }

  return value as WorkspaceTrustManifest;
}

function updatedWorkspaceTrustFile(
  existing: WorkspaceTrustFile | undefined,
  scope: WorkspaceTrustScope,
): WorkspaceTrustFile {
  const next: WorkspaceTrustFile = {
    version: 1,
    ...(existing ?? {}),
    allowWorkspaceCommands: true,
    commands: existing?.commands ?? {},
  };

  if (scope === "prefix") {
    const prefixes = next.workspaceRootPrefixes ?? [];
    next.workspaceRootPrefixes = prefixes.includes(".") ? prefixes : [...prefixes, "."];
  } else {
    const exactRoots = next.workspaceRoots ?? [];
    if (next.workspaceRoot !== undefined && next.workspaceRoot !== ".") {
      next.workspaceRoots = exactRoots.includes(next.workspaceRoot)
        ? exactRoots
        : [next.workspaceRoot, ...exactRoots];
      delete next.workspaceRoot;
    }

    if (next.workspaceRoots !== undefined) {
      next.workspaceRoots = next.workspaceRoots.includes(".")
        ? next.workspaceRoots
        : [...next.workspaceRoots, "."];
    } else if (next.workspaceRoot === undefined) {
      if (!next.workspaceRootPrefixes?.includes(".")) {
        next.workspaceRoot = ".";
      }
    } else if (next.workspaceRoot !== ".") {
      next.workspaceRoots = [next.workspaceRoot, "."];
      delete next.workspaceRoot;
    }
  }

  return next;
}

async function writeJsonIfChanged(
  path: string,
  value: unknown,
  existed: boolean,
): Promise<boolean> {
  const next = stringifyJson(value);
  if (existed) {
    const current = await readFile(path, "utf8");
    if (current === next) {
      return false;
    }
  }

  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, next, "utf8");
  return true;
}

function manifestHasTrustPath(
  manifestPath: string,
  entries: string[],
  trustFilePath: string,
): boolean {
  const manifestDir = dirname(manifestPath);
  const resolvedTrustFilePath = realpathSync(trustFilePath);
  return entries.some((entry) => {
    const resolvedEntry = isAbsolute(entry)
      ? resolve(entry)
      : resolve(manifestDir, entry);
    try {
      return realpathSync(resolvedEntry) === resolvedTrustFilePath;
    } catch {
      return resolvedEntry === trustFilePath;
    }
  });
}

export async function trustWorkspace(
  options: WorkspaceTrustOptions = {},
): Promise<WorkspaceTrustResult> {
  const scope = options.scope ?? "exact";
  const workspaceRoot = await realpath(resolve(options.workspacePath ?? process.cwd()));
  const trustFilePath = resolve(
    workspaceRoot,
    options.trustFileName ?? SCRIPT_ALLOWLIST_FILENAME,
  );
  const manifestPath = resolve(
    options.manifestPath ?? DEFAULT_WORKSPACE_TRUST_MANIFEST_PATH,
  );

  const trustFileCreated = !(await pathExists(trustFilePath));
  const existingTrust = trustFileCreated
    ? undefined
    : workspaceTrustFileFromUnknown(await readJsonFile(trustFilePath));
  const nextTrust = updatedWorkspaceTrustFile(existingTrust, scope);
  const trustFileUpdated = await writeJsonIfChanged(
    trustFilePath,
    nextTrust,
    !trustFileCreated,
  );

  const manifestCreated = !(await pathExists(manifestPath));
  const existingManifest = manifestCreated
    ? { version: 1, allowlists: [] }
    : manifestFromUnknown(await readJsonFile(manifestPath));
  const nextManifest: WorkspaceTrustManifest = {
    ...existingManifest,
    version: 1,
    allowlists: manifestHasTrustPath(
      manifestPath,
      existingManifest.allowlists,
      trustFilePath,
    )
      ? existingManifest.allowlists
      : [...existingManifest.allowlists, trustFilePath],
  };
  const manifestUpdated = await writeJsonIfChanged(
    manifestPath,
    nextManifest,
    !manifestCreated,
  );

  return {
    workspaceRoot,
    trustFilePath,
    manifestPath,
    scope,
    trustFileCreated,
    trustFileUpdated,
    manifestCreated,
    manifestUpdated,
  };
}

function readCliValue(
  args: string[],
  index: number,
  name: string,
): { value: string; nextIndex: number } {
  const current = args[index]!;
  const prefix = `--${name}=`;
  if (current.startsWith(prefix)) {
    return { value: current.slice(prefix.length), nextIndex: index };
  }
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`Missing value for --${name}.`);
  }
  return { value, nextIndex: index + 1 };
}

export function parseWorkspaceTrustArgs(
  argv: string[],
  cwd = process.cwd(),
): Required<WorkspaceTrustOptions> {
  if (argv.includes("-h") || argv.includes("--help")) {
    throw new WorkspaceTrustHelpError(workspaceTrustUsage());
  }

  let workspacePath = cwd;
  let manifestPath = DEFAULT_WORKSPACE_TRUST_MANIFEST_PATH;
  let trustFileName = SCRIPT_ALLOWLIST_FILENAME;
  let scope: WorkspaceTrustScope = "exact";
  const positional: string[] = [];

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]!;
    if (arg === "--manifest" || arg.startsWith("--manifest=")) {
      const parsed = readCliValue(argv, index, "manifest");
      manifestPath = parsed.value;
      index = parsed.nextIndex;
      continue;
    }
    if (arg === "--trust-file" || arg.startsWith("--trust-file=")) {
      const parsed = readCliValue(argv, index, "trust-file");
      trustFileName = parsed.value;
      index = parsed.nextIndex;
      continue;
    }
    if (arg === "--scope" || arg.startsWith("--scope=")) {
      const parsed = readCliValue(argv, index, "scope");
      if (parsed.value !== "exact" && parsed.value !== "prefix") {
        throw new Error("Workspace trust scope must be exact or prefix.");
      }
      scope = parsed.value;
      index = parsed.nextIndex;
      continue;
    }
    if (arg.startsWith("--")) {
      throw new Error(`Unknown trust-workspace option: ${arg}`);
    }
    positional.push(arg);
  }

  if (positional.length > 1) {
    throw new Error("trust-workspace accepts at most one workspace path.");
  }
  if (positional[0]) {
    workspacePath = positional[0];
  }

  return {
    workspacePath: resolve(cwd, workspacePath),
    manifestPath: isAbsolute(manifestPath)
      ? manifestPath
      : resolve(cwd, manifestPath),
    trustFileName,
    scope,
  };
}

export function workspaceTrustUsage(): string {
  return [
    "Usage: onepassword-mcp-cli trust-workspace [workspacePath] [options]",
    "",
    "Adds the current workspace to the Connect workspace trust manifest.",
    "Defaults: workspacePath is the current directory; manifest is ~/.onepassword-mcp/workspace-trust.json.",
    "",
    "Options:",
    "  --manifest=<path>       Workspace trust manifest to update",
    "  --trust-file=<filename>  Project trust file name (default: .onepassword-mcp.json)",
    "  --scope=exact|prefix     exact trusts this workspace and descendants; prefix also trusts sibling worktrees",
  ].join("\n");
}

export function formatWorkspaceTrustResult(result: WorkspaceTrustResult): string {
  const trustFileState = result.trustFileCreated
    ? "created"
    : result.trustFileUpdated
      ? "updated"
      : "unchanged";
  const manifestState = result.manifestCreated
    ? "created"
    : result.manifestUpdated
      ? "updated"
      : "unchanged";

  return [
    "Workspace trust ready.",
    `workspaceRoot: ${result.workspaceRoot}`,
    `trustConfigPath: ${result.trustFilePath} (${trustFileState})`,
    `workspaceTrustManifest: ${result.manifestPath} (${manifestState})`,
    `scope: ${result.scope}`,
    "",
    "Next:",
    `- Start the MCP with the workspace trust manifest configured: --script-runner-allowlist-manifest=${result.manifestPath}`,
    "- If the Connect MCP is already running with that manifest, call workspace_trust_reload.",
  ].join("\n");
}
