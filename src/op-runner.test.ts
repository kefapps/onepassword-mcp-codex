import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, realpath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import type { ServerConfig } from "./config.js";
import {
  DEFAULT_OUTPUT_LIMIT_BYTES,
  DefaultOpScriptRunner,
  NodeProcessRunner,
  OpCliSessionManager,
  SCRIPT_ALLOWLIST_FILENAME,
  loadConfiguredScriptAllowlists,
  type ProcessRunResult,
  type ProcessRunner,
} from "./op-runner.js";

const TEST_COMMAND = process.execPath;

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function createConfig(overrides: Partial<ServerConfig> = {}): ServerConfig {
  return {
    authMode: "desktop",
    account: "TestAccount",
    enableSecretReveal: false,
    enableWrites: false,
    enableDestructiveActions: false,
    enablePermissionMutation: false,
    enableScriptRunner: true,
    enableUnrestrictedScriptRunner: false,
    scriptRunnerRoots: [],
    scriptRunnerAllowlistPaths: [],
    scriptRunnerAllowlistManifestPaths: [],
    enableUnrestrictedRunner: false,
    unrestrictedRunnerRoots: [],
    unrestrictedRunnerRequireSessionApproval: true,
    unrestrictedRunnerApprovalHost: "127.0.0.1",
    unrestrictedRunnerApprovalPort: 0,
    unrestrictedRunnerApprovalTtlMs: 12 * 60 * 60_000,
    unrestrictedRunnerCommandTimeoutMs: 600_000,
    approvalRememberStorePath: "/tmp/onepassword-mcp-test-approvals.enc.json",
    approvalRememberKeyPath: "/tmp/onepassword-mcp-test-approvals.key",
    approvalRememberTtlMs: 24 * 60 * 60_000,
    opCliPath: "op",
    opCliAuthMode: "auto",
    transport: "stdio",
    httpHost: "127.0.0.1",
    httpPort: 17337,
    httpPath: "/mcp",
    httpRequireBearer: false,
    httpAllowedOrigins: [],
    httpMaxSessions: 64,
    httpSessionIdleMs: 15 * 60_000,
    httpRequestTimeoutMs: 30_000,
    auditLogPath: "/tmp/onepassword-mcp-test-audit.jsonl",
    enableDiagnostics: false,
    logLevel: "info",
    integrationName: "Test",
    integrationVersion: "0.1.0",
    ...overrides,
  };
}

async function createWorkspace(allowlist: unknown): Promise<string> {
  const workspace = await mkdtemp(join(tmpdir(), "op-runner-test-"));
  await writeAllowlist(workspace, allowlist);
  return workspace;
}

async function writeAllowlist(workspace: string, allowlist: unknown): Promise<void> {
  await writeFile(
    join(workspace, SCRIPT_ALLOWLIST_FILENAME),
    JSON.stringify(allowlist, null, 2),
    "utf8",
  );
}

function allowlistPath(workspace: string): string {
  return join(workspace, SCRIPT_ALLOWLIST_FILENAME);
}

async function createWorkspaceUnder(
  parent: string,
  name: string,
  allowlist: unknown,
): Promise<string> {
  const workspace = join(parent, name);
  await mkdir(workspace, { recursive: true });
  await writeAllowlist(workspace, allowlist);
  return workspace;
}

function createScriptRunnerConfig(
  workspace: string,
  overrides: Partial<ServerConfig> = {},
): ServerConfig {
  return createConfig({
    scriptRunnerRoots: [workspace],
    scriptRunnerAllowlistPaths: [allowlistPath(workspace)],
    ...overrides,
  });
}

class FakeProcessRunner implements ProcessRunner {
  public readonly calls: Array<{
    command: string;
    args: string[];
    cwd?: string;
    env?: NodeJS.ProcessEnv;
  }> = [];

  public constructor(private readonly results: ProcessRunResult[]) {}

  public async run(
    command: string,
    args: string[],
    options: {
      cwd?: string;
      env?: NodeJS.ProcessEnv;
      timeoutMs: number;
      maxOutputBytes: number;
    },
  ): Promise<ProcessRunResult> {
    this.calls.push({
      command,
      args,
      cwd: options.cwd,
      env: options.env,
    });

    const result = this.results.shift();
    if (!result) {
      throw new Error("No fake process result queued.");
    }
    return result;
  }
}

function processResult(overrides: Partial<ProcessRunResult> = {}): ProcessRunResult {
  return {
    stdout: "",
    stderr: "",
    exitCode: 0,
    signal: null,
    timedOut: false,
    outputTruncated: false,
    durationMs: 1,
    ...overrides,
  };
}

test("loadConfiguredScriptAllowlists parses command defaults", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
        args: ["run", "deploy"],
      },
    },
  });

  const allowlist = loadConfiguredScriptAllowlists(
    createScriptRunnerConfig(workspace),
  )[0]!;

  assert.equal(allowlist.commands[0]?.id, "deploy");
  assert.equal(allowlist.commands[0]?.cwd, ".");
  assert.equal(allowlist.commands[0]?.sensitiveOutput, false);
  assert.deepEqual(allowlist.commands[0]?.args, ["run", "deploy"]);
});

test("loadConfiguredScriptAllowlists supports multiple workspaceRoots in one allowlist", async () => {
  const workspace = await createWorkspace({
    version: 1,
    workspaceRoots: [".", "extra"],
    commands: {
      deploy: {
        command: TEST_COMMAND,
        args: ["run", "deploy"],
      },
    },
  });

  await mkdir(`${workspace}/extra`, { recursive: true });

  const allowlists = loadConfiguredScriptAllowlists(
    createScriptRunnerConfig(workspace, {
      scriptRunnerRoots: [workspace],
    }),
  );

  assert.equal(allowlists.length, 2);
  assert.equal(allowlists[0]?.commands[0]?.id, "deploy");
  assert.equal(allowlists[1]?.commands[0]?.id, "deploy");
});

test("DefaultOpScriptRunner matches allowlist for sibling workspace root prefixes", async () => {
  const workspace = await createWorkspace({
    version: 1,
    workspaceRootPrefixes: ["."],
    commands: {
      deploy: {
        command: TEST_COMMAND,
      },
    },
  });
  const siblingWorkspace = `${workspace}-branch`;
  const unrelatedWorkspace = `${workspace}branch`;
  await mkdir(siblingWorkspace, { recursive: true });
  await mkdir(unrelatedWorkspace, { recursive: true });

  const processRunner = new FakeProcessRunner([
    processResult({ stdout: "{}\n" }),
    processResult({ stdout: "ok\n" }),
  ]);
  const config = createScriptRunnerConfig(workspace);
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  const allowlist = await runner.list(siblingWorkspace);
  const result = await runner.run(siblingWorkspace, "deploy");
  const resolvedWorkspace = await realpath(workspace);
  const resolvedSiblingWorkspace = await realpath(siblingWorkspace);
  const commandCall = processRunner.calls.find((call) => call.command === TEST_COMMAND);

  assert.equal(allowlist.workspaceRoot, resolvedWorkspace);
  assert.equal(allowlist.workspaceRootMatch, "prefix");
  assert.equal(result.workspaceRoot, resolvedSiblingWorkspace);
  assert.equal(commandCall?.cwd, resolvedSiblingWorkspace);
  await assert.rejects(
    () => runner.list(unrelatedWorkspace),
    /does not have a startup-configured script allowlist/,
  );
});

test("loadConfiguredScriptAllowlists resolves allowlists from startup manifests", async () => {
  const trustedRoot = await mkdtemp(join(tmpdir(), "op-runner-manifest-root-"));
  const workspaceA = await createWorkspaceUnder(trustedRoot, "project-a", {
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
      },
    },
  });
  const workspaceB = await createWorkspaceUnder(trustedRoot, "project-b", {
    version: 1,
    commands: {
      migrate: {
        command: TEST_COMMAND,
      },
    },
  });
  const manifestPath = join(trustedRoot, "allowlists.json");
  await writeFile(
    manifestPath,
    JSON.stringify({
      version: 1,
      allowlists: [
        "project-a/.onepassword-mcp.json",
        allowlistPath(workspaceB),
      ],
    }),
    "utf8",
  );

  const allowlists = loadConfiguredScriptAllowlists(
    createConfig({
      scriptRunnerRoots: [trustedRoot],
      scriptRunnerAllowlistPaths: [],
      scriptRunnerAllowlistManifestPaths: [manifestPath],
    }),
  );
  const workspaceAAllowlistPath = await realpath(allowlistPath(workspaceA));
  const workspaceBAllowlistPath = await realpath(allowlistPath(workspaceB));

  assert.equal(allowlists.length, 2);
  assert.equal(allowlists[0]?.path, workspaceAAllowlistPath);
  assert.equal(allowlists[0]?.commands[0]?.id, "deploy");
  assert.equal(allowlists[1]?.path, workspaceBAllowlistPath);
  assert.equal(allowlists[1]?.commands[0]?.id, "migrate");
});

test("loadConfiguredScriptAllowlists applies trusted roots to manifest entries", async () => {
  const trustedRoot = await mkdtemp(join(tmpdir(), "op-runner-trusted-root-"));
  const outsideWorkspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
      },
    },
  });
  const manifestPath = join(trustedRoot, "allowlists.json");
  await writeFile(
    manifestPath,
    JSON.stringify({
      version: 1,
      allowlists: [allowlistPath(outsideWorkspace)],
    }),
    "utf8",
  );

  assert.throws(
    () =>
      loadConfiguredScriptAllowlists(
        createConfig({
          scriptRunnerRoots: [trustedRoot],
          scriptRunnerAllowlistPaths: [],
          scriptRunnerAllowlistManifestPaths: [manifestPath],
        }),
      ),
    /outside the configured script runner roots/,
  );
});

test("DefaultOpScriptRunner rejects cwd outside workspace", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      escape: {
        command: TEST_COMMAND,
        cwd: "..",
      },
    },
  });
  const processRunner = new FakeProcessRunner([]);
  const config = createScriptRunnerConfig(workspace);
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  await assert.rejects(
    () => runner.run(workspace, "escape"),
    /resolves outside workspace/,
  );
});

test("DefaultOpScriptRunner rejects relative command paths", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      relative: {
        command: "./script.sh",
      },
    },
  });
  const processRunner = new FakeProcessRunner([]);
  const config = createScriptRunnerConfig(workspace);
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  await assert.rejects(
    () => runner.run(workspace, "relative"),
    /absolute executable path/,
  );
});

test("DefaultOpScriptRunner rejects workspace outside configured roots", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
      },
    },
  });
  const trustedRoot = await mkdtemp(join(tmpdir(), "op-runner-trusted-"));
  const processRunner = new FakeProcessRunner([]);
  const config = createConfig({
    scriptRunnerRoots: [trustedRoot],
    scriptRunnerAllowlistPaths: [allowlistPath(workspace)],
  });

  assert.throws(
    () =>
      new DefaultOpScriptRunner(
        config,
        new OpCliSessionManager(config, processRunner),
        processRunner,
      ),
    /outside the configured script runner roots/,
  );
});

test("DefaultOpScriptRunner only observes allowlist edits after reload", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
      },
    },
  });
  const config = createScriptRunnerConfig(workspace);
  const processRunner = new FakeProcessRunner([processResult()]);
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  const initialAllowlist = await runner.list(workspace);
  assert.equal(initialAllowlist.commands[0]?.id, "deploy");

  await writeFile(
    allowlistPath(workspace),
    JSON.stringify({
      version: 1,
      commands: {
        injected: {
          command: TEST_COMMAND,
        },
      },
    }),
    "utf8",
  );

  await assert.rejects(() => runner.run(workspace, "injected"), /not found/);

  const reload = runner.reload();
  const reloadedAllowlist = await runner.list(workspace);

  assert.equal(reload.previousAllowlistCount, 1);
  assert.equal(reload.allowlistCount, 1);
  assert.equal(reload.commandCount, 1);
  assert.equal(reloadedAllowlist.commands[0]?.id, "injected");
  await assert.rejects(() => runner.run(workspace, "deploy"), /not found/);
});

test("DefaultOpScriptRunner discovers new manifest allowlist entries after reload", async () => {
  const trustedRoot = await mkdtemp(join(tmpdir(), "op-runner-manifest-root-"));
  const workspaceA = await createWorkspaceUnder(trustedRoot, "project-a", {
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
      },
    },
  });
  const workspaceB = await createWorkspaceUnder(trustedRoot, "project-b", {
    version: 1,
    commands: {
      test: {
        command: TEST_COMMAND,
      },
    },
  });
  const manifestPath = join(trustedRoot, "allowlists.json");
  await writeFile(
    manifestPath,
    JSON.stringify({
      version: 1,
      allowlists: [allowlistPath(workspaceA)],
    }),
    "utf8",
  );
  const config = createConfig({
    scriptRunnerRoots: [trustedRoot],
    scriptRunnerAllowlistPaths: [],
    scriptRunnerAllowlistManifestPaths: [manifestPath],
  });
  const processRunner = new FakeProcessRunner([]);
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  await assert.rejects(() => runner.list(workspaceB), /startup-configured/);

  await writeFile(
    manifestPath,
    JSON.stringify({
      version: 1,
      allowlists: [allowlistPath(workspaceA), allowlistPath(workspaceB)],
    }),
    "utf8",
  );

  const reload = runner.reload();
  const allowlist = await runner.list(workspaceB);

  assert.equal(reload.previousAllowlistCount, 1);
  assert.equal(reload.allowlistCount, 2);
  assert.equal(reload.commandCount, 2);
  assert.equal(allowlist.commands[0]?.id, "test");
});

test("DefaultOpScriptRunner keeps active allowlists when reload fails", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
      },
    },
  });
  const config = createScriptRunnerConfig(workspace);
  const processRunner = new FakeProcessRunner([]);
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  await writeFile(
    allowlistPath(workspace),
    JSON.stringify({
      version: 1,
      workspaceRoot: "..",
      commands: {
        injected: {
          command: TEST_COMMAND,
        },
      },
    }),
    "utf8",
  );

  assert.throws(
    () => runner.reload(),
    /outside the configured script runner roots/,
  );

  const allowlist = await runner.list(workspace);
  assert.equal(allowlist.commands[0]?.id, "deploy");
});

test("DefaultOpScriptRunner matches allowlist for nested workspace roots", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
      },
    },
  });
  const nestedWorkspace = `${workspace}/subdir`;
  await mkdir(nestedWorkspace, { recursive: true });

  const processRunner = new FakeProcessRunner([
    processResult({ stdout: "{}\n" }),
    processResult({ stdout: "ok\n" }),
  ]);
  const config = createScriptRunnerConfig(workspace);
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  const allowlist = await runner.list(nestedWorkspace);
  const result = await runner.run(nestedWorkspace, "deploy");
  const resolvedWorkspace = await realpath(workspace);
  const resolvedNestedWorkspace = await realpath(nestedWorkspace);
  const commandCall = processRunner.calls.find((call) => call.command === TEST_COMMAND);

  assert.equal(allowlist.workspaceRoot, resolvedWorkspace);
  assert.equal(result.workspaceRoot, resolvedNestedWorkspace);
  assert.equal(commandCall?.cwd, resolvedNestedWorkspace);
});

test("desktop auth validates the configured account and injects OP_ACCOUNT", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
        args: ["run", "deploy"],
      },
    },
  });
  const processRunner = new FakeProcessRunner([
    processResult({ stdout: "{}\n" }),
    processResult({ stdout: "ok\n" }),
  ]);
  const config = createScriptRunnerConfig(workspace, {
    opCliAuthMode: "desktop",
  });
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  const result = await runner.run(workspace, "deploy");
  const accountCall = processRunner.calls[0];
  const commandCall = processRunner.calls.find(
    (call) => call.command === TEST_COMMAND,
  );

  assert.deepEqual(accountCall?.args, [
    "account",
    "get",
    "--account",
    "TestAccount",
    "--format",
    "json",
  ]);
  assert.equal(result.authMode, "desktop");
  assert.equal(result.stdout, "ok\n");
  assert.equal(commandCall?.env?.OP_ACCOUNT, "TestAccount");
  assert.equal(commandCall?.env?.OP_SESSION, undefined);
});

test("script runner injects extra env and redacts supplied secret values", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
        args: ["run", "deploy"],
      },
    },
  });
  const processRunner = new FakeProcessRunner([
    processResult({ stdout: "{}\n" }),
    processResult({
      stdout: "ok db-secret\n",
      stderr: "warn db-secret\n",
      errorMessage: "failed db-secret",
    }),
  ]);
  const config = createScriptRunnerConfig(workspace, {
    opCliAuthMode: "desktop",
  });
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  const result = await runner.run(workspace, "deploy", {
    extraEnv: {
      SUPABASE_DB_PASSWORD: "db-secret",
    },
    secretRedactionValues: ["db-secret"],
  });
  const commandCall = processRunner.calls.find(
    (call) => call.command === TEST_COMMAND,
  );

  assert.equal(commandCall?.env?.SUPABASE_DB_PASSWORD, "db-secret");
  assert.equal(result.stdout, "ok [REDACTED]\n");
  assert.equal(result.stderr, "warn [REDACTED]\n");
  assert.equal(result.errorMessage, "failed [REDACTED]");
});

test("script run PATH includes configured op directory without command directory prepend", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
        args: ["run", "deploy"],
      },
    },
  });
  const processRunner = new FakeProcessRunner([
    processResult({ stdout: "{}\n" }),
    processResult({ stdout: "ok\n" }),
  ]);
  const config = createScriptRunnerConfig(workspace, {
    opCliAuthMode: "desktop",
    opCliPath: "/opt/homebrew/bin/op",
  });
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  await runner.run(workspace, "deploy");

  const commandCall = processRunner.calls.find(
    (call) => call.command === TEST_COMMAND,
  );
  const pathEntries = commandCall?.env?.PATH?.split(delimiter) ?? [];

  assert.equal(pathEntries[0], "/opt/homebrew/bin");
  assert.notEqual(pathEntries[0], dirname(TEST_COMMAND));
});

test("manual-session auth reuses cached OP_SESSION without repeated validation", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
        args: ["run", "deploy"],
      },
    },
  });
  const processRunner = new FakeProcessRunner([
    processResult({ stdout: "session-token-1\n" }),
    processResult({ stdout: "first run ok\n" }),
    processResult({ stdout: "second run ok\n" }),
  ]);
  const config = createScriptRunnerConfig(workspace, {
    opCliAuthMode: "manual-session",
  });
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  const firstResult = await runner.run(workspace, "deploy");
  const secondResult = await runner.run(workspace, "deploy");
  const signinCalls = processRunner.calls.filter((call) =>
    call.args.includes("signin"),
  );
  const whoamiCalls = processRunner.calls.filter((call) =>
    call.args.includes("whoami"),
  );
  const commandCalls = processRunner.calls.filter(
    (call) => call.command === TEST_COMMAND,
  );

  assert.equal(firstResult.refreshedAuth, false);
  assert.equal(firstResult.stdout, "first run ok\n");
  assert.equal(secondResult.refreshedAuth, false);
  assert.equal(secondResult.stdout, "second run ok\n");
  assert.equal(signinCalls.length, 1);
  assert.equal(whoamiCalls.length, 0);
  assert.equal(commandCalls.length, 2);
  assert.equal(commandCalls[0]?.env?.OP_SESSION, "session-token-1");
  assert.equal(commandCalls[1]?.env?.OP_SESSION, "session-token-1");
  assert.equal(commandCalls[0]?.env?.OP_SERVICE_ACCOUNT_TOKEN, undefined);
});

test("manual-session auth coalesces concurrent signin refreshes", async () => {
  const processRunner = new FakeProcessRunner([
    processResult({ stdout: "session-token-1\n" }),
  ]);
  const config = createConfig({
    opCliAuthMode: "manual-session",
  });
  const sessionManager = new OpCliSessionManager(config, processRunner);

  const [firstEnvironment, secondEnvironment] = await Promise.all([
    sessionManager.getEnvironment(),
    sessionManager.getEnvironment(),
  ]);
  const signinCalls = processRunner.calls.filter((call) =>
    call.args.includes("signin"),
  );

  assert.equal(signinCalls.length, 1);
  assert.equal(firstEnvironment.env.OP_SESSION, "session-token-1");
  assert.equal(secondEnvironment.env.OP_SESSION, "session-token-1");
});

test("manual-session auth refreshes on the next run after auth-looking script failure", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
        args: ["run", "deploy"],
      },
    },
  });
  const processRunner = new FakeProcessRunner([
    processResult({ stdout: "session-token-1\n" }),
    processResult({
      stderr: "remote API says run op signin before deployment",
      exitCode: 1,
    }),
    processResult({ stdout: "session-token-2\n" }),
    processResult({ stdout: "second run ok\n" }),
  ]);
  const config = createScriptRunnerConfig(workspace, {
    opCliAuthMode: "manual-session",
  });
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  const firstResult = await runner.run(workspace, "deploy");
  const commandCallsAfterFirstRun = processRunner.calls.filter(
    (call) => call.command === TEST_COMMAND,
  );
  const statusAfterFirstRun = sessionManager.status();
  const secondResult = await runner.run(workspace, "deploy");
  const commandCalls = processRunner.calls.filter(
    (call) => call.command === TEST_COMMAND,
  );
  const signinCalls = processRunner.calls.filter((call) =>
    call.args.includes("signin"),
  );

  assert.equal(firstResult.refreshedAuth, false);
  assert.equal(firstResult.stderr, "remote API says run op signin before deployment");
  assert.equal(commandCallsAfterFirstRun.length, 1);
  assert.equal(statusAfterFirstRun.manualSessionMarkedInvalid, true);
  assert.equal(secondResult.refreshedAuth, true);
  assert.equal(secondResult.stdout, "second run ok\n");
  assert.equal(signinCalls.length, 2);
  assert.equal(commandCalls.length, 2);
  assert.equal(commandCalls[0]?.env?.OP_SESSION, "session-token-1");
  assert.equal(commandCalls[1]?.env?.OP_SESSION, "session-token-2");
});

test("manual-session auth reuses cached OP_SESSION after ordinary script failures", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
        args: ["run", "deploy"],
      },
    },
  });
  const processRunner = new FakeProcessRunner([
    processResult({ stdout: "session-token-1\n" }),
    processResult({ stdout: "first run ok\n" }),
    processResult({
      stderr: "script failed after partial side effects",
      exitCode: 1,
    }),
  ]);
  const config = createScriptRunnerConfig(workspace, {
    opCliAuthMode: "manual-session",
  });
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  await runner.run(workspace, "deploy");
  const result = await runner.run(workspace, "deploy");
  const signinCalls = processRunner.calls.filter((call) =>
    call.args.includes("signin"),
  );
  const whoamiCalls = processRunner.calls.filter((call) =>
    call.args.includes("whoami"),
  );
  const commandCalls = processRunner.calls.filter(
    (call) => call.command === TEST_COMMAND,
  );

  assert.equal(result.refreshedAuth, false);
  assert.equal(result.stderr, "script failed after partial side effects");
  assert.equal(signinCalls.length, 1);
  assert.equal(whoamiCalls.length, 0);
  assert.equal(commandCalls.length, 2);
  assert.equal(commandCalls[0]?.env?.OP_SESSION, "session-token-1");
  assert.equal(commandCalls[1]?.env?.OP_SESSION, "session-token-1");
});

test("service-account auth does not rerun scripts after auth-looking failures", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: TEST_COMMAND,
        args: ["run", "deploy"],
      },
    },
  });
  const processRunner = new FakeProcessRunner([
    processResult({
      stderr:
        "You are not currently signed in to your 1Password account. Run `op signin`.",
      exitCode: 1,
    }),
  ]);
  const config = createScriptRunnerConfig(workspace, {
    authMode: "service-account",
    serviceAccountToken: "service-token",
    opCliAuthMode: "service-account",
  });
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  const result = await runner.run(workspace, "deploy");
  const commandCalls = processRunner.calls.filter(
    (call) => call.command === TEST_COMMAND,
  );

  assert.equal(result.refreshedAuth, false);
  assert.equal(commandCalls.length, 1);
});

test("unrestricted script runner uses a non-login shell", async () => {
  const workspace = await realpath(await mkdtemp(join(tmpdir(), "unrestricted-script-shell-")));
  const processRunner = new FakeProcessRunner([
    processResult({ stdout: "ok\n" }),
  ]);
  const config = createConfig({
    authMode: "service-account",
    serviceAccountToken: "service-token",
    opCliAuthMode: "service-account",
    enableUnrestrictedScriptRunner: true,
  });
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  const result = await runner.runCommand(workspace, "echo ok");

  assert.equal(result.shell, "/bin/sh");
  assert.deepEqual(result.shellArgs, ["-c", "echo ok"]);
  assert.equal(processRunner.calls[0]?.command, "/bin/sh");
  assert.deepEqual(processRunner.calls[0]?.args, ["-c", "echo ok"]);
});

test("service-account auth injects OP_SERVICE_ACCOUNT_TOKEN into a minimal env", async () => {
  process.env.OP_MCP_TEST_SECRET = "must-not-leak";
  const processRunner = new FakeProcessRunner([]);
  const config = createConfig({
    authMode: "service-account",
    serviceAccountToken: "service-token",
    opCliAuthMode: "service-account",
  });
  const sessionManager = new OpCliSessionManager(config, processRunner);

  const auth = await sessionManager.getEnvironment();

  assert.equal(auth.mode, "service-account");
  assert.equal(auth.env.OP_SERVICE_ACCOUNT_TOKEN, "service-token");
  assert.equal(auth.env.OP_SESSION, undefined);
  assert.equal(auth.env.OP_MCP_TEST_SECRET, undefined);
  delete process.env.OP_MCP_TEST_SECRET;
});

test("NodeProcessRunner times out long-running commands", async () => {
  const runner = new NodeProcessRunner();

  const result = await runner.run(
    process.execPath,
    ["-e", "setTimeout(() => {}, 1000)"],
    {
      timeoutMs: 50,
      maxOutputBytes: DEFAULT_OUTPUT_LIMIT_BYTES,
    },
  );

  assert.equal(result.timedOut, true);
});

test("NodeProcessRunner enforces max output across stdout and stderr", async () => {
  const runner = new NodeProcessRunner();

  const result = await runner.run(
    process.execPath,
    [
      "-e",
      "process.stdout.write('a'.repeat(20)); process.stderr.write('b'.repeat(20));",
    ],
    {
      timeoutMs: 1_000,
      maxOutputBytes: 30,
    },
  );

  assert.equal(result.exitCode, 0);
  assert.equal(result.outputTruncated, true);
  assert.ok(
    Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr) <= 30,
  );
});

test("NodeProcessRunner force-kills commands that ignore SIGTERM", async () => {
  const runner = new NodeProcessRunner();

  const result = await runner.run(
    process.execPath,
    [
      "-e",
      "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);",
    ],
    {
      timeoutMs: 2_000,
      maxOutputBytes: DEFAULT_OUTPUT_LIMIT_BYTES,
    },
  );

  assert.equal(result.timedOut, true);
  assert.equal(result.signal, "SIGKILL");
  assert.ok(result.durationMs < 4_500);
});

test("NodeProcessRunner kills shell child process groups on timeout", async () => {
  if (process.platform === "win32") {
    return;
  }

  const runner = new NodeProcessRunner();
  const tempDir = await mkdtemp(join(tmpdir(), "op-runner-process-group-"));
  const pidFile = join(tempDir, "child.pid");
  const childScript = [
    `require("node:fs").writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));`,
    "setInterval(() => {}, 1000);",
  ].join("");
  const shellScript = `${JSON.stringify(process.execPath)} -e ${JSON.stringify(childScript)}`;

  const result = await runner.run("/bin/sh", ["-c", shellScript], {
    timeoutMs: 1_000,
    maxOutputBytes: DEFAULT_OUTPUT_LIMIT_BYTES,
  });
  const childPid = Number(await readFile(pidFile, "utf8"));

  for (let attempts = 0; attempts < 20 && processExists(childPid); attempts += 1) {
    await delay(50);
  }

  assert.equal(result.timedOut, true);
  assert.equal(processExists(childPid), false);
});
