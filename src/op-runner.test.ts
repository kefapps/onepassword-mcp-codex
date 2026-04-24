import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { ServerConfig } from "./config.js";
import {
  DEFAULT_OUTPUT_LIMIT_BYTES,
  DefaultOpScriptRunner,
  NodeProcessRunner,
  OpCliSessionManager,
  SCRIPT_ALLOWLIST_FILENAME,
  loadScriptAllowlist,
  type ProcessRunResult,
  type ProcessRunner,
} from "./op-runner.js";

function createConfig(overrides: Partial<ServerConfig> = {}): ServerConfig {
  return {
    authMode: "desktop",
    account: "TestAccount",
    enableSecretReveal: false,
    enableWrites: false,
    enableDestructiveActions: false,
    enablePermissionMutation: false,
    enableScriptRunner: true,
    scriptRunnerRoots: [],
    scriptRunnerAllowlistPaths: [],
    opCliPath: "op",
    opCliAuthMode: "auto",
    auditLogPath: "/tmp/onepassword-mcp-codex-test-audit.jsonl",
    logLevel: "info",
    integrationName: "Test",
    integrationVersion: "0.1.0",
    ...overrides,
  };
}

async function createWorkspace(allowlist: unknown): Promise<string> {
  const workspace = await mkdtemp(join(tmpdir(), "op-runner-test-"));
  await writeFile(
    join(workspace, SCRIPT_ALLOWLIST_FILENAME),
    JSON.stringify(allowlist, null, 2),
    "utf8",
  );
  return workspace;
}

function allowlistPath(workspace: string): string {
  return join(workspace, SCRIPT_ALLOWLIST_FILENAME);
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

test("loadScriptAllowlist parses command defaults", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: "npm",
        args: ["run", "deploy"],
      },
    },
  });

  const allowlist = await loadScriptAllowlist(workspace, [workspace]);

  assert.equal(allowlist.commands[0]?.id, "deploy");
  assert.equal(allowlist.commands[0]?.cwd, ".");
  assert.equal(allowlist.commands[0]?.sensitiveOutput, false);
  assert.deepEqual(allowlist.commands[0]?.args, ["run", "deploy"]);
});

test("DefaultOpScriptRunner rejects cwd outside workspace", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      escape: {
        command: "npm",
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
    /PATH executable name or an absolute path inside the workspace/,
  );
});

test("DefaultOpScriptRunner rejects workspace outside configured roots", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: "npm",
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

test("DefaultOpScriptRunner uses startup-pinned allowlists", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: "npm",
      },
    },
  });
  const config = createScriptRunnerConfig(workspace);
  const processRunner = new FakeProcessRunner([processResult()]);
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  await writeFile(
    allowlistPath(workspace),
    JSON.stringify({
      version: 1,
      commands: {
        injected: {
          command: "npm",
        },
      },
    }),
    "utf8",
  );

  await assert.rejects(() => runner.run(workspace, "injected"), /not found/);
});

test("manual-session auth caches OP_SESSION and refreshes after auth failure", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: "npm",
        args: ["run", "deploy"],
      },
    },
  });
  const processRunner = new FakeProcessRunner([
    processResult({ stdout: "session-token-1\n" }),
    processResult({
      stderr:
        "You are not currently signed in to your 1Password account. Run `op signin`.",
      exitCode: 1,
    }),
    processResult({
      stderr: "session expired",
      exitCode: 1,
    }),
    processResult({ stdout: "session-token-2\n" }),
    processResult({ stdout: "ok session-token-2\n" }),
  ]);
  const config = createScriptRunnerConfig(workspace, {
    opCliAuthMode: "manual-session",
  });
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  const result = await runner.run(workspace, "deploy");
  const commandCalls = processRunner.calls.filter((call) => call.command === "npm");

  assert.equal(result.refreshedAuth, true);
  assert.equal(result.stdout, "ok [REDACTED]\n");
  assert.equal(commandCalls[0]?.env?.OP_SESSION, "session-token-1");
  assert.equal(commandCalls[1]?.env?.OP_SESSION, "session-token-2");
  assert.equal(commandCalls[0]?.env?.OP_SERVICE_ACCOUNT_TOKEN, undefined);
});

test("manual-session auth does not refresh when deterministic auth check passes", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: "npm",
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
    processResult(),
  ]);
  const config = createScriptRunnerConfig(workspace, {
    opCliAuthMode: "manual-session",
  });
  const sessionManager = new OpCliSessionManager(config, processRunner);
  const runner = new DefaultOpScriptRunner(config, sessionManager, processRunner);

  const result = await runner.run(workspace, "deploy");
  const commandCalls = processRunner.calls.filter((call) => call.command === "npm");

  assert.equal(result.refreshedAuth, false);
  assert.equal(result.stderr, "remote API says run op signin before deployment");
  assert.equal(commandCalls.length, 1);
});

test("service-account auth does not rerun scripts after auth-looking failures", async () => {
  const workspace = await createWorkspace({
    version: 1,
    commands: {
      deploy: {
        command: "npm",
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
  const commandCalls = processRunner.calls.filter((call) => call.command === "npm");

  assert.equal(result.refreshedAuth, false);
  assert.equal(commandCalls.length, 1);
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
