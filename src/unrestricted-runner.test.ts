import assert from "node:assert/strict";
import { mkdtemp, readFile, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { MemoryAuditLogger } from "./audit.js";
import type { ServerConfig } from "./config.js";
import { UNRESTRICTED_RUNNER_ACK } from "./constants.js";
import type { ProcessRunResult, ProcessRunner } from "./op-runner.js";
import {
  DefaultUnrestrictedRunner,
  UnrestrictedApprovalManager,
  startUnrestrictedApprovalServer,
} from "./unrestricted-runner.js";

function createConfig(root: string, overrides: Partial<ServerConfig> = {}): ServerConfig {
  return {
    authMode: "desktop",
    account: "TestAccount",
    enableSecretReveal: false,
    enableWrites: false,
    enableDestructiveActions: false,
    enablePermissionMutation: false,
    enableScriptRunner: false,
    enableUnrestrictedScriptRunner: false,
    scriptRunnerRoots: [],
    scriptRunnerAllowlistPaths: [],
    scriptRunnerAllowlistManifestPaths: [],
    enableUnrestrictedRunner: true,
    unrestrictedRunnerRoots: [root],
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

class FakeProcessRunner implements ProcessRunner {
  public lastCall?: {
    command: string;
    args: string[];
    cwd?: string;
    timeoutMs: number;
    maxOutputBytes: number;
  };

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
    this.lastCall = {
      command,
      args,
      cwd: options.cwd,
      timeoutMs: options.timeoutMs,
      maxOutputBytes: options.maxOutputBytes,
    };
    return {
      stdout: "ok\n",
      stderr: "",
      exitCode: 0,
      signal: null,
      timedOut: false,
      outputTruncated: false,
      durationMs: 3,
    };
  }
}

test("unrestricted approval server requires checkbox and exact acknowledgement", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "unrestricted-approval-test-")));
  const config = createConfig(root);
  const auditLogger = new MemoryAuditLogger();
  const approvalManager = new UnrestrictedApprovalManager(
    config.unrestrictedRunnerApprovalTtlMs,
  );
  const handle = await startUnrestrictedApprovalServer(
    config,
    approvalManager,
    auditLogger,
  );

  assert(handle);
  try {
    const request = approvalManager.createAuthorizationRequest(root, root);
    const token = new URL(request.approvalUrl).searchParams.get("token") ?? "";

    const getResponse = await fetch(request.approvalUrl);
    const page = await getResponse.text();
    assert.equal(getResponse.status, 200);
    assert.match(page, /Approve Unrestricted Command Execution/);
    assert.match(page, /Remember this approval for 24 hours/);
    assert.match(page, new RegExp(UNRESTRICTED_RUNNER_ACK));

    const rejected = await fetch(`${handle.url}/approve`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        token,
        acknowledgement: UNRESTRICTED_RUNNER_ACK,
      }),
    });
    assert.equal(rejected.status, 400);
    assert.equal(approvalManager.isApproved(root), false);

    const approved = await fetch(`${handle.url}/approve`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        token,
        acceptedRisk: "on",
        acknowledgement: UNRESTRICTED_RUNNER_ACK,
      }),
    });
    assert.equal(approved.status, 200);
    assert.equal(approvalManager.isApproved(root), true);
    assert.equal(auditLogger.events.at(-1)?.action, "op_unrestricted_runner_approve");
    assert.equal(auditLogger.events.at(-1)?.outcome, "success");
    assert.equal(auditLogger.events.at(-1)?.metadata.remembered, false);
  } finally {
    await handle.close();
  }
});

test("unrestricted approval can remember encrypted grants across manager instances", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "unrestricted-remember-root-")));
  const storeDir = await mkdtemp(join(tmpdir(), "unrestricted-remember-store-"));
  const storePath = join(storeDir, "grants.enc.json");
  const keyPath = join(storeDir, "grants.key");
  const persistence = {
    storePath,
    keyPath,
    rememberTtlMs: 24 * 60 * 60_000,
  };
  const approvalManager = new UnrestrictedApprovalManager(60_000, persistence);
  approvalManager.setApprovalBaseUrl("http://127.0.0.1:19000");

  const request = approvalManager.createAuthorizationRequest(
    root,
    "unrestricted-script-runner-session",
  );
  const token = new URL(request.approvalUrl).searchParams.get("token") ?? "";
  const result = approvalManager.approveToken(
    token,
    true,
    UNRESTRICTED_RUNNER_ACK,
    true,
  );
  const encryptedStore = await readFile(storePath, "utf8");
  const reloadedApprovalManager = new UnrestrictedApprovalManager(60_000, persistence);

  assert.equal(result.remembered, true);
  assert.equal(reloadedApprovalManager.isApproved("unrestricted-script-runner-session"), true);
  assert(!encryptedStore.includes("unrestricted-script-runner-session"));
  assert(!encryptedStore.includes(root));
});

test("unrestricted runner gates arbitrary shell command execution by approved root", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "unrestricted-runner-test-")));
  const approvalManager = new UnrestrictedApprovalManager(60_000);
  approvalManager.setApprovalBaseUrl("http://127.0.0.1:19000");
  const fakeProcessRunner = new FakeProcessRunner();
  const runner = new DefaultUnrestrictedRunner(
    createConfig(root, {
      unrestrictedRunnerCommandTimeoutMs: 12_345,
    }),
    approvalManager,
    fakeProcessRunner,
  );

  const authorization = await runner.authorization(root);
  assert(authorization);
  assert.equal(authorization.authorizationRequired, true);
  assert.match(authorization.approvalUrl, /^http:\/\/127\.0\.0\.1:19000\/approve/);

  const token = new URL(authorization.approvalUrl).searchParams.get("token") ?? "";
  approvalManager.approveToken(token, true, UNRESTRICTED_RUNNER_ACK);

  const result = await runner.run(root, "echo ok");
  assert.equal(result.stdout, "ok\n");
  assert.equal(result.workspaceRoot, root);
  assert.equal(result.configuredRoot, root);
  assert.equal(result.sensitiveOutput, true);
  assert.equal(fakeProcessRunner.lastCall?.cwd, root);
  assert.equal(fakeProcessRunner.lastCall?.command, "/bin/sh");
  assert.deepEqual(fakeProcessRunner.lastCall?.args, ["-c", "echo ok"]);
  assert.equal(fakeProcessRunner.lastCall?.timeoutMs, 12_345);
});

test("unrestricted runner rejects workspaces outside configured roots", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "unrestricted-root-test-")));
  const outside = await realpath(await mkdtemp(join(tmpdir(), "unrestricted-outside-test-")));
  const approvalManager = new UnrestrictedApprovalManager(60_000);
  approvalManager.setApprovalBaseUrl("http://127.0.0.1:19000");
  const runner = new DefaultUnrestrictedRunner(createConfig(root), approvalManager);

  await assert.rejects(
    () => runner.authorization(outside),
    /outside the configured unrestricted runner roots/,
  );
});
