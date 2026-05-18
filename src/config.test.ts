import assert from "node:assert/strict";
import test from "node:test";
import { parseConfig } from "./config.js";
import { UNRESTRICTED_RUNNER_ACK } from "./constants.js";

const ENV_KEYS = [
  "OP_MCP_ACCOUNT",
  "OP_SERVICE_ACCOUNT_TOKEN",
  "OP_MCP_SERVICE_ACCOUNT_TOKEN",
  "OP_CONNECT_HOST",
  "OP_CONNECT_TOKEN",
  "OP_MCP_CONNECT_TIMEOUT_MS",
  "OP_MCP_HTTP_BEARER_TOKEN",
  "OP_MCP_TRANSPORT",
  "OP_MCP_HTTP_HOST",
  "OP_MCP_HTTP_PORT",
  "OP_MCP_HTTP_PATH",
  "OP_MCP_HTTP_REQUIRE_BEARER",
  "OP_MCP_HTTP_ALLOWED_ORIGINS",
  "OP_MCP_HTTP_MAX_SESSIONS",
  "OP_MCP_HTTP_SESSION_IDLE_MS",
  "OP_MCP_HTTP_REQUEST_TIMEOUT_MS",
  "OP_MCP_SCRIPT_RUNNER_ALLOWLIST_MANIFESTS",
  "OP_MCP_ENABLE_UNRESTRICTED_SCRIPT_RUNNER",
  "OP_MCP_ENABLE_UNRESTRICTED_RUNNER",
  "OP_MCP_UNRESTRICTED_RUNNER_ROOTS",
  "OP_MCP_UNRESTRICTED_RUNNER_REQUIRE_SESSION_APPROVAL",
  "OP_MCP_UNRESTRICTED_RUNNER_APPROVAL_HOST",
  "OP_MCP_UNRESTRICTED_RUNNER_APPROVAL_PORT",
  "OP_MCP_UNRESTRICTED_RUNNER_APPROVAL_TTL_MS",
  "OP_MCP_UNRESTRICTED_RUNNER_COMMAND_TIMEOUT_MS",
  "OP_MCP_APPROVAL_REMEMBER_STORE_PATH",
  "OP_MCP_APPROVAL_REMEMBER_KEY_PATH",
  "OP_MCP_APPROVAL_REMEMBER_TTL_MS",
  "OP_MCP_ACKNOWLEDGE_UNRESTRICTED_RUNNER",
  "OP_MCP_DIAGNOSTICS",
] as const;

function withCleanAuthEnv(callback: () => void): void {
  const originalValues = new Map<string, string | undefined>();
  for (const key of ENV_KEYS) {
    originalValues.set(key, process.env[key]);
    delete process.env[key];
  }

  try {
    callback();
  } finally {
    for (const key of ENV_KEYS) {
      const value = originalValues.get(key);
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

test("parseConfig keeps write and script runner gates disabled by default", () => {
  const config = parseConfig(["--account", "TestAccount"], "0.1.0");

  assert.equal(config.enableWrites, false);
  assert.equal(config.enableDestructiveActions, false);
  assert.equal(config.enablePermissionMutation, false);
  assert.equal(config.enableScriptRunner, false);
  assert.equal(config.enableUnrestrictedScriptRunner, false);
  assert.deepEqual(config.scriptRunnerRoots, []);
  assert.deepEqual(config.scriptRunnerAllowlistPaths, []);
  assert.deepEqual(config.scriptRunnerAllowlistManifestPaths, []);
  assert.equal(config.enableUnrestrictedRunner, false);
  assert.deepEqual(config.unrestrictedRunnerRoots, []);
  assert.equal(config.unrestrictedRunnerRequireSessionApproval, true);
  assert.equal(config.unrestrictedRunnerApprovalHost, "127.0.0.1");
  assert.equal(config.unrestrictedRunnerApprovalPort, 0);
  assert.equal(config.unrestrictedRunnerApprovalTtlMs, 12 * 60 * 60_000);
  assert.equal(config.unrestrictedRunnerCommandTimeoutMs, 600_000);
  assert.match(config.approvalRememberStorePath, /approval-grants\.enc\.json$/);
  assert.match(config.approvalRememberKeyPath, /approval-grants\.key$/);
  assert.equal(config.approvalRememberTtlMs, 24 * 60 * 60_000);
  assert.equal(config.transport, "stdio");
  assert.equal(config.httpHost, "127.0.0.1");
  assert.equal(config.httpPort, 17337);
  assert.equal(config.httpPath, "/mcp");
  assert.equal(config.httpRequireBearer, false);
  assert.deepEqual(config.httpAllowedOrigins, []);
  assert.equal(config.httpMaxSessions, 64);
  assert.equal(config.httpSessionIdleMs, 15 * 60_000);
  assert.equal(config.httpRequestTimeoutMs, 30_000);
  assert.equal(config.enableDiagnostics, false);
});

test("parseConfig enables diagnostics from flag", () => {
  const config = parseConfig(
    ["--account", "TestAccount", "--diagnostics=true"],
    "0.1.0",
  );

  assert.equal(config.enableDiagnostics, true);
});

test("parseConfig accepts local Connect auth mode", () => {
  withCleanAuthEnv(() => {
    process.env.OP_CONNECT_TOKEN = "connect-token";

    const config = parseConfig(["--auth-mode=connect"], "0.1.0");

    assert.equal(config.authMode, "connect");
    assert.equal(config.connectHost, "http://127.0.0.1:8080");
    assert.equal(config.connectToken, "connect-token");
    assert.equal(config.connectTimeoutMs, 30_000);
    assert.equal(config.account, undefined);
    assert.equal(config.serviceAccountToken, undefined);
  });
});

test("parseConfig accepts IPv6 loopback Connect hosts", () => {
  const config = parseConfig(
    [
      "--auth-mode=connect",
      "--connect-token=connect-token",
      "--connect-host=http://[::1]:8080",
    ],
    "0.1.0",
  );

  assert.equal(config.authMode, "connect");
  assert.equal(config.connectHost, "http://[::1]:8080");
});

test("parseConfig rejects Connect hosts outside localhost", () => {
  withCleanAuthEnv(() => {
    assert.throws(
      () =>
        parseConfig(
          [
            "--auth-mode=connect",
            "--connect-token=connect-token",
            "--connect-host=https://connect.example.com",
          ],
          "0.1.0",
        ),
      /Connect host must use localhost/,
    );
  });
});

test("parseConfig accepts unrestricted script runner without allowlists", () => {
  const config = parseConfig(
    [
      "--account",
      "TestAccount",
      "--enable-unrestricted-script-runner=true",
      "--op-cli-path=/usr/local/bin/op",
      "--op-cli-auth-mode=desktop",
    ],
    "0.1.0",
  );

  assert.equal(config.enableScriptRunner, true);
  assert.equal(config.enableUnrestrictedScriptRunner, true);
  assert.deepEqual(config.scriptRunnerRoots, []);
  assert.deepEqual(config.scriptRunnerAllowlistPaths, []);
  assert.deepEqual(config.scriptRunnerAllowlistManifestPaths, []);
  assert.equal(config.unrestrictedRunnerRequireSessionApproval, true);
});

test("parseConfig requires configured allowlists when script runner is enabled", () => {
  assert.throws(
    () =>
      parseConfig(
        [
          "--account",
          "TestAccount",
          "--enable-script-runner=true",
          "--script-runner-root=/tmp",
          "--op-cli-path=/usr/local/bin/op",
        ],
        "0.1.0",
      ),
    /script-runner-allowlist/,
  );
});

test("parseConfig rejects missing values for separate flag arguments", () => {
  assert.throws(
    () => parseConfig(["--account", "--enable-writes=true"], "0.1.0"),
    /Missing value for --account/,
  );
});

test("parseConfig rejects empty values for equals-style flag arguments", () => {
  assert.throws(
    () => parseConfig(["--account="], "0.1.0"),
    /Missing value for --account/,
  );
});

test("parseConfig rejects missing values for repeatable flags", () => {
  assert.throws(
    () =>
      parseConfig(
        [
          "--account=TestAccount",
          "--enable-script-runner=true",
          "--script-runner-allowlist=/tmp/.onepassword-mcp.json",
          "--script-runner-root",
          "--op-cli-path=/usr/local/bin/op",
        ],
        "0.1.0",
      ),
    /Missing value for --script-runner-root/,
  );
});

test("parseConfig requires absolute op path when script runner is enabled", () => {
  assert.throws(
    () =>
      parseConfig(
        [
          "--account",
          "TestAccount",
          "--enable-script-runner=true",
          "--script-runner-root=/tmp",
          "--script-runner-allowlist=/tmp/.onepassword-mcp.json",
          "--op-cli-path=op",
        ],
        "0.1.0",
      ),
    /op-cli-path/,
  );
});

test("parseConfig requires absolute allowlist paths when script runner is enabled", () => {
  assert.throws(
    () =>
      parseConfig(
        [
          "--account",
          "TestAccount",
          "--enable-script-runner=true",
          "--script-runner-allowlist=.onepassword-mcp.json",
          "--op-cli-path=/usr/local/bin/op",
        ],
        "0.1.0",
      ),
    /allowlist path must be absolute/,
  );
});

test("parseConfig requires absolute allowlist manifest paths when script runner is enabled", () => {
  assert.throws(
    () =>
      parseConfig(
        [
          "--account",
          "TestAccount",
          "--enable-script-runner=true",
          "--script-runner-allowlist-manifest=.onepassword-mcp-manifest.json",
          "--op-cli-path=/usr/local/bin/op",
        ],
        "0.1.0",
      ),
    /allowlist manifest path must be absolute/,
  );
});

test("parseConfig accepts hardened script runner configuration", () => {
  const config = parseConfig(
    [
      "--account",
      "TestAccount",
      "--enable-script-runner=true",
      "--script-runner-root=/tmp",
      "--script-runner-allowlist=/tmp/.onepassword-mcp.json",
      "--op-cli-path=/usr/local/bin/op",
      "--op-cli-auth-mode=manual-session",
    ],
    "0.1.0",
  );

  assert.equal(config.enableScriptRunner, true);
  assert.deepEqual(config.scriptRunnerRoots, ["/tmp"]);
  assert.deepEqual(config.scriptRunnerAllowlistPaths, [
    "/tmp/.onepassword-mcp.json",
  ]);
  assert.deepEqual(config.scriptRunnerAllowlistManifestPaths, []);
  assert.equal(config.opCliPath, "/usr/local/bin/op");
  assert.equal(config.opCliAuthMode, "manual-session");
});

test("parseConfig accepts startup allowlist manifests", () => {
  const config = parseConfig(
    [
      "--account",
      "TestAccount",
      "--enable-script-runner=true",
      "--script-runner-root=/tmp",
      "--script-runner-allowlist-manifest=/tmp/onepassword-mcp-manifest.json",
      "--op-cli-path=/usr/local/bin/op",
    ],
    "0.1.0",
  );

  assert.equal(config.enableScriptRunner, true);
  assert.deepEqual(config.scriptRunnerAllowlistPaths, []);
  assert.deepEqual(config.scriptRunnerAllowlistManifestPaths, [
    "/tmp/onepassword-mcp-manifest.json",
  ]);
});

test("parseConfig accepts unrestricted runner configuration with session approval", () => {
  const config = parseConfig(
    [
      "--account",
      "TestAccount",
      "--enable-unrestricted-runner=true",
      "--unrestricted-runner-root=/tmp/project",
      "--unrestricted-runner-approval-host=localhost",
      "--unrestricted-runner-approval-port=19000",
      "--unrestricted-runner-approval-ttl-ms=3600000",
      "--unrestricted-runner-command-timeout-ms=120000",
      "--approval-remember-store-path=/tmp/approval-grants.enc.json",
      "--approval-remember-key-path=/tmp/approval-grants.key",
      "--approval-remember-ttl-ms=7200000",
    ],
    "0.1.0",
  );

  assert.equal(config.enableUnrestrictedRunner, true);
  assert.deepEqual(config.unrestrictedRunnerRoots, ["/tmp/project"]);
  assert.equal(config.unrestrictedRunnerRequireSessionApproval, true);
  assert.equal(config.unrestrictedRunnerApprovalHost, "localhost");
  assert.equal(config.unrestrictedRunnerApprovalPort, 19000);
  assert.equal(config.unrestrictedRunnerApprovalTtlMs, 3_600_000);
  assert.equal(config.unrestrictedRunnerCommandTimeoutMs, 120_000);
  assert.equal(config.approvalRememberStorePath, "/tmp/approval-grants.enc.json");
  assert.equal(config.approvalRememberKeyPath, "/tmp/approval-grants.key");
  assert.equal(config.approvalRememberTtlMs, 7_200_000);
});

test("parseConfig validates unrestricted runner roots and approval bypass", () => {
  assert.throws(
    () =>
      parseConfig(
        [
          "--account",
          "TestAccount",
          "--enable-unrestricted-runner=true",
        ],
        "0.1.0",
      ),
    /unrestricted-runner-root/,
  );
  assert.throws(
    () =>
      parseConfig(
        [
          "--account",
          "TestAccount",
          "--enable-unrestricted-runner=true",
          "--unrestricted-runner-root=relative",
        ],
        "0.1.0",
      ),
    /root must be absolute/,
  );
  assert.throws(
    () =>
      parseConfig(
        [
          "--account",
          "TestAccount",
          "--enable-unrestricted-runner=true",
          "--unrestricted-runner-root=/tmp/project",
          "--unrestricted-runner-approval-host=0.0.0.0",
        ],
        "0.1.0",
      ),
    /approval host must be localhost/,
  );
  assert.throws(
    () =>
      parseConfig(
        [
          "--account",
          "TestAccount",
          "--enable-unrestricted-runner=true",
          "--unrestricted-runner-root=/tmp/project",
          "--unrestricted-runner-require-session-approval=false",
        ],
        "0.1.0",
      ),
    /acknowledge-unrestricted-runner/,
  );
});

test("parseConfig accepts explicit unrestricted runner approval bypass acknowledgement", () => {
  const config = parseConfig(
    [
      "--account",
      "TestAccount",
      "--enable-unrestricted-runner=true",
      "--unrestricted-runner-root=/tmp/project",
      "--unrestricted-runner-require-session-approval=false",
      `--acknowledge-unrestricted-runner=${UNRESTRICTED_RUNNER_ACK}`,
    ],
    "0.1.0",
  );

  assert.equal(config.enableUnrestrictedRunner, true);
  assert.equal(config.unrestrictedRunnerRequireSessionApproval, false);
});

test("parseConfig requires a bearer token for HTTP transport by default", () => {
  withCleanAuthEnv(() => {
    assert.throws(
      () =>
        parseConfig(
          [
            "--account",
            "TestAccount",
            "--transport=http",
            "--http-host=127.0.0.1",
            "--http-port=17337",
            "--http-path=/mcp",
          ],
          "0.1.0",
        ),
      /OP_MCP_HTTP_BEARER_TOKEN/,
    );
  });
});

test("parseConfig accepts HTTP transport with bearer token", () => {
  withCleanAuthEnv(() => {
    process.env.OP_MCP_HTTP_BEARER_TOKEN = "local-token-123456";
    const config = parseConfig(
      [
        "--account",
        "TestAccount",
        "--transport=http",
        "--http-host=127.0.0.1",
        "--http-port=18080",
        "--http-path=/onepassword",
        "--http-allowed-origin=http://127.0.0.1:18080",
        "--http-max-sessions=8",
        "--http-session-idle-ms=60000",
        "--http-request-timeout-ms=5000",
      ],
      "0.1.0",
    );

    assert.equal(config.transport, "http");
    assert.equal(config.httpHost, "127.0.0.1");
    assert.equal(config.httpPort, 18080);
    assert.equal(config.httpPath, "/onepassword");
    assert.equal(config.httpRequireBearer, true);
    assert.equal(config.httpBearerToken, "local-token-123456");
    assert.deepEqual(config.httpAllowedOrigins, ["http://127.0.0.1:18080"]);
    assert.equal(config.httpMaxSessions, 8);
    assert.equal(config.httpSessionIdleMs, 60_000);
    assert.equal(config.httpRequestTimeoutMs, 5_000);
  });
});

test("parseConfig can disable HTTP bearer requirement explicitly", () => {
  withCleanAuthEnv(() => {
    const config = parseConfig(
      [
        "--account",
        "TestAccount",
        "--transport=http",
        "--http-require-bearer=false",
      ],
      "0.1.0",
    );

    assert.equal(config.transport, "http");
    assert.equal(config.httpRequireBearer, false);
    assert.equal(config.httpBearerToken, undefined);
  });
});

test("parseConfig rejects short HTTP bearer tokens and unauthenticated non-localhost binds", () => {
  withCleanAuthEnv(() => {
    process.env.OP_MCP_HTTP_BEARER_TOKEN = "short";
    assert.throws(
      () => parseConfig(["--account", "TestAccount", "--transport=http"], "0.1.0"),
      /at least 16 characters/,
    );
  });

  withCleanAuthEnv(() => {
    assert.throws(
      () =>
        parseConfig(
          [
            "--account",
            "TestAccount",
            "--transport=http",
            "--http-host=0.0.0.0",
            "--http-require-bearer=false",
          ],
          "0.1.0",
        ),
      /localhost/,
    );
  });
});

test("parseConfig validates HTTP transport settings", () => {
  assert.throws(
    () => parseConfig(["--account", "TestAccount", "--transport=tcp"], "0.1.0"),
    /Unsupported transport/,
  );
  assert.throws(
    () =>
      parseConfig(
        ["--account", "TestAccount", "--http-port=70000"],
        "0.1.0",
      ),
    /Invalid HTTP port/,
  );
  assert.throws(
    () =>
      parseConfig(
        ["--account", "TestAccount", "--http-path=mcp"],
        "0.1.0",
      ),
    /HTTP path must start/,
  );
  assert.throws(
    () =>
      parseConfig(
        ["--account", "TestAccount", "--http-max-sessions=0"],
        "0.1.0",
      ),
    /Invalid HTTP max sessions/,
  );
});

test("parseConfig requires account for script runner manual-session auth", () => {
  withCleanAuthEnv(() => {
    assert.throws(
      () =>
        parseConfig(
          [
            "--auth-mode=service-account",
            "--service-account-token=service-token",
            "--enable-script-runner=true",
            "--script-runner-root=/tmp",
            "--script-runner-allowlist=/tmp/.onepassword-mcp.json",
            "--op-cli-path=/usr/local/bin/op",
            "--op-cli-auth-mode=manual-session",
          ],
          "0.1.0",
        ),
      /requires --account/,
    );
  });
});

test("parseConfig requires service token for script runner service-account auth", () => {
  withCleanAuthEnv(() => {
    assert.throws(
      () =>
        parseConfig(
          [
            "--account=TestAccount",
            "--enable-script-runner=true",
            "--script-runner-root=/tmp",
            "--script-runner-allowlist=/tmp/.onepassword-mcp.json",
            "--op-cli-path=/usr/local/bin/op",
            "--op-cli-auth-mode=service-account",
          ],
          "0.1.0",
        ),
      /service-account mode requires/,
    );
  });
});
