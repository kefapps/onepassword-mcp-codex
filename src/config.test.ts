import assert from "node:assert/strict";
import test from "node:test";
import { parseConfig } from "./config.js";

const ENV_KEYS = [
  "OP_MCP_ACCOUNT",
  "OP_SERVICE_ACCOUNT_TOKEN",
  "OP_MCP_SERVICE_ACCOUNT_TOKEN",
  "OP_MCP_HTTP_BEARER_TOKEN",
  "OP_MCP_TRANSPORT",
  "OP_MCP_HTTP_HOST",
  "OP_MCP_HTTP_PORT",
  "OP_MCP_HTTP_PATH",
  "OP_MCP_HTTP_REQUIRE_BEARER",
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
  assert.deepEqual(config.scriptRunnerRoots, []);
  assert.deepEqual(config.scriptRunnerAllowlistPaths, []);
  assert.equal(config.transport, "stdio");
  assert.equal(config.httpHost, "127.0.0.1");
  assert.equal(config.httpPort, 17337);
  assert.equal(config.httpPath, "/mcp");
  assert.equal(config.httpRequireBearer, false);
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
  assert.equal(config.opCliPath, "/usr/local/bin/op");
  assert.equal(config.opCliAuthMode, "manual-session");
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
    process.env.OP_MCP_HTTP_BEARER_TOKEN = "local-token";
    const config = parseConfig(
      [
        "--account",
        "TestAccount",
        "--transport=http",
        "--http-host=127.0.0.1",
        "--http-port=18080",
        "--http-path=/onepassword",
      ],
      "0.1.0",
    );

    assert.equal(config.transport, "http");
    assert.equal(config.httpHost, "127.0.0.1");
    assert.equal(config.httpPort, 18080);
    assert.equal(config.httpPath, "/onepassword");
    assert.equal(config.httpRequireBearer, true);
    assert.equal(config.httpBearerToken, "local-token");
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
