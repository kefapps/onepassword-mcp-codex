import assert from "node:assert/strict";
import test from "node:test";
import { parseConfig } from "./config.js";

test("parseConfig keeps write and script runner gates disabled by default", () => {
  const config = parseConfig(["--account", "TestAccount"], "0.1.0");

  assert.equal(config.enableWrites, false);
  assert.equal(config.enableDestructiveActions, false);
  assert.equal(config.enablePermissionMutation, false);
  assert.equal(config.enableScriptRunner, false);
  assert.deepEqual(config.scriptRunnerRoots, []);
});

test("parseConfig requires trusted roots when script runner is enabled", () => {
  assert.throws(
    () =>
      parseConfig(
        [
          "--account",
          "TestAccount",
          "--enable-script-runner=true",
          "--op-cli-path=/usr/local/bin/op",
        ],
        "0.1.0",
      ),
    /script-runner-root/,
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
          "--op-cli-path=op",
        ],
        "0.1.0",
      ),
    /op-cli-path/,
  );
});

test("parseConfig accepts hardened script runner configuration", () => {
  const config = parseConfig(
    [
      "--account",
      "TestAccount",
      "--enable-script-runner=true",
      "--script-runner-root=/tmp",
      "--op-cli-path=/usr/local/bin/op",
      "--op-cli-auth-mode=manual-session",
    ],
    "0.1.0",
  );

  assert.equal(config.enableScriptRunner, true);
  assert.deepEqual(config.scriptRunnerRoots, ["/tmp"]);
  assert.equal(config.opCliPath, "/usr/local/bin/op");
  assert.equal(config.opCliAuthMode, "manual-session");
});
