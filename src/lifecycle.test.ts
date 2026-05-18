import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import { installStdioShutdownHandler } from "./lifecycle.js";

test("installStdioShutdownHandler shuts down once when stdin closes", async () => {
  const stdin = new EventEmitter();
  const reasons: string[] = [];

  installStdioShutdownHandler(stdin, async (reason) => {
    reasons.push(reason);
  });
  stdin.emit("close");
  stdin.emit("end");
  await new Promise((resolve) => setImmediate(resolve));

  assert.deepEqual(reasons, ["stdin_close"]);
});
