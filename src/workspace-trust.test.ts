import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, realpath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  parseWorkspaceTrustArgs,
  trustWorkspace,
} from "./workspace-trust.js";

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

test("trustWorkspace creates current workspace trust file and manifest entry", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "workspace-trust-"));
  const resolvedWorkspace = await realpath(workspace);
  const manifestPath = join(workspace, ".mcp", "workspace-trust.json");

  const result = await trustWorkspace({
    workspacePath: workspace,
    manifestPath,
  });

  assert.equal(result.workspaceRoot, resolvedWorkspace);
  assert.equal(result.trustFilePath, join(resolvedWorkspace, ".onepassword-mcp.json"));
  assert.equal(result.trustFileCreated, true);
  assert.equal(result.trustFileUpdated, true);
  assert.equal(result.manifestCreated, true);
  assert.equal(result.manifestUpdated, true);

  assert.deepEqual(await readJson(result.trustFilePath), {
    version: 1,
    workspaceRoot: ".",
    allowWorkspaceCommands: true,
    commands: {},
  });
  assert.deepEqual(await readJson(manifestPath), {
    version: 1,
    allowlists: [result.trustFilePath],
  });
});

test("trustWorkspace preserves existing command catalog and avoids duplicate manifest entries", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "workspace-trust-"));
  const trustFilePath = join(workspace, ".onepassword-mcp.json");
  const manifestPath = join(workspace, ".mcp", "workspace-trust.json");
  await mkdir(join(workspace, ".mcp"), { recursive: true });
  await writeFile(
    trustFilePath,
    JSON.stringify(
      {
        version: 1,
        workspaceRoot: ".",
        allowWorkspaceCommands: false,
        commands: {
          deploy: {
            command: "/usr/bin/true",
          },
        },
      },
      null,
      2,
    ),
    "utf8",
  );
  await writeFile(
    manifestPath,
    JSON.stringify({ version: 1, allowlists: [trustFilePath] }, null, 2),
    "utf8",
  );

  const first = await trustWorkspace({ workspacePath: workspace, manifestPath });
  const second = await trustWorkspace({ workspacePath: workspace, manifestPath });

  assert.equal(first.trustFileCreated, false);
  assert.equal(first.trustFileUpdated, true);
  assert.equal(second.trustFileUpdated, false);
  assert.equal(second.manifestUpdated, false);
  assert.deepEqual(await readJson(trustFilePath), {
    version: 1,
    workspaceRoot: ".",
    allowWorkspaceCommands: true,
    commands: {
      deploy: {
        command: "/usr/bin/true",
      },
    },
  });
  assert.deepEqual(await readJson(manifestPath), {
    version: 1,
    allowlists: [trustFilePath],
  });
});

test("trustWorkspace adds the current root to an existing exact catalog", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "workspace-trust-"));
  const trustFilePath = join(workspace, ".onepassword-mcp.json");
  const manifestPath = join(workspace, ".mcp", "workspace-trust.json");
  await mkdir(join(workspace, ".mcp"), { recursive: true });
  await writeFile(
    trustFilePath,
    JSON.stringify(
      {
        version: 1,
        workspaceRoot: "../other-project",
        allowWorkspaceCommands: false,
        commands: {
          deploy: {
            command: "/usr/bin/true",
          },
        },
      },
      null,
      2,
    ),
    "utf8",
  );

  await trustWorkspace({ workspacePath: workspace, manifestPath });
  const first = await readJson(trustFilePath);
  await trustWorkspace({ workspacePath: workspace, manifestPath });

  assert.deepEqual(first, {
    version: 1,
    workspaceRoots: ["../other-project", "."],
    allowWorkspaceCommands: true,
    commands: {
      deploy: {
        command: "/usr/bin/true",
      },
    },
  });
  assert.deepEqual(await readJson(trustFilePath), first);
});

test("parseWorkspaceTrustArgs defaults to the current directory and default manifest", () => {
  const options = parseWorkspaceTrustArgs([], "/workspace");

  assert.equal(options.workspacePath, "/workspace");
  assert.match(options.manifestPath, /workspace-trust\.json$/);
  assert.equal(options.scope, "exact");
});

test("parseWorkspaceTrustArgs accepts explicit path, manifest, and prefix scope", () => {
  const options = parseWorkspaceTrustArgs(
    [
      "../project",
      "--manifest=/tmp/trust.json",
      "--scope=prefix",
    ],
    "/workspace/current",
  );

  assert.equal(options.workspacePath, "/workspace/project");
  assert.equal(options.manifestPath, "/tmp/trust.json");
  assert.equal(options.scope, "prefix");
});
