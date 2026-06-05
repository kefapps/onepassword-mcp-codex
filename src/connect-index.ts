#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { FileAuditLogger } from "./audit.js";
import { HelpError, parseConnectOnlyConfig } from "./config.js";
import { ConnectOnePasswordService } from "./connect-service.js";
import { processMetadata, recordDiagnosticAudit } from "./diagnostics.js";
import { errorMessage } from "./errors.js";
import { startOnePasswordHttpServer } from "./http-server.js";
import { installStdioShutdownHandler } from "./lifecycle.js";
import { DefaultOpScriptRunner } from "./op-runner.js";
import { createOnePasswordMcpServer } from "./server.js";
import {
  DefaultUnrestrictedRunner,
  createUnrestrictedApprovalManager,
  startUnrestrictedApprovalServer,
} from "./unrestricted-runner.js";
import {
  WorkspaceTrustHelpError,
  formatWorkspaceTrustResult,
  parseWorkspaceTrustArgs,
  trustWorkspace,
} from "./workspace-trust.js";

function readPackageVersion(): string {
  const currentDir = dirname(fileURLToPath(import.meta.url));
  const packageJsonPath = join(currentDir, "..", "package.json");
  const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8")) as {
    version: string;
  };
  return packageJson.version;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const [command, ...commandArgs] = argv;
  if (command === "trust-workspace" || command === "workspace-trust") {
    const options = parseWorkspaceTrustArgs(commandArgs);
    const result = await trustWorkspace(options);
    console.log(formatWorkspaceTrustResult(result));
    return;
  }

  const config = parseConnectOnlyConfig(argv, readPackageVersion());
  const auditLogger = new FileAuditLogger(config.auditLogPath);
  recordDiagnosticAudit(config, auditLogger, "server_start", "success", {
    ...processMetadata(config),
    argvCount: process.argv.length,
    connectOnly: true,
  });

  const service = new ConnectOnePasswordService(config, undefined, auditLogger);
  const unrestrictedApprovalManager = createUnrestrictedApprovalManager(config);
  const scriptRunner = new DefaultOpScriptRunner(config);
  const unrestrictedApprovalServer = await startUnrestrictedApprovalServer(
    config,
    unrestrictedApprovalManager,
    auditLogger,
  );
  const unrestrictedRunner = new DefaultUnrestrictedRunner(
    config,
    unrestrictedApprovalManager,
  );

  console.error(
    `[mcp-1password-connect] transport=${config.transport} auth=${config.authMode} connectHost=${config.connectHost ?? "none"} reveal=${config.enableSecretReveal} writes=${config.enableWrites} destructive=${config.enableDestructiveActions} scriptRunner=${config.enableScriptRunner} unrestrictedScriptRunner=${config.enableUnrestrictedScriptRunner} scriptAllowlists=${config.scriptRunnerAllowlistPaths.length} scriptAllowlistManifests=${config.scriptRunnerAllowlistManifestPaths.length} unrestrictedRunner=${config.enableUnrestrictedRunner} unrestrictedRoots=${config.unrestrictedRunnerRoots.length} unrestrictedApproval=${config.unrestrictedRunnerRequireSessionApproval} audit=${config.auditLogPath}`,
  );
  if (unrestrictedApprovalServer) {
    console.error(
      `[mcp-1password-connect] unrestricted runner approval listening on ${unrestrictedApprovalServer.url}`,
    );
  }

  if (config.transport === "http") {
    const httpServer = await startOnePasswordHttpServer(
      config,
      service,
      auditLogger,
      scriptRunner,
      unrestrictedRunner,
      unrestrictedApprovalManager,
    );
    console.error(`[mcp-1password-connect] listening on ${httpServer.url}`);

    const localhostHosts = new Set(["127.0.0.1", "::1", "localhost"]);
    if (!localhostHosts.has(config.httpHost)) {
      console.error(
        `[mcp-1password-connect] WARNING: HTTP transport is bound to ${config.httpHost} without TLS. ` +
          `The bearer token is transmitted in plaintext. Use a TLS-terminating reverse proxy ` +
          `(nginx, Caddy, Traefik) or restrict to 127.0.0.1 for local use.`,
      );
    }

    const shutdown = async () => {
      recordDiagnosticAudit(config, auditLogger, "server_shutdown", "success", {
        ...processMetadata(config),
        reason: "signal",
        connectOnly: true,
      });
      await httpServer.close();
      await unrestrictedApprovalServer?.close();
      process.exit(0);
    };
    process.once("SIGINT", () => {
      void shutdown();
    });
    process.once("SIGTERM", () => {
      void shutdown();
    });
    return;
  }

  const server = createOnePasswordMcpServer(
    config,
    service,
    auditLogger,
    scriptRunner,
    unrestrictedRunner,
    unrestrictedApprovalManager,
  );
  const transport = new StdioServerTransport();
  let shuttingDown = false;
  const shutdown = async (reason: string) => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    recordDiagnosticAudit(config, auditLogger, "server_shutdown", "success", {
      ...processMetadata(config),
      reason,
      connectOnly: true,
    });
    await server.close();
    await unrestrictedApprovalServer?.close();
    process.exit(0);
  };
  process.once("SIGINT", () => {
    void shutdown("SIGINT");
  });
  process.once("SIGTERM", () => {
    void shutdown("SIGTERM");
  });
  installStdioShutdownHandler(process.stdin, async (reason) => {
    recordDiagnosticAudit(config, auditLogger, "stdio_closed", "success", {
      ...processMetadata(config),
      reason,
      connectOnly: true,
    });
    await shutdown(reason);
  });
  await server.connect(transport);
}

main().catch((error) => {
  if (error instanceof HelpError || error instanceof WorkspaceTrustHelpError) {
    console.error(error.message);
    process.exit(0);
  }
  console.error(`[mcp-1password-connect] fatal: ${errorMessage(error)}`);
  process.exit(1);
});
