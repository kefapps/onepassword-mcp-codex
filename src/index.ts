#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { FileAuditLogger } from "./audit.js";
import { HelpError, parseConfig } from "./config.js";
import { startOnePasswordHttpServer } from "./http-server.js";
import { DefaultOpScriptRunner } from "./op-runner.js";
import { createOnePasswordMcpServer } from "./server.js";
import { SdkOnePasswordService } from "./service.js";
import {
  DefaultUnrestrictedRunner,
  UnrestrictedApprovalManager,
  startUnrestrictedApprovalServer,
} from "./unrestricted-runner.js";

function readPackageVersion(): string {
  const currentDir = dirname(fileURLToPath(import.meta.url));
  const packageJsonPath = join(currentDir, "..", "package.json");
  const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8")) as {
    version: string;
  };
  return packageJson.version;
}

async function main(): Promise<void> {
  const config = parseConfig(process.argv.slice(2), readPackageVersion());
  const auditLogger = new FileAuditLogger(config.auditLogPath);
  const service = new SdkOnePasswordService(config);
  const scriptRunner = new DefaultOpScriptRunner(config);
  const unrestrictedApprovalManager = new UnrestrictedApprovalManager(
    config.unrestrictedRunnerApprovalTtlMs,
  );
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
    `[mcp-1password] transport=${config.transport} auth=${config.authMode} reveal=${config.enableSecretReveal} writes=${config.enableWrites} destructive=${config.enableDestructiveActions} permissions=${config.enablePermissionMutation} scriptRunner=${config.enableScriptRunner} scriptAllowlists=${config.scriptRunnerAllowlistPaths.length} scriptAllowlistManifests=${config.scriptRunnerAllowlistManifestPaths.length} unrestrictedRunner=${config.enableUnrestrictedRunner} unrestrictedRoots=${config.unrestrictedRunnerRoots.length} unrestrictedApproval=${config.unrestrictedRunnerRequireSessionApproval} opAuth=${config.opCliAuthMode} audit=${config.auditLogPath}`,
  );
  if (unrestrictedApprovalServer) {
    console.error(
      `[mcp-1password] unrestricted runner approval listening on ${unrestrictedApprovalServer.url}`,
    );
  }

  if (config.transport === "http") {
    const httpServer = await startOnePasswordHttpServer(
      config,
      service,
      auditLogger,
      scriptRunner,
      unrestrictedRunner,
    );
    console.error(`[mcp-1password] listening on ${httpServer.url}`);

    const localhostHosts = new Set(["127.0.0.1", "::1", "localhost"]);
    if (!localhostHosts.has(config.httpHost)) {
      console.error(
        `[mcp-1password] WARNING: HTTP transport is bound to ${config.httpHost} without TLS. ` +
        `The bearer token is transmitted in plaintext. Use a TLS-terminating reverse proxy ` +
        `(nginx, Caddy, Traefik) or restrict to 127.0.0.1 for local use.`,
      );
    }

    const shutdown = async () => {
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
  );
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  if (error instanceof HelpError) {
    console.error(error.message);
    process.exit(0);
  }
  console.error("[mcp-1password] fatal:", error);
  process.exit(1);
});
