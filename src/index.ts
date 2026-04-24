#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { FileAuditLogger } from "./audit.js";
import { HelpError, parseConfig } from "./config.js";
import { createOnePasswordMcpServer } from "./server.js";
import { SdkOnePasswordService } from "./service.js";

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
  const server = createOnePasswordMcpServer(config, service, auditLogger);
  const transport = new StdioServerTransport();

  console.error(
    `[onepassword-mcp-codex] auth=${config.authMode} reveal=${config.enableSecretReveal} writes=${config.enableWrites} destructive=${config.enableDestructiveActions} permissions=${config.enablePermissionMutation} scriptRunner=${config.enableScriptRunner} opAuth=${config.opCliAuthMode} audit=${config.auditLogPath}`,
  );

  await server.connect(transport);
}

main().catch((error) => {
  if (error instanceof HelpError) {
    console.error(error.message);
    process.exit(0);
  }
  console.error("[onepassword-mcp-codex] fatal:", error);
  process.exit(1);
});
