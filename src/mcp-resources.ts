import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SDK_CAPABILITIES } from "./capabilities.js";
import type { ServerConfig } from "./config.js";
import { redactItem, redactItemOverview } from "./redaction.js";
import type { OnePasswordService } from "./service.js";

function jsonResource(uri: string, data: unknown) {
  return {
    contents: [
      {
        uri,
        mimeType: "application/json",
        text: JSON.stringify(data, null, 2),
      },
    ],
  };
}

export function registerOnePasswordResources(
  server: McpServer,
  config: ServerConfig,
  service: OnePasswordService,
): void {
  server.registerResource(
    "1password-config",
    "onepassword://config",
    {
      title: "1Password MCP Config",
      description: "Non-secret runtime configuration and capability summary for this server.",
      mimeType: "application/json",
    },
    async () =>
      jsonResource("onepassword://config", {
        authMode: config.authMode,
        account: config.account,
        secretRevealEnabled: config.enableSecretReveal,
        writesEnabled: config.enableWrites,
        destructiveActionsEnabled: config.enableDestructiveActions,
        permissionMutationEnabled: config.enablePermissionMutation,
        scriptRunnerEnabled: config.enableScriptRunner,
        scriptRunnerRoots: config.scriptRunnerRoots,
        opCliAuthMode: config.opCliAuthMode,
        opCliPath: config.opCliPath,
        integrationName: config.integrationName,
        integrationVersion: config.integrationVersion,
        capabilities: SDK_CAPABILITIES,
      }),
  );

  server.registerResource(
    "1password-vaults",
    "onepassword://vaults",
    {
      title: "1Password Vaults",
      description: "Browse the vaults visible to the active 1Password integration.",
      mimeType: "application/json",
    },
    async () => {
      const vaults = await service.vaultList({ decryptDetails: false });
      return jsonResource("onepassword://vaults", {
        vaults: vaults.map((vault) => ({
          ...vault,
          createdAt: vault.createdAt.toISOString(),
          updatedAt: vault.updatedAt.toISOString(),
        })),
      });
    },
  );

  const vaultItemsTemplate = new ResourceTemplate("onepassword://vaults/{vaultId}/items", {
    list: async () => {
      const vaults = await service.vaultList({ decryptDetails: false });
      return {
        resources: vaults.map((vault) => ({
          name: `1password-vault-items-${vault.id}`,
          uri: `onepassword://vaults/${vault.id}/items`,
          title: `Items in ${vault.title}`,
          description: `Redacted item overviews for vault ${vault.title}.`,
          mimeType: "application/json",
        })),
      };
    },
    complete: {
      vaultId: async (value) => {
        const vaults = await service.vaultList({ decryptDetails: false });
        return vaults
          .map((vault) => vault.id)
          .filter((candidate) => candidate.toLowerCase().includes(value.toLowerCase()));
      },
    },
  });

  server.registerResource(
    "1password-vault-items",
    vaultItemsTemplate,
    {
      title: "1Password Vault Items",
      description: "Redacted item overviews for one vault.",
      mimeType: "application/json",
    },
    async (_uri, variables) => {
      const vaultId = String(variables.vaultId);
      const items = await service.itemList(vaultId, {
        type: "ByState",
        content: {
          active: true,
          archived: true,
        },
      });
      return jsonResource(`onepassword://vaults/${vaultId}/items`, {
        vaultId,
        items: items.map(redactItemOverview),
      });
    },
  );

  const environmentVariablesTemplate = new ResourceTemplate(
    "onepassword://environments/{environmentId}/variables",
    {
      list: undefined,
    },
  );

  server.registerResource(
    "1password-environment-variables",
    environmentVariablesTemplate,
    {
      title: "1Password Environment Variables",
      description: "Redacted variables for one 1Password Environment.",
      mimeType: "application/json",
    },
    async (_uri, variables) => {
      const environmentId = String(variables.environmentId);
      const environment = await service.environmentGetVariables(environmentId);
      return jsonResource(`onepassword://environments/${environmentId}/variables`, {
        environmentId,
        totalMatched: environment.variables.length,
        variables: environment.variables.map((variable) => ({
          name: variable.name,
          masked: variable.masked,
          valueState: "redacted",
        })),
      });
    },
  );

  const itemMetadataTemplate = new ResourceTemplate(
    "onepassword://vaults/{vaultId}/items/{itemId}/metadata",
    {
      list: undefined,
      complete: {
        vaultId: async (value) => {
          const vaults = await service.vaultList({ decryptDetails: false });
          return vaults
            .map((vault) => vault.id)
            .filter((candidate) => candidate.toLowerCase().includes(value.toLowerCase()));
        },
      },
    },
  );

  server.registerResource(
    "1password-item-metadata",
    itemMetadataTemplate,
    {
      title: "1Password Item Metadata",
      description: "Redacted metadata for one 1Password item.",
      mimeType: "application/json",
    },
    async (_uri, variables) => {
      const vaultId = String(variables.vaultId);
      const itemId = String(variables.itemId);
      const item = await service.itemGet(vaultId, itemId);
      return jsonResource(`onepassword://vaults/${vaultId}/items/${itemId}/metadata`, {
        item: redactItem(item),
      });
    },
  );
}
