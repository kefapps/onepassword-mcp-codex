import type { ServerConfig } from "./config.js";

export interface BackendCapabilities {
  vaultMutation: boolean;
  vaultDestructive: boolean;
  permissionRead: boolean;
  permissionMutation: boolean;
  environments: boolean;
  itemArchive: boolean;
  itemDelete: boolean;
}

export const SDK_CAPABILITIES = {
  supportedAuthModes: ["desktop", "service-account", "connect"],
  supportedTransports: ["stdio", "http"],
  supportedTools: [
    "sdk_capabilities",
    "password_generate",
    "password_generate_memorable",
    "password_read",
    "password_create",
    "password_update",
    "vault_list",
    "vault_get",
    "vault_create",
    "vault_update",
    "vault_delete",
    "group_get",
    "vault_permissions_get",
    "vault_permissions_grant_group",
    "vault_permissions_update_group",
    "vault_permissions_revoke_group",
    "item_search",
    "item_get_metadata",
    "item_create",
    "item_update",
    "item_archive",
    "item_delete",
    "environment_get_variables",
    "environment_get_variable",
    "environment_reveal_variable",
    "secret_reveal",
    "op_script_list",
    "op_script_reload_allowlists",
    "op_script_run",
    "op_unrestricted_run",
    "op_session_status",
    "op_session_reset",
  ],
  supportedPrompts: [
    "credential-rotation",
    "vault-audit",
    "environment-inspection",
    "generate-secure-password",
  ],
  supportedResources: [
    "onepassword://config",
    "onepassword://vaults",
    "onepassword://vaults/{vaultId}/items",
    "onepassword://vaults/{vaultId}/items/{itemId}/metadata",
    "onepassword://environments/{environmentId}/variables",
  ],
  unsupportedByOfficialJsSdkBeta: [
    "group_list",
    "group_create",
    "group_members_update",
    "user_list",
    "user_get",
    "user_suspend",
  ],
  notes: [
    "Desktop auth requires the 1Password desktop app beta with SDK integration enabled.",
    "Secrets are opaque by default. Plaintext reveal is disabled unless the server starts with --enable-secret-reveal=true.",
    "When a secret is needed only by a command or local script, prefer op_script_run with envSecretRefs instead of password_read reveal or secret_reveal; the server injects values into the child process without returning plaintext to the model.",
    "Password generator tools return new plaintext secrets only with a reason and generated-secret acknowledgement.",
    "Write, destructive, and permission mutation tools are separately gated behind startup flags; destructive and permission mutation calls require per-call acknowledgement.",
    "The allowlisted script runner is disabled unless the server starts with --enable-script-runner=true.",
    "The unrestricted script runner is disabled unless the server starts with --enable-unrestricted-script-runner=true. In that mode op_script_run ignores startup allowlists, accepts free-form shell commands after one local approval per MCP process, and still supports envSecretRefs injection.",
    "The script runner only uses startup-configured --script-runner-allowlist paths and --script-runner-allowlist-manifest trust anchors; their file contents can be reloaded on demand and stdout/stderr is withheld by default. Sensitive output requested without acknowledgement is rejected before the command is executed.",
    "The unrestricted runner is disabled unless the server starts with --enable-unrestricted-runner=true and configured roots. It accepts free-form shell commands only after explicit local session approval; the configured path is an approval scope, not an operating-system sandbox.",
    "HTTP transport is optional, local/single-user by design, validates browser Origin headers, bounds session lifetime/count, and requires OP_MCP_HTTP_BEARER_TOKEN unless explicitly disabled on localhost.",
    "Vault permission mutation is available only for group-based access because that is the surface exposed by the official JS SDK beta.",
    "1Password Environments are read-only at the moment because the official JS SDK beta only exposes variable retrieval.",
  ],
} as const;

export function backendCapabilities(config: ServerConfig): BackendCapabilities {
  if (config.authMode === "connect") {
    return {
      vaultMutation: false,
      vaultDestructive: false,
      permissionRead: false,
      permissionMutation: false,
      environments: false,
      itemArchive: false,
      itemDelete: true,
    };
  }

  return {
    vaultMutation: true,
    vaultDestructive: true,
    permissionRead: true,
    permissionMutation: true,
    environments: true,
    itemArchive: true,
    itemDelete: true,
  };
}

export function effectiveSupportedTools(config: ServerConfig): string[] {
  const capabilities = backendCapabilities(config);
  return SDK_CAPABILITIES.supportedTools.filter((tool) => {
    if (
      (tool === "password_create" ||
        tool === "password_update" ||
        tool === "item_create" ||
        tool === "item_update") &&
      !config.enableWrites
    ) {
      return false;
    }
    if (
      (tool === "vault_create" || tool === "vault_update") &&
      (!config.enableWrites || !capabilities.vaultMutation)
    ) {
      return false;
    }
    if (
      tool === "vault_delete" &&
      (!config.enableDestructiveActions || !capabilities.vaultDestructive)
    ) {
      return false;
    }
    if (
      (tool === "group_get" || tool === "vault_permissions_get") &&
      !capabilities.permissionRead
    ) {
      return false;
    }
    if (
      (tool === "vault_permissions_grant_group" ||
        tool === "vault_permissions_update_group" ||
        tool === "vault_permissions_revoke_group") &&
      (!config.enablePermissionMutation || !capabilities.permissionMutation)
    ) {
      return false;
    }
    if (
      (tool === "environment_get_variables" ||
        tool === "environment_get_variable" ||
        tool === "environment_reveal_variable") &&
      !capabilities.environments
    ) {
      return false;
    }
    if (
      tool === "item_archive" &&
      (!config.enableDestructiveActions || !capabilities.itemArchive)
    ) {
      return false;
    }
    if (
      tool === "item_delete" &&
      (!config.enableDestructiveActions || !capabilities.itemDelete)
    ) {
      return false;
    }
    if (
      (tool === "op_script_list" ||
        tool === "op_script_reload_allowlists" ||
        tool === "op_script_run" ||
        tool === "op_session_reset") &&
      !config.enableScriptRunner
    ) {
      return false;
    }
    if (tool === "op_unrestricted_run" && !config.enableUnrestrictedRunner) {
      return false;
    }
    return true;
  });
}
