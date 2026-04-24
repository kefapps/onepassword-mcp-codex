import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SECRET_REVEAL_ACK } from "./constants.js";

function userPrompt(text: string) {
  return {
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text,
        },
      },
    ],
  };
}

export function registerOnePasswordPrompts(server: McpServer): void {
  server.registerPrompt(
    "credential-rotation",
    {
      title: "Credential Rotation",
      description:
        "Guide a safe password rotation workflow using redacted reads first, then explicit reveal only if required.",
      argsSchema: {
        vaultId: z.string().optional(),
        itemId: z.string().optional(),
        field: z.string().optional(),
      },
    },
    async ({ vaultId, itemId, field }) =>
      userPrompt(
        [
          "Rotate a 1Password credential safely.",
          vaultId && itemId
            ? `Target item: vaultId=\`${vaultId}\`, itemId=\`${itemId}\`.`
            : "If the target item is unknown, start by using `vault_list` and `item_search` to identify it.",
          `Use \`password_read\` with \`reveal=false\`${field ? ` and \`field=${field}\`` : ""} to inspect the current password field without exposing plaintext.`,
          "Generate a replacement with `password_generate` or `password_generate_memorable`.",
          `Write the new credential with \`password_update\`${field ? ` targeting field \`${field}\`` : ""}.`,
          `Only if plaintext is explicitly required, call \`password_read\` with \`reveal=true\`, a concrete \`reason\`, and the acknowledgement string \`${SECRET_REVEAL_ACK}\`.`,
          "Keep the response focused on what changed, where it was stored, and whether any plaintext reveal happened.",
        ].join("\n"),
      ),
  );

  server.registerPrompt(
    "vault-audit",
    {
      title: "Vault Audit",
      description:
        "Audit a vault using metadata and redacted item reads, without revealing secrets by default.",
      argsSchema: {
        vaultId: z.string().optional(),
        query: z.string().optional(),
      },
    },
    async ({ vaultId, query }) =>
      userPrompt(
        [
          "Audit 1Password vault contents without exposing secrets.",
          vaultId
            ? `Work inside vault \`${vaultId}\`.`
            : "If no vault is specified, start with `vault_list` and ask or infer which vault matters.",
          `Use \`item_search\`${query ? ` with \`query=${query}\`` : ""} to identify candidate items.`,
          "Use `item_get_metadata` for detailed inspection. Treat all fields and notes as redacted metadata unless explicit plaintext reveal is required.",
          "Report risks, stale credentials, missing tags, confusing titles, duplicate-looking entries, and any obvious rotation candidates.",
          "Do not reveal plaintext secrets during the audit unless the user explicitly asks for them.",
        ].join("\n"),
      ),
  );

  server.registerPrompt(
    "environment-inspection",
    {
      title: "Environment Inspection",
      description:
        "Inspect a 1Password Environment in redacted mode, and reveal one variable only if there is an explicit operational reason.",
      argsSchema: {
        environmentId: z.string(),
        variableName: z.string().optional(),
      },
    },
    async ({ environmentId, variableName }) =>
      userPrompt(
        [
          `Inspect the 1Password Environment \`${environmentId}\`.`,
          variableName
            ? `Start with \`environment_get_variable\` for \`${variableName}\` to inspect it in redacted form.`
            : "Start with `environment_get_variables` to enumerate the available variables in redacted form.",
          "Summarize names, masking state, and what is present or missing.",
          `Only if plaintext is explicitly needed for debugging or recovery, use \`environment_reveal_variable\` with a concrete \`reason\` and the acknowledgement string \`${SECRET_REVEAL_ACK}\`.`,
          "Be explicit when you are switching from redacted inspection to plaintext reveal.",
        ].join("\n"),
      ),
  );

  server.registerPrompt(
    "generate-secure-password",
    {
      title: "Generate Secure Password",
      description:
        "Choose the right password helper, generate a value, and optionally store it in 1Password.",
      argsSchema: {
        memorable: z.boolean().optional(),
        vaultId: z.string().optional(),
        title: z.string().optional(),
      },
    },
    async ({ memorable, vaultId, title }) =>
      userPrompt(
        [
          "Generate a secure password using the 1Password MCP helpers.",
          memorable
            ? "Use `password_generate_memorable` unless the user changes the requirement."
            : "Use `password_generate` unless the user explicitly prefers a memorable passphrase.",
          "Explain the tradeoff briefly: random passwords maximize entropy density; memorable passphrases are easier to type correctly.",
          vaultId && title
            ? `After generation, store it with \`password_create\` in vault \`${vaultId}\` with title \`${title}\`, unless the user wants generation-only.`
            : "If the user also wants storage, use `password_create` after generation.",
          "Do not reveal an existing stored password unless the user explicitly asks for plaintext.",
        ].join("\n"),
      ),
  );
}
