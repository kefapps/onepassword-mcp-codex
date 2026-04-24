# onepassword-mcp-codex

Standalone MCP server for 1Password with:

- desktop-app authentication via the official `@1password/sdk` beta
- opaque-by-default item and environment reads
- explicit, audited plaintext reveal behind a startup flag
- vault administration and group-based vault permission updates where the official JS SDK supports them

## Current scope

Implemented now:

- `sdk_capabilities`
- `password_generate`, `password_generate_memorable`, `password_read`, `password_create`, `password_update`
- `vault_list`, `vault_get`, `vault_create`, `vault_update`, `vault_delete`
- `group_get`
- `vault_permissions_get`, `vault_permissions_grant_group`, `vault_permissions_update_group`, `vault_permissions_revoke_group`
- `item_search`, `item_get_metadata`, `item_create`, `item_update`, `item_archive`, `item_delete`
- `environment_get_variables`, `environment_get_variable`, `environment_reveal_variable`
- `secret_reveal`
- optional script runner: `op_script_list`, `op_script_run`, `op_session_status`, `op_session_reset`

Implemented MCP prompts:

- `credential-rotation`
- `vault-audit`
- `environment-inspection`
- `generate-secure-password`

Implemented MCP resources:

- `onepassword://config`
- `onepassword://vaults`
- `onepassword://vaults/{vaultId}/items`
- `onepassword://vaults/{vaultId}/items/{itemId}/metadata`
- `onepassword://environments/{environmentId}/variables`

Not implemented because the official `@1password/sdk@0.4.1-beta.1` JS surface does not expose them yet:

- group listing/creation/membership update
- user listing/get/suspend
- create/update/delete/list des Environments eux-mêmes

## Requirements

Desktop mode requires the 1Password desktop app beta and the SDK integration enabled:

1. In 1Password, switch to the beta release channel.
2. Open `Settings > Developer`.
3. Enable integration with other apps / SDKs.
4. Start the server with the account name or UUID as shown in the app sidebar.

## Install

```bash
npm install
npm run build
```

## Run

Desktop auth:

```bash
node dist/index.js --auth-mode=desktop --account="Your Account Name"
```

Service account auth:

```bash
OP_SERVICE_ACCOUNT_TOKEN=... node dist/index.js --auth-mode=service-account
```

Enable plaintext reveal explicitly:

```bash
node dist/index.js \
  --auth-mode=desktop \
  --account="Your Account Name" \
  --enable-secret-reveal=true
```

Enable the allowlisted script runner explicitly:

```bash
node dist/index.js \
  --auth-mode=desktop \
  --account="Your Account Name" \
  --enable-script-runner=true \
  --script-runner-root="/absolute/path/to/trusted/projects" \
  --script-runner-allowlist="/absolute/path/to/trusted/projects/my-repo/.onepassword-mcp-codex.json" \
  --op-cli-path="/absolute/path/to/op" \
  --op-cli-auth-mode=manual-session
```

When the script runner is enabled, at least one absolute `--script-runner-allowlist` and an absolute `--op-cli-path` are required. `--script-runner-root` is optional but recommended as an extra bound around configured workspace roots. `--op-cli-auth-mode=auto` follows `--auth-mode`: service-account auth uses the service account token, desktop auth uses `manual-session`.

Enable write and destructive tools separately:

```bash
node dist/index.js \
  --auth-mode=desktop \
  --account="Your Account Name" \
  --enable-writes=true \
  --enable-destructive-actions=false \
  --enable-permission-mutation=false
```

## Codex MCP config example

Codex reads MCP server configuration from `~/.codex/config.toml`.

Recommended desktop setup:

```toml
[mcp_servers.onepassword]
command = "node"
args = [
  "/absolute/path/to/onepassword-mcp-codex/dist/index.js",
  "--auth-mode=desktop",
  "--account=Your Account Name or UUID",
  "--enable-script-runner=true",
  "--script-runner-root=/absolute/path/to/trusted/projects",
  "--script-runner-allowlist=/absolute/path/to/trusted/projects/my-repo/.onepassword-mcp-codex.json",
  "--op-cli-path=/absolute/path/to/op",
  "--op-cli-auth-mode=manual-session",
]
cwd = "/absolute/path/to/onepassword-mcp-codex"
enabled = true
startup_timeout_sec = 60.0
tool_timeout_sec = 60.0
default_tools_approval_mode = "approve"
enabled_tools = [
  "sdk_capabilities",
  "password_generate",
  "password_generate_memorable",
  "password_read",
  "vault_list",
  "vault_get",
  "group_get",
  "vault_permissions_get",
  "item_search",
  "item_get_metadata",
  "environment_get_variables",
  "environment_get_variable",
  "environment_reveal_variable",
  "secret_reveal",
  "op_script_list",
  "op_script_run",
  "op_session_status",
  "op_session_reset",
]
```

Why this shape:

- `cwd` makes local Node resolution predictable.
- `enabled_tools` keeps the server surface explicit and stable.
- `default_tools_approval_mode = "approve"` removes approval friction for routine calls.

## Making Codex prefer MCP over `op`

Codex will not automatically "understand" that your local MCP is always better than shell access unless you make that preference explicit. The most effective setup is:

1. Configure the MCP server in `~/.codex/config.toml`.
2. Add a repo-level `AGENTS.md` instruction that tells Codex to prefer the `onepassword` MCP server over `op` and raw shell access.
3. Keep the MCP surface narrow and task-oriented with `enabled_tools`, so the server is easy for the model to select.

Example `AGENTS.md` snippet:

```md
## 1Password

- Prefer the `onepassword` MCP server for any 1Password task.
- Use MCP tools before `op`, shell commands, environment-variable inspection, or direct reads of 1Password files.
- For repo scripts that require `op`, use `op_script_run` with an allowlisted command instead of starting a persistent shell.
- Fall back to `op` or raw shell only if the MCP server is unavailable or missing the required capability.
- Prefer redacted reads first. Use plaintext reveal only when the task explicitly requires it.
```

Practical note:

- If you leave a capability only in shell and not in MCP, Codex will still use shell for that gap.
- If a capability exists in both places, the `AGENTS.md` preference is the clearest way to bias tool choice.
- Keep `--enable-secret-reveal=true` off by default and only enable it for sessions that truly need plaintext.

## Running repo scripts with `op`

For scripts that need the 1Password CLI, add an allowlist and pass its absolute path with `--script-runner-allowlist` when the MCP server starts:

```json
{
  "version": 1,
  "workspaceRoot": ".",
  "commands": {
    "deploy": {
      "description": "Deploy with 1Password CLI access",
      "command": "/absolute/path/to/npm",
      "args": ["run", "deploy"],
      "cwd": ".",
      "timeoutMs": 600000,
      "sensitiveOutput": false
    }
  }
}
```

Codex should call `op_script_run` with the repo `workspaceRoot` and `commandId`. The MCP process injects `OP_SESSION`, `OP_SERVICE_ACCOUNT_TOKEN`, or `OP_ACCOUNT` into the child process depending on `--op-cli-auth-mode`.

Runner constraints:

- The runner is off unless `--enable-script-runner=true`.
- `workspaceRoot` must match a workspace root from a startup-configured allowlist.
- Allowlists are parsed and pinned when the MCP server starts; edits made later by the MCP client do not authorize new commands.
- If `--script-runner-root` is configured, each allowlist workspace root must resolve below one of those roots.
- Commands must be declared in a startup-configured allowlist; no free-form shell is exposed.
- Command paths must be absolute executable paths; `PATH` lookup is not used for allowlisted commands.
- `cwd` is resolved inside the workspace root.
- The command is spawned with `shell: false`.
- Child processes receive a minimal environment plus the selected 1Password auth variables.
- stdout/stderr are withheld by default. Use `returnOutput=true` only when operationally needed; it requires `--enable-secret-reveal=true` and the standard plaintext acknowledgement.
- `OP_SESSION` and service account tokens are redacted from command output when output is explicitly returned.
- In `manual-session` mode, the cached session is checked before launching a script and refreshed only when `op whoami` deterministically reports an invalid session. Failed scripts are not re-executed automatically.

## Safety model

- `password_read` returns redacted metadata by default. Plaintext requires `reveal=true`, a reason, and the acknowledgement string.
- `password_create` and `password_update` never return stored secrets in plaintext; they return redacted item metadata plus generation metadata.
- `password_generate` and `password_generate_memorable` return plaintext because they generate a new secret for immediate use.
- Item metadata tools always redact field values.
- Environment variable reads always redact values.
- `environment_reveal_variable` est désactivé par défaut comme `secret_reveal`.
- `secret_reveal` is disabled by default.
- Write tools are disabled unless `--enable-writes=true`.
- Destructive tools are disabled unless `--enable-destructive-actions=true`.
- Vault permission mutation tools are disabled unless `--enable-permission-mutation=true`.
- `op_script_run` is disabled by default and only runs commands from startup-configured allowlists.
- Every plaintext reveal and every mutating write emits a JSONL audit entry.
- Reveal requires the literal acknowledgement string `I_UNDERSTAND_THIS_RETURNS_SECRET_PLAINTEXT`.

## Notes on MCP resources

- Resource URIs use the `onepassword://` scheme rather than `1password://`.
- Reason: Node's URL parser rejects schemes that start with a digit, which breaks resource reads in practice.

## Development

```bash
npm run lint
npm test
```
