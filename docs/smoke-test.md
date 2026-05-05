# Real Smoke Test

This smoke test is meant to run against a real 1Password account before beta publication. It exercises the built MCP server through stdio and local HTTP, while keeping destructive behavior opt-in.

## Safety Rules

- Use a disposable test vault, not a production vault.
- Keep HTTP bound to localhost.
- Do not paste real secrets into the terminal output.
- Enable reveal, writes, destructive actions, permission mutation, and script runner only for the sections you intentionally want to validate.
- Permission mutation must use a disposable test group and vault.

## Command

```bash
npm run smoke:real
```

The npm script builds `dist/` first, then runs `scripts/smoke-test.mjs`.

## Minimum Read-Only Run

Desktop auth:

```bash
OP_MCP_ACCOUNT="Your 1Password account name or UUID" \
npm run smoke:real
```

Service account auth:

```bash
OP_MCP_SMOKE_AUTH_MODE=service-account \
OP_SERVICE_ACCOUNT_TOKEN="<service-account-token>" \
npm run smoke:real
```

This validates:

- MCP stdio connection.
- Tool listing.
- `onepassword://config` without local path/account leaks.
- `sdk_capabilities`.
- `vault_list` against real 1Password access.
- `password_generate` with generated-secret acknowledgement.
- Local HTTP `/healthz`, invalid `Origin` rejection, bearer-authenticated MCP connection.

## Item Metadata And Redacted Password Read

Add a disposable item from a disposable vault:

```bash
OP_MCP_ACCOUNT="Your account" \
OP_MCP_SMOKE_VAULT_ID="<test-vault-id>" \
OP_MCP_SMOKE_ITEM_ID="<test-item-id>" \
npm run smoke:real
```

This additionally validates:

- `item_search`.
- `item_get_metadata` with redacted fields.
- `password_read` with `reveal=false` by default.

## Explicit Plaintext Reveal

Reveal via secret reference:

```bash
OP_MCP_ACCOUNT="Your account" \
OP_MCP_SMOKE_ENABLE_REVEAL=true \
OP_MCP_SMOKE_SECRET_REFERENCE="op://vault/item/field" \
npm run smoke:real
```

Or reveal a password field from the item configured above:

```bash
OP_MCP_ACCOUNT="Your account" \
OP_MCP_SMOKE_ENABLE_REVEAL=true \
OP_MCP_SMOKE_VAULT_ID="<test-vault-id>" \
OP_MCP_SMOKE_ITEM_ID="<test-item-id>" \
npm run smoke:real
```

The script verifies that reveal only works with `I_UNDERSTAND_THIS_RETURNS_SECRET_PLAINTEXT`. It never prints the revealed value.

## Writes

```bash
OP_MCP_ACCOUNT="Your account" \
OP_MCP_SMOKE_ENABLE_WRITES=true \
OP_MCP_SMOKE_VAULT_ID="<test-vault-id>" \
npm run smoke:real
```

This creates a disposable item named `mcp-smoke-<timestamp>` and updates its password.

## Destructive Cleanup

```bash
OP_MCP_ACCOUNT="Your account" \
OP_MCP_SMOKE_ENABLE_WRITES=true \
OP_MCP_SMOKE_ENABLE_DESTRUCTIVE=true \
OP_MCP_SMOKE_VAULT_ID="<test-vault-id>" \
npm run smoke:real
```

This archives only the disposable item created by the same smoke run, using `I_UNDERSTAND_THIS_CAN_DELETE_1PASSWORD_DATA`.

## Permission Mutation

```bash
OP_MCP_ACCOUNT="Your account" \
OP_MCP_SMOKE_ENABLE_PERMISSION_MUTATION=true \
OP_MCP_SMOKE_CONFIRM_PERMISSION_MUTATION=I_UNDERSTAND_THIS_CAN_CHANGE_1PASSWORD_PERMISSIONS \
OP_MCP_SMOKE_VAULT_ID="<test-vault-id>" \
OP_MCP_SMOKE_GROUP_ID="<test-group-id>" \
npm run smoke:real
```

This grants and then revokes `READ_ITEMS` for the test group. Override with `OP_MCP_SMOKE_PERMISSION_NAMES=READ_ITEMS,CREATE_ITEMS` if needed.

## Script Runner

Create a disposable allowlist command first, then run:

```bash
OP_MCP_ACCOUNT="Your account" \
OP_MCP_SMOKE_SCRIPT_ROOT="/absolute/path/to/test/workspace" \
OP_MCP_SMOKE_SCRIPT_ALLOWLIST="/absolute/path/to/test/workspace/.onepassword-mcp.json" \
OP_MCP_SMOKE_SCRIPT_COMMAND_ID="<allowlisted-command-id>" \
OP_MCP_SMOKE_OP_CLI_PATH="/absolute/path/to/op" \
npm run smoke:real
```

Use `OP_MCP_SMOKE_SCRIPT_ALLOWLIST_MANIFEST="/absolute/path/to/allowlists.json"` instead of `OP_MCP_SMOKE_SCRIPT_ALLOWLIST` to validate manifest-based startup configuration. This validates `op_script_list` and `op_script_run` without returning command output.

## Pass Criteria

- The command exits with status 0.
- Every step prints `ok`.
- No plaintext secret appears in terminal output.
- `npm audit --audit-level=moderate`, `npm run lint`, and `npm test` are still green before publication.
