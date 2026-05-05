# mcp-1password

> **Status: Public Beta**
>
> This package is under active development (v0.x). The API and CLI flags may change between minor versions. The underlying `@1password/sdk` dependency is also a beta release. Pin an exact version (`mcp-1password@x.y.z`) in production-like environments.

A [Model Context Protocol](https://modelcontextprotocol.io/) server that exposes 1Password to AI agents with **opaque-by-default secret handling**. Secrets are never revealed unless you explicitly opt in.

## Features

- Read and search vaults, items, and environments with secrets redacted by default.
- Create, update, archive, and delete items and vaults when write/destructive capabilities are enabled.
- Manage group permissions on vaults when permission mutation is enabled.
- Reveal plaintext secrets only on explicit request with a per-call acknowledgement.
- Generate plaintext passwords only with a reason and explicit acknowledgement.
- Run pre-approved scripts with injected 1Password CLI authentication.
- Use stdio by default, or a local/single-user HTTP transport protected by a bearer token.
- Write a JSONL audit log for sensitive actions at `~/.onepassword-mcp/audit.jsonl`.

## Requirements

- **Node.js >= 20.10**
- **1Password desktop app** for `--auth-mode=desktop`; this requires the 1Password beta channel with SDK integration enabled.
- **1Password CLI (`op`)** only when `--enable-script-runner=true`.

### Enable Desktop Integration

Desktop auth requires the 1Password beta channel and SDK integration:

1. In 1Password, switch to the beta channel: *Settings -> Updates -> Beta channel*.
2. Enable SDK integration: *Settings -> Developer -> Connect with 1Password SDKs*.

## Installation

```bash
# Public beta install
npm install -g mcp-1password@beta

# Run on demand without a global install
npx -y mcp-1password@beta --auth-mode=desktop --account="My Account"
```

During beta, prefer `mcp-1password@beta` or an exact version instead of relying on the default npm tag.

## Quick Start

### Claude Desktop (stdio Transport)

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "1password": {
      "command": "npx",
      "args": [
        "-y", "mcp-1password@beta",
        "--auth-mode=desktop",
        "--account=1Password account name or UUID"
      ]
    }
  }
}
```

### Service Account (CI / Headless)

```json
{
  "mcpServers": {
    "1password": {
      "command": "npx",
      "args": ["-y", "mcp-1password@beta", "--auth-mode=service-account"],
      "env": {
        "OP_SERVICE_ACCOUNT_TOKEN": "<service-account-token>"
      }
    }
  }
}
```

### HTTP Transport (Remote Agents)

```bash
OP_MCP_HTTP_BEARER_TOKEN="$(openssl rand -base64 32)" \
mcp-1password \
  --auth-mode=desktop \
  --account="My Account" \
  --transport=http
```

> **HTTP security:** The HTTP transport is designed for local/single-user use. The bearer token must be at least 16 characters, and `--http-require-bearer=false` is only allowed on localhost. If you bind the server to any interface other than `127.0.0.1`, put it behind a reverse proxy with TLS termination (nginx, Caddy, Traefik). For multi-user or public deployments, add a real upstream authorization layer such as OIDC/OAuth with client identity, scopes, and expiry.

## Configuration Reference

Every flag can also be set through an environment variable.

| Flag | Environment variable | Default | Description |
|---|---|---|---|
| `--auth-mode` | `OP_MCP_AUTH_MODE` | `desktop` | `desktop` or `service-account` |
| `--account` | `OP_MCP_ACCOUNT` | - | Account name or UUID, required in desktop mode |
| `--service-account-token` | `OP_SERVICE_ACCOUNT_TOKEN` | - | Token, required in service-account mode |
| `--enable-secret-reveal` | `OP_MCP_ENABLE_SECRET_REVEAL` | `false` | Allow plaintext secret reveal |
| `--enable-writes` | `OP_MCP_ENABLE_WRITES` | `false` | Allow item and vault creation/update |
| `--enable-destructive-actions` | `OP_MCP_ENABLE_DESTRUCTIVE_ACTIONS` | `false` | Allow archive and delete operations |
| `--enable-permission-mutation` | `OP_MCP_ENABLE_PERMISSION_MUTATION` | `false` | Allow vault permission changes |
| `--enable-script-runner` | `OP_MCP_ENABLE_SCRIPT_RUNNER` | `false` | Allow execution of allowlisted scripts |
| `--script-runner-allowlist` | `OP_MCP_SCRIPT_RUNNER_ALLOWLISTS` | - | Absolute path to an allowlist file; repeatable |
| `--script-runner-root` | `OP_MCP_SCRIPT_RUNNER_ROOTS` | - | Trusted workspace root; repeatable |
| `--op-cli-path` | `OP_MCP_OP_CLI_PATH` | `op` | Path to the `op` binary; must be absolute when the script runner is enabled |
| `--op-cli-auth-mode` | `OP_MCP_OP_CLI_AUTH_MODE` | `auto` | `auto`, `desktop`, `manual-session`, or `service-account` |
| `--transport` | `OP_MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `--http-host` | `OP_MCP_HTTP_HOST` | `127.0.0.1` | HTTP bind address |
| `--http-port` | `OP_MCP_HTTP_PORT` | `17337` | HTTP port |
| `--http-path` | `OP_MCP_HTTP_PATH` | `/mcp` | HTTP path prefix |
| `--http-require-bearer` | `OP_MCP_HTTP_REQUIRE_BEARER` | `true` when HTTP is enabled | Require `Authorization: Bearer` |
| - | `OP_MCP_HTTP_BEARER_TOKEN` | - | Bearer token required by default with `--transport=http`; minimum 16 characters |
| `--http-allowed-origin` | `OP_MCP_HTTP_ALLOWED_ORIGINS` | Localhost origins for the current port | Browser origins allowed for HTTP transport; strict `Origin` validation, repeatable flag, comma-separated env |
| `--http-max-sessions` | `OP_MCP_HTTP_MAX_SESSIONS` | `64` | Maximum active HTTP MCP sessions |
| `--http-session-idle-ms` | `OP_MCP_HTTP_SESSION_IDLE_MS` | `900000` | Idle HTTP session expiry |
| `--http-request-timeout-ms` | `OP_MCP_HTTP_REQUEST_TIMEOUT_MS` | `30000` | HTTP request timeout |
| `--audit-log-path` | `OP_MCP_AUDIT_LOG_PATH` | `~/.onepassword-mcp/audit.jsonl` | Audit log path |
| `--log-level` | `OP_MCP_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |

## Script Runner

The script runner lets agents invoke pre-approved shell commands with 1Password CLI authentication injected automatically. **Free-form shell execution is never accepted**; only commands defined in allowlist paths configured at startup can run. The contents of those startup-configured allowlist files can be reloaded on demand with `op_script_reload_allowlists`.

### Allowlist Format

Create a `.onepassword-mcp.json` file at the root of your project:

```json
{
  "version": 1,
  "workspaceRoot": ".",
  "commands": {
    "deploy-staging": {
      "description": "Deploy to staging",
      "command": "/usr/local/bin/deploy.sh",
      "args": ["--env", "staging"],
      "cwd": ".",
      "timeoutMs": 120000,
      "sensitiveOutput": false
    }
  }
}
```

- `command` must be an **absolute path** to an executable.
- The directory containing `command` is not automatically prepended to `PATH`. Use absolute paths in scripts, or configure `--op-cli-path` so the directory containing `op` can be injected.
- `sensitiveOutput: true` withholds stdout/stderr from the agent unless `returnOutput=true` is explicitly requested with reveal acknowledgement.
- `op_script_run` accepts an optional `envSecretRefs` object that maps environment variable names to `op://` references. The server resolves those references, injects only the values into the child process environment, and never returns or audits the plaintext values.
- `returnOutput=true` does not require startup secret reveal for ordinary output, but when `envSecretRefs` is provided or the command has `sensitiveOutput: true`, the call must include `acknowledgePlaintext: "I_UNDERSTAND_THIS_RETURNS_SECRET_PLAINTEXT"`. Returned stdout/stderr/error messages are redacted by exact secret value.
- After editing a startup-configured allowlist file, call `op_script_reload_allowlists` with a reason. If the edited file is invalid, the reload fails and the previous in-memory allowlist remains active.

### Agent Routing Guidance

When an agent needs a secret only to run a local command, it should not call `password_read` with `reveal=true` or `secret_reveal` first. Prefer this flow:

1. Call `op_script_list` for the current workspace.
2. Pick the allowlisted command that performs the operation.
3. Call `op_script_run` with `envSecretRefs`, mapping environment variable names to `op://` references.
4. Leave `returnOutput=false` unless command output is required.

This keeps the plaintext secret out of the model transcript while still letting the command receive it.

## Security Model

- **Secrets are opaque by default.** Item fields are returned with `valueState: "redacted"` unless `--enable-secret-reveal=true` is passed.
- **Plaintext reveal requires explicit consent.** Tools that return secrets require `acknowledgePlaintext: "I_UNDERSTAND_THIS_RETURNS_SECRET_PLAINTEXT"`.
- **Password generators return a new plaintext secret.** They require `reason` and `acknowledgePlaintext: "I_UNDERSTAND_THIS_RETURNS_GENERATED_SECRET_PLAINTEXT"`, and audit the action without logging the secret.
- **Destructive actions and permission mutations require per-call acknowledgement.** Use `acknowledgeDestructive: "I_UNDERSTAND_THIS_CAN_DELETE_1PASSWORD_DATA"` for archive/delete operations and `acknowledgePermissionMutation: "I_UNDERSTAND_THIS_CAN_CHANGE_1PASSWORD_PERMISSIONS"` for permissions.
- **Dangerous capabilities are opt-in and disabled by default**, including writes, destructive actions, permission mutation, secret reveal, and the script runner.
- **Every sensitive action is audited** to a JSONL file. Secret references and auth tokens are automatically redacted from logs.
- **The script runner uses `spawn` with `shell: false`**, so shell injection is not available. Commands must be allowlisted and use absolute paths.
- **Allowlist reloads are bounded and audited.** `op_script_reload_allowlists` only reloads allowlist file paths and trusted roots configured at startup, records the reload reason, and keeps the previous in-memory allowlist if validation fails.
- **Script secret injection is run-only.** `envSecretRefs` values are resolved in memory, injected into the allowlisted child process, redacted from returned output, and audited only by env var name, reference scheme, and reference hash.
- **Bearer token comparison uses `crypto.timingSafeEqual`** to reduce timing attack risk.
- **HTTP binds to localhost (`127.0.0.1`) by default.** It validates the `Origin` header, caps active sessions, expires idle sessions, and returns generic messages for server errors.
- **Resources and capabilities avoid sensitive local metadata.** Local paths, 1Password account names, HTTP host/port, and the `op` binary path are not exposed to MCP clients.
- **`errorMessage` for scripts with `sensitiveOutput: true` is withheld** unless `returnOutput=true` is explicitly requested.

## MCP Resource Notes

Resource URIs use the `onepassword://` scheme instead of `1password://`. Node.js URL parsing rejects schemes that start with a number, which breaks resource reads in practice.

## Development

```bash
npm run lint   # TypeScript type checking
npm test       # Test suite
npm run build  # Compile to dist/
```

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/). This project uses [release-please](https://github.com/googleapis/release-please) to automate CHANGELOG generation and version bumps.

### npm Publication

The `publish.yml` workflow uses npm Trusted Publishing through OIDC. It does not use a long-lived npm token (`NPM_TOKEN`, `NODE_AUTH_TOKEN`, or a 1Password secret) for publication.

npm-side prerequisites:

- package `mcp-1password` exists on npm and is associated with `kefapps/onepassword-mcp-codex`
- a GitHub Actions trusted publisher is configured for repository `kefapps/onepassword-mcp-codex`
- workflow filename: `publish.yml`

The GitHub workflow uses Node.js 24 and has the `id-token: write` permission required by npm to exchange the job OIDC identity for a short-lived publishing token. npm automatically generates provenance attestations when the package and GitHub repository are public.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) before opening a pull request.

Please report vulnerabilities privately instead of opening a public issue. See [SECURITY.md](./SECURITY.md).

## License

MIT
