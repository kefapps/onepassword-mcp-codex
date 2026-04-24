# Security Review: onepassword-mcp-codex

## Executive Summary

Remediation update: the high-risk runner findings have been addressed in code. The script runner now requires configured trusted roots, requires an absolute `op` path when enabled, injects a minimal child environment, withholds stdout/stderr by default, and requires plaintext reveal acknowledgement before returning output. Mutating, destructive, and permission mutation tools are now behind separate startup gates.

The remaining risks are mostly operational: only configure trusted script roots, keep dangerous tools disabled unless needed, and treat any script allowed to run with `op` auth as trusted code.

## Original Review Summary

The MCP has several good defaults: plaintext reveal is off by default, reveal tools require an acknowledgement string, redacted metadata is used for normal reads, password generation uses `crypto.randomInt`, runner commands use `spawn(..., shell: false)`, and command output is bounded.

The main security concern is the new script runner. It turns the MCP into a broker that can inject 1Password CLI auth into child processes. That is useful, but it must be treated as a privileged execution boundary. Today the allowlist is repo-local, but the client controls `workspaceRoot`, the child inherits the MCP process environment, and stdout/stderr are returned to the model. Those choices make accidental or malicious secret exfiltration realistic.

`npm audit --audit-level=moderate` found no dependency vulnerabilities.

## High Severity

### SEC-1: `workspaceRoot` is client-controlled, so the script allowlist is not a strong security boundary

Status: remediated. `--enable-script-runner=true` now requires at least one absolute `--script-runner-allowlist`, and allowlists are parsed and pinned when the MCP server starts. Optional `--script-runner-root` values further constrain the configured workspace roots.

Impact: A client that can point the MCP at an attacker-controlled directory can execute commands from that directory with 1Password CLI auth injected.

Evidence:

- `op_script_run` accepts any non-empty `workspaceRoot` string from the MCP client: `src/server.ts:347-354`.
- The runner resolves and reads `.onepassword-mcp-codex.json` from that arbitrary path: `src/op-runner.ts:480-484`.
- The selected command is then spawned with the authenticated environment: `src/op-runner.ts:440-447`.

Risk:

The allowlist protects against free-form command strings only if the allowlist file itself is trusted. In a Codex-style environment, the model often has filesystem write access through other tools; it could create or modify an allowlist and then call `op_script_run`.

Recommended fix:

- Add server-level `--script-runner-allowlist=/absolute/file`.
- Reject `workspaceRoot` values that do not match a startup-configured allowlist workspace root.
- Prefer startup-loaded command definitions for high-risk environments.

### SEC-2: Child scripts inherit the full MCP process environment plus 1Password auth

Status: remediated. Child processes now receive a minimal environment plus the selected 1Password auth variables.

Impact: Any allowlisted script and every subprocess it starts can read all inherited environment variables, including the injected 1Password session or service account token.

Evidence:

- `createChildEnvironment` starts from `{ ...process.env }`: `src/op-runner.ts:172-190`.
- Service-account mode injects `OP_SERVICE_ACCOUNT_TOKEN`: `src/op-runner.ts:315-327`.
- Manual-session mode injects `OP_SESSION`: `src/op-runner.ts:344-349`.
- That environment is passed directly to the child process: `src/op-runner.ts:442-446`.

Risk:

Even if the intended script only calls `op`, a compromised dependency, package script, postinstall hook, or nested process can exfiltrate the token. The runner also forwards unrelated host secrets from the MCP process environment.

Recommended fix:

- Build a minimal child environment instead of copying all `process.env`.
- Preserve only required keys such as `PATH`, `HOME`, `SHELL`, locale vars, and the selected `OP_*` auth keys.
- Document that `op_script_run` is only safe for trusted scripts.
- Consider using a short-lived per-run token where possible and clearing session state after sensitive commands.

### SEC-3: Command output can leak secrets back into the transcript

Status: remediated. `op_script_run` now withholds stdout/stderr by default; `returnOutput=true` requires `--enable-secret-reveal=true` plus the plaintext acknowledgement.

Impact: A script can print secrets, and the MCP will return stdout/stderr to the model unless the allowlist author correctly marks the command as sensitive.

Evidence:

- `op_script_run` returns `stdout`, `stderr`, and `errorMessage` in structured content: `src/server.ts:394-409`.
- `commandOutputText` includes stdout/stderr in the visible tool response: `src/server.ts:261-290`.
- `sensitiveOutput` is checked from one allowlist read: `src/server.ts:357-372`.
- The runner reads the allowlist again before executing, creating a TOCTOU gap: `src/op-runner.ts:431-438`.

Risk:

The MCP cannot know whether an arbitrary script output contains a 1Password secret. A false `sensitiveOutput=false` setting, stale allowlist check, or malicious script can leak plaintext into the chat and logs.

Recommended fix:

- Default `op_script_run` to returning only exit status and bounded tail output unless `returnOutput=true` is explicitly requested.
- Treat all script output as sensitive when OP auth is injected, or require the plaintext acknowledgement for any stdout/stderr return.
- Load the allowlist once per run and pass the resolved command object into execution to remove the TOCTOU gap.

### SEC-4: Mutating/destructive 1Password tools are exposed by default

Status: remediated. Write, destructive, and permission mutation tools are registered only when their corresponding startup flags are enabled.

Impact: Any MCP client granted these tools can create, update, delete, archive, or change permissions in 1Password without an additional server-side safety gate.

Evidence:

- Password/item writes: `password_create`, `password_update`, `item_create`, `item_update`: `src/server.ts:631-795` and `src/server.ts:1113-1204`.
- Destructive operations: `vault_delete`, `item_archive`, `item_delete`: `src/server.ts:880-898` and `src/server.ts:1206-1258`.
- Permission mutations: `vault_permissions_grant_group`, `vault_permissions_update_group`, `vault_permissions_revoke_group`: `src/server.ts:936-1057`.

Risk:

The README recommends `default_tools_approval_mode = "approve"` and enabling many tools. That makes model or prompt mistakes more consequential. The reveal flag protects plaintext reads, but there is no equivalent write/destructive flag.

Recommended fix:

- Add server flags such as `--enable-writes`, `--enable-destructive`, and `--enable-permission-mutation`, all defaulting to false.
- Register dangerous tools only when the matching flag is enabled.
- Add explicit acknowledgement fields for vault delete, item delete, and permission changes.

## Medium Severity

### SEC-5: Audit logs may contain sensitive metadata and are not permission-hardened

Status: partially remediated. Audit files are opened with `0600` and `O_NOFOLLOW` where supported; audit strings now redact `op://` references and known OP token patterns.

Evidence:

- `FileAuditLogger` uses `appendFileSync` without setting restrictive file mode or checking symlinks: `src/audit.ts:14-23`.
- Secret references and operational reasons are logged for reveals: `src/server.ts:583-587`, `src/server.ts:603-609`, `src/server.ts:1324-1328`.
- `config.ts` creates the audit directory but does not enforce directory or file mode: `src/config.ts:163-166`.

Risk:

Secret references, item IDs, environment variable names, reasons, and error messages can be sensitive. A local symlink or permissive file mode could leak audit metadata or append to an unexpected file.

Recommended fix:

- Create audit directories with mode `0700` and files with mode `0600`.
- Consider redacting `op://` references and sensitive object titles in audit records.
- Avoid logging raw `String(error)` unless passed through a sanitizer.

### SEC-6: `opCliPath` defaults to PATH lookup

Status: remediated for the runner. `--enable-script-runner=true` now requires an absolute `--op-cli-path`.

Evidence:

- The default CLI path is the string `"op"`: `src/config.ts:158`.
- That value is used for `op whoami` and `op signin --raw`: `src/op-runner.ts:358-386`.

Risk:

If the MCP process runs with a poisoned `PATH`, the runner could execute a malicious `op` binary. This is mostly a local compromise / misconfiguration risk, but this MCP handles high-value auth.

Recommended fix:

- Prefer requiring an absolute `--op-cli-path`.
- Resolve and validate it once at startup.
- Document that `PATH` should not include project-local writable directories before system binary directories.

### SEC-7: `op-cli-auth-mode=auto` can unexpectedly choose service-account mode

Status: remediated. Auto mode now follows `--auth-mode` instead of switching merely because a service account token exists in the environment.

Evidence:

- Auto mode chooses `service-account` whenever `serviceAccountToken` is present: `src/op-runner.ts:153-156`.
- `serviceAccountToken` can come from inherited environment variables: `src/config.ts:131-134`.

Risk:

A user may configure desktop/manual script auth but run the MCP in an environment containing `OP_SERVICE_ACCOUNT_TOKEN`. Scripts would then receive broader or different credentials than expected.

Recommended fix:

- Make script-runner auth mode explicit when `--enable-script-runner=true`.
- Or make `auto` prefer desktop/manual unless `--auth-mode=service-account` is also selected.

## Low Severity / Design Tradeoffs

### SEC-8: New generated passwords are returned in plaintext

Evidence:

- `password_generate` and `password_generate_memorable` return plaintext directly: `src/server.ts:454-503`.

Risk:

This is intentional, but generated secrets can land in transcripts. Safer workflows should generate-and-store without exposing the value.

Recommended fix:

- Add a `password_create` mode that generates and stores without returning plaintext, and recommend it for persisted credentials.

### SEC-9: Redacted reads still expose operational metadata

Evidence:

- `password_read` without reveal returns item title, field ID/type, and secret reference metadata: `src/server.ts:555-575`.
- Resources expose vault IDs, item overviews, environment variable names, and masked state: `src/mcp-resources.ts:46-140`.

Risk:

This is expected for an inspection MCP, but in some environments item titles, variable names, and secret references are sensitive.

Recommended fix:

- Add an optional `--metadata-minimal=true` mode for stricter environments.
- Avoid echoing full `op://` references unless needed.

## Positive Findings

- Plaintext reveal is disabled by default and enforced server-side: `src/server.ts:165-170`.
- Reveal calls require a reason and exact acknowledgement string: `src/server.ts:539-550`, `src/server.ts:1310-1315`, `src/server.ts:1355-1363`.
- Runner uses `spawn` with `shell: false`: `src/op-runner.ts:215-219`.
- Runner applies timeouts and output limits: `src/op-runner.ts:222-255`.
- Password generation uses `crypto.randomInt`, not `Math.random`: `src/passwords.ts:1`, `src/passwords.ts:54-77`.
- Dependency audit reports no moderate-or-higher vulnerabilities.

## Recommended Operational Defaults

1. Configure explicit `--script-runner-allowlist` files and keep optional `--script-runner-root` bounds as narrow as possible.
2. Keep `--enable-writes`, `--enable-destructive-actions`, and `--enable-permission-mutation` disabled unless the session explicitly needs them.
3. Prefer `op_script_run` without `returnOutput`; use `returnOutput=true` only when the output itself is required.
4. Keep `--enable-secret-reveal=false` by default.
5. Use an absolute `--op-cli-path` owned by the system or trusted package manager.
