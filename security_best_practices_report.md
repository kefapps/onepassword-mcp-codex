# Security Review: mcp-1password

Audit date: 2026-04-28
Status: all findings from the 2026-04-28 beta-readiness audit have been remediated for the documented local/single-user MCP deployment model.

## Executive Summary

The MCP now has no open Critical or High code-level findings from this audit. The previous blockers around Streamable HTTP origin validation, missing per-call acknowledgements, unbounded sessions, raw HTTP errors, script runner `PATH` behavior, runtime metadata exposure, plaintext generator friction, and dependency drift have been addressed with tests and documentation.

The remaining deployment boundary is intentional: HTTP is still a local/single-user transport protected by a shared bearer token. It is acceptable for beta publication when documented this way. Public or multi-user exposure still needs an upstream authorization layer with identity, expiry, audience validation, and scopes.

## External References

- MCP Streamable HTTP transport security warning: https://modelcontextprotocol.io/specification/draft/basic/transports
- MCP security best practices, including DNS rebinding and local MCP compromise risks: https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- MCP authorization guidance: https://modelcontextprotocol.io/docs/tutorials/security/authorization
- Local `security-best-practices` skill guidance was used for Node HTTP error handling, dependency hygiene, DoS limits, command execution, and token handling review.

## Remediation Status

| ID | Previous severity | Status | Evidence |
|---|---:|---|---|
| SEC-1 | High | Fixed | HTTP `Origin` allowlist helpers and enforcement: `src/http-server.ts:133-165`, `src/http-server.ts:223-226`; tests: `src/http-server.test.ts:107-137`. |
| SEC-2 | High | Fixed by product boundary and safer config | HTTP remains local/single-user by design. Bearer tokens must be at least 16 chars and no-bearer mode is localhost-only: `src/config.ts:383-395`; README documents TLS and upstream auth requirements: `README.md:88`, `README.md:112-117`. |
| SEC-3 | High | Fixed | Destructive tools require `reason` and `acknowledgeDestructive`: `src/server.ts:1019-1040`, `src/server.ts:1363-1410`; permission mutation tools require `reason` and `acknowledgePermissionMutation`: `src/server.ts:1079-1210`; tests: `src/server.test.ts:635-698`. |
| SEC-4 | Medium | Fixed | Active HTTP sessions are capped and refreshed with idle expiry: `src/http-server.ts:195-215`, `src/http-server.ts:257-265`; request/header timeouts configured: `src/http-server.ts:309-310`; tests: `src/http-server.test.ts:222-240`. |
| SEC-5 | Medium | Fixed | Generic internal HTTP errors are returned instead of raw exception messages: `src/http-server.ts:297-304`. |
| SEC-6 | Medium | Fixed | Script runner no longer prepends the allowlisted command directory to `PATH`; only the configured absolute `op` directory is prepended: `src/op-runner.ts:256-261`; README documents this: `README.md:146-148`. |
| SEC-7 | Medium | Fixed | MCP config resource now exposes counts/booleans instead of account, local roots, allowlist paths, HTTP host/port, or `op` path: `src/mcp-resources.ts:33-54`; README documents the reduced metadata surface: `README.md:161`. |
| SEC-8 | Medium | Fixed | Password generators now require `reason` and generated-secret acknowledgement and audit without logging plaintext: `src/server.ts:552-620`; tests: `src/server.test.ts:534-572`; README documents the acknowledgement string: `README.md:154`. |
| SEC-9 | Low | Fixed | Runtime dependencies are exact-pinned during beta: `package.json:41-44`; lockfile updated. |
| SEC-10 | Low | Fixed | Malformed JSON and oversized bodies map to 400/413 instead of generic 500: `src/http-server.ts:101-123`; test: `src/http-server.test.ts:143-167`. |

## Positive Controls Still In Place

- Secrets are redacted by default; plaintext reveal requires startup opt-in plus acknowledgement.
- Writes, destructive actions, permission mutations, and script runner are disabled by default.
- Script execution uses startup-pinned allowlists, absolute commands, `spawn(..., shell: false)`, timeouts, output limits, and withheld sensitive output.
- Audit logs avoid secret values and are written to a `0600` file in a `0700` directory.
- `/healthz` returns only `{ ok: true }`.

## Residual Guidance

Do not market HTTP as a public multi-user API. For remote/team deployment, keep this server behind a reverse proxy that provides TLS plus real authorization, or keep it bound to localhost and tunnel from a trusted client. The shared bearer token is now safer for local beta use, but it is not user identity.

## Verification Performed

- `git diff --check`: passed.
- `npm run lint`: passed.
- `npm test`: 67 passing tests.
- `npm audit --audit-level=moderate`: 0 vulnerabilities.
- `npm pack --dry-run`: package builds and packs successfully, 31 files.
