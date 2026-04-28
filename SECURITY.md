# Security Policy

## Supported Versions

`mcp-1password` is currently in public beta. Security fixes target the latest published beta version and `main`.

| Version | Supported |
|---|---|
| `0.x` latest beta | Yes |
| Older beta versions | Best effort |

## Reporting A Vulnerability

Please do not open a public issue for a vulnerability that could expose secrets, bypass capability gates, weaken script execution controls, or compromise 1Password data.

Report security issues through GitHub private vulnerability reporting or by contacting the maintainer privately. Include:

- affected version or commit
- reproduction steps
- expected and actual behavior
- impact assessment
- any logs with secrets removed

You should receive an initial acknowledgement within 72 hours when possible.

## Security Boundaries

The server is designed for local/single-user MCP use by default.

- Secrets are redacted by default.
- Plaintext reveal, writes, destructive actions, permission mutation, and script execution are opt-in.
- HTTP transport is local/single-user and bearer-token protected; public or multi-user exposure requires an upstream authorization layer with TLS, identity, scopes, and expiry.

See the README security model for operational guidance.

