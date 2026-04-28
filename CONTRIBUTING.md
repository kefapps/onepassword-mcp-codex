# Contributing

Thanks for helping improve `mcp-1password`.

This project is a public beta for a security-sensitive MCP server. Contributions are welcome, but changes are reviewed conservatively because the server can interact with real 1Password data.

## Ways To Contribute

- Open an issue for bugs, documentation gaps, or design questions.
- Open a pull request for focused fixes and improvements.
- Use discussions in issues before starting broad behavior changes, new write-capable tools, or changes to security boundaries.

## Pull Request Rules

- Keep each pull request focused on one intent.
- Follow the existing TypeScript style and local patterns.
- Add or update tests for behavior changes.
- Do not include real vault names, item names, secret references, tokens, or personal account metadata in tests, logs, screenshots, or examples.
- Do not edit generated release files manually: `CHANGELOG.md`, `.release-please-manifest.json`, and version bumps in `package.json` are managed by release-please.
- Use Conventional Commits for commit titles. Security fixes must use `fix(security): ...`.

## Required Verification

Run these before requesting review when possible:

```bash
npm run lint
npm test
npm pack --dry-run
```

For changes touching real 1Password behavior, also document whether `docs/smoke-test.md` needs to be run and which mode is affected.

## Review And Merge Policy

All changes to `main` must go through a pull request. The repository owner and code owner, `@JulienJBO`, is the only required approver for merges.

External contributors can open issues and pull requests. Maintainer approval is required before any pull request can merge.

## Security-Sensitive Changes

Security-sensitive changes include:

- plaintext secret reveal behavior
- write, destructive, or permission mutation tools
- script runner execution and allowlist behavior
- HTTP transport authentication, origin checks, sessions, and errors
- audit logging and redaction
- dependency or release workflow changes

For these areas, prefer smaller pull requests and include a clear security rationale in the description.

