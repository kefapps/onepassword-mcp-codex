# Agent Instructions - mcp-1password

## Commits And Versioning

This project uses [Conventional Commits](https://www.conventionalcommits.org/) and [release-please](https://github.com/googleapis/release-please) to automate the CHANGELOG and version bumps. **Every commit must follow this format**, without exception.

### Format

```
<type>(<optional scope>): <short description>

<optional body>

<optional footer>
```

### Types And Version Impact

| Type | Version bump | Appears in CHANGELOG | Usage |
|---|---|---|---|
| `feat` | **minor** (0.x.0) | Features | User-visible feature |
| `fix` | **patch** (0.0.x) | Bug Fixes | Bug fix |
| `fix(security)` | **patch** | Bug Fixes, `security` scope | Security fix; use this scope systematically |
| `security` | not guaranteed | Security | Reserved for exceptional/manual changelog entries; prefer `fix(security):` to guarantee a patch bump |
| `perf` | **patch** | Performance Improvements | Measurable performance improvement |
| `docs` | none | Documentation | Documentation-only changes |
| `refactor` | none | hidden | Refactor without behavior change |
| `test` | none | hidden | Test-only changes |
| `chore` | none | hidden | Maintenance work such as build, config, or dependencies |
| `ci` | none | hidden | CI/CD workflow changes |
| `revert` | **patch** | Reverts | Revert of a previous commit |

**Breaking change -> major (x.0.0):** add `!` after the type (`feat!:`, `fix!:`) or add a footer `BREAKING CHANGE: <description>`.

### Mandatory Rules

1. **Never use generic messages.** Avoid `fix: bug`, `chore: update`, or `feat: add feature`. The description must be specific and fit on one line.
2. **The scope is optional but recommended** for targeted changes: `fix(http-server):`, `feat(script-runner):`, `fix(security):`.
3. **One commit = one intent.** Do not mix a fix and a refactor in the same commit.
4. **Automatic merge commits** from release-please or Dependabot are bot-owned; do not imitate them manually.
5. **Use `fix(security):`** for every security-related fix, even small ones. This guarantees a coherent patch bump; with release-please, the `security` scope remains visible in the CHANGELOG entry even if the section remains `Bug Fixes`.

### Good Examples

```
feat(script-runner): support multiple workspaceRoots in a single allowlist file

fix(security): withhold errorMessage for sensitive script output when returnOutput=false

fix(http-server): return 400 instead of 500 on malformed JSON body

docs: add TLS warning and HTTP configuration reference to README

chore: add release-please configuration for automated versioning

test(op-runner): add coverage for SIGKILL grace period on timeout

refactor(config): extract flag parsing helpers into dedicated functions

perf(service): cache SDK client across requests to avoid reconnection overhead
```

### Bad Examples

```
# Too vague
fix: bug fix
feat: new feature
update: stuff

# Wrong type
chore: fix security issue   # must be fix(security):
feat: update README         # must be docs:

# Multiple intents in one commit
feat: add vault search and fix pagination bug  # split into two commits
```

## Release Pipeline

The pipeline works as follows:

1. Commits on `main` trigger the `release-please.yml` workflow.
2. release-please analyzes commits since the last tag and creates or updates a `chore(release): vX.Y.Z` PR.
3. Merging that PR creates a Git tag and GitHub Release.
4. The GitHub Release triggers `publish.yml`, which publishes to npm through Trusted Publishing/OIDC with `--tag beta`.

**Never bump the version in `package.json` manually.** That is exclusively handled by release-please through its release PR.
**Never add a raw GitHub `NPM_TOKEN` secret or any long-lived npm token.** Nominal publication uses npm Trusted Publishing through the OIDC identity of the GitHub `publish.yml` workflow. The publish workflow must remain on a Node/npm version compatible with Trusted Publishing.

## Change Scope

- Stay within files relevant to the task. Do not reformat or refactor unrelated code.
- Do not edit `CHANGELOG.md` directly; it is managed by release-please.
- Do not edit `.release-please-manifest.json` directly; it is updated by release-please.
