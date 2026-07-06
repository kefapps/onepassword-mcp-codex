# Changelog

## [1.0.0](https://github.com/kefapps/onepassword-mcp-codex/compare/mcp-1password-v0.2.0...mcp-1password-v1.0.0) (2026-07-06)


### ⚠ BREAKING CHANGES

* **tools:** password_create and item_create are no longer registered MCP tools. Use item_request_create to create tracked placeholder items.

### Features

* **connect:** add short workspace trust cli ([f517748](https://github.com/kefapps/onepassword-mcp-codex/commit/f517748a69195a63953d3b4b5502f94a767849c5))
* **connect:** expose workspace command tools ([b35bb0f](https://github.com/kefapps/onepassword-mcp-codex/commit/b35bb0f9a33aaaeefe375f65c3f8769a3ab70702))
* **connect:** support local 1Password Connect backend ([2c9f0e1](https://github.com/kefapps/onepassword-mcp-codex/commit/2c9f0e15bc1e42f0d0f352b065b55a447d4f3859))
* **script-runner:** reload configured allowlists dynamically ([3bced12](https://github.com/kefapps/onepassword-mcp-codex/commit/3bced1205900a43bb5283b64230b8912e1d3669c))
* **script-runner:** support dynamic allowlist manifests ([5f3c982](https://github.com/kefapps/onepassword-mcp-codex/commit/5f3c98239d5d2a06031d4f8513a4d81388802e60))
* **tools:** add tracked secret request workflow ([a9a31ba](https://github.com/kefapps/onepassword-mcp-codex/commit/a9a31baaaf90a716264b2e788291079dcb9d9216))
* **tools:** require tracked item requests for creation ([b37c6fe](https://github.com/kefapps/onepassword-mcp-codex/commit/b37c6fe37de767b3ece4267507d1c1849438ad5a))
* **unrestricted-runner:** require approval for free-form commands ([cca70dc](https://github.com/kefapps/onepassword-mcp-codex/commit/cca70dc80f95e4fb0fdef6a3043c532bf9e9c4e5))


### Bug Fixes

* **audit:** sanitize non-enumerable and symbol-keyed properties ([8f21c6a](https://github.com/kefapps/onepassword-mcp-codex/commit/8f21c6a88eb739cfeb5e9c879ebf0f3ae542ffc5))
* **capabilities:** report runtime-gated tools ([bc79b4a](https://github.com/kefapps/onepassword-mcp-codex/commit/bc79b4a41a58d4e0ffeefc0393e1a634da5f3c4c))
* **connect:** harden secret reference parsing ([0b051d3](https://github.com/kefapps/onepassword-mcp-codex/commit/0b051d3fe443cbfd2207385f8729f5edc520bb34))
* **connect:** preserve document item categories ([71c9dee](https://github.com/kefapps/onepassword-mcp-codex/commit/71c9dee05d9f8e6e8f6e8bd05abc7ba13488b842))
* **connect:** report only runtime workspace tools ([3717847](https://github.com/kefapps/onepassword-mcp-codex/commit/371784792bec8b7255c4f9f3c18a91a77e61c638))
* **connect:** suggest trust command for untrusted workspaces ([2126c15](https://github.com/kefapps/onepassword-mcp-codex/commit/2126c157a2dc8bccf3efc94343ffe65f6d64a804))
* **connect:** support field title secret references ([c324f46](https://github.com/kefapps/onepassword-mcp-codex/commit/c324f463528b43dc951b19cd6e773fd616911844))
* **connect:** use public item delete API ([410cc2f](https://github.com/kefapps/onepassword-mcp-codex/commit/410cc2f5b820e7307540a450fa15db097f664eb8))
* **error:** normalize MCP error serialization ([39a7977](https://github.com/kefapps/onepassword-mcp-codex/commit/39a7977db820716fbd02f2fba6c8dce8c1dbbdef))
* **errors:** drop untrusted cause to prevent secret leakage ([68d81b6](https://github.com/kefapps/onepassword-mcp-codex/commit/68d81b6f92551952dba260c06049a851b1209266))
* **http:** bypass Host check on wildcard binds without allowlist ([f5912ef](https://github.com/kefapps/onepassword-mcp-codex/commit/f5912ef27b608f47562592e65800171523c4bfba))
* **http:** validate Host header against listen address ([b6e6863](https://github.com/kefapps/onepassword-mcp-codex/commit/b6e6863f3c9292496182b521d7a870c8dbcd2cc0))
* **op-runner:** redact secret values case-insensitively ([330bc60](https://github.com/kefapps/onepassword-mcp-codex/commit/330bc60ddda2c44f6e8f07716156d5d0baf12467))
* **review:** address Connect and runner findings ([47b92db](https://github.com/kefapps/onepassword-mcp-codex/commit/47b92db8295620fdf27f3b7067094757616a95b4))
* **script-runner:** harden secret env validation ([0855fe3](https://github.com/kefapps/onepassword-mcp-codex/commit/0855fe3a91e2febc9a7e7f428c01109193d86b65))
* **script-runner:** skip invalid manifest allowlists ([4db9a87](https://github.com/kefapps/onepassword-mcp-codex/commit/4db9a87e6a47fafde73888067f867ee739e42bd4))
* **script-runner:** withhold missing-ack output without rejecting runs ([29b9bc9](https://github.com/kefapps/onepassword-mcp-codex/commit/29b9bc96eced88e7d97bb2d62b916c20b47e9b34))
* **security:** override audited transitive dependencies ([c8c2528](https://github.com/kefapps/onepassword-mcp-codex/commit/c8c2528577521c604d8bb5097d6116006c4f0d5e))
* **security:** override vulnerable ip-address dependency ([061a44c](https://github.com/kefapps/onepassword-mcp-codex/commit/061a44cf5711d68e9d2a41bb3c96c76b35117374))
* **security:** override vulnerable transitive packages ([8aff450](https://github.com/kefapps/onepassword-mcp-codex/commit/8aff450c38c70c2c464542560e52d2ee10621065))
* **security:** redact secret references case-insensitively ([9dfdc66](https://github.com/kefapps/onepassword-mcp-codex/commit/9dfdc6620db8f8d25db2b71b45ee7de266d9a907))
* **security:** require acknowledgement for approval bypass ([1e922ff](https://github.com/kefapps/onepassword-mcp-codex/commit/1e922fff91bf11b01fdb4ea3aca9b659fb3c6a8e))
* **security:** share unrestricted approval manager defaults ([5ed26cd](https://github.com/kefapps/onepassword-mcp-codex/commit/5ed26cd40db7292f65338e557a5316eedc61a9d6))


### Documentation

* add public contribution and security policy ([41f1996](https://github.com/kefapps/onepassword-mcp-codex/commit/41f199607b514e575cea6face6e6e14feee21cae))

## [0.2.0](https://github.com/kefapps/onepassword-mcp-codex/compare/mcp-1password-v0.1.0...mcp-1password-v0.2.0) (2026-04-28)


### Features

* **http:** add configurable bearer-protected transport settings ([a2bae83](https://github.com/kefapps/onepassword-mcp-codex/commit/a2bae83cf15ad15a7d24535b04fe3219e7c8daab))
* **script-runner:** support multi-root allowlists and hardened op auth ([49fd593](https://github.com/kefapps/onepassword-mcp-codex/commit/49fd593537aef97638b50073b74059d9acae8374))


### Bug Fixes

* **security:** remediate beta audit findings ([5509c23](https://github.com/kefapps/onepassword-mcp-codex/commit/5509c23d329e207128254f28841af9c7e9f50318))
* **security:** remove version and feature flags from unauthenticated /healthz endpoint ([750c092](https://github.com/kefapps/onepassword-mcp-codex/commit/750c0922f57a4b093eb49a53d0557c89a8a1bd67))
* **security:** warn on startup when HTTP transport is bound to non-localhost interface without TLS ([c5eab76](https://github.com/kefapps/onepassword-mcp-codex/commit/c5eab762764e89fa471aabfdbb07856ca9cfd9e0))
* **security:** withhold errorMessage for sensitive script output when returnOutput=false ([4deacd4](https://github.com/kefapps/onepassword-mcp-codex/commit/4deacd49242be05d2dc77710cc33cb549b8bff1a))


### Documentation

* add AGENTS.md with conventional commits policy and version bump rules ([f762a40](https://github.com/kefapps/onepassword-mcp-codex/commit/f762a4059236c8005296e93f506a28d13ff41d53))
* align release policy and distribution guidance ([e2a3a7e](https://github.com/kefapps/onepassword-mcp-codex/commit/e2a3a7e66df4f3c0905073e064f7c0488c19abbd))
* keep repository documentation in English ([70c9f23](https://github.com/kefapps/onepassword-mcp-codex/commit/70c9f237fe0c1f50ce6fbdd033fc7b4cdcdff513))
* rewrite README with beta disclaimer, TLS warning, and full configuration reference ([33b0e7d](https://github.com/kefapps/onepassword-mcp-codex/commit/33b0e7de1b483d46cfe0ed34b14401886c3a1c4f))

## Changelog

All notable changes to this project will be documented in this file.

See [Conventional Commits](https://www.conventionalcommits.org/) for commit guidelines.
This file is auto-generated by [release-please](https://github.com/googleapis/release-please).
