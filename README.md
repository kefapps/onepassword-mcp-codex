# mcp-1password

> **⚠ Status : Public Beta**
>
> Ce package est en développement actif (v0.x). L'API et les flags CLI peuvent changer entre versions mineures. Le SDK sous-jacent `@1password/sdk` est lui-même une version beta. Épinglez une version exacte (`mcp-1password@x.y.z`) dans les environnements de production.

Un serveur [Model Context Protocol](https://modelcontextprotocol.io/) qui expose 1Password aux agents d'IA — avec une **gestion des secrets opaque par défaut**. Les secrets ne sont jamais révélés sauf opt-in explicite.

## Fonctionnalités

- Lire et rechercher coffres, items, et environnements (secrets redactés par défaut)
- Créer, mettre à jour, archiver, et supprimer items et coffres (`--enable-writes`, `--enable-destructive-actions`)
- Gérer les permissions de groupe sur les coffres (`--enable-permission-mutation`)
- Révéler les secrets en clair sur demande, avec acquittement explicite (`--enable-secret-reveal`)
- Exécuter des scripts pré-approuvés avec auth 1Password CLI injectée (`--enable-script-runner`)
- Transports : stdio (défaut) ou HTTP avec auth bearer token
- Journal d'audit complet de toutes les actions sensibles (JSONL, `~/.local/share/mcp-1password/audit.jsonl`)

## Prérequis

- **Node.js ≥ 20.10**
- **Application 1Password desktop** (pour `--auth-mode=desktop`) — nécessite la version beta avec l'intégration SDK activée
- **1Password CLI (`op`)** — uniquement requis avec `--enable-script-runner=true`

### Activer l'intégration desktop (mode desktop uniquement)

1. Dans 1Password, passer sur le canal beta : *Paramètres → Mises à jour → Canal bêta*
2. Activer l'intégration desktop : *Paramètres → Développeur → Se connecter avec les SDK 1Password*

## Installation

```bash
# Installation globale npm
npm install -g mcp-1password

# Ou exécution à la demande sans installation globale
npx mcp-1password --auth-mode=desktop --account="Mon Compte"
```

## Démarrage rapide

### Claude Desktop (transport stdio)

Modifier `~/Library/Application\ Support/Claude/claude_desktop_config.json` :

```json
{
  "mcpServers": {
    "1password": {
      "command": "npx",
      "args": [
        "-y", "mcp-1password",
        "--auth-mode=desktop",
        "--account=Nom ou UUID du compte 1Password"
      ]
    }
  }
}
```

### Compte de service (CI / headless)

```json
{
  "mcpServers": {
    "1password": {
      "command": "npx",
      "args": ["-y", "mcp-1password", "--auth-mode=service-account"],
      "env": {
        "OP_SERVICE_ACCOUNT_TOKEN": "<votre-token-de-compte-de-service>"
      }
    }
  }
}
```

### Transport HTTP (agents distants)

```bash
OP_MCP_HTTP_BEARER_TOKEN="$(openssl rand -base64 32)" \
mcp-1password \
  --auth-mode=desktop \
  --account="Mon Compte" \
  --transport=http \
  --http-port=3010
```

> **⚠ Sécurité — pas de TLS intégré :** Le transport HTTP utilise du HTTP en clair. Si vous liez le serveur à une interface autre que `127.0.0.1`, le bearer token transite en clair. Utilisez un reverse proxy avec terminaison TLS (nginx, Caddy, Traefik) pour toute exposition non-localhost.

## Référence de configuration

Tous les flags peuvent aussi être définis via des variables d'environnement.

| Flag | Variable d'env | Défaut | Description |
|---|---|---|---|
| `--auth-mode` | `OP_MCP_AUTH_MODE` | `desktop` | `desktop` ou `service-account` |
| `--account` | `OP_MCP_ACCOUNT` | — | Nom ou UUID du compte (requis en mode desktop) |
| `--service-account-token` | `OP_SERVICE_ACCOUNT_TOKEN` | — | Token (requis en mode service-account) |
| `--enable-secret-reveal` | `OP_MCP_ENABLE_SECRET_REVEAL` | `false` | Autoriser la révélation en clair des secrets |
| `--enable-writes` | `OP_MCP_ENABLE_WRITES` | `false` | Autoriser la création et mise à jour d'items/coffres |
| `--enable-destructive-actions` | `OP_MCP_ENABLE_DESTRUCTIVE_ACTIONS` | `false` | Autoriser la suppression et l'archivage |
| `--enable-permission-mutation` | `OP_MCP_ENABLE_PERMISSION_MUTATION` | `false` | Autoriser la modification des permissions de coffre |
| `--enable-script-runner` | `OP_MCP_ENABLE_SCRIPT_RUNNER` | `false` | Autoriser l'exécution de scripts allowlistés |
| `--script-runner-allowlist` | `OP_MCP_SCRIPT_RUNNER_ALLOWLISTS` | — | Chemin absolu vers un fichier d'allowlist (répétable) |
| `--script-runner-root` | `OP_MCP_SCRIPT_RUNNER_ROOTS` | — | Racine de workspace de confiance (répétable) |
| `--op-cli-path` | `OP_MCP_OP_CLI_PATH` | `op` | Chemin vers le binaire op CLI (doit être absolu si script runner activé) |
| `--op-cli-auth-mode` | `OP_MCP_OP_CLI_AUTH_MODE` | `auto` | `auto`, `desktop`, `manual-session`, `service-account` |
| `--transport` | `OP_MCP_TRANSPORT` | `stdio` | `stdio` ou `http` |
| `--http-host` | `OP_MCP_HTTP_HOST` | `127.0.0.1` | Adresse de bind pour le transport HTTP |
| `--http-port` | `OP_MCP_HTTP_PORT` | `3010` | Port pour le transport HTTP |
| `--http-path` | `OP_MCP_HTTP_PATH` | `/mcp` | Préfixe de chemin pour le transport HTTP |
| `--http-require-bearer` | `OP_MCP_HTTP_REQUIRE_BEARER` | `true` si HTTP | Exiger l'en-tête `Authorization: Bearer` |
| `--audit-log-path` | `OP_MCP_AUDIT_LOG_PATH` | `~/.local/share/mcp-1password/audit.jsonl` | Chemin du journal d'audit |
| `--log-level` | `OP_MCP_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

## Script runner

Le script runner permet aux agents d'invoquer des commandes shell pré-approuvées avec l'authentification 1Password CLI injectée automatiquement. **Aucune commande shell libre n'est acceptée** — seules les commandes définies dans un fichier d'allowlist configuré au démarrage sont exécutables.

### Format du fichier d'allowlist

Créer un fichier `.onepassword-mcp.json` à la racine de votre projet :

```json
{
  "version": 1,
  "workspaceRoot": ".",
  "commands": {
    "deploy-staging": {
      "description": "Déployer en environnement de staging",
      "command": "/usr/local/bin/deploy.sh",
      "args": ["--env", "staging"],
      "cwd": ".",
      "timeoutMs": 120000,
      "sensitiveOutput": false
    }
  }
}
```

- `command` doit être un **chemin absolu** vers un exécutable
- `sensitiveOutput: true` empêche stdout/stderr d'être retournés à l'agent, sauf si `returnOutput=true` est explicitement demandé avec l'acquittement de révélation

## Modèle de sécurité

- **Secrets opaques par défaut.** Tous les champs d'items sont retournés avec `valueState: "redacted"` sauf si `--enable-secret-reveal=true` est passé.
- **La révélation en clair requiert un consentement explicite.** Les outils qui retournent des secrets nécessitent `acknowledgePlaintext: "I_UNDERSTAND_THIS_RETURNS_SECRET_PLAINTEXT"`.
- **Toutes les capacités dangereuses sont opt-in et désactivées par défaut** (écriture, actions destructives, mutation de permissions, révélation de secrets, script runner).
- **Chaque action sensible est journalisée** dans un fichier JSONL. Les références de secrets et tokens d'auth sont automatiquement redactés des logs.
- **Le script runner utilise `spawn` avec `shell: false`** — aucune injection shell n'est possible. Les commandes doivent être allowlistées et utiliser des chemins absolus.
- **La comparaison du bearer token utilise `crypto.timingSafeEqual`** pour prévenir les attaques temporelles.
- **Le transport HTTP se bind sur localhost (`127.0.0.1`) par défaut.** Un bind non-localhost émet un warning TLS au démarrage.
- **`errorMessage` des scripts avec `sensitiveOutput: true` est retenu** sauf si `returnOutput=true` est explicitement demandé.

## Notes sur les ressources MCP

Les URI de ressources utilisent le schéma `onepassword://` plutôt que `1password://`. Le parser URL de Node.js rejette les schémas commençant par un chiffre, ce qui casse la lecture des ressources en pratique.

## Développement

```bash
npm run lint   # Vérification de types TypeScript
npm test       # Suite de tests
npm run build  # Compilation vers dist/
```

Les commits doivent suivre [Conventional Commits](https://www.conventionalcommits.org/) — ce projet utilise [release-please](https://github.com/googleapis/release-please) pour automatiser la génération du CHANGELOG et les bumps de version.

## Changelog

Voir [CHANGELOG.md](./CHANGELOG.md).

## Licence

MIT
