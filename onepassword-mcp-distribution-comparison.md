# Comparatif des projets 1Password/MCP trouvés

Date d’observation: **27/04/2026 (local)**.  
Sources principales: registre npm (`npm view`, `npm search`) + README des packages.

## Projets comparés

- `onepassword-mcp-server` (package npm public, projet actif)
- `@executor-js/plugin-onepassword` (plugin executor, non MCP server)
- `@1password/pulumi-onepassword` (provider Pulumi, infra-as-code)
- `@simcubeltd/pulumi-onepassword` (provider Pulumi, infra-as-code)
- `@cdktf-providers/1password-onepassword` (provider CDKTF/Terraform)
- `mcp-1password` (ton projet, localement en `0.1.0`)

> Remarque: d’autres résultats de recherche (`react-native-onepassword`, etc.) sont des SDK/SDKs mobiles ou libs app, donc non comparables à ton objectif “serveur MCP installable”.

Autres paquets trouvés mais explicitement non comparables à ton cas:

- `onepassword` (paquet historique/utilitaire 1Password, pas MCP)
- `onepassword-mcp-server` est le seul concurrent MCP immédiatement pertinent.
- `react-native-onepassword` (plugin mobile)
- `@1password/pulumi-onepassword`, `@simcubeltd/pulumi-onepassword` (providers Pulumi)
- `@cdktf-providers/1password-onepassword` (provider CDKTF/Terraform)

## 1) Bilan rapide

| Projet | Type | But principal | Installation | Forces | Limites |
|---|---|---|---|---|---|
| `onepassword-mcp-server` | MCP server | Gestion lecture/écriture vaults via CLI + workflows avec approbation | `npx onepassword-mcp-server` | Versionnage actif (0.3.6, updates récentes), sécurité basée sur éllicitation utilisateur, install simple | Moins de surface (liste/étalonnage plus limitée que ton projet), mode auth orienté service-account, pas de transport HTTP visible dans la doc, pas de script-runner propre à la session |
| `@executor-js/plugin-onepassword` | Plugin API | Source secrets pour Executor | Intégration via `@executor/sdk` (lib) | Intéressant pour Executor, support desktop + service account | Pas un serveur MCP, non plug-and-play avec les clients MCP |
| `@1password/pulumi-onepassword` | Provider IaC | Déploiement de ressources Pulumi | Dépend de Pulumi | Intégré dans l’écosystème 1Password officiel | N’est pas un outil d’assistance opérationnelle MCP |
| `@simcubeltd/pulumi-onepassword` | Provider IaC | Provisioning/Pulumi | Dépend de Pulumi | Alternatif communautaire | Même scope infra, pas MCP |
| `@cdktf-providers/1password-onepassword` | Provider IaC | Terraform/CDKTF | Dépend de CDKTF | Écosystème terraform | Pas MCP |
| `mcp-1password` | MCP server | Opérations complètes 1Password + script runner contrôlé + transports multiples | `npx mcp-1password` / `npm install -g mcp-1password` + `mcp-1password ...`; HTTP: `--transport=http` + bearer | Très orienté sécurité (secrets opaques par défaut, révélé uniquement avec ack explicite), contrôle d’installation stricte des scripts (`allowlist`), audit JSONL, ressources/ prompts, transports stdio+HTTP singleton, auth desktop + service account | Encore jeune (v0.1.0, pas de maintainer large), et dépend d’auth desktop beta côté SDK |

## 2) Comparatif détaillé vs `onepassword-mcp`

### `onepassword-mcp-server` vs `mcp-1password`

- **Sécurité des secrets**  
- `onepassword-mcp-server`: ellicitation par demande + whitelist d’items, option `DANGEROUSLY_SKIP_ELICITATIONS=true` (danger explicit).  
- `mcp-1password`: redaction stricte par défaut, révélation explicite via flag de démarrage + `I_UNDERSTAND...`, sans bypass gratuit.

- **Modèle auth**  
- `onepassword-mcp-server`: orienté service-account dans la doc et variables d’environnement; requis côté CLI.  
- `mcp-1password`: support `desktop` (SDK desktop) + `service-account`, utile quand on veut fonctionner avec le client desktop.

- **Surface d’API**  
- `onepassword-mcp-server`: outils de base list/get/create/share + whitelist + toolgroups (`readonly/write`).  
- `mcp-1password`: surface plus large (mots de passe, vaults, items CRUD, permissions groupe, environnements, reveal, script runner, prompts, resources).

- **Ops & installation**  
  - Les deux supportent une exécution facile par `npx`;  
- `mcp-1password` ajoute transport HTTP local `--transport=http` + token bearer, pratique pour un seul daemon partagé.

- **Contrainte de contexte utilisateur**  
- `onepassword-mcp-server` expose des confirmations fréquentes (élucitation).  
- `mcp-1password` privilégie explicitement l’intégration client MCP (flags de capacité, session status, audit, tool gating).

### `@executor-js/plugin-onepassword`

- C’est un composant de l’écosystème **Executor**, pas un serveur MCP.  
- Utile si tu utilises Executor, pas idéal pour ton objectif distribution MCP “standard”.

### Providers Pulumi/CDKTF

- Spécialisés “infrastructure as code” (create/update resources), pas interaction assistante.
- Très bons pour provisioning automatisé, pas pour une surface LLM/MCP.

## 3) Verdict

- **Meilleure option “distribution MCP standard + sécurité opérationnelle” aujourd’hui**: `mcp-1password` (vu ton besoin de contrôle de scripts, audit, transport HTTP et usage client).
- **Option la plus proche “déjà mature + simple”**: `onepassword-mcp-server`, surtout si ton cas d’usage est uniquement CRUD/lecture 1Password via service account et que tu ne veux pas le layer script runner.
- **Option complémentaire**: `@executor-js/plugin-onepassword` si tu veux un bridge de secrets dans une stack Executor.

## 4) Scoring

Échelle utilisée: 1 = faible, 5 = fort.

| Projet | Sécurité | Fonctionnalités | Intégration client MCP | Installation/ops | Maturité | Ajustement à ton besoin | Total / 30 |
|---|---:|---:|---:|---:|---:|---:|
| `mcp-1password` | 5 | 5 | 5 | 3 | 2 | 5 | **25** |
| `onepassword-mcp-server` | 4 | 3 | 2 | 4 | 4 | 3 | **20** |
| `@executor-js/plugin-onepassword` | 3 | 2 | 1 | 3 | 1 | 2 | **12** |
| `@1password/pulumi-onepassword` | 3 | 2 | 1 | 2 | 3 | 1 | **12** |
| `@simcubeltd/pulumi-onepassword` | 2 | 2 | 1 | 2 | 2 | 1 | **10** |
| `@cdktf-providers/1password-onepassword` | 3 | 2 | 1 | 2 | 3 | 1 | **12** |

### Interprétation rapide

- Ton meilleur score visuel est `mcp-1password`, parce qu’il colle précisément aux contraintes de contrôle de scripts, d’audit et d’intégration client.
- `onepassword-mcp-server` reste intéressant pour une intégration 1Password “classique MCP + service-account” si tu veux moins de surface et une stack plus mature.
- Les autres sont des solutions de niche (Executor / IaC) : utiles dans leurs écosystèmes, moins alignées avec ton usage MCP opérationnel.

## 5) Recommandation de publication

Pour un install facile “comme les autres MCP”:

- Garder le nom `mcp-1password` (disponible sur npm).
- Publier public npm avec bin stable + scripts `prepack`/`prepare` déjà mis en place.
- Dans la doc, laisser la marche `npx` comme commande par défaut et ajouter le mode HTTP singleton via launchd.
