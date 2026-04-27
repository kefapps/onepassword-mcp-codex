# Agent Instructions — mcp-1password

## Commits et versionnage

Ce projet utilise [Conventional Commits](https://www.conventionalcommits.org/) et [release-please](https://github.com/googleapis/release-please) pour automatiser le CHANGELOG et les bumps de version. **Chaque commit doit respecter ce format**, sans exception.

### Format

```
<type>(<scope optionnel>): <description courte>

<corps optionnel>

<footer optionnel>
```

### Types et impact sur la version

| Type | Bump de version | Apparaît dans CHANGELOG | Usage |
|---|---|---|---|
| `feat` | **minor** (0.x.0) | ✅ Features | Nouvelle fonctionnalité exposée à l'utilisateur |
| `fix` | **patch** (0.0.x) | ✅ Bug Fixes | Correction de bug |
| `fix(security)` | **patch** | ✅ Security | Correctif de sécurité — utiliser ce scope systématiquement |
| `perf` | **patch** | ✅ Performance Improvements | Amélioration de performance mesurable |
| `docs` | aucun | ✅ Documentation | Modifications de documentation uniquement |
| `refactor` | aucun | ❌ (caché) | Refactoring sans changement de comportement |
| `test` | aucun | ❌ (caché) | Ajout ou modification de tests uniquement |
| `chore` | aucun | ❌ (caché) | Tâches de maintenance (build, config, dépendances) |
| `ci` | aucun | ❌ (caché) | Modifications des workflows CI/CD |
| `revert` | **patch** | ✅ Reverts | Annulation d'un commit précédent |

**Breaking change → major (x.0.0) :** ajouter `!` après le type (`feat!:`, `fix!:`) ou un footer `BREAKING CHANGE: <description>`.

### Règles impératives

1. **Ne jamais utiliser de message générique.** Pas de `fix: bug`, `chore: update`, `feat: add feature`. La description doit être spécifique et tenir en une ligne.
2. **Le scope est optionnel mais recommandé** pour les changements ciblés : `fix(http-server):`, `feat(script-runner):`, `fix(security):`.
3. **Un commit = une intention.** Ne pas mélanger un fix et un refactoring dans le même commit.
4. **Les commits de merge automatiques** (release-please, Dependabot) sont gérés par les bots — ne pas les imiter manuellement.
5. **`fix(security):`** pour tout correctif lié à la sécurité, même mineur. Ce scope crée une section dédiée dans le CHANGELOG.

### Exemples corrects

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

### Exemples incorrects

```
# ❌ trop vague
fix: bug fix
feat: new feature
update: stuff

# ❌ mauvais type (le travail n'est pas documenté dans le bon CHANGELOG)
chore: fix security issue   # → doit être fix(security):
feat: update README         # → doit être docs:

# ❌ multiple intentions dans un commit
feat: add vault search and fix pagination bug  # → deux commits séparés
```

## Pipeline de publication

Le pipeline fonctionne ainsi :

1. Les commits sur `main` déclenchent le workflow `release-please.yml`
2. release-please analyse les commits depuis le dernier tag et crée/met à jour une PR `chore(release): vX.Y.Z`
3. Merger cette PR crée un tag Git + une GitHub Release
4. La GitHub Release déclenche `publish.yml` qui publie sur npm avec `--tag beta`

**Ne jamais bumper la version dans `package.json` manuellement.** C'est le rôle exclusif de release-please via sa PR de release.

## Périmètre des changements

- Rester dans les fichiers pertinents pour la tâche. Ne pas reformatter ou refactorer du code non lié.
- Ne pas modifier `CHANGELOG.md` directement — il est géré par release-please.
- Ne pas modifier `.release-please-manifest.json` directement — il est mis à jour par release-please.
