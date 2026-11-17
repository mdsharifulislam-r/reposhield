# RepoShield

Static malware defense for Node.js repositories. RepoShield reads your source, config, lockfiles, and Git metadata and reports supply-chain attacks, leaked secrets, and policy violations. It does not run your code.

[![CI](https://github.com/reposhield/reposhield/actions/workflows/reposhield.yml/badge.svg)](https://github.com/reposhield/reposhield/actions)
[![npm version](https://badge.fury.io/js/reposhield-scan.svg)](https://www.npmjs.com/package/reposhield-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## What a scan covers

| Area | Examples |
| --- | --- |
| Source | `eval`, `new Function`, download-and-execute chains, hidden loaders |
| Scripts | `package.json` hooks, `node init && next dev`, oversized script bodies |
| Carriers | Fake fonts in any folder, editor tasks that run them on folder open |
| Config | GitHub Actions injection, `.npmrc` tokens, shell `curl \| bash` |
| Dependencies | Typosquats, git or URL dependencies, lockfile source mismatches |
| Secrets | Cloud keys, GitHub and npm tokens, private keys, database URLs |
| Git | Hook path changes, commits that touch workflows or `package.json` scripts |

Findings use stable rule IDs such as `RS-DROP-001`. The same tree always produces the same report.

## What a scan never does

- Run lifecycle scripts or any file in the repository
- Edit source, Git history, or the working tree
- Contact the network, unless you explicitly turn advisory checks on
- Print a full secret. Matches are redacted.

Pass an `AbortSignal` to cancel a scan in progress.

## Install

```bash
npm install --save-dev reposhield-scan
```

In CI, skip install scripts:

```bash
npm install --ignore-scripts --save-dev reposhield-scan
```

## Use it

### Command line

```bash
npx reposhield-scan init
npx reposhield-scan init --yes

npx reposhield-scan scan
npx reposhield-scan scan --mode ci --severity high
npx reposhield-scan scan --remove
npx reposhield-scan scan --remove --remove-source --yes
npx reposhield-scan scan --format sarif --output reposhield.sarif

npx reposhield-scan run -- npm test
npx reposhield-scan run --fail-on medium -- npm test

npx reposhield-scan report --input reposhield-report.json
npx reposhield-scan doctor

npx reposhield-scan recover --inspect
npx reposhield-scan recover --to <trusted-sha>
npx reposhield-scan recover --revert <sha>
npx reposhield-scan recovery inspect

npx reposhield-scan file path/to/file.js
npx reposhield-scan baseline create
npx reposhield-scan baseline compare
npx reposhield-scan monitor
npx reposhield-scan rules
```

| Command | Purpose |
| --- | --- |
| `init` | Write `reposhield.config.json`. Refuses to overwrite an existing file. |
| `init --yes` | Keep every npm script as `reposhield:init:original:*` and add scan wrappers. |
| `scan` | Inspect the repository. Default mode is `audit`. |
| `run` | Scan first. Start the command after `--` only when policy passes. |
| `report` | Print a saved JSON report as text. |
| `doctor` | Check Node.js 18+, Git, the repository, and the config. |
| `recover` | Show a plan (`--inspect`), branch from a trusted commit (`--to`), or create a revert commit (`--revert`). |
| `recovery inspect` | Read-only recovery plan. Does not reset, revert, or delete. |
| `file <path>` | Scan one file. Refuses paths outside the root. |
| `baseline create` | Write `.reposhield-baseline.json`. Critical findings stay unaccepted unless `--include-critical` is set. |
| `baseline compare` | Show findings the baseline has not accepted. |
| `monitor` | Re-scan until you stop it. `--interval <seconds>` defaults to 30. |
| `rules` | List detection rules. |

`init` and `doctor` accept `--root <path>`. The default is the current directory.

`scan` flags:

| Flag | Purpose |
| --- | --- |
| `--root <path>` | Repository to scan. Default is the current directory. |
| `--mode <mode>` | `audit`, `strict`, `ci`, `changed`, or `monitor`. Default is `audit`. |
| `--changed` | Same as `--mode changed`. |
| `--base <sha>` | Trusted commit or branch for a changed scan. |
| `--severity <level>` | Lowest severity to report: `critical`, `high`, `medium`, `low`, or `info`. Default is `info`. |
| `--format <format>` | `text`, `json`, or `sarif`. Default is `text`. |
| `--output <file>` | Write the report to this file. |
| `--fail-on <severity>` | `info`, `low`, `medium`, `high`, or `critical`. |
| `--remove` | Remove matched critical VS Code tasks and npm scripts, then preview source files. |
| `--remove-source` | With `--remove --yes`, delete those source files. |
| `--yes` | Confirm source deletion. On `init`, write the script changes. |
| `--history` | Include recent Git commit history. |
| `--no-cache` | Do not reuse a cached result. |
| `--quiet` | Hide progress output. |

`report` reads `--input <file>`. The default file is `reposhield-report.json`.

`recover` flags:

| Flag | Purpose |
| --- | --- |
| `--inspect` | Print the recovery plan. Does not change the repository. |
| `--to <sha>` | Create a local recovery branch from that commit. Asks before it writes. Does not push. |
| `--revert <sha>` | Create a revert commit for that SHA. Creates a backup branch and asks before it writes. |
| `--root <path>` | Repository to inspect. Default is the current directory. |

### From code

```typescript
import { clean } from 'reposhield-scan';

const summary = await clean({
  root: process.cwd(),
  mode: 'audit',
  minSeverity: 'medium',
  exclude: ['dist/', 'coverage/'],
});

console.log(`${summary.findings.length} findings`);
console.log(`${summary.secretFindings.length} secrets`);
console.log(`policy violation: ${summary.policyViolation}`);
```

## Scan modes and exit codes

| Mode | What it does | Can fail the run |
| --- | --- | --- |
| `audit` | Report every finding. Critical and high still violate policy | Yes |
| `strict` | Enforce the configured policy | Yes |
| `ci` | Same enforcement, for automation | Yes |
| `changed` | Only files changed since `--base` | Yes |
| `monitor` | Local watch. Critical and high still violate policy | Yes |

| Exit code | Meaning |
| --- | --- |
| `0` | No policy violation |
| `1` | Policy violation |
| `2` | Invalid arguments or scan error |
| `3` | Cancelled |

## Configuration

`reposhield-scan init` creates `reposhield.config.json`:

```json
{
  "version": 1,
  "exclude": ["dist/", "build/", "coverage/"],
  "suppressions": [
    {
      "ruleId": "RS-AST-001",
      "path": "src/api/client.ts",
      "reason": "Reviewed fetch wrapper. Ticket SEC-120.",
      "reviewer": "security",
      "expiresAt": "2026-10-01"
    }
  ],
  "policy": {
    "blockOnCritical": true,
    "blockOnHigh": true,
    "blockOnMedium": false,
    "blockOnSecrets": true,
    "blockOnDependencyFindings": "high"
  }
}
```

A suppression needs an exact `ruleId` and a non-empty `reason`. `path` is an optional glob. `expiresAt` is optional; an expired entry is reported and does not hide the finding.

`node_modules`, `.git`, `dist`, `build`, and `coverage` are skipped by default.

## CI

```yaml
- name: Install RepoShield
  run: npm install --ignore-scripts --save-dev reposhield-scan

- name: Scan
  run: npx reposhield-scan scan --mode ci --format json --output report.json

- name: Upload report
  uses: actions/upload-artifact@v4
  with:
    name: security-report
    path: report.json
```

The workflow in [`.github/workflows/reposhield.yml`](.github/workflows/reposhield.yml) is a full example.

Husky:

```bash
npx husky add .husky/pre-commit "npx reposhield-scan scan --mode strict --severity high"
```

## Rules

Severity is the default for that rule. Correlation can raise it when several signals appear in one file.

### Supply-chain droppers

| ID | Severity | Flags |
| --- | --- | --- |
| `RS-CFG-009` | Critical | `dev` / `build` / `start` runs `node` on `init`, `api.js`, `app.js`, or a font file |
| `RS-DROP-001` | Critical | Hidden loader: campaign marker, decoder fingerprint, or a payload after a long space run |
| `RS-DROP-002` | High | Unusually large or dense script, including a long `package.json` script |
| `RS-FONT-001` | Critical | Font file that is not a real font, in any directory |
| `RS-IDE-001` | Critical | VS Code task runs `node` on a dropper when the folder opens |

A real font (`wOFF`, `wOF2`, `OTTO`, valid EOT) is not flagged. A normal formatted source file over 10KB is not flagged.

### Source

| ID | Severity | Flags |
| --- | --- | --- |
| `RS-AST-001` | High | `eval` or `new Function` |
| `RS-AST-002` | Critical | Base64 decode followed by execution |
| `RS-AST-003` | Critical | Download followed by execution |
| `RS-AST-004` | Medium | `process.env` sent over the network |
| `RS-AST-005` | Medium | `child_process` |
| `RS-AST-009` | High | `vm` module |
| `RS-AST-010` | High | `require` or `import` with a dynamic path |
| `RS-AST-011` | High | Network call in a lifecycle script |

### Config, secrets, and Git

| ID | Severity | Flags |
| --- | --- | --- |
| `RS-CFG-001` | Critical | `curl \| bash` in an install script |
| `RS-CFG-006` | High | `node -e` in an install script |
| `RS-PKG-001` | High | `main` path escapes the package |
| `RS-WF-001` | Critical | `${{ github.event.* }}` injected into a shell step |
| `RS-WF-003` | High | `pull_request_target` |
| `RS-NPM-002` | Critical | Hardcoded npm token in `.npmrc` |
| `RS-SH-001` | Critical | `curl \| bash` in a shell script |
| `RS-SEC-001` | Critical | AWS access key |
| `RS-SEC-003` | Critical | GitHub personal access token |
| `RS-SEC-012` | Critical | Private key |

## If a scan reports a compromise

1. Rotate tokens, cloud keys, and database passwords before you clean the tree.
2. Read the plan. This does not change the repository:

   ```bash
   npx reposhield-scan recover --inspect
   ```

3. Branch from a commit you trust. This does not push:

   ```bash
   npx reposhield-scan recover --to <trusted-sha>
   ```

4. Scan that commit before you deploy:

   ```bash
   npx reposhield-scan scan --base <trusted-sha>
   ```

An older commit is not safe just because it is older. Scan it.

## Project

- [CONTRIBUTING.md](CONTRIBUTING.md) — setup, tests, and pull requests
- [SECURITY.md](SECURITY.md) — how to report a problem
- [LICENSE](LICENSE) — MIT
