# RepoShield (`reposhield-scan`)

A **read-only** scanner that looks for suspicious, obfuscated, or compromised JavaScript/TypeScript code in a repository _before_ it can run.

- Parses code with Babel; it **never executes, evaluates, or imports** what it scans.
- **Never contacts** URLs found in files, never runs lifecycle scripts, never installs packages.
- Explainable findings: rule ID, severity, confidence, location, evidence, and a recommended action.
- Context-aware: a lone `eval`, `fetch`, `spawn`, or Base64 call is not reported as malware. Correlated behaviour (decode → eval, download → execute, env → network) is.
- Secrets are **always redacted** in reports.

> **Honest limits.** RepoShield is a heuristic scanner. A finding is a lead to review, not proof of malware, and **a clean result does not prove a repository is safe**. See [Limitations](#limitations).

## Install

```bash
npm install --save-dev reposhield-scan        # project-local
npx reposhield-scan scan                      # or run without installing
```

The npm package is **`reposhield-scan`**. It installs the `reposhield` command (and `reposhield-scan` as an alias). Requires Node.js 18.18 or newer. Pin the version you have reviewed rather than using `latest`.

## Quick start

```bash
npx reposhield-scan scan                      # audit mode, human-readable output, exit 0
npx reposhield-scan scan --mode strict        # fail on medium and above
npx reposhield-scan scan --mode ci            # deterministic output, non-zero exit on violation
npx reposhield-scan scan --changed --base origin/main
npx reposhield-scan scan --format json
npx reposhield-scan scan --format sarif --output reposhield.sarif
npx reposhield-scan baseline create           # accept current findings (critical excluded)
npx reposhield-scan baseline compare          # show what is not accepted
npx reposhield-scan recovery inspect          # read-only recovery plan
npx reposhield-scan file path/to/file.js      # single file
npx reposhield-scan rules                     # list rules
```

### Exit codes

| Code | Meaning                                                                                                |
| ---- | ------------------------------------------------------------------------------------------------------ |
| 0    | Success. In `audit` mode findings never fail the run unless `--fail-on` is given.                      |
| 1    | Policy violation: active findings at or above `--fail-on` (`strict`, `ci`, `changed`, or `--fail-on`). |
| 2    | Usage or configuration error.                                                                          |
| 3    | Runtime error (unreadable root, aborted scan, internal failure).                                       |

## API

```ts
import { clean } from "reposhield-scan";

const report = await clean({
  root: process.cwd(),
  mode: "audit",
  includeGitHistory: true,
  baseline: true,
  failOn: "high",
  ignore: ["dist/**", "coverage/**"],
});

console.log(report.safe); // false when policy thresholds are violated
console.log(report.summary);
console.log(report.findings);
```

`clean()` is a compatibility alias for `scan()`. **It scans and reports; it never cleans, deletes, or rewrites anything.** `report.safe === true` means "no policy violation was found", never "proven safe".

Exports: `clean`, `scan`, `scanFile`, `compareWithBaseline`, `createBaseline`, `generateReport`, `inspectRecovery`, `renderRecoveryPlan`, `monitor`, `ALL_RULES`, `optionsSchema`, and the types `Report`, `Finding`, `Severity`, `Confidence`, `Mode`. Both ESM and CommonJS are supported. Full reference: [docs/api.md](docs/api.md).

## Modes

| Mode      | Behaviour                                                                                            |
| --------- | ---------------------------------------------------------------------------------------------------- |
| `audit`   | Scan and report. Default threshold `high`; fails the exit code only if `--fail-on` is passed.        |
| `strict`  | Default threshold `medium`; unparseable config files and incomplete scans count against policy.      |
| `ci`      | Deterministic output (no timestamp), non-zero exit on violation.                                     |
| `changed` | Scan only files changed relative to `--base` (default: origin default branch, else `HEAD~1`).        |
| `monitor` | Re-scan on an interval until stopped. Starts only when you call `monitor()` or `reposhield monitor`. |

## What it detects

Run `reposhield rules` for the live list. Highlights:

- **Execution**: `eval`/`new Function` with non-literal input; decoded payload reaching an execution sink (`RS-EXEC-002`); remote content executed (`RS-DL-001`); shell commands matching attack patterns such as `curl … | sh` (`RS-PROC-002`).
- **Obfuscation**: hex-identifier obfuscation, encoded blobs that decode to executable-looking text, string-concatenated `require`, computed `globalThis["ev"+"al"]`.
- **Exfiltration**: environment variables, tokens, or credential files sent over the network.
- **Config files**: load-time network/process activity in `vite.config.*`, `next.config.*`, `postcss.config.*`, `tailwind.config.*`, `webpack.config.*`, and similar. The same construct scores higher in a config file or when newly introduced; ordinary configs are not flagged.
- **Packages**: install-time lifecycle scripts, Git/URL dependencies, look-alike names, unpinned ranges, lockfile inconsistencies and untrusted resolution sources, risky `.npmrc` settings. This is **offline** analysis; RepoShield does not look up registry reputation.
- **Secrets**: API keys, tokens, private keys, credential assignments (placeholders ignored).
- **Git**: findings on added lines relative to the base ref are marked `newlyIntroduced` and scored higher; dependency and lifecycle-script changes are reported.

How scores are computed: [docs/scoring.md](docs/scoring.md).

## Configuration

Options are validated with a strict schema (unknown keys are rejected with a clear message). The CLI reads JSON only from `.reposhieldrc.json` (or `--config`); **RepoShield never executes a JavaScript config.**

```json
{
  "mode": "ci",
  "failOn": "high",
  "ignore": ["generated/**"],
  "disabledRules": ["RS-DEP-005"],
  "severityOverrides": { "RS-NET-001": "low" },
  "allowlist": [
    {
      "ruleId": "RS-CFG-001",
      "path": "next.config.js",
      "reason": "Reads git hash for build ID; reviewed 2026-10"
    }
  ]
}
```

Allowlisted and baselined findings stay **visible** in reports but do not fail policy. Allowlist entries require a `reason`. Ignore rules: built-in defaults (`node_modules`, build output, `*.min.js`, …), `.gitignore`, `.reposhieldignore`, and the `ignore` option.

### Baselines

`reposhield baseline create` writes `.reposhield-baseline.json` (the only file RepoShield ever writes, and only on this command). Entries use stable fingerprints with no raw secrets. **Critical findings are not accepted unless you pass `--include-critical`.** A baseline that changed relative to the base ref is itself flagged (`RS-BASE-001`), so an attacker cannot silently accept their own payload.

## Running it safely

Order matters: **scan first, then install, build, or start.** `npm install` lifecycle scripts, `next build`, and `vite` all execute repository code.

- **CI**: [examples/github-actions-reposhield.yml](examples/github-actions-reposhield.yml), and [docs/github-actions.md](docs/github-actions.md) for the required branch-protection settings. A workflow file alone protects nothing.
- **Next.js**: [examples/nextjs-package-scripts.json](examples/nextjs-package-scripts.json) runs the scan in `predev`/`prebuild`.
- **Express**: [examples/express-startup.ts](examples/express-startup.ts). **A runtime scan cannot protect against code that already executed during module loading or startup.** Importing RepoShield does not protect a process. Use it as a pre-start gate, not a sandbox.

### Servers and `server.ts`

Calling `clean()` inside `server.ts` is too late if `server.ts` has static `import`s: ESM loads and runs every import **before** the file body, so your application code has already executed when the scan starts. Use a separate entry point that scans first and then loads the app with a dynamic `import()` ([examples/bootstrap.ts](examples/bootstrap.ts)):

```ts
import { clean } from "reposhield-scan";

const report = await clean({ root: process.cwd(), mode: "strict", failOn: "high" });
if (!report.safe) process.exit(1);

await import("./server.js"); // loaded only after the scan passed
```

Even then, `reposhield` itself and your dependencies are already loaded. The safest pattern is an out-of-process scan before start: `"prestart": "reposhield scan --mode ci --fail-on high"`.

Deploy order on a server ([examples/deploy.sh](examples/deploy.sh)): `git pull` → **scan** → `npm ci --ignore-scripts` → build → restart. Use `set -e` so a failed scan stops the deploy. Run the app as a non-root user.

## Recovery

`reposhield recovery inspect` identifies affected files, the commit that introduced them, diff context (secrets redacted), and comparison with the trusted commit in your baseline. It prints a plan with suggested commands and **runs none of them**: no reset, revert, branch, or file deletion. Reverting a commit does not remove all consequences; see [docs/remediation.md](docs/remediation.md) for credential rotation and dependency review.

## Safety guarantees (enforced by tests)

- Scanned code is parsed, never executed; URLs are never fetched; scripts are never run.
- Git is invoked read-only through an allowlist of subcommands, with hooks and fsmonitor disabled; option-like refs are rejected.
- Scans do not modify the working tree, index, refs, or history.
- Symlinks leaving the root are not followed; `scanFile` rejects path traversal.
- File names and content are treated as untrusted; terminal control characters are stripped from output.
- Secrets are redacted in text, JSON, SARIF, baselines, and recovery diffs.

## Limitations

- Static, heuristic analysis. Determined attackers can evade it (runtime-built code, exotic encodings, native addons, payloads in non-JS files, compromised dependencies in `node_modules`, which are skipped by default).
- It reads the files on disk and the Git history it can see; shallow clones limit "newly introduced" detection.
- No registry or reputation lookups; dependency findings are offline heuristics.
- Look-alike and typosquat checks use a small built-in list of popular packages.
- A clean report means "nothing matched these rules", not "safe".

## Development

```bash
npm ci --ignore-scripts
npm run typecheck && npm run lint && npm test
npm run build && npm run verify:pack
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Test fixtures are inert `.txt` files that are only ever read as text.

## License

MIT. See [LICENSE](LICENSE).