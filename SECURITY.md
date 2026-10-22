# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** (for example via GitHub's "Report a vulnerability" private advisory on the repository), not in public issues. Include the version, a minimal reproduction, and the impact. Please do not include real secrets or live malware; inert samples are enough.

Maintainer contact and response targets: _to be filled in before the first release._

## Scope

In scope: anything that makes RepoShield execute, evaluate, or import scanned content; contact URLs found in scanned files; run repository scripts or Git hooks; modify scanned files beyond the explicit `baseline create` and opt-in `--remove` behavior; let `--remove` modify files other than suspicious entries in `.vscode/tasks.json`; follow symlinks or paths outside the root; leak unredacted secrets; or crash/hang on crafted input (ReDoS, parser bombs, symlink loops).

Out of scope: evasion of heuristic detection by itself (a missed detection is a bug report, not a vulnerability), and findings in third-party dependencies already tracked upstream.

## Design guarantees

See "Safety guarantees" in the README. They are covered by automated tests; a regression is treated as a security bug.

## Supply-chain hygiene for this package

- `.npmrc` sets `ignore-scripts=true`; the package has no install-time scripts.
- Published files are limited to `dist`, docs, and policy files and are checked by `npm run verify:pack`.
- Publishing requires an explicit maintainer action. Enable 2FA and prefer npm provenance when releasing.
