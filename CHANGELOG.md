# Changelog

All notable changes to RepoShield are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2024-10-20

### Added

#### Core Architecture
- **Modular layered scanner**: file discovery → AST analysis → config analysis → dependency inspection → secret detection → Git analysis → policy evaluation
- **100% static analysis**: no untrusted code execution, no lifecycle scripts run during scan
- **AbortSignal support** for graceful scan cancellation

#### File Discovery (`src/discovery.ts`)
- Cross-platform file discovery using `fast-glob`
- Symlink safety: external symlinks never traversed
- Binary file detection and skipping
- Configurable file size limit (default 512 KB)
- Coverage reporting for skipped files

#### AST Analysis (`src/analyzer.ts`, `src/rules.ts`)
- 11 built-in AST detection rules (RS-AST-001 through RS-AST-011)
- Correlated signal scoring: multiple co-located signals escalate severity
- Deterministic risk scoring (0–100)
- Babel-based parser supporting JS, TS, JSX, TSX, MJS, CJS
- Graceful parse-error handling (invalid files are skipped, not crashed on)

#### Config Analysis (`src/config-analyzer.ts`)
- `package.json` lifecycle script analysis (preinstall, postinstall, prepare, etc.)
- GitHub Actions workflow analysis (script injection, `pull_request_target`, wildcard permissions)
- `.npmrc` analysis (hardcoded tokens, custom registries)
- Build configuration inspection (Vite, Webpack, Next.js, Rollup)
- Shell script analysis (curl-pipe-to-shell, wget-pipe-to-shell, dangerous patterns)

#### Dependency Inspection (`src/dependency-inspector.ts`)
- Typosquat candidate detection against 200+ popular package names
- Git and URL dependency detection (never install to inspect)
- `package-lock.json` v2/v3 suspicious source detection
- `pnpm-lock.yaml` and `yarn.lock` inspection
- Registry change detection

#### Secret Detection (`src/secret-detector.ts`)
- 15+ secret pattern rules (AWS, GitHub, npm, Stripe, JWT, private keys, etc.)
- Context-aware false positive reduction (test files, localhost URIs, placeholders)
- Shannon entropy analysis for high-entropy strings
- Full redaction: secrets NEVER stored in full form

#### Git Analysis (`src/git-analyzer.ts`)
- Safe Git subprocess calls: array-based arguments, no shell interpolation
- Git ref validation (reject injection characters)
- Commit history analysis for sensitive file changes
- Git hook tampering detection
- Configurable timeouts on all Git operations

#### Policy Engine (`src/policy.ts`)
- Per-rule suppression with glob path matching
- Suppression expiry enforcement
- Wildcard suppression rejection (security requirement)
- Four enforcement modes: audit, strict, ci, changed

#### Recovery Subsystem (`src/recovery.ts`)
- Recovery plan generation (no automatic changes)
- Backup branch creation before any operation
- Controlled revert commit creation (with user confirmation)
- Recovery branch creation from trusted SHA
- Explicit warnings: previous commits are NOT automatically safe

#### CLI (`src/cli/index.ts`)
- `reposhield init` — initialize configuration
- `reposhield scan` — run security scan with all options
- `reposhield report` — display existing JSON report
- `reposhield doctor` — check environment readiness
- `reposhield recover` — recovery plan and operations
- JSON and text output formats
- Exit codes: 0 (pass), 1 (policy violation), 2 (error), 3 (aborted)

#### Configuration (`reposhield.config.json`)
- JSON-based configuration with comment stripping
- Path traversal rejection in exclude patterns
- Wildcard suppression rejection
- Required `reason` field on all suppressions
- Optional suppression expiry dates

#### GitHub Actions Integration
- Least-privilege workflow (`contents: read` only)
- Installs RepoShield with `--ignore-scripts` to prevent malicious install hooks
- Change-based scanning for pull requests
- Artifact upload of redacted JSON reports

#### Result Caching (`src/cache.ts`)
- Content-hash based caching (SHA-256 of file content)
- Rule version invalidation
- LRU eviction to prevent unbounded growth

#### Testing
- Jest test suite with 70+ assertions across 6 test files
- Test fixtures for malicious patterns (inert, never executed)
- False positive prevention tests
- Determinism verification tests
- Config validation boundary tests

### Security
- No `eval()` calls in scanner source
- No `shell: true` in any subprocess call
- All Git refs validated before use
- Secrets redacted before any storage or reporting

---

## Versioning Policy

- **Patch** (1.0.x): Bug fixes, false positive reductions, new secret patterns
- **Minor** (1.x.0): New detection rules, CLI options, non-breaking API additions
- **Major** (x.0.0): Breaking API changes, config schema changes, behavior changes
