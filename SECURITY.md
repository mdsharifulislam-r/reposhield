# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅         |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing: **security@reposhield.dev**

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Your suggested fix (if any)

You will receive an acknowledgment within **48 hours** and a resolution within **7 days** for critical issues.

## Security Design Principles

RepoShield is built with defense-in-depth from the ground up:

### What RepoShield Does NOT Do
- **Never executes** target project code, lifecycle scripts, or install hooks
- **Never runs** `npm install` or any package manager install during scanning
- **Never modifies** source files, Git history, or working tree (except explicit `recover` commands with user confirmation)
- **Never force-pushes** to any branch
- **Never contacts external hosts** during scanning (network is disabled by default)
- **Never stores** or logs full secret values (only redacted representations are stored)
- **Never automatically** resets working tree or deletes commits

### What RepoShield Does
- Static analysis only — reads files, parses ASTs, inspects Git metadata
- Runs safe `git` subprocesses using array-based argument passing (no shell interpolation)
- Validates all Git refs before using them to prevent injection attacks
- Applies configurable timeouts to all external process calls
- Supports `AbortSignal` for graceful cancellation
- Produces structured, deterministic JSON reports

### False Positive Handling
Suppressions require:
- A specific rule ID (wildcards are rejected)
- A human-readable justification reason
- Optional expiry date (expired suppressions are flagged)

### Incident Response
RepoShield's `recover` commands:
- Require explicit user confirmation before any Git operation
- Create backup branches before any destructive operation
- Never automatically push changes
- Warn that a previous commit is not automatically safe

## Scope

The following are in scope for security reports:
- Bypass of detection rules by malicious code
- Injection vulnerabilities in Git argument handling
- Accidental execution of untrusted code
- Secret leakage in scan reports
- Path traversal in configuration parsing
- Denial-of-service via malicious input files

## Out of Scope
- Bugs in third-party dependencies (report upstream)
- Missing detection of novel malware (submit as a feature request)
