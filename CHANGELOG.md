# Changelog

## 0.3.0 (unreleased)

- Add critical detection for VS Code tasks that execute font assets as code, download and execute content, or run encoded commands.
- Add opt-in `--remove` and `clean({ remove: true })` to remove only matching task entries and rescan.

## 0.2.0 (unreleased)

- Rename the npm package to `reposhield-scan` while retaining the `reposhield` CLI command and alias.
- Add `reposhield run` to gate a user-specified command on a CI-mode scan.
- Detect Dean Edwards packers from parsed AST nodes rather than raw source text.
- Expand command-gating, server bootstrap, and deployment guidance.

## 0.1.0 (unreleased)

Initial release: read-only static scanner with Babel-based analysis, config-file and package/lockfile analysis, secret detection with redaction, Git-aware "newly introduced" marking, baselines, allowlists, risk scoring, text/JSON/SARIF reports, recovery inspection, monitor mode, and a CLI.
