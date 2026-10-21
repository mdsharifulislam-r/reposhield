# Contributing

## Setup

```bash
npm ci --ignore-scripts
npm run typecheck && npm run lint && npm run format:check && npm test
npm run build && npm run verify:pack
```

## Ground rules

- **Never execute scanned content.** No `eval`, `new Function`, `vm`, `import()` or `require()` of scanned files, and no running their scripts. ESLint forbids `eval`-style calls in this repo.
- **Never fetch URLs** found in scanned files.
- **Git is read-only.** Use the allowlisted helpers in `src/git/git.ts`; add a subcommand there only if it cannot mutate state.
- **Redact secrets** everywhere (`src/core/redact.ts`). Add a test for any new output path.
- **Treat file names, content, and package metadata as untrusted** (strip terminal control characters in text output).
- Normal scans must not write to the scanned project. The only writer is `baseline create`.

## Adding a rule

1. Add detection in `src/rules/` (or a fact in `src/analyzers/` if it needs AST data) with a stable `RS-…` ID, severity, confidence, and a clear recommendation.
2. Prefer **correlation** over single-API triggers; a lone `eval`/`fetch`/`spawn` must stay low or unflagged.
3. Add a benign fixture and a malicious fixture. Fixtures are inert `.txt` files in `test/fixtures/` that tests read as text; never make them runnable.
4. Register the rule in `src/rules/index.ts` and document it if it changes scoring.

## Tests

Use temporary directories and isolated repositories (`test/helpers/project.ts`). Do not read real secrets or touch the network. Add a regression test with every bug fix.
