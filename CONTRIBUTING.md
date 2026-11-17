# Contributing to RepoShield

Thank you for your interest in contributing! This guide covers development setup, testing, and pull request guidelines.

## Development Setup

### Prerequisites
- Node.js >= 18
- Git
- npm >= 9

### Setup

```bash
git clone https://github.com/reposhield/reposhield.git
cd reposhield
npm install --ignore-scripts
npm run build
npm test
```

### Project Structure

```
src/
  types.ts           # Public API interfaces and error types
  config.ts          # Configuration loader and validator
  discovery.ts       # File discovery (Layer A)
  rules.ts           # Built-in rule definitions
  analyzer.ts        # AST analysis engine (Layer B)
  config-analyzer.ts # Config/script analysis (Layer C)
  dependency-inspector.ts  # Dependency auditing (Layer D)
  secret-detector.ts # Secret detection (Layer E)
  git-analyzer.ts    # Git history analysis (Layer F)
  policy.ts          # Policy evaluation and suppression
  cache.ts           # Result caching
  scanner.ts         # Main orchestration (clean() API)
  recovery.ts        # Safe recovery subsystem
  index.ts           # Public API exports
  cli/
    index.ts         # CLI entry point

tests/
  *.test.ts          # Unit tests
  fixtures/
    malicious/       # Inert malicious pattern fixtures (NEVER EXECUTE)
    benign/          # Legitimate code fixtures
    secrets/         # Secret pattern fixtures

examples/
  api-usage.js       # Programmatic API example
  pre-commit.js      # Pre-commit hook example
  custom-rules.js    # Custom rule extension example
```

## Scripts

```bash
npm run build         # Compile all targets (CJS, ESM, types)
npm run build:cjs     # Compile CommonJS only
npm run build:esm     # Compile ESM only
npm run build:types   # Compile type declarations only
npm test              # Run test suite
npm run test:coverage # Run tests with coverage report
npm run typecheck     # Type-check without emitting
npm run lint          # ESLint
npm run lint:fix      # ESLint with auto-fix
npm run pack:dry      # Preview npm pack output
```

## Adding a New Detection Rule

1. **Add the rule definition** in `src/rules.ts`:
   ```typescript
   {
     id: 'RS-AST-012',
     name: 'Suspicious Pattern Name',
     version: '1',
     severity: 'high',
     confidence: 'medium',
     description: 'Detects...',
     remediation: 'Remove or replace...',
     tags: ['ast', 'obfuscation'],
     enabled: true,
   }
   ```

2. **Add the detection visitor** in `src/analyzer.ts` in the `visitors` object.

3. **Write tests** in `tests/analyzer.test.ts`:
   - A test that detects the pattern
   - A test that does NOT flag the legitimate equivalent

4. **Update the rule reference** in `README.md`.

## Security Requirements for Contributions

- **No `eval()` calls** in scanner source code
- **No `shell: true`** in any subprocess call — use array args
- **No execution of target code** — all analysis must be static
- **Redact secrets** — never store or log full secret values
- **Validate Git refs** before using in subprocess calls
- **Test for false positives** — every new rule needs a benign test case

## Pull Request Guidelines

1. Ensure `npm test` and `npm run typecheck` pass
2. Add tests for any new detection rules
3. Do not add wildcard suppression capabilities
4. Do not add network calls to the scan path (use `networkAdvisory` flag pattern)
5. Update `CHANGELOG.md` under `[Unreleased]`
6. Sign your commits (`git commit -S`)

## Reporting False Positives

Open an issue with:
- The rule ID
- The legitimate code pattern that was flagged
- Why it is benign in that context

We take false positive rates seriously — a scanner that cries wolf gets disabled.

## Code of Conduct

Be respectful. Security is a collaborative discipline.
