/**
 * RepoShield — Secret Detector Tests
 */

import { detectSecrets } from '../src/secret-detector';
import path from 'path';
import fs from 'fs';

const FIXTURE_DIR = path.join(__dirname, '..', 'fixtures');

// ─── Detection Tests ──────────────────────────────────────────────────────────

describe('Secret Detector — Pattern Detection', () => {
  test('detects GitHub Personal Access Token', () => {
    const findings = detectSecrets('/test/config.js', `
      const token = 'ghp_abcdefghijklmnopqrstuvwxyz123456789012';
    `);
    expect(findings.some((f) => f.ruleId === 'RS-SEC-003')).toBe(true);
  });

  test('detects npm auth token', () => {
    const findings = detectSecrets('/test/.npmrc', `
      //registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz123456789012
    `);
    expect(findings.some((f) => f.ruleId === 'RS-SEC-006')).toBe(true);
  });

  test('detects AWS access key', () => {
    const findings = detectSecrets('/test/aws.js', `
      const accessKeyId = 'AKIAIOSFODNN7EXAMPLE';
    `);
    expect(findings.some((f) => f.ruleId === 'RS-SEC-001')).toBe(true);
  });

  test('detects private key header', () => {
    const findings = detectSecrets('/test/cert.js', `
      const key = '-----BEGIN RSA PRIVATE KEY-----';
    `);
    expect(findings.some((f) => f.ruleId === 'RS-SEC-012')).toBe(true);
  });

  test('detects JWT token', () => {
    const findings = detectSecrets('/test/auth.js', `
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    `);
    expect(findings.some((f) => f.ruleId === 'RS-SEC-007')).toBe(true);
  });

  test('detects database connection with credentials', () => {
    const findings = detectSecrets('/test/db.js', `
      const uri = 'mongodb://admin:secretpassword@mongo.prod.company.com:27017';
    `);
    expect(findings.some((f) => f.ruleId === 'RS-SEC-015')).toBe(true);
  });

  test('detects Stripe secret key', () => {
    const findings = detectSecrets('/test/stripe.js', `
      const stripeKey = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';
    `);
    expect(findings.some((f) => f.ruleId === 'RS-SEC-008')).toBe(true);
  });
});

// ─── Redaction Tests ──────────────────────────────────────────────────────────

describe('Secret Detector — Redaction', () => {
  test('never returns full secret value', () => {
    const realToken = 'ghp_abcdefghijklmnopqrstuvwxyz123456789012';
    const findings = detectSecrets('/test/config.js', `const t = '${realToken}';`);
    for (const finding of findings) {
      // The redacted value must NOT equal the full token
      expect(finding.redactedValue).not.toBe(realToken);
      // The redacted value must contain asterisks
      expect(finding.redactedValue).toMatch(/\*/);
    }
  });

  test('redacted value starts with secret prefix', () => {
    const findings = detectSecrets('/test/config.js', `
      const token = 'ghp_abcdefghijklmnopqrstuvwxyz123456789012';
    `);
    const ghpFinding = findings.find((f) => f.ruleId === 'RS-SEC-003');
    expect(ghpFinding?.redactedValue).toBeDefined();
    // Should show first 4 chars of ghp_ prefix
    expect(ghpFinding?.redactedValue.startsWith('ghp_')).toBe(true);
  });
});

// ─── False Positive Tests ─────────────────────────────────────────────────────

describe('Secret Detector — False Positive Reduction', () => {
  test('does not flag localhost database URIs', () => {
    const findings = detectSecrets('/test/db.js', `
      const uri = 'mongodb://admin:password@localhost:27017/mydb';
    `);
    expect(findings.filter((f) => f.ruleId === 'RS-SEC-015').length).toBe(0);
  });

  test('does not flag JWT tokens in test fixtures', () => {
    const findings = detectSecrets(
      path.join(__dirname, '..', 'fixtures', 'auth.test.js'),
      `const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';`,
    );
    // Test files are excluded from secret detection
    expect(findings.filter((f) => f.ruleId === 'RS-SEC-007').length).toBe(0);
  });

  test('does not flag example placeholder values', () => {
    const findings = detectSecrets('/test/example.js', `
      // Example: replace with your actual password
      const password = 'REPLACE_WITH_YOUR_PASSWORD';
    `);
    expect(findings.filter((f) => f.ruleId === 'RS-SEC-013').length).toBe(0);
  });

  test('fixture: detects secrets in secret-strings.fixture.js', () => {
    const fixturePath = path.join(FIXTURE_DIR, 'secrets', 'secret-strings.fixture.js');
    const content = fs.readFileSync(fixturePath, 'utf-8');
    // The fixture file path does not match the test file exclusion pattern
    const findings = detectSecrets('/src/config.js', content);
    expect(findings.length).toBeGreaterThan(0);
  });
});

// ─── Newly Introduced Tests ───────────────────────────────────────────────────

describe('Secret Detector — New Introduction Tracking', () => {
  test('marks secrets as newly introduced when isNewlyIntroduced=true', () => {
    const findings = detectSecrets(
      '/test/config.js',
      `const token = 'ghp_abcdefghijklmnopqrstuvwxyz123456789012';`,
      { isNewlyIntroduced: true },
    );
    expect(findings[0]?.isNewlyIntroduced).toBe(true);
  });
});
