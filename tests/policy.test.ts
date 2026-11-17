/**
 * RepoShield — Policy Engine Tests
 */

import { checkSuppression, evaluatePolicy, filterBySeverity } from '../src/policy';
import { Finding, SecretFinding, DependencyFinding, GitFinding, RepoShieldConfig } from '../src/types';


function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'RS-AST-001',
    ruleName: 'Test Rule',
    ruleVersion: '1',
    severity: 'high',
    confidence: 'medium',
    filePath: '/test/file.js',
    message: 'Test finding',
    evidence: [],
    remediation: 'Fix it',
    riskScore: 50,
    ...overrides,
  };
}

function makeConfig(overrides: Partial<RepoShieldConfig> = {}): RepoShieldConfig {
  return {
    version: 1,
    policy: {
      blockOnCritical: true,
      blockOnHigh: true,
      blockOnMedium: false,
      blockOnSecrets: true,
      blockOnDependencyFindings: 'high',
    },
    suppressions: [],
    ...overrides,
  };
}

// ─── Suppression Tests ────────────────────────────────────────────────────────

describe('Policy Engine — Suppression Matching', () => {
  test('matches exact rule ID', () => {
    const result = checkSuppression('RS-AST-001', '/file.js', [
      { ruleId: 'RS-AST-001', reason: 'Intentional' },
    ]);
    expect(result.suppressed).toBe(true);
  });

  test('does not match different rule ID', () => {
    const result = checkSuppression('RS-AST-002', '/file.js', [
      { ruleId: 'RS-AST-001', reason: 'Intentional' },
    ]);
    expect(result.suppressed).toBe(false);
  });

  test('matches file path glob pattern', () => {
    const result = checkSuppression('RS-AST-001', 'src/legacy/old-code.js', [
      { ruleId: 'RS-AST-001', reason: 'Legacy code', path: 'src/legacy/**' },
    ]);
    expect(result.suppressed).toBe(true);
  });

  test('does not match if glob does not match file', () => {
    const result = checkSuppression('RS-AST-001', 'src/new/code.js', [
      { ruleId: 'RS-AST-001', reason: 'Legacy code', path: 'src/legacy/**' },
    ]);
    expect(result.suppressed).toBe(false);
  });

  test('expired suppression is NOT active but is reported', () => {
    const past = new Date(Date.now() - 86400000).toISOString(); // Yesterday
    const result = checkSuppression('RS-AST-001', '/file.js', [
      { ruleId: 'RS-AST-001', reason: 'Expired', expiresAt: past },
    ]);
    expect(result.suppressed).toBe(false);
    expect(result.isExpired).toBe(true);
  });

  test('valid future expiry suppression IS active', () => {
    const future = new Date(Date.now() + 86400000).toISOString(); // Tomorrow
    const result = checkSuppression('RS-AST-001', '/file.js', [
      { ruleId: 'RS-AST-001', reason: 'Temporary', expiresAt: future },
    ]);
    expect(result.suppressed).toBe(true);
    expect(result.isExpired).toBe(false);
  });
});

// ─── Policy Evaluation Tests ──────────────────────────────────────────────────

describe('Policy Engine — Policy Evaluation', () => {
  test('audit mode treats critical findings as a policy violation', () => {
    const findings = [
      makeFinding({ severity: 'critical' }),
      makeFinding({ severity: 'high' }),
    ];
    const config = makeConfig();
    const result = evaluatePolicy(findings, [], [], [], config, 'audit');
    expect(result.policyViolation).toBe(true);
    expect(result.reasons.some((r) => r.includes('critical'))).toBe(true);
  });

  test('monitor mode treats critical findings as a policy violation', () => {
    const findings = [makeFinding({ severity: 'critical' })];
    const config = makeConfig();
    const result = evaluatePolicy(findings, [], [], [], config, 'monitor');
    expect(result.policyViolation).toBe(true);
  });

  test('strict mode blocks on critical findings', () => {
    const findings = [makeFinding({ severity: 'critical' })];
    const config = makeConfig();
    const result = evaluatePolicy(findings, [], [], [], config, 'strict');
    expect(result.policyViolation).toBe(true);
    expect(result.reasons.some((r) => r.includes('critical'))).toBe(true);
  });

  test('ci mode blocks on high findings', () => {
    const findings = [makeFinding({ severity: 'high' })];
    const config = makeConfig();
    const result = evaluatePolicy(findings, [], [], [], config, 'ci');
    expect(result.policyViolation).toBe(true);
  });

  test('ci mode does NOT block on medium if policy not set', () => {
    const findings = [makeFinding({ severity: 'medium' })];
    const config = makeConfig({ policy: { blockOnMedium: false, blockOnHigh: false, blockOnCritical: true } });
    const result = evaluatePolicy(findings, [], [], [], config, 'ci');
    expect(result.policyViolation).toBe(false);
  });

  test('ci mode blocks on secrets', () => {
    const secretFinding: SecretFinding = {
      ruleId: 'RS-SEC-003',
      filePath: '/test/config.js',
      line: 1,
      redactedValue: 'ghp_****',
      secretType: 'GitHub PAT',
      isHighEntropy: true,
      remediation: 'Rotate the token',
    };
    const config = makeConfig();
    const result = evaluatePolicy([], [secretFinding], [], [], config, 'ci');
    expect(result.policyViolation).toBe(true);
    expect(result.reasons.some((r) => r.includes('secret'))).toBe(true);
  });

  test('suppressed findings do not trigger policy violation', () => {
    const findings = [makeFinding({ severity: 'critical' })];
    const config = makeConfig({
      suppressions: [{ ruleId: 'RS-AST-001', reason: 'Intentional', path: 'test/file.js' }],
    });
    const result = evaluatePolicy(findings, [], [], [], config, 'strict');
    // The finding is suppressed — no violation
    expect(result.suppressedCount).toBe(1);
    expect(result.policyViolation).toBe(false);
  });

  test('expired suppressions are reported in results', () => {
    const findings = [makeFinding({ severity: 'critical' })];
    const past = new Date(Date.now() - 86400000).toISOString();
    const config = makeConfig({
      suppressions: [{ ruleId: 'RS-AST-001', reason: 'Expired', expiresAt: past }],
    });
    const result = evaluatePolicy(findings, [], [], [], config, 'strict');
    expect(result.expiredSuppressions.length).toBe(1);
    // Expired suppressions don't suppress the finding
    expect(result.policyViolation).toBe(true);
  });
});

// ─── Severity Filter Tests ────────────────────────────────────────────────────

describe('Policy Engine — Severity Filter', () => {
  test('filters out findings below minSeverity', () => {
    const findings = [
      makeFinding({ severity: 'critical' }),
      makeFinding({ severity: 'high' }),
      makeFinding({ severity: 'medium' }),
      makeFinding({ severity: 'low' }),
      makeFinding({ severity: 'info' }),
    ];
    const filtered = filterBySeverity(findings, 'high');
    expect(filtered.length).toBe(2);
    expect(filtered.every((f) => f.severity === 'critical' || f.severity === 'high')).toBe(true);
  });
});
