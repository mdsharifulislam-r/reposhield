/**
 * RepoShield — Policy Engine
 *
 * Evaluates findings against configured policy and suppression entries.
 * Determines whether findings block CI or require review.
 */

import { Finding, SecretFinding, DependencyFinding, GitFinding,
  PolicyConfig, SuppressionEntry, RepoShieldConfig, Severity, ScanMode } from './types.js';
import micromatch from 'micromatch';

// ─── Suppression Matching ─────────────────────────────────────────────────────

export interface SuppressionResult {
  suppressed: boolean;
  entry?: SuppressionEntry;
  isExpired: boolean;
}

export function checkSuppression(
  ruleId: string,
  filePath: string,
  suppressions: readonly SuppressionEntry[],
  now = new Date(),
): SuppressionResult {
  for (const entry of suppressions) {
    if (entry.ruleId !== ruleId) continue;

    // Check path match
    if (entry.path) {
      const relPath = filePath.replace(/\\/g, '/').replace(/^\/+/, '');
      const pattern = entry.path.replace(/\\/g, '/').replace(/^\/+/, '');
      if (!micromatch.isMatch(relPath, pattern)) {
        continue;
      }
    }

    // Check expiry
    if (entry.expiresAt) {
      const expiry = new Date(entry.expiresAt);
      if (isNaN(expiry.getTime())) {
        // Invalid date — treat suppression as expired for safety
        return { suppressed: false, entry, isExpired: true };
      }
      if (now > expiry) {
        return { suppressed: false, entry, isExpired: true };
      }
    }

    return { suppressed: true, entry, isExpired: false };
  }

  return { suppressed: false, isExpired: false };
}

// ─── Policy Evaluation ────────────────────────────────────────────────────────

export interface PolicyEvaluationResult {
  policyViolation: boolean;
  reasons: string[];
  suppressedCount: number;
  expiredSuppressions: SuppressionEntry[];
  processedFindings: Finding[];
  processedSecretFindings: SecretFinding[];
}

export function evaluatePolicy(
  findings: Finding[],
  secretFindings: SecretFinding[],
  depFindings: DependencyFinding[],
  gitFindings: GitFinding[],
  config: RepoShieldConfig,
  mode: ScanMode,
): PolicyEvaluationResult {
  const policy = config.policy ?? {};
  const suppressions = config.suppressions ?? [];
  const reasons: string[] = [];
  let policyViolation = false;
  let suppressedCount = 0;
  const expiredSuppressions: SuppressionEntry[] = [];
  const now = new Date();

  // Process findings and apply suppressions
  const processedFindings = findings.map((finding) => {
    const result = checkSuppression(finding.ruleId, finding.filePath, suppressions, now);

    if (result.isExpired && result.entry) {
      if (!expiredSuppressions.includes(result.entry)) {
        expiredSuppressions.push(result.entry);
      }
    }

    if (result.suppressed && result.entry) {
      suppressedCount++;
      return { ...finding, suppressed: true, suppressedBy: result.entry };
    }

    return finding;
  });

  // Process secret findings
  const processedSecretFindings = secretFindings.map((sf) => sf);

  // Check policy only in strict/ci modes (audit mode always passes)
  const isEnforcing = mode === 'strict' || mode === 'ci';

  if (isEnforcing) {
    // Check for critical findings
    const criticalFindings = processedFindings.filter(
      (f) => f.severity === 'critical' && !f.suppressed,
    );
    if ((policy.blockOnCritical ?? true) && criticalFindings.length > 0) {
      policyViolation = true;
      reasons.push(
        `${criticalFindings.length} critical finding(s) detected and policy blocks on critical severity`,
      );
    }

    // Check for high findings
    const highFindings = processedFindings.filter((f) => f.severity === 'high' && !f.suppressed);
    if ((policy.blockOnHigh ?? true) && highFindings.length > 0) {
      policyViolation = true;
      reasons.push(
        `${highFindings.length} high severity finding(s) detected and policy blocks on high severity`,
      );
    }

    // Check for medium findings
    const mediumFindings = processedFindings.filter(
      (f) => f.severity === 'medium' && !f.suppressed,
    );
    if ((policy.blockOnMedium ?? false) && mediumFindings.length > 0) {
      policyViolation = true;
      reasons.push(
        `${mediumFindings.length} medium severity finding(s) detected and policy blocks on medium severity`,
      );
    }

    // Check for secrets
    if ((policy.blockOnSecrets ?? true) && processedSecretFindings.length > 0) {
      policyViolation = true;
      reasons.push(`${processedSecretFindings.length} secret(s) detected`);
    }

    // Check dependency findings
    const depSeverityThreshold = (policy.blockOnDependencyFindings as Severity) ?? 'high';
    const blockedDepFindings = depFindings.filter(
      (df) => compareSeverity(df.severity, depSeverityThreshold) >= 0,
    );
    if (blockedDepFindings.length > 0) {
      policyViolation = true;
      reasons.push(
        `${blockedDepFindings.length} dependency finding(s) at or above "${depSeverityThreshold}" severity`,
      );
    }

    // Check for critical git findings
    const criticalGitFindings = gitFindings.filter((gf) => gf.severity === 'critical');
    if (criticalGitFindings.length > 0) {
      policyViolation = true;
      reasons.push(`${criticalGitFindings.length} critical Git finding(s) detected`);
    }

    // Expired suppressions are reported but don't trigger violations
    if (expiredSuppressions.length > 0) {
      reasons.push(
        `${expiredSuppressions.length} suppression(s) have expired and may need renewal or removal`,
      );
    }
  }

  return {
    policyViolation,
    reasons,
    suppressedCount,
    expiredSuppressions,
    processedFindings,
    processedSecretFindings,
  };
}

// ─── Severity Ordering ────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

function compareSeverity(a: Severity, b: Severity): number {
  return (SEVERITY_ORDER[a] ?? 0) - (SEVERITY_ORDER[b] ?? 0);
}

// ─── Minimum Severity Filter ──────────────────────────────────────────────────

export function filterBySeverity<T extends { severity: Severity }>(
  items: T[],
  minSeverity: Severity,
): T[] {
  const minLevel = SEVERITY_ORDER[minSeverity] ?? 0;
  return items.filter((item) => (SEVERITY_ORDER[item.severity] ?? 0) >= minLevel);
}
