/**
 * RepoShield — Secret Detector
 *
 * Detects common secret formats and high-entropy credential candidates.
 * Context-aware false-positive reduction.
 *
 * CRITICAL SECURITY PROPERTIES:
 * - Never logs complete secret values
 * - Redacts sensitive data before inclusion in reports
 * - Never sends detected secrets to external services
 * - Never automatically revokes credentials
 */

import crypto from 'crypto';
import { SecretFinding } from './types.js';

// ─── Secret Pattern Definitions ───────────────────────────────────────────────

interface SecretPattern {
  id: string;
  name: string;
  pattern: RegExp;
  /** Context patterns that increase confidence */
  contextPatterns?: RegExp[];
  /** Context patterns that reduce confidence (false-positive indicators) */
  fpPatterns?: RegExp[];
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'RS-SEC-001',
    name: 'AWS Access Key',
    pattern: /\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/,
  },
  {
    id: 'RS-SEC-002',
    name: 'AWS Secret Access Key',
    pattern: /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/,
    contextPatterns: [/aws_secret|AWS_SECRET|secret_key|SECRET_KEY/i],
    fpPatterns: [/[Ee]xample|[Pp]laceholder|[Tt]odo|REPLACE|your-/i],
  },
  {
    id: 'RS-SEC-003',
    name: 'GitHub Personal Access Token',
    pattern: /ghp_[A-Za-z0-9]{36}/,
  },
  {
    id: 'RS-SEC-004',
    name: 'GitHub OAuth Token',
    pattern: /gho_[A-Za-z0-9]{36}/,
  },
  {
    id: 'RS-SEC-005',
    name: 'GitHub App Token',
    pattern: /ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}/,
  },
  {
    id: 'RS-SEC-006',
    name: 'npm Auth Token',
    pattern: /npm_[A-Za-z0-9]{36,}/,
  },
  {
    id: 'RS-SEC-007',
    name: 'JWT Token',
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    fpPatterns: [/[Ee]xample|[Ff]ake|[Tt]est|[Mm]ock|[Ss]ample/i],
  },
  {
    id: 'RS-SEC-008',
    name: 'Stripe Secret Key',
    pattern: /sk_(live|test)_[A-Za-z0-9]{24,}/,
  },
  {
    id: 'RS-SEC-009',
    name: 'Stripe Publishable Key',
    pattern: /pk_(live|test)_[A-Za-z0-9]{24,}/,
  },
  {
    id: 'RS-SEC-010',
    name: 'Google API Key',
    pattern: /AIza[A-Za-z0-9\-_]{35}/,
  },
  {
    id: 'RS-SEC-011',
    name: 'Slack Token',
    pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/,
  },
  {
    id: 'RS-SEC-012',
    name: 'Private Key Header',
    pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
  },
  {
    id: 'RS-SEC-013',
    name: 'Hardcoded Password Assignment',
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'](?!.*\$\{)[^"'\s]{8,}["']/i,
    fpPatterns: [/[Ee]xample|[Pp]laceholder|your-password|CHANGE_ME|INSERT_YOUR/i],
  },
  {
    id: 'RS-SEC-014',
    name: 'Generic High-Entropy String',
    pattern: /["'][A-Za-z0-9+/=]{32,}["']/,
    contextPatterns: [/secret|token|key|password|auth|credential/i],
    fpPatterns: [/[Ee]xample|base64|[Ss]ample|placeholder|[Ff]ixture|[Mm]ock/i],
  },
  {
    id: 'RS-SEC-015',
    name: 'Database Connection String with Credentials',
    pattern: /(?:mongodb|postgresql|mysql|redis|mssql):\/\/[^:@\s]+:[^@\s]+@/i,
    fpPatterns: [/localhost|127\.0\.0\.1|example\.com/i],
  },
  {
    id: 'RS-SEC-016',
    name: 'Heroku API Key',
    pattern: /[h|H][e|E][r|R][o|O][k|K][u|U][_\-\s]+[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/,
  },
  {
    id: 'RS-SEC-017',
    name: 'SendGrid API Key',
    pattern: /SG\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}/,
  },
  {
    id: 'RS-SEC-018',
    name: 'Twilio API Key',
    pattern: /SK[A-Za-z0-9]{32}/,
    contextPatterns: [/twilio|TWILIO/i],
  },
];

// ─── Shannon Entropy Calculator ───────────────────────────────────────────────

function shannonEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Returns true if the string has high entropy suggestive of a secret/key. */
function isHighEntropy(value: string, threshold = 3.5): boolean {
  if (value.length < 20) return false;
  return shannonEntropy(value) > threshold;
}

// ─── Context Window ───────────────────────────────────────────────────────────

function getContextWindow(lines: string[], lineIndex: number, window = 2): string {
  const start = Math.max(0, lineIndex - window);
  const end = Math.min(lines.length - 1, lineIndex + window);
  return lines.slice(start, end + 1).join('\n');
}

// ─── Redaction ────────────────────────────────────────────────────────────────

/**
 * Produce a redacted representation of a secret.
 * Shows type prefix + masked value. Never the full value.
 */
function redactValue(secretType: string, fullValue: string): string {
  if (fullValue.length <= 8) return `[${secretType}:REDACTED]`;
  const prefix = fullValue.substring(0, 4);
  const suffix = fullValue.substring(fullValue.length - 2);
  return `${prefix}${'*'.repeat(Math.min(8, fullValue.length - 6))}${suffix}`;
}

// ─── Main Secret Detection Function ──────────────────────────────────────────

export function detectSecrets(
  filePath: string,
  content: string,
  opts: { isNewlyIntroduced?: boolean } = {},
): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = content.split('\n');

  // Skip test fixture files and documentation
  if (isLikelyFalsePositiveFile(filePath)) return findings;

  const seen = new Set<string>(); // Deduplicate by (ruleId, line)

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex] ?? '';

    // Skip comments. npmrc registry scopes start with "//host/" and are not comments.
    const trimmed = line.trim();
    const isNpmrcRegistry = /^\/\/[^/\s]+\/.*:_/.test(trimmed);
    if ((trimmed.startsWith('//') && !isNpmrcRegistry) || trimmed.startsWith('#')) continue;

    const context = getContextWindow(lines, lineIndex);

    for (const secretPattern of SECRET_PATTERNS) {
      const match = secretPattern.pattern.exec(line);
      if (!match) continue;

      const matchedValue = match[0];

      // Check false-positive patterns
      if (secretPattern.fpPatterns?.some((fp) => fp.test(line) || fp.test(context))) {
        continue;
      }

      // For high-entropy generic pattern, require context
      if (secretPattern.id === 'RS-SEC-014') {
        const hasContext = secretPattern.contextPatterns?.some(
          (cp) => cp.test(line) || cp.test(context),
        );
        if (!hasContext) continue;
        if (!isHighEntropy(matchedValue.replace(/['"]/g, ''))) continue;
      }

      // For AWS secret key, require context pattern
      if (secretPattern.id === 'RS-SEC-002') {
        const hasContext = secretPattern.contextPatterns?.some(
          (cp) => cp.test(line) || cp.test(context),
        );
        if (!hasContext) continue;
      }

      const dedupeKey = `${secretPattern.id}:${lineIndex + 1}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      const entropy = isHighEntropy(matchedValue.replace(/['"]/g, ''));
      const redacted = redactValue(secretPattern.name, matchedValue);

      findings.push({
        ruleId: secretPattern.id,
        filePath,
        line: lineIndex + 1,
        redactedValue: redacted,
        secretType: secretPattern.name,
        isHighEntropy: entropy,
        isNewlyIntroduced: opts.isNewlyIntroduced,
        remediation: buildSecretRemediation(secretPattern.name),
      });
    }
  }

  return findings;
}

// ─── False Positive File Detection ───────────────────────────────────────────

const FP_FILE_PATTERNS = [
  /\.test\.(ts|js|tsx|jsx)$/i,
  /\.spec\.(ts|js|tsx|jsx)$/i,
  /fixtures?\//i,
  /\/__mocks__\//i,
  /\/test-data\//i,
  /CHANGELOG/i,
  /README/i,
  /\.md$/i,
];

function isLikelyFalsePositiveFile(filePath: string): boolean {
  return FP_FILE_PATTERNS.some((p) => p.test(filePath));
}

// ─── Remediation Builder ──────────────────────────────────────────────────────

function buildSecretRemediation(secretType: string): string {
  return (
    `A "${secretType}" was detected. Steps: ` +
    '(1) Remove the secret from the file immediately. ' +
    '(2) Rotate/revoke the credential via its provider dashboard. ' +
    '(3) Check if the secret was ever committed to Git history — use `git log -p` to verify. ' +
    '(4) If in Git history, use git filter-repo or contact your hosting provider. ' +
    '(5) Use environment variables or a secrets manager instead. ' +
    'WARNING: This tool does NOT send secrets to any external service. Rotation must be done manually.'
  );
}
