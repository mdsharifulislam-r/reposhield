/**
 * RepoShield — Core Type Definitions
 *
 * Stable public API types. Changes to these types follow semantic versioning.
 */

// ─── Scan Mode ────────────────────────────────────────────────────────────────

/**
 * Scan mode controls behavior and exit-code semantics.
 *
 * - `audit`   : Inspect and report. Never block. Never modify files.
 * - `strict`  : Block on configured severity thresholds. No file modification.
 * - `ci`      : Machine-readable JSON output; non-zero exit on policy violation.
 * - `changed` : Inspect only files changed relative to a trusted baseline.
 * - `monitor` : Local watch mode. Not suitable for CI enforcement.
 */
export type ScanMode = 'audit' | 'strict' | 'ci' | 'changed' | 'monitor';

// ─── Severity & Confidence ────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'confirmed' | 'high' | 'medium' | 'low' | 'speculative';

// ─── Finding ──────────────────────────────────────────────────────────────────

/**
 * A single detected issue. Immutable once produced.
 */
export interface Finding {
  /** Stable rule identifier, e.g. "RS-AST-001". */
  readonly ruleId: string;
  /** Human-readable rule name. */
  readonly ruleName: string;
  /** Rule schema version, e.g. "1". */
  readonly ruleVersion: string;
  /** Severity classification. */
  readonly severity: Severity;
  /** Confidence level — do not present as a probability. */
  readonly confidence: Confidence;
  /** Absolute path to the affected file. */
  readonly filePath: string;
  /** Line number (1-based) or undefined for manifest-level findings. */
  readonly line?: number;
  /** Column number (1-based) or undefined. */
  readonly column?: number;
  /** Human-readable description of the finding. */
  readonly message: string;
  /** Evidence snippets. Secrets MUST be redacted before inclusion. */
  readonly evidence: readonly string[];
  /** Remediation guidance. */
  readonly remediation: string;
  /** Risk score 0–100. Deterministic and explainable, not a calibrated probability. */
  readonly riskScore: number;
  /** Correlated sub-signals that contributed to this finding. */
  readonly correlatedSignals?: readonly CorrelatedSignal[];
  /** Whether this finding was introduced in the current change set. */
  readonly isNewlyIntroduced?: boolean;
  /** Whether this finding is suppressed by a configured rule. */
  readonly suppressed?: boolean;
  /** The suppression entry that applies, if any. */
  readonly suppressedBy?: SuppressionEntry;
}

export interface CorrelatedSignal {
  readonly signalId: string;
  readonly description: string;
  readonly weight: number;
}

// ─── Suppression ──────────────────────────────────────────────────────────────

export interface SuppressionEntry {
  /** Rule ID to suppress, e.g. "RS-AST-001". Must be specific. */
  readonly ruleId: string;
  /** Glob pattern for files to suppress, or undefined for repo-wide. */
  readonly path?: string;
  /** Human-readable reason for suppression. Required. */
  readonly reason: string;
  /** ISO-8601 expiry date. Expired suppressions are reported. */
  readonly expiresAt?: string;
  /** Reviewer or ticket reference. */
  readonly reviewer?: string;
}

// ─── Skipped File Record ──────────────────────────────────────────────────────

export interface SkippedFile {
  readonly filePath: string;
  readonly reason:
    | 'binary'
    | 'oversized'
    | 'unreadable'
    | 'excluded'
    | 'symlink-external'
    | 'parse-error';
  readonly details?: string;
}

// ─── Dependency Finding ───────────────────────────────────────────────────────

export interface DependencyFinding {
  readonly packageName: string;
  readonly version: string;
  readonly findingType:
    | 'lifecycle-script'
    | 'git-dependency'
    | 'url-dependency'
    | 'registry-change'
    | 'typosquat-candidate'
    | 'lockfile-inconsistency'
    | 'known-vulnerability'
    | 'new-dependency'
    | 'suspicious-source';
  readonly severity: Severity;
  readonly message: string;
  readonly remediation: string;
  readonly evidence?: string;
}

// ─── Git Finding ─────────────────────────────────────────────────────────────

export interface GitFinding {
  readonly findingType:
    | 'suspicious-commit'
    | 'new-executable'
    | 'hook-tamper'
    | 'security-control-change'
    | 'baseline-change'
    | 'scanner-config-change';
  readonly severity: Severity;
  readonly commitSha?: string;
  readonly filePath?: string;
  readonly message: string;
  readonly remediation: string;
}

// ─── Secret Finding ──────────────────────────────────────────────────────────

export interface SecretFinding {
  readonly ruleId: string;
  readonly filePath: string;
  readonly line: number;
  /** Redacted representation — never the full secret value. */
  readonly redactedValue: string;
  readonly secretType: string;
  readonly isHighEntropy: boolean;
  readonly isNewlyIntroduced?: boolean;
  readonly remediation: string;
}

// ─── Scan Summary ─────────────────────────────────────────────────────────────

export interface ScanSummary {
  readonly scannedAt: string;
  readonly scanDurationMs: number;
  readonly mode: ScanMode;
  readonly root: string;
  readonly totalFilesDiscovered: number;
  readonly totalFilesScanned: number;
  readonly totalFilesSkipped: number;
  readonly findings: readonly Finding[];
  readonly dependencyFindings: readonly DependencyFinding[];
  readonly gitFindings: readonly GitFinding[];
  readonly secretFindings: readonly SecretFinding[];
  readonly skippedFiles: readonly SkippedFile[];
  readonly suppressedCount: number;
  readonly expiredSuppressions: readonly SuppressionEntry[];
  readonly policyViolation: boolean;
  readonly policyViolationReasons: readonly string[];
  readonly cacheHits: number;
  readonly gitBaseSha?: string;
}

// ─── Scan Options ─────────────────────────────────────────────────────────────

export interface ScanOptions {
  /** Absolute path to the repository root. Defaults to process.cwd(). */
  root?: string;
  /** Scan mode. Default: 'audit'. */
  mode?: ScanMode;
  /** Trusted Git base SHA or branch reference for change-based scans. */
  baseSha?: string;
  /** Additional glob patterns to exclude. */
  exclude?: string[];
  /** Maximum file size in bytes. Default: 512 KB. */
  maxFileSizeBytes?: number;
  /** Maximum number of files to scan concurrently. Default: 4. */
  concurrency?: number;
  /** Disable caching. Default: false. */
  noCache?: boolean;
  /** Minimum severity to include in report. Default: 'info'. */
  minSeverity?: Severity;
  /** Enable network-backed advisory checks. Default: false. */
  networkAdvisory?: boolean;
  /** Timeout for network requests in milliseconds. Default: 10000. */
  networkTimeoutMs?: number;
  /** AbortSignal for cancellation. */
  signal?: AbortSignal;
  /** Path to reposhield config file. Auto-detected if not specified. */
  configPath?: string;
  /** Suppress console output. */
  quiet?: boolean;
}

// ─── RepoShield Config File Schema ────────────────────────────────────────────

export interface RepoShieldConfig {
  readonly version: 1;
  /** Glob patterns to exclude from scanning. Applied after built-in exclusions. */
  readonly exclude?: readonly string[];
  /** Maximum file size in bytes. */
  readonly maxFileSizeBytes?: number;
  /** Suppression entries. */
  readonly suppressions?: readonly SuppressionEntry[];
  /** Policy configuration. */
  readonly policy?: PolicyConfig;
  /** Trusted baseline SHA (used in 'changed' mode if --base not specified). */
  readonly trustedBaseSha?: string;
}

export interface PolicyConfig {
  /** Block on critical findings. Default: true in strict/ci mode. */
  readonly blockOnCritical?: boolean;
  /** Block on high findings. Default: true in strict/ci mode. */
  readonly blockOnHigh?: boolean;
  /** Block on medium findings. Default: false. */
  readonly blockOnMedium?: boolean;
  /** Block on any secret findings. Default: true in strict/ci mode. */
  readonly blockOnSecrets?: boolean;
  /** Block on dependency findings at this severity or above. */
  readonly blockOnDependencyFindings?: Severity;
}

// ─── Stable Error Types ───────────────────────────────────────────────────────

export class RepoShieldError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = 'RepoShieldError';
  }
}

export class ConfigError extends RepoShieldError {
  constructor(message: string) {
    super(message, 'CONFIG_ERROR');
    this.name = 'ConfigError';
  }
}

export class GitError extends RepoShieldError {
  constructor(message: string) {
    super(message, 'GIT_ERROR');
    this.name = 'GitError';
  }
}

export class ScanAbortedError extends RepoShieldError {
  constructor(message = 'Scan was aborted') {
    super(message, 'SCAN_ABORTED');
    this.name = 'ScanAbortedError';
  }
}

// ─── Rule Definition ─────────────────────────────────────────────────────────

export interface RuleDefinition {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly description: string;
  readonly remediation: string;
  readonly tags: readonly string[];
  readonly enabled: boolean;
}
