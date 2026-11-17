export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = ["low", "medium", "high"] as const;
export type Confidence = (typeof CONFIDENCES)[number];

export const MODES = ["audit", "strict", "ci", "changed", "monitor"] as const;
export type Mode = (typeof MODES)[number];

export type FindingCategory =
  | "dynamic-execution"
  | "process-execution"
  | "obfuscation"
  | "network"
  | "exfiltration"
  | "download-execute"
  | "sensitive-module"
  | "secret"
  | "lifecycle-script"
  | "dependency"
  | "config-file"
  | "git-change"
  | "baseline"
  | "scan-error";

export interface SourceLocation {
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
}

export interface Finding {
  /** Stable identifier of the rule that produced the finding, e.g. `RS-EXEC-001`. */
  ruleId: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  /** Path relative to the scan root, always using forward slashes. */
  file: string;
  location?: SourceLocation;
  /** Short explanation of why this matters. Never contains raw secrets. */
  message: string;
  /** Redacted, human-readable evidence summary. */
  evidence: string[];
  recommendation: string;
  /** Explainable 0-100 score; see docs/scoring.md. */
  score: number;
  /** Breakdown of how the score was derived. */
  scoreFactors: ScoreFactor[];
  /** Rule IDs of related findings in the same file that were correlated. */
  correlatedWith?: string[];
  /** True when the finding is in a file/line changed relative to the base ref. */
  newlyIntroduced?: boolean;
  /** Stable fingerprint used by baselines. Does not contain raw secrets. */
  fingerprint: string;
  /** Set when a finding is matched by the accepted baseline. It stays visible but does not fail policy. */
  baselined?: boolean;
  /** Set when a project allowlist entry matched. It stays visible but does not fail policy. */
  allowlisted?: { reason: string };
}

export interface ScoreFactor {
  name: string;
  delta: number;
  note: string;
}

export interface ScanError {
  file: string;
  kind: "parse" | "read" | "too-large" | "binary" | "unsupported" | "symlink" | "other";
  message: string;
}

export interface GitContext {
  available: boolean;
  isRepository: boolean;
  head?: string;
  branch?: string | null;
  detached?: boolean;
  shallow?: boolean;
  baseRef?: string;
  changedFiles: string[];
  notes: string[];
}

export interface ReportSummary {
  filesScanned: number;
  filesSkipped: number;
  findingsTotal: number;
  bySeverity: Record<Severity, number>;
  newFindings: number;
  baselinedFindings: number;
  allowlistedFindings: number;
  /** Findings that count toward policy (not baselined, not allowlisted). */
  activeFindings: number;
  highestSeverity: Severity | "none";
  riskScore: number;
  riskLevel: "none" | "low" | "elevated" | "high" | "critical";
  errors: number;
}

export interface Report {
  tool: { name: "reposhield"; version: string };
  mode: Mode;
  root: string;
  /** ISO timestamp. Omitted in `ci` mode for deterministic output. */
  generatedAt?: string;
  /** False when policy thresholds are violated. `true` never means "proven safe". */
  safe: boolean;
  /** Why `safe` has its value. */
  policy: { failOn: Severity; failedBecause: string[] };
  summary: ReportSummary;
  findings: Finding[];
  errors: ScanError[];
  /** General notes about coverage and configuration (missing baseline, truncated scans, ...). */
  notes: string[];
  git: GitContext;
  disclaimer: string;
}

export const DISCLAIMER =
  "RepoShield uses heuristics. A clean result does not prove a repository is safe, " +
  "and a finding is a lead to review, not proof of malware.";

export function severityRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return severityRank(a) >= severityRank(b) ? a : b;
}
