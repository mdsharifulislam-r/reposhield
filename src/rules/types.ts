import type { Confidence, FindingCategory, Severity, SourceLocation } from "../core/types.js";

export interface RuleMeta {
  id: string;
  title: string;
  category: FindingCategory;
  /** Baseline severity. Scoring may escalate it, never lower it. */
  severity: Severity;
  description: string;
}

/** A finding as emitted by a rule, before scoring, fingerprinting and policy are applied. */
export interface RawFinding {
  ruleId: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  file: string;
  location?: SourceLocation;
  message: string;
  /** Redacted evidence lines. Rules must never put raw secret values here. */
  evidence: string[];
  recommendation: string;
  /**
   * Stable, content-free description of the matched construct, used to build
   * baseline fingerprints (e.g. `eval|arg:decoded`). Must not contain secrets.
   */
  key: string;
  topLevel?: boolean;
  /** The file is a build/tooling config or another security-sensitive location. */
  sensitiveLocation?: boolean;
  lifecycle?: boolean;
}

export const loc = (s: {
  line: number;
  column: number;
  endLine?: number | undefined;
  endColumn?: number | undefined;
}): SourceLocation => ({
  line: s.line,
  column: s.column,
  ...(s.endLine !== undefined ? { endLine: s.endLine } : {}),
  ...(s.endColumn !== undefined ? { endColumn: s.endColumn } : {}),
});
