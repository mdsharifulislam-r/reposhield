import type { RawFinding } from "../rules/types.js";
import { fingerprint } from "./redact.js";
import {
  SEVERITIES,
  severityRank,
  type Finding,
  type ReportSummary,
  type ScoreFactor,
  type Severity,
} from "./types.js";

/** Base score per severity. Documented in docs/scoring.md. */
export const BASE_SCORE: Record<Severity, number> = { info: 5, low: 15, medium: 35, high: 60, critical: 85 };

const CONFIDENCE_DELTA = { low: -10, medium: -4, high: 0 } as const;

/** Signal classes used to detect correlated behaviours within one file. */
function signalClass(ruleId: string): string | undefined {
  if (/^RS-(EXEC|PROC|DL)-/.test(ruleId)) return "execution";
  if (/^RS-(NET|EXFIL)-/.test(ruleId)) return "network";
  if (/^RS-OBF-/.test(ruleId)) return "obfuscation";
  if (ruleId === "RS-FS-001") return "credential-access";
  return undefined;
}

export interface ScoreContext {
  newlyIntroduced: boolean;
}

export function escalate(s: Severity): Severity {
  return SEVERITIES[Math.min(severityRank(s) + 1, SEVERITIES.length - 1)] as Severity;
}

/**
 * Turn raw rule output into scored findings.
 *
 * Severity may be raised by at most one level, only for correlated behaviour
 * (three or more distinct signal classes in one file) or for a medium-or-higher
 * finding that is newly introduced in a sensitive location. It is never lowered.
 */
export function scoreFindings(raws: RawFinding[], isNew: (f: RawFinding) => boolean): Finding[] {
  const classesByFile = new Map<string, Map<string, Set<string>>>();
  for (const r of raws) {
    const c = signalClass(r.ruleId);
    if (!c) continue;
    const m = classesByFile.get(r.file) ?? new Map<string, Set<string>>();
    const set = m.get(c) ?? new Set<string>();
    set.add(r.ruleId);
    m.set(c, set);
    classesByFile.set(r.file, m);
  }

  const ordinals = new Map<string, number>();
  const out: Finding[] = [];
  for (const r of raws) {
    const factors: ScoreFactor[] = [];
    const newly = isNew(r);
    let score = BASE_SCORE[r.severity];
    factors.push({ name: "severity", delta: score, note: `base score for ${r.severity}` });

    const cd = CONFIDENCE_DELTA[r.confidence];
    if (cd !== 0) {
      score += cd;
      factors.push({ name: "confidence", delta: cd, note: `${r.confidence} detection confidence` });
    }
    if (r.sensitiveLocation) {
      score += 10;
      factors.push({
        name: "sensitive-location",
        delta: 10,
        note: "build/tooling config or dependency manifest",
      });
    }
    if (r.lifecycle) {
      score += 10;
      factors.push({ name: "install-time", delta: 10, note: "runs automatically during npm install" });
    }
    if (r.topLevel && r.sensitiveLocation) {
      score += 5;
      factors.push({ name: "runs-at-load", delta: 5, note: "executes when the file is loaded" });
    }
    if (newly) {
      score += 10;
      factors.push({
        name: "newly-introduced",
        delta: 10,
        note: "added in changes relative to the base reference",
      });
    }

    let correlatedWith: string[] | undefined;
    const classes = classesByFile.get(r.file);
    const own = signalClass(r.ruleId);
    let classCount = 0;
    if (classes && own) {
      classCount = classes.size;
      if (classCount >= 2) {
        const bonus = classCount >= 3 ? 15 : 10;
        score += bonus;
        factors.push({
          name: "correlated",
          delta: bonus,
          note: `${classCount} distinct behaviour classes in this file (${[...classes.keys()].sort().join(", ")})`,
        });
        correlatedWith = [...new Set([...classes.values()].flatMap((s) => [...s]))]
          .filter((id) => id !== r.ruleId)
          .sort();
      }
    }

    let severity = r.severity;
    const sr = severityRank(severity);
    if (sr >= severityRank("medium") && sr < severityRank("critical")) {
      if (classCount >= 3) {
        severity = escalate(severity);
        factors.push({
          name: "severity-escalation",
          delta: 0,
          note: "raised one level: three or more correlated behaviour classes",
        });
      } else if (newly && r.sensitiveLocation) {
        severity = escalate(severity);
        factors.push({
          name: "severity-escalation",
          delta: 0,
          note: "raised one level: newly introduced in a sensitive location",
        });
      }
    }

    score = Math.max(0, Math.min(100, score));
    const kc = `${r.ruleId}\u0000${r.file}\u0000${r.key}`;
    const n = (ordinals.get(kc) ?? 0) + 1;
    ordinals.set(kc, n);

    out.push({
      ruleId: r.ruleId,
      title: r.title,
      category: r.category,
      severity,
      confidence: r.confidence,
      file: r.file,
      ...(r.location ? { location: r.location } : {}),
      message: r.message,
      evidence: r.evidence,
      recommendation: r.recommendation,
      score,
      scoreFactors: factors,
      ...(correlatedWith ? { correlatedWith } : {}),
      ...(newly ? { newlyIntroduced: true } : {}),
      fingerprint: fingerprint([r.ruleId, r.file, r.key, n]),
    });
  }
  return out;
}

export function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank(b.severity) - severityRank(a.severity) ||
    b.score - a.score ||
    (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) ||
    (a.location?.line ?? 0) - (b.location?.line ?? 0) ||
    (a.location?.column ?? 0) - (b.location?.column ?? 0) ||
    (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0)
  );
}

export const isActive = (f: Finding): boolean => !f.baselined && !f.allowlisted;

export function riskLevel(score: number): ReportSummary["riskLevel"] {
  if (score <= 0) return "none";
  if (score < 25) return "low";
  if (score < 50) return "elevated";
  if (score < 75) return "high";
  return "critical";
}

/**
 * Aggregate risk: the highest active finding score plus 2 per additional active
 * finding of medium severity or above, capped at 100.
 */
export function aggregateRisk(findings: Finding[]): number {
  const active = findings.filter(isActive);
  if (active.length === 0) return 0;
  const top = Math.max(...active.map((f) => f.score));
  const extra = active.filter((f) => severityRank(f.severity) >= severityRank("medium")).length - 1;
  return Math.min(100, top + Math.max(0, extra) * 2);
}
