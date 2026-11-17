import { ALL_RULES } from "../rules/index.js";
import type { Finding, Report, Severity } from "../core/types.js";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

/** SARIF 2.1.0 for GitHub code scanning. Evidence is already redacted; no raw secrets are emitted. */
export function renderSarif(report: Report): string {
  const used = new Set(report.findings.map((f) => f.ruleId));
  const rules = ALL_RULES.filter((r) => used.has(r.id)).map((r) => ({
    id: r.id,
    name: r.id.replace(/-/g, ""),
    shortDescription: { text: r.title },
    fullDescription: { text: r.description },
    defaultConfiguration: { level: LEVEL[r.severity] },
    properties: { category: r.category, "security-severity": secSeverity(r.severity) },
  }));
  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));

  const results = report.findings.map((f: Finding) => {
    const suppressions: Array<{ kind: "external"; justification: string }> = [];
    if (f.baselined)
      suppressions.push({ kind: "external", justification: "Accepted in the RepoShield baseline." });
    if (f.allowlisted)
      suppressions.push({ kind: "external", justification: `Allowlisted: ${f.allowlisted.reason}` });
    return {
      ruleId: f.ruleId,
      ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
      level: LEVEL[f.severity],
      message: { text: `${f.message} ${f.evidence.join("; ")}`.trim() },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.file, uriBaseId: "%SRCROOT%" },
            region: {
              startLine: f.location?.line ?? 1,
              startColumn: f.location?.column ?? 1,
              ...(f.location?.endLine ? { endLine: f.location.endLine } : {}),
              ...(f.location?.endColumn ? { endColumn: f.location.endColumn } : {}),
            },
          },
        },
      ],
      partialFingerprints: { "reposhieldFingerprint/v1": f.fingerprint },
      properties: {
        severity: f.severity,
        confidence: f.confidence,
        score: f.score,
        recommendation: f.recommendation,
        ...(f.newlyIntroduced ? { newlyIntroduced: true } : {}),
      },
      ...(suppressions.length ? { suppressions } : {}),
    };
  });

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "RepoShield",
            version: report.tool.version,
            informationUri: "https://github.com/reposhield/reposhield",
            rules,
          },
        },
        originalUriBaseIds: { "%SRCROOT%": { uri: "file:///" } },
        results,
        columnKind: "utf16CodeUnits",
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

function secSeverity(s: Severity): string {
  return { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" }[s];
}
