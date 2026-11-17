import { sanitizeForTerminal } from "../core/redact.js";
import { SEVERITIES, type Finding, type Report, type Severity } from "../core/types.js";

const COLORS: Record<Severity, string> = {
  critical: "\u001b[1;41;97m",
  high: "\u001b[1;31m",
  medium: "\u001b[33m",
  low: "\u001b[36m",
  info: "\u001b[2m",
};
const RESET = "\u001b[0m";
const BADGE: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

export interface TextOptions {
  color?: boolean;
  /** Show every finding, including baselined and allowlisted ones. Default true. */
  verbose?: boolean;
}

const s = sanitizeForTerminal;

export function renderText(report: Report, o: TextOptions = {}): string {
  const paint = (sev: Severity, text: string): string => (o.color ? `${COLORS[sev]}${text}${RESET}` : text);
  const dim = (t: string): string => (o.color ? `\u001b[2m${t}${RESET}` : t);
  const lines: string[] = [];
  const sum = report.summary;

  lines.push(`RepoShield ${report.tool.version}  mode=${report.mode}  root=${s(report.root)}`);
  lines.push("");
  const result = report.safe ? "PASS" : "FAIL";
  lines.push(
    `Result: ${result}  risk ${sum.riskScore}/100 (${sum.riskLevel})  fail-on=${report.policy.failOn}`,
  );
  lines.push(
    `Scanned ${sum.filesScanned} files (${sum.filesSkipped} skipped). ${sum.activeFindings} active finding(s)` +
      `${sum.baselinedFindings ? `, ${sum.baselinedFindings} baselined` : ""}` +
      `${sum.allowlistedFindings ? `, ${sum.allowlistedFindings} allowlisted` : ""}` +
      `${sum.newFindings ? `, ${sum.newFindings} newly introduced` : ""}.`,
  );
  const counts = SEVERITIES.slice()
    .reverse()
    .filter((x) => sum.bySeverity[x] > 0)
    .map((x) => `${x}: ${sum.bySeverity[x]}`);
  if (counts.length) lines.push(counts.join("  "));
  for (const why of report.policy.failedBecause) lines.push(`Policy: ${s(why)}`);

  const visible = report.findings.filter((f) => o.verbose !== false || (!f.baselined && !f.allowlisted));
  // Group by file; files with the most severe findings come first, findings keep their ranking.
  const order = new Map<string, number>();
  visible.forEach((f, i) => {
    if (!order.has(f.file)) order.set(f.file, i);
  });
  const shown = visible.slice().sort((a, b) => (order.get(a.file) ?? 0) - (order.get(b.file) ?? 0));
  if (shown.length) lines.push("");
  let lastFile = "";
  for (const f of shown) {
    if (f.file !== lastFile) {
      lines.push(o.color ? `\u001b[1m${s(f.file)}\u001b[0m` : s(f.file));
      lastFile = f.file;
    }
    lines.push(...renderFinding(f, paint, dim));
  }

  if (report.errors.length) {
    lines.push("", `Coverage notes (${report.errors.length}):`);
    for (const e of report.errors.slice(0, 20)) lines.push(`  - ${s(e.file)}: ${e.kind}: ${s(e.message)}`);
    if (report.errors.length > 20)
      lines.push(`  ... and ${report.errors.length - 20} more (see --format json)`);
  }
  if (report.notes.length) {
    lines.push("", "Notes:");
    for (const n of report.notes) lines.push(`  - ${s(n)}`);
  }
  lines.push("", report.disclaimer);
  return `${lines.join("\n")}\n`;
}

function renderFinding(
  f: Finding,
  paint: (s: Severity, t: string) => string,
  dim: (t: string) => string,
): string[] {
  const where = f.location ? `${f.location.line}:${f.location.column}` : "-";
  const tags = [
    f.newlyIntroduced ? "NEW" : "",
    f.baselined ? "baselined" : "",
    f.allowlisted ? `allowlisted: ${f.allowlisted.reason}` : "",
  ]
    .filter(Boolean)
    .join(", ");
  const out = [
    `  ${paint(f.severity, `[${BADGE[f.severity]}]`)} ${f.ruleId} ${s(f.title)}  ${dim(`${where}  confidence: ${f.confidence}  score: ${f.score}${tags ? `  (${s(tags)})` : ""}`)}`,
    `      ${s(f.message)}`,
  ];
  for (const e of f.evidence) out.push(`      · ${s(e)}`);
  if (f.correlatedWith?.length) out.push(`      · correlated with: ${f.correlatedWith.join(", ")}`);
  out.push(`      → ${s(f.recommendation)}`);
  return out;
}
