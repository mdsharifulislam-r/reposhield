import fs from "node:fs/promises";
import path from "node:path";
import picomatch from "picomatch";
import { extractFacts } from "../analyzers/extract.js";
import { isConfigFilePath } from "../analyzers/facts.js";
import { analyzeGit, isLineAdded, showAtRef, type GitAnalysis } from "../git/git.js";
import { JS_RULES } from "../rules/index.js";
import {
  analyzeNpmrc,
  analyzePackageJson,
  analyzePackageLock,
  analyzeTextLockfile,
  parsePackageJson,
} from "../rules/package.js";
import { secretFindings } from "../rules/secrets.js";
import { inspectVSCodeTasks } from "../rules/vscode.js";
import { loc, type RawFinding } from "../rules/types.js";
import { applyBaseline, loadBaseline, type Baseline, type BaselineEntry } from "./baseline.js";
import {
  ConfigError,
  SCANNABLE_EXTENSIONS,
  isInside,
  resolveOptions,
  type RepoShieldOptions,
  type ResolvedOptions,
} from "./options.js";
import { snippet } from "./redact.js";
import { aggregateRisk, compareFindings, isActive, riskLevel, scoreFindings } from "./scoring.js";
import {
  CONFIDENCES,
  DISCLAIMER,
  SEVERITIES,
  severityRank,
  type Report,
  type ReportSummary,
  type ScanError,
  type Severity,
} from "./types.js";
import { VERSION } from "./version.js";
import { abortError, errMsg, mapLimit, toPosix, walk, type WalkedFile } from "./walker.js";

const JS_EXT = new Set(SCANNABLE_EXTENSIONS);
const TEXT_EXT = [".json", ".yml", ".yaml", ".toml", ".env", ".sh", ".properties", ".ini", ".cfg", ".conf"];
const SPECIAL_NAMES = [
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  ".npmrc",
  ".env",
  ".env.local",
  ".env.production",
  ".env.development",
  ".env.test",
];

type Kind = "js" | "package" | "lock" | "textlock" | "npmrc" | "text";

function kindOf(rel: string): Kind {
  const base = rel.slice(rel.lastIndexOf("/") + 1).toLowerCase();
  if (base === "package.json") return "package";
  if (base === "package-lock.json" || base === "npm-shrinkwrap.json") return "lock";
  if (base === "yarn.lock" || base === "pnpm-lock.yaml") return "textlock";
  if (base === ".npmrc") return "npmrc";
  if (JS_EXT.has(path.extname(base))) return "js";
  return "text";
}

export interface ScanInternals {
  report: Report;
  git: GitAnalysis;
  baseline: Baseline | null;
  resolved: BaselineEntry[];
  opts: ResolvedOptions;
}

interface FileOutcome {
  raws: RawFinding[];
  errors: ScanError[];
  scanned: boolean;
}

function binaryLike(buf: Buffer): boolean {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

async function analyzeFile(f: WalkedFile, opts: ResolvedOptions, git: GitAnalysis): Promise<FileOutcome> {
  const kind = kindOf(f.rel);
  const errors: ScanError[] = [];
  const raws: RawFinding[] = [];
  const configFile = isConfigFilePath(f.rel);

  if (f.size > opts.maxFileSizeBytes) {
    errors.push({
      file: f.rel,
      kind: "too-large",
      message: `File is ${f.size} bytes; limit is ${opts.maxFileSizeBytes}.`,
    });
    if (kind === "js") {
      raws.push({
        ruleId: "RS-SCAN-002",
        title: "File too large to analyze",
        category: "scan-error",
        severity: "medium",
        confidence: "medium",
        file: f.rel,
        ...(configFile ? { sensitiveLocation: true } : {}),
        location: loc({ line: 1, column: 1 }),
        message: `This source file is ${f.size} bytes, above the ${opts.maxFileSizeBytes}-byte limit, so it was not analyzed. Oversized files can hide code from scanners.`,
        evidence: [`size: ${f.size} bytes`, `limit: ${opts.maxFileSizeBytes} bytes`],
        recommendation:
          "Review the file manually, or raise maxFileSizeBytes if it is a legitimate generated file.",
        key: "too-large",
      });
    }
    return { raws, errors, scanned: false };
  }

  let buf: Buffer;
  try {
    buf = await fs.readFile(f.abs);
  } catch (err) {
    errors.push({ file: f.rel, kind: "read", message: errMsg(err) });
    return { raws, errors, scanned: false };
  }
  if (binaryLike(buf)) {
    errors.push({ file: f.rel, kind: "binary", message: "Binary content skipped." });
    return { raws, errors, scanned: false };
  }
  let text = buf.toString("utf8");
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

  const parseFail = (what: string, message: string): void => {
    errors.push({ file: f.rel, kind: "parse", message });
    raws.push({
      ruleId: "RS-SCAN-001",
      title: "File could not be parsed",
      category: "scan-error",
      severity: configFile || opts.mode === "strict" || opts.mode === "ci" ? "medium" : "low",
      confidence: "medium",
      file: f.rel,
      ...(configFile || kind === "package" ? { sensitiveLocation: true } : {}),
      location: loc({ line: 1, column: 1 }),
      message: `${what} could not be parsed, so it was not fully analyzed. Unparseable code cannot be checked.`,
      evidence: [`parser: ${snippet(message, 100)}`],
      recommendation: "Fix the syntax error or review the file manually.",
      key: "parse-error",
    });
  };

  switch (kind) {
    case "js": {
      let facts: ReturnType<typeof extractFacts>;
      try {
        facts = extractFacts(text, f.rel);
      } catch (err) {
        // Analysis failures (for example scope errors on invalid code) must never abort the scan.
        facts = {
          ...extractFacts("", f.rel),
          parseError: `analysis failed: ${errMsg(err).split("\n")[0] ?? "error"}`,
        };
      }
      if (!facts.parsed) {
        parseFail("This file", facts.parseError ?? "parse error");
      } else {
        for (const rule of JS_RULES) {
          try {
            raws.push(...rule.run(facts));
          } catch (err) {
            errors.push({ file: f.rel, kind: "other", message: `Rule ${rule.id} failed: ${errMsg(err)}` });
          }
        }
      }
      raws.push(...secretFindings(f.rel, text, configFile));
      break;
    }
    case "package": {
      let base: ReturnType<typeof parsePackageJson> | null | undefined;
      if (git.runner && git.effectiveBase && git.context.changedFiles.includes(f.rel)) {
        const old = await showAtRef(git.runner, git.effectiveBase, f.rel);
        base = typeof old === "string" ? parsePackageJson(old) : undefined;
      }
      const r = analyzePackageJson({ file: f.rel, text, ...(base ? { base } : {}) });
      if (r.parseError) parseFail("package.json", r.parseError);
      raws.push(...r.findings, ...secretFindings(f.rel, text, true));
      break;
    }
    case "lock": {
      let pkgText: string | undefined;
      try {
        pkgText = await fs.readFile(path.join(path.dirname(f.abs), "package.json"), "utf8");
      } catch {
        pkgText = undefined;
      }
      const r = analyzePackageLock(f.rel, text, pkgText);
      if (r.parseError) parseFail("Lockfile", r.parseError);
      raws.push(...r.findings);
      break;
    }
    case "textlock":
      raws.push(...analyzeTextLockfile(f.rel, text));
      break;
    case "npmrc":
      raws.push(...analyzeNpmrc(f.rel, text), ...secretFindings(f.rel, text, true));
      break;
    default:
      if (/(^|\/)\.vscode\/tasks\.json$/i.test(f.rel)) {
        raws.push(...inspectVSCodeTasks(f.rel, text).findings);
      }
      raws.push(...secretFindings(f.rel, text, false));
  }
  return { raws, errors, scanned: true };
}

function ruleMatcher(patterns: string[]): (id: string) => boolean {
  if (patterns.length === 0) return () => false;
  return picomatch(patterns, { nocase: false });
}

export async function runScan(input: RepoShieldOptions = {}, only?: string[]): Promise<ScanInternals> {
  const opts = resolveOptions(input);
  const signal = opts.signal;
  if (signal?.aborted) throw abortError();

  let rootStat;
  try {
    rootStat = await fs.stat(opts.rootAbs);
  } catch {
    throw new ConfigError(`Scan root does not exist: ${opts.rootAbs}`);
  }
  if (!rootStat.isDirectory()) throw new ConfigError(`Scan root is not a directory: ${opts.rootAbs}`);

  const git = await analyzeGit(opts.rootAbs, {
    baseRef: opts.baseRef,
    mode: opts.mode,
    signal,
    enabled: opts.includeGitHistory,
  });
  const notes: string[] = [];

  let files: WalkedFile[];
  let skipped: number;
  const errors: ScanError[] = [];
  if (only) {
    files = [];
    skipped = 0;
    for (const abs of only) {
      const st = await fs.stat(abs);
      files.push({ abs, rel: toPosix(path.relative(opts.rootAbs, abs)), size: st.size });
    }
  } else {
    const w = await walk(opts, [...SCANNABLE_EXTENSIONS, ...TEXT_EXT], SPECIAL_NAMES);
    files = w.files;
    skipped = w.skipped;
    errors.push(...w.errors);
  }

  if (opts.mode === "changed") {
    if (git.runner) {
      const changed = new Set(git.context.changedFiles);
      const before = files.length;
      files = files.filter((f) => changed.has(f.rel));
      skipped += before - files.length;
      notes.push(
        `changed mode: ${files.length} of ${before} candidate files changed relative to ${git.context.baseRef ?? "HEAD"}.`,
      );
    } else {
      notes.push("changed mode requires a Git repository with history; scanned all files instead.");
    }
  }

  const outcomes = await mapLimit(files, opts.concurrency, (f) => analyzeFile(f, opts, git), signal);
  let raws: RawFinding[] = [];
  let scanned = 0;
  for (const o of outcomes) {
    raws.push(...o.raws);
    errors.push(...o.errors);
    if (o.scanned) scanned++;
    else skipped++;
  }

  // Baseline file tampering check.
  const baselineRel = opts.baselinePath ? toPosix(path.relative(opts.rootAbs, opts.baselinePath)) : undefined;
  if (baselineRel && git.context.changedFiles.includes(baselineRel)) {
    raws.push({
      ruleId: "RS-BASE-001",
      title: "Baseline file changed",
      category: "baseline",
      severity: "medium",
      confidence: "high",
      file: baselineRel,
      sensitiveLocation: true,
      location: loc({ line: 1, column: 1 }),
      message:
        "The accepted-findings baseline was modified relative to the base reference. New entries silence findings, so they need review.",
      evidence: [`file: ${baselineRel}`, `compared against: ${git.context.baseRef ?? "HEAD"}`],
      recommendation: "Review the baseline diff and confirm each newly accepted finding is understood.",
      key: "baseline-changed",
    });
  }

  // Rule configuration.
  const disabled = ruleMatcher(opts.disabledRules);
  raws = raws.filter((r) => !disabled(r.ruleId));
  const minRank = CONFIDENCES.indexOf(opts.minConfidence);
  raws = raws.filter((r) => CONFIDENCES.indexOf(r.confidence) >= minRank);
  for (const r of raws) {
    for (const [pattern, sev] of Object.entries(opts.severityOverrides)) {
      if (picomatch.isMatch(r.ruleId, pattern)) r.severity = sev;
    }
  }

  const isNew = (r: RawFinding): boolean => {
    if (!git.effectiveBase) return false;
    return isLineAdded(git.added.get(r.file), r.location?.line);
  };
  const findings = scoreFindings(raws, isNew);

  // Allowlist (findings remain visible and are labelled).
  for (const entry of opts.allowlist) {
    const idMatch = ruleMatcher([entry.ruleId]);
    const pathMatch = entry.path ? picomatch(entry.path, { dot: true }) : () => true;
    for (const f of findings)
      if (!f.allowlisted && idMatch(f.ruleId) && pathMatch(f.file)) f.allowlisted = { reason: entry.reason };
  }

  // Baseline.
  let baseline: Baseline | null = null;
  let resolved: BaselineEntry[] = [];
  if (opts.baselinePath) {
    baseline = await loadBaseline(opts.baselinePath);
    if (baseline) resolved = applyBaseline(findings, baseline).resolved;
    else
      notes.push(
        `Baseline not found at ${toPosix(path.relative(opts.rootAbs, opts.baselinePath))}; no findings were accepted.`,
      );
  }

  findings.sort(compareFindings);
  errors.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.message < b.message ? -1 : 1));
  for (const n of git.context.notes) if (!notes.includes(n)) notes.push(n);

  // Policy.
  const active = findings.filter(isActive);
  const failedBecause: string[] = [];
  const violating = active.filter((f) => severityRank(f.severity) >= severityRank(opts.failOn));
  if (violating.length > 0) {
    const sample = violating
      .slice(0, 3)
      .map((f) => `${f.ruleId} ${f.file}${f.location ? `:${f.location.line}` : ""}`)
      .join(", ");
    failedBecause.push(
      `${violating.length} active finding(s) at or above "${opts.failOn}" severity (${sample}${violating.length > 3 ? ", ..." : ""}).`,
    );
  }
  if (
    (opts.mode === "strict" || opts.mode === "ci") &&
    errors.some((e) => e.kind === "other" && e.file === ".")
  ) {
    failedBecause.push(
      "The scan was incomplete (file limit reached), and strict/ci policy does not accept partial coverage.",
    );
  }

  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of active) bySeverity[f.severity]++;
  const highest =
    SEVERITIES.slice()
      .reverse()
      .find((s) => bySeverity[s] > 0) ?? "none";
  const risk = aggregateRisk(findings);
  const summary: ReportSummary = {
    filesScanned: scanned,
    filesSkipped: skipped,
    findingsTotal: findings.length,
    bySeverity,
    newFindings: active.filter((f) => f.newlyIntroduced).length,
    baselinedFindings: findings.filter((f) => f.baselined).length,
    allowlistedFindings: findings.filter((f) => f.allowlisted).length,
    activeFindings: active.length,
    highestSeverity: highest,
    riskScore: risk,
    riskLevel: riskLevel(risk),
    errors: errors.length,
  };

  const deterministic = opts.mode === "ci";
  const report: Report = {
    tool: { name: "reposhield", version: VERSION },
    mode: opts.mode,
    root: deterministic ? "." : opts.rootAbs,
    ...(deterministic ? {} : { generatedAt: new Date().toISOString() }),
    safe: failedBecause.length === 0,
    policy: { failOn: opts.failOn, failedBecause },
    summary,
    findings,
    errors,
    notes,
    git: git.context,
    disclaimer: DISCLAIMER,
  };
  return { report, git, baseline, resolved, opts };
}

export async function scanSingleFile(filePath: string, input: RepoShieldOptions = {}): Promise<Report> {
  const opts = resolveOptions(input);
  const abs = path.resolve(opts.rootAbs, filePath);
  if (!isInside(opts.rootAbs, abs))
    throw new ConfigError(`Refusing to scan a path outside the root: ${filePath}`);
  let real: string;
  try {
    real = await fs.realpath(abs);
  } catch {
    throw new ConfigError(`File not found: ${filePath}`);
  }
  const rootReal = await fs.realpath(opts.rootAbs);
  if (!isInside(rootReal, real))
    throw new ConfigError(`Refusing to follow a symlink that leaves the root: ${filePath}`);
  const st = await fs.stat(real);
  if (!st.isFile()) throw new ConfigError(`Not a regular file: ${filePath}`);
  return (await runScan(input, [abs])).report;
}
