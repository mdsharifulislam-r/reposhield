import {
  buildBaseline,
  loadBaseline,
  writeBaseline,
  BaselineError,
  type Baseline,
  type BaselineEntry,
} from "./core/baseline.js";
import {
  ConfigError,
  DEFAULT_BASELINE_FILE,
  resolveOptions,
  type RepoShieldOptions,
} from "./core/options.js";
import { runScan, scanSingleFile } from "./core/scanner.js";
import { isActive } from "./core/scoring.js";
import type { Finding, Report } from "./core/types.js";
import { VERSION } from "./core/version.js";

/**
 * Scan the repository and return a report. Despite the name, this never
 * modifies, deletes, or rewrites anything: it scans and reports.
 * `report.safe === true` means no policy violation was found, not that the repository is proven safe.
 */
export async function clean(options: RepoShieldOptions = {}): Promise<Report> {
  return scan(options);
}

/** Explicit scan entry point. Read-only; never executes scanned code. */
export async function scan(options: RepoShieldOptions = {}): Promise<Report> {
  return (await runScan(options)).report;
}

/** Scan one file. Paths outside the root, or symlinks leaving it, are refused. */
export async function scanFile(filePath: string, options: RepoShieldOptions = {}): Promise<Report> {
  return scanSingleFile(filePath, options);
}

export interface BaselineComparison {
  baselinePath: string;
  baselineFound: boolean;
  /** Active findings not accepted by the baseline. */
  newFindings: Finding[];
  /** Findings accepted by the baseline and still present. */
  accepted: Finding[];
  /** Baseline entries that no longer match any finding (fixed, moved, or changed). */
  resolved: BaselineEntry[];
  report: Report;
}

/** Compare current findings with the trusted baseline (default `.reposhield-baseline.json`). */
export async function compareWithBaseline(options: RepoShieldOptions = {}): Promise<BaselineComparison> {
  const o = {
    ...options,
    baseline: options.baseline === undefined || options.baseline === false ? true : options.baseline,
  };
  const { report, baseline, resolved, opts } = await runScan(o);
  return {
    baselinePath: opts.baselinePath ?? DEFAULT_BASELINE_FILE,
    baselineFound: baseline !== null,
    newFindings: report.findings.filter(isActive),
    accepted: report.findings.filter((f) => f.baselined),
    resolved,
    report,
  };
}

export interface CreateBaselineResult {
  path: string;
  baseline: Baseline;
  /** Critical findings that were not accepted. */
  excluded: Finding[];
  report: Report;
}

/**
 * Write a baseline of the current findings. This is the one API that writes a
 * file (only the baseline path inside the root). Critical findings are not
 * accepted unless `includeCritical` is set.
 */
export async function createBaseline(
  options: RepoShieldOptions & { includeCritical?: boolean } = {},
): Promise<CreateBaselineResult> {
  const { includeCritical = false, ...rest } = options;
  // Scan without applying an existing baseline so the new file is a complete snapshot.
  const { report, git } = await runScan({ ...rest, baseline: false });
  const target =
    rest.baseline === undefined || rest.baseline === false || rest.baseline === true
      ? DEFAULT_BASELINE_FILE
      : rest.baseline;
  const file = resolveOptions({ ...rest, baseline: target }).baselinePath as string;
  const { baseline, excluded } = buildBaseline(report.findings, {
    version: VERSION,
    head: git.context.head,
    includeCritical,
  });
  await writeBaseline(file, baseline);
  return { path: file, baseline, excluded, report };
}

export { inspectRecovery, renderRecoveryPlan, type RecoveryInspection } from "./recovery/inspect.js";
export { generateReport, FORMATS, type GenerateReportOptions, type ReportFormat } from "./reporters/index.js";
export { monitor, type MonitorHandle, type MonitorHandlers } from "./monitor.js";
export { ALL_RULES } from "./rules/index.js";
export { ConfigError, BaselineError, loadBaseline };
export { optionsSchema, type RepoShieldOptions } from "./core/options.js";
export { VERSION } from "./core/version.js";
export type {
  Confidence,
  Finding,
  FindingCategory,
  GitContext,
  Mode,
  Report,
  ReportSummary,
  ScanError,
  Severity,
} from "./core/types.js";
export type { Baseline, BaselineEntry };
