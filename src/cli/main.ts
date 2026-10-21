import spawn from "cross-spawn";
import { constants as osConstants } from "node:os";
import fs from "node:fs/promises";
import path from "node:path";
import { parseArgs } from "node:util";
import {
  ALL_RULES,
  BaselineError,
  ConfigError,
  FORMATS,
  VERSION,
  compareWithBaseline,
  createBaseline,
  generateReport,
  inspectRecovery,
  monitor,
  renderRecoveryPlan,
  scan,
  scanFile,
  type ReportFormat,
  type RepoShieldOptions,
} from "../index.js";
import { sanitizeForTerminal } from "../core/redact.js";
import { CONFIDENCES, MODES, SEVERITIES, type Mode, type Report } from "../core/types.js";

export const EXIT = { OK: 0, POLICY: 1, USAGE: 2, ERROR: 3 } as const;

export interface CliIO {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  cwd: string;
  env: NodeJS.ProcessEnv;
  isTTY: boolean;
  /** Registers a handler for termination signals; returns an unsubscribe function. */
  onSignal?: (handler: (signal: NodeJS.Signals) => void) => () => void;
}

export const HELP = `RepoShield ${VERSION}: read-only scanner for suspicious JavaScript/TypeScript code in repositories.

It never executes scanned code, never contacts URLs found in files, and never changes your
repository during a scan. Findings are heuristic leads, not proof of malware, and a clean
result does not prove a repository is safe.

USAGE
  reposhield scan [options]               Scan and report (default command)
  reposhield run [scan options] -- <command> [args...]
  reposhield scan --changed               Only files changed relative to a Git ref
  reposhield baseline create              Accept current findings into .reposhield-baseline.json
  reposhield baseline compare             Show findings not accepted by the baseline
  reposhield recovery inspect             Read-only recovery plan for suspicious changes
  reposhield monitor                      Re-scan on an interval until stopped
  reposhield rules                        List detection rules
  reposhield file <path>                  Scan a single file

RUN
  Scans in ci mode and starts the command only when report.safe is true. The scan is
  heuristic and a pass is not proof of safety. Put scan options before --; command
  arguments after -- are passed through unchanged.

OPTIONS
  --root <dir>             Project root (default: current directory)
  --mode <mode>            audit | strict | ci | changed | monitor (default: audit)
  --changed                Shorthand for --mode changed
  --base <ref>             Git ref to compare against (default for --changed: origin default branch or HEAD~1)
  --format <fmt>           text | json | sarif (default: text)
  --output <file>          Write the report to a file instead of stdout
  --fail-on <severity>     info | low | medium | high | critical (default: high; strict: medium)
  --min-confidence <c>     low | medium | high (default: low)
  --ignore <glob>          Extra ignore pattern (repeatable)
  --baseline               Apply the default baseline file
  --baseline-file <path>   Apply or write a baseline at this path (inside the root)
  --include-critical       baseline create: also accept critical findings (not recommended)
  --max-file-size <bytes>  Skip analysis of larger files (default: 1000000)
  --no-git                 Disable Git analysis
  --no-gitignore           Do not honor .gitignore
  --follow-symlinks        Follow symlinks that stay inside the root
  --interval <seconds>     monitor: seconds between scans (default: 30)
  --config <file>          JSON config file (default: .reposhieldrc.json if present)
  --no-color               Disable colors
  -h, --help               Show help
  -v, --version            Show version

EXIT CODES
  0  Success. In audit mode findings never fail the run unless --fail-on is given.
  1  Policy violation: active findings at or above --fail-on (strict, ci, changed, or explicit --fail-on).
  2  Usage or configuration error.
  3  Runtime error (unreadable root, aborted scan, internal failure).
  127 The run command could not be started.
  128+signal The run command was terminated by a signal.

Configuration files are JSON only; RepoShield never executes a JavaScript config.
`;

class UsageError extends Error {}

const OPTIONS = {
  root: { type: "string" },
  mode: { type: "string" },
  changed: { type: "boolean" },
  base: { type: "string" },
  format: { type: "string" },
  output: { type: "string" },
  "fail-on": { type: "string" },
  "min-confidence": { type: "string" },
  ignore: { type: "string", multiple: true },
  baseline: { type: "boolean" },
  "baseline-file": { type: "string" },
  "include-critical": { type: "boolean" },
  "max-file-size": { type: "string" },
  "no-git": { type: "boolean" },
  "no-gitignore": { type: "boolean" },
  "follow-symlinks": { type: "boolean" },
  interval: { type: "string" },
  config: { type: "string" },
  "no-color": { type: "boolean" },
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
} as const;

type Values = ReturnType<typeof parseArgs<{ options: typeof OPTIONS; allowPositionals: true }>>["values"];

function oneOf<T extends string>(
  value: string | undefined,
  allowed: readonly T[],
  flag: string,
): T | undefined {
  if (value === undefined) return undefined;
  if (!(allowed as readonly string[]).includes(value))
    throw new UsageError(`Invalid value for ${flag}: "${value}". Expected one of: ${allowed.join(", ")}.`);
  return value as T;
}

async function loadConfigFile(
  rootAbs: string,
  explicit: string | undefined,
  cwd: string,
): Promise<Partial<RepoShieldOptions>> {
  const file = explicit ? path.resolve(cwd, explicit) : path.join(rootAbs, ".reposhieldrc.json");
  let raw: string;
  try {
    raw = await fs.readFile(file, "utf8");
  } catch (err) {
    if (!explicit && (err as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw new UsageError(`Cannot read config file ${file}: ${(err as Error).message}`);
  }
  try {
    const json: unknown = JSON.parse(raw);
    if (!json || typeof json !== "object" || Array.isArray(json)) throw new Error("must be a JSON object");
    const { root: _r, signal: _s, ...rest } = json as Record<string, unknown>;
    void _r;
    void _s;
    return rest as Partial<RepoShieldOptions>;
  } catch (err) {
    throw new UsageError(`Invalid config file ${file}: ${(err as Error).message}`);
  }
}

async function buildOptions(
  v: Values,
  io: CliIO,
  defaults: Partial<RepoShieldOptions> = {},
): Promise<RepoShieldOptions> {
  const root = path.resolve(io.cwd, v.root ?? ".");
  const fileCfg = await loadConfigFile(root, v.config, io.cwd);
  const o: Record<string, unknown> = { ...fileCfg, ...defaults, root };
  const mode = v.changed ? "changed" : oneOf(v.mode, MODES, "--mode");
  if (v.changed && v.mode && v.mode !== "changed") throw new UsageError("--changed conflicts with --mode.");
  if (mode) o["mode"] = mode;
  if (v.base) o["baseRef"] = v.base;
  const failOn = oneOf(v["fail-on"], SEVERITIES, "--fail-on");
  if (failOn) o["failOn"] = failOn;
  const mc = oneOf(v["min-confidence"], CONFIDENCES, "--min-confidence");
  if (mc) o["minConfidence"] = mc;
  if (v.ignore?.length) o["ignore"] = [...((fileCfg.ignore as string[] | undefined) ?? []), ...v.ignore];
  if (v.baseline) o["baseline"] = true;
  if (v["baseline-file"]) o["baseline"] = v["baseline-file"];
  if (v["no-git"]) o["includeGitHistory"] = false;
  if (v["no-gitignore"]) o["respectGitignore"] = false;
  if (v["follow-symlinks"]) o["followSymlinks"] = true;
  if (v["max-file-size"] !== undefined) {
    const n = Number(v["max-file-size"]);
    if (!Number.isInteger(n) || n <= 0) throw new UsageError("--max-file-size must be a positive integer.");
    o["maxFileSizeBytes"] = n;
  }
  if (v.interval !== undefined) {
    const n = Number(v.interval);
    if (!(n >= 1)) throw new UsageError("--interval must be at least 1 second.");
    o["monitorIntervalMs"] = Math.round(n * 1000);
  }
  return o as RepoShieldOptions;
}

function shouldFail(report: Report, mode: Mode, explicitFailOn: boolean): boolean {
  const enforcing = mode === "strict" || mode === "ci" || mode === "changed" || explicitFailOn;
  return enforcing && !report.safe;
}

async function emit(
  text: string,
  output: string | undefined,
  io: CliIO,
  summaryLine?: string,
): Promise<void> {
  if (output) {
    const file = path.resolve(io.cwd, output);
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, text, "utf8");
    io.stderr(
      `${summaryLine ?? "Report"} written to ${sanitizeForTerminal(path.relative(io.cwd, file) || file)}\n`,
    );
  } else io.stdout(text);
}

/** CLI entry point. Returns the process exit code instead of exiting. */
export async function main(argv: string[], io: CliIO): Promise<number> {
  const separator = argv.indexOf("--");
  const commandArgs = separator < 0 ? undefined : argv.slice(separator + 1);
  const cliArgs = separator < 0 ? argv : argv.slice(0, separator);
  let parsed;
  try {
    parsed = parseArgs({ args: cliArgs, options: OPTIONS, allowPositionals: true, strict: true });
  } catch (err) {
    io.stderr(
      `reposhield: ${sanitizeForTerminal((err as Error).message)}\nRun "reposhield --help" for usage.\n`,
    );
    return EXIT.USAGE;
  }
  const { values: v, positionals } = parsed;
  if (separator >= 0 && positionals[0] !== "run") {
    io.stderr('reposhield: The "--" command separator is only valid with "run".\n');
    return EXIT.USAGE;
  }
  if (v.help) {
    io.stdout(HELP);
    return EXIT.OK;
  }
  if (v.version) {
    io.stdout(`${VERSION}\n`);
    return EXIT.OK;
  }

  try {
    const [cmd = "scan", sub] = positionals;
    if (commandArgs !== undefined && cmd !== "run")
      throw new UsageError('The "--" command separator is only valid with "run".');
    const formatFlag = oneOf(v.format, FORMATS, "--format") as ReportFormat | undefined;
    const color =
      io.isTTY && !io.env["NO_COLOR"] && !v["no-color"] && !io.env["CI"] && (formatFlag ?? "text") === "text";

    switch (cmd) {
      case "run": {
        if (commandArgs === undefined)
          throw new UsageError("Usage: reposhield run [scan options] -- <command> [args...]");
        if (commandArgs.length === 0 || !commandArgs[0])
          throw new UsageError("Usage: reposhield run [scan options] -- <command> [args...]");
        if (sub || positionals.length > 1)
          throw new UsageError('Put scan options before "--" and the command after it.');

        const options = await buildOptions(v, io);
        options.mode ??= "ci";
        options.failOn ??= "high";
        const report = await scan(options);
        const text = generateReport(report, { format: formatFlag ?? "text", color });
        const displayCommand = sanitizeForTerminal(commandArgs.join(" "));
        if (!report.safe) {
          if (v.output) await emit(text, v.output, io, `${formatFlag ?? "text"} report`);
          else io.stderr(text);
          io.stderr(`scan blocked the command, so it was not started: ${displayCommand}\n`);
          return EXIT.POLICY;
        }

        if (v.output) await emit(text, v.output, io, `${formatFlag ?? "text"} report`);
        io.stderr(
          `scan passed with ${report.summary.activeFindings} active finding(s); this is not proof of safety. Running: ${displayCommand}\n`,
        );
        return await runCommand(commandArgs, io);
      }
      case "scan": {
        if (sub)
          throw new UsageError(
            `Unexpected argument "${sub}". Use "reposhield file <path>" to scan one file.`,
          );
        const options = await buildOptions(v, io);
        const report = await scan(options);
        const text = generateReport(report, { format: formatFlag ?? "text", color });
        await emit(text, v.output, io, `${formatFlag ?? "text"} report`);
        return shouldFail(report, report.mode, v["fail-on"] !== undefined || options.failOn !== undefined)
          ? EXIT.POLICY
          : EXIT.OK;
      }
      case "file": {
        if (!sub) throw new UsageError("Usage: reposhield file <path>");
        const options = await buildOptions(v, io);
        const report = await scanFile(sub, options);
        await emit(generateReport(report, { format: formatFlag ?? "text", color }), v.output, io);
        return shouldFail(report, report.mode, v["fail-on"] !== undefined) ? EXIT.POLICY : EXIT.OK;
      }
      case "baseline": {
        if (sub === "create") {
          const options = await buildOptions(v, io);
          const r = await createBaseline({
            ...options,
            ...(v["include-critical"] ? { includeCritical: true } : {}),
          });
          io.stdout(
            `Baseline written: ${sanitizeForTerminal(path.relative(io.cwd, r.path) || r.path)} (${r.baseline.entries.length} accepted finding(s)).\n`,
          );
          if (r.excluded.length) {
            io.stdout(
              `${r.excluded.length} critical finding(s) were NOT accepted. Review them; use --include-critical only after investigation.\n`,
            );
          }
          io.stdout(
            "Review the baseline in code review: every entry silences a finding for this fingerprint.\n",
          );
          return EXIT.OK;
        }
        if (sub === "compare") {
          const options = await buildOptions(v, io);
          const cmp = await compareWithBaseline(options);
          const text = generateReport(cmp.report, { format: formatFlag ?? "text", color, verbose: false });
          await emit(text, v.output, io, "baseline comparison");
          if (!cmp.baselineFound) io.stderr("No baseline file found; every finding is treated as new.\n");
          io.stderr(
            `Baseline: ${cmp.accepted.length} accepted, ${cmp.newFindings.length} new, ${cmp.resolved.length} no longer present.\n`,
          );
          return cmp.report.safe ? EXIT.OK : EXIT.POLICY;
        }
        throw new UsageError("Usage: reposhield baseline <create|compare>");
      }
      case "recovery": {
        if (sub !== "inspect") throw new UsageError("Usage: reposhield recovery inspect");
        const options = await buildOptions(v, io);
        const r = await inspectRecovery(options);
        const text = formatFlag === "json" ? `${JSON.stringify(r, null, 2)}\n` : renderRecoveryPlan(r);
        await emit(text, v.output, io, "recovery plan");
        return EXIT.OK;
      }
      case "monitor": {
        const options = await buildOptions(v, io, { mode: "monitor" });
        let last = "";
        const handle = monitor(options, {
          onReport(report, { cycle, newFindings }) {
            const line = `[${new Date().toISOString()}] cycle ${cycle}: ${report.summary.activeFindings} active finding(s), risk ${report.summary.riskScore}/100 (${report.summary.riskLevel})\n`;
            if (cycle === 1 || newFindings.length > 0 || line.slice(26) !== last) {
              io.stdout(line);
              for (const f of newFindings.slice(0, 10)) {
                io.stdout(
                  `  NEW [${f.severity}] ${f.ruleId} ${sanitizeForTerminal(f.file)}:${f.location?.line ?? 1}\n`,
                );
              }
            }
            last = line.slice(26);
          },
          onError(err) {
            io.stderr(`reposhield: scan failed: ${sanitizeForTerminal(err.message)}\n`);
          },
        });
        const off = io.onSignal?.(() => void handle.stop());
        await handle.done;
        off?.();
        io.stdout("Monitor stopped.\n");
        return EXIT.OK;
      }
      case "rules": {
        if (formatFlag === "json") io.stdout(`${JSON.stringify(ALL_RULES, null, 2)}\n`);
        else for (const r of ALL_RULES) io.stdout(`${r.id.padEnd(12)} ${r.severity.padEnd(9)} ${r.title}\n`);
        return EXIT.OK;
      }
      case "help":
        io.stdout(HELP);
        return EXIT.OK;
      default:
        throw new UsageError(`Unknown command "${cmd}".`);
    }
  } catch (err) {
    if (err instanceof UsageError || err instanceof ConfigError || err instanceof BaselineError) {
      io.stderr(`reposhield: ${sanitizeForTerminal(err.message)}\n`);
      return EXIT.USAGE;
    }
    if ((err as Error).name === "AbortError") {
      io.stderr("reposhield: scan aborted\n");
      return EXIT.ERROR;
    }
    io.stderr(`reposhield: unexpected error: ${sanitizeForTerminal((err as Error).message)}\n`);
    return EXIT.ERROR;
  }
}

async function runCommand(commandArgs: string[], io: CliIO): Promise<number> {
  const [command, ...args] = commandArgs;
  if (!command) return EXIT.USAGE;

  return await new Promise<number>((resolve) => {
    const child = spawn(command, args, {
      cwd: io.cwd,
      stdio: "inherit",
    });
    const offSignal = io.onSignal?.((signal) => {
      child.kill(signal);
    });
    child.once("error", (error) => {
      offSignal?.();
      io.stderr(`reposhield: cannot start command: ${sanitizeForTerminal(error.message)}\n`);
      resolve(127);
    });
    child.once("close", (code, signal) => {
      offSignal?.();
      resolve(code ?? 128 + (signal ? (osConstants.signals[signal] ?? 0) : 0));
    });
  });
}
