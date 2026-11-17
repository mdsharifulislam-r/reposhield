#!/usr/bin/env node
/**
 * RepoShield CLI — Entry Point
 *
 * Implements:
 *   reposhield-scan init
 *   reposhield-scan scan [options]
 *   reposhield-scan report
 *   reposhield-scan doctor
 *   reposhield-scan recover --inspect
 *   reposhield-scan recover --to <sha>
 */

import { Command } from 'commander';
import path from 'path';
import fs from 'fs';
import readline from 'readline';
import { clean } from '../scanner.js';
import { checkGitAvailability, getRepoStatus } from '../git-analyzer.js';
import { buildRecoveryPlan, createRevertCommit, createRecoveryBranch } from '../recovery.js';
import { ScanSummary, Severity, ScanMode } from '../types.js';
import { loadConfig } from '../config.js';

// ─── Exit Codes ───────────────────────────────────────────────────────────────
// 0 = success / no violations
// 1 = policy violation
// 2 = scan error / invalid arguments
// 3 = aborted

const EXIT_OK = 0;
const EXIT_POLICY_VIOLATION = 1;
const EXIT_ERROR = 2;
const EXIT_ABORTED = 3;

const program = new Command();

program
  .name('reposhield-scan')
  .description('Advanced repository malware defense and supply-chain protection')
  .version('1.0.0');

// ─── Init Command ─────────────────────────────────────────────────────────────

program
  .command('init')
  .description('Initialize reposhield configuration in the current repository')
  .option('--root <path>', 'Repository root', process.cwd())
  .action(async (opts: { root: string }) => {
    const root = path.resolve(opts.root as string);
    const configPath = path.join(root, 'reposhield.config.json');

    if (fs.existsSync(configPath)) {
      console.error(`Configuration already exists: ${configPath}`);
      process.exit(EXIT_ERROR);
    }

    const defaultConfig = {
      version: 1,
      exclude: ['dist/', 'build/', 'coverage/'],
      suppressions: [],
      policy: {
        blockOnCritical: true,
        blockOnHigh: true,
        blockOnMedium: false,
        blockOnSecrets: true,
        blockOnDependencyFindings: 'high',
      },
    };

    try {
      fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2) + '\n', 'utf-8');
      console.log(`✓ Created ${configPath}`);
      console.log('Edit the config to add suppressions or adjust policy thresholds.');
      console.log('\nNext step: reposhield-scan scan');
    } catch (err) {
      console.error(`Failed to create config: ${String(err)}`);
      process.exit(EXIT_ERROR);
    }
  });

// ─── Scan Command ─────────────────────────────────────────────────────────────

program
  .command('scan')
  .description('Scan the repository for security issues')
  .option('--root <path>', 'Repository root', process.cwd())
  .option('--changed', 'Only scan changed files relative to base SHA')
  .option('--base <sha>', 'Trusted base SHA or branch reference for change-based scan')
  .option('--format <format>', 'Output format: text or json', 'text')
  .option('--severity <level>', 'Minimum severity to report: critical, high, medium, low, info', 'info')
  .option('--history', 'Analyze recent Git commit history')
  .option('--mode <mode>', 'Scan mode: audit, strict, ci, changed', 'audit')
  .option('--no-cache', 'Disable result caching')
  .option('--quiet', 'Suppress progress output')
  .option('--output <file>', 'Write JSON report to file')
  .action(async (opts: {
    root: string;
    changed?: boolean;
    base?: string;
    format: string;
    severity: string;
    history?: boolean;
    mode: string;
    noCache?: boolean;
    quiet?: boolean;
    output?: string;
  }) => {
    const root = path.resolve(opts.root as string);
    const format = opts.format as string;
    const minSeverity = opts.severity as Severity;
    const mode = (opts.changed ? 'changed' : (opts.mode as ScanMode)) ?? 'audit';
    const quiet = opts.quiet as boolean;

    if (!['text', 'json'].includes(format)) {
      console.error(`Invalid format: "${format}". Must be "text" or "json".`);
      process.exit(EXIT_ERROR);
    }

    if (!['critical', 'high', 'medium', 'low', 'info'].includes(minSeverity)) {
      console.error(`Invalid severity: "${minSeverity}".`);
      process.exit(EXIT_ERROR);
    }

    if (!['audit', 'strict', 'ci', 'changed', 'monitor'].includes(mode)) {
      console.error(`Invalid mode: "${mode}".`);
      process.exit(EXIT_ERROR);
    }

    const controller = new AbortController();
    process.on('SIGINT', () => {
      if (!quiet) console.log('\nScan aborted.');
      controller.abort();
      process.exit(EXIT_ABORTED);
    });

    if (!quiet) {
      console.log(`🛡️  RepoShield scanning ${root} (mode: ${mode})`);
    }

    let summary: ScanSummary | undefined;
    try {
      summary = await clean({
        root,
        mode,
        baseSha: opts.base as string | undefined,
        minSeverity,
        noCache: !!opts.noCache,
        quiet,
        signal: controller.signal,
      });
    } catch (err: unknown) {
      const error = err as { name?: string; message?: string };
      if (error.name === 'ScanAbortedError') {
        console.error('Scan was aborted.');
        process.exit(EXIT_ABORTED);
      }
      console.error(`Scan error: ${String(err)}`);
      process.exit(EXIT_ERROR);
    }

    if (!summary) {
      process.exit(EXIT_ERROR);
      return;
    }

    if (format === 'json') {
      const output = JSON.stringify(summary, null, 2);
      if (opts.output) {
        fs.writeFileSync(opts.output as string, output, 'utf-8');
        if (!quiet) console.log(`Report written to ${opts.output}`);
      } else {
        console.log(output);
      }
    } else {
      printTextReport(summary, quiet);
    }

    if (opts.output && format !== 'json') {
      fs.writeFileSync(opts.output as string, JSON.stringify(summary, null, 2), 'utf-8');
    }

    process.exit(summary.policyViolation ? EXIT_POLICY_VIOLATION : EXIT_OK);
  });

// ─── Report Command ───────────────────────────────────────────────────────────

program
  .command('report')
  .description('Display the last scan report from a JSON file')
  .option('--input <file>', 'JSON report file to display', 'reposhield-report.json')
  .action((opts: { input: string }) => {
    const inputPath = path.resolve(opts.input);
    if (!fs.existsSync(inputPath)) {
      console.error(`Report file not found: ${inputPath}`);
      console.error('Run `reposhield-scan scan --format json --output reposhield-report.json` first.');
      process.exit(EXIT_ERROR);
    }

    let summary: ScanSummary | undefined;
    try {
      const content = fs.readFileSync(inputPath, 'utf-8');
      summary = JSON.parse(content) as ScanSummary;
    } catch (err) {
      console.error(`Failed to read report: ${String(err)}`);
      process.exit(EXIT_ERROR);
    }

    if (!summary) { process.exit(EXIT_ERROR); return; }
    printTextReport(summary, false);
    process.exit(EXIT_OK);
  });

// ─── Doctor Command ───────────────────────────────────────────────────────────

program
  .command('doctor')
  .description('Check Git availability, repository status, and scanner readiness')
  .option('--root <path>', 'Repository root', process.cwd())
  .action(async (opts: { root: string }) => {
    const root = path.resolve(opts.root as string);
    let allOk = true;

    console.log('🩺 RepoShield Doctor\n');

    // Check Node.js version
    const nodeVersion = process.version;
    const [, nodeMajor] = nodeVersion.match(/^v(\d+)/) ?? [];
    if (parseInt(nodeMajor ?? '0', 10) >= 18) {
      console.log(`✓ Node.js ${nodeVersion}`);
    } else {
      console.log(`✗ Node.js ${nodeVersion} — requires v18 or later`);
      allOk = false;
    }

    // Check Git availability
    const git = await checkGitAvailability();
    if (git.available) {
      console.log(`✓ Git available: ${git.version}`);
    } else {
      console.log('✗ Git not found in PATH. Git-based features will be unavailable.');
      allOk = false;
    }

    // Check repository status
    const status = await getRepoStatus(root);
    if (status.isRepo) {
      console.log(`✓ Git repository: ${root}`);
      console.log(`  Branch: ${status.currentBranch ?? 'detached HEAD'}`);
      console.log(`  HEAD: ${status.headSha ?? 'unknown'}`);
      if (status.hasUncommittedChanges) {
        console.log(`  ⚠ Working tree has uncommitted changes`);
      }
    } else {
      console.log(`⚠ Not a Git repository: ${root}`);
    }

    // Check configuration
    try {
      const config = loadConfig({ root });
      console.log(`✓ Configuration loaded (version ${config.version})`);
      console.log(`  Exclusions: ${(config.exclude ?? []).length}`);
      console.log(`  Suppressions: ${(config.suppressions ?? []).length}`);
    } catch (err) {
      console.log(`✗ Configuration error: ${String(err)}`);
      allOk = false;
    }

    console.log('\n' + (allOk ? '✓ Scanner is ready.' : '✗ Some checks failed — see above.'));
    process.exit(allOk ? EXIT_OK : EXIT_ERROR);
  });

// ─── Recover Command ──────────────────────────────────────────────────────────

program
  .command('recover')
  .description('Inspect the repository state and produce a recovery plan')
  .option('--root <path>', 'Repository root', process.cwd())
  .option('--inspect', 'Display recovery plan without making changes')
  .option('--to <sha>', 'Create a recovery branch from a trusted commit SHA')
  .option('--revert <sha>', 'Create a revert commit for the specified SHA')
  .action(async (opts: { root: string; inspect?: boolean; to?: string; revert?: string }) => {
    const root = path.resolve(opts.root as string);

    if (opts.inspect) {
      try {
        const plan = await buildRecoveryPlan(root);
        printRecoveryPlan(plan);
        process.exit(EXIT_OK);
      } catch (err) {
        console.error(`Recovery plan failed: ${String(err)}`);
        process.exit(EXIT_ERROR);
      }
    }

    if (opts.to) {
      const targetSha = opts.to as string;

      console.log(`\n⚠️  You are about to create a recovery branch from: ${targetSha}`);
      console.log('This will NOT modify the current branch or any remote.');
      console.log('\nIMPORTANT: A previous commit is not automatically safe.');
      console.log('Scan the recovery target before deploying.\n');

      const confirmed = await promptConfirm('Proceed with recovery branch creation?');
      if (!confirmed) {
        console.log('Cancelled.');
        process.exit(EXIT_OK);
      }

      const result = await createRecoveryBranch(root, targetSha, () => Promise.resolve(true));
      console.log(result.success ? `✓ ${result.message}` : `✗ ${result.message}`);
      process.exit(result.success ? EXIT_OK : EXIT_ERROR);
    }

    if (opts.revert) {
      const targetSha = opts.revert as string;

      console.log(`\n⚠️  You are about to create a REVERT COMMIT for: ${targetSha}`);
      console.log('This creates a new commit that undoes the target commit.');
      console.log('A backup branch will be created automatically.\n');

      const confirmed = await promptConfirm('Proceed with revert commit creation?');
      if (!confirmed) {
        console.log('Cancelled.');
        process.exit(EXIT_OK);
      }

      const result = await createRevertCommit(root, targetSha, () => Promise.resolve(true));
      console.log(result.success ? `✓ ${result.message}` : `✗ ${result.message}`);
      process.exit(result.success ? EXIT_OK : EXIT_ERROR);
    }

    // Default: show help
    console.log('Use --inspect to see the recovery plan, --to <sha> to create a recovery branch,');
    console.log('or --revert <sha> to create a revert commit.');
    process.exit(EXIT_OK);
  });

// ─── Helpers ──────────────────────────────────────────────────────────────────

function printTextReport(summary: ScanSummary, quiet: boolean): void {
  const totalIssues =
    summary.findings.length +
    summary.secretFindings.length +
    summary.dependencyFindings.length +
    summary.gitFindings.length;

  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🛡️  RepoShield Scan Report');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`Scanned at:    ${summary.scannedAt}`);
  console.log(`Mode:          ${summary.mode}`);
  console.log(`Root:          ${summary.root}`);
  console.log(`Duration:      ${summary.scanDurationMs}ms`);
  console.log(`Files found:   ${summary.totalFilesDiscovered}`);
  console.log(`Files scanned: ${summary.totalFilesScanned}`);
  console.log(`Files skipped: ${summary.totalFilesSkipped}`);
  console.log(`Cache hits:    ${summary.cacheHits}`);
  if (summary.gitBaseSha) {
    console.log(`Base SHA:      ${summary.gitBaseSha}`);
  }
  console.log('');

  if (summary.findings.length > 0) {
    console.log(`📋 Code Findings (${summary.findings.length}):`);
    for (const f of summary.findings) {
      if (f.suppressed) continue;
      const loc = f.line ? `:${f.line}` : '';
      console.log(`  [${f.severity.toUpperCase()}] ${f.ruleId} — ${path.relative(summary.root, f.filePath)}${loc}`);
      console.log(`    ${f.message}`);
      if (!quiet && f.evidence.length > 0) {
        console.log(`    Evidence: ${f.evidence[0]}`);
      }
    }
    console.log('');
  }

  if (summary.secretFindings.length > 0) {
    console.log(`🔑 Secret Findings (${summary.secretFindings.length}):`);
    for (const s of summary.secretFindings) {
      console.log(
        `  [CRITICAL] ${s.ruleId} — ${path.relative(summary.root, s.filePath)}:${s.line}`,
      );
      console.log(`    Type: ${s.secretType} | Value: ${s.redactedValue}`);
      if (s.isNewlyIntroduced) console.log('    ⚠ Newly introduced in current changes');
    }
    console.log('');
  }

  if (summary.dependencyFindings.length > 0) {
    console.log(`📦 Dependency Findings (${summary.dependencyFindings.length}):`);
    for (const d of summary.dependencyFindings) {
      console.log(`  [${d.severity.toUpperCase()}] ${d.findingType} — ${d.packageName}@${d.version}`);
      console.log(`    ${d.message}`);
    }
    console.log('');
  }

  if (summary.gitFindings.length > 0) {
    console.log(`🔀 Git Findings (${summary.gitFindings.length}):`);
    for (const g of summary.gitFindings) {
      console.log(`  [${g.severity.toUpperCase()}] ${g.findingType}`);
      console.log(`    ${g.message}`);
    }
    console.log('');
  }

  if (summary.suppressedCount > 0) {
    console.log(`ℹ️  ${summary.suppressedCount} finding(s) suppressed by configuration`);
  }

  if (summary.expiredSuppressions.length > 0) {
    console.log(`⚠️  ${summary.expiredSuppressions.length} expired suppression(s) — review needed`);
  }

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  if (summary.policyViolation) {
    console.log('❌ POLICY VIOLATION — This scan would fail CI enforcement');
    for (const reason of summary.policyViolationReasons) {
      console.log(`   • ${reason}`);
    }
  } else {
    console.log(
      totalIssues === 0
        ? '✅ No issues found'
        : `✅ No policy violations (${totalIssues} informational finding(s))`,
    );
  }
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
}

function printRecoveryPlan(plan: import('../recovery.js').RecoveryPlan): void {
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🛡️  RepoShield Recovery Plan');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`Current branch: ${plan.currentBranch ?? 'unknown'}`);
  console.log(`Current SHA:    ${plan.currentSha ?? 'unknown'}`);
  console.log('');

  console.log('⚠️  IMPORTANT WARNINGS:');
  for (const warning of plan.importantWarnings) {
    console.log(`  ${warning}`);
  }
  console.log('');

  console.log('📋 Working Tree Status:');
  console.log(`  Uncommitted changes: ${plan.workingTreeStatus.hasUncommittedChanges ? 'YES' : 'No'}`);
  if (plan.workingTreeStatus.stagedFiles.length > 0) {
    console.log(`  Staged: ${plan.workingTreeStatus.stagedFiles.join(', ')}`);
  }
  if (plan.workingTreeStatus.untrackedFiles.length > 0) {
    console.log(`  Untracked: ${plan.workingTreeStatus.untrackedFiles.join(', ')}`);
  }
  console.log('');

  console.log('🔍 Candidate Recovery Targets (NOT automatically safe):');
  for (const target of plan.candidateTargets) {
    console.log(`  ${target.sha} — ${target.description}`);
    if (!target.hasBeenScanned) {
      console.log('    ⚠ Not yet scanned — run reposhield-scan scan --base <sha> before using');
    }
  }
  console.log('');

  console.log('💾 Backup Strategy:');
  console.log(plan.backupStrategy);
  console.log('');

  console.log('🔧 Recovery Options:');
  console.log(plan.strategy1Description);
  console.log('');
  console.log(plan.strategy2Description);
  console.log('');

  console.log('🚨 Incident Response Checklist:');
  for (const item of plan.incidentChecklist) {
    console.log(`  ${item}`);
  }
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
}

async function promptConfirm(question: string): Promise<boolean> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(`${question} [y/N]: `, (answer: string) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y');
    });
  });
}

// ─── Parse and execute ────────────────────────────────────────────────────────

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(`CLI error: ${String(err)}`);
  process.exit(EXIT_ERROR);
});
