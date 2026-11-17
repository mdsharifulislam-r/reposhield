/**
 * RepoShield — Main clean() API Orchestrator
 *
 * Coordinates all scanning layers and produces a structured report.
 *
 * GUARANTEES:
 * - Does NOT modify source files
 * - Does NOT execute lifecycle scripts
 * - Does NOT change Git history
 * - Does NOT contact external hosts (unless networkAdvisory: true)
 * - Does NOT delete or move files
 */

import fs from 'fs';
import path from 'path';
import pLimit from 'p-limit';
import { loadConfig, mergeOptions } from './config.js';
import { discoverFiles, safeReadFile } from './discovery.js';
import { analyzeFile } from './analyzer.js';
import {
  analyzePackageJson,
  analyzeWorkflow,
  analyzeNpmrc,
  analyzeBuildConfig,
  analyzeShellScript,
} from './config-analyzer.js';
import {
  inspectPackageJson,
  inspectPackageLock,
  inspectPnpmLock,
  inspectYarnLock,
} from './dependency-inspector.js';
import { detectSecrets } from './secret-detector.js';
import {
  getRepoStatus,
  getChangedFiles,
  analyzeGitHooks,
  getRecentCommits,
  analyzeCommits,
} from './git-analyzer.js';
import { evaluatePolicy, filterBySeverity } from './policy.js';
import { getCachedResult, setCachedResult } from './cache.js';
import {
  detectObfuscatedLoader,
  detectLargeScript,
  inspectFontCarrier,
  analyzeIdeTasks,
} from './dropper-detector.js';
import {
  ScanOptions,
  ScanSummary,
  Finding,
  DependencyFinding,
  GitFinding,
  SecretFinding,
  SkippedFile,
  ScanAbortedError,
} from './types.js';

// ─── Public API ───────────────────────────────────────────────────────────────

export async function clean(options: ScanOptions = {}): Promise<ScanSummary> {
  const startTime = Date.now();

  if (options.signal?.aborted) {
    throw new ScanAbortedError();
  }

  const config = loadConfig(options);
  const merged = mergeOptions(options, config);
  const { root, mode, maxFileSizeBytes, concurrency, minSeverity } = merged;
  const noCache = options.noCache ?? false;
  const signal = options.signal;

  // ── Step 1: Git status ───────────────────────────────────────────────────
  const gitStatus = await getRepoStatus(root, signal);

  // ── Step 2: Determine file set ────────────────────────────────────────────
  let changedPaths: string[] | undefined;
  let gitBaseSha: string | undefined;

  if (mode === 'changed' || options.baseSha) {
    const baseSha =
      options.baseSha ??
      config.trustedBaseSha ??
      (gitStatus.isRootCommit ? undefined : undefined);

    if (baseSha && gitStatus.isRepo) {
      try {
        const changed = await getChangedFiles(root, baseSha, 'HEAD', signal);
        changedPaths = changed.files;
        gitBaseSha = changed.baseSha;
      } catch {
        // If we can't get changed files, fall back to full scan
        changedPaths = undefined;
      }
    }
  }

  // ── Step 3: File discovery ────────────────────────────────────────────────
  const discovery = await discoverFiles({
    root,
    exclude: [...(config.exclude ?? []), ...(options.exclude ?? [])],
    maxFileSizeBytes,
    changedPaths,
    signal,
  });

  if (signal?.aborted) throw new ScanAbortedError();

  const allFindings: Finding[] = [];
  const allDepFindings: DependencyFinding[] = [];
  const allGitFindings: GitFinding[] = [];
  const allSecretFindings: SecretFinding[] = [];
  let cacheHits = 0;

  // ── Step 4: Identify lifecycle-referenced files ───────────────────────────
  const lifecycleFiles = new Set<string>();
  for (const configFile of discovery.configFiles) {
    const basename = path.basename(configFile);
    if (basename === 'package.json') {
      const content = safeReadFile(configFile);
      if (content) {
        const { lifecycleFiles: lf } = analyzePackageJson(configFile, content);
        for (const f of lf) lifecycleFiles.add(f);
      }
    }
  }

  // ── Step 5: Analyze source files (with concurrency limit) ─────────────────
  const limit = pLimit(concurrency);

  const sourceFilePromises = discovery.sourceFiles.map((filePath) =>
    limit(async () => {
      if (signal?.aborted) return;

      const content = safeReadFile(filePath);
      if (!content) {
        discovery.skippedFiles.push({ filePath, reason: 'unreadable' } as SkippedFile);
        return;
      }

      // Check cache
      allFindings.push(...detectObfuscatedLoader(filePath, content));
      allFindings.push(...detectLargeScript(filePath, content));

      const cached = getCachedResult(filePath, content, noCache);
      if (cached) {
        cacheHits++;
        allFindings.push(...cached.findings);
        return;
      }

      const isLifecycleContext = lifecycleFiles.has(filePath);
      const result = analyzeFile(filePath, content, { isLifecycleContext });
      setCachedResult(filePath, content, result, noCache);
      allFindings.push(...result.findings);

      // Secret detection on source files
      const secrets = detectSecrets(filePath, content, {
        isNewlyIntroduced: changedPaths ? changedPaths.includes(path.relative(root, filePath)) : undefined,
      });
      allSecretFindings.push(...secrets);
    }),
  );

  await Promise.all(sourceFilePromises);

  if (signal?.aborted) throw new ScanAbortedError();

  // ── Step 6: Analyze config files ─────────────────────────────────────────
  for (const configFile of discovery.configFiles) {
    if (signal?.aborted) break;
    const content = safeReadFile(configFile);
    if (!content) continue;

    const basename = path.basename(configFile);
    allFindings.push(...detectObfuscatedLoader(configFile, content));
    allFindings.push(...detectLargeScript(configFile, content));
    allFindings.push(...analyzeIdeTasks(configFile, content));

    if (basename === 'package.json') {
      const { findings } = analyzePackageJson(configFile, content);
      allFindings.push(...findings);
      const depFindings = inspectPackageJson(configFile, content);
      allDepFindings.push(...depFindings);

      // Secret detection in package.json too
      const secrets = detectSecrets(configFile, content);
      allSecretFindings.push(...secrets);
    } else if (basename === 'package-lock.json') {
      const { findings } = inspectPackageLock(configFile, content);
      allDepFindings.push(...findings);
    } else if (basename === 'pnpm-lock.yaml') {
      const { findings } = inspectPnpmLock(configFile, content);
      allDepFindings.push(...findings);
    } else if (basename === 'yarn.lock') {
      const { findings } = inspectYarnLock(configFile, content);
      allDepFindings.push(...findings);
    } else if (basename === '.npmrc') {
      const findings = analyzeNpmrc(configFile, content);
      allFindings.push(...findings);
      const secrets = detectSecrets(configFile, content);
      allSecretFindings.push(...secrets);
    } else if (/vite|webpack|next|postcss|tailwind|rollup|eslint|babel|jest|vitest/.test(basename)) {
      const findings = analyzeBuildConfig(configFile, content);
      allFindings.push(...findings);
    }
  }

  // ── Step 6b: Fake fonts and extensionless droppers ──────────────────────
  for (const fontFile of discovery.fontFiles) {
    if (signal?.aborted) break;
    const bytes = readFileBuffer(fontFile);
    if (!bytes) continue;
    const fontFinding = inspectFontCarrier(fontFile, bytes);
    if (fontFinding) allFindings.push(fontFinding);
    if (!isBinaryBuffer(bytes)) {
      allFindings.push(...detectObfuscatedLoader(fontFile, bytes.toString('utf8')));
      allFindings.push(...detectLargeScript(fontFile, bytes.toString('utf8')));
    }
  }

  for (const carrierFile of discovery.carrierFiles) {
    if (signal?.aborted) break;
    const content = safeReadFile(carrierFile);
    if (!content) continue;
    allFindings.push(...detectObfuscatedLoader(carrierFile, content));
    allFindings.push(...detectLargeScript(carrierFile, content));
  }

  // ── Step 7: Analyze workflow files ───────────────────────────────────────
  for (const workflowFile of discovery.workflowFiles) {
    if (signal?.aborted) break;
    const content = safeReadFile(workflowFile);
    if (!content) continue;

    const findings = analyzeWorkflow(workflowFile, content);
    allFindings.push(...findings);
  }

  // ── Step 8: Analyze shell scripts ─────────────────────────────────────────
  for (const shellFile of discovery.shellFiles) {
    if (signal?.aborted) break;
    const content = safeReadFile(shellFile);
    if (!content) continue;

    const findings = analyzeShellScript(shellFile, content);
    allFindings.push(...findings);
    allFindings.push(...detectLargeScript(shellFile, content));
    const secrets = detectSecrets(shellFile, content);
    allSecretFindings.push(...secrets);
  }

  // ── Step 9: Git analysis ──────────────────────────────────────────────────
  if (gitStatus.isRepo) {
    const hookFindings = await analyzeGitHooks(root, signal);
    allGitFindings.push(...hookFindings);

    if (options.mode === 'changed' || gitBaseSha) {
      const commits = await getRecentCommits(root, 20, gitBaseSha, signal);
      const commitFindings = analyzeCommits(commits, root);
      allGitFindings.push(...commitFindings);
    }
  }

  if (signal?.aborted) throw new ScanAbortedError();

  // ── Step 10: Apply severity filter ───────────────────────────────────────
  const filteredFindings = filterBySeverity(allFindings, minSeverity);
  const filteredDepFindings = filterBySeverity(allDepFindings, minSeverity);
  const filteredGitFindings = filterBySeverity(allGitFindings, minSeverity);

  // ── Step 11: Policy evaluation ────────────────────────────────────────────
  const policyResult = evaluatePolicy(
    filteredFindings,
    allSecretFindings,
    filteredDepFindings,
    filteredGitFindings,
    config,
    mode,
  );

  const totalScanned =
    discovery.sourceFiles.length +
    discovery.configFiles.length +
    discovery.workflowFiles.length +
    discovery.hookFiles.length +
    discovery.shellFiles.length +
    discovery.fontFiles.length +
    discovery.carrierFiles.length;

  const summary: ScanSummary = {
    scannedAt: new Date().toISOString(),
    scanDurationMs: Date.now() - startTime,
    mode,
    root,
    totalFilesDiscovered: discovery.totalDiscovered,
    totalFilesScanned: totalScanned,
    totalFilesSkipped: discovery.skippedFiles.length,
    findings: policyResult.processedFindings,
    dependencyFindings: filteredDepFindings,
    gitFindings: filteredGitFindings,
    secretFindings: policyResult.processedSecretFindings,
    skippedFiles: discovery.skippedFiles,
    suppressedCount: policyResult.suppressedCount,
    expiredSuppressions: policyResult.expiredSuppressions,
    policyViolation: policyResult.policyViolation,
    policyViolationReasons: policyResult.reasons,
    cacheHits,
    gitBaseSha,
  };

  return summary;
}

function readFileBuffer(filePath: string): Buffer | null {
  try {
    return fs.readFileSync(filePath);
  } catch {
    return null;
  }
}

function isBinaryBuffer(buf: Buffer): boolean {
  const checkLength = Math.min(buf.length, 8192);
  for (let i = 0; i < checkLength; i += 1) {
    if (buf[i] === 0) return true;
  }
  return false;
}
