/**
 * RepoShield — Dependency Inspector
 *
 * Parses package.json, package-lock.json, yarn.lock, and pnpm-lock.yaml
 * WITHOUT running any installation scripts or network requests (unless
 * networkAdvisory is explicitly enabled).
 *
 * Detects:
 * - Lifecycle script risks
 * - Git/URL dependencies
 * - Registry changes
 * - Typosquat candidates
 * - Lockfile inconsistencies
 * - Known vulnerabilities (offline DB only unless networkAdvisory=true)
 */

import path from 'path';
import semver from 'semver';
import { DependencyFinding, Severity } from './types.js';

// ─── Known typosquat candidates (abbreviated list for illustration) ────────────

const KNOWN_POPULAR_PACKAGES = new Set([
  'express', 'react', 'react-dom', 'vue', 'angular', 'next', 'nuxt',
  'lodash', 'axios', 'moment', 'dayjs', 'chalk', 'commander', 'yargs',
  'typescript', 'webpack', 'vite', 'rollup', 'babel', 'jest', 'mocha',
  'eslint', 'prettier', 'husky', 'lint-staged', 'dotenv', 'cors',
  'mongoose', 'sequelize', 'prisma', 'typeorm', 'knex', 'pg', 'mysql2',
  'socket.io', 'ws', 'fastify', 'koa', 'hapi', 'restify', 'nodemon',
  'pm2', 'cross-env', 'rimraf', 'glob', 'minimatch', 'semver', 'uuid',
  'bcrypt', 'jsonwebtoken', 'passport', 'helmet', 'morgan', 'body-parser',
  'multer', 'sharp', 'jimp', 'node-fetch', 'got', 'superagent', 'cheerio',
]);

// Common typosquat patterns: character substitution, extra/missing chars
function isTyposquatCandidate(name: string): string | null {
  const clean = name.replace(/^@[^/]+\//, ''); // strip scope

  for (const popular of KNOWN_POPULAR_PACKAGES) {
    if (clean === popular) return null; // Exact match — not suspicious
    if (levenshteinDistance(clean, popular) === 1 && clean !== popular) {
      return popular;
    }
  }
  return null;
}

function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)),
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i]![j]! =
        a[i - 1] === b[j - 1]
          ? dp[i - 1]![j - 1]!
          : 1 + Math.min(dp[i - 1]![j]!, dp[i]![j - 1]!, dp[i - 1]![j - 1]!);
    }
  }
  return dp[m]![n]!;
}

// ─── Git / URL dependency patterns ────────────────────────────────────────────

const GIT_DEP_PATTERNS = [
  /^git\+/,
  /^github:/,
  /^gitlab:/,
  /^bitbucket:/,
  /^[^@]+\/[^@]+$/,            // shorthand github: user/repo
  /^https?:\/\/.*\.git/,
  /^git:\/\//,
];

const URL_DEP_PATTERNS = [
  /^https?:\/\//,
  /^file:/,
  /^link:/,
];

function isGitDependency(version: string): boolean {
  return GIT_DEP_PATTERNS.some((p) => p.test(version));
}

function isUrlDependency(version: string): boolean {
  return URL_DEP_PATTERNS.some((p) => p.test(version));
}

// ─── Lifecycle Script Risk ────────────────────────────────────────────────────

const LIFECYCLE_KEYS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack', 'prepublish'];

function hasRiskyLifecycleScript(scripts: Record<string, string>): string[] {
  return Object.keys(scripts).filter((k) => LIFECYCLE_KEYS.includes(k));
}

// ─── Package.json Dependency Inspector ────────────────────────────────────────

export function inspectPackageJson(
  filePath: string,
  content: string,
): DependencyFinding[] {
  const findings: DependencyFinding[] = [];

  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return findings;
  }

  const allDeps: Record<string, string> = {
    ...((pkg['dependencies'] as Record<string, string> | undefined) ?? {}),
    ...((pkg['devDependencies'] as Record<string, string> | undefined) ?? {}),
    ...((pkg['optionalDependencies'] as Record<string, string> | undefined) ?? {}),
    ...((pkg['peerDependencies'] as Record<string, string> | undefined) ?? {}),
  };

  for (const [name, version] of Object.entries(allDeps)) {
    if (typeof version !== 'string') continue;

    // Git dependency
    if (isGitDependency(version)) {
      findings.push({
        packageName: name,
        version,
        findingType: 'git-dependency',
        severity: 'medium',
        message: `Package "${name}" is installed from a Git source: "${version}". Git dependencies bypass integrity checks and may include arbitrary commits.`,
        remediation: 'Prefer published npm packages with integrity checksums. If Git is required, pin to a specific commit SHA.',
        evidence: `"${name}": "${version}"`,
      });
    }

    // URL dependency
    if (isUrlDependency(version)) {
      findings.push({
        packageName: name,
        version,
        findingType: 'url-dependency',
        severity: 'high',
        message: `Package "${name}" is installed from a URL: "${version}". URL dependencies have no integrity verification.`,
        remediation: 'Do not install packages from arbitrary URLs. Use the npm registry with provenance.',
        evidence: `"${name}": "${version}"`,
      });
    }

    // Typosquat candidate
    const popular = isTyposquatCandidate(name);
    if (popular) {
      findings.push({
        packageName: name,
        version,
        findingType: 'typosquat-candidate',
        severity: 'high',
        message: `Package "${name}" is 1 character away from popular package "${popular}". This may be a typosquat attack.`,
        remediation: `Verify that "${name}" is the intended package. If "${popular}" was intended, correct the dependency name.`,
        evidence: `"${name}" ≈ "${popular}"`,
      });
    }
  }

  // Lifecycle scripts
  const scripts = (pkg['scripts'] as Record<string, string>) ?? {};
  const riskyScripts = hasRiskyLifecycleScript(scripts);
  for (const scriptKey of riskyScripts) {
    findings.push({
      packageName: (pkg['name'] as string) ?? path.basename(path.dirname(filePath)),
      version: (pkg['version'] as string) ?? 'unknown',
      findingType: 'lifecycle-script',
      severity: 'medium',
      message: `Package has lifecycle script "${scriptKey}": "${scripts[scriptKey]?.substring(0, 200) ?? ''}". This script executes during npm install.`,
      remediation:
        'Review lifecycle scripts. Consider whether they are necessary. ' +
        'Users can disable lifecycle scripts with --ignore-scripts, but this may break intended functionality. ' +
        'See https://docs.npmjs.com/cli/v9/commands/npm-install',
      evidence: `"${scriptKey}": "${scripts[scriptKey]?.substring(0, 100) ?? ''}"`,
    });
  }

  return findings;
}

// ─── Lockfile Inspector ───────────────────────────────────────────────────────

export interface LockfileInspectionResult {
  findings: DependencyFinding[];
  packageCount: number;
}

export function inspectPackageLock(
  filePath: string,
  content: string,
): LockfileInspectionResult {
  const findings: DependencyFinding[] = [];

  let lock: Record<string, unknown>;
  try {
    lock = JSON.parse(content) as Record<string, unknown>;
  } catch {
    findings.push({
      packageName: path.basename(filePath),
      version: 'unknown',
      findingType: 'lockfile-inconsistency',
      severity: 'medium',
      message: 'package-lock.json is not valid JSON — lockfile may be corrupted or tampered',
      remediation: 'Regenerate the lockfile with npm install.',
    });
    return { findings, packageCount: 0 };
  }

  const lockfileVersion = lock['lockfileVersion'];
  const packages = lock['packages'] as Record<string, unknown> | undefined;

  if (!packages) {
    return { findings, packageCount: 0 };
  }

  let packageCount = 0;

  for (const [pkgPath, pkgInfo] of Object.entries(packages)) {
    if (!pkgPath || pkgPath === '') continue; // root
    packageCount++;

    const info = pkgInfo as Record<string, unknown>;
    const resolved = info['resolved'] as string | undefined;
    const integrity = info['integrity'] as string | undefined;
    const version = info['version'] as string | undefined;

    // Missing integrity — can't verify
    if (!integrity && resolved) {
      findings.push({
        packageName: pkgPath.replace(/^node_modules\//, ''),
        version: version ?? 'unknown',
        findingType: 'lockfile-inconsistency',
        severity: 'low',
        message: `Package "${pkgPath}" in lockfile has no integrity hash. Cannot verify content integrity.`,
        remediation: 'Regenerate lockfile to include integrity hashes.',
        evidence: `resolved: ${resolved}`,
      });
    }

    // Non-registry resolved URLs
    if (resolved && !/^https:\/\/registry\.npmjs\.org\//.test(resolved)) {
      if (/^https?:\/\//.test(resolved)) {
        findings.push({
          packageName: pkgPath.replace(/^node_modules\//, ''),
          version: version ?? 'unknown',
          findingType: 'suspicious-source',
          severity: 'high',
          message: `Package "${pkgPath}" resolves from non-npm registry: "${resolved}"`,
          remediation: 'Verify the registry source is trusted. Dependency confusion attacks use non-default registries.',
          evidence: `resolved: ${resolved}`,
        });
      }
    }

    // Git-resolved packages
    if (resolved && (resolved.startsWith('git+') || resolved.includes('.git#'))) {
      findings.push({
        packageName: pkgPath.replace(/^node_modules\//, ''),
        version: version ?? 'unknown',
        findingType: 'git-dependency',
        severity: 'medium',
        message: `Package "${pkgPath}" is resolved from Git: "${resolved}"`,
        remediation: 'Git dependencies bypass npm integrity verification.',
        evidence: `resolved: ${resolved}`,
      });
    }
  }

  return { findings, packageCount };
}

// ─── pnpm Lock Inspector ──────────────────────────────────────────────────────

export function inspectPnpmLock(filePath: string, content: string): LockfileInspectionResult {
  const findings: DependencyFinding[] = [];
  let packageCount = 0;

  // Check for git: or file: dependencies in pnpm-lock.yaml
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (/^\s+resolution:/.test(line)) {
      packageCount++;
      if (/git\+|\.git#/.test(line)) {
        findings.push({
          packageName: extractPnpmPackageName(lines, i),
          version: 'unknown',
          findingType: 'git-dependency',
          severity: 'medium',
          message: `pnpm lockfile contains a Git-resolved dependency on line ${i + 1}`,
          remediation: 'Review and replace Git dependencies with registry-published versions.',
          evidence: line.trim(),
        });
      }
      if (/https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com)/.test(line)) {
        findings.push({
          packageName: extractPnpmPackageName(lines, i),
          version: 'unknown',
          findingType: 'suspicious-source',
          severity: 'high',
          message: `pnpm lockfile references non-standard registry on line ${i + 1}`,
          remediation: 'Verify all package sources are trusted registries.',
          evidence: line.trim(),
        });
      }
    }
  }

  return { findings, packageCount };
}

function extractPnpmPackageName(lines: string[], fromLine: number): string {
  // Walk back to find the package name header
  for (let i = fromLine; i >= 0; i--) {
    const line = lines[i] ?? '';
    if (/^\//.test(line.trim())) {
      return line.trim().split('@')[0]?.replace(/^\//, '') ?? 'unknown';
    }
  }
  return 'unknown';
}

// ─── Yarn Lock Inspector ──────────────────────────────────────────────────────

export function inspectYarnLock(filePath: string, content: string): LockfileInspectionResult {
  const findings: DependencyFinding[] = [];
  let packageCount = 0;

  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (/^\s+resolved\s+"/.test(line)) {
      packageCount++;
      const resolvedMatch = line.match(/resolved\s+"([^"]+)"/);
      const resolved = resolvedMatch?.[1];
      if (!resolved) continue;

      if (!resolved.includes('registry.npmjs.org') && !resolved.includes('registry.yarnpkg.com')) {
        if (/^https?:\/\//.test(resolved)) {
          findings.push({
            packageName: extractYarnPackageName(lines, i),
            version: 'unknown',
            findingType: 'suspicious-source',
            severity: 'high',
            message: `yarn.lock resolves from non-standard registry: "${resolved}"`,
            remediation: 'Verify the package source is trusted.',
            evidence: `resolved: ${resolved}`,
          });
        }
      }

      if (/^git\+|\.git#/.test(resolved)) {
        findings.push({
          packageName: extractYarnPackageName(lines, i),
          version: 'unknown',
          findingType: 'git-dependency',
          severity: 'medium',
          message: `yarn.lock contains a Git-resolved package: "${resolved}"`,
          remediation: 'Replace Git dependencies with registry-published versions.',
          evidence: `resolved: ${resolved}`,
        });
      }
    }
  }

  return { findings, packageCount };
}

function extractYarnPackageName(lines: string[], fromLine: number): string {
  for (let i = fromLine; i >= 0; i--) {
    const line = lines[i] ?? '';
    if (/^[^"\s]/.test(line)) {
      return line.split('@')[0]?.trim().replace(/^"/, '') ?? 'unknown';
    }
  }
  return 'unknown';
}
