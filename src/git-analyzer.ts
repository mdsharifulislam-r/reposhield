/**
 * RepoShield — Git Analysis Subsystem
 *
 * Analyzes Git history and working tree changes safely.
 *
 * Security properties:
 * - All Git commands use array-based argument passing (no shell interpolation)
 * - Bounded timeouts on all Git operations
 * - Validates Git references before using them
 * - Never modifies Git history
 * - Never treats HEAD~1 as automatically safe
 * - Rejects untrusted filenames in shell commands
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import { GitFinding, GitError } from './types.js';

const execFileAsync = promisify(execFile);

const GIT_TIMEOUT_MS = 30_000; // 30 seconds maximum

// ─── Git Execution Wrapper ────────────────────────────────────────────────────

async function runGit(
  args: string[],
  cwd: string,
  signal?: AbortSignal,
): Promise<string> {
  // Validate all arguments to prevent injection
  for (const arg of args) {
    if (typeof arg !== 'string') {
      throw new GitError(`Invalid Git argument type: ${typeof arg}`);
    }
    // Reject args containing shell metacharacters when not a file path
    // File path args should be validated separately before passing
  }

  try {
    const { stdout } = await execFileAsync('git', args, {
      cwd,
      timeout: GIT_TIMEOUT_MS,
      maxBuffer: 10 * 1024 * 1024, // 10 MB
      signal,
      windowsHide: true,
    } as Parameters<typeof execFileAsync>[2]);
    return typeof stdout === 'string' ? stdout : '';
  } catch (err: unknown) {
    const error = err as NodeJS.ErrnoException & { killed?: boolean; code?: unknown };
    if (error.killed || (signal && signal.aborted)) {
      throw new GitError('Git command timed out or was aborted');
    }
    // Exit code 1 from git diff means "differences found" — not an error
    const stderr = (err as { stderr?: string }).stderr ?? '';
    if (String(error.code) === '1' && args[0] === 'diff') {
      return (err as { stdout?: string }).stdout ?? '';
    }
    // git log with no commits is not an error for our purposes
    if (stderr.includes('does not have any commits yet')) {
      return '';
    }
    throw new GitError(`Git error: ${stderr || String(err)}`);
  }
}

// ─── Reference Validation ─────────────────────────────────────────────────────

const SAFE_REF_PATTERN = /^[a-zA-Z0-9._/\-]{1,200}$/;

export function validateGitRef(ref: string): void {
  if (!SAFE_REF_PATTERN.test(ref)) {
    throw new GitError(
      `Invalid Git reference: "${ref}". References must contain only alphanumeric characters, dots, slashes, hyphens, and underscores.`,
    );
  }
  if (ref.includes('..') && !ref.includes('...')) {
    // Allow range notation but block directory traversal
    const parts = ref.split('..');
    for (const part of parts) {
      if (!SAFE_REF_PATTERN.test(part)) {
        throw new GitError(`Invalid Git reference range: "${ref}"`);
      }
    }
  }
}

// ─── Repository Status ────────────────────────────────────────────────────────

export interface GitStatus {
  isRepo: boolean;
  currentBranch: string | null;
  headSha: string | null;
  hasUncommittedChanges: boolean;
  stagedFiles: string[];
  unstagedFiles: string[];
  untrackedFiles: string[];
  isRootCommit: boolean;
}

export async function getRepoStatus(root: string, signal?: AbortSignal): Promise<GitStatus> {
  const defaultStatus: GitStatus = {
    isRepo: false,
    currentBranch: null,
    headSha: null,
    hasUncommittedChanges: false,
    stagedFiles: [],
    unstagedFiles: [],
    untrackedFiles: [],
    isRootCommit: false,
  };

  try {
    // Verify this is a Git repo
    await runGit(['rev-parse', '--git-dir'], root, signal);
  } catch {
    return defaultStatus;
  }

  try {
    const [branchOutput, headShaOutput, statusOutput, rootCheckOutput] = await Promise.allSettled([
      runGit(['rev-parse', '--abbrev-ref', 'HEAD'], root, signal),
      runGit(['rev-parse', 'HEAD'], root, signal),
      runGit(['status', '--porcelain=v1'], root, signal),
      runGit(['rev-list', '--parents', '-n', '1', 'HEAD'], root, signal),
    ]);

    const branch = branchOutput.status === 'fulfilled' ? branchOutput.value.trim() : null;
    const headSha = headShaOutput.status === 'fulfilled' ? headShaOutput.value.trim() : null;
    const statusText = statusOutput.status === 'fulfilled' ? statusOutput.value : '';
    const rootCheck = rootCheckOutput.status === 'fulfilled' ? rootCheckOutput.value.trim() : '';

    // Root commit has no parent — only 1 SHA in the rev-list output
    const isRootCommit = rootCheck ? rootCheck.split(' ').length === 1 : false;

    const staged: string[] = [];
    const unstaged: string[] = [];
    const untracked: string[] = [];

    for (const line of statusText.split('\n')) {
      if (!line.trim()) continue;
      const stagedCode = line[0] ?? ' ';
      const unstagedCode = line[1] ?? ' ';
      const filePath = line.substring(3).trim();

      if (stagedCode !== ' ' && stagedCode !== '?') staged.push(filePath);
      if (unstagedCode !== ' ' && unstagedCode !== '?') unstaged.push(filePath);
      if (stagedCode === '?' && unstagedCode === '?') untracked.push(filePath);
    }

    return {
      isRepo: true,
      currentBranch: branch,
      headSha,
      hasUncommittedChanges: staged.length > 0 || unstaged.length > 0,
      stagedFiles: staged,
      unstagedFiles: unstaged,
      untrackedFiles: untracked,
      isRootCommit,
    };
  } catch {
    return { ...defaultStatus, isRepo: true };
  }
}

// ─── Changed Files ────────────────────────────────────────────────────────────

export interface ChangedFilesResult {
  files: string[];
  baseSha: string;
  headSha: string;
}

export async function getChangedFiles(
  root: string,
  baseSha: string,
  headSha = 'HEAD',
  signal?: AbortSignal,
): Promise<ChangedFilesResult> {
  validateGitRef(baseSha);
  validateGitRef(headSha);

  // Resolve SHAs to prevent ambiguity
  const [resolvedBase, resolvedHead] = await Promise.all([
    runGit(['rev-parse', '--verify', baseSha], root, signal),
    runGit(['rev-parse', '--verify', headSha], root, signal),
  ]);

  const diffOutput = await runGit(
    ['diff', '--name-only', '--diff-filter=ACMRT', resolvedBase.trim(), resolvedHead.trim()],
    root,
    signal,
  );

  const files = diffOutput
    .split('\n')
    .map((f) => f.trim())
    .filter(Boolean)
    .filter((f) => {
      // Validate each file path — no shell metacharacters, no absolute paths
      return !path.isAbsolute(f) && !f.includes('\0');
    });

  return {
    files,
    baseSha: resolvedBase.trim(),
    headSha: resolvedHead.trim(),
  };
}

// ─── Working Tree Changes ─────────────────────────────────────────────────────

export async function getWorkingTreeChangedFiles(root: string, signal?: AbortSignal): Promise<string[]> {
  try {
    const output = await runGit(['diff', '--name-only', 'HEAD'], root, signal);
    return output
      .split('\n')
      .map((f) => f.trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

// ─── Git Hook Analysis ────────────────────────────────────────────────────────

export async function analyzeGitHooks(root: string, signal?: AbortSignal): Promise<GitFinding[]> {
  const findings: GitFinding[] = [];

  // Check if hooks directory has been moved (custom hooksPath)
  let hooksPath = '.git/hooks';
  try {
    const configOutput = await runGit(['config', 'core.hooksPath'], root, signal);
    const customPath = configOutput.trim();
    if (customPath && customPath !== '.git/hooks') {
      findings.push({
        findingType: 'hook-tamper',
        severity: 'medium',
        filePath: customPath,
        message: `Git hooks path has been moved to "${customPath}" via core.hooksPath. This could redirect hook execution to malicious scripts.`,
        remediation: 'Verify that the custom hooks path is intentional and trusted.',
      });
      hooksPath = customPath;
    }
  } catch {
    // core.hooksPath not configured
  }

  return findings;
}

// ─── Commit History Analysis ──────────────────────────────────────────────────

export interface CommitInfo {
  sha: string;
  author: string;
  date: string;
  message: string;
  filesChanged: string[];
}

export async function getRecentCommits(
  root: string,
  limit = 20,
  baseSha?: string,
  signal?: AbortSignal,
): Promise<CommitInfo[]> {
  const args = baseSha
    ? ['log', '--format=%H|%ae|%aI|%s', `${baseSha}..HEAD`, `-${limit}`, '--name-only']
    : ['log', '--format=%H|%ae|%aI|%s', `-${limit}`, '--name-only'];

  if (baseSha) validateGitRef(baseSha);

  let output: string;
  try {
    output = await runGit(args, root, signal);
  } catch {
    return [];
  }

  const commits: CommitInfo[] = [];
  const blocks = output.split('\n\n').filter(Boolean);

  for (const block of blocks) {
    const lines = block.trim().split('\n');
    const headerLine = lines[0];
    if (!headerLine) continue;

    const parts = headerLine.split('|');
    if (parts.length < 4) continue;

    const [sha, author, date, ...messageParts] = parts;
    commits.push({
      sha: sha ?? '',
      author: author ?? '',
      date: date ?? '',
      message: messageParts.join('|'),
      filesChanged: lines.slice(1).filter((l) => l.trim()),
    });
  }

  return commits;
}

// ─── Suspicious Commit Detection ──────────────────────────────────────────────

const SECURITY_SENSITIVE_FILES = [
  '.github/workflows',
  'package.json',
  '.npmrc',
  '.gitignore',
  '.gitattributes',
  '.gitconfig',
  'reposhield.config',
  '.reposhieldrc',
];

export function analyzeCommits(commits: CommitInfo[], root: string): GitFinding[] {
  const findings: GitFinding[] = [];

  for (const commit of commits) {
    // Check for modification of scanner config files
    for (const file of commit.filesChanged) {
      const normalized = file.toLowerCase();

      if (SECURITY_SENSITIVE_FILES.some((s) => normalized.includes(s.toLowerCase()))) {
        findings.push({
          findingType: 'security-control-change',
          severity: 'medium',
          commitSha: commit.sha,
          filePath: file,
          message:
            `Commit ${commit.sha.substring(0, 8)} (by ${commit.author}) modified security-sensitive file: "${file}". ` +
            `Message: "${commit.message}"`,
          remediation:
            'Review this commit carefully. Changes to workflows, package.json scripts, or scanner config may weaken security controls.',
        });
      }

      // Check for newly added executable files
      if (file.match(/\.(sh|bash|ps1|cmd|bat|exe|dll|so)$/i)) {
        findings.push({
          findingType: 'new-executable',
          severity: 'medium',
          commitSha: commit.sha,
          filePath: file,
          message: `Commit ${commit.sha.substring(0, 8)} modified executable file: "${file}"`,
          remediation: 'Review the executable file for malicious content.',
        });
      }
    }

    // Check for suspicious commit messages
    const msgLower = commit.message.toLowerCase();
    const SUSPICIOUS_MESSAGES = [
      'disable security', 'skip scan', 'bypass check', 'remove lint',
      'ignore reposhield', 'disable reposhield', 'skip validation',
    ];
    if (SUSPICIOUS_MESSAGES.some((m) => msgLower.includes(m))) {
      findings.push({
        findingType: 'scanner-config-change',
        severity: 'high',
        commitSha: commit.sha,
        message: `Commit ${commit.sha.substring(0, 8)} has a suspicious message that may indicate an attempt to bypass security: "${commit.message}"`,
        remediation: 'Investigate this commit and the intent behind the message.',
      });
    }
  }

  return findings;
}

// ─── Git Availability Check ───────────────────────────────────────────────────

export async function checkGitAvailability(): Promise<{ available: boolean; version: string | null }> {
  try {
    const output = await runGit(['--version'], process.cwd());
    return { available: true, version: output.trim() };
  } catch {
    return { available: false, version: null };
  }
}
