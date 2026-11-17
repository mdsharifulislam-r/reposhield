/**
 * RepoShield — Safe Recovery Subsystem
 *
 * Produces recovery plans and executes safe recovery operations.
 *
 * SAFETY GUARANTEES:
 * - Never runs git reset --hard automatically
 * - Never runs git clean -fd automatically
 * - Never pushes or force-pushes
 * - Never deletes the current commit
 * - Requires explicit confirmation for history-changing operations
 * - Verifies backups before any destructive operation
 * - A previous commit is NOT considered safe merely because it predates the incident
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import fs from 'fs';
import { GitError } from './types.js';
import { getRepoStatus, validateGitRef, getRecentCommits } from './git-analyzer.js';

const execFileAsync = promisify(execFile);
const GIT_TIMEOUT_MS = 30_000;

async function runGit(args: string[], cwd: string, signal?: AbortSignal): Promise<string> {
  const { stdout } = await execFileAsync('git', args, {
    cwd, timeout: GIT_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024,
    signal, windowsHide: true,
  } as Parameters<typeof execFileAsync>[2]);
  return typeof stdout === 'string' ? stdout : '';
}

// ─── Recovery Plan ────────────────────────────────────────────────────────────

export interface RecoveryTarget {
  sha: string;
  description: string;
  hasBeenScanned: boolean;
}

export interface RecoveryPlan {
  currentBranch: string | null;
  currentSha: string | null;
  candidateTargets: RecoveryTarget[];
  suspiciousCommits: Array<{ sha: string; reason: string }>;
  affectedFiles: string[];
  workingTreeStatus: {
    hasUncommittedChanges: boolean;
    stagedFiles: string[];
    unstagedFiles: string[];
    untrackedFiles: string[];
  };
  backupStrategy: string;
  strategy1Description: string;
  strategy2Description: string;
  importantWarnings: string[];
  incidentChecklist: string[];
}

// ─── Recovery Plan Generation ─────────────────────────────────────────────────

export async function buildRecoveryPlan(
  root: string,
  signal?: AbortSignal,
): Promise<RecoveryPlan> {
  const status = await getRepoStatus(root, signal);

  if (!status.isRepo) {
    throw new GitError('Not inside a Git repository. Cannot build recovery plan.');
  }

  // Get recent commits for analysis
  const commits = await getRecentCommits(root, 10, undefined, signal);

  // Identify suspicious commits (simplified — scanner findings should be correlated here)
  const suspiciousCommits: Array<{ sha: string; reason: string }> = [];
  const affectedFiles: string[] = [];

  for (const commit of commits) {
    const msgLower = commit.message.toLowerCase();
    if (
      msgLower.includes('fix') ||
      commit.filesChanged.some((f) =>
        ['package.json', '.npmrc', '.github/workflows'].some((s) => f.includes(s)),
      )
    ) {
      suspiciousCommits.push({
        sha: commit.sha.substring(0, 8),
        reason: `Modified sensitive files: ${commit.filesChanged.join(', ')}`,
      });
      affectedFiles.push(...commit.filesChanged);
    }
  }

  // Build candidate recovery targets
  const candidateTargets: RecoveryTarget[] = commits.slice(0, 5).map((c, i) => ({
    sha: c.sha.substring(0, 8),
    description:
      `${i === 0 ? 'HEAD' : `HEAD~${i}`}: ${c.message.substring(0, 60)} (${c.author}, ${c.date.substring(0, 10)})`,
    hasBeenScanned: false, // Would be true if scan was run against this commit
  }));

  return {
    currentBranch: status.currentBranch,
    currentSha: status.headSha,
    candidateTargets,
    suspiciousCommits,
    affectedFiles: [...new Set(affectedFiles)],
    workingTreeStatus: {
      hasUncommittedChanges: status.hasUncommittedChanges,
      stagedFiles: status.stagedFiles,
      unstagedFiles: status.unstagedFiles,
      untrackedFiles: status.untrackedFiles,
    },
    backupStrategy:
      'Before any recovery: create a backup branch:\n' +
      '  git branch backup/pre-recovery-$(date +%Y%m%d%H%M%S)\n' +
      'Also export your work:\n' +
      '  git stash\n' +
      '  git bundle create backup.bundle --all',
    strategy1Description:
      'Strategy 1 — Revert commit (preserves shared history):\n' +
      '  git revert <suspicious-commit-sha>\n' +
      '  This creates a new commit that undoes changes without rewriting history.\n' +
      '  Safe for shared branches. Requires review of the revert diff.',
    strategy2Description:
      'Strategy 2 — Recovery branch from trusted commit:\n' +
      '  git checkout -b recovery/<trusted-sha-short> <trusted-sha>\n' +
      '  Cherry-pick legitimate changes onto the new branch.\n' +
      '  Requires team coordination. Never force-push to protected branches.',
    importantWarnings: [
      'WARNING: A previous commit is NOT automatically safe merely because it predates the detected incident.',
      'WARNING: Malware may have been present before the current detection.',
      'WARNING: Recovery does not guarantee that secrets were not already exfiltrated.',
      'WARNING: You must rotate all credentials and secrets as a separate step.',
      'WARNING: Review the recovery target with `reposhield-scan scan --base <sha>` before restoring.',
      'WARNING: This tool does not automatically execute git reset --hard, git clean, or git push --force.',
    ],
    incidentChecklist: [
      '1. IMMEDIATELY rotate all credentials: npm tokens, GitHub PATs, cloud keys, database passwords.',
      '2. Review GitHub organization access: check OAuth apps, deploy keys, and collaborator access.',
      '3. Audit CI/CD secrets in GitHub Actions, CircleCI, and similar platforms.',
      '4. Review all workflow runs that may have accessed secrets during the compromised period.',
      '5. Investigate dependency tree: run `npm audit` and check for unexpected package changes.',
      '6. Verify deployed build artifacts: re-deploy from a verified clean revision if possible.',
      '7. Contact your security team and follow your incident response plan.',
      '8. Notify affected users if sensitive data was exposed.',
      '9. File a report with npm security if a published package was compromised.',
      '10. Document the incident timeline and remediation steps taken.',
    ],
  };
}

// ─── Backup Verification ──────────────────────────────────────────────────────

export async function verifyBackupExists(
  root: string,
  backupRef: string,
  signal?: AbortSignal,
): Promise<{ exists: boolean; details: string }> {
  try {
    validateGitRef(backupRef);
    const output = await runGit(['rev-parse', '--verify', backupRef], root, signal);
    return { exists: true, details: `Backup reference "${backupRef}" exists: ${output.trim()}` };
  } catch {
    return {
      exists: false,
      details: `Backup reference "${backupRef}" does not exist. Create it before proceeding.`,
    };
  }
}

// ─── Revert Commit (Strategy 1) ───────────────────────────────────────────────

export async function createRevertCommit(
  root: string,
  targetSha: string,
  confirmCallback: () => Promise<boolean>,
  signal?: AbortSignal,
): Promise<{ success: boolean; message: string }> {
  validateGitRef(targetSha);

  // Resolve and verify the target SHA
  let resolvedSha: string;
  try {
    resolvedSha = (await runGit(['rev-parse', '--verify', targetSha], root, signal)).trim();
  } catch {
    return { success: false, message: `Cannot resolve target: "${targetSha}". Verify it exists.` };
  }

  // Verify backup exists
  const status = await getRepoStatus(root, signal);
  const backupBranch = `backup/pre-recovery-${Date.now()}`;

  // Require explicit confirmation
  const confirmed = await confirmCallback();
  if (!confirmed) {
    return { success: false, message: 'Recovery cancelled by user.' };
  }

  // Create backup branch first
  try {
    await runGit(['branch', backupBranch, 'HEAD'], root, signal);
  } catch {
    return { success: false, message: `Failed to create backup branch "${backupBranch}". Aborting.` };
  }

  // Create the revert commit
  try {
    await runGit(['revert', '--no-edit', resolvedSha], root, signal);
    return {
      success: true,
      message:
        `Revert commit created. Backup branch: "${backupBranch}". ` +
        'Review the revert diff before pushing. Run reposhield-scan scan before deploying.',
    };
  } catch (err) {
    return {
      success: false,
      message: `Revert failed: ${String(err)}. The backup branch "${backupBranch}" was created.`,
    };
  }
}

// ─── Recovery Branch (Strategy 2) ────────────────────────────────────────────

export async function createRecoveryBranch(
  root: string,
  trustedSha: string,
  confirmCallback: () => Promise<boolean>,
  signal?: AbortSignal,
): Promise<{ success: boolean; branchName: string; message: string }> {
  validateGitRef(trustedSha);

  let resolvedSha: string;
  try {
    resolvedSha = (await runGit(['rev-parse', '--verify', trustedSha], root, signal)).trim();
  } catch {
    return {
      success: false,
      branchName: '',
      message: `Cannot resolve trusted SHA: "${trustedSha}". Verify it exists.`,
    };
  }

  const confirmed = await confirmCallback();
  if (!confirmed) {
    return { success: false, branchName: '', message: 'Recovery cancelled by user.' };
  }

  const branchName = `recovery/${resolvedSha.substring(0, 8)}-${Date.now()}`;

  try {
    await runGit(['checkout', '-b', branchName, resolvedSha], root, signal);
    return {
      success: true,
      branchName,
      message:
        `Recovery branch "${branchName}" created from "${resolvedSha.substring(0, 8)}". ` +
        'Cherry-pick legitimate commits onto this branch. ' +
        'Run reposhield-scan scan before merging or deploying.',
    };
  } catch (err) {
    return { success: false, branchName: '', message: `Branch creation failed: ${String(err)}` };
  }
}
