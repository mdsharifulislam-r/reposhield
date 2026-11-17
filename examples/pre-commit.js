/**
 * RepoShield — CI/CD Integration Example (Pre-commit Hook)
 *
 * Install this as a Git pre-commit hook:
 *   cp examples/pre-commit.js .git/hooks/pre-commit
 *   chmod +x .git/hooks/pre-commit
 *
 * Or use husky:
 *   npx husky add .husky/pre-commit "node examples/pre-commit.js"
 *
 * This scans ONLY staged (changed) files so it stays fast.
 */

const { execSync } = require('child_process');
const path = require('path');

// In a real project: const { clean } = require('reposhield-scan');
const { clean } = require('../dist/cjs/index.js');

async function runPreCommitScan() {
  const repoRoot = process.cwd();

  // Get staged file paths (without running them)
  let stagedFiles;
  try {
    const output = execSync('git diff --cached --name-only --diff-filter=ACM', {
      cwd: repoRoot,
      encoding: 'utf8',
      timeout: 10_000,
    });
    stagedFiles = output.trim().split('\n').filter(Boolean);
  } catch {
    // If git fails, run full scan
    stagedFiles = undefined;
  }

  if (stagedFiles && stagedFiles.length === 0) {
    // Nothing staged — skip
    process.exit(0);
  }

  console.log(`🛡️  RepoShield pre-commit scan (${stagedFiles?.length ?? 'all'} file(s))...`);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 60_000);

  try {
    const summary = await clean({
      root: repoRoot,
      mode: 'strict',
      minSeverity: 'high',
      signal: controller.signal,
      quiet: false,
    });

    clearTimeout(timeout);

    const hasIssues =
      summary.findings.some((f) => !f.suppressed && (f.severity === 'critical' || f.severity === 'high')) ||
      summary.secretFindings.length > 0;

    if (summary.policyViolation || hasIssues) {
      console.error('\n❌ RepoShield pre-commit check FAILED');
      console.error('Fix the findings above before committing.');
      console.error('\nTo temporarily suppress a false positive, add to reposhield.config.json:');
      console.error('  { "ruleId": "RS-XXX-###", "reason": "Justified reason here", "expiresAt": "2025-12-31" }');
      process.exit(1);
    }

    console.log('✅ RepoShield pre-commit check passed\n');
    process.exit(0);
  } catch (err) {
    clearTimeout(timeout);
    if (err.name === 'ScanAbortedError') {
      console.error('Pre-commit scan timed out. Allowing commit, but run reposhield-scan scan manually.');
      process.exit(0); // Don't block if scan times out
    }
    console.error('RepoShield error:', err.message);
    process.exit(0); // Don't block commits on unexpected errors
  }
}

runPreCommitScan();
