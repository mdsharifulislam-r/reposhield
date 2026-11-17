/**
 * RepoShield — Programmatic API Example
 *
 * Shows how to consume RepoShield as a library in your own tooling.
 * Run: node examples/api-usage.js
 */

// In a real project: import { clean } from 'reposhield-scan';
// For this example we import from the local build
const { clean } = require('../dist/cjs/index.js');
const path = require('path');

async function runSecurityScan() {
  console.log('🛡️  Starting RepoShield API scan...\n');

  const controller = new AbortController();

  // Abort the scan after 30 seconds if it hasn't completed
  const timeout = setTimeout(() => controller.abort(), 30_000);

  try {
    const summary = await clean({
      // Absolute path to the repository to scan
      root: path.resolve(__dirname, '..'),

      // Scan mode:
      //   'audit'   — report only, never block
      //   'ci'      — block on policy violations
      //   'strict'  — strictest policy enforcement
      //   'changed' — only scan files changed relative to baseSha
      mode: 'audit',

      // Minimum severity to include in results
      minSeverity: 'medium',

      // Additional directories to exclude (on top of built-in exclusions)
      exclude: ['examples/', 'tests/fixtures/'],

      // Disable cache for demonstration (enable in production for speed)
      noCache: true,

      // AbortSignal for graceful cancellation
      signal: controller.signal,
    });

    clearTimeout(timeout);

    // ── Summary ───────────────────────────────────────────────────────────────
    console.log('Scan complete in', summary.scanDurationMs, 'ms');
    console.log('Files scanned:', summary.totalFilesScanned);
    console.log('Cache hits:', summary.cacheHits);
    console.log('');

    // ── Code findings ─────────────────────────────────────────────────────────
    if (summary.findings.length > 0) {
      console.log(`📋 Code findings: ${summary.findings.length}`);
      for (const f of summary.findings) {
        if (f.suppressed) continue;
        console.log(`  [${f.severity.toUpperCase()}] ${f.ruleId} — ${f.filePath}:${f.line ?? '?'}`);
        console.log(`    ${f.message}`);
        console.log(`    Risk score: ${f.riskScore}/100 | Confidence: ${f.confidence}`);
        if (f.correlatedSignals && f.correlatedSignals.length > 1) {
          console.log(`    Correlated signals: ${f.correlatedSignals.map((s) => s.signalId).join(', ')}`);
        }
      }
      console.log('');
    }

    // ── Secret findings ───────────────────────────────────────────────────────
    if (summary.secretFindings.length > 0) {
      console.log(`🔑 Secret findings: ${summary.secretFindings.length}`);
      for (const s of summary.secretFindings) {
        console.log(`  ${s.ruleId} — ${s.filePath}:${s.line} — ${s.secretType}`);
        console.log(`  Redacted: ${s.redactedValue}`);
      }
      console.log('');
    }

    // ── Dependency findings ────────────────────────────────────────────────────
    if (summary.dependencyFindings.length > 0) {
      console.log(`📦 Dependency findings: ${summary.dependencyFindings.length}`);
      for (const d of summary.dependencyFindings) {
        console.log(`  [${d.severity.toUpperCase()}] ${d.findingType} — ${d.packageName}@${d.version}`);
        console.log(`    ${d.message}`);
      }
      console.log('');
    }

    // ── Git findings ───────────────────────────────────────────────────────────
    if (summary.gitFindings.length > 0) {
      console.log(`🔀 Git findings: ${summary.gitFindings.length}`);
      for (const g of summary.gitFindings) {
        console.log(`  [${g.severity.toUpperCase()}] ${g.findingType}: ${g.message}`);
      }
      console.log('');
    }

    // ── Policy result ─────────────────────────────────────────────────────────
    if (summary.policyViolation) {
      console.error('❌ Policy violation:');
      for (const reason of summary.policyViolationReasons) {
        console.error(`  • ${reason}`);
      }
      process.exit(1);
    } else {
      console.log('✅ Scan passed — no policy violations');
    }

    return summary;
  } catch (err) {
    clearTimeout(timeout);
    if (err.name === 'ScanAbortedError') {
      console.error('Scan aborted.');
      process.exit(3);
    }
    throw err;
  }
}

runSecurityScan().catch((err) => {
  console.error('Unexpected error:', err);
  process.exit(2);
});
