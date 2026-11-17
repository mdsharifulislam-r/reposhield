/**
 * RepoShield — Integration Test (Scanner Orchestrator)
 *
 * Tests the full clean() pipeline end-to-end against fixture directories.
 * These tests run the complete scan but NEVER execute fixture code.
 */

import path from 'path';
import os from 'os';
import fs from 'fs';
import { clean } from '../../src/scanner';

const MALICIOUS_FIXTURES = path.join(__dirname, '..', 'fixtures', 'malicious');
const BENIGN_FIXTURES = path.join(__dirname, '..', 'fixtures', 'benign');

// ─── Scan Fixture Directories ─────────────────────────────────────────────────

describe('Integration — clean() API', () => {
  test('returns a valid ScanSummary structure', async () => {
    const summary = await clean({
      root: MALICIOUS_FIXTURES,
      mode: 'audit',
      minSeverity: 'info',
      noCache: true,
    });

    expect(summary).toBeDefined();
    expect(typeof summary.scannedAt).toBe('string');
    expect(typeof summary.scanDurationMs).toBe('number');
    expect(summary.scanDurationMs).toBeGreaterThan(0);
    expect(Array.isArray(summary.findings)).toBe(true);
    expect(Array.isArray(summary.dependencyFindings)).toBe(true);
    expect(Array.isArray(summary.gitFindings)).toBe(true);
    expect(Array.isArray(summary.secretFindings)).toBe(true);
    expect(Array.isArray(summary.skippedFiles)).toBe(true);
    expect(typeof summary.suppressedCount).toBe('number');
    expect(typeof summary.policyViolation).toBe('boolean');
    expect(Array.isArray(summary.policyViolationReasons)).toBe(true);
  });

  test('detects issues in malicious fixture directory', async () => {
    const summary = await clean({
      root: MALICIOUS_FIXTURES,
      mode: 'audit',
      minSeverity: 'info',
      noCache: true,
    });

    // Malicious fixtures must produce findings
    const totalIssues =
      summary.findings.length +
      summary.secretFindings.length +
      summary.dependencyFindings.length;
    expect(totalIssues).toBeGreaterThan(0);
  });

  test('audit mode sets policyViolation when critical findings exist', async () => {
    const summary = await clean({
      root: MALICIOUS_FIXTURES,
      mode: 'audit',
      minSeverity: 'info',
      noCache: true,
    });

    expect(summary.policyViolation).toBe(true);
    expect(summary.policyViolationReasons.length).toBeGreaterThan(0);
  });

  test('no findings in totally empty directory', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'reposhield-empty-'));
    try {
      const summary = await clean({
        root: tmpDir,
        mode: 'audit',
        noCache: true,
      });
      expect(summary.findings.length).toBe(0);
      expect(summary.secretFindings.length).toBe(0);
      expect(summary.dependencyFindings.length).toBe(0);
      expect(summary.policyViolation).toBe(false);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('AbortSignal causes ScanAbortedError', async () => {
    const controller = new AbortController();
    controller.abort(); // Pre-abort

    await expect(
      clean({
        root: MALICIOUS_FIXTURES,
        mode: 'audit',
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ name: 'ScanAbortedError' });
  });

  test('scan result is deterministic across two identical runs', async () => {
    const opts = {
      root: MALICIOUS_FIXTURES,
      mode: 'audit' as const,
      minSeverity: 'info' as const,
      noCache: true,
    };
    const run1 = await clean(opts);
    const run2 = await clean(opts);

    expect(run1.findings.length).toBe(run2.findings.length);
    expect(run1.secretFindings.length).toBe(run2.secretFindings.length);
    expect(run1.dependencyFindings.length).toBe(run2.dependencyFindings.length);
  });

  test('minSeverity filter excludes low-severity findings', async () => {
    const allSeverities = await clean({
      root: MALICIOUS_FIXTURES,
      mode: 'audit',
      minSeverity: 'info',
      noCache: true,
    });

    const highOnly = await clean({
      root: MALICIOUS_FIXTURES,
      mode: 'audit',
      minSeverity: 'high',
      noCache: true,
    });

    // High-only scan should have equal or fewer findings
    expect(highOnly.findings.length).toBeLessThanOrEqual(allSeverities.findings.length);
    // All remaining findings should be high or critical
    for (const f of highOnly.findings) {
      expect(['high', 'critical']).toContain(f.severity);
    }
  });

  test('benign fixture directory produces no critical findings', async () => {
    const summary = await clean({
      root: BENIGN_FIXTURES,
      mode: 'audit',
      minSeverity: 'info',
      noCache: true,
    });

    const criticalFindings = summary.findings.filter((f) => f.severity === 'critical');
    expect(criticalFindings.length).toBe(0);
  });

  test('scan scans clean directory with clean package.json without issues', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'reposhield-clean-'));
    try {
      const cleanPkg = {
        name: 'clean-app',
        version: '1.0.0',
        scripts: { start: 'node index.js', test: 'jest' },
        dependencies: { express: '^4.18.0' },
      };
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify(cleanPkg, null, 2));
      fs.writeFileSync(
        path.join(tmpDir, 'index.js'),
        '// Simple Node.js app\nconst express = require("express");\nconst app = express();\napp.listen(3000);\n',
      );

      const summary = await clean({
        root: tmpDir,
        mode: 'ci',
        noCache: true,
      });

      expect(summary.policyViolation).toBe(false);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

// ─── Cache Tests ──────────────────────────────────────────────────────────────

describe('Integration — Caching', () => {
  test('second scan with caching enabled hits cache', async () => {
    const opts = {
      root: BENIGN_FIXTURES,
      mode: 'audit' as const,
      minSeverity: 'info' as const,
      noCache: false,
    };

    const run1 = await clean(opts);
    const run2 = await clean(opts);

    // Second run should have cache hits
    expect(run2.cacheHits).toBeGreaterThan(0);
    // Results should be identical
    expect(run2.findings.length).toBe(run1.findings.length);
  });

  test('noCache=true bypasses cache on both runs', async () => {
    const opts = {
      root: BENIGN_FIXTURES,
      mode: 'audit' as const,
      noCache: true,
    };

    const run1 = await clean(opts);
    const run2 = await clean(opts);

    expect(run1.cacheHits).toBe(0);
    expect(run2.cacheHits).toBe(0);
  });
});
