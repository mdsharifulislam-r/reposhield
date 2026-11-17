/**
 * RepoShield — Custom Rule Extension Example
 *
 * Shows how to build custom detection rules on top of RepoShield's
 * rule registry and inject them into scans.
 *
 * Custom rules must:
 *   - Be pure functions (no side effects, no I/O)
 *   - Accept only the AST node and return signals
 *   - Never execute untrusted code
 */

// This example assumes RepoShield is built
// In production: const { clean, RULE_REGISTRY } = require('reposhield-scan');
const { RULE_REGISTRY } = require('../dist/cjs/index.js');

// ─── 1. Inspect the built-in rule registry ───────────────────────────────────

console.log('Built-in RepoShield rules:\n');
for (const rule of RULE_REGISTRY) {
  console.log(
    `  ${rule.id.padEnd(14)} [${rule.severity.toUpperCase().padEnd(8)}] ${rule.name}`,
  );
}
console.log('');

// ─── 2. View rule details ─────────────────────────────────────────────────────

const evalRule = RULE_REGISTRY.find((r) => r.id === 'RS-AST-001');
if (evalRule) {
  console.log('Rule detail: RS-AST-001');
  console.log('  Name:        ', evalRule.name);
  console.log('  Severity:    ', evalRule.severity);
  console.log('  Confidence:  ', evalRule.confidence);
  console.log('  Description: ', evalRule.description);
  console.log('  Remediation: ', evalRule.remediation);
  console.log('  Tags:        ', evalRule.tags.join(', '));
  console.log('');
}

// ─── 3. Define a custom policy check ─────────────────────────────────────────

// Example: fail if the repo uses a specific banned dependency
async function checkBannedDependencies(summary) {
  const BANNED = ['left-pad', 'event-stream', 'ua-parser-js'];
  const bannedFound = [];

  for (const dep of summary.dependencyFindings) {
    if (BANNED.includes(dep.packageName)) {
      bannedFound.push(dep.packageName);
    }
  }

  if (bannedFound.length > 0) {
    console.error('❌ Custom policy: Banned dependencies found:', bannedFound.join(', '));
    return false;
  }
  return true;
}

// ─── 4. Custom report formatter ────────────────────────────────────────────────

function formatSARIF(summary) {
  // Minimal SARIF 2.1.0 output for GitHub Advanced Security
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'RepoShield',
            version: '1.0.0',
            rules: RULE_REGISTRY.map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.description },
              helpUri: `https://github.com/reposhield/reposhield/wiki/${r.id}`,
              properties: { tags: [...r.tags] },
            })),
          },
        },
        results: summary.findings
          .filter((f) => !f.suppressed)
          .map((f) => ({
            ruleId: f.ruleId,
            level:
              f.severity === 'critical' || f.severity === 'high'
                ? 'error'
                : f.severity === 'medium'
                  ? 'warning'
                  : 'note',
            message: { text: f.message },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.filePath },
                  region: { startLine: f.line ?? 1 },
                },
              },
            ],
          })),
      },
    ],
  };
}

// Export helpers for integration use
module.exports = { checkBannedDependencies, formatSARIF };

console.log('Custom rules and formatters loaded successfully.');
console.log('Use formatSARIF(summary) to produce GitHub Advanced Security SARIF output.');
