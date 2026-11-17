/**
 * RepoShield — Layer D: Configuration File Analyzer
 *
 * Inspects high-risk configuration files for suspicious patterns:
 * - package.json lifecycle scripts
 * - Vite, Next.js, PostCSS, Tailwind, Webpack, ESLint configs
 * - GitHub Actions workflows
 * - .npmrc, .gitconfig
 * - Shell scripts
 *
 * NEVER executes the configuration files.
 */

import path from 'path';
import yaml from 'js-yaml';
import { Finding, DependencyFinding, Severity, Confidence } from './types.js';
import { safeReadFile } from './discovery.js';
import { findSuspiciousNodeHooks, extractNodeScriptTargets, findOversizedPackageScripts } from './dropper-detector.js';
import { RULE_REGISTRY } from './rules.js';

// ─── Lifecycle Script Risk Patterns ──────────────────────────────────────────

const DANGEROUS_SCRIPT_PATTERNS: Array<{
  pattern: RegExp;
  ruleId: string;
  description: string;
  severity: Severity;
}> = [
  {
    pattern: /curl\s+.*\|\s*(ba)?sh/i,
    ruleId: 'RS-CFG-001',
    description: 'curl-pipe-to-shell: remote code execution via curl | sh',
    severity: 'critical',
  },
  {
    pattern: /wget\s+.*-O\s*-\s*\|\s*(ba)?sh/i,
    ruleId: 'RS-CFG-002',
    description: 'wget-pipe-to-shell: remote code execution via wget | sh',
    severity: 'critical',
  },
  {
    pattern: /eval\s*\(/i,
    ruleId: 'RS-CFG-003',
    description: 'eval() in lifecycle script',
    severity: 'high',
  },
  {
    pattern: /base64\s+-d/i,
    ruleId: 'RS-CFG-004',
    description: 'Base64 decode in lifecycle script',
    severity: 'high',
  },
  {
    pattern: /python[23]?\s+-c/i,
    ruleId: 'RS-CFG-005',
    description: 'Inline Python execution in lifecycle script',
    severity: 'high',
  },
  {
    pattern: /node\s+-e\s+/i,
    ruleId: 'RS-CFG-006',
    description: 'node -e inline execution in lifecycle script',
    severity: 'high',
  },
  {
    pattern: /powershell\s+.*Invoke-Expression/i,
    ruleId: 'RS-CFG-007',
    description: 'PowerShell Invoke-Expression in lifecycle script',
    severity: 'critical',
  },
  {
    pattern: /iwr\s+.*\|\s*iex/i,
    ruleId: 'RS-CFG-008',
    description: 'PowerShell download-and-execute pattern',
    severity: 'critical',
  },
];

// ─── GitHub Actions Risk Patterns ─────────────────────────────────────────────

const DANGEROUS_WORKFLOW_PATTERNS: Array<{
  pattern: RegExp;
  ruleId: string;
  description: string;
  severity: Severity;
}> = [
  {
    pattern: /\$\{\{.*github\.event\..*\}\}/,
    ruleId: 'RS-WF-001',
    description: 'Unsanitized user-controlled input injected into shell command (script injection risk)',
    severity: 'critical',
  },
  {
    pattern: /secrets\.\w+\s*>>/,
    ruleId: 'RS-WF-002',
    description: 'Secret value redirected to output file — potential secret exposure',
    severity: 'high',
  },
  {
    pattern: /pull_request_target/,
    ruleId: 'RS-WF-003',
    description:
      'Workflow uses pull_request_target which runs in base repo context with full access to secrets. ' +
      'Extremely dangerous if combined with checkout of PR head.',
    severity: 'high',
  },
  {
    pattern: /permissions:\s*write-all/,
    ruleId: 'RS-WF-004',
    description: 'Workflow grants write-all permissions — violates least-privilege principle',
    severity: 'medium',
  },
  {
    pattern: /ACTIONS_ALLOW_UNSECURE_COMMANDS:\s*true/i,
    ruleId: 'RS-WF-005',
    description: 'Workflow enables deprecated unsafe commands',
    severity: 'high',
  },
  {
    pattern: /actions\/checkout@v[12][^3-9]/,
    ruleId: 'RS-WF-006',
    description: 'Outdated actions/checkout version (v1/v2) — use v4',
    severity: 'medium',
  },
  {
    pattern: /uses:\s+[^@]+@(?!([0-9a-f]{40}|v\d))/,
    ruleId: 'RS-WF-007',
    description: 'Action pinned to a mutable branch reference instead of a commit SHA or version tag',
    severity: 'medium',
  },
  {
    pattern: /curl\s+.*\|\s*(ba)?sh/i,
    ruleId: 'RS-WF-008',
    description: 'curl-pipe-to-shell in workflow step',
    severity: 'critical',
  },
];

// ─── NPM RC Risk Patterns ─────────────────────────────────────────────────────

const NPMRC_RISK_PATTERNS: Array<{
  pattern: RegExp;
  ruleId: string;
  description: string;
  severity: Severity;
}> = [
  {
    pattern: /registry\s*=\s*(?!https:\/\/registry\.npmjs\.org)/i,
    ruleId: 'RS-NPM-001',
    description: 'Custom npm registry configured — verify it is trusted',
    severity: 'medium',
  },
  {
    pattern: /:_authToken\s*=\s*(?!\$\{)(?!%[A-Za-z0-9_]+%)\S+/i,
    ruleId: 'RS-NPM-002',
    description: 'Hardcoded npm auth token in .npmrc',
    severity: 'critical',
  },
  {
    pattern: /always-auth\s*=\s*true/i,
    ruleId: 'RS-NPM-003',
    description: '.npmrc sets always-auth=true — credentials sent to all registries',
    severity: 'medium',
  },
];

// ─── Package.json Analyzer ────────────────────────────────────────────────────

export function analyzePackageJson(
  filePath: string,
  content: string,
): { findings: Finding[]; lifecycleFiles: string[] } {
  const findings: Finding[] = [];
  const lifecycleFiles: string[] = [];

  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return { findings, lifecycleFiles };
  }

  const scripts = pkg['scripts'] as Record<string, string> | undefined;
  if (scripts && typeof scripts === 'object') {
    const lifecycleKeys = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack'];
    const scriptDir = path.dirname(filePath);

    for (const key of lifecycleKeys) {
      const scriptValue = scripts[key];
      if (!scriptValue || typeof scriptValue !== 'string') continue;

      for (const { pattern, ruleId, description, severity } of DANGEROUS_SCRIPT_PATTERNS) {
        if (pattern.test(scriptValue)) {
          findings.push({
            ruleId,
            ruleName: 'Malicious Lifecycle Script',
            ruleVersion: '1',
            severity,
            confidence: 'high',
            filePath,
            message: `Lifecycle script "${key}" contains suspicious pattern: ${description}`,
            evidence: [redactSecret(`"${key}": "${scriptValue}"`)],
            remediation:
              'Remove or audit the lifecycle script. Consider installing with --ignore-scripts to prevent execution during npm install.',
            riskScore: severityToScore(severity),
          });
        }
      }

      for (const target of extractNodeScriptTargets(scriptValue)) {
        const resolved = resolveNodeTarget(scriptDir, target);
        if (resolved) lifecycleFiles.push(resolved);
      }
    }

    const sizeRule = RULE_REGISTRY['RS-DROP-002']!;
    for (const hit of findOversizedPackageScripts(scripts)) {
      findings.push({
        ruleId: sizeRule.id,
        ruleName: sizeRule.name,
        ruleVersion: sizeRule.version,
        severity: 'high',
        confidence: 'medium',
        filePath,
        message: `Script "${hit.scriptName}" is unusually large (${hit.length} characters). Treat it as suspicious.`,
        evidence: [`${hit.scriptName}: ${hit.length} characters`],
        remediation: sizeRule.remediation,
        riskScore: 62,
      });
    }

    const hookRule = RULE_REGISTRY['RS-CFG-009']!;
    for (const hit of findSuspiciousNodeHooks(scripts)) {
      findings.push({
        ruleId: hookRule.id,
        ruleName: hookRule.name,
        ruleVersion: hookRule.version,
        severity: 'critical',
        confidence: 'high',
        filePath,
        message: `Script "${hit.scriptName}" runs node on unusual file "${hit.target}" before the real command.`,
        evidence: [redactSecret(`"${hit.scriptName}": "${hit.command}"`).slice(0, 240)],
        remediation: hookRule.remediation,
        riskScore: 95,
      });
      const resolved = resolveNodeTarget(scriptDir, hit.target);
      if (resolved) lifecycleFiles.push(resolved);
    }
  }

  // Check for suspicious "main" or "bin" pointing to unexpected locations
  const mainField = pkg['main'];
  if (typeof mainField === 'string' && mainField.includes('..')) {
    findings.push({
      ruleId: 'RS-PKG-001',
      ruleName: 'Suspicious Main Field Path Traversal',
      ruleVersion: '1',
      severity: 'high',
      confidence: 'medium',
      filePath,
      message: `package.json "main" field contains path traversal: "${mainField}"`,
      evidence: [`"main": "${mainField}"`],
      remediation: 'The "main" field should point within the package directory.',
      riskScore: 60,
    });
  }

  return { findings, lifecycleFiles };
}

// ─── GitHub Actions Workflow Analyzer ────────────────────────────────────────

export function analyzeWorkflow(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];

  const lines = content.split('\n');

  for (const { pattern, ruleId, description, severity } of DANGEROUS_WORKFLOW_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (pattern.test(line)) {
        findings.push({
          ruleId,
          ruleName: 'Suspicious GitHub Actions Workflow',
          ruleVersion: '1',
          severity,
          confidence: 'medium',
          filePath,
          line: i + 1,
          message: description,
          evidence: [redactSecret(line.trim())],
          remediation: getWorkflowRemediation(ruleId),
          riskScore: severityToScore(severity),
        });
      }
    }
  }

  // Parse YAML to check for env vars that expose secrets
  try {
    const parsed = yaml.load(content) as Record<string, unknown>;
    if (parsed && typeof parsed === 'object') {
      findSecretExposureInWorkflow(parsed, filePath, findings);
    }
  } catch {
    // YAML parse failure — already caught patterns above
  }

  return findings;
}

function findSecretExposureInWorkflow(
  obj: unknown,
  filePath: string,
  findings: Finding[],
  depth = 0,
): void {
  if (depth > 10 || typeof obj !== 'object' || obj === null) return;
  if (Array.isArray(obj)) {
    for (const item of obj) findSecretExposureInWorkflow(item, filePath, findings, depth + 1);
    return;
  }
  const record = obj as Record<string, unknown>;
  for (const [key, value] of Object.entries(record)) {
    // Check for environment variables that reference secrets
    if (key === 'env' && typeof value === 'object' && value !== null) {
      const envObj = value as Record<string, unknown>;
      for (const [envKey, envVal] of Object.entries(envObj)) {
        if (
          typeof envVal === 'string' &&
          envVal.includes('${{ secrets.') &&
          isHighPrivilegeEnvName(envKey)
        ) {
          findings.push({
            ruleId: 'RS-WF-009',
            ruleName: 'Secret Exposed in Environment Variable',
            ruleVersion: '1',
            severity: 'medium',
            confidence: 'medium',
            filePath,
            message: `Workflow exposes secret in env variable "${envKey}" — ensure it is required and scoped narrowly`,
            evidence: [`${envKey}: $\{{ secrets.*** }}`],
            remediation:
              'Scope secrets to only the steps that need them. Avoid exposing write tokens to PR workflows.',
            riskScore: 45,
          });
        }
      }
    }
    findSecretExposureInWorkflow(value, filePath, findings, depth + 1);
  }
}

function isHighPrivilegeEnvName(name: string): boolean {
  const HIGH_PRIV = ['GITHUB_TOKEN', 'NPM_TOKEN', 'AWS_ACCESS_KEY', 'GCP_SA_KEY', 'PRIVATE_KEY'];
  return HIGH_PRIV.some((h) => name.toUpperCase().includes(h));
}

// ─── .npmrc Analyzer ──────────────────────────────────────────────────────────

export function analyzeNpmrc(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (const { pattern, ruleId, description, severity } of NPMRC_RISK_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (line.startsWith('#')) continue; // Comment
      if (pattern.test(line)) {
        findings.push({
          ruleId,
          ruleName: 'Suspicious .npmrc Configuration',
          ruleVersion: '1',
          severity,
          confidence: 'medium',
          filePath,
          line: i + 1,
          message: description,
          evidence: [redactSecret(line.trim())],
          remediation: getNpmrcRemediation(ruleId),
          riskScore: severityToScore(severity),
        });
      }
    }
  }

  return findings;
}

// ─── Vite/Webpack/Next Config Analyzer ───────────────────────────────────────

export function analyzeBuildConfig(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const basename = path.basename(filePath);

  // Check for server.proxy or rewrites that redirect to unexpected hosts
  if (/server\s*[:=]\s*\{[^}]*proxy/s.test(content)) {
    if (/['"](https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0))/i.test(content)) {
      findings.push({
        ruleId: 'RS-BUILD-001',
        ruleName: 'Unexpected Proxy Target in Build Config',
        ruleVersion: '1',
        severity: 'medium',
        confidence: 'low',
        filePath,
        message: `${basename} configures a proxy to an external host — verify this is intentional`,
        evidence: ['Proxy configuration detected'],
        remediation: 'Ensure proxy targets are to trusted internal endpoints only.',
        riskScore: 35,
      });
    }
  }

  // Check for plugins that execute arbitrary code
  const SUSPICIOUS_PLUGIN_PATTERNS = [
    /require\s*\(\s*['"][^'"]*exec[^'"]*['"]\s*\)/,
    /require\s*\(\s*['"][^'"]*shell[^'"]*['"]\s*\)/,
  ];

  for (const pat of SUSPICIOUS_PLUGIN_PATTERNS) {
    if (pat.test(content)) {
      findings.push({
        ruleId: 'RS-BUILD-002',
        ruleName: 'Suspicious Plugin in Build Config',
        ruleVersion: '1',
        severity: 'high',
        confidence: 'medium',
        filePath,
        message: `${basename} requires a plugin with suspicious name (exec/shell)`,
        evidence: ['Suspicious plugin reference detected'],
        remediation: 'Review all plugins loaded in build configuration.',
        riskScore: 55,
      });
    }
  }

  return findings;
}

// ─── Shell Script Analyzer ────────────────────────────────────────────────────

export function analyzeShellScript(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  const SHELL_PATTERNS: Array<{ pattern: RegExp; ruleId: string; description: string; severity: Severity }> = [
    {
      pattern: /curl\s+.*\|\s*(ba)?sh/i,
      ruleId: 'RS-SH-001',
      description: 'curl-pipe-to-shell',
      severity: 'critical',
    },
    {
      pattern: /wget\s+.*-O\s*-\s*\|\s*(ba)?sh/i,
      ruleId: 'RS-SH-002',
      description: 'wget-pipe-to-shell',
      severity: 'critical',
    },
    {
      pattern: /base64\s+--decode|\bbase64\s+-d\b/i,
      ruleId: 'RS-SH-003',
      description: 'Base64 decode in shell script',
      severity: 'medium',
    },
    {
      pattern: /eval\s+["'`]/,
      ruleId: 'RS-SH-004',
      description: 'eval with string in shell',
      severity: 'high',
    },
    {
      pattern: /\/proc\/self\/mem|\/dev\/mem/,
      ruleId: 'RS-SH-005',
      description: 'Access to process memory device',
      severity: 'critical',
    },
  ];

  for (const { pattern, ruleId, description, severity } of SHELL_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (line.trim().startsWith('#')) continue;
      if (pattern.test(line)) {
        findings.push({
          ruleId,
          ruleName: 'Suspicious Shell Script Pattern',
          ruleVersion: '1',
          severity,
          confidence: 'medium',
          filePath,
          line: i + 1,
          message: description,
          evidence: [redactSecret(line.trim()).substring(0, 200)],
          remediation: 'Review and remove dangerous shell patterns.',
          riskScore: severityToScore(severity),
        });
      }
    }
  }

  return findings;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function resolveNodeTarget(scriptDir: string, target: string): string | null {
  const normalized = target.replace(/\\/g, '/');
  if (!normalized || normalized.startsWith('-') || normalized.includes('node_modules/')) return null;
  if (/^[a-z]+:/i.test(normalized)) return null;
  return path.resolve(scriptDir, normalized);
}

function severityToScore(severity: Severity): number {
  const map: Record<Severity, number> = { critical: 85, high: 65, medium: 40, low: 15, info: 5 };
  return map[severity];
}

/** Redact common secret patterns. Never logs full values. */
export function redactSecret(text: string): string {
  return text
    .replace(/(_authToken\s*=\s*)[^\s]+/gi, '$1[REDACTED]')
    .replace(/(token|password|secret|key|auth)\s*[:=]\s*["']?[^\s"']+["']?/gi, '$1=[REDACTED]')
    .replace(/Bearer\s+[A-Za-z0-9+/=._-]{10,}/gi, 'Bearer [REDACTED]')
    .replace(/[A-Za-z0-9+/]{40,}={0,2}/g, '[POSSIBLE-SECRET-REDACTED]');
}

function getWorkflowRemediation(ruleId: string): string {
  const map: Record<string, string> = {
    'RS-WF-001': 'Use github.event.inputs or intermediate environment variables sanitized before shell injection. Never interpolate ${{ github.event.* }} directly into run commands.',
    'RS-WF-002': 'Do not redirect secret values to files or outputs. Use masked output or skip the step.',
    'RS-WF-003': 'Avoid pull_request_target unless you fully control the PR code. Use pull_request instead.',
    'RS-WF-004': 'Set minimal permissions per job. Use permissions: { contents: read } or more restrictive.',
    'RS-WF-005': 'Remove ACTIONS_ALLOW_UNSECURE_COMMANDS. It is deprecated and dangerous.',
    'RS-WF-006': 'Update to actions/checkout@v4.',
    'RS-WF-007': 'Pin actions to full commit SHAs for immutability.',
    'RS-WF-008': 'Remove curl-pipe-to-shell. Download artifacts separately and verify checksums.',
  };
  return map[ruleId] ?? 'Review the workflow step for security issues.';
}

function getNpmrcRemediation(ruleId: string): string {
  const map: Record<string, string> = {
    'RS-NPM-001': 'Verify the custom registry is trusted. Prefer the official npm registry.',
    'RS-NPM-002': 'Remove hardcoded auth tokens from .npmrc. Use environment variables: //registry.npmjs.org/:_authToken=${NPM_TOKEN}',
    'RS-NPM-003': 'Restrict always-auth to specific registries. Sending credentials to all registries is a risk.',
  };
  return map[ruleId] ?? 'Review your .npmrc configuration.';
}

export { safeReadFile };
