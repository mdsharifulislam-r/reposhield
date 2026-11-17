/**
 * RepoShield — Layer B & C: AST Analyzer + Correlated Risk Scoring
 *
 * Parses JavaScript/TypeScript source files using @babel/parser.
 * Traverses the AST collecting signals.
 * Correlates signals into findings with deterministic risk scores.
 *
 * IMPORTANT: This module NEVER executes any code. It performs static analysis only.
 */

import * as parser from '@babel/parser';
import traverse, { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import {
  Finding,
  Severity,
  Confidence,
  CorrelatedSignal,
} from './types.js';
import {
  AstSignal,
  RULE_REGISTRY,
  extractStringValue,
  isDangerousExecCall,
  isBase64Decode,
  isNetworkCall,
  isChildProcessCall,
  isHighlyEncodedString,
  isDynamicPropertyOnSensitiveObject,
  isProcessEnvAccess,
} from './rules.js';

// ─── File-Level Scan Result ───────────────────────────────────────────────────

export interface FileScanResult {
  readonly filePath: string;
  readonly findings: Finding[];
  readonly parseError?: string;
}

// ─── Context Flags (tracked per-file during traversal) ────────────────────────

interface TraversalContext {
  hasNetworkCall: boolean;
  hasExecCall: boolean;
  hasBase64Decode: boolean;
  hasProcessEnvAccess: boolean;
  hasChildProcess: boolean;
  hasFilesystemWrite: boolean;
  signals: AstSignal[];
  filePath: string;
  isLifecycleContext: boolean; // true if this file is referenced by lifecycle scripts
}

// ─── Parse Options ────────────────────────────────────────────────────────────

const BABEL_PARSE_OPTIONS: parser.ParserOptions = {
  sourceType: 'unambiguous', // Try module first, fall back to script
  strictMode: false,
  allowImportExportEverywhere: true,
  allowReturnOutsideFunction: true,
  allowSuperOutsideMethod: true,
  plugins: [
    'jsx',
    'typescript',
    'decorators-legacy',
    'classProperties',
    'classPrivateProperties',
    'classPrivateMethods',
    'dynamicImport',
    'importMeta',
    'optionalCatchBinding',
    'optionalChaining',
    'nullishCoalescingOperator',
    'logicalAssignment',
    'numericSeparator',
    'bigInt',
    'doExpressions',
    'exportDefaultFrom',
    'exportNamespaceFrom',
    'functionBind',
    'moduleStringNames',
    'recordAndTuple',
  ],
};

// ─── Main Analyzer ────────────────────────────────────────────────────────────

export function analyzeFile(
  filePath: string,
  source: string,
  opts: { isLifecycleContext?: boolean } = {},
): FileScanResult {
  let ast: t.File;
  try {
    ast = parser.parse(source, BABEL_PARSE_OPTIONS);
  } catch (err) {
    return {
      filePath,
      findings: [],
      parseError: `Parse error: ${String(err)}`,
    };
  }

  const ctx: TraversalContext = {
    hasNetworkCall: false,
    hasExecCall: false,
    hasBase64Decode: false,
    hasProcessEnvAccess: false,
    hasChildProcess: false,
    hasFilesystemWrite: false,
    signals: [],
    filePath,
    isLifecycleContext: opts.isLifecycleContext ?? false,
  };

  traverseAst(ast, ctx);

  const findings = correlateSignals(ctx);
  return { filePath, findings };
}

// ─── AST Traversal ────────────────────────────────────────────────────────────

function traverseAst(ast: t.File, ctx: TraversalContext): void {
  // @babel/traverse default export compatibility
  const traverseFn = (traverse as unknown as { default?: typeof traverse }).default ?? traverse;

  traverseFn(ast, {
    // ── RS-AST-001/002/003/005/008/010: Call expression signals ─────────────
    CallExpression: {
      enter(path: NodePath<t.CallExpression>) {
      const node = path.node;

      if (isDangerousExecCall(node)) {
        ctx.hasExecCall = true;
        const loc = node.loc?.start;
        ctx.signals.push({
          ruleId: 'RS-AST-001',
          line: loc?.line ?? 0,
          column: loc?.column ?? 0,
          description: 'Dynamic code execution call detected',
          weight: 5,
          evidence: safeCodeSlice(node),
        });
      }

      // ── RS-AST-002: Buffer.from(..., 'base64') / atob() ───────────────────
      if (isBase64Decode(node)) {
        ctx.hasBase64Decode = true;
        const loc = node.loc?.start;
        ctx.signals.push({
          ruleId: 'RS-AST-002',
          line: loc?.line ?? 0,
          column: loc?.column ?? 0,
          description: 'Base64/hex decode detected',
          weight: 3,
          evidence: safeCodeSlice(node),
        });
      }

      // ── RS-AST-003: Network calls ──────────────────────────────────────────
      if (isNetworkCall(node)) {
        ctx.hasNetworkCall = true;
        const loc = node.loc?.start;
        // Extract the URL if it is a static string
        const firstArg = node.arguments[0];
        const url = firstArg ? extractStringValue(firstArg) : null;
        ctx.signals.push({
          ruleId: 'RS-AST-003',
          line: loc?.line ?? 0,
          column: loc?.column ?? 0,
          description: 'Network request detected',
          weight: 2,
          evidence: url ? `URL: ${url}` : 'Dynamic URL',
        });

        // RS-AST-011: Network in lifecycle context
        if (ctx.isLifecycleContext) {
          ctx.signals.push({
            ruleId: 'RS-AST-011',
            line: loc?.line ?? 0,
            column: loc?.column ?? 0,
            description: 'Network request in lifecycle script context',
            weight: 8,
            evidence: url ? `URL: ${url}` : 'Dynamic URL',
          });
        }
      }

      // ── RS-AST-005: child_process ──────────────────────────────────────────
      if (isChildProcessCall(node)) {
        ctx.hasChildProcess = true;
        const loc = node.loc?.start;
        ctx.signals.push({
          ruleId: 'RS-AST-005',
          line: loc?.line ?? 0,
          column: loc?.column ?? 0,
          description: 'Child process execution detected',
          weight: 3,
          evidence: safeCodeSlice(node),
        });
      }

      // ── RS-AST-008: fs.writeFile / fs.writeFileSync ───────────────────────
      if (t.isMemberExpression(node.callee)) {
        const prop = node.callee.property;
        if (
          t.isIdentifier(prop) &&
          ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync'].includes(prop.name)
        ) {
          ctx.hasFilesystemWrite = true;
          const loc = node.loc?.start;
          ctx.signals.push({
            ruleId: 'RS-AST-008',
            line: loc?.line ?? 0,
            column: loc?.column ?? 0,
            description: 'Filesystem write detected',
            weight: 2,
            evidence: safeCodeSlice(node),
          });
        }
      }

      // ── RS-AST-010: Dynamic require() / import() ────────────────────────────
      if (
        t.isIdentifier(node.callee) &&
        node.callee.name === 'require' &&
        node.arguments.length > 0
      ) {
        const firstArg = node.arguments[0];
        // Dynamic require if the argument is not a string literal
        if (!t.isStringLiteral(firstArg) && firstArg !== undefined) {
          const loc = node.loc?.start;
          ctx.signals.push({
            ruleId: 'RS-AST-010',
            line: loc?.line ?? 0,
            column: loc?.column ?? 0,
            description: 'Dynamic require() with non-literal module specifier',
            weight: 5,
            evidence: safeCodeSlice(node),
          });
        }
      }
      },
    },

    NewExpression: {
      enter(path: NodePath<t.NewExpression>) {
        const node = path.node;
        if (!isDangerousExecCall(node)) return;
        ctx.hasExecCall = true;
        const loc = node.loc?.start;
        ctx.signals.push({
          ruleId: 'RS-AST-001',
          line: loc?.line ?? 0,
          column: loc?.column ?? 0,
          description: 'Dynamic code execution call detected',
          weight: 5,
          evidence: safeCodeSlice(node),
        });
      },
    },

    // ── RS-AST-006: Dynamic property access on sensitive objects ─────────────
    MemberExpression(path: NodePath<t.MemberExpression>) {
      const node = path.node;

      if (isDynamicPropertyOnSensitiveObject(node)) {
        const loc = node.loc?.start;
        ctx.signals.push({
          ruleId: 'RS-AST-006',
          line: loc?.line ?? 0,
          column: loc?.column ?? 0,
          description: 'Dynamic computed property access on sensitive object',
          weight: 4,
          evidence: safeCodeSlice(node),
        });
      }

      // ── RS-AST-004: process.env access ──────────────────────────────────
      if (isProcessEnvAccess(node)) {
        ctx.hasProcessEnvAccess = true;
        // Don't emit a signal alone — only when combined with network
      }
    },

    // ── RS-AST-007: Hex/Unicode encoded strings ───────────────────────────────
    StringLiteral(path: NodePath<t.StringLiteral>) {
      const node = path.node;
      if (node.extra?.raw && typeof node.extra.raw === 'string') {
        const rawStr = node.extra.raw as string;
        if (isHighlyEncodedString(rawStr)) {
          const loc = node.loc?.start;
          ctx.signals.push({
            ruleId: 'RS-AST-007',
            line: loc?.line ?? 0,
            column: loc?.column ?? 0,
            description: 'Highly encoded string literal detected',
            weight: 4,
            evidence: `String length: ${node.value.length}, encoded representation length: ${rawStr.length}`,
          });
        }
      }
    },

    // ── RS-AST-009: vm module usage ───────────────────────────────────────────
    VariableDeclarator(path: NodePath<t.VariableDeclarator>) {
      const init = path.node.init;
      if (!init) return;
      if (
        t.isCallExpression(init) &&
        t.isIdentifier(init.callee) &&
        init.callee.name === 'require' &&
        init.arguments[0] &&
        extractStringValue(init.arguments[0]) === 'vm'
      ) {
        const loc = path.node.loc?.start;
        ctx.signals.push({
          ruleId: 'RS-AST-009',
          line: loc?.line ?? 0,
          column: loc?.column ?? 0,
          description: 'vm module imported',
          weight: 6,
          evidence: 'require("vm")',
        });
      }
    },

    ImportDeclaration(path: NodePath<t.ImportDeclaration>) {
      if (path.node.source.value === 'vm') {
        const loc = path.node.loc?.start;
        ctx.signals.push({
          ruleId: 'RS-AST-009',
          line: loc?.line ?? 0,
          column: loc?.column ?? 0,
          description: 'vm module imported via ESM',
          weight: 6,
          evidence: 'import ... from "vm"',
        });
      }
    },
  } as Parameters<typeof traverseFn>[1]);

  // Emit process.env + network combined signal
  if (ctx.hasProcessEnvAccess && ctx.hasNetworkCall) {
    ctx.signals.push({
      ruleId: 'RS-AST-004',
      line: 0,
      column: 0,
      description: 'process.env access combined with network transmission detected in same file',
      weight: 7,
      evidence: 'process.env AND network call in same file',
    });
  }
}

// ─── Signal Correlator ────────────────────────────────────────────────────────

/**
 * Groups signals by rule and synthesizes correlated findings.
 * Risk scores are deterministic and based on signal weights, not probabilities.
 */
function correlateSignals(ctx: TraversalContext): Finding[] {
  const findings: Finding[] = [];

  // Group signals by ruleId
  const byRule = new Map<string, AstSignal[]>();
  for (const sig of ctx.signals) {
    const existing = byRule.get(sig.ruleId) ?? [];
    existing.push(sig);
    byRule.set(sig.ruleId, existing);
  }

  // ── Correlated finding: Base64-decode → exec chain ────────────────────────
  if (ctx.hasBase64Decode && ctx.hasExecCall) {
    const b64Sigs = byRule.get('RS-AST-002') ?? [];
    const execSigs = byRule.get('RS-AST-001') ?? [];
    const allSigs = [...b64Sigs, ...execSigs];
    const firstSig = allSigs[0];
    if (firstSig) {
      const rule = RULE_REGISTRY['RS-AST-002']!;
      findings.push({
        ruleId: 'RS-AST-002',
        ruleName: rule.name,
        ruleVersion: rule.version,
        severity: 'critical',
        confidence: 'high',
        filePath: ctx.filePath,
        line: firstSig.line,
        column: firstSig.column,
        message: 'Base64/hex decode immediately followed by dynamic code execution — high-confidence obfuscated payload pattern.',
        evidence: allSigs.map((s) => s.evidence),
        remediation: rule.remediation,
        riskScore: computeRiskScore(['critical', 'high'], allSigs),
        correlatedSignals: allSigs.map((s) => ({
          signalId: s.ruleId,
          description: s.description,
          weight: s.weight,
        })),
      });
      byRule.delete('RS-AST-002');
      byRule.delete('RS-AST-001');
    }
  }

  // ── Correlated finding: Network + exec ────────────────────────────────────
  if (ctx.hasNetworkCall && ctx.hasExecCall) {
    const netSigs = byRule.get('RS-AST-003') ?? [];
    const execSigs = byRule.get('RS-AST-001') ?? [];
    if (netSigs.length > 0 || execSigs.length > 0) {
      const allSigs = [...netSigs, ...execSigs];
      const firstSig = allSigs[0];
      if (firstSig) {
        const rule = RULE_REGISTRY['RS-AST-003']!;
        findings.push({
          ruleId: 'RS-AST-003',
          ruleName: rule.name,
          ruleVersion: rule.version,
          severity: 'critical',
          confidence: 'high',
          filePath: ctx.filePath,
          line: firstSig.line,
          column: firstSig.column,
          message: 'Remote network download combined with dynamic code execution — download-and-execute malware pattern.',
          evidence: allSigs.map((s) => s.evidence),
          remediation: rule.remediation,
          riskScore: computeRiskScore(['critical', 'high'], allSigs),
          correlatedSignals: allSigs.map((s) => ({
            signalId: s.ruleId,
            description: s.description,
            weight: s.weight,
          })),
        });
        byRule.delete('RS-AST-003');
        byRule.delete('RS-AST-001');
      }
    }
  }

  // ── Emit remaining signals as individual findings ─────────────────────────
  for (const [ruleId, signals] of byRule.entries()) {
    const rule = RULE_REGISTRY[ruleId];
    if (!rule || !rule.enabled) continue;
    const firstSig = signals[0];
    if (!firstSig) continue;

    findings.push({
      ruleId,
      ruleName: rule.name,
      ruleVersion: rule.version,
      severity: rule.severity,
      confidence: rule.confidence,
      filePath: ctx.filePath,
      line: firstSig.line || undefined,
      column: firstSig.column || undefined,
      message: `${rule.description} (${signals.length} occurrence${signals.length > 1 ? 's' : ''})`,
      evidence: signals.map((s) => s.evidence).slice(0, 5),
      remediation: rule.remediation,
      riskScore: computeRiskScore([rule.severity, rule.confidence as unknown as Severity], signals),
      correlatedSignals: signals.map((s) => ({
        signalId: s.ruleId,
        description: s.description,
        weight: s.weight,
      })),
    });
  }

  return findings;
}

// ─── Risk Score Calculator ────────────────────────────────────────────────────

/**
 * Deterministic risk score 0–100.
 * Severity and confidence set the base; signal weight sum provides the multiplier.
 * This is NOT a calibrated probability — it is an ordinal ranking.
 */
function computeRiskScore(factors: Severity[], signals: AstSignal[]): number {
  const severityBase: Record<Severity, number> = {
    critical: 70,
    high: 50,
    medium: 30,
    low: 10,
    info: 5,
  };

  const base = Math.max(...factors.map((f) => severityBase[f] ?? 10));
  const signalBonus = Math.min(
    30,
    signals.reduce((acc, s) => acc + s.weight, 0),
  );

  return Math.min(100, base + signalBonus);
}

// ─── Safe Code Slice ──────────────────────────────────────────────────────────

/** Returns a truncated, safe string representation of a node for evidence. Never executes it. */
function safeCodeSlice(node: t.Node): string {
  // Use source location info only — do not re-generate code
  const loc = node.loc;
  if (!loc) return `[node:${node.type}]`;
  return `[${node.type} at line ${loc.start.line}:${loc.start.column}]`;
}
