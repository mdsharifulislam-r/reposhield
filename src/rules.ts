/**
 * RepoShield — AST Rule Definitions
 *
 * Each rule is a pure function that receives AST context and returns signals.
 * Rules are composable and independently testable.
 *
 * IMPORTANT: No rule executes any code. Analysis is purely static.
 */

import * as t from '@babel/types';
import { RuleDefinition, Severity, Confidence } from './types.js';

// ─── Signal (raw output from a single rule visit) ─────────────────────────────

export interface AstSignal {
  readonly ruleId: string;
  readonly line: number;
  readonly column: number;
  readonly description: string;
  readonly weight: number; // 1–10, used by correlator
  readonly evidence: string;
}

// ─── Rule Registry ────────────────────────────────────────────────────────────

export const RULE_REGISTRY: Record<string, RuleDefinition> = {
  'RS-AST-001': {
    id: 'RS-AST-001',
    name: 'Dynamic Code Evaluation',
    version: '1',
    severity: 'high' as Severity,
    confidence: 'medium' as Confidence,
    description:
      'Detected use of eval(), Function(), or similar dynamic code execution. ' +
      'A single occurrence is not automatically malicious, but warrants review.',
    remediation:
      'Avoid eval() and Function(). If legitimate, document the use case and add a suppression with a reason.',
    tags: ['dynamic-execution', 'obfuscation'],
    enabled: true,
  },
  'RS-AST-002': {
    id: 'RS-AST-002',
    name: 'Base64 Decode to Execution',
    version: '1',
    severity: 'high' as Severity,
    confidence: 'high' as Confidence,
    description:
      'Detected pattern of Base64 decoding (Buffer.from(..., "base64") or atob()) ' +
      'followed by dynamic execution. This is a common malware obfuscation pattern.',
    remediation:
      'Investigate the encoded payload. If introduced recently, treat as a potential supply-chain attack.',
    tags: ['decode-to-exec', 'obfuscation', 'base64'],
    enabled: true,
  },
  'RS-AST-003': {
    id: 'RS-AST-003',
    name: 'Remote Download and Execute',
    version: '1',
    severity: 'medium' as Severity,
    confidence: 'high' as Confidence,
    description:
      'Detected pattern of fetching content from a remote URL and then executing it ' +
      '(eval, vm.runInNewContext, or child_process). This is the primary delivery mechanism ' +
      'for second-stage malware payloads.',
    remediation:
      'Remove the download-and-execute pattern. Code must not fetch and run remote payloads.',
    tags: ['download-exec', 'remote-payload', 'fetch'],
    enabled: true,
  },
  'RS-AST-004': {
    id: 'RS-AST-004',
    name: 'Environment Secret Access',
    version: '1',
    severity: 'medium' as Severity,
    confidence: 'low' as Confidence,
    description:
      'Detected access to process.env combined with network transmission. ' +
      'This may indicate credential exfiltration.',
    remediation:
      'Review why environment variables are being sent over the network. ' +
      'If intentional, suppress with a documented reason.',
    tags: ['secret-exfiltration', 'env-access', 'network'],
    enabled: true,
  },
  'RS-AST-005': {
    id: 'RS-AST-005',
    name: 'Child Process Execution',
    version: '1',
    severity: 'medium' as Severity,
    confidence: 'low' as Confidence,
    description:
      'Detected child_process execution. Single occurrences in build tools are often legitimate. ' +
      'Elevated risk when combined with dynamic command construction or network I/O.',
    remediation:
      'Ensure spawned commands are statically determined and not influenced by external input.',
    tags: ['child-process', 'execution'],
    enabled: true,
  },
  'RS-AST-006': {
    id: 'RS-AST-006',
    name: 'Dynamic Property Access on Sensitive APIs',
    version: '1',
    severity: 'medium' as Severity,
    confidence: 'medium' as Confidence,
    description:
      'Detected dynamically constructed property access on process, require, or global objects. ' +
      'This is a known obfuscation technique to avoid static detection.',
    remediation: 'Use explicit property access. Dynamic property access on core APIs is suspicious.',
    tags: ['obfuscation', 'dynamic-property'],
    enabled: true,
  },
  'RS-AST-007': {
    id: 'RS-AST-007',
    name: 'Hex or Unicode Encoded Strings',
    version: '1',
    severity: 'medium' as Severity,
    confidence: 'medium' as Confidence,
    description:
      'Detected large hex-encoded or Unicode-escaped string literals. ' +
      'Benign in minified code; suspicious in lifecycle scripts or config files.',
    remediation: 'Investigate the decoded content. Report the encoded string for analysis.',
    tags: ['obfuscation', 'encoding', 'hex', 'unicode'],
    enabled: true,
  },
  'RS-AST-008': {
    id: 'RS-AST-008',
    name: 'Filesystem Write in Unexpected Context',
    version: '1',
    severity: 'medium' as Severity,
    confidence: 'low' as Confidence,
    description:
      'Detected file write operations (fs.writeFile, fs.writeFileSync) in a context that ' +
      'does not appear to be a build tool or generator. Potential persistence mechanism.',
    remediation:
      'Review why this code writes files. Ensure it cannot overwrite security-sensitive paths.',
    tags: ['filesystem', 'persistence'],
    enabled: true,
  },
  'RS-AST-009': {
    id: 'RS-AST-009',
    name: 'VM Module Usage',
    version: '1',
    severity: 'high' as Severity,
    confidence: 'medium' as Confidence,
    description:
      'Detected use of the Node.js vm module (vm.runInNewContext, vm.Script, etc.). ' +
      'The vm module executes code in a separate V8 context.',
    remediation:
      'Review the purpose of vm module usage. Dynamic vm execution of external input is very high risk.',
    tags: ['dynamic-execution', 'vm-module'],
    enabled: true,
  },
  'RS-AST-010': {
    id: 'RS-AST-010',
    name: 'Obfuscated Require / Import',
    version: '1',
    severity: 'high' as Severity,
    confidence: 'medium' as Confidence,
    description:
      'Detected require() or import() called with a dynamically constructed module specifier. ' +
      'This prevents static analysis from resolving the actual module being loaded.',
    remediation: 'Use static string literals for module specifiers. Dynamic imports require documented justification.',
    tags: ['obfuscation', 'dynamic-import'],
    enabled: true,
  },
  'RS-AST-011': {
    id: 'RS-AST-011',
    name: 'Network Request in Lifecycle Context',
    version: '1',
    severity: 'high' as Severity,
    confidence: 'medium' as Confidence,
    description:
      'Detected outbound network requests in a file referenced from a package lifecycle script. ' +
      'Installation scripts should not contact external hosts.',
    remediation:
      'Remove network requests from lifecycle scripts. If needed, document and obtain explicit user consent.',
    tags: ['lifecycle', 'network', 'install-script'],
    enabled: true,
  },
  'RS-CFG-009': {
    id: 'RS-CFG-009',
    name: 'Hidden Node Hook in Package Script',
    version: '1',
    severity: 'critical' as Severity,
    confidence: 'high' as Confidence,
    description:
      'A dev, build, start, or related script runs node against an unusual local file ' +
      '(init, api.js, app.js, or a font carrier) before the real toolchain.',
    remediation:
      'Remove the node <file> prefix from the script. Delete that file if you did not write it, then reinstall dependencies from a clean lockfile.',
    tags: ['supply-chain', 'package-script', 'dropper'],
    enabled: true,
  },
  'RS-DROP-001': {
    id: 'RS-DROP-001',
    name: 'Obfuscated Supply-Chain Loader',
    version: '1',
    severity: 'critical' as Severity,
    confidence: 'high' as Confidence,
    description:
      'File contains a hidden loader: campaign marker, base91 decoder fingerprint, ' +
      'blockchain dead-drop calls, or a payload appended after a long whitespace run.',
    remediation:
      'Treat the file as compromised. Replace it from a known-good copy. Do not execute it. Rotate secrets if it may already have run.',
    tags: ['supply-chain', 'obfuscation', 'loader'],
    enabled: true,
  },
  'RS-DROP-002': {
    id: 'RS-DROP-002',
    name: 'Unusually Large Script',
    version: '1',
    severity: 'high' as Severity,
    confidence: 'medium' as Confidence,
    description:
      'A script is large enough to hide a dropped payload: a very long line, a dense minified body, ' +
      'or a config/init/font file that should be small. Large scripts are suspicious even when the campaign markers change.',
    remediation:
      'Open the file and confirm you wrote it. Replace oversized config, init, and font files from a known-good copy.',
    tags: ['supply-chain', 'size', 'obfuscation'],
    enabled: true,
  },
  'RS-FONT-001': {
    id: 'RS-FONT-001',
    name: 'Fake Font Carrier',
    version: '1',
    severity: 'critical' as Severity,
    confidence: 'high' as Confidence,
    description:
      'A file presented as a font is not a valid font. This campaign drops the same carrier ' +
      'anywhere in the tree, not only under public/.',
    remediation:
      'Delete the file. Search the repo for other font-extension files and for package scripts or editor tasks that execute them.',
    tags: ['supply-chain', 'fake-font', 'carrier'],
    enabled: true,
  },
  'RS-IDE-001': {
    id: 'RS-IDE-001',
    name: 'Editor Task Runs a Dropper',
    version: '1',
    severity: 'critical' as Severity,
    confidence: 'high' as Confidence,
    description:
      'A VS Code task runs node against a dropper or fake font, often automatically when the folder opens.',
    remediation:
      'Delete the task. Set task.allowAutomaticTasks to off until the workspace is clean.',
    tags: ['supply-chain', 'vscode', 'dropper'],
    enabled: true,
  },
};

// ─── Helper: Extract string value from a node ─────────────────────────────────

export function extractStringValue(node: t.Node): string | null {
  if (t.isStringLiteral(node)) return node.value;
  if (t.isTemplateLiteral(node) && node.quasis.length === 1) {
    return node.quasis[0]?.value.raw ?? null;
  }
  return null;
}

// ─── Helper: Check if a MemberExpression accesses a known dangerous API ───────

export function isDangerousExecCall(node: t.Node): boolean {
  if (!t.isCallExpression(node) && !t.isNewExpression(node)) return false;
  const callee = (node as t.CallExpression | t.NewExpression).callee;

  // Direct eval()
  if (t.isIdentifier(callee) && callee.name === 'eval') return true;

  // Function() constructor
  if (t.isIdentifier(callee) && callee.name === 'Function') return true;

  // new Function(...)
  if (t.isNewExpression(node) && t.isIdentifier(node.callee) && node.callee.name === 'Function') return true;

  // setTimeout / setInterval with string first argument
  if (t.isIdentifier(callee) && (callee.name === 'setTimeout' || callee.name === 'setInterval')) {
    const firstArg = node.arguments[0];
    if (firstArg && t.isStringLiteral(firstArg)) return true;
  }

  // vm.runInNewContext, vm.runInThisContext, vm.Script
  if (t.isMemberExpression(callee)) {
    const obj = callee.object;
    const prop = callee.property;
    if (
      t.isIdentifier(obj) &&
      obj.name === 'vm' &&
      t.isIdentifier(prop) &&
      ['runInNewContext', 'runInThisContext', 'runInContext', 'Script'].includes(prop.name)
    ) {
      return true;
    }
  }

  return false;
}

// ─── Helper: Check if a node accesses process.env ────────────────────────────

export function isProcessEnvAccess(node: t.Node): boolean {
  if (!t.isMemberExpression(node)) return false;
  const { object, property } = node;
  return (
    t.isIdentifier(object) &&
    object.name === 'process' &&
    t.isIdentifier(property) &&
    property.name === 'env'
  );
}

// ─── Helper: Detect fetch / http / https / request network calls ──────────────

export function isNetworkCall(node: t.Node): boolean {
  if (!t.isCallExpression(node) && !t.isNewExpression(node)) return false;
  const callee = (node as t.CallExpression | t.NewExpression).callee;

  // fetch(...)
  if (t.isIdentifier(callee) && callee.name === 'fetch') return true;

  // http.get / https.get / http.request / https.request / axios.get etc
  if (t.isMemberExpression(callee)) {
    const obj = callee.object;
    const prop = callee.property;
    if (
      t.isIdentifier(obj) &&
      ['http', 'https', 'axios', 'got', 'superagent', 'needle', 'node-fetch'].includes(obj.name) &&
      t.isIdentifier(prop) &&
      ['get', 'post', 'request', 'put', 'delete', 'patch'].includes(prop.name)
    ) {
      return true;
    }
  }

  // XMLHttpRequest
  if (t.isNewExpression(node) && t.isIdentifier(node.callee) && node.callee.name === 'XMLHttpRequest') {
    return true;
  }

  return false;
}

// ─── Helper: Detect Buffer.from(x, 'base64') ──────────────────────────────────

export function isBase64Decode(node: t.Node): boolean {
  if (!t.isCallExpression(node)) return false;
  const callee = node.callee;
  if (
    t.isMemberExpression(callee) &&
    t.isIdentifier(callee.object) &&
    callee.object.name === 'Buffer' &&
    t.isIdentifier(callee.property) &&
    callee.property.name === 'from'
  ) {
    const secondArg = node.arguments[1];
    if (secondArg) {
      const val = extractStringValue(secondArg);
      if (val && ['base64', 'base64url', 'hex'].includes(val.toLowerCase())) return true;
    }
  }
  // atob()
  if (t.isIdentifier(callee) && callee.name === 'atob') return true;
  return false;
}

// ─── Helper: Detect child_process usage ──────────────────────────────────────

export function isChildProcessCall(node: t.Node): boolean {
  if (!t.isCallExpression(node)) return false;
  const callee = node.callee;

  // require('child_process')
  if (t.isIdentifier(callee) && callee.name === 'require') {
    const firstArg = node.arguments[0];
    if (firstArg && extractStringValue(firstArg) === 'child_process') return true;
  }

  // exec, execSync, spawn, spawnSync, execFile, fork
  if (t.isIdentifier(callee)) {
    const CHILD_PROCESS_FNS = ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'];
    if (CHILD_PROCESS_FNS.includes(callee.name)) return true;
  }

  // cp.exec / child_process.exec etc
  if (t.isMemberExpression(callee)) {
    const prop = callee.property;
    if (t.isIdentifier(prop)) {
      const CHILD_PROCESS_FNS = ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'];
      if (CHILD_PROCESS_FNS.includes(prop.name)) return true;
    }
  }

  return false;
}

// ─── Helper: Detect suspicious hex/unicode strings ───────────────────────────

const HEX_PATTERN = /\\x[0-9a-fA-F]{2}/g;
const UNICODE_PATTERN = /\\u[0-9a-fA-F]{4}/g;

export function isHighlyEncodedString(value: string): boolean {
  if (value.length < 20) return false;
  const hexMatches = (value.match(HEX_PATTERN) || []).length;
  const unicodeMatches = (value.match(UNICODE_PATTERN) || []).length;
  const encodedRatio = ((hexMatches + unicodeMatches) * 4) / value.length;
  return encodedRatio > 0.3; // More than 30% of string is escape sequences
}

// ─── Helper: Detect dynamic property access ──────────────────────────────────

export function isDynamicPropertyOnSensitiveObject(node: t.Node): boolean {
  if (!t.isMemberExpression(node)) return false;
  if (!node.computed) return false; // Only flag computed property access
  const obj = node.object;
  if (!t.isIdentifier(obj)) return false;
  return ['process', 'require', 'global', 'globalThis', 'window', 'self'].includes(obj.name);
}
