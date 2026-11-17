/**
 * RepoShield — Supply-chain dropper detector
 *
 * Static checks for the current npm/Next loader family:
 * - package scripts that prepend `node <unusual file>`
 * - obfuscated loaders appended after legitimate code
 * - font-extension and Font Awesome decoy files that are not real fonts
 * - editor tasks that execute those carriers
 *
 * Never executes file contents. Font location is irrelevant: a bad font
 * header is critical in any directory.
 */

import path from 'path';
import { Finding } from './types.js';
import { RULE_REGISTRY } from './rules.js';

const FONT_EXTENSIONS = new Set(['.woff', '.woff2', '.ttf', '.otf', '.eot', '.fon']);

/** Real icon/text assets that share Font Awesome-like names. */
const BENIGN_ASSET_EXTENSIONS = new Set([
  '.svg', '.css', '.scss', '.sass', '.less', '.map', '.json', '.md', '.txt', '.html', '.vue',
]);

const FA_DECOY_NAME = /fa-(?:brands?|solid|regular)(?:[-_.]|$)/i;

const HIGH_CONFIDENCE_TARGETS = new Set([
  'init',
  'init.js',
  'init.mjs',
  'init.cjs',
  'init.ts',
  'preload.js',
  'preload.mjs',
  'preload.cjs',
  'setup.js',
  'setup.mjs',
  'boot.js',
  'loader.js',
  'payload.js',
]);

const MEDIUM_CONFIDENCE_TARGETS = new Set([
  'api',
  'api.js',
  'api.mjs',
  'api.cjs',
  'app',
  'app.js',
  'app.mjs',
  'app.cjs',
]);

const DEV_BUILD_SCRIPTS = /^(pre|post)?(dev|build|preview|lint)$/;

const FLAGS_WITH_VALUE = new Set([
  '-r',
  '--require',
  '--import',
  '--loader',
  '--experimental-loader',
  '--watch-path',
  '-C',
  '--conditions',
  '--cpu-prof-dir',
  '--heap-prof-dir',
  '--diagnostic-dir',
  '--redirect-warnings',
  '--test-reporter',
  '--test-reporter-destination',
]);

const CAMPAIGN_ASSIGN =
  /global\s*(?:\.\s*i|\[\s*['"](?:i|\\u0069|!)['"]\s*\])\s*=\s*(['"])([^'"]{1,32})\1/;

const BASE91_FINGERPRINT = /&\s*8191\s*\)\s*>\s*88/;

const STAGE_PATH = new RegExp(['/', '0x', '/', '(?:cls|ls)\\b'].join(''));

const PAYLOAD_HEADER = new RegExp(['x-payload-', 'b64'].join(''), 'i');

const ETH_RPC = /eth_(?:getBlockByNumber|getTransactionCount|blockNumber)\b/;

const EVAL_CALL = /\beval\s*\(|\bnew\s+Function\s*\(/;

const HIDDEN_REPL = /\[\s*['"]-i['"]\s*\]/;

const HIDDEN_PAD = /[ \t]{80,}/;

export interface NodeHookHit {
  readonly scriptName: string;
  readonly command: string;
  readonly target: string;
}

export function findSuspiciousNodeHooks(
  scripts: Record<string, unknown> | undefined,
): NodeHookHit[] {
  if (!scripts) return [];
  const hits: NodeHookHit[] = [];

  for (const [scriptName, value] of Object.entries(scripts)) {
    if (typeof value !== 'string' || value.length === 0) continue;
    for (const target of extractNodeScriptTargets(value)) {
      if (isSuspiciousNodeTarget(scriptName, value, target)) {
        hits.push({ scriptName, command: value, target });
      }
    }
  }

  return hits;
}

export function extractNodeScriptTargets(command: string): string[] {
  const targets: string[] = [];
  const segments = command.split(/&&|\|\||;/);

  for (const segment of segments) {
    const parts = segment.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) continue;
    const bin = (parts[0] ?? '').replace(/^.*[\\/]/, '').toLowerCase();
    if (bin !== 'node' && bin !== 'node.exe' && bin !== 'nodejs') continue;

    let index = 1;
    while (index < parts.length) {
      const token = stripQuotes(parts[index] ?? '');
      if (token === '-e' || token === '--eval' || token === '-p' || token === '--print') break;
      if (token.startsWith('-')) {
        if (!token.includes('=') && FLAGS_WITH_VALUE.has(token)) {
          index += 2;
          continue;
        }
        index += 1;
        continue;
      }
      if (token.length > 0) targets.push(token);
      break;
    }
  }

  return targets;
}

function isSuspiciousNodeTarget(scriptName: string, command: string, target: string): boolean {
  const base = basename(target);
  if (FONT_EXTENSIONS.has(path.posix.extname(base).toLowerCase())) return true;
  if (FA_DECOY_NAME.test(base)) return true;
  if (HIGH_CONFIDENCE_TARGETS.has(base)) return true;

  if (MEDIUM_CONFIDENCE_TARGETS.has(base)) {
    const chained = /&&|;/.test(command);
    const devBuild = DEV_BUILD_SCRIPTS.test(scriptName);
    const withFramework = /\b(next|vite|nuxt|ng|react-scripts|remix|astro|webpack|turbo)\b/.test(command);
    return chained || devBuild || withFramework;
  }

  const ext = path.posix.extname(base);
  if (!ext && isRepoRootTarget(target, base) && DEV_BUILD_SCRIPTS.test(scriptName)) return true;

  return false;
}

export function detectObfuscatedLoader(filePath: string, content: string): Finding[] {
  const reasons: string[] = [];

  const campaign = CAMPAIGN_ASSIGN.exec(content);
  if (campaign && /[-*@&_!]/.test(campaign[2] ?? '')) {
    reasons.push('campaign marker on global.i');
  }
  if (BASE91_FINGERPRINT.test(content)) {
    reasons.push('base91 decoder fingerprint');
  }
  if (STAGE_PATH.test(content)) {
    reasons.push('hidden stage path');
  }
  if (PAYLOAD_HEADER.test(content)) {
    reasons.push('encoded payload staging header');
  }

  const eth = ETH_RPC.test(content);
  const exec = EVAL_CALL.test(content);
  const repl = HIDDEN_REPL.test(content) && /windowsHide\s*:/.test(content) && /detached\s*:/.test(content);
  if (repl) reasons.push('hidden detached node REPL spawn');
  if (eth && (exec || repl)) reasons.push('blockchain dead-drop combined with code execution');

  const padded = HIDDEN_PAD.test(content);
  if (padded && (exec || eth || (campaign != null && /[-*@&_!]/.test(campaign[2] ?? '')))) {
    reasons.push('payload hidden after a long whitespace run');
  }

  const createRequireCount = content.split('createRequire').length - 1;
  if (createRequireCount >= 2 && (padded || exec || eth)) {
    reasons.push('duplicated createRequire followed by a hidden payload');
  }

  if (reasons.length === 0) return [];

  const rule = RULE_REGISTRY['RS-DROP-001']!;
  const line = lineOfFirst(content, [
    CAMPAIGN_ASSIGN,
    BASE91_FINGERPRINT,
    STAGE_PATH,
    PAYLOAD_HEADER,
    ETH_RPC,
    HIDDEN_PAD,
  ]);

  return [
    {
      ruleId: rule.id,
      ruleName: rule.name,
      ruleVersion: rule.version,
      severity: 'critical',
      confidence: 'high',
      filePath,
      line,
      message: `Obfuscated supply-chain loader (${reasons.join('; ')}).`,
      evidence: reasons,
      remediation: rule.remediation,
      riskScore: 95,
    },
  ];
}

const LARGE_LINE_CHARS = 2500;
const LARGE_SCRIPT_BYTES = 10 * 1024;
const DENSE_AVERAGE_CHARS = 280;
const LARGE_PACKAGE_SCRIPT_CHARS = 500;

const SCRIPT_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.jsx',
  '.ts', '.tsx', '.mts', '.cts',
  '.sh', '.bash', '.ps1', '.bat', '.cmd',
]);

export function detectLargeScript(filePath: string, content: string): Finding[] {
  if (!isScriptLikePath(filePath)) return [];

  const measured = measureScript(content);
  const longLine = measured.longest >= LARGE_LINE_CHARS;
  const dense = measured.bytes >= LARGE_SCRIPT_BYTES && measured.average >= DENSE_AVERAGE_CHARS;
  const sensitive = measured.bytes >= LARGE_SCRIPT_BYTES && isSensitiveScriptPath(filePath);
  if (!longLine && !dense && !sensitive) return [];

  const reasons: string[] = [];
  if (longLine) reasons.push(`line of ${measured.longest} characters`);
  if (dense) reasons.push(`dense ${measured.bytes}-byte script`);
  if (sensitive) reasons.push(`${measured.bytes}-byte script in a file that should stay small`);

  const rule = RULE_REGISTRY['RS-DROP-002']!;
  return [
    {
      ruleId: rule.id,
      ruleName: rule.name,
      ruleVersion: rule.version,
      severity: 'high',
      confidence: 'medium',
      filePath,
      line: longLine ? measured.longestLine : undefined,
      message: `Unusually large script (${reasons.join('; ')}). Treat it as suspicious.`,
      evidence: reasons,
      remediation: rule.remediation,
      riskScore: 62,
    },
  ];
}

export function findOversizedPackageScripts(
  scripts: Record<string, unknown> | undefined,
): Array<{ scriptName: string; length: number }> {
  if (!scripts) return [];
  const hits: Array<{ scriptName: string; length: number }> = [];
  for (const [scriptName, value] of Object.entries(scripts)) {
    if (typeof value === 'string' && value.length >= LARGE_PACKAGE_SCRIPT_CHARS) {
      hits.push({ scriptName, length: value.length });
    }
  }
  return hits;
}

export function inspectFontCarrier(filePath: string, bytes: Buffer): Finding | null {
  if (bytes.length === 0) return null;

  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath);
  const fontExt = FONT_EXTENSIONS.has(ext);
  const decoy = FA_DECOY_NAME.test(base);
  if (!fontExt && !decoy) return null;
  if (fontExt && hasValidFontMagic(ext, bytes)) return null;
  if (!fontExt && BENIGN_ASSET_EXTENSIONS.has(ext)) return null;
  if (!fontExt && !looksLikeScript(bytes)) return null;

  const rule = RULE_REGISTRY['RS-FONT-001']!;
  const where = fontExt
    ? `${ext} file does not have a valid font header`
    : `decoy font name "${base}" contains script text`;

  return {
    ruleId: rule.id,
    ruleName: rule.name,
    ruleVersion: rule.version,
    severity: 'critical',
    confidence: 'high',
    filePath,
    message: `Fake font carrier in ${displayDir(filePath)}: ${where}. Location is not limited to public/.`,
    evidence: [where],
    remediation: rule.remediation,
    riskScore: 95,
  };
}

export function analyzeIdeTasks(filePath: string, content: string): Finding[] {
  const normalized = filePath.replace(/\\/g, '/');
  if (!normalized.endsWith('/.vscode/tasks.json') && !normalized.endsWith('.vscode/tasks.json')) {
    return [];
  }

  const runsNode = /\bnode(?:\.exe)?\b/.test(content);
  if (!runsNode) return [];

  const auto = /folderOpen/.test(content);
  const fontTarget =
    /\.(?:woff2?|ttf|otf|eot|fon|lkf|orc)\b/i.test(content) || FA_DECOY_NAME.test(content);
  const dropperName = /\b(?:init|api\.js|app\.js|preload\.js|setup\.js|loader\.js)\b/.test(content);
  if (!fontTarget && !dropperName) return [];
  if (!auto && !fontTarget) return [];

  const rule = RULE_REGISTRY['RS-IDE-001']!;
  const why = auto
    ? 'task runs node when the folder opens'
    : 'task runs node against a font or dropper path';

  return [
    {
      ruleId: rule.id,
      ruleName: rule.name,
      ruleVersion: rule.version,
      severity: 'critical',
      confidence: 'high',
      filePath,
      message: `Editor task executes a supply-chain dropper (${why}).`,
      evidence: [why],
      remediation: rule.remediation,
      riskScore: 95,
    },
  ];
}

export function hasValidFontMagic(ext: string, bytes: Buffer): boolean {
  if (bytes.length < 4) return false;
  const sig = bytes.toString('ascii', 0, 4);
  switch (ext) {
    case '.woff':
      return sig === 'wOFF';
    case '.woff2':
      return sig === 'wOF2';
    case '.ttf':
    case '.otf':
      return (
        sig === 'OTTO' ||
        sig === 'true' ||
        sig === 'typ1' ||
        (bytes[0] === 0x00 && bytes[1] === 0x01 && bytes[2] === 0x00 && bytes[3] === 0x00)
      );
    case '.eot':
      return bytes.length >= 36 && bytes[34] === 0x4c && bytes[35] === 0x50;
    case '.fon':
      return sig.startsWith('MZ');
    default:
      return false;
  }
}

export function isFontCarrierPath(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath);
  if (FONT_EXTENSIONS.has(ext)) return true;
  if (BENIGN_ASSET_EXTENSIONS.has(ext)) return false;
  return FA_DECOY_NAME.test(base);
}

function looksLikeScript(bytes: Buffer): boolean {
  const sample = bytes.toString('utf8', 0, Math.min(bytes.length, 4096)).replace(/^[\s\0]+/, '');
  return /^(?:\/[/*]|['"]use strict['"]|(?:async\s+)?function\b|(?:var|const|let|import|export)\b|global\s*[.[]|module\.|exports\b|!function|\(function)/.test(
    sample,
  );
}

function isRepoRootTarget(target: string, base: string): boolean {
  const normalized = stripQuotes(target).replace(/\\/g, '/');
  const prefix = normalized.slice(0, Math.max(0, normalized.length - base.length));
  return prefix === '' || prefix === './';
}

function basename(target: string): string {
  const normalized = stripQuotes(target).replace(/\\/g, '/');
  const base = normalized.split('/').pop() ?? normalized;
  return base.toLowerCase();
}

function stripQuotes(value: string): string {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

function displayDir(filePath: string): string {
  const dir = path.dirname(filePath).replace(/\\/g, '/');
  return dir === '.' ? 'the repository root' : dir;
}

function lineOfFirst(content: string, patterns: RegExp[]): number | undefined {
  let best = -1;
  for (const pattern of patterns) {
    const flags = pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`;
    const re = new RegExp(pattern.source, flags);
    const match = re.exec(content);
    if (match && (best === -1 || match.index < best)) best = match.index;
  }
  if (best < 0) return undefined;
  let line = 1;
  for (let i = 0; i < best; i += 1) {
    if (content.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function isScriptLikePath(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath).toLowerCase();
  if (SCRIPT_EXTENSIONS.has(ext)) return true;
  if (FONT_EXTENSIONS.has(ext)) return true;
  if (FA_DECOY_NAME.test(base)) return true;
  if (!ext && !base.startsWith('.')) return true;
  return false;
}

function isSensitiveScriptPath(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath).toLowerCase();
  if (!ext || FONT_EXTENSIONS.has(ext) || FA_DECOY_NAME.test(base)) return true;
  if (HIGH_CONFIDENCE_TARGETS.has(base) || MEDIUM_CONFIDENCE_TARGETS.has(base)) return true;
  return /^(?:postcss|tailwind|vite|webpack|next|eslint|babel|rollup|jest|vitest)\.config\./.test(base);
}

function measureScript(content: string): {
  bytes: number;
  longest: number;
  longestLine: number;
  average: number;
} {
  const bytes = Buffer.byteLength(content);
  let longest = 0;
  let longestLine = 1;
  let line = 1;
  let lineStart = 0;
  for (let i = 0; i <= content.length; i += 1) {
    if (i === content.length || content.charCodeAt(i) === 10) {
      const len = i - lineStart;
      if (len > longest) {
        longest = len;
        longestLine = line;
      }
      line += 1;
      lineStart = i + 1;
    }
  }
  const lineCount = Math.max(1, line - 1);
  return { bytes, longest, longestLine, average: bytes / lineCount };
}
