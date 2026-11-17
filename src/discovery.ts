/**
 * RepoShield — Layer A: File Discovery
 *
 * Enumerates repository files safely:
 * - Respects configured exclusions
 * - Rejects symlinks that escape the repository root
 * - Skips binary, oversized, and unreadable files
 * - Reports scan coverage
 * - Never follows symlinks outside the permitted root
 */

import fs from 'fs';
import path from 'path';
import { SkippedFile } from './types.js';
import { isFontCarrierPath } from './dropper-detector.js';

// ─── Supported File Patterns ──────────────────────────────────────────────────

const SOURCE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.jsx',
  '.ts', '.tsx', '.mts', '.cts',
]);

const CONFIG_PATTERNS = [
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  '.npmrc',
  '.gitconfig',
  '.gitignore',
  '.gitattributes',
  'vite.config.js', 'vite.config.ts', 'vite.config.mjs',
  'next.config.js', 'next.config.ts', 'next.config.mjs',
  'postcss.config.js', 'postcss.config.ts', 'postcss.config.mjs',
  'tailwind.config.js', 'tailwind.config.ts', 'tailwind.config.mjs',
  'webpack.config.js', 'webpack.config.ts', 'webpack.config.mjs',
  'eslint.config.js', 'eslint.config.ts', 'eslint.config.mjs',
  '.eslintrc', '.eslintrc.js', '.eslintrc.json', '.eslintrc.yaml', '.eslintrc.yml',
  'babel.config.js', 'babel.config.ts', 'babel.config.json',
  'rollup.config.js', 'rollup.config.ts', 'rollup.config.mjs',
  'jest.config.js', 'jest.config.ts', 'jest.config.json',
  'vitest.config.js', 'vitest.config.ts',
  'turbo.json',
  'lerna.json',
  'nx.json',
  'pnpm-workspace.yaml',
];

const WORKFLOW_DIR = '.github/workflows';
const GIT_HOOKS_DIR = '.git/hooks';
const SHELL_EXTENSIONS = new Set(['.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd']);

const EXTENSIONLESS_SKIP = new Set([
  'license',
  'licence',
  'readme',
  'changelog',
  'authors',
  'contributors',
  'notice',
  'copying',
  'makefile',
  'dockerfile',
  'containerfile',
  'jenkinsfile',
  'procfile',
  'gemfile',
  'rakefile',
  'pipfile',
  'codeowners',
  'todo',
]);

// Directories to always skip — prevents scanning node_modules and build artifacts
const ALWAYS_EXCLUDED_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  '.nyc_output',
  '.cache',
  '__pycache__',
  '.venv',
  'vendor',
]);

// ─── Binary Detection ─────────────────────────────────────────────────────────

/**
 * Heuristically detect binary files by checking for null bytes in the first 8 KB.
 * This is the same approach used by git.
 */
function isBinaryBuffer(buf: Buffer): boolean {
  const checkLength = Math.min(buf.length, 8192);
  for (let i = 0; i < checkLength; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

// ─── Discovery Result ─────────────────────────────────────────────────────────

export interface DiscoveryResult {
  readonly sourceFiles: string[];
  readonly configFiles: string[];
  readonly workflowFiles: string[];
  readonly hookFiles: string[];
  readonly shellFiles: string[];
  /** Font extensions and Font Awesome decoy names, in any directory. */
  readonly fontFiles: string[];
  /** Extensionless text files such as a root `init` dropper. */
  readonly carrierFiles: string[];
  readonly skippedFiles: SkippedFile[];
  readonly totalDiscovered: number;
}

// ─── Main Discovery Function ──────────────────────────────────────────────────

export interface DiscoveryOptions {
  root: string;
  exclude?: string[];
  maxFileSizeBytes?: number;
  /** If provided, only return files whose path matches one of these relative paths. */
  changedPaths?: string[];
  signal?: AbortSignal;
}

export async function discoverFiles(opts: DiscoveryOptions): Promise<DiscoveryResult> {
  const {
    root,
    exclude = [],
    maxFileSizeBytes = 512 * 1024,
    changedPaths,
    signal,
  } = opts;

  const normalizedRoot = path.resolve(root);
  const skippedFiles: SkippedFile[] = [];
  const sourceFiles: string[] = [];
  const configFiles: string[] = [];
  const workflowFiles: string[] = [];
  const hookFiles: string[] = [];
  const shellFiles: string[] = [];
  const fontFiles: string[] = [];
  const carrierFiles: string[] = [];

  // Build exclusion set for quick lookup
  const userExcludeSet = new Set(
    exclude.map((e) => path.resolve(normalizedRoot, e).toLowerCase()),
  );

  // If changedPaths is supplied, only scan those files
  if (changedPaths && changedPaths.length > 0) {
    for (const relPath of changedPaths) {
      if (signal?.aborted) break;
      const absPath = path.resolve(normalizedRoot, relPath);
      await classifyFile(absPath, normalizedRoot, maxFileSizeBytes, userExcludeSet, skippedFiles, {
        sourceFiles,
        configFiles,
        workflowFiles,
        hookFiles,
        shellFiles,
        fontFiles,
        carrierFiles,
      });
    }
    return packDiscovery({
      sourceFiles,
      configFiles,
      workflowFiles,
      hookFiles,
      shellFiles,
      fontFiles,
      carrierFiles,
      skippedFiles,
    });
  }

  // Full walk
  await walkDirectory(normalizedRoot, normalizedRoot, {
    maxFileSizeBytes,
    userExcludeSet,
    skippedFiles,
    sourceFiles,
    configFiles,
    workflowFiles,
    hookFiles,
    shellFiles,
    fontFiles,
    carrierFiles,
    signal,
  });

  return packDiscovery({
    sourceFiles,
    configFiles,
    workflowFiles,
    hookFiles,
    shellFiles,
    fontFiles,
    carrierFiles,
    skippedFiles,
  });
}

function packDiscovery(state: Omit<DiscoveryResult, 'totalDiscovered'>): DiscoveryResult {
  const totalDiscovered =
    state.sourceFiles.length +
    state.configFiles.length +
    state.workflowFiles.length +
    state.hookFiles.length +
    state.shellFiles.length +
    state.fontFiles.length +
    state.carrierFiles.length +
    state.skippedFiles.length;
  return { ...state, totalDiscovered };
}

interface WalkState {
  maxFileSizeBytes: number;
  userExcludeSet: Set<string>;
  skippedFiles: SkippedFile[];
  sourceFiles: string[];
  configFiles: string[];
  workflowFiles: string[];
  hookFiles: string[];
  shellFiles: string[];
  fontFiles: string[];
  carrierFiles: string[];
  signal?: AbortSignal;
}

async function walkDirectory(
  dirPath: string,
  root: string,
  state: WalkState,
): Promise<void> {
  if (state.signal?.aborted) return;

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch {
    state.skippedFiles.push({
      filePath: dirPath,
      reason: 'unreadable',
      details: 'Cannot read directory',
    });
    return;
  }

  for (const entry of entries) {
    if (state.signal?.aborted) return;
    const fullPath = path.join(dirPath, entry.name);

    // Skip always-excluded directories
    if (entry.isDirectory() && ALWAYS_EXCLUDED_DIRS.has(entry.name)) {
      continue;
    }

    // Skip user-excluded paths
    if (state.userExcludeSet.has(fullPath.toLowerCase())) {
      state.skippedFiles.push({ filePath: fullPath, reason: 'excluded' });
      continue;
    }

    if (entry.isSymbolicLink()) {
      // Check that the symlink target stays within the repo root
      let realPath: string;
      try {
        realPath = fs.realpathSync(fullPath);
      } catch {
        state.skippedFiles.push({
          filePath: fullPath,
          reason: 'unreadable',
          details: 'Broken symlink',
        });
        continue;
      }
      if (!realPath.startsWith(root + path.sep) && realPath !== root) {
        state.skippedFiles.push({
          filePath: fullPath,
          reason: 'symlink-external',
          details: `Symlink targets outside repository root: ${realPath}`,
        });
        continue;
      }
      // Treat as file/dir for classification purposes
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        await walkDirectory(fullPath, root, state);
      } else {
        await classifyFile(fullPath, root, state.maxFileSizeBytes, state.userExcludeSet, state.skippedFiles, state);
      }
      continue;
    }

    if (entry.isDirectory()) {
      await walkDirectory(fullPath, root, state);
      continue;
    }

    if (entry.isFile()) {
      await classifyFile(fullPath, root, state.maxFileSizeBytes, state.userExcludeSet, state.skippedFiles, state);
    }
  }
}

async function classifyFile(
  filePath: string,
  root: string,
  maxFileSizeBytes: number,
  userExcludeSet: Set<string>,
  skippedFiles: SkippedFile[],
  state: Pick<
    WalkState,
    | 'sourceFiles'
    | 'configFiles'
    | 'workflowFiles'
    | 'hookFiles'
    | 'shellFiles'
    | 'fontFiles'
    | 'carrierFiles'
  >,
): Promise<void> {
  if (userExcludeSet.has(filePath.toLowerCase())) {
    skippedFiles.push({ filePath, reason: 'excluded' });
    return;
  }

  let stat: fs.Stats;
  try {
    stat = fs.statSync(filePath);
  } catch {
    skippedFiles.push({ filePath, reason: 'unreadable', details: 'Cannot stat file' });
    return;
  }

  if (!stat.isFile()) return;

  if (stat.size > maxFileSizeBytes) {
    skippedFiles.push({
      filePath,
      reason: 'oversized',
      details: `File size ${stat.size} exceeds limit ${maxFileSizeBytes}`,
    });
    return;
  }

  // Read a small chunk to detect binary
  let headerBuf: Buffer;
  try {
    const fd = fs.openSync(filePath, 'r');
    headerBuf = Buffer.alloc(Math.min(8192, stat.size));
    fs.readSync(fd, headerBuf, 0, headerBuf.length, 0);
    fs.closeSync(fd);
  } catch {
    skippedFiles.push({ filePath, reason: 'unreadable', details: 'Cannot read file header' });
    return;
  }

  const relPath = path.relative(root, filePath);
  const basename = path.basename(filePath);
  const ext = path.extname(filePath).toLowerCase();
  const relPosix = relPath.replace(/\\/g, '/');

  // Font carriers are classified before the binary skip. Real fonts stay
  // quiet after a magic-byte check; fake ones are critical in any directory.
  if (isFontCarrierPath(filePath)) {
    state.fontFiles.push(filePath);
    return;
  }

  if (isBinaryBuffer(headerBuf)) {
    skippedFiles.push({ filePath, reason: 'binary', details: 'Binary content detected' });
    return;
  }

  // Classify by type
  if (
    relPath.startsWith(WORKFLOW_DIR + path.sep) ||
    relPath.startsWith(WORKFLOW_DIR + '/')
  ) {
    state.workflowFiles.push(filePath);
    return;
  }

  if (
    relPath.startsWith(GIT_HOOKS_DIR + path.sep) ||
    relPath.startsWith(GIT_HOOKS_DIR + '/')
  ) {
    state.hookFiles.push(filePath);
    return;
  }

  if (SOURCE_EXTENSIONS.has(ext)) {
    state.sourceFiles.push(filePath);
    return;
  }

  if (relPosix.includes('/.vscode/tasks.json') || relPosix.endsWith('.vscode/tasks.json')) {
    state.configFiles.push(filePath);
    return;
  }

  if (CONFIG_PATTERNS.includes(basename)) {
    state.configFiles.push(filePath);
    return;
  }

  if (SHELL_EXTENSIONS.has(ext)) {
    state.shellFiles.push(filePath);
    return;
  }

  if (!ext && !basename.startsWith('.') && !EXTENSIONLESS_SKIP.has(basename.toLowerCase())) {
    state.carrierFiles.push(filePath);
  }
}

/**
 * Read a file safely, returning null if unreadable.
 * Never executes the file.
 */
export function safeReadFile(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}
