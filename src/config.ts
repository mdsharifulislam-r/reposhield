/**
 * RepoShield — Configuration Loader
 *
 * Loads and validates reposhield.config.js / reposhield.config.json / .reposhieldrc
 * Never executes lifecycle scripts or untrusted code.
 */

import fs from 'fs';
import path from 'path';
import { ConfigError, RepoShieldConfig, ScanOptions } from './types.js';

const CONFIG_FILE_NAMES = [
  'reposhield.config.json',
  '.reposhieldrc',
  '.reposhieldrc.json',
];

const DEFAULT_POLICY = {
  blockOnCritical: true,
  blockOnHigh: true,
  blockOnMedium: false,
  blockOnSecrets: true,
  blockOnDependencyFindings: 'high' as const,
};

export function loadConfig(options: ScanOptions): RepoShieldConfig {
  const root = options.root ?? process.cwd();

  if (options.configPath) {
    const absPath = path.resolve(root, options.configPath);
    return readAndValidateConfig(absPath);
  }

  for (const name of CONFIG_FILE_NAMES) {
    const candidate = path.join(root, name);
    if (fs.existsSync(candidate)) {
      return readAndValidateConfig(candidate);
    }
  }

  // Return safe defaults if no config file found.
  return {
    version: 1,
    exclude: [],
    suppressions: [],
    policy: DEFAULT_POLICY,
  };
}

function readAndValidateConfig(filePath: string): RepoShieldConfig {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch (err) {
    throw new ConfigError(`Cannot read config file: ${filePath} — ${String(err)}`);
  }

  let parsed: unknown;
  try {
    // Only allow JSON configs — never eval or require() user config.
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new ConfigError(`Config file is not valid JSON: ${filePath} — ${String(err)}`);
  }

  return validateConfig(parsed, filePath);
}

function validateConfig(raw: unknown, source: string): RepoShieldConfig {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new ConfigError(`Config must be a JSON object: ${source}`);
  }

  const obj = raw as Record<string, unknown>;

  if (obj['version'] !== 1) {
    throw new ConfigError(
      `Config version must be 1. Got: ${String(obj['version'])} in ${source}`,
    );
  }

  // Validate excludes
  const exclude = obj['exclude'];
  if (exclude !== undefined) {
    if (!Array.isArray(exclude) || !exclude.every((e) => typeof e === 'string')) {
      throw new ConfigError(`Config 'exclude' must be an array of strings in ${source}`);
    }
    // Safety: reject patterns that escape the repository root
    for (const pattern of exclude as string[]) {
      if (pattern.includes('..') || path.isAbsolute(pattern)) {
        throw new ConfigError(
          `Config 'exclude' contains an unsafe path pattern: "${pattern}" in ${source}`,
        );
      }
    }
  }

  // Validate suppressions
  const suppressions = obj['suppressions'];
  if (suppressions !== undefined) {
    if (!Array.isArray(suppressions)) {
      throw new ConfigError(`Config 'suppressions' must be an array in ${source}`);
    }
    for (const s of suppressions as unknown[]) {
      validateSuppression(s, source);
    }
  }

  // Validate policy
  const policy = obj['policy'];
  if (policy !== undefined) {
    if (typeof policy !== 'object' || policy === null) {
      throw new ConfigError(`Config 'policy' must be an object in ${source}`);
    }
  }

  return {
    version: 1,
    exclude: (exclude as string[] | undefined) ?? [],
    suppressions: (suppressions as RepoShieldConfig['suppressions']) ?? [],
    policy: {
      ...DEFAULT_POLICY,
      ...(policy as object),
    },
    trustedBaseSha: typeof obj['trustedBaseSha'] === 'string' ? obj['trustedBaseSha'] : undefined,
    maxFileSizeBytes:
      typeof obj['maxFileSizeBytes'] === 'number' ? obj['maxFileSizeBytes'] : undefined,
  };
}

function validateSuppression(s: unknown, source: string): void {
  if (typeof s !== 'object' || s === null) {
    throw new ConfigError(`Suppression entry must be an object in ${source}`);
  }
  const entry = s as Record<string, unknown>;
  if (typeof entry['ruleId'] !== 'string' || !entry['ruleId']) {
    throw new ConfigError(`Suppression entry must have a non-empty 'ruleId' in ${source}`);
  }
  // Reject wildcard suppressions that would disable all rules
  if (entry['ruleId'] === '*') {
    throw new ConfigError(
      `Broad wildcard suppression (*) is not allowed in ${source}. Specify a rule ID.`,
    );
  }
  if (typeof entry['reason'] !== 'string' || !entry['reason']) {
    throw new ConfigError(
      `Suppression for rule "${String(entry['ruleId'])}" must have a non-empty 'reason' in ${source}`,
    );
  }
}

export function mergeOptions(
  options: ScanOptions,
  config: RepoShieldConfig,
): Required<
  Pick<ScanOptions, 'root' | 'mode' | 'maxFileSizeBytes' | 'concurrency' | 'minSeverity'>
> {
  return {
    root: path.resolve(options.root ?? process.cwd()),
    mode: options.mode ?? 'audit',
    maxFileSizeBytes: options.maxFileSizeBytes ?? config.maxFileSizeBytes ?? 512 * 1024,
    concurrency: options.concurrency ?? 4,
    minSeverity: options.minSeverity ?? 'info',
  };
}
