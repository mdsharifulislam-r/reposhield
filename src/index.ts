/**
 * RepoShield — Public API Entry Point
 *
 * Stable exports for CommonJS, ESM, and TypeScript consumers.
 */

export { clean } from './scanner.js';

// Type exports
export type {
  ScanOptions,
  ScanSummary,
  ScanMode,
  Finding,
  Severity,
  Confidence,
  DependencyFinding,
  GitFinding,
  SecretFinding,
  SkippedFile,
  SuppressionEntry,
  PolicyConfig,
  RepoShieldConfig,
  RuleDefinition,
  CorrelatedSignal,
} from './types.js';

// Error types
export { RepoShieldError, ConfigError, GitError, ScanAbortedError } from './types.js';

// Rule registry (for tool integrators)
export { RULE_REGISTRY } from './rules.js';
