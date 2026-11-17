/**
 * RepoShield — Config Loader Tests
 */

import { loadConfig } from '../src/config';

import path from 'path';
import fs from 'fs';
import os from 'os';

describe('Config Loader', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'reposhield-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('returns safe defaults when no config file exists', () => {
    const config = loadConfig({ root: tmpDir });
    expect(config.version).toBe(1);
    expect(config.suppressions).toBeDefined();
    expect(config.policy).toBeDefined();
    expect(config.policy?.blockOnCritical).toBe(true);
  });

  test('loads valid reposhield.config.json', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'reposhield.config.json'),
      JSON.stringify({
        version: 1,
        exclude: ['dist/', 'coverage/'],
        suppressions: [{ ruleId: 'RS-AST-001', reason: 'Intentional' }],
        policy: { blockOnCritical: true, blockOnHigh: false },
      }),
    );
    const config = loadConfig({ root: tmpDir });
    expect(config.exclude).toContain('dist/');
    expect(config.suppressions?.length).toBe(1);
    expect(config.policy?.blockOnHigh).toBe(false);
  });

  test('throws ConfigError for invalid JSON', () => {
    fs.writeFileSync(path.join(tmpDir, 'reposhield.config.json'), 'NOT JSON');
    expect(() => loadConfig({ root: tmpDir })).toThrow();
  });

  test('throws ConfigError for wrong version', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'reposhield.config.json'),
      JSON.stringify({ version: 999 }),
    );
    expect(() => loadConfig({ root: tmpDir })).toThrow(/version must be 1/i);
  });

  test('rejects path traversal in exclude patterns', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'reposhield.config.json'),
      JSON.stringify({ version: 1, exclude: ['../../etc'] }),
    );
    expect(() => loadConfig({ root: tmpDir })).toThrow(/unsafe path/i);
  });

  test('rejects absolute paths in exclude patterns', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'reposhield.config.json'),
      JSON.stringify({ version: 1, exclude: ['/etc/passwd'] }),
    );
    expect(() => loadConfig({ root: tmpDir })).toThrow(/unsafe path/i);
  });

  test('rejects wildcard suppression of all rules', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'reposhield.config.json'),
      JSON.stringify({
        version: 1,
        suppressions: [{ ruleId: '*', reason: 'Suppress everything' }],
      }),
    );
    expect(() => loadConfig({ root: tmpDir })).toThrow(/wildcard/i);
  });

  test('rejects suppression without a reason', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'reposhield.config.json'),
      JSON.stringify({
        version: 1,
        suppressions: [{ ruleId: 'RS-AST-001', reason: '' }],
      }),
    );
    expect(() => loadConfig({ root: tmpDir })).toThrow(/reason/i);
  });
});
