/**
 * RepoShield — Dependency Inspector Tests
 */

import {
  inspectPackageJson,
  inspectPackageLock,
  inspectYarnLock,
} from '../src/dependency-inspector';

describe('Dependency Inspector — package.json', () => {
  test('detects URL dependency', () => {
    const pkg = JSON.stringify({
      name: 'test',
      dependencies: { 'malicious-lib': 'https://evil.example.com/lib.tgz' },
    });
    const findings = inspectPackageJson('/test/package.json', pkg);
    expect(findings.some((f) => f.findingType === 'url-dependency')).toBe(true);
    expect(findings.find((f) => f.findingType === 'url-dependency')?.severity).toBe('high');
  });

  test('detects git dependency', () => {
    const pkg = JSON.stringify({
      name: 'test',
      dependencies: { 'some-lib': 'git+https://github.com/user/repo.git' },
    });
    const findings = inspectPackageJson('/test/package.json', pkg);
    expect(findings.some((f) => f.findingType === 'git-dependency')).toBe(true);
  });

  test('detects typosquat candidate (expresss vs express)', () => {
    const pkg = JSON.stringify({
      name: 'test',
      dependencies: { 'expresss': '^4.18.0' }, // extra 's'
    });
    const findings = inspectPackageJson('/test/package.json', pkg);
    expect(findings.some((f) => f.findingType === 'typosquat-candidate')).toBe(true);
    expect(findings.find((f) => f.findingType === 'typosquat-candidate')?.severity).toBe('high');
  });

  test('does NOT flag exact popular package names as typosquats', () => {
    const pkg = JSON.stringify({
      name: 'test',
      dependencies: { express: '^4.18.0', lodash: '^4.17.21', react: '^18.0.0' },
    });
    const findings = inspectPackageJson('/test/package.json', pkg);
    expect(findings.filter((f) => f.findingType === 'typosquat-candidate').length).toBe(0);
  });

  test('detects lifecycle script', () => {
    const pkg = JSON.stringify({
      name: 'test',
      scripts: { postinstall: 'node setup.js' },
    });
    const findings = inspectPackageJson('/test/package.json', pkg);
    expect(findings.some((f) => f.findingType === 'lifecycle-script')).toBe(true);
  });

  test('does not flag clean package', () => {
    const pkg = JSON.stringify({
      name: 'clean-app',
      version: '1.0.0',
      dependencies: { express: '^4.18.0' },
      scripts: { start: 'node index.js', test: 'jest' },
    });
    const findings = inspectPackageJson('/test/package.json', pkg);
    const highOrAbove = findings.filter(
      (f) => f.severity === 'critical' || f.severity === 'high',
    );
    expect(highOrAbove.length).toBe(0);
  });
});

describe('Dependency Inspector — package-lock.json', () => {
  test('detects package resolved from non-registry URL', () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        'node_modules/evil-lib': {
          version: '1.0.0',
          resolved: 'https://evil.example.com/evil-lib.tgz',
          integrity: 'sha512-abc123',
        },
      },
    });
    const { findings } = inspectPackageLock('/test/package-lock.json', lock);
    expect(findings.some((f) => f.findingType === 'suspicious-source')).toBe(true);
  });

  test('reports error for invalid JSON lockfile', () => {
    const { findings } = inspectPackageLock('/test/package-lock.json', 'not valid json {{{');
    expect(findings.some((f) => f.findingType === 'lockfile-inconsistency')).toBe(true);
  });

  test('does not flag standard npm registry packages', () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        'node_modules/express': {
          version: '4.18.2',
          resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
          integrity: 'sha512-abc123',
        },
      },
    });
    const { findings } = inspectPackageLock('/test/package-lock.json', lock);
    const highOrAbove = findings.filter(
      (f) => f.severity === 'critical' || f.severity === 'high',
    );
    expect(highOrAbove.length).toBe(0);
  });
});
