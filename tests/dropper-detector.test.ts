/**
 * Supply-chain dropper tests.
 *
 * Marker strings are built at runtime so this file does not itself match
 * the detector when the repository is scanned.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { discoverFiles } from '../src/discovery';
import {
  analyzeIdeTasks,
  detectLargeScript,
  detectObfuscatedLoader,
  inspectFontCarrier,
} from '../src/dropper-detector';

function campaignTag(): string {
  return ['global', ".i = 'A10-*", "5557';"].join('');
}

function base91Fingerprint(): string {
  return ['(j', '&', '8191)>88'].join('');
}

function stagePath(): string {
  return ['/0x/', 'cls'].join('');
}

describe('Obfuscated loader', () => {
  test('flags a decoy init file with a payload after whitespace', () => {
    const benign = [
      "'use strict';",
      'function init(){ return { ready: true }; }',
      'init();',
    ].join('\n');
    const content = `${benign}${' '.repeat(120)}${campaignTag()} ${base91Fingerprint()}`;
    const findings = detectObfuscatedLoader('/repo/init', content);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('RS-DROP-001');
    expect(findings[0]?.severity).toBe('critical');
  });

  test('flags a postcss config whose real export is followed by a hidden loader', () => {
    const head = [
      "import { createRequire } from 'module';",
      "import { createRequire } from 'module';",
      'const require = createRequire(import.meta.url);',
      'const config = { plugins: { "@tailwindcss/postcss": {} } };',
      'export default config;',
    ].join('\n');
    const content = `${head}${' '.repeat(100)}${campaignTag()} ${stagePath()}`;
    const findings = detectObfuscatedLoader('/repo/postcss.config.mjs', content);
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.evidence.join(' ')).toContain('whitespace');
  });

  test('does not flag a normal postcss config', () => {
    const content = [
      "import { createRequire } from 'module';",
      'const require = createRequire(import.meta.url);',
      'const config = { plugins: { "@tailwindcss/postcss": {} } };',
      'export default config;',
    ].join('\n');
    expect(detectObfuscatedLoader('/repo/postcss.config.mjs', content)).toHaveLength(0);
  });

  test('detector source does not flag itself', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'dropper-detector.ts'), 'utf8');
    const tests = fs.readFileSync(path.join(__dirname, 'dropper-detector.test.ts'), 'utf8');
    expect(detectObfuscatedLoader('/repo/src/dropper-detector.ts', source)).toHaveLength(0);
    expect(detectObfuscatedLoader('/repo/tests/dropper-detector.test.ts', tests)).toHaveLength(0);
    expect(detectLargeScript('/repo/src/dropper-detector.ts', source)).toHaveLength(0);
    expect(detectLargeScript('/repo/tests/dropper-detector.test.ts', tests)).toHaveLength(0);
    expect(inspectFontCarrier('/repo/tests/dropper-detector.test.ts', Buffer.from(tests))).toBeNull();
  });
});

describe('Fake font carriers', () => {
  test('flags script bytes in a font file outside public/', () => {
    const bytes = Buffer.from(['function ', 'drop(){return 1}'].join(''));
    const filePath = '/repo/src/assets/vendor/fa-brand-400.woff';
    const finding = inspectFontCarrier(filePath, bytes);
    expect(finding?.ruleId).toBe('RS-FONT-001');
    expect(finding?.severity).toBe('critical');
    expect(finding?.message).not.toContain('only public');
    expect(filePath.includes('/public/')).toBe(false);
  });

  test('flags an otf carrier under app/components', () => {
    const bytes = Buffer.from(`${' '.repeat(40)}${campaignTag()}`);
    const finding = inspectFontCarrier('/repo/app/components/fonts/fa-solid-700.otf', bytes);
    expect(finding?.severity).toBe('critical');
  });

  test('accepts a real woff header in public/fonts', () => {
    const bytes = Buffer.alloc(32);
    bytes.write('wOFF', 0);
    expect(inspectFontCarrier('/repo/public/fonts/GeistVF.woff', bytes)).toBeNull();
  });

  test('accepts a real eot header', () => {
    const bytes = Buffer.alloc(40);
    bytes[34] = 0x4c;
    bytes[35] = 0x50;
    expect(inspectFontCarrier('/repo/anywhere/fa-solid-900.eot', bytes)).toBeNull();
  });

  test('discovery keeps font files from every directory', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reposhield-font-'));
    const realDir = path.join(root, 'public', 'fonts');
    const fakeDir = path.join(root, 'src', 'assets');
    fs.mkdirSync(realDir, { recursive: true });
    fs.mkdirSync(fakeDir, { recursive: true });
    const real = Buffer.alloc(16);
    real.write('wOFF', 0);
    fs.writeFileSync(path.join(realDir, 'GeistVF.woff'), real);
    fs.writeFileSync(path.join(fakeDir, 'fa-brand-400.woff'), ['function ', 'drop(){return 1}'].join(''));
    fs.writeFileSync(path.join(root, 'init'), `${' '.repeat(90)}${campaignTag()}`);

    return discoverFiles({ root }).then((found) => {
      const fonts = found.fontFiles.map((file) => path.basename(file)).sort();
      expect(fonts).toEqual(['GeistVF.woff', 'fa-brand-400.woff']);
      expect(found.carrierFiles.some((file) => path.basename(file) === 'init')).toBe(true);

      const fake = found.fontFiles.find((file) => file.endsWith('fa-brand-400.woff'));
      const legit = found.fontFiles.find((file) => file.endsWith('GeistVF.woff'));
      expect(fake && inspectFontCarrier(fake, fs.readFileSync(fake))?.severity).toBe('critical');
      expect(legit && inspectFontCarrier(legit, fs.readFileSync(legit))).toBeNull();
      const initFile = found.carrierFiles.find((file) => path.basename(file) === 'init');
      expect(initFile && detectObfuscatedLoader(initFile, fs.readFileSync(initFile, 'utf8')).length).toBe(1);
    });
  });
});

describe('Large scripts', () => {
  test('flags a long single-line script anywhere', () => {
    const content = `const payload = "${'a'.repeat(2600)}";\n`;
    const findings = detectLargeScript('/repo/src/pages/home.tsx', content);
    expect(findings[0]?.ruleId).toBe('RS-DROP-002');
    expect(findings[0]?.severity).toBe('high');
  });

  test('flags a dense script body over 10KB', () => {
    const line = `var ${'x'.repeat(400)}=1;`;
    const content = `${line}\n`.repeat(30);
    const findings = detectLargeScript('/repo/lib/runtime.js', content);
    expect(findings.some((f) => f.ruleId === 'RS-DROP-002')).toBe(true);
  });

  test('flags an oversized init or config even when lines are short', () => {
    const content = `${'const ready = true;\n'.repeat(700)}`;
    expect(detectLargeScript('/repo/init', content).some((f) => f.ruleId === 'RS-DROP-002')).toBe(true);
    expect(detectLargeScript('/repo/postcss.config.mjs', content).some((f) => f.ruleId === 'RS-DROP-002')).toBe(true);
  });

  test('does not flag a normal formatted source file', () => {
    const content = `${'export function view(){ return null; }\n'.repeat(400)}`;
    expect(content.length).toBeGreaterThan(10 * 1024);
    expect(detectLargeScript('/repo/src/pages/home.tsx', content)).toHaveLength(0);
  });
});

describe('Editor tasks', () => {
  test('flags a folderOpen task that runs node on a font outside public/', () => {
    const content = JSON.stringify({
      version: '2.0.0',
      tasks: [
        {
          label: 'fonts',
          type: 'shell',
          command: 'node',
          args: ['lib/vendor/fa-brand-400.woff'],
          runOptions: { runOn: 'folderOpen' },
        },
      ],
    });
    const findings = analyzeIdeTasks('/repo/frontend/.vscode/tasks.json', content);
    expect(findings[0]?.ruleId).toBe('RS-IDE-001');
    expect(findings[0]?.severity).toBe('critical');
  });

  test('does not flag an ordinary build task', () => {
    const content = JSON.stringify({
      version: '2.0.0',
      tasks: [{ label: 'build', type: 'npm', script: 'build' }],
    });
    expect(analyzeIdeTasks('/repo/.vscode/tasks.json', content)).toHaveLength(0);
  });
});
