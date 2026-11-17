import { snippet } from "../core/redact.js";
import type { Confidence, Severity } from "../core/types.js";
import {
  CHMOD_THEN_RUN,
  DECODE_TO_SHELL,
  PIPE_TO_SHELL,
  REVERSE_SHELL,
  WINDOWS_LOLBIN,
  redactUrls,
} from "./js-rules.js";
import { loc, type RawFinding, type RuleMeta } from "./types.js";

export const PACKAGE_RULE_META: RuleMeta[] = [
  {
    id: "RS-PKG-001",
    title: "npm script matches an attack pattern or runs inline code",
    category: "lifecycle-script",
    severity: "high",
    description:
      "A package.json script pipes a download into a shell, decodes into a shell, opens a reverse shell, evals inline code, or touches credential files. Install-time scripts are weighted most heavily.",
  },
  {
    id: "RS-PKG-002",
    title: "Install-time lifecycle script present",
    category: "lifecycle-script",
    severity: "low",
    description:
      "preinstall, install, postinstall, or prepare scripts run automatically on npm install. Most are benign; they are listed so they get a human look. Scripts are never executed by RepoShield.",
  },
  {
    id: "RS-DEP-001",
    title: "Dependency installed from a non-registry source",
    category: "dependency",
    severity: "medium",
    description: "Git, tarball URL, or plain-HTTP dependency sources bypass registry integrity and review.",
  },
  {
    id: "RS-DEP-002",
    title: "Dependency name resembles a popular package",
    category: "dependency",
    severity: "low",
    description:
      "The name is one edit away from a very popular package. This is an offline heuristic and does not verify registry contents or reputation.",
  },
  {
    id: "RS-DEP-003",
    title: "Dependencies changed relative to the base reference",
    category: "git-change",
    severity: "low",
    description:
      "Dependencies were added or changed compared with the base Git reference. Review additions before installing.",
  },
  {
    id: "RS-DEP-004",
    title: "Lockfile inconsistency or untrusted resolution source",
    category: "dependency",
    severity: "medium",
    description:
      "A lockfile entry resolves from a non-default host, over plain HTTP, from Git, lacks an integrity hash, or a declared dependency is missing from the lockfile.",
  },
  {
    id: "RS-DEP-005",
    title: "Unpinned dependency range",
    category: "dependency",
    severity: "low",
    description:
      "'*', 'latest' or empty ranges accept any published version, which widens exposure to dependency confusion and hijacked releases.",
  },
  {
    id: "RS-DEP-006",
    title: "Risky .npmrc setting",
    category: "dependency",
    severity: "medium",
    description: "Disabling TLS verification or redirecting the registry changes where packages come from.",
  },
];

export interface PackageJson {
  name?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

const INSTALL_HOOKS = new Set([
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "preprepare",
  "postprepare",
  "prepublish",
]);
const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"] as const;

function lineOfKey(text: string, key: string, after = 0): { line: number; column: number } {
  const needle = JSON.stringify(key);
  let idx = text.indexOf(needle, after);
  if (idx < 0) idx = 0;
  const before = text.slice(0, idx);
  const line = before.split("\n").length;
  const column = idx - (before.lastIndexOf("\n") + 1) + 1;
  return { line, column };
}

export function parsePackageJson(text: string): PackageJson | undefined {
  try {
    const v: unknown = JSON.parse(text);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as PackageJson) : undefined;
  } catch {
    return undefined;
  }
}

// --------------------------------------------------------------- scripts
const BENIGN_SEGMENT =
  /^(?:(?:npx\s+(?:--no-install\s+)?)?(?:husky(?:\s+install)?(?:\s+[\w./-]+)?|patch-package|only-allow\s+\w+|is-ci|node-gyp-build|node-gyp\s+rebuild|prisma\s+generate|tsc(?:\s+[-\w./=]+)*|tsup(?:\s+[-\w./=]+)*|nuxt\s+prepare|svelte-kit\s+sync|panda\s+codegen|lefthook\s+install|simple-git-hooks|opencollective-postinstall)|(?:npm|pnpm|yarn)\s+(?:run\s+)?(?:build|compile|prepare:\w+)|(?:next|vite|astro)\s+build)$/i;

const NETWORK_FETCH = /\b(curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b|https?:\/\//i;
const INLINE_CODE =
  /(\bnode\s+(?:--eval|-e|-p|--print)\b|\bpython3?\s+-c\b|\bperl\s+-e\b|\bruby\s+-e\b|\beval\b|\bbase64\b|\batob\b|Buffer\.from|powershell[^|;&\n]*\s-(?:enc|encodedcommand|e)\b|\b(?:sh|bash|zsh)\s+-c\b)/i;
const CREDENTIAL_TOUCH =
  /(\.npmrc|\.ssh\b|\.aws\b|id_rsa|\.netrc|\.git-credentials|\bprintenv\b|\bNPM_TOKEN\b|\bGITHUB_TOKEN\b|\$\{?(?:NPM|GH|GITHUB|AWS)_\w*(?:TOKEN|KEY|SECRET)\w*\}?)/i;
const LOCAL_NODE = /^\s*(?:node|tsx|ts-node|bun|deno\s+run)\s+(?:--[\w-]+\s+)*(\S+)/i;

export interface ScriptVerdict {
  severity: Severity;
  confidence: Confidence;
  reason: string;
  attack: boolean;
}

function isBenignScript(cmd: string): boolean {
  const parts = cmd
    .split(/&&|\|\||;/)
    .map((s) => s.trim())
    .filter(Boolean);
  return parts.length > 0 && parts.every((s) => BENIGN_SEGMENT.test(s));
}

/** Classify a script command line by text only. The command is never run. */
export function classifyScript(cmd: string, installTime: boolean): ScriptVerdict | null {
  if (PIPE_TO_SHELL.test(cmd))
    return { severity: "critical", confidence: "high", reason: "download piped into a shell", attack: true };
  if (DECODE_TO_SHELL.test(cmd))
    return {
      severity: "critical",
      confidence: "high",
      reason: "decoded data piped into a shell",
      attack: true,
    };
  if (REVERSE_SHELL.test(cmd))
    return { severity: "critical", confidence: "high", reason: "reverse-shell pattern", attack: true };
  if (WINDOWS_LOLBIN.test(cmd))
    return {
      severity: "critical",
      confidence: "high",
      reason: "Windows download/execute utility",
      attack: true,
    };
  if (CHMOD_THEN_RUN.test(cmd) && installTime)
    return {
      severity: "high",
      confidence: "medium",
      reason: "chmod then execute at install time",
      attack: true,
    };
  if (isBenignScript(cmd)) return null;
  if (!installTime) {
    // Outside install hooks, inline code is common (dev tooling); only flag credential access paired with network use.
    if (CREDENTIAL_TOUCH.test(cmd) && NETWORK_FETCH.test(cmd)) {
      return {
        severity: "high",
        confidence: "medium",
        reason: "credential files or tokens combined with network access",
        attack: false,
      };
    }
    return null;
  }
  if (CREDENTIAL_TOUCH.test(cmd))
    return {
      severity: "high",
      confidence: "medium",
      reason: "install-time script touches credential files or tokens",
      attack: false,
    };
  if (NETWORK_FETCH.test(cmd))
    return {
      severity: "high",
      confidence: "medium",
      reason: "install-time script downloads from the network",
      attack: false,
    };
  if (INLINE_CODE.test(cmd))
    return {
      severity: "high",
      confidence: "medium",
      reason: "install-time script runs inline or encoded code",
      attack: false,
    };
  const m = LOCAL_NODE.exec(cmd);
  if (m) {
    const target = m[1] ?? "";
    const hidden = /(^|\/)\.[\w-]+\//.test(target) && !/^\.\.?\//.test(target);
    return {
      severity: hidden ? "medium" : "low",
      confidence: "medium",
      reason: hidden
        ? `runs a script from a hidden directory (${snippet(target, 40)})`
        : `runs a local script (${snippet(target, 40)}) at install time; that file is scanned separately`,
      attack: false,
    };
  }
  return { severity: "low", confidence: "low", reason: "runs a command at install time", attack: false };
}

// ------------------------------------------------------------- dependency sources
export type DepSource = "registry" | "git" | "url" | "http" | "github-shorthand" | "local";

export function classifyDepSource(spec: string): DepSource {
  const s = spec.trim();
  if (/^http:\/\//i.test(s)) return "http";
  if (/^(git\+|git:|ssh:|git@)/i.test(s) || /\.git(#|$)/i.test(s) || /^github:|^gitlab:|^bitbucket:/i.test(s))
    return "git";
  if (/^https:\/\//i.test(s)) return "url";
  if (
    /^[\w.-]+\/[\w.-]+(#.*)?$/.test(s) &&
    !/^(npm:|workspace:|file:|link:|portal:|patch:)/.test(s) &&
    !s.startsWith("@")
  )
    return "github-shorthand";
  if (/^(file:|link:|portal:|workspace:)/i.test(s)) return "local";
  return "registry";
}

const POPULAR = [
  "react",
  "react-dom",
  "react-is",
  "lodash",
  "express",
  "axios",
  "chalk",
  "commander",
  "debug",
  "moment",
  "request",
  "webpack",
  "typescript",
  "eslint",
  "prettier",
  "jest",
  "vite",
  "next",
  "mongoose",
  "dotenv",
  "async",
  "bluebird",
  "underscore",
  "jquery",
  "colors",
  "color",
  "minimist",
  "yargs",
  "glob",
  "rimraf",
  "mkdirp",
  "semver",
  "tslib",
  "rxjs",
  "cors",
  "body-parser",
  "cookie-parser",
  "jsonwebtoken",
  "bcrypt",
  "bcryptjs",
  "passport",
  "socket.io",
  "nodemon",
  "tailwindcss",
  "postcss",
  "autoprefixer",
  "core-js",
  "classnames",
  "node-fetch",
  "inquirer",
  "execa",
  "puppeteer",
  "cross-env",
  "sequelize",
  "mysql",
  "mysql2",
  "vitest",
  "mocha",
  "chai",
  "sinon",
  "uuid",
  "zod",
  "fs-extra",
  "event-stream",
  "left-pad",
  "express-session",
  "morgan",
  "helmet",
  "winston",
  "pino",
  "ioredis",
];

function withinOneEdit(a: string, b: string): boolean {
  if (a === b) return false;
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > 1) return false;
  if (la === lb) {
    const diffs: number[] = [];
    for (let i = 0; i < la; i++) if (a[i] !== b[i]) diffs.push(i);
    if (diffs.length === 1) return true;
    if (diffs.length === 2) {
      const [i, j] = diffs as [number, number];
      return j === i + 1 && a[i] === b[j] && a[j] === b[i];
    }
    return false;
  }
  const [s, l] = la < lb ? [a, b] : [b, a];
  let i = 0;
  while (i < s.length && s[i] === l[i]) i++;
  return s.slice(i) === l.slice(i + 1);
}

const POPULAR_SET = new Set(POPULAR);

export function lookalikeOf(name: string): string | undefined {
  if (name.startsWith("@") || name.length < 5 || POPULAR_SET.has(name)) return undefined;
  const stripped = name.replace(/[-_.]/g, "");
  for (const p of POPULAR) {
    if (p.length < 5) continue;
    if (withinOneEdit(name, p)) return p;
    // `crossenv` vs `cross-env`: same name once separators are dropped.
    if (stripped === p.replace(/[-_.]/g, "") && name !== p) return p;
  }
  return undefined;
}

// ------------------------------------------------------------------ package.json
export interface PackageAnalysisInput {
  file: string;
  text: string;
  /** Parsed package.json at the base ref. `undefined` = unknown, `null` = file did not exist there. */
  base?: PackageJson | null;
}

export function analyzePackageJson(input: PackageAnalysisInput): {
  findings: RawFinding[];
  parseError?: string;
} {
  const { file, text } = input;
  const pkg = parsePackageJson(text);
  if (!pkg) return { findings: [], parseError: "package.json is not valid JSON" };
  const out: RawFinding[] = [];
  const base = { file, sensitiveLocation: true as const };

  // Scripts
  const scripts = pkg.scripts && typeof pkg.scripts === "object" ? pkg.scripts : {};
  for (const [name, cmdRaw] of Object.entries(scripts)) {
    if (typeof cmdRaw !== "string") continue;
    const cmd = cmdRaw;
    const bare = name.replace(/^(pre|post)/, "");
    const installTime =
      INSTALL_HOOKS.has(name) || (INSTALL_HOOKS.has(bare) && /^(pre|post)/.test(name) && bare !== "publish");
    const v = classifyScript(cmd, installTime);
    if (!v) continue;
    const at = lineOfKey(text, name, text.indexOf('"scripts"'));
    const isAlert = v.attack || v.severity === "high" || v.severity === "critical";
    out.push({
      ruleId: isAlert ? "RS-PKG-001" : "RS-PKG-002",
      title: isAlert
        ? "npm script matches an attack pattern or runs inline code"
        : "Install-time lifecycle script present",
      category: "lifecycle-script",
      severity: v.severity,
      confidence: v.confidence,
      ...base,
      location: loc(at),
      message: isAlert
        ? `The "${name}" script matched: ${v.reason}. ${installTime ? "It runs automatically when dependencies are installed, before any code review." : ""}`.trim()
        : `The "${name}" script matched: ${v.reason}. It runs automatically on install; RepoShield did not run it.`,
      evidence: [`script: ${name}`, `command: ${snippet(redactUrls(cmd), 110)}`],
      recommendation: isAlert
        ? "Do not run npm install or this script until it is reviewed. Compare against the last trusted commit and remove the behaviour if unexpected."
        : "Confirm this install-time behaviour is expected. Consider installing with --ignore-scripts in CI.",
      key: `script|${name}|${v.reason}`,
      lifecycle: installTime,
    });
  }

  // Dependencies
  for (const field of DEP_FIELDS) {
    const deps = pkg[field];
    if (!deps || typeof deps !== "object") continue;
    const fieldAt = text.indexOf(`"${field}"`);
    for (const [name, specRaw] of Object.entries(deps)) {
      if (typeof specRaw !== "string") continue;
      const spec = specRaw;
      const at = lineOfKey(text, name, Math.max(fieldAt, 0));
      const src = classifyDepSource(spec);
      if (src === "http" || src === "git" || src === "url" || src === "github-shorthand") {
        out.push({
          ruleId: "RS-DEP-001",
          title: "Dependency installed from a non-registry source",
          category: "dependency",
          severity: src === "http" ? "high" : src === "github-shorthand" ? "low" : "medium",
          confidence: "medium",
          ...base,
          location: loc(at),
          message: `"${name}" is installed from a ${src === "http" ? "plain-HTTP URL" : src === "url" ? "tarball URL" : "Git source"} instead of the npm registry. Registry integrity checks and review do not apply, and the source can change without a version bump.`,
          evidence: [`dependency: ${name}`, `source type: ${src}`],
          recommendation:
            "Prefer a registry release pinned to an exact version. If a Git dependency is required, pin it to a full commit hash.",
          key: `dep-source|${field}|${name}|${src}`,
        });
      }
      const alike = lookalikeOf(name);
      if (alike) {
        out.push({
          ruleId: "RS-DEP-002",
          title: "Dependency name resembles a popular package",
          category: "dependency",
          severity: "low",
          confidence: "low",
          ...base,
          location: loc(at),
          message: `"${name}" is one edit away from the popular package "${alike}". This offline check cannot tell whether it is legitimate; typosquatting is a common supply-chain attack.`,
          evidence: [`dependency: ${name}`, `similar to: ${alike}`],
          recommendation: `Confirm you meant "${name}" and not "${alike}", and review the package on the registry before installing.`,
          key: `lookalike|${name}|${alike}`,
        });
      }
      if (src === "registry" && /^(\*|latest|x|)$/i.test(spec.trim())) {
        out.push({
          ruleId: "RS-DEP-005",
          title: "Unpinned dependency range",
          category: "dependency",
          severity: "low",
          confidence: "medium",
          ...base,
          location: loc(at),
          message: `"${name}" accepts any version ("${spec || "empty"}"). A hijacked or confused release would be installed automatically.`,
          evidence: [`dependency: ${name}`, `range: ${spec || "(empty)"}`],
          recommendation: "Use a bounded semver range and commit a lockfile.",
          key: `unpinned|${name}`,
        });
      }
    }
  }

  // Changes since base ref
  if (input.base) out.push(...dependencyChange(file, text, pkg, input.base));
  return { findings: out };
}

function dependencyChange(file: string, text: string, now: PackageJson, before: PackageJson): RawFinding[] {
  const added: string[] = [];
  const changed: string[] = [];
  let risky = false;
  for (const field of DEP_FIELDS) {
    const a = now[field] ?? {};
    const b = before[field] ?? {};
    for (const [name, spec] of Object.entries(a)) {
      if (typeof spec !== "string") continue;
      if (!(name in b)) {
        added.push(`${name}@${snippet(spec, 30)}`);
        if (classifyDepSource(spec) !== "registry" && classifyDepSource(spec) !== "local") risky = true;
        if (lookalikeOf(name)) risky = true;
      } else if (b[name] !== spec) {
        changed.push(`${name}: ${snippet(String(b[name]), 20)} → ${snippet(spec, 20)}`);
        const src = classifyDepSource(spec);
        if (src !== "registry" && src !== "local" && classifyDepSource(String(b[name])) === "registry")
          risky = true;
      }
    }
  }
  if (added.length === 0 && changed.length === 0) return [];
  const at = lineOfKey(text, "dependencies");
  return [
    {
      ruleId: "RS-DEP-003",
      title: "Dependencies changed relative to the base reference",
      category: "git-change",
      severity: risky ? "medium" : "low",
      confidence: "medium",
      file,
      sensitiveLocation: true,
      location: loc(at),
      message: `${added.length} dependenc${added.length === 1 ? "y was" : "ies were"} added and ${changed.length} changed since the base reference.${risky ? " At least one comes from a non-registry source or has a look-alike name." : ""}`,
      evidence: [
        ...added.slice(0, 12).map((a) => `added: ${a}`),
        ...changed.slice(0, 8).map((c) => `changed: ${c}`),
      ],
      recommendation:
        "Review every added dependency (maintainers, install scripts, download counts) before installing. Install with --ignore-scripts first.",
      key: `dep-change|${[...added.map((a) => a.split("@")[0]), ...changed.map((c) => c.split(":")[0])].sort().join(",")}`,
    },
  ];
}

// ------------------------------------------------------------------ lockfiles
export function analyzePackageLock(
  file: string,
  text: string,
  pkgText?: string,
): { findings: RawFinding[]; parseError?: string } {
  let lock: unknown;
  try {
    lock = JSON.parse(text);
  } catch {
    return { findings: [], parseError: "lockfile is not valid JSON" };
  }
  if (!lock || typeof lock !== "object") return { findings: [] };
  const packages = (lock as { packages?: Record<string, Record<string, unknown>> }).packages;
  const base = { file, sensitiveLocation: true as const };
  const out: RawFinding[] = [];
  if (!packages) return { findings: out };

  const offHost = new Map<string, number>();
  const plainHttp: string[] = [];
  const gitRes: string[] = [];
  let noIntegrity = 0;
  for (const [key, entry] of Object.entries(packages)) {
    if (!key || entry["link"] === true) continue;
    const resolved = entry["resolved"];
    if (typeof resolved !== "string") continue;
    const nm = key.replace(/^.*node_modules\//, "");
    if (/^http:\/\//i.test(resolved)) plainHttp.push(nm);
    else if (/^(git\+|git:|ssh:)/i.test(resolved)) gitRes.push(nm);
    else {
      try {
        const host = new URL(resolved).hostname;
        if (host !== "registry.npmjs.org" && host !== "registry.yarnpkg.com")
          offHost.set(host, (offHost.get(host) ?? 0) + 1);
      } catch {
        /* ignore */
      }
    }
    if (typeof entry["integrity"] !== "string" && !/^(git\+|git:|ssh:)/i.test(resolved)) noIntegrity++;
  }
  const at = lineOfKey(text, "packages");
  const emit = (
    severity: Severity,
    confidence: Confidence,
    message: string,
    evidence: string[],
    key: string,
  ): void => {
    out.push({
      ruleId: "RS-DEP-004",
      title: "Lockfile inconsistency or untrusted resolution source",
      category: "dependency",
      severity,
      confidence,
      ...base,
      location: loc(at),
      message,
      evidence,
      recommendation:
        "Regenerate the lockfile from a trusted registry and review the diff. Never merge lockfile changes you cannot explain.",
      key,
    });
  };
  if (plainHttp.length)
    emit(
      "high",
      "high",
      "Packages resolve over plain HTTP, which can be tampered with in transit.",
      plainHttp.slice(0, 8).map((n) => `package: ${n}`),
      `lock-http|${plainHttp.sort().join(",")}`,
    );
  if (gitRes.length)
    emit(
      "medium",
      "medium",
      "Packages resolve from Git sources rather than registry tarballs.",
      gitRes.slice(0, 8).map((n) => `package: ${n}`),
      `lock-git|${gitRes.sort().join(",")}`,
    );
  if (offHost.size) {
    const hosts = [...offHost.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
    emit(
      "medium",
      "low",
      "Packages resolve from a host other than the public npm registry. This is normal for a private registry mirror, and it is also how dependency confusion and substituted tarballs appear.",
      hosts.slice(0, 6).map(([h, n]) => `host: ${h} (${n} packages)`),
      `lock-host|${hosts.map((h) => h[0]).join(",")}`,
    );
  }
  if (noIntegrity > 0)
    emit(
      "low",
      "medium",
      `${noIntegrity} locked package(s) have no integrity hash, so downloads cannot be verified.`,
      [`entries without integrity: ${noIntegrity}`],
      "lock-no-integrity",
    );

  const pkg = pkgText ? parsePackageJson(pkgText) : undefined;
  if (pkg) {
    const missing: string[] = [];
    for (const field of ["dependencies", "devDependencies"] as const) {
      for (const name of Object.keys(pkg[field] ?? {})) {
        const declared = classifyDepSource(String(pkg[field]?.[name]));
        if (declared === "local") continue;
        if (!packages[`node_modules/${name}`]) missing.push(name);
      }
    }
    if (missing.length)
      emit(
        "low",
        "medium",
        "package.json declares dependencies that the lockfile does not contain, so the lockfile is out of sync.",
        missing.slice(0, 10).map((n) => `missing from lockfile: ${n}`),
        `lock-missing|${missing.sort().join(",")}`,
      );
  }
  return { findings: out };
}

/** Lightweight scan of yarn.lock / pnpm-lock.yaml text for plain-HTTP and Git resolutions. */
export function analyzeTextLockfile(file: string, text: string): RawFinding[] {
  const bad: string[] = [];
  const re = /(?:resolved|tarball)[:\s]+["']?(http:\/\/[^\s"']+|git\+[^\s"']+)/gi;
  for (let m = re.exec(text); m; m = re.exec(text)) bad.push(m[1] as string);
  if (bad.length === 0) return [];
  const http = bad.some((b) => b.startsWith("http:"));
  return [
    {
      ruleId: "RS-DEP-004",
      title: "Lockfile inconsistency or untrusted resolution source",
      category: "dependency",
      severity: http ? "high" : "medium",
      confidence: "medium",
      file,
      sensitiveLocation: true,
      location: loc({ line: 1, column: 1 }),
      message: http
        ? "Lockfile entries resolve over plain HTTP."
        : "Lockfile entries resolve from Git sources.",
      evidence: [`entries: ${bad.length}`, ...bad.slice(0, 3).map((b) => `source: ${redactUrls(b)}`)],
      recommendation: "Regenerate the lockfile from a trusted registry and review the diff.",
      key: `textlock|${http ? "http" : "git"}`,
    },
  ];
}

// -------------------------------------------------------------------- .npmrc
export function analyzeNpmrc(file: string, text: string): RawFinding[] {
  const out: RawFinding[] = [];
  const lines = text.split("\n");
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) return;
    let message: string | undefined;
    let severity: Severity = "medium";
    let key = "";
    if (/^strict-ssl\s*=\s*false/i.test(line)) {
      message = "TLS certificate verification is disabled for npm, so package downloads can be intercepted.";
      severity = "high";
      key = "strict-ssl";
    } else if (/^(?:@[\w-]+:)?registry\s*=\s*(\S+)/i.test(line)) {
      const url = /=\s*(\S+)/.exec(line)?.[1] ?? "";
      if (/^http:\/\//i.test(url)) {
        message = "The registry is configured over plain HTTP.";
        severity = "high";
        key = "registry-http";
      } else if (!/registry\.(npmjs\.org|yarnpkg\.com)/i.test(url) && !line.startsWith("@")) {
        message =
          "The default registry is redirected away from the public npm registry. Normal for a private mirror; also how a malicious registry substitution looks.";
        severity = "low";
        key = "registry-redirect";
      }
    }
    if (message) {
      out.push({
        ruleId: "RS-DEP-006",
        title: "Risky .npmrc setting",
        category: "dependency",
        severity,
        confidence: "medium",
        file,
        sensitiveLocation: true,
        location: loc({ line: i + 1, column: 1 }),
        message,
        evidence: [`setting: ${line.split("=")[0]?.trim() ?? "?"}`],
        recommendation: "Confirm the setting is intended and owned by your team.",
        key: `npmrc|${key}`,
      });
    }
  });
  return out;
}
