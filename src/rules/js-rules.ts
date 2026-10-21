import type { FileFacts, Site, TaintKind } from "../analyzers/facts.js";
import { SENSITIVE_MODULES } from "../analyzers/helpers.js";
import { snippet } from "../core/redact.js";
import { loc, type RawFinding, type RuleMeta } from "./types.js";

export interface JsRule extends RuleMeta {
  run(facts: FileFacts): RawFinding[];
}

type Base = Pick<RawFinding, "file" | "sensitiveLocation">;
const baseOf = (f: FileFacts): Base => ({
  file: f.file,
  ...(f.isConfigFile ? { sensitiveLocation: true } : {}),
});

const hasSensitive = (k: TaintKind[]): boolean => k.includes("secret");

function describeTaint(k: TaintKind[]): string {
  const names: Record<TaintKind, string> = {
    decoded: "decoded (base64/hex/char-code) data",
    network: "data received from the network",
    env: "environment variables",
    secret: "credential-like data",
    hostinfo: "host/system information",
  };
  return k.map((x) => names[x]).join(", ");
}

// ---------------------------------------------------------------------------
export const execDecodedRule: JsRule = {
  id: "RS-EXEC-002",
  title: "Decoded payload reaches code execution",
  category: "dynamic-execution",
  severity: "critical",
  description:
    "Data produced by a decoding step (base64, hex, character codes, decryption) flows into eval, new Function, vm, or a process-execution API.",
  run(f) {
    const out: RawFinding[] = [];
    for (const d of f.dynamicExec) {
      if (!d.taint.includes("decoded")) continue;
      out.push({
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: "critical",
        confidence: "high",
        ...baseOf(f),
        location: loc(d.site),
        message:
          "A value built by decoding data is passed to a dynamic-execution sink. Hiding code in an encoded string and running it is a common malware technique.",
        evidence: [`sink: ${d.kind}`, `input carries: ${describeTaint(d.taint)}`],
        recommendation:
          "Do not run this code. Review the encoded value (decode it as text only), check git blame for who added it, and treat the repository as potentially compromised until explained.",
        key: `${d.kind}|decoded`,
        topLevel: d.site.topLevel,
      });
    }
    for (const p of f.processExec) {
      if (!p.taint.includes("decoded")) continue;
      out.push({
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: "critical",
        confidence: "high",
        ...baseOf(f),
        location: loc(p.site),
        message:
          "A decoded value is used as a command or argument for a child process. This pattern is typical of staged payloads.",
        evidence: [`sink: ${p.api}`, `input carries: ${describeTaint(p.taint)}`],
        recommendation:
          "Do not run this code. Decode the value as text only, review it, and investigate how it was introduced.",
        key: `${p.api}|decoded`,
        topLevel: p.site.topLevel,
      });
    }
    return out;
  },
};

export const downloadExecuteRule: JsRule = {
  id: "RS-DL-001",
  title: "Remote content is executed",
  category: "download-execute",
  severity: "critical",
  description:
    "Content fetched over the network is passed to an execution sink, or is written to disk and then made executable or run in the same file.",
  run(f) {
    const out: RawFinding[] = [];
    for (const d of f.dynamicExec) {
      if (!d.taint.includes("network")) continue;
      out.push({
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: "critical",
        confidence: "high",
        ...baseOf(f),
        location: loc(d.site),
        message:
          "Data received from the network flows directly into a dynamic-execution sink (download-and-execute).",
        evidence: [`sink: ${d.kind}`, `input carries: ${describeTaint(d.taint)}`, ...hostsOf(f)],
        recommendation:
          "Remove remote code execution, pin and vendor what you need, and verify the remote endpoint's owner. Do not contact the URL from an untrusted context.",
        key: `${d.kind}|network`,
        topLevel: d.site.topLevel,
      });
    }
    for (const p of f.processExec) {
      if (!p.taint.includes("network")) continue;
      out.push({
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: "critical",
        confidence: "high",
        ...baseOf(f),
        location: loc(p.site),
        message: "Data received from the network is used to build a command run by a child process.",
        evidence: [`sink: ${p.api}`, `input carries: ${describeTaint(p.taint)}`, ...hostsOf(f)],
        recommendation: "Remove this behaviour or replace it with a pinned, verified dependency.",
        key: `${p.api}|network`,
        topLevel: p.site.topLevel,
      });
    }
    // Written to disk, then made executable or executed in the same file.
    const wroteRemote = f.fsWrites.find((w) => w.taint.includes("network"));
    const runs = f.chmodExec.length > 0 || f.processExec.length > 0;
    if (wroteRemote && runs && out.length === 0) {
      out.push({
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: "critical",
        confidence: "medium",
        ...baseOf(f),
        location: loc(wroteRemote.site),
        message:
          "Network data is written to disk and this file also marks files executable or spawns processes, which matches a download-then-run dropper.",
        evidence: [
          `write: ${wroteRemote.api}`,
          f.chmodExec.length > 0
            ? "file also sets executable permissions"
            : "file also spawns child processes",
          ...hostsOf(f),
        ],
        recommendation:
          "Review what is downloaded and executed. Prefer pinned dependencies with integrity hashes.",
        key: "fs-write|network|exec",
        topLevel: wroteRemote.site.topLevel,
      });
    }
    return out;
  },
};

function hostsOf(f: FileFacts): string[] {
  const hosts = [...new Set(f.network.map((n) => n.host).filter((h): h is string => !!h))].slice(0, 3);
  return hosts.length ? [`hosts referenced (not contacted): ${hosts.join(", ")}`] : [];
}

// ---------------------------------------------------------------------------
export const dynamicExecRule: JsRule = {
  id: "RS-EXEC-001",
  title: "Dynamic code execution with non-literal input",
  category: "dynamic-execution",
  severity: "medium",
  description:
    "eval, new Function, vm, or string timers with a computed argument. Often legitimate; weighted by context and correlated signals.",
  run(f) {
    const out: RawFinding[] = [];
    for (const d of f.dynamicExec) {
      if (d.literalArg) continue;
      if (d.taint.includes("decoded") || d.taint.includes("network")) continue; // stronger rules cover these
      const fromEnv = d.taint.includes("env") || d.taint.includes("secret");
      const weak = d.kind === "dynamic-import" || d.kind === "vm" || d.kind === "compile";
      out.push({
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: fromEnv ? "high" : weak ? "low" : "medium",
        confidence: fromEnv ? "medium" : "low",
        ...baseOf(f),
        location: loc(d.site),
        message: fromEnv
          ? "An environment-derived value is executed as code."
          : `${d.kind} is called with a value that is not a string literal. This can be benign (templating, bundlers, polyfills) but is also how hidden code runs.`,
        evidence: [
          `sink: ${d.kind}`,
          d.taint.length ? `input carries: ${describeTaint(d.taint)}` : "input is computed at runtime",
        ],
        recommendation:
          "Confirm the input is trusted and static. Prefer parsing data (JSON.parse) or explicit function calls over executing strings.",
        key: `${d.kind}|computed`,
        topLevel: d.site.topLevel,
      });
    }
    return out;
  },
};

// ---------------------------------------------------------------------------
export const PIPE_TO_SHELL = /\b(curl|wget|fetch)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i;
export const REVERSE_SHELL =
  /(\/dev\/tcp\/|\bnc\b[^|;&\n]*\s-e\b|\bbash\s+-i\b|mkfifo\b[^|;&\n]*\bnc\b|socat\b[^|;&\n]*exec:)/i;
export const WINDOWS_LOLBIN =
  /(powershell[^|;&\n]*\s-(enc|encodedcommand)\b|certutil[^|;&\n]*-urlcache|mshta\s+https?:|bitsadmin[^|;&\n]*\/transfer|regsvr32[^|;&\n]*\/i:http)/i;
export const DECODE_TO_SHELL = /\bbase64\s+(-d|--decode)\b[^|;&\n]*\|\s*(ba|z)?sh\b/i;
export const CHMOD_THEN_RUN = /\bchmod\s+\+?[0-7x]+\b[^;&\n]*[;&]+\s*\.\//i;

export const shellCommandRule: JsRule = {
  id: "RS-PROC-002",
  title: "Command line matches a known attack pattern",
  category: "process-execution",
  severity: "critical",
  description:
    "A literal shell command pipes a download into a shell, opens a reverse shell, decodes into a shell, or uses a Windows download/exec utility.",
  run(f) {
    const out: RawFinding[] = [];
    for (const p of f.processExec) {
      const cmd = p.commandText;
      if (!cmd) continue;
      const hit = PIPE_TO_SHELL.test(cmd)
        ? "download piped into a shell"
        : REVERSE_SHELL.test(cmd)
          ? "reverse-shell pattern"
          : DECODE_TO_SHELL.test(cmd)
            ? "decoded data piped into a shell"
            : WINDOWS_LOLBIN.test(cmd)
              ? "Windows download/execute utility"
              : CHMOD_THEN_RUN.test(cmd)
                ? "chmod then execute"
                : undefined;
      if (!hit) continue;
      out.push({
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: hit === "chmod then execute" ? "medium" : "critical",
        confidence: hit === "chmod then execute" ? "low" : "high",
        ...baseOf(f),
        location: loc(p.site),
        message: `The command text matches: ${hit}.`,
        evidence: [`api: ${p.api}`, `command: ${snippet(redactUrls(cmd), 100)}`],
        recommendation: "Remove this command or replace it with a pinned, integrity-checked dependency.",
        key: `${p.api}|${hit}`,
        topLevel: p.site.topLevel,
      });
    }
    return out;
  },
};

export function redactUrls(s: string): string {
  return s.replace(/(https?:\/\/)([^/\s"']+)[^\s"']*/gi, "$1$2/…");
}

export const processExecRule: JsRule = {
  id: "RS-PROC-001",
  title: "Process execution with computed command",
  category: "process-execution",
  severity: "low",
  description:
    "child_process execution whose command is not a literal, or that uses a shell with environment-derived input.",
  run(f) {
    const out: RawFinding[] = [];
    for (const p of f.processExec) {
      if (p.taint.includes("decoded") || p.taint.includes("network")) continue;
      const fromEnv = p.taint.length > 0;
      if (p.literalCommand && !fromEnv) continue;
      const sev = p.shell && (fromEnv || !p.literalCommand) ? "medium" : "low";
      out.push({
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: sev,
        confidence: "low",
        ...baseOf(f),
        location: loc(p.site),
        message: p.shell
          ? "A shell command is built from non-literal input, which risks injection and is also a common malware vector."
          : "A child process is started with a computed command or arguments.",
        evidence: [
          `api: ${p.api}`,
          p.shell ? "runs through a shell" : "no shell",
          p.taint.length ? `input carries: ${describeTaint(p.taint)}` : "command is computed at runtime",
        ],
        recommendation:
          "Prefer execFile/spawn with an argument array and validated inputs. Confirm this call is expected here.",
        key: `${p.api}|computed|${p.shell ? "shell" : "noshell"}`,
        topLevel: p.site.topLevel,
      });
    }
    return out;
  },
};

// ---------------------------------------------------------------------------
export const exfiltrationRule: JsRule = {
  id: "RS-EXFIL-001",
  title: "Sensitive data is sent over the network",
  category: "exfiltration",
  severity: "high",
  description:
    "Credentials, environment variables, cookies, or host information flow into an outbound network request.",
  run(f) {
    const out: RawFinding[] = [];
    for (const n of f.network) {
      const t = n.dataTaint.filter((k) => k !== "network" && k !== "decoded");
      if (t.length === 0) continue;
      const wholeEnv = t.includes("env") && f.envReads.some((e) => e.whole);
      const secret = hasSensitive(t);
      const sev = secret || wholeEnv ? "high" : t.includes("hostinfo") ? "medium" : "low";
      const suspiciousHost = n.hostClass !== undefined;
      out.push({
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: suspiciousHost && sev !== "low" ? "critical" : sev,
        confidence: secret || wholeEnv ? "high" : "medium",
        ...baseOf(f),
        location: loc(n.site),
        message: secret
          ? "Credential-like data (tokens, keys, cookies, or secret files) is included in an outbound request."
          : wholeEnv
            ? "The full process environment is included in an outbound request."
            : "Environment or host information is included in an outbound request.",
        evidence: [
          `api: ${n.api}`,
          `data carries: ${describeTaint(t)}`,
          ...(n.host
            ? [`destination host (not contacted): ${n.host}${n.hostClass ? ` [${n.hostClass}]` : ""}`]
            : []),
        ],
        recommendation:
          "Remove the transmission unless it is a documented feature. If this was not added intentionally, rotate every credential the process could read.",
        key: `${n.api}|exfil|${[...t].sort().join("+")}`,
        topLevel: n.site.topLevel,
      });
    }
    return out;
  },
};

export const suspiciousNetworkRule: JsRule = {
  id: "RS-NET-001",
  title: "Request to a host commonly used by malware",
  category: "network",
  severity: "medium",
  description:
    "Outbound request to paste/raw hosting, webhook endpoints, tunnels, URL shorteners, bare IP addresses, or IP-recon services.",
  run(f) {
    const out: RawFinding[] = [];
    for (const n of f.network) {
      if (!n.hostClass) continue;
      const strong =
        n.hostClass === "webhook-endpoint" ||
        n.hostClass === "tunnel" ||
        n.hostClass === "paste-or-raw-hosting";
      out.push({
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: strong ? "medium" : "low",
        confidence: "medium",
        ...baseOf(f),
        location: loc(n.site),
        message: `The code contacts a ${n.hostClass.replace(/-/g, " ")} host. Many legitimate tools do this, but so does malware.`,
        evidence: [`api: ${n.api}`, `host (not contacted): ${n.host ?? "unknown"} [${n.hostClass}]`],
        recommendation:
          "Confirm the destination is expected for this project and owned by someone you trust.",
        key: `${n.api}|host|${n.hostClass}`,
        topLevel: n.site.topLevel,
      });
    }
    return out;
  },
};

export const sensitiveFileRule: JsRule = {
  id: "RS-FS-001",
  title: "Reads credential or wallet files",
  category: "exfiltration",
  severity: "medium",
  description: "Reads SSH keys, cloud credentials, .npmrc, browser data, wallets, or shell history.",
  run(f) {
    return f.sensitiveReads.map<RawFinding>((r) => ({
      ruleId: this.id,
      title: this.title,
      category: this.category,
      severity: "medium",
      confidence: "medium",
      ...baseOf(f),
      location: loc(r.site),
      message: `The code reads a path that looks like a credential store (${r.target}).`,
      evidence: [`path pattern: ${r.target}`],
      recommendation: "Application and build code rarely needs these files. Confirm this is intentional.",
      key: `fs-read|${r.target}`,
      topLevel: r.site.topLevel,
    }));
  },
};

// ---------------------------------------------------------------------------
const STRONG_OBF = new Set([
  "hex-identifiers",
  "string-array",
  "escape-density",
  "packer",
  "jsfuck-like",
  "control-flow-flattening",
]);

export const obfuscationRule: JsRule = {
  id: "RS-OBF-001",
  title: "Code looks obfuscated",
  category: "obfuscation",
  severity: "medium",
  description:
    "Obfuscator-style identifiers, string arrays, escape-heavy strings, packers, or control-flow flattening.",
  run(f) {
    if (f.obfuscation.length === 0) return [];
    const strong = f.obfuscation.filter((o) => STRONG_OBF.has(o.kind));
    const packed = f.obfuscation.some((o) => o.kind === "packer" || o.kind === "jsfuck-like");
    const sev = packed || strong.length >= 2 ? "high" : strong.length === 1 ? "medium" : "low";
    const first = f.obfuscation.find((o) => o.site) ?? undefined;
    return [
      {
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: sev,
        confidence: strong.length >= 2 || packed ? "high" : "medium",
        ...baseOf(f),
        ...(first?.site ? { location: loc(first.site) } : { location: { line: 1, column: 1 } }),
        message:
          "The file shows traits of automated obfuscation. Legitimate source rarely looks like this, though minified or generated code can.",
        evidence: f.obfuscation.map((o) => `${o.kind}: ${o.detail}`),
        recommendation:
          "If this file is not a generated bundle, ask who added it and why. Compare against the last trusted commit.",
        key: `obf|${[...new Set(f.obfuscation.map((o) => o.kind))].sort().join("+")}`,
      },
    ];
  },
};

export const encodedBlobRule: JsRule = {
  id: "RS-OBF-002",
  title: "Encoded blob decodes to executable-looking text",
  category: "obfuscation",
  severity: "high",
  description:
    "A long base64/hex string, or a decoded literal, contains tokens such as child_process, eval(, or URLs when decoded statically.",
  run(f) {
    const out: RawFinding[] = [];
    for (const b of f.encodedBlobs) {
      if (b.markers.length > 0) {
        out.push({
          ruleId: this.id,
          title: this.title,
          category: this.category,
          severity: "high",
          confidence: "high",
          ...baseOf(f),
          location: loc(b.site),
          message:
            "A long encoded string decodes (statically, without executing anything) to text containing dangerous tokens.",
          evidence: [`encoded length: ${b.length} chars`, `decoded text contains: ${b.markers.join(", ")}`],
          recommendation: "Decode the value as text only and review it. Do not run it.",
          key: `blob|${b.markers.join("+")}`,
          topLevel: b.site.topLevel,
        });
      } else if (f.decode.length > 0 || f.dynamicExec.length > 0) {
        out.push({
          ruleId: this.id,
          title: this.title,
          category: this.category,
          severity: "medium",
          confidence: "low",
          ...baseOf(f),
          location: loc(b.site),
          message:
            "A long high-entropy encoded string sits in a file that also decodes data or executes code dynamically.",
          evidence: [`encoded length: ${b.length} chars`, `entropy: ${b.entropy} bits/char`],
          recommendation: "Confirm what this blob is and where it is decoded.",
          key: "blob|unknown",
          topLevel: b.site.topLevel,
        });
      }
    }
    for (const d of f.decode) {
      if (
        d.literalInput &&
        d.decodedMarkers.length > 0 &&
        !f.encodedBlobs.some((b) => b.site.line === d.site.line)
      ) {
        out.push({
          ruleId: this.id,
          title: this.title,
          category: this.category,
          severity: "high",
          confidence: "high",
          ...baseOf(f),
          location: loc(d.site),
          message: "A literal is decoded and the decoded text contains dangerous tokens.",
          evidence: [`decoder: ${d.api}`, `decoded text contains: ${d.decodedMarkers.join(", ")}`],
          recommendation: "Review the decoded text. Do not run it.",
          key: `decode-literal|${d.decodedMarkers.join("+")}`,
          topLevel: d.site.topLevel,
        });
      }
    }
    return out;
  },
};

export const hiddenApiRule: JsRule = {
  id: "RS-OBF-003",
  title: "Sensitive API reached indirectly",
  category: "obfuscation",
  severity: "high",
  description:
    "A sensitive module or global (child_process, eval, Function, process.binding) is reached through concatenated strings or computed property access.",
  run(f) {
    const out: RawFinding[] = [];
    for (const i of f.imports) {
      if (!i.hidden || !SENSITIVE_MODULES.has(i.module)) continue;
      out.push({
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: "high",
        confidence: "high",
        ...baseOf(f),
        location: loc(i.site),
        message: `The module name '${i.module}' is assembled at runtime instead of being written plainly, which hides the dependency from review and simple scanners.`,
        evidence: [`resolved module: ${i.module}`, "name built from concatenation, template, or char codes"],
        recommendation: "There is rarely a legitimate reason to hide a require. Treat this as suspicious.",
        key: `hidden-import|${i.module}`,
        topLevel: i.site.topLevel,
      });
    }
    for (const h of f.hiddenAccess) {
      const strong =
        h.name === "eval" || h.name === "Function" || h.name === "require" || h.name === "child_process";
      out.push({
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: strong ? "high" : "medium",
        confidence: strong ? "high" : "medium",
        ...baseOf(f),
        location: loc(h.site),
        message: `Access to '${h.name}' goes through computed or internal properties.`,
        evidence: [`target: ${h.name}`],
        recommendation: "Review why this API is reached indirectly.",
        key: `hidden-access|${h.name}`,
        topLevel: h.site.topLevel,
      });
    }
    return out;
  },
};

export const configLoadRule: JsRule = {
  id: "RS-CFG-001",
  title: "Config file runs network or process activity at load time",
  category: "config-file",
  severity: "medium",
  description:
    "A tooling config file performs outbound requests or non-literal process execution at module load, where it will run on every build or dev-server start.",
  run(f) {
    if (!f.isConfigFile) return [];
    const out: RawFinding[] = [];
    const sites: Array<{ site: Site; what: string }> = [];
    for (const n of f.network)
      if (n.site.topLevel) sites.push({ site: n.site, what: `network request (${n.api})` });
    for (const p of f.processExec) {
      if (p.site.topLevel && !p.literalCommand)
        sites.push({ site: p.site, what: `computed command (${p.api})` });
    }
    for (const d of f.dynamicExec) {
      if (d.site.topLevel && !d.literalArg)
        sites.push({ site: d.site, what: `dynamic execution (${d.kind})` });
    }
    for (const s of sites) {
      out.push({
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: "medium",
        confidence: "medium",
        file: f.file,
        sensitiveLocation: true,
        location: loc(s.site),
        message:
          "Build and tool config files run automatically, so unexpected activity here is a common place to hide malware. Some projects do this legitimately (for example reading a git hash).",
        evidence: [`at module load: ${s.what}`],
        recommendation:
          "Confirm this behaviour is expected for this config. Check recent changes to this file.",
        key: `cfg-load|${s.what}`,
        topLevel: true,
      });
    }
    return out;
  },
};

export const sensitiveModuleRule: JsRule = {
  id: "RS-MOD-001",
  title: "Config file imports a sensitive Node.js module",
  category: "sensitive-module",
  severity: "low",
  description:
    "child_process, vm, net, dgram, dns, tls, or worker_threads imported by a tooling config file.",
  run(f) {
    if (!f.isConfigFile) return [];
    return f.imports
      .filter((i) => !i.hidden && SENSITIVE_MODULES.has(i.module))
      .map<RawFinding>((i) => ({
        ruleId: this.id,
        title: this.title,
        category: this.category,
        severity: "low",
        confidence: "medium",
        file: f.file,
        sensitiveLocation: true,
        location: loc(i.site),
        message: `Config files rarely need '${i.module}'. This is common for reading git metadata but worth a glance.`,
        evidence: [`module: ${i.module}`],
        recommendation: "Confirm the usage is limited to what the config needs.",
        key: `import|${i.module}`,
        topLevel: i.site.topLevel,
      }));
  },
};

export const JS_RULES: JsRule[] = [
  execDecodedRule,
  downloadExecuteRule,
  dynamicExecRule,
  shellCommandRule,
  processExecRule,
  exfiltrationRule,
  suspiciousNetworkRule,
  sensitiveFileRule,
  obfuscationRule,
  encodedBlobRule,
  hiddenApiRule,
  configLoadRule,
  sensitiveModuleRule,
];
