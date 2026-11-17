import type * as t from "@babel/types";
import type { HostClass } from "./facts.js";

/**
 * Statically fold simple string-building expressions (concatenation, templates
 * without expressions, String.fromCharCode with literals, array join, atob of a
 * literal). This is pure string manipulation - nothing is ever executed.
 */
export function constFold(node: t.Node | null | undefined, depth = 0): string | undefined {
  if (!node || depth > 12) return undefined;
  switch (node.type) {
    case "StringLiteral":
      return node.value;
    case "NumericLiteral":
      return String(node.value);
    case "TemplateLiteral": {
      if (node.expressions.length === 0) return node.quasis.map((q) => q.value.cooked ?? "").join("");
      let out = "";
      for (let i = 0; i < node.quasis.length; i++) {
        out += node.quasis[i]?.value.cooked ?? "";
        const expr = node.expressions[i];
        if (expr) {
          const v = constFold(expr, depth + 1);
          if (v === undefined) return undefined;
          out += v;
        }
      }
      return out;
    }
    case "BinaryExpression": {
      if (node.operator !== "+") return undefined;
      const l = constFold(node.left as t.Node, depth + 1);
      const r = constFold(node.right, depth + 1);
      return l !== undefined && r !== undefined ? l + r : undefined;
    }
    case "ParenthesizedExpression":
    case "TSAsExpression":
    case "TSNonNullExpression":
      return constFold(node.expression, depth + 1);
    case "CallExpression": {
      const c = node.callee;
      // String.fromCharCode(104, 105)
      if (
        c.type === "MemberExpression" &&
        c.object.type === "Identifier" &&
        c.object.name === "String" &&
        c.property.type === "Identifier" &&
        c.property.name === "fromCharCode"
      ) {
        const codes: number[] = [];
        for (const a of node.arguments) {
          if (a.type !== "NumericLiteral") return undefined;
          codes.push(a.value);
        }
        return String.fromCharCode(...codes);
      }
      // atob("...") on a literal
      if (c.type === "Identifier" && c.name === "atob" && node.arguments.length === 1) {
        const v = constFold(node.arguments[0], depth + 1);
        return v === undefined ? undefined : safeBase64(v);
      }
      // ["a","b"].join("")  and "abc".split("").reverse().join("")
      if (c.type === "MemberExpression" && c.property.type === "Identifier" && c.property.name === "join") {
        const sep = node.arguments[0] ? constFold(node.arguments[0], depth + 1) : ",";
        const arr = foldArray(c.object, depth + 1);
        if (arr && sep !== undefined) return arr.join(sep);
      }
      // Buffer.from("...", "base64").toString()
      if (
        c.type === "MemberExpression" &&
        c.property.type === "Identifier" &&
        c.property.name === "toString" &&
        c.object.type === "CallExpression"
      ) {
        const inner = c.object;
        const ic = inner.callee;
        if (
          ic.type === "MemberExpression" &&
          ic.object.type === "Identifier" &&
          ic.object.name === "Buffer" &&
          ic.property.type === "Identifier" &&
          ic.property.name === "from"
        ) {
          const data = constFold(inner.arguments[0], depth + 1);
          const enc = constFold(inner.arguments[1], depth + 1);
          if (data !== undefined && (enc === "base64" || enc === "base64url")) return safeBase64(data);
          if (data !== undefined && enc === "hex") return safeHex(data);
        }
      }
      return undefined;
    }
    default:
      return undefined;
  }
}

function foldArray(node: t.Node, depth: number): string[] | undefined {
  if (depth > 12) return undefined;
  if (node.type === "ArrayExpression") {
    const out: string[] = [];
    for (const el of node.elements) {
      if (!el || el.type === "SpreadElement") return undefined;
      const v = constFold(el, depth + 1);
      if (v === undefined) return undefined;
      out.push(v);
    }
    return out;
  }
  return undefined;
}

/** Collect every literal string fragment inside an expression, even if the whole is not foldable. */
export function stringParts(node: t.Node | null | undefined, depth = 0, out: string[] = []): string[] {
  if (!node || depth > 10) return out;
  switch (node.type) {
    case "StringLiteral":
      out.push(node.value);
      break;
    case "TemplateLiteral":
      for (const q of node.quasis) out.push(q.value.cooked ?? "");
      for (const e of node.expressions) stringParts(e, depth + 1, out);
      break;
    case "BinaryExpression":
      stringParts(node.left as t.Node, depth + 1, out);
      stringParts(node.right, depth + 1, out);
      break;
    case "CallExpression":
      for (const a of node.arguments) stringParts(a, depth + 1, out);
      break;
    case "ArrayExpression":
      for (const e of node.elements) if (e) stringParts(e, depth + 1, out);
      break;
    default:
      break;
  }
  return out;
}

export function safeBase64(input: string): string | undefined {
  if (input.length > 400_000) return undefined;
  const cleaned = input.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(cleaned)) return undefined;
  try {
    const text = Buffer.from(cleaned, "base64").toString("utf8");
    return printableRatio(text) >= 0.85 ? text : undefined;
  } catch {
    return undefined;
  }
}

function safeHex(input: string): string | undefined {
  if (input.length > 400_000 || !/^(?:[0-9a-fA-F]{2})+$/.test(input)) return undefined;
  const text = Buffer.from(input, "hex").toString("utf8");
  return printableRatio(text) >= 0.85 ? text : undefined;
}

export function printableRatio(text: string): number {
  if (text.length === 0) return 0;
  let ok = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c > 159) ok++;
  }
  return ok / text.length;
}

export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Names of dangerous constructs found inside statically-decoded text. Only token names are returned. */
const DECODED_MARKERS: Array<[string, RegExp]> = [
  ["child_process", /child_process/],
  ["eval(", /\beval\s*\(/],
  ["new Function", /new\s+Function\s*\(/],
  ["require(", /\brequire\s*\(/],
  ["process.env", /process\.env/],
  ["http(s) URL", /https?:\/\/[^\s"'`]+/],
  ["curl/wget", /\b(?:curl|wget)\b/],
  ["shell invocation", /\b(?:\/bin\/(?:ba)?sh|powershell|cmd\.exe)\b/i],
  ["fs access", /\bfs\.(?:readFile|writeFile|readdir)/],
  ["net/socket", /\b(?:net\.Socket|net\.connect|dgram|WebSocket)\b/],
];

export function decodedMarkers(text: string): string[] {
  const found: string[] = [];
  for (const [name, re] of DECODED_MARKERS) if (re.test(text)) found.push(name);
  return found;
}

const SENSITIVE_PATH_RE =
  /(\.ssh\b|id_rsa|id_ed25519|id_ecdsa|\.aws[\\/]|\.npmrc|\.netrc|\.git-credentials|\.docker[\\/]config\.json|\.kube[\\/]config|\.config[\\/]gcloud|login data|\bcookies\b|local state|wallet\.dat|keychain|\/etc\/passwd|\/etc\/shadow|\.bash_history|\.zsh_history|(^|[\\/])\.env(\.|$)|metamask|exodus|\.gnupg|known_hosts)/i;

export function sensitivePathMatch(parts: string[]): string | undefined {
  for (const p of parts) {
    const m = SENSITIVE_PATH_RE.exec(p);
    if (m) return m[0].toLowerCase();
  }
  return undefined;
}

const SENSITIVE_ENV_RE =
  /(token|secret|passw(or)?d|passwd|api[_-]?key|private[_-]?key|credential|auth|session|cookie|aws_|npm_config|github_|gitlab_|ci_job|ssh|bearer|access[_-]?key)/i;

export function isSensitiveEnvName(name: string): boolean {
  return SENSITIVE_ENV_RE.test(name);
}

const HOST_RULES: Array<[HostClass, RegExp]> = [
  [
    "paste-or-raw-hosting",
    /(^|\.)(pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w+|0x0\.st|transfer\.sh|anonfiles\.com|raw\.githubusercontent\.com|gist\.githubusercontent\.com|ipfs\.io|dweb\.link)$/i,
  ],
  [
    "webhook-endpoint",
    /(^|\.)(discord(app)?\.com|api\.telegram\.org|hooks\.slack\.com|webhook\.site|requestbin\.\w+|pipedream\.net|burpcollaborator\.net|interact\.sh|oast\.\w+)$/i,
  ],
  [
    "tunnel",
    /(^|\.)(ngrok\.io|ngrok-free\.app|ngrok\.app|trycloudflare\.com|loca\.lt|serveo\.net|localhost\.run)$/i,
  ],
  ["url-shortener", /(^|\.)(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|t\.me)$/i],
  [
    "recon-service",
    /(^|\.)(ipinfo\.io|ifconfig\.me|api\.ipify\.org|ip-api\.com|icanhazip\.com|checkip\.amazonaws\.com)$/i,
  ],
];

export function classifyHost(host: string): HostClass | undefined {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) && host !== "127.0.0.1" && host !== "0.0.0.0") return "ip-literal";
  for (const [cls, re] of HOST_RULES) {
    if (re.test(host)) {
      // Discord / telegram classification only applies to their webhook/bot paths; hosts alone are enough here.
      return cls;
    }
  }
  return undefined;
}

export function parseHost(url: string): string | undefined {
  try {
    const u = new URL(url);
    return u.hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

export const SENSITIVE_MODULES = new Set([
  "child_process",
  "vm",
  "worker_threads",
  "net",
  "tls",
  "dgram",
  "dns",
  "cluster",
]);

export const NETWORK_MODULES = new Set([
  "http",
  "https",
  "http2",
  "net",
  "tls",
  "dgram",
  "dns",
  "axios",
  "got",
  "node-fetch",
  "undici",
  "request",
  "superagent",
  "ky",
  "needle",
  "ws",
  "socket.io-client",
  "cross-fetch",
  "isomorphic-fetch",
]);

export const PROCESS_MODULES = new Set(["child_process", "execa", "shelljs", "cross-spawn"]);

export function normalizeModule(name: string): string {
  return name.startsWith("node:") ? name.slice(5) : name;
}
