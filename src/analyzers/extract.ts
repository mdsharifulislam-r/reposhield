import { parse, type ParserPlugin } from "@babel/parser";
import traverseModule, { type NodePath, type Scope } from "@babel/traverse";
import * as t from "@babel/types";
import { emptyFacts, isConfigFilePath, type FileFacts, type Site, type TaintKind } from "./facts.js";
import {
  NETWORK_MODULES,
  PROCESS_MODULES,
  classifyHost,
  constFold,
  decodedMarkers,
  isSensitiveEnvName,
  normalizeModule,
  parseHost,
  safeBase64,
  sensitivePathMatch,
  shannonEntropy,
  stringParts,
} from "./helpers.js";

type TraverseFn = typeof traverseModule;
const traverse: TraverseFn =
  (traverseModule as unknown as { default?: TraverseFn }).default ?? traverseModule;

interface Alias {
  module: string;
  member?: string | undefined;
}

interface CalleeInfo {
  api: string;
  name?: string | undefined;
  module?: string | undefined;
  global: boolean;
  hidden?: boolean;
}

type AnyMember = t.MemberExpression | t.OptionalMemberExpression;
type AnyCall = t.CallExpression | t.OptionalCallExpression | t.NewExpression;

const NETWORK_PSEUDO = new Set(["XMLHttpRequest", "WebSocket", "EventSource"]);
const GLOBAL_OBJECTS = new Set(["global", "globalThis", "window", "self"]);
const NON_IO_NAMES = new Set([
  "create",
  "createServer",
  "createAgent",
  "Agent",
  "Server",
  "on",
  "once",
  "off",
  "addListener",
  "removeListener",
  "emit",
  "close",
  "destroy",
  "setHeader",
  "setNoDelay",
  "unref",
  "ref",
  "listen",
  "address",
  "isIP",
  "isIPv4",
  "isIPv6",
  "setTimeout",
  "setEncoding",
  "pipe",
  "STATUS_CODES",
  "METHODS",
]);
const FS_MODULES = new Set(["fs", "fs/promises"]);
const FS_READ = new Set([
  "readFile",
  "readFileSync",
  "createReadStream",
  "readdir",
  "readdirSync",
  "copyFile",
  "copyFileSync",
  "cp",
  "cpSync",
  "open",
  "openSync",
  "opendir",
  "opendirSync",
]);
const FS_WRITE = new Set(["writeFile", "writeFileSync", "appendFile", "appendFileSync", "createWriteStream"]);
const FS_CHMOD = new Set(["chmod", "chmodSync", "fchmod", "fchmodSync"]);
const DECODE_ENCODINGS = new Set(["base64", "base64url", "hex"]);
const ZLIB_DECODE = new Set([
  "inflate",
  "inflateSync",
  "gunzip",
  "gunzipSync",
  "unzip",
  "unzipSync",
  "brotliDecompress",
  "brotliDecompressSync",
  "inflateRaw",
  "inflateRawSync",
]);
const DANGEROUS_COMPUTED = new Set(["eval", "Function", "require", "process", "child_process"]);
const MAX_BLOBS = 20;

// Tab, newline, carriage return, printable ASCII, and anything above Latin-1 control range.
// eslint-disable-next-line no-control-regex
const PRINTABLE_TEXT = /^[\x09\x0a\x0d\x20-\x7e\u00a0-\uffff]*$/;

function isMember(n: t.Node | null | undefined): n is AnyMember {
  return !!n && (n.type === "MemberExpression" || n.type === "OptionalMemberExpression");
}

function isFunctionNode(n: t.Node | null | undefined): n is t.ArrowFunctionExpression | t.FunctionExpression {
  return !!n && (n.type === "ArrowFunctionExpression" || n.type === "FunctionExpression");
}

function propName(m: AnyMember): string | undefined {
  const p = m.property;
  if (!m.computed) return p.type === "Identifier" ? p.name : undefined;
  return constFold(p);
}

function parseWithFallback(code: string, rel: string): t.File {
  const isTs = /\.(c|m)?tsx?$/i.test(rel);
  const isTsx = /\.tsx$/i.test(rel);
  const attempts: ParserPlugin[][] = isTs
    ? [isTsx ? ["typescript", "jsx"] : ["typescript"]]
    : [["jsx"], ["typescript", "jsx"], ["jsx", "flow"]];
  let lastErr: unknown;
  for (const plugins of attempts) {
    try {
      return parse(code, {
        sourceType: "unambiguous",
        errorRecovery: true,
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
        allowImportExportEverywhere: true,
        allowSuperOutsideMethod: true,
        allowUndeclaredExports: true,
        plugins,
      });
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}

/**
 * Parse `code` and extract behavioural facts. This is purely static: the source
 * is parsed and walked, never executed, evaluated, or imported.
 */
export function extractFacts(code: string, rel: string): FileFacts {
  const facts = emptyFacts(rel, isConfigFilePath(rel));
  let ast: t.File;
  try {
    ast = parseWithFallback(code, rel);
  } catch (err) {
    facts.parseError = err instanceof Error ? (err.message.split("\n")[0] ?? "parse error") : "parse error";
    return facts;
  }
  facts.parsed = true;

  const aliases = new Map<t.Node, Alias>();
  const taint = new Map<t.Node, Set<TaintKind>>();
  const pathParts = new Map<t.Node, string[]>();
  const hexIdents = new Set<string>();
  let escapeCount = 0;
  let literalChars = 0;

  const siteOf = (node: t.Node, path: NodePath): Site => {
    const loc = node.loc;
    return {
      line: loc?.start.line ?? 1,
      column: (loc?.start.column ?? 0) + 1,
      ...(loc ? { endLine: loc.end.line, endColumn: loc.end.column + 1 } : {}),
      topLevel: path.getFunctionParent() === null,
    };
  };

  // ---------------------------------------------------------------- aliases
  const rootAlias = (node: t.Node | null | undefined, scope: Scope, depth = 0): Alias | undefined => {
    if (!node || depth > 15) return undefined;
    switch (node.type) {
      case "Identifier": {
        const b = scope.getBinding(node.name);
        return b ? aliases.get(b.identifier) : undefined;
      }
      case "CallExpression":
      case "OptionalCallExpression": {
        const cal = node.callee;
        const isRequire =
          (cal.type === "Identifier" && cal.name === "require") ||
          (isMember(cal) && propName(cal) === "require") ||
          cal.type === "Import";
        if (isRequire) {
          const m = constFold(node.arguments[0]);
          return m !== undefined ? { module: normalizeModule(m) } : undefined;
        }
        return rootAlias(cal, scope, depth + 1);
      }
      case "NewExpression": {
        const c = node.callee;
        if (c.type === "Identifier" && !scope.getBinding(c.name) && NETWORK_PSEUDO.has(c.name)) {
          return { module: c.name };
        }
        return rootAlias(c, scope, depth + 1);
      }
      case "MemberExpression":
      case "OptionalMemberExpression":
        return rootAlias(node.object, scope, depth + 1);
      case "AwaitExpression":
        return rootAlias(node.argument, scope, depth + 1);
      case "ParenthesizedExpression":
      case "TSAsExpression":
      case "TSNonNullExpression":
        return rootAlias(node.expression, scope, depth + 1);
      default:
        return undefined;
    }
  };

  const aliasForInit = (init: t.Node, scope: Scope): Alias | undefined => {
    if (isMember(init)) {
      const r = rootAlias(init.object, scope);
      if (!r) return undefined;
      return r.member ? { module: r.module } : { module: r.module, member: propName(init) };
    }
    if (init.type === "CallExpression") {
      const c = init.callee;
      const cname = c.type === "Identifier" ? c.name : isMember(c) ? propName(c) : undefined;
      if (cname === "promisify" && init.arguments[0]) {
        const inner = isMember(init.arguments[0] as t.Node)
          ? aliasForInit(init.arguments[0] as t.Node, scope)
          : rootAlias(init.arguments[0] as t.Node, scope);
        if (inner) return inner;
      }
    }
    return rootAlias(init, scope);
  };

  const bindPattern = (id: t.Node, al: Alias | undefined, scope: Scope): void => {
    if (!al) return;
    if (id.type === "Identifier") {
      const b = scope.getBinding(id.name);
      aliases.set(b ? b.identifier : id, al);
    } else if (id.type === "ObjectPattern") {
      for (const prop of id.properties) {
        if (prop.type !== "ObjectProperty") continue;
        const key =
          prop.key.type === "Identifier" && !prop.computed
            ? prop.key.name
            : prop.key.type === "StringLiteral"
              ? prop.key.value
              : undefined;
        const val = prop.value.type === "AssignmentPattern" ? prop.value.left : prop.value;
        if (key && val.type === "Identifier") {
          const b = scope.getBinding(val.name);
          aliases.set(b ? b.identifier : val, { module: al.module, member: key });
        }
      }
    }
  };

  // ------------------------------------------------------------ callee info
  const resolveCallee = (calleeIn: t.Node, scope: Scope): CalleeInfo | undefined => {
    let c: t.Node = calleeIn;
    while (c.type === "ParenthesizedExpression") c = c.expression;
    if (c.type === "SequenceExpression") c = c.expressions[c.expressions.length - 1] ?? c;
    if (c.type === "Import") return { api: "import", name: "import", global: true };
    if (c.type === "Identifier") {
      const b = scope.getBinding(c.name);
      if (!b) return { api: c.name, name: c.name, global: true };
      const al = aliases.get(b.identifier);
      if (al) {
        const nm = al.member ?? al.module;
        return {
          api: al.member ? `${al.module}.${al.member}` : al.module,
          name: nm,
          module: al.module,
          global: false,
        };
      }
      return { api: c.name, name: c.name, global: false };
    }
    if (isMember(c)) {
      const name = propName(c);
      const obj = c.object;
      if (obj.type === "Identifier" && !scope.getBinding(obj.name)) {
        if (GLOBAL_OBJECTS.has(obj.name) && name) {
          return {
            api: name,
            name,
            global: true,
            hidden: c.computed && c.property.type !== "StringLiteral",
          };
        }
        return { api: `${obj.name}.${name ?? "?"}`, name, global: true };
      }
      const root = rootAlias(obj, scope);
      if (root) return { api: `${root.module}.${name ?? "?"}`, module: root.module, name, global: false };
      return { api: `?.${name ?? "?"}`, name, global: false };
    }
    return undefined;
  };

  // ------------------------------------------------------------------ taint
  const union = (...sets: Array<Set<TaintKind> | undefined>): Set<TaintKind> => {
    const out = new Set<TaintKind>();
    for (const s of sets) if (s) for (const k of s) out.add(k);
    return out;
  };

  const isProcessEnv = (n: t.Node, scope: Scope): boolean =>
    isMember(n) &&
    n.object.type === "Identifier" &&
    n.object.name === "process" &&
    !scope.getBinding("process") &&
    propName(n) === "env";

  const isNetworkCall = (ci: CalleeInfo, isNew: boolean): boolean => {
    if (ci.global) {
      if (ci.name === "fetch" && !isNew) return true;
      if (isNew && ci.name && NETWORK_PSEUDO.has(ci.name)) return true;
      if (ci.api === "navigator.sendBeacon") return true;
      return false;
    }
    if (!ci.module) return false;
    if (!(NETWORK_MODULES.has(ci.module) || NETWORK_PSEUDO.has(ci.module))) return false;
    return !(ci.name && NON_IO_NAMES.has(ci.name));
  };

  const isDecodeCall = (ci: CalleeInfo, node: AnyCall): string | undefined => {
    const args = node.arguments as t.Node[];
    const isNew = node.type === "NewExpression";
    if (ci.global && (ci.api === "Buffer.from" || (isNew && ci.name === "Buffer"))) {
      const enc = constFold(args[1])?.toLowerCase();
      if (enc && DECODE_ENCODINGS.has(enc)) return `Buffer.from(…, '${enc}')`;
      return undefined;
    }
    if (ci.global && ci.name === "atob" && !isNew) return "atob";
    if (ci.global && (ci.api === "String.fromCharCode" || ci.api === "String.fromCodePoint")) {
      const many = args.length >= 8 || args.some((a) => a.type === "SpreadElement");
      return many ? ci.api : undefined;
    }
    if (ci.module === "crypto" && (ci.name === "createDecipheriv" || ci.name === "createDecipher")) {
      return `crypto.${ci.name}`;
    }
    if (ci.module === "zlib" && ci.name && ZLIB_DECODE.has(ci.name)) return `zlib.${ci.name}`;
    return undefined;
  };

  const exprTaint = (n: t.Node | null | undefined, scope: Scope, depth = 0): Set<TaintKind> => {
    const empty = new Set<TaintKind>();
    if (!n || depth > 25) return empty;
    switch (n.type) {
      case "Identifier": {
        const b = scope.getBinding(n.name);
        return b ? (taint.get(b.identifier) ?? empty) : empty;
      }
      case "TemplateLiteral":
        return union(...n.expressions.map((e) => exprTaint(e, scope, depth + 1)));
      case "TaggedTemplateExpression":
        return exprTaint(n.quasi, scope, depth + 1);
      case "MemberExpression":
      case "OptionalMemberExpression": {
        if (isProcessEnv(n, scope)) return new Set<TaintKind>(["env"]);
        if (isMember(n.object) && isProcessEnv(n.object, scope)) {
          const key = propName(n);
          const out = new Set<TaintKind>(["env"]);
          if (key === undefined || isSensitiveEnvName(key)) out.add("secret");
          return out;
        }
        if (n.object.type === "Identifier" && !scope.getBinding(n.object.name)) {
          const key = propName(n);
          if (n.object.name === "document" && key === "cookie") return new Set<TaintKind>(["secret"]);
          if ((n.object.name === "localStorage" || n.object.name === "sessionStorage") && key) {
            return new Set<TaintKind>(["secret"]);
          }
        }
        return exprTaint(n.object, scope, depth + 1);
      }
      case "CallExpression":
      case "OptionalCallExpression":
      case "NewExpression": {
        const out = new Set<TaintKind>();
        const ci = resolveCallee(n.callee, scope);
        const isNew = n.type === "NewExpression";
        if (ci) {
          if (isNetworkCall(ci, isNew)) out.add("network");
          if (isDecodeCall(ci, n)) out.add("decoded");
          if (
            ci.module === "os" &&
            ci.name &&
            ["homedir", "userInfo", "hostname", "networkInterfaces"].includes(ci.name)
          ) {
            out.add("hostinfo");
          }
          if (ci.module && FS_MODULES.has(ci.module) && ci.name && FS_READ.has(ci.name)) {
            if (sensitivePathMatch(argPathParts(n.arguments[0] as t.Node | undefined, scope)))
              out.add("secret");
          }
        }
        for (const a of n.arguments) {
          if (isFunctionNode(a as t.Node)) continue;
          for (const k of exprTaint(a as t.Node, scope, depth + 1)) out.add(k);
        }
        if (isMember(n.callee)) for (const k of exprTaint(n.callee.object, scope, depth + 1)) out.add(k);
        return out;
      }
      case "AwaitExpression":
      case "UnaryExpression":
      case "SpreadElement":
      case "YieldExpression":
        return exprTaint(n.argument, scope, depth + 1);
      case "ParenthesizedExpression":
      case "TSAsExpression":
      case "TSNonNullExpression":
      case "TypeCastExpression":
        return exprTaint(n.expression, scope, depth + 1);
      case "BinaryExpression":
      case "LogicalExpression":
        return union(exprTaint(n.left as t.Node, scope, depth + 1), exprTaint(n.right, scope, depth + 1));
      case "ConditionalExpression":
        return union(exprTaint(n.consequent, scope, depth + 1), exprTaint(n.alternate, scope, depth + 1));
      case "SequenceExpression":
        return exprTaint(n.expressions[n.expressions.length - 1], scope, depth + 1);
      case "AssignmentExpression":
        return exprTaint(n.right, scope, depth + 1);
      case "ArrayExpression":
        return union(...n.elements.map((e) => exprTaint(e, scope, depth + 1)));
      case "ObjectExpression":
        return union(
          ...n.properties.map((p) =>
            p.type === "ObjectProperty"
              ? exprTaint(p.value, scope, depth + 1)
              : p.type === "SpreadElement"
                ? exprTaint(p.argument, scope, depth + 1)
                : undefined,
          ),
        );
      default:
        return empty;
    }
  };

  const argPathParts = (n: t.Node | undefined, scope: Scope): string[] => {
    if (!n) return [];
    const direct = stringParts(n);
    if (n.type === "Identifier") {
      const b = scope.getBinding(n.name);
      const stored = b ? pathParts.get(b.identifier) : undefined;
      if (stored) return [...direct, ...stored];
    }
    return direct;
  };

  const addTaint = (id: t.Node, kinds: Set<TaintKind>, scope: Scope): void => {
    if (kinds.size === 0) return;
    let target: t.Node | undefined = id;
    while (target && isMember(target)) target = target.object;
    if (!target) return;
    const names: t.Identifier[] = [];
    if (target.type === "Identifier") names.push(target);
    else if (target.type === "ObjectPattern" || target.type === "ArrayPattern") {
      for (const v of Object.values(t.getBindingIdentifiers(target))) {
        if (!Array.isArray(v)) names.push(v);
      }
    }
    for (const ident of names) {
      const b = scope.getBinding(ident.name);
      const key = b ? b.identifier : ident;
      taint.set(key, union(taint.get(key), kinds));
    }
  };

  const markCallbackParams = (args: t.Node[], kinds: Set<TaintKind>, path: NodePath): void => {
    if (kinds.size === 0) return;
    const argPaths = path.get("arguments") as NodePath[];
    argPaths.forEach((ap, i) => {
      const an = args[i];
      if (!isFunctionNode(an)) return;
      for (const p of an.params) addTaint(p, kinds, ap.scope);
    });
  };

  // ---------------------------------------------------------------- sinks
  const urlFromArgs = (args: t.Node[]): { url?: string; host?: string } => {
    for (const a of args) {
      const candidates: string[] = [];
      if (a.type === "ObjectExpression") {
        for (const p of a.properties) {
          if (p.type !== "ObjectProperty") continue;
          const k =
            p.key.type === "Identifier" ? p.key.name : p.key.type === "StringLiteral" ? p.key.value : "";
          if (["url", "uri", "href", "hostname", "host", "baseURL"].includes(k)) {
            candidates.push(...stringParts(p.value));
          }
        }
      } else {
        candidates.push(...stringParts(a));
      }
      for (const c of candidates) {
        if (/^(https?|wss?|ftp):\/\//i.test(c)) {
          const host = parseHost(c);
          return { url: c.length > 120 ? `${c.slice(0, 117)}…` : c, ...(host ? { host } : {}) };
        }
        if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(c) && a.type === "ObjectExpression") {
          return { host: c.toLowerCase() };
        }
      }
    }
    return {};
  };

  const handleCall = (path: NodePath<AnyCall>): void => {
    const node = path.node;
    const scope = path.scope;
    const isNew = node.type === "NewExpression";
    const args = node.arguments as t.Node[];
    // Dean Edwards style packer: eval(function(p,a,c,k,e,d){...}). Matched on the AST so a
    // detector pattern inside a string, regex, or comment is not mistaken for a packer.
    const first = args[0];
    const packerFn =
      first?.type === "CallExpression" && first.callee.type === "FunctionExpression"
        ? first.callee
        : first?.type === "FunctionExpression"
          ? first
          : undefined;
    if (
      !isNew &&
      node.callee.type === "Identifier" &&
      node.callee.name === "eval" &&
      packerFn &&
      packerFn.params.length >= 5 &&
      ["p", "a", "c", "k", "e"].every((n, i) => {
        const prm = packerFn.params[i];
        return prm?.type === "Identifier" && prm.name === n;
      })
    ) {
      facts.obfuscation.push({
        kind: "packer",
        detail: "Dean Edwards style eval(function(p,a,c,k,e,d) packer",
      });
    }
    const ci = resolveCallee(node.callee, scope);
    if (!ci) return;
    const site = siteOf(node, path);
    const argTaint = union(...args.filter((a) => !isFunctionNode(a)).map((a) => exprTaint(a, scope)));

    // require / dynamic import -------------------------------------------
    if (!isNew && ci.global && ci.name === "require" && args[0]) {
      const folded = constFold(args[0]);
      if (folded !== undefined) {
        facts.imports.push({
          module: normalizeModule(folded),
          hidden: args[0].type !== "StringLiteral",
          dynamic: false,
          site,
        });
      } else {
        facts.imports.push({ module: "?", hidden: false, dynamic: true, site });
      }
    }
    if (!isNew && ci.api === "import" && args[0]) {
      const folded = constFold(args[0]);
      if (folded !== undefined) {
        facts.imports.push({
          module: normalizeModule(folded),
          hidden: args[0].type !== "StringLiteral",
          dynamic: false,
          site,
        });
      } else {
        facts.imports.push({ module: "?", hidden: false, dynamic: true, site });
        facts.dynamicExec.push({ kind: "dynamic-import", literalArg: false, taint: [...argTaint], site });
      }
    }

    // dynamic code execution ---------------------------------------------
    if (ci.global && ci.name === "eval" && !isNew) {
      facts.dynamicExec.push({
        kind: "eval",
        literalArg: args[0]?.type === "StringLiteral",
        taint: [...argTaint],
        site,
      });
      if (ci.hidden) facts.hiddenAccess.push({ name: "eval", site });
    }
    if (ci.global && ci.name === "Function") {
      facts.dynamicExec.push({
        kind: "Function",
        literalArg: args.length > 0 && args.every((a) => constFold(a) !== undefined),
        taint: [...argTaint],
        site,
      });
      if (ci.hidden) facts.hiddenAccess.push({ name: "Function", site });
    }
    if (isMember(node.callee) && propName(node.callee) === "constructor") {
      const o = node.callee.object;
      if (isMember(o) && propName(o) === "constructor") {
        facts.dynamicExec.push({
          kind: "Function",
          literalArg: args.length > 0 && args.every((a) => constFold(a) !== undefined),
          taint: [...argTaint],
          site,
        });
      }
    }
    if (
      ci.module === "vm" &&
      ci.name &&
      ["runInContext", "runInNewContext", "runInThisContext", "Script", "compileFunction"].includes(ci.name)
    ) {
      facts.dynamicExec.push({
        kind: "vm",
        literalArg: constFold(args[0]) !== undefined,
        taint: [...argTaint],
        site,
      });
    }
    if (
      ci.global &&
      !isNew &&
      (ci.name === "setTimeout" || ci.name === "setInterval" || ci.name === "setImmediate") &&
      args[0] &&
      !isFunctionNode(args[0])
    ) {
      const a0 = args[0];
      const stringish =
        a0.type === "StringLiteral" ||
        a0.type === "TemplateLiteral" ||
        a0.type === "BinaryExpression" ||
        exprTaint(a0, scope).size > 0;
      if (stringish) {
        facts.dynamicExec.push({
          kind: "timer-string",
          literalArg: a0.type === "StringLiteral",
          taint: [...exprTaint(a0, scope)],
          site,
        });
      }
    }
    if (isMember(node.callee) && propName(node.callee) === "_compile") {
      facts.dynamicExec.push({ kind: "compile", literalArg: false, taint: [...argTaint], site });
    }

    // process execution --------------------------------------------------
    if (ci.module && PROCESS_MODULES.has(ci.module)) {
      const nm = ci.name ?? "";
      const isCp = ci.module === "child_process";
      const known = isCp
        ? ["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"].includes(nm)
        : true;
      if (known && !NON_IO_NAMES.has(nm)) {
        const optionShell = args.some(
          (a) =>
            a.type === "ObjectExpression" &&
            a.properties.some(
              (p) =>
                p.type === "ObjectProperty" &&
                ((p.key.type === "Identifier" && p.key.name === "shell") ||
                  (p.key.type === "StringLiteral" && p.key.value === "shell")) &&
                !(p.value.type === "BooleanLiteral" && p.value.value === false),
            ),
        );
        const shell =
          nm === "exec" || nm === "execSync" || (ci.module === "shelljs" && nm === "exec") || optionShell;
        const cmd = constFold(args[0]);
        const arr = args[1];
        const arrParts =
          arr && arr.type === "ArrayExpression"
            ? arr.elements.map((e) => (e && e.type !== "SpreadElement" ? constFold(e) : undefined))
            : undefined;
        const arrLiteral =
          !arr || arr.type !== "ArrayExpression" ? true : (arrParts ?? []).every((p) => p !== undefined);
        const literal = cmd !== undefined && arrLiteral;
        facts.processExec.push({
          api: `${ci.module}.${nm || "call"}`,
          literalCommand: literal,
          shell,
          taint: [...argTaint],
          ...(literal ? { commandText: [cmd, ...(arrParts ?? [])].join(" ").slice(0, 500) } : {}),
          site,
        });
      }
    }

    // decoding -----------------------------------------------------------
    const decodeApi = isDecodeCall(ci, node);
    if (decodeApi) {
      const folded = constFold(args[0]);
      const decoded = folded !== undefined && /base64|atob/i.test(decodeApi) ? safeBase64(folded) : undefined;
      facts.decode.push({
        api: decodeApi,
        literalInput: folded !== undefined,
        decodedMarkers: decoded ? decodedMarkers(decoded) : [],
        site,
      });
    }

    // network ------------------------------------------------------------
    if (isNetworkCall(ci, isNew)) {
      const { url, host } = urlFromArgs(args);
      const nm = ci.name ?? "";
      const urlIsPlain = (n: t.Node | undefined): boolean =>
        !!n && (n.type === "Identifier" || isMember(n) || n.type === "StringLiteral");
      const sendsBody = ["write", "end", "send", "post", "put", "patch", "emit", "publish"].includes(nm);
      const dataArgs = sendsBody ? args : args.slice(1);
      const first = args[0];
      const dataTaint = union(
        ...dataArgs.filter((a) => !isFunctionNode(a)).map((a) => exprTaint(a, scope)),
        first && !urlIsPlain(first) && !sendsBody ? exprTaint(first, scope) : undefined,
      );
      const hostClass = host ? classifyHost(host) : undefined;
      facts.network.push({
        api: ci.api,
        ...(ci.module ? { module: ci.module } : {}),
        ...(url ? { urlLiteral: url } : {}),
        ...(host ? { host } : {}),
        ...(hostClass ? { hostClass } : {}),
        dataTaint: [...dataTaint],
        site,
      });
      markCallbackParams(args, new Set<TaintKind>(["network"]), path);
    }

    // filesystem ---------------------------------------------------------
    if (ci.module && FS_MODULES.has(ci.module) && ci.name) {
      if (FS_WRITE.has(ci.name)) {
        const dataTaint = ci.name === "createWriteStream" ? new Set<TaintKind>() : exprTaint(args[1], scope);
        facts.fsWrites.push({ api: `fs.${ci.name}`, taint: [...dataTaint], site });
      }
      if (FS_CHMOD.has(ci.name)) {
        const mode = args[1];
        const isExec =
          (mode?.type === "NumericLiteral" && (mode.value & 0o111) !== 0) ||
          (mode?.type === "StringLiteral" && /^[0-7]*[1357][0-7]{0,2}$|^\+x$/.test(mode.value));
        if (isExec) facts.chmodExec.push(site);
      }
      if (FS_READ.has(ci.name)) {
        const hit = sensitivePathMatch(argPathParts(args[0], scope));
        if (hit) facts.sensitiveReads.push({ target: hit, site });
      }
    }
    // stream.pipe(fs.createWriteStream(...)) with network data
    if (isMember(node.callee) && propName(node.callee) === "pipe" && args[0]) {
      const srcTaint = exprTaint(node.callee.object, scope);
      const dest = rootAlias(args[0], scope);
      if (srcTaint.size > 0 && dest && FS_MODULES.has(dest.module)) {
        facts.fsWrites.push({ api: "stream.pipe(fs.createWriteStream)", taint: [...srcTaint], site });
      }
    }

    // propagate taint into callback parameters (`.then(cb)`, `.on('data', cb)`)
    if (isMember(node.callee)) {
      const objTaint = exprTaint(node.callee.object, scope);
      markCallbackParams(args, objTaint, path);
    }
  };

  // ------------------------------------------------------------- traversal
  traverse(ast, {
    ImportDeclaration(path) {
      const mod = normalizeModule(path.node.source.value);
      facts.imports.push({ module: mod, hidden: false, dynamic: false, site: siteOf(path.node, path) });
      for (const spec of path.node.specifiers) {
        const b = path.scope.getBinding(spec.local.name);
        const key = b ? b.identifier : spec.local;
        if (spec.type === "ImportSpecifier") {
          const imported = spec.imported.type === "Identifier" ? spec.imported.name : spec.imported.value;
          aliases.set(key, { module: mod, member: imported });
        } else {
          aliases.set(key, { module: mod });
        }
      }
    },
    VariableDeclarator(path) {
      const { id, init } = path.node;
      if (!init) return;
      const scope = path.scope;
      const al = aliasForInit(init, scope);
      bindPattern(id, al, scope);
      if (al === undefined && isMember(init) === false && init.type === "Identifier") {
        // `const cp2 = cp` handled by rootAlias via aliasForInit
      }
      if (id.type === "Identifier") {
        const parts = stringParts(init);
        if (parts.length > 0) {
          const b = scope.getBinding(id.name);
          pathParts.set(b ? b.identifier : id, parts);
        }
      }
      if (isProcessEnv(init, scope) && id.type === "ObjectPattern") {
        for (const prop of id.properties) {
          if (prop.type === "RestElement") {
            facts.envReads.push({ whole: true, sensitive: false, site: siteOf(prop, path) });
          } else if (prop.type === "ObjectProperty") {
            const key =
              prop.key.type === "Identifier"
                ? prop.key.name
                : prop.key.type === "StringLiteral"
                  ? prop.key.value
                  : undefined;
            facts.envReads.push({
              ...(key ? { key } : {}),
              whole: false,
              sensitive: key ? isSensitiveEnvName(key) : false,
              site: siteOf(prop, path),
            });
          }
        }
      }
      addTaint(id, exprTaint(init, scope), scope);
    },
    AssignmentExpression(path) {
      const { left, right, operator } = path.node;
      const scope = path.scope;
      const kinds = exprTaint(right, scope);
      if (left.type === "Identifier") {
        const al = aliasForInit(right, scope);
        if (al && operator === "=") bindPattern(left, al, scope);
      }
      addTaint(left, kinds, scope);
    },
    CallExpression(path) {
      handleCall(path);
    },
    OptionalCallExpression(path) {
      handleCall(path);
    },
    NewExpression(path) {
      handleCall(path);
    },
    ImportExpression(path) {
      const src = path.node.source;
      const site = siteOf(path.node, path);
      const folded = constFold(src);
      if (folded !== undefined) {
        facts.imports.push({
          module: normalizeModule(folded),
          hidden: src.type !== "StringLiteral",
          dynamic: false,
          site,
        });
      } else {
        facts.imports.push({ module: "?", hidden: false, dynamic: true, site });
        facts.dynamicExec.push({
          kind: "dynamic-import",
          literalArg: false,
          taint: [...exprTaint(src, path.scope)],
          site,
        });
      }
    },
    MemberExpression(path) {
      memberVisit(path.node, path);
    },
    OptionalMemberExpression(path) {
      memberVisit(path.node, path);
    },
    Identifier(path) {
      if (/^_0x[0-9a-f]{3,}$/i.test(path.node.name)) hexIdents.add(path.node.name);
    },
    ArrayExpression(path) {
      const els = path.node.elements;
      if (els.length >= 30 && els.every((e) => e?.type === "StringLiteral")) {
        facts.obfuscation.push({
          kind: "string-array",
          detail: `array of ${els.length} string literals`,
          site: siteOf(path.node, path),
        });
      }
    },
    StringLiteral(path) {
      const raw = path.node.extra?.raw;
      if (typeof raw === "string") {
        literalChars += raw.length;
        const m = raw.match(/\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/g);
        if (m) escapeCount += m.length;
      }
      blobCheck(path.node.value, path.node, path);
    },
    TemplateLiteral(path) {
      if (path.node.expressions.length === 0 && path.node.quasis.length === 1) {
        blobCheck(path.node.quasis[0]?.value.cooked ?? "", path.node, path);
      }
    },
  });

  function memberVisit(node: AnyMember, path: NodePath): void {
    const scope = path.scope;
    const parent = path.parent;
    // process.env.KEY  /  process.env
    if (isProcessEnv(node, scope)) {
      const parentIsAccess = isMember(parent) && parent.object === node;
      if (!parentIsAccess) facts.envReads.push({ whole: true, sensitive: false, site: siteOf(node, path) });
    } else if (isMember(node.object) && isProcessEnv(node.object, scope)) {
      const key = propName(node);
      facts.envReads.push({
        ...(key ? { key } : {}),
        whole: false,
        sensitive: key === undefined ? false : isSensitiveEnvName(key),
        site: siteOf(node, path),
      });
    }
    // process.mainModule / process.binding
    if (node.object.type === "Identifier" && node.object.name === "process" && !scope.getBinding("process")) {
      const key = propName(node);
      if (key === "mainModule" || key === "binding" || key === "dlopen") {
        facts.hiddenAccess.push({ name: `process.${key}`, site: siteOf(node, path) });
      }
    }
    // globalThis["ev"+"al"]
    if (
      node.computed &&
      node.object.type === "Identifier" &&
      GLOBAL_OBJECTS.has(node.object.name) &&
      !scope.getBinding(node.object.name)
    ) {
      const folded = constFold(node.property);
      if (folded && DANGEROUS_COMPUTED.has(folded) && node.property.type !== "StringLiteral") {
        facts.hiddenAccess.push({ name: folded, site: siteOf(node, path) });
      }
    }
  }

  function blobCheck(value: string, node: t.Node, path: NodePath): void {
    if (value.length < 200 || facts.encodedBlobs.length >= MAX_BLOBS) return;
    if (value.startsWith("data:")) return;
    const isB64 = /^[A-Za-z0-9+/=_-]+$/.test(value);
    const isHex = /^[0-9a-fA-F]+$/.test(value);
    if (!isB64 && !isHex) return;
    const entropy = shannonEntropy(value.length > 4000 ? value.slice(0, 4000) : value);
    if (isHex ? entropy < 3.3 : entropy < 4.3) return;
    const decoded = isHex ? Buffer.from(value, "hex").toString("utf8") : safeBase64(value);
    const printable = decoded !== undefined && decoded.length > 0 && PRINTABLE_TEXT.test(decoded);
    facts.encodedBlobs.push({
      length: value.length,
      entropy: Math.round(entropy * 100) / 100,
      markers: printable && decoded ? decodedMarkers(decoded) : [],
      site: siteOf(node, path),
    });
  }

  // ------------------------------------------------- whole-file obfuscation
  if (hexIdents.size >= 6) {
    facts.obfuscation.push({
      kind: "hex-identifiers",
      detail: `${hexIdents.size} distinct identifiers shaped like _0x1a2b3c`,
    });
  }
  if (escapeCount >= 30 && (escapeCount * 4) / Math.max(literalChars, 1) >= 0.3) {
    facts.obfuscation.push({
      kind: "escape-density",
      detail: `${escapeCount} \\x/\\u escapes make up most of the string literal text`,
    });
  }
  let maxLine = 0;
  for (const line of code.split("\n")) if (line.length > maxLine) maxLine = line.length;
  if (maxLine >= 3000) {
    facts.obfuscation.push({ kind: "long-lines", detail: `longest line is ${maxLine} characters` });
  }
  const bang = code.match(/!!\[\]/g)?.length ?? 0;
  const plusEmpty = code.match(/\+\[\]/g)?.length ?? 0;
  if (bang >= 10 && plusEmpty >= 10) {
    facts.obfuscation.push({ kind: "jsfuck-like", detail: "dense !![] / +[] coercion sequences" });
  }
  if (
    /\.split\(['"]\|['"]\)/.test(code) &&
    /while\s*\(\s*(!!\[\]|true|!0|1)\s*\)/.test(code) &&
    (code.match(/case\s*['"]\d+['"]\s*:/g)?.length ?? 0) >= 3
  ) {
    facts.obfuscation.push({
      kind: "control-flow-flattening",
      detail: "split('|') dispatcher driving a while/switch loop",
    });
  }

  return facts;
}
