import type { SourceLocation } from "../core/types.js";

/** What kind of untrusted/sensitive data a value is believed to carry. */
export type TaintKind = "decoded" | "network" | "env" | "secret" | "hostinfo";

export type Site = SourceLocation & {
  /** True when the construct runs at module load (not inside any function). */
  topLevel: boolean;
};

export type HostClass =
  "paste-or-raw-hosting" | "webhook-endpoint" | "tunnel" | "url-shortener" | "ip-literal" | "recon-service";

export interface DynamicExecFact {
  kind: "eval" | "Function" | "vm" | "timer-string" | "compile" | "dynamic-import";
  /** Argument is a plain string literal (much lower risk than computed input). */
  literalArg: boolean;
  taint: TaintKind[];
  site: Site;
}

export interface ProcessExecFact {
  api: string;
  /** The command is a static string literal. */
  literalCommand: boolean;
  /** `shell: true` or an `exec`-style API that always uses a shell. */
  shell: boolean;
  taint: TaintKind[];
  /** Only set for literal commands; used for pattern checks such as `curl | sh`. */
  commandText?: string;
  site: Site;
}

export interface DecodeFact {
  api: string;
  /** Input was a literal; markers are dangerous tokens found in the statically decoded text. */
  literalInput: boolean;
  decodedMarkers: string[];
  site: Site;
}

export interface NetworkFact {
  api: string;
  module?: string;
  urlLiteral?: string;
  host?: string;
  hostClass?: HostClass;
  /** Taint carried by anything other than a bare URL argument (body, headers, query). */
  dataTaint: TaintKind[];
  site: Site;
}

export interface FsWriteFact {
  api: string;
  taint: TaintKind[];
  site: Site;
}

export interface SensitiveReadFact {
  target: string;
  site: Site;
}

export interface EnvReadFact {
  key?: string;
  whole: boolean;
  sensitive: boolean;
  site: Site;
}

export interface ModuleImportFact {
  module: string;
  /** Module name was assembled at runtime rather than written as a literal. */
  hidden: boolean;
  /** Module name could not be resolved statically at all. */
  dynamic: boolean;
  site: Site;
}

export interface ObfuscationFact {
  kind:
    | "hex-identifiers"
    | "string-array"
    | "escape-density"
    | "long-lines"
    | "jsfuck-like"
    | "packer"
    | "control-flow-flattening";
  detail: string;
  site?: Site;
}

export interface EncodedBlobFact {
  length: number;
  entropy: number;
  markers: string[];
  site: Site;
}

export interface HiddenAccessFact {
  /** The dangerous name resolved from a computed expression, e.g. `eval`. */
  name: string;
  site: Site;
}

export interface FileFacts {
  file: string;
  isConfigFile: boolean;
  parsed: boolean;
  parseError?: string;
  dynamicExec: DynamicExecFact[];
  processExec: ProcessExecFact[];
  decode: DecodeFact[];
  network: NetworkFact[];
  fsWrites: FsWriteFact[];
  sensitiveReads: SensitiveReadFact[];
  chmodExec: Site[];
  envReads: EnvReadFact[];
  imports: ModuleImportFact[];
  obfuscation: ObfuscationFact[];
  encodedBlobs: EncodedBlobFact[];
  hiddenAccess: HiddenAccessFact[];
}

export function emptyFacts(file: string, isConfigFile: boolean): FileFacts {
  return {
    file,
    isConfigFile,
    parsed: false,
    dynamicExec: [],
    processExec: [],
    decode: [],
    network: [],
    fsWrites: [],
    sensitiveReads: [],
    chmodExec: [],
    envReads: [],
    imports: [],
    obfuscation: [],
    encodedBlobs: [],
    hiddenAccess: [],
  };
}

const CONFIG_FILE_PATTERNS: RegExp[] = [
  /(^|\/)[^/]*\.config\.(c|m)?[jt]s$/i,
  /(^|\/)\.(babelrc|eslintrc|prettierrc|postcssrc|stylelintrc|mocharc)\.(c|m)?js$/i,
  /(^|\/)(gulpfile|gruntfile|rollupfile|webpackfile)\.(c|m)?[jt]s$/i,
  /(^|\/)(jest|karma|protractor)\.conf(ig)?\.(c|m)?js$/i,
];

export function isConfigFilePath(rel: string): boolean {
  return CONFIG_FILE_PATTERNS.some((re) => re.test(rel));
}
