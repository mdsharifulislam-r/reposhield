import path from "node:path";
import { z } from "zod";
import { CONFIDENCES, MODES, SEVERITIES } from "./types.js";

export const DEFAULT_IGNORE = [
  "node_modules/**",
  "**/node_modules/**",
  ".git/**",
  "dist/**",
  "build/**",
  "out/**",
  ".next/**",
  ".nuxt/**",
  ".svelte-kit/**",
  ".turbo/**",
  ".cache/**",
  "coverage/**",
  "vendor/**",
  "**/*.min.js",
  "**/*.map",
];

export const SCANNABLE_EXTENSIONS = [".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"];

const severity = z.enum(SEVERITIES);

const allowlistEntry = z.object({
  ruleId: z.string().min(1),
  /** Glob relative to root. Omit to allow the rule everywhere (discouraged). */
  path: z.string().min(1).optional(),
  reason: z.string().min(1, "An allowlist entry needs a reason so reviewers can audit it."),
});

export const optionsSchema = z
  .object({
    root: z.string().min(1).default("."),
    mode: z.enum(MODES).default("audit"),
    includeGitHistory: z.boolean().default(true),
    /** `true` uses the default baseline path; a string is a custom path relative to root. */
    baseline: z.union([z.boolean(), z.string().min(1)]).default(false),
    failOn: severity.default("high"),
    minConfidence: z.enum(CONFIDENCES).default("low"),
    ignore: z.array(z.string()).default([]),
    /** Replace the built-in ignore list instead of extending it (discouraged). */
    replaceDefaultIgnore: z.boolean().default(false),
    respectGitignore: z.boolean().default(true),
    maxFileSizeBytes: z.number().int().positive().default(1_000_000),
    maxFiles: z.number().int().positive().default(50_000),
    concurrency: z.number().int().min(1).max(64).default(8),
    followSymlinks: z.boolean().default(false),
    /** Git ref to diff against in `changed` mode or when marking newly introduced findings. */
    baseRef: z.string().min(1).optional(),
    disabledRules: z.array(z.string()).default([]),
    severityOverrides: z.record(z.string(), severity).default({}),
    allowlist: z.array(allowlistEntry).default([]),
    /** Raw secret values are never emitted unless this is explicitly true. */
    redactSecrets: z.boolean().default(true),
    /** Interval for `monitor` mode in milliseconds. */
    monitorIntervalMs: z.number().int().min(1000).default(30_000),
  })
  .strict();

export type RepoShieldOptions = z.input<typeof optionsSchema> & {
  /** Abort a running scan. */
  signal?: AbortSignal;
};

export interface ResolvedOptions extends z.output<typeof optionsSchema> {
  rootAbs: string;
  baselinePath: string | null;
  signal?: AbortSignal;
}

export class ConfigError extends Error {
  override name = "ConfigError";
}

export const DEFAULT_BASELINE_FILE = ".reposhield-baseline.json";

export function resolveOptions(input: RepoShieldOptions = {}): ResolvedOptions {
  const { signal, ...rest } = input;
  const parsed = optionsSchema.safeParse(rest);
  if (!parsed.success) {
    const lines = parsed.error.issues.map((i) => {
      const where = i.path.length ? i.path.join(".") : "options";
      return `  - ${where}: ${i.message}`;
    });
    throw new ConfigError(`Invalid RepoShield options:\n${lines.join("\n")}`);
  }
  const o = parsed.data;

  // Mode adjustments: strict tightens defaults, but never loosens an explicit choice.
  const explicitFailOn = rest.failOn !== undefined;
  const failOn = o.mode === "strict" && !explicitFailOn ? "medium" : o.failOn;

  const rootAbs = path.resolve(o.root);
  const baselinePath =
    o.baseline === false
      ? null
      : o.baseline === true
        ? path.join(rootAbs, DEFAULT_BASELINE_FILE)
        : path.resolve(rootAbs, o.baseline);

  if (baselinePath && !isInside(rootAbs, baselinePath)) {
    throw new ConfigError("Invalid RepoShield options:\n  - baseline: path must stay inside root");
  }

  const resolved: ResolvedOptions = {
    ...o,
    failOn,
    rootAbs,
    baselinePath,
    ...(signal ? { signal } : {}),
  };
  return resolved;
}

export function isInside(rootAbs: string, candidateAbs: string): boolean {
  const rel = path.relative(rootAbs, candidateAbs);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}
