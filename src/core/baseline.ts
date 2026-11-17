import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import type { Finding, Severity } from "./types.js";
import { SEVERITIES } from "./types.js";

export const BASELINE_VERSION = 1;

const entrySchema = z.object({
  fingerprint: z.string().min(1),
  ruleId: z.string(),
  file: z.string(),
  severity: z.enum(SEVERITIES),
  /** Optional reviewer note; never contains secrets. */
  note: z.string().optional(),
});

const baselineSchema = z.object({
  version: z.literal(BASELINE_VERSION),
  tool: z.string(),
  createdAt: z.string().optional(),
  /** HEAD commit when the baseline was accepted: the "known trusted" point for recovery inspection. */
  head: z.string().nullable().optional(),
  entries: z.array(entrySchema),
});

export type BaselineEntry = z.infer<typeof entrySchema>;
export type Baseline = z.infer<typeof baselineSchema>;

export class BaselineError extends Error {
  override name = "BaselineError";
}

export async function loadBaseline(file: string): Promise<Baseline | null> {
  let raw: string;
  try {
    raw = await fs.readFile(file, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new BaselineError(`Cannot read baseline ${file}: ${(err as Error).message}`);
  }
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    throw new BaselineError(`Baseline ${file} is not valid JSON.`);
  }
  const parsed = baselineSchema.safeParse(json);
  if (!parsed.success) {
    throw new BaselineError(
      `Baseline ${file} is invalid: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`,
    );
  }
  return parsed.data;
}

export interface BaselineCreateOptions {
  version: string;
  head?: string | undefined;
  includeCritical: boolean;
  now?: Date | undefined;
}

/** Build a baseline from findings. Critical findings are excluded unless explicitly accepted. */
export function buildBaseline(
  findings: Finding[],
  o: BaselineCreateOptions,
): { baseline: Baseline; excluded: Finding[] } {
  const excluded: Finding[] = [];
  const entries: BaselineEntry[] = [];
  const seen = new Set<string>();
  for (const f of findings) {
    if (f.baselined || f.allowlisted) continue;
    if (f.severity === "critical" && !o.includeCritical) {
      excluded.push(f);
      continue;
    }
    if (seen.has(f.fingerprint)) continue;
    seen.add(f.fingerprint);
    entries.push({ fingerprint: f.fingerprint, ruleId: f.ruleId, file: f.file, severity: f.severity });
  }
  entries.sort((a, b) =>
    a.file < b.file ? -1 : a.file > b.file ? 1 : a.fingerprint < b.fingerprint ? -1 : 1,
  );
  return {
    baseline: {
      version: BASELINE_VERSION,
      tool: `reposhield@${o.version}`,
      createdAt: (o.now ?? new Date()).toISOString(),
      head: o.head ?? null,
      entries,
    },
    excluded,
  };
}

export async function writeBaseline(file: string, baseline: Baseline): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, `${JSON.stringify(baseline, null, 2)}\n`, "utf8");
}

/** Mark findings accepted by the baseline. Findings stay in the report. */
export function applyBaseline(findings: Finding[], baseline: Baseline): { resolved: BaselineEntry[] } {
  const accepted = new Map(baseline.entries.map((e) => [e.fingerprint, e]));
  const present = new Set<string>();
  for (const f of findings) {
    const e = accepted.get(f.fingerprint);
    if (e) {
      f.baselined = true;
      present.add(f.fingerprint);
    }
  }
  return { resolved: baseline.entries.filter((e) => !present.has(e.fingerprint)) };
}

export type { Severity };
