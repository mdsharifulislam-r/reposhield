import fs from "node:fs/promises";
import path from "node:path";
import ignore, { type Ignore } from "ignore";
import picomatch from "picomatch";
import { DEFAULT_IGNORE, isInside, type ResolvedOptions } from "./options.js";
import type { ScanError } from "./types.js";

export interface WalkedFile {
  abs: string;
  /** Relative to root, forward slashes. */
  rel: string;
  size: number;
}

export interface WalkResult {
  files: WalkedFile[];
  skipped: number;
  errors: ScanError[];
}

export function toPosix(p: string): string {
  return p.split(path.sep).join("/");
}

async function readIgnoreFile(file: string): Promise<string | null> {
  try {
    return await fs.readFile(file, "utf8");
  } catch {
    return null;
  }
}

export async function buildIgnore(opts: ResolvedOptions): Promise<Ignore> {
  const ig = ignore();
  if (!opts.replaceDefaultIgnore) ig.add(DEFAULT_IGNORE);
  ig.add(opts.ignore);
  if (opts.respectGitignore) {
    const gi = await readIgnoreFile(path.join(opts.rootAbs, ".gitignore"));
    if (gi) ig.add(gi);
  }
  const rs = await readIgnoreFile(path.join(opts.rootAbs, ".reposhieldignore"));
  if (rs) ig.add(rs);
  return ig;
}

/**
 * Walk the project with a bounded, iterative traversal.
 *
 * - never follows symlinks unless `followSymlinks` is set, and even then never
 *   outside the root;
 * - never reads file contents (only stat);
 * - stops at `maxFiles` to avoid unbounded traversal.
 */
export async function walk(
  opts: ResolvedOptions,
  extensions: readonly string[],
  extraNames: readonly string[] = [],
): Promise<WalkResult> {
  const ig = await buildIgnore(opts);
  const extSet = new Set(extensions);
  const nameSet = new Set(extraNames);
  const files: WalkedFile[] = [];
  const errors: ScanError[] = [];
  let skipped = 0;

  const rootReal = await fs.realpath(opts.rootAbs);
  const stack: string[] = [opts.rootAbs];
  const visitedDirs = new Set<string>([rootReal]);

  while (stack.length > 0) {
    if (opts.signal?.aborted) throw abortError();
    const dir = stack.pop() as string;
    let entries: import("node:fs").Dirent[];
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch (err) {
      errors.push({
        file: toPosix(path.relative(opts.rootAbs, dir)) || ".",
        kind: "read",
        message: errMsg(err),
      });
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

    for (const entry of entries) {
      const abs = path.join(dir, entry.name);
      const rel = toPosix(path.relative(opts.rootAbs, abs));
      const isDir = entry.isDirectory();
      if (ig.ignores(isDir ? `${rel}/` : rel)) {
        skipped++;
        continue;
      }

      if (entry.isSymbolicLink()) {
        const handled = await handleSymlink(abs, rel, rootReal, opts, errors);
        if (!handled) {
          skipped++;
          continue;
        }
        if (handled.isDir) {
          if (!visitedDirs.has(handled.real)) {
            visitedDirs.add(handled.real);
            stack.push(abs);
          }
          continue;
        }
        if (wanted(rel, extSet, nameSet)) {
          if (files.length >= opts.maxFiles) return limit(files, skipped, errors, opts);
          files.push({ abs, rel, size: handled.size });
        }
        continue;
      }

      if (isDir) {
        stack.push(abs);
        continue;
      }
      if (!entry.isFile()) {
        skipped++;
        continue;
      }
      if (!wanted(rel, extSet, nameSet)) continue;
      try {
        const st = await fs.stat(abs);
        if (files.length >= opts.maxFiles) return limit(files, skipped, errors, opts);
        files.push({ abs, rel, size: st.size });
      } catch (err) {
        errors.push({ file: rel, kind: "read", message: errMsg(err) });
      }
    }
  }

  files.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  return { files, skipped, errors };
}

function limit(files: WalkedFile[], skipped: number, errors: ScanError[], opts: ResolvedOptions): WalkResult {
  errors.push({
    file: ".",
    kind: "other",
    message: `File limit of ${opts.maxFiles} reached; remaining files were not scanned. Raise maxFiles or add ignore rules.`,
  });
  files.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  return { files, skipped, errors };
}

function wanted(rel: string, exts: Set<string>, names: Set<string>): boolean {
  const base = rel.slice(rel.lastIndexOf("/") + 1);
  return names.has(base) || exts.has(path.extname(base).toLowerCase());
}

async function handleSymlink(
  abs: string,
  rel: string,
  rootReal: string,
  opts: ResolvedOptions,
  errors: ScanError[],
): Promise<{ isDir: boolean; real: string; size: number } | null> {
  let real: string;
  try {
    real = await fs.realpath(abs);
  } catch {
    errors.push({ file: rel, kind: "symlink", message: "Broken symlink skipped." });
    return null;
  }
  if (!isInside(rootReal, real)) {
    errors.push({
      file: rel,
      kind: "symlink",
      message: "Symlink points outside the project root and was not followed.",
    });
    return null;
  }
  if (!opts.followSymlinks) {
    errors.push({ file: rel, kind: "symlink", message: "Symlink skipped (followSymlinks is false)." });
    return null;
  }
  try {
    const st = await fs.stat(real);
    return { isDir: st.isDirectory(), real, size: st.size };
  } catch {
    return null;
  }
}

export function makeMatcher(patterns: string[]): (rel: string) => boolean {
  if (patterns.length === 0) return () => false;
  return picomatch(patterns, { dot: true });
}

export function abortError(): Error {
  const e = new Error("Scan aborted");
  e.name = "AbortError";
  return e;
}

export function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Run `fn` over items with bounded concurrency, preserving input order in results. */
export async function mapLimit<T, R>(
  items: readonly T[],
  limitN: number,
  fn: (item: T, index: number) => Promise<R>,
  signal?: AbortSignal,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limitN, items.length) }, async () => {
    for (;;) {
      if (signal?.aborted) throw abortError();
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i] as T, i);
    }
  });
  await Promise.all(workers);
  return results;
}
