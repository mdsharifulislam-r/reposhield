import { execFile } from "node:child_process";
import type { GitContext } from "../core/types.js";
import { toPosix } from "../core/walker.js";

/**
 * Read-only Git access.
 *
 * Only a fixed allowlist of read-only subcommands is ever executed, repository
 * configuration that can launch programs is overridden, and no hooks run for
 * these commands. Nothing here writes to the working tree, index, refs, or config.
 */
const READ_ONLY = new Set([
  "rev-parse",
  "symbolic-ref",
  "diff",
  "show",
  "log",
  "ls-files",
  "merge-base",
  "blame",
  "cat-file",
  "rev-list",
  "status",
]);

const HARDENING = [
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.hooksPath=/dev/null",
  "-c",
  "core.pager=cat",
  "-c",
  "core.quotepath=false",
  "-c",
  "protocol.ext.allow=never",
  "-c",
  "diff.external=",
];

export interface GitResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  code: number | string | null;
}

export class GitRunner {
  constructor(
    readonly cwd: string,
    private readonly signal?: AbortSignal,
  ) {}

  run(args: string[], maxBuffer = 32 * 1024 * 1024): Promise<GitResult> {
    const sub = args[0] ?? "";
    if (!READ_ONLY.has(sub)) {
      return Promise.resolve({
        ok: false,
        stdout: "",
        stderr: `refused non-read-only git command: ${sub}`,
        code: "EREFUSED",
      });
    }
    const env: NodeJS.ProcessEnv = {
      PATH: process.env["PATH"] ?? "",
      HOME: process.env["HOME"] ?? "",
      ...(process.env["SYSTEMROOT"] ? { SYSTEMROOT: process.env["SYSTEMROOT"] } : {}),
      LANG: "C",
      LC_ALL: "C",
      GIT_OPTIONAL_LOCKS: "0",
      GIT_TERMINAL_PROMPT: "0",
      GIT_PAGER: "cat",
      GIT_EXTERNAL_DIFF: "",
      GIT_ASKPASS: "echo",
    };
    return new Promise((resolve) => {
      execFile(
        "git",
        [...HARDENING, ...args],
        {
          cwd: this.cwd,
          env,
          maxBuffer,
          timeout: 60_000,
          encoding: "utf8",
          ...(this.signal ? { signal: this.signal } : {}),
        },
        (err, stdout, stderr) => {
          if (err) {
            const code = (err as NodeJS.ErrnoException & { code?: number | string }).code ?? null;
            resolve({ ok: false, stdout: String(stdout ?? ""), stderr: String(stderr || err.message), code });
          } else resolve({ ok: true, stdout: String(stdout), stderr: String(stderr), code: 0 });
        },
      );
    });
  }
}

/** Reject refs that could be interpreted as options or contain unexpected characters. */
export function isSafeRef(ref: string): boolean {
  return (
    ref.length > 0 &&
    ref.length < 256 &&
    !ref.startsWith("-") &&
    /^[\w./@~^{}:+-]+$/.test(ref) &&
    !ref.includes("..")
  );
}

export interface AddedLines {
  /** `all` when the whole file is new (untracked). */
  all: boolean;
  ranges: Array<[number, number]>;
}

export interface GitAnalysis {
  context: GitContext;
  runner: GitRunner | null;
  /** The commit changes are compared against (merge-base resolved), if any. */
  effectiveBase?: string;
  added: Map<string, AddedLines>;
}

const EMPTY = (notes: string[], available: boolean, isRepository: boolean): GitAnalysis => ({
  context: { available, isRepository, changedFiles: [], notes },
  runner: null,
  added: new Map(),
});

export async function analyzeGit(
  rootAbs: string,
  opts: { baseRef?: string | undefined; mode: string; signal?: AbortSignal | undefined; enabled: boolean },
): Promise<GitAnalysis> {
  if (!opts.enabled) return EMPTY(["Git analysis disabled (includeGitHistory is false)."], false, false);
  const git = new GitRunner(rootAbs, opts.signal);

  const v = await git.run(["rev-parse", "--is-inside-work-tree"]);
  if (!v.ok && (v.code === "ENOENT" || String(v.code) === "ENOENT")) {
    return EMPTY(["Git is not installed or not on PATH; Git-based analysis was skipped."], false, false);
  }
  if (!v.ok || v.stdout.trim() !== "true") {
    const dubious = /dubious ownership|safe\.directory/i.test(v.stderr);
    return EMPTY(
      [
        dubious
          ? "Git refused to read this repository (unsafe directory ownership); Git-based analysis was skipped."
          : "Not a Git repository; Git-based analysis was skipped.",
      ],
      true,
      false,
    );
  }

  const notes: string[] = [];
  const headR = await git.run(["rev-parse", "--verify", "-q", "HEAD"]);
  const head = headR.ok ? headR.stdout.trim() : undefined;
  const branchR = await git.run(["symbolic-ref", "-q", "--short", "HEAD"]);
  const branch = branchR.ok ? branchR.stdout.trim() : null;
  const shallowR = await git.run(["rev-parse", "--is-shallow-repository"]);
  const shallow = shallowR.ok && shallowR.stdout.trim() === "true";
  const detached = !!head && branch === null;
  if (shallow)
    notes.push(
      "Shallow clone: history and merge-base are limited. Use fetch-depth: 0 in CI for accurate change detection.",
    );
  if (detached) notes.push("Detached HEAD.");
  if (!head) notes.push("Repository has no commits yet; change tracking is unavailable.");

  const context: GitContext = {
    available: true,
    isRepository: true,
    ...(head ? { head } : {}),
    branch,
    detached,
    shallow,
    changedFiles: [],
    notes,
  };
  const analysis: GitAnalysis = { context, runner: git, added: new Map() };
  if (!head) return analysis;

  // Resolve base reference.
  let base: string | undefined;
  if (opts.baseRef) {
    if (!isSafeRef(opts.baseRef)) {
      notes.push(`Ignored unsafe baseRef value.`);
    } else {
      const r = await git.run(["rev-parse", "--verify", "-q", `${opts.baseRef}^{commit}`]);
      if (r.ok) base = opts.baseRef;
      else
        notes.push(
          `baseRef "${opts.baseRef}" was not found${shallow ? " (shallow clone?)" : ""}; comparing against HEAD instead.`,
        );
    }
  } else if (opts.mode === "changed") {
    base = await defaultBase(git, head);
    if (!base)
      notes.push("No upstream branch or parent commit found; comparing uncommitted changes against HEAD.");
  }
  base ??= "HEAD";
  context.baseRef = base;

  let effective = base;
  if (base !== "HEAD") {
    const mb = await git.run(["merge-base", base, "HEAD"]);
    if (mb.ok && mb.stdout.trim()) effective = mb.stdout.trim();
  }
  analysis.effectiveBase = effective;

  const names = await git.run([
    "diff",
    "--name-only",
    "--relative",
    "--no-ext-diff",
    "--no-textconv",
    "--diff-filter=ACMRT",
    "-z",
    effective,
    "--",
  ]);
  const untracked = await git.run(["ls-files", "--others", "--exclude-standard", "-z"]);
  const changed = new Set<string>();
  if (names.ok) for (const n of names.stdout.split("\0")) if (n) changed.add(toPosix(n));
  const untrackedSet = new Set<string>();
  if (untracked.ok)
    for (const n of untracked.stdout.split("\0"))
      if (n) {
        changed.add(toPosix(n));
        untrackedSet.add(toPosix(n));
      }
  context.changedFiles = [...changed].sort();

  const diff = await git.run([
    "diff",
    "-U0",
    "--relative",
    "--no-ext-diff",
    "--no-textconv",
    "--no-color",
    effective,
    "--",
  ]);
  if (diff.ok) analysis.added = parseAddedLines(diff.stdout);
  for (const f of untrackedSet) analysis.added.set(f, { all: true, ranges: [] });
  // A changed file whose hunks could not be parsed is conservatively treated as wholly new.
  for (const f of changed) if (!analysis.added.has(f)) analysis.added.set(f, { all: true, ranges: [] });
  return analysis;
}

async function defaultBase(git: GitRunner, head: string): Promise<string | undefined> {
  const candidates: string[] = [];
  const up = await git.run(["rev-parse", "--verify", "-q", "origin/HEAD^{commit}"]);
  if (up.ok) candidates.push("origin/HEAD");
  candidates.push("origin/main", "origin/master", "main", "master");
  for (const c of candidates) {
    const r = await git.run(["rev-parse", "--verify", "-q", `${c}^{commit}`]);
    if (r.ok && r.stdout.trim() !== head) return c;
  }
  const parent = await git.run(["rev-parse", "--verify", "-q", "HEAD~1^{commit}"]);
  return parent.ok ? "HEAD~1" : undefined;
}

export function parseAddedLines(diff: string): Map<string, AddedLines> {
  const out = new Map<string, AddedLines>();
  let current: AddedLines | undefined;
  for (const line of diff.split("\n")) {
    if (line.startsWith("+++ ")) {
      const p = line.slice(4);
      if (p === "/dev/null") {
        current = undefined;
        continue;
      }
      const rel = toPosix(p.startsWith("b/") ? p.slice(2) : p);
      current = { all: false, ranges: [] };
      out.set(rel, current);
    } else if (line.startsWith("@@") && current) {
      const m = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
      if (m) {
        const start = Number(m[1]);
        const count = m[2] === undefined ? 1 : Number(m[2]);
        if (count > 0) current.ranges.push([start, start + count - 1]);
      }
    }
  }
  return out;
}

export function isLineAdded(a: AddedLines | undefined, line: number | undefined): boolean {
  if (!a) return false;
  if (a.all) return true;
  if (line === undefined) return a.ranges.length > 0;
  return a.ranges.some(([s, e]) => line >= s && line <= e);
}

/** Read a file's content at a ref, relative to the scan root. `null` = absent there, `undefined` = unknown. */
export async function showAtRef(
  git: GitRunner,
  ref: string,
  rel: string,
): Promise<string | null | undefined> {
  if (!isSafeRef(ref)) return undefined;
  const r = await git.run(["show", `${ref}:./${rel}`]);
  if (r.ok) return r.stdout;
  if (
    /does not exist|exists on disk, but not in|bad revision|unknown revision|Not a valid object/i.test(
      r.stderr,
    )
  )
    return null;
  return undefined;
}

export interface CommitInfo {
  sha: string;
  subject: string;
  author: string;
  date: string;
}

export async function commitsTouching(git: GitRunner, rel: string, limit = 5): Promise<CommitInfo[]> {
  const r = await git.run(["log", `-n${limit}`, "--no-color", "--format=%H%x1f%s%x1f%an%x1f%aI", "--", rel]);
  if (!r.ok) return [];
  return r.stdout
    .split("\n")
    .filter(Boolean)
    .map((l) => {
      const [sha = "", subject = "", author = "", date = ""] = l.split("\x1f");
      return { sha, subject, author, date };
    });
}

/** Commit that last changed a specific line, or `uncommitted`. */
export async function blameLine(
  git: GitRunner,
  rel: string,
  line: number,
): Promise<CommitInfo | "uncommitted" | undefined> {
  const r = await git.run(["blame", "-L", `${line},${line}`, "--porcelain", "--", rel]);
  if (!r.ok) return undefined;
  const sha = r.stdout.split("\n")[0]?.split(" ")[0];
  if (!sha) return undefined;
  if (/^0+$/.test(sha)) return "uncommitted";
  const field = (name: string): string => new RegExp(`^${name} (.*)$`, "m").exec(r.stdout)?.[1] ?? "";
  const ts = Number(field("author-time"));
  return {
    sha,
    subject: field("summary"),
    author: field("author"),
    date: Number.isFinite(ts) && ts > 0 ? new Date(ts * 1000).toISOString() : "",
  };
}

export async function diffExcerpt(
  git: GitRunner,
  base: string,
  rel: string,
  maxLines = 60,
): Promise<string[]> {
  const r = await git.run([
    "diff",
    "-U1",
    "--relative",
    "--no-ext-diff",
    "--no-textconv",
    "--no-color",
    base,
    "--",
    rel,
  ]);
  if (!r.ok) return [];
  return r.stdout.split("\n").slice(0, maxLines);
}

export async function commitExists(git: GitRunner, sha: string): Promise<boolean> {
  if (!/^[0-9a-f]{7,64}$/i.test(sha)) return false;
  const r = await git.run(["cat-file", "-e", `${sha}^{commit}`]);
  return r.ok;
}
