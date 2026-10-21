import path from "node:path";
import {
  blameLine,
  commitExists,
  commitsTouching,
  diffExcerpt,
  type CommitInfo,
  type GitAnalysis,
} from "../git/git.js";
import { loadBaseline } from "../core/baseline.js";
import { sanitizeForTerminal } from "../core/redact.js";
import { runScan } from "../core/scanner.js";
import { isActive } from "../core/scoring.js";
import type { RepoShieldOptions } from "../core/options.js";
import { severityRank, type Finding, type GitContext } from "../core/types.js";
import { redactText } from "../rules/secrets.js";

export interface AffectedFile {
  file: string;
  findings: Array<{ ruleId: string; severity: Finding["severity"]; line?: number; newlyIntroduced: boolean }>;
  recentCommits: CommitInfo[];
  /** Redacted, sanitized, truncated diff against the comparison point. */
  diffExcerpt: string[];
}

export interface SuspectCommit extends CommitInfo {
  files: string[];
  findingCount: number;
}

export interface RecoveryInspection {
  /** Always true: inspection never changes files, refs, the index, or configuration. */
  readOnly: true;
  git: GitContext;
  comparedAgainst?: string;
  trustedBaseline?: { path: string; head: string | null; commitPresent: boolean };
  affected: AffectedFile[];
  uncommittedFindings: number;
  suspectCommits: SuspectCommit[];
  plan: { steps: string[]; suggestedCommands: string[] };
  remediation: string[];
  caveats: string[];
}

export const REMEDIATION = [
  "Assume any credential the code could read (environment variables, .npmrc, cloud keys, SSH keys, CI secrets) may be exposed. Rotate them, newest and most privileged first.",
  "Revoke npm, GitHub, and cloud tokens from their own dashboards; deleting the code does not invalidate them.",
  "Review recent changes to .github/workflows, git hooks, package.json scripts, lockfiles, and any file that runs at build or install time.",
  "Check that no unexpected collaborators, deploy keys, GitHub Apps, or Actions secrets were added.",
  "Review added and updated dependencies and their install scripts. Reinstall from a clean checkout with --ignore-scripts, then inspect.",
  "Rebuild and redeploy from a trusted commit. Artifacts built from the suspect state should be discarded.",
  "Audit systems that ran the code (developer machines, CI runners, servers) and treat them as potentially compromised.",
];

export const CAVEATS = [
  "Reverting a commit removes its changes from the branch only. It does not remove the commit from history, invalidate leaked credentials, undo what already executed, or clean external systems.",
  "Malicious changes can sit in other commits, lockfiles, GitHub Actions workflows, or dependencies that this heuristic scan did not flag.",
  "RepoShield never runs these commands. Review each one, work on a backup branch, and coordinate before rewriting shared history.",
];

function cap(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

/**
 * Inspect recovery options without modifying anything. Uses only read-only Git
 * commands and returns a plan the developer can review.
 */
export async function inspectRecovery(options: RepoShieldOptions = {}): Promise<RecoveryInspection> {
  const { report, git, opts } = await runScan(options);
  const active = report.findings
    .filter(isActive)
    .filter((f) => severityRank(f.severity) >= severityRank("medium") || f.newlyIntroduced);

  const byFile = new Map<string, Finding[]>();
  for (const f of active) byFile.set(f.file, [...(byFile.get(f.file) ?? []), f]);

  const runner = git.runner;
  const affected: AffectedFile[] = [];
  const suspects = new Map<string, SuspectCommit>();
  let uncommitted = 0;
  const base = git.effectiveBase ?? "HEAD";

  for (const [file, fs] of [...byFile.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).slice(0, 25)) {
    const recent = runner ? await commitsTouching(runner, file, 5) : [];
    const excerpt = runner
      ? (await diffExcerpt(runner, base, file)).map((l) => cap(sanitizeForTerminal(redactText(l)), 160))
      : [];
    affected.push({
      file,
      findings: fs.map((f) => ({
        ruleId: f.ruleId,
        severity: f.severity,
        ...(f.location ? { line: f.location.line } : {}),
        newlyIntroduced: f.newlyIntroduced === true,
      })),
      recentCommits: recent,
      diffExcerpt: excerpt,
    });

    if (runner) {
      for (const f of fs.slice(0, 10)) {
        if (!f.location) continue;
        const b = await blameLine(runner, file, f.location.line);
        if (b === "uncommitted") {
          uncommitted++;
        } else if (b) {
          const cur = suspects.get(b.sha) ?? { ...b, files: [], findingCount: 0 };
          if (!cur.files.includes(file)) cur.files.push(file);
          cur.findingCount++;
          suspects.set(b.sha, cur);
        }
      }
    }
  }

  let trusted: RecoveryInspection["trustedBaseline"];
  if (opts.baselinePath) {
    try {
      const b = await loadBaseline(opts.baselinePath);
      if (b) {
        trusted = {
          path: path.relative(opts.rootAbs, opts.baselinePath).split(path.sep).join("/"),
          head: b.head ?? null,
          commitPresent: runner && b.head ? await commitExists(runner, b.head) : false,
        };
      }
    } catch {
      /* baseline problems are reported by scan notes */
    }
  }

  const suspectCommits = [...suspects.values()].sort(
    (a, b) => b.findingCount - a.findingCount || (a.sha < b.sha ? -1 : 1),
  );
  return {
    readOnly: true,
    git: report.git,
    ...(runner ? { comparedAgainst: base } : {}),
    ...(trusted ? { trustedBaseline: trusted } : {}),
    affected,
    uncommittedFindings: uncommitted,
    suspectCommits,
    plan: buildPlan(affected, suspectCommits, trusted, git, uncommitted),
    remediation: REMEDIATION,
    caveats: CAVEATS,
  };
}

function buildPlan(
  affected: AffectedFile[],
  suspects: SuspectCommit[],
  trusted: RecoveryInspection["trustedBaseline"],
  git: GitAnalysis,
  uncommitted: number,
): RecoveryInspection["plan"] {
  const steps: string[] = [];
  const cmds: string[] = [];
  if (!git.runner) {
    steps.push(
      "Git history is unavailable, so no commit can be identified. Compare the affected files against a trusted copy (a clean clone or a release tarball).",
    );
    return { steps, suggestedCommands: cmds };
  }
  if (affected.length === 0) {
    steps.push(
      "No active medium-or-higher or newly introduced findings need recovery. Re-run RepoShield after any further changes.",
    );
    return { steps, suggestedCommands: cmds };
  }
  steps.push(
    "Stop: do not run npm install, build, or start commands in this checkout until the findings are reviewed.",
  );
  steps.push("Create a backup branch so nothing is lost: it records the current state without changing it.");
  cmds.push("git branch reposhield-backup-$(date +%Y%m%d%H%M%S)");
  if (uncommitted > 0)
    steps.push(
      `${uncommitted} finding(s) are in uncommitted changes. Inspect with git diff and discard only what you have reviewed.`,
    );
  if (suspects.length > 0) {
    steps.push(
      "Review each suspect commit and decide whether to revert it. Only commits that introduced a flagged line are listed.",
    );
    for (const s of suspects.slice(0, 5)) {
      cmds.push(`git show --stat ${s.sha}`);
    }
    steps.push(
      "If a commit is confirmed malicious, revert it on a new branch (this adds a new commit and keeps history). For a merge commit add -m 1.",
    );
    for (const s of suspects.slice(0, 5))
      cmds.push(`git revert --no-commit ${s.sha}   # review the result before committing`);
  }
  if (trusted?.head && trusted.commitPresent) {
    steps.push(`Compare against the trusted baseline commit ${trusted.head.slice(0, 12)}.`);
    cmds.push(
      `git diff ${trusted.head} -- ${affected
        .slice(0, 5)
        .map((a) => a.file)
        .join(" ")}`,
    );
  } else if (trusted?.head) {
    steps.push(
      "The baseline's trusted commit is not in this clone (shallow or rewritten history). Fetch full history before relying on it.",
    );
  } else {
    steps.push(
      "No trusted baseline commit is recorded. Identify the last commit you trust, then run: reposhield baseline create after review.",
    );
  }
  steps.push(
    "Rotate credentials and review dependencies and workflows; see the remediation list. Reverting alone is not sufficient.",
  );
  return { steps, suggestedCommands: cmds };
}

export function renderRecoveryPlan(r: RecoveryInspection): string {
  const L: string[] = [];
  L.push("# RepoShield recovery plan", "");
  L.push(
    "> Read-only inspection. RepoShield did not modify any files, branches, or history, and will not run the commands below.",
    "",
  );
  L.push(`Compared against: \`${r.comparedAgainst ?? "n/a"}\``);
  if (r.git.head)
    L.push(
      `HEAD: \`${r.git.head.slice(0, 12)}\`${r.git.branch ? ` on \`${r.git.branch}\`` : r.git.detached ? " (detached)" : ""}`,
    );
  if (r.trustedBaseline)
    L.push(
      `Trusted baseline: \`${r.trustedBaseline.path}\` (commit ${r.trustedBaseline.head ? `\`${r.trustedBaseline.head.slice(0, 12)}\`` : "unrecorded"}${r.trustedBaseline.commitPresent ? "" : ", not present locally"})`,
    );
  L.push("", "## Affected files", "");
  if (r.affected.length === 0) L.push("None.");
  for (const a of r.affected) {
    L.push(`### \`${a.file}\``);
    for (const f of a.findings)
      L.push(
        `- ${f.ruleId} (${f.severity})${f.line ? ` at line ${f.line}` : ""}${f.newlyIntroduced ? " — newly introduced" : ""}`,
      );
    if (a.recentCommits.length) {
      L.push("", "Recent commits touching this file:");
      for (const c of a.recentCommits)
        L.push(
          `- \`${c.sha.slice(0, 12)}\` ${sanitizeForTerminal(cap(c.subject, 80))} — ${sanitizeForTerminal(c.author)}, ${c.date.slice(0, 10)}`,
        );
    }
    if (a.diffExcerpt.length) L.push("", "```diff", ...a.diffExcerpt, "```");
    L.push("");
  }
  if (r.suspectCommits.length) {
    L.push("## Suspect commits", "");
    for (const c of r.suspectCommits)
      L.push(
        `- \`${c.sha.slice(0, 12)}\` ${sanitizeForTerminal(cap(c.subject, 80))} — ${sanitizeForTerminal(c.author)}; ${c.findingCount} finding(s) in ${c.files.join(", ")}`,
      );
    L.push("");
  }
  L.push("## Plan", "", ...r.plan.steps.map((s, i) => `${i + 1}. ${s}`), "");
  if (r.plan.suggestedCommands.length)
    L.push("Suggested commands (not executed):", "", "```sh", ...r.plan.suggestedCommands, "```", "");
  L.push(
    "## Remediation",
    "",
    ...r.remediation.map((s) => `- ${s}`),
    "",
    "## Limits",
    "",
    ...r.caveats.map((s) => `- ${s}`),
    "",
  );
  return L.join("\n");
}
