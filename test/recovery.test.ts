import { describe, expect, it } from "vitest";
import { createBaseline, inspectRecovery, renderRecoveryPlan } from "../src/index.js";
import { commitAll, fake, fixture, git, initRepo, project, snapshot, write } from "./helpers/project.js";

function compromisedRepo(): { root: string; trusted: string; bad: string } {
  const root = project({
    "src/app.js": fixture("benign/plain.js.txt"),
    "vite.config.js": "module.exports = {};\n",
  });
  initRepo(root);
  const trusted = commitAll(root, "trusted state");
  write(
    root,
    "vite.config.js",
    `${fixture("malicious/vite.config.js.txt")}\nconst k = "${fake.github()}";\n`,
  );
  const bad = commitAll(root, "chore: update build config");
  return { root, trusted, bad };
}

describe("recovery inspection", () => {
  it("identifies affected files, the suspect commit, and suggests commands without running them", async () => {
    const { root, trusted, bad } = compromisedRepo();
    const r = await inspectRecovery({ root, baseRef: trusted });
    expect(r.readOnly).toBe(true);
    expect(r.affected.map((a) => a.file)).toContain("vite.config.js");
    expect(r.suspectCommits[0]?.sha).toBe(bad);
    expect(r.suspectCommits[0]?.subject).toBe("chore: update build config");
    const cmds = r.plan.suggestedCommands.join("\n");
    expect(cmds).toMatch(new RegExp(`git revert --no-commit ${bad}`));
    expect(cmds).toMatch(/git branch reposhield-backup/);
    expect(r.plan.steps.join(" ")).toMatch(/do not run npm install/i);
    expect(r.remediation.join(" ")).toMatch(/Rotate/);
    expect(r.caveats.join(" ")).toMatch(
      /does not remove the commit from history|invalidate leaked credentials/,
    );
  });

  it("shows diff context with secrets redacted", async () => {
    const { root, trusted } = compromisedRepo();
    const r = await inspectRecovery({ root, baseRef: trusted });
    const excerpt = r.affected.find((a) => a.file === "vite.config.js")!.diffExcerpt.join("\n");
    expect(excerpt).toMatch(/^\+.*child_process/m);
    expect(excerpt).not.toContain(fake.github());
    expect(excerpt).toMatch(/REDACTED/);
    const md = renderRecoveryPlan(r);
    expect(md).toContain("# RepoShield recovery plan");
    expect(md).not.toContain(fake.github());
    expect(md).toMatch(/will not run the commands/);
  });

  it("compares against the trusted commit recorded in the baseline", async () => {
    const root = project({ "src/app.js": fixture("benign/plain.js.txt") });
    initRepo(root);
    const trusted = commitAll(root, "trusted");
    await createBaseline({ root });
    commitAll(root, "baseline");
    write(root, "src/evil.js", fixture("malicious/shell-pipe.js.txt"));
    commitAll(root, "evil");
    const r = await inspectRecovery({ root, baseline: true, baseRef: "HEAD~1" });
    expect(r.trustedBaseline?.head).toBe(trusted.length ? git(root, "rev-parse", "HEAD~2").trim() : "");
    expect(r.trustedBaseline?.commitPresent).toBe(true);
    expect(r.plan.suggestedCommands.join("\n")).toMatch(/git diff [0-9a-f]{40} --/);
  });

  it("does not mutate the repository, index, refs, or working tree", async () => {
    const { root, trusted } = compromisedRepo();
    write(root, "src/new.js", fixture("malicious/exfil.js.txt"));
    const before = snapshot(root);
    const head = git(root, "rev-parse", "HEAD");
    const refs = git(root, "for-each-ref");
    const status = git(root, "status", "--porcelain");
    await inspectRecovery({ root, baseRef: trusted });
    await inspectRecovery({ root });
    expect(snapshot(root)).toBe(before);
    expect(git(root, "rev-parse", "HEAD")).toBe(head);
    expect(git(root, "for-each-ref")).toBe(refs);
    expect(git(root, "status", "--porcelain")).toBe(status);
  });

  it("degrades gracefully without Git", async () => {
    const root = project({ "a.js": fixture("malicious/shell-pipe.js.txt") });
    const r = await inspectRecovery({ root });
    expect(r.suspectCommits).toEqual([]);
    expect(r.plan.steps.join(" ")).toMatch(/Git history is unavailable/);
  });

  it("reports nothing to recover for a clean repository", async () => {
    const root = project({ "a.js": fixture("benign/plain.js.txt") });
    initRepo(root);
    commitAll(root);
    const r = await inspectRecovery({ root });
    expect(r.affected).toEqual([]);
    expect(r.plan.suggestedCommands).toEqual([]);
  });
});
