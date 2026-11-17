import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { compareWithBaseline, createBaseline, scan, BaselineError } from "../src/index.js";
import { commitAll, fixture, git, initRepo, project, snapshot, write } from "./helpers/project.js";

const GOOD = { "src/a.js": fixture("malicious/exfil.js.txt") };

describe("baseline", () => {
  it("creates a baseline that marks existing findings as accepted but still visible", async () => {
    const root = project(GOOD);
    const created = await createBaseline({ root });
    expect(created.baseline.entries.length).toBeGreaterThan(0);
    expect(fs.existsSync(path.join(root, ".reposhield-baseline.json"))).toBe(true);

    const r = await scan({ root, baseline: true, failOn: "high" });
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.findings.every((f) => f.baselined)).toBe(true);
    expect(r.summary.baselinedFindings).toBe(r.findings.length);
    expect(r.summary.activeFindings).toBe(0);
    expect(r.safe).toBe(true);
  });

  it("detects findings that are new relative to the baseline", async () => {
    const root = project(GOOD);
    await createBaseline({ root });
    write(root, "src/b.js", fixture("malicious/shell-pipe.js.txt"));
    const cmp = await compareWithBaseline({ root });
    expect(cmp.baselineFound).toBe(true);
    expect(cmp.newFindings.map((f) => f.file)).toContain("src/b.js");
    expect(cmp.newFindings.every((f) => f.file === "src/b.js")).toBe(true);
    expect(cmp.accepted.length).toBeGreaterThan(0);
    expect(cmp.report.safe).toBe(false);
  });

  it("reports baseline entries that are no longer present", async () => {
    const root = project(GOOD);
    await createBaseline({ root });
    write(root, "src/a.js", "export const ok = 1;\n");
    const cmp = await compareWithBaseline({ root });
    expect(cmp.newFindings).toEqual([]);
    expect(cmp.resolved.length).toBeGreaterThan(0);
  });

  it("does not accept critical findings unless explicitly asked", async () => {
    const root = project({ "src/run.js": fixture("malicious/shell-pipe.js.txt") });
    const c = await createBaseline({ root });
    expect(c.excluded.length).toBeGreaterThan(0);
    expect(c.baseline.entries.every((e) => e.severity !== "critical")).toBe(true);
    const r = await scan({ root, baseline: true });
    expect(r.safe).toBe(false);

    const c2 = await createBaseline({ root, includeCritical: true });
    expect(c2.excluded).toEqual([]);
    expect((await scan({ root, baseline: true })).safe).toBe(true);
  });

  it("keeps fingerprints stable when lines move and free of raw secrets", async () => {
    const root = project(GOOD);
    await createBaseline({ root });
    write(root, "src/a.js", `// a new comment line\n\n${GOOD["src/a.js"]}`);
    const r = await scan({ root, baseline: true });
    expect(r.summary.activeFindings).toBe(0);
    const raw = fs.readFileSync(path.join(root, ".reposhield-baseline.json"), "utf8");
    expect(raw).not.toMatch(/NPM_TOKEN=|ghp_/);
  });

  it("writes only the baseline file and nothing else", async () => {
    const root = project(GOOD);
    initRepo(root);
    commitAll(root);
    const before = snapshot(path.join(root, "src"));
    await createBaseline({ root });
    expect(snapshot(path.join(root, "src"))).toBe(before);
    expect(git(root, "status", "--porcelain").trim()).toBe("?? .reposhield-baseline.json");
  });

  it("refuses a baseline path outside the root", async () => {
    const root = project(GOOD);
    await expect(createBaseline({ root, baseline: "../outside.json" })).rejects.toThrow(/inside root/);
  });

  it("rejects a corrupted baseline with a clear error", async () => {
    const root = project({ ...GOOD, ".reposhield-baseline.json": "{ nope" });
    await expect(scan({ root, baseline: true })).rejects.toBeInstanceOf(BaselineError);
    write(root, ".reposhield-baseline.json", JSON.stringify({ version: 9, entries: [] }));
    await expect(scan({ root, baseline: true })).rejects.toThrow(/invalid/i);
  });

  it("notes a missing baseline instead of silently accepting findings", async () => {
    const r = await scan({ root: project(GOOD), baseline: true });
    expect(r.notes.join(" ")).toMatch(/Baseline not found/);
    expect(r.summary.baselinedFindings).toBe(0);
  });

  it("flags a baseline that was changed relative to the base reference", async () => {
    const root = project(GOOD);
    await createBaseline({ root });
    initRepo(root);
    commitAll(root, "with baseline");
    const file = path.join(root, ".reposhield-baseline.json");
    const b = JSON.parse(fs.readFileSync(file, "utf8"));
    b.entries.push({ fingerprint: "deadbeef", ruleId: "RS-X", file: "x.js", severity: "low" });
    fs.writeFileSync(file, JSON.stringify(b));
    const r = await scan({ root, baseline: true });
    expect(r.findings.find((f) => f.ruleId === "RS-BASE-001")).toBeDefined();
  });
});

describe("allowlist and rule configuration", () => {
  it("keeps allowlisted findings visible but non-failing, and requires a reason", async () => {
    const root = project({ "src/run.js": fixture("malicious/shell-pipe.js.txt") });
    const r = await scan({
      root,
      allowlist: [{ ruleId: "RS-PROC-002", path: "src/**", reason: "reviewed: intentional installer" }],
    });
    expect(r.findings.find((f) => f.ruleId === "RS-PROC-002")?.allowlisted?.reason).toMatch(/reviewed/);
    expect(r.safe).toBe(true);
    expect(r.summary.allowlistedFindings).toBeGreaterThan(0);
    await expect(scan({ root, allowlist: [{ ruleId: "RS-PROC-002", reason: "" }] })).rejects.toThrow(
      /reason/,
    );
  });

  it("supports disabling rules, severity overrides and minimum confidence", async () => {
    const root = project({ "src/run.js": fixture("malicious/shell-pipe.js.txt") });
    expect(
      (await scan({ root, disabledRules: ["RS-PROC-*"] })).findings.some((f) =>
        f.ruleId.startsWith("RS-PROC"),
      ),
    ).toBe(false);
    const down = await scan({ root, severityOverrides: { "RS-PROC-002": "low" } });
    expect(down.findings.find((f) => f.ruleId === "RS-PROC-002")?.severity).toBe("low");
    const conf = await scan({ root: project({ "a.js": `eval(process.env.X)` }), minConfidence: "high" });
    expect(conf.findings).toEqual([]);
  });
});
